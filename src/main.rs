use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use cnlman::package::{Origin, Package, non_empty};
use cnlman::pyload::{Destination, PyLoad};
use cnlman::server::{Listener, Stop};
use cnlman::{crypto, html};

/// Exit code when `listen` times out before any package arrived.
const EXIT_TIMEOUT: u8 = 2;
/// Exit code when `extract` finds no payload in the page.
const EXIT_NOTHING_FOUND: u8 = 3;

/// Capture Click'n'Load packages, decrypt them and hand the links to pyLoad.
///
/// Every decoded package is written to stdout, one JSON object per line
/// (or one link per line with `--format links`). Diagnostics go to stderr.
#[derive(Debug, Parser)]
#[command(version, about, long_about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Listen on the Click'n'Load port and decode what the browser posts.
    Listen(ListenArgs),
    /// Decode Click'n'Load payloads embedded in saved page HTML.
    Extract(ExtractArgs),
    /// Decrypt a single jk/crypted pair.
    Decrypt(DecryptArgs),
    /// Send links to pyLoad, one per line from a file or stdin.
    Push(PushArgs),
}

#[derive(Debug, Args)]
struct ListenArgs {
    /// Address to listen on.
    #[arg(long, env = "CNLMAN_BIND", default_value = "127.0.0.1:9666")]
    bind: SocketAddr,
    /// Permit a non-loopback bind address (lets the network inject links).
    #[arg(long)]
    allow_remote: bool,
    /// Exit after the first package.
    #[arg(long, conflicts_with = "count")]
    once: bool,
    /// Exit after this many packages.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
    count: Option<u32>,
    /// Give up after this many seconds (exit code 2 if nothing arrived).
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,
    #[command(flatten)]
    output: OutputArgs,
    #[command(flatten)]
    pyload: PyLoadArgs,
}

#[derive(Debug, Args)]
struct ExtractArgs {
    /// HTML file to read; `-` or nothing reads stdin.
    file: Option<PathBuf>,
    #[command(flatten)]
    output: OutputArgs,
    #[command(flatten)]
    pyload: PyLoadArgs,
}

#[derive(Debug, Args)]
struct DecryptArgs {
    /// The jk value: a `function f(){ return '<hex>'; }` or the bare hex key.
    #[arg(long)]
    jk: String,
    /// The base64 ciphertext; `-` reads it from stdin.
    #[arg(long)]
    crypted: String,
    /// Package name to report and to use in pyLoad.
    #[arg(long)]
    name: Option<String>,
    #[command(flatten)]
    output: OutputArgs,
    #[command(flatten)]
    pyload: PyLoadArgs,
}

#[derive(Debug, Args)]
struct PushArgs {
    /// Package name in pyLoad.
    #[arg(long)]
    name: String,
    /// File with one link per line; `-` or nothing reads stdin.
    file: Option<PathBuf>,
    #[command(flatten)]
    connection: PyLoadConnection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// One JSON object per package and line.
    Json,
    /// One link per line.
    Links,
}

#[derive(Debug, Args)]
struct OutputArgs {
    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = Format::Json)]
    format: Format,
}

#[derive(Debug, Args)]
struct PyLoadArgs {
    /// Also add every package to pyLoad.
    #[arg(long)]
    pyload: bool,
    #[command(flatten)]
    connection: PyLoadConnection,
}

#[derive(Debug, Args)]
struct PyLoadConnection {
    /// pyLoad base URL. The API key is read from `PYLOAD_API_KEY`.
    #[arg(long = "pyload-url", env = "PYLOAD_URL", value_name = "URL")]
    url: Option<String>,
    /// Where pyLoad files the package.
    #[arg(long = "pyload-dest", value_enum, default_value_t = Destination::Queue)]
    dest: Destination,
    /// Allow sending the API key over plain HTTP to a non-local host.
    #[arg(long = "pyload-insecure")]
    insecure: bool,
}

impl PyLoadConnection {
    fn client(&self) -> Result<PyLoad> {
        let url = self
            .url
            .as_deref()
            .context("no pyLoad URL; set PYLOAD_URL or pass --pyload-url")?;
        let key = std::env::var("PYLOAD_API_KEY")
            .context("PYLOAD_API_KEY is not set; create a key in pyLoad under Settings → API")?;
        PyLoad::new(url, key, self.dest, self.insecure)
    }
}

impl PyLoadArgs {
    fn client(&self) -> Result<Option<PyLoad>> {
        self.pyload.then(|| self.connection.client()).transpose()
    }
}

#[derive(Serialize)]
struct Emitted<'a> {
    #[serde(flatten)]
    package: &'a Package,
    #[serde(skip_serializing_if = "Option::is_none")]
    pyload_package_id: Option<u64>,
}

/// Writes a package to stdout and, if configured, adds it to pyLoad first.
fn emit(package: &Package, format: Format, pyload: Option<&PyLoad>) -> Result<()> {
    let pyload_package_id = pyload
        .map(|client| {
            let name = package_name(package);
            let id = client.add_package(&name, &package.links)?;
            eprintln!("cnlman: added {name:?} to pyLoad as package {id}");
            anyhow::Ok(id)
        })
        .transpose()?;
    let mut out = std::io::stdout().lock();
    match format {
        Format::Json => {
            serde_json::to_writer(
                &mut out,
                &Emitted {
                    package,
                    pyload_package_id,
                },
            )?;
            writeln!(out)?;
        }
        Format::Links => {
            for link in &package.links {
                writeln!(out, "{link}")?;
            }
        }
    }
    out.flush()?;
    Ok(())
}

/// Name for pyLoad: the page's package name, else the last path segment of
/// the first link.
fn package_name(package: &Package) -> String {
    package.name.clone().unwrap_or_else(|| {
        package
            .links
            .first()
            .and_then(|l| l.trim_end_matches('/').rsplit('/').next())
            .filter(|s| !s.is_empty())
            .unwrap_or("cnlman")
            .to_owned()
    })
}

fn read_input(file: Option<&PathBuf>) -> Result<String> {
    match file {
        Some(path) if path.as_os_str() != "-" => {
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
        }
        _ => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading stdin")?;
            Ok(buf)
        }
    }
}

fn listen(args: &ListenArgs) -> Result<ExitCode> {
    let pyload = args.pyload.client()?;
    let limit = if args.once {
        Some(1)
    } else {
        args.count.map(|n| n as usize)
    };
    let listener = Listener::bind(args.bind, args.allow_remote)?;
    eprintln!("cnlman: listening on http://{}", listener.local_addr());
    let mut received = 0usize;
    let stop = listener.run(limit, args.timeout.map(Duration::from_secs), |package| {
        received += 1;
        emit(&package, args.output.format, pyload.as_ref())
    })?;
    if stop == Stop::Timeout && received == 0 {
        eprintln!("cnlman: timed out without receiving a package");
        return Ok(ExitCode::from(EXIT_TIMEOUT));
    }
    Ok(ExitCode::SUCCESS)
}

fn extract(args: &ExtractArgs) -> Result<ExitCode> {
    let pyload = args.pyload.client()?;
    let page = read_input(args.file.as_ref())?;
    let candidates = html::find(&page);
    if candidates.is_empty() {
        eprintln!("cnlman: no Click'n'Load payload found");
        return Ok(ExitCode::from(EXIT_NOTHING_FOUND));
    }
    for candidate in candidates {
        let package = candidate.decrypt()?;
        emit(&package, args.output.format, pyload.as_ref())?;
    }
    Ok(ExitCode::SUCCESS)
}

fn decrypt(args: &DecryptArgs) -> Result<ExitCode> {
    let pyload = args.pyload.client()?;
    let crypted = if args.crypted == "-" {
        read_input(None)?
    } else {
        args.crypted.clone()
    };
    let package = Package {
        origin: Origin::Manual,
        name: non_empty(args.name.clone()),
        passwords: None,
        source: None,
        links: crypto::decrypt(&args.jk, &crypted)?,
    };
    emit(&package, args.output.format, pyload.as_ref())?;
    Ok(ExitCode::SUCCESS)
}

fn push(args: &PushArgs) -> Result<ExitCode> {
    let client = args.connection.client()?;
    let links = crypto::split_links(&read_input(args.file.as_ref())?);
    if links.is_empty() {
        bail!("no links given");
    }
    let id = client.add_package(&args.name, &links)?;
    println!(
        "{}",
        serde_json::json!({ "name": args.name, "links": links.len(), "pyload_package_id": id })
    );
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Listen(args) => listen(args),
        Command::Extract(args) => extract(args),
        Command::Decrypt(args) => decrypt(args),
        Command::Push(args) => push(args),
    };
    result.unwrap_or_else(|e| {
        eprintln!("cnlman: error: {e:#}");
        ExitCode::FAILURE
    })
}
