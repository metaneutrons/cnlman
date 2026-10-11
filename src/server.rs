//! The Click'n'Load HTTP listener.
//!
//! Implements the endpoints a page probes and posts to, the way `JDownloader`
//! answers them:
//!
//! | Request | Answer |
//! | --- | --- |
//! | `GET /jdcheck.js` | `jdownloader=true;`, so the page offers the button |
//! | `GET /crossdomain.xml` | permissive policy for the legacy Flash path |
//! | `GET /`, `GET /flash` | `JDownloader` |
//! | `POST /flash/addcrypted2` | decrypts `jk` + `crypted` |
//! | `POST /flash/add` | plain links in `urls` |
//! | `POST /flash/addcrypted` | DLC, answered with 501 |
//! | `OPTIONS *` | CORS preflight |

use std::collections::HashMap;
use std::io::Read as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::crypto;
use crate::package::{Origin, Package, non_empty};

/// Largest request body accepted; a real package is a few kilobytes.
const MAX_BODY: u64 = 1024 * 1024;

const JDCHECK: &str = "jdownloader=true;\nvar version='cnlman';\n";
const CROSSDOMAIN: &str = "<?xml version=\"1.0\"?>\n<!DOCTYPE cross-domain-policy SYSTEM \
    \"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd\">\n<cross-domain-policy>\n\
    <allow-access-from domain=\"*\" />\n</cross-domain-policy>\n";

/// Why [`Listener::run`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The requested number of packages arrived.
    Count,
    /// The timeout elapsed first.
    Timeout,
}

/// A bound Click'n'Load listener.
pub struct Listener {
    server: Server,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("addr", &self.server.server_addr())
            .finish()
    }
}

impl Listener {
    /// Binds the listener.
    ///
    /// Click'n'Load lets any page in the browser post to this port, so a
    /// non-loopback address also lets any machine on the network inject links.
    /// It is refused unless `allow_remote` is set.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is not loopback without `allow_remote`,
    /// or if binding fails, typically because another CNL client holds the
    /// port.
    pub fn bind(addr: SocketAddr, allow_remote: bool) -> Result<Self> {
        if !addr.ip().is_loopback() && !allow_remote {
            bail!(
                "refusing to listen on non-loopback address {addr}; pass --allow-remote to override"
            );
        }
        let server = Server::http(addr).map_err(|e| {
            anyhow::anyhow!(
                "cannot listen on {addr}: {e} (is JDownloader, pyLoad or Swinkl running?)"
            )
        })?;
        Ok(Self { server })
    }

    /// The address actually bound, useful with port 0.
    ///
    /// # Panics
    ///
    /// Panics if the server is not bound to an IP socket, which cannot happen
    /// for a listener created by [`Listener::bind`].
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.server
            .server_addr()
            .to_ip()
            .expect("bound to an IP address")
    }

    /// Serves requests and hands every decoded package to `on_package` until
    /// `limit` packages arrived (unlimited if `None`) or `timeout` elapsed.
    ///
    /// # Errors
    ///
    /// Returns an error if receiving fails or `on_package` fails.
    pub fn run(
        &self,
        limit: Option<usize>,
        timeout: Option<Duration>,
        mut on_package: impl FnMut(Package) -> Result<()>,
    ) -> Result<Stop> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut received = 0usize;
        loop {
            if limit.is_some_and(|l| received >= l) {
                return Ok(Stop::Count);
            }
            let request = match deadline {
                Some(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Ok(Stop::Timeout);
                    }
                    match self
                        .server
                        .recv_timeout(left)
                        .context("receiving request")?
                    {
                        Some(r) => r,
                        None => return Ok(Stop::Timeout),
                    }
                }
                None => self.server.recv().context("receiving request")?,
            };
            if let Some(package) = handle(request) {
                received += 1;
                on_package(package)?;
            }
        }
    }
}

/// Answers one request; returns the package it carried, if any.
fn handle(mut request: Request) -> Option<Package> {
    let path = request.url().split('?').next().unwrap_or("").to_owned();
    let method = request.method().clone();
    eprintln!("cnlman: {method} {path}");
    let (response, package) = match (&method, path.as_str()) {
        (Method::Options, _) => (text(200, ""), None),
        (Method::Get, "/jdcheck.js") => (typed(200, JDCHECK, "text/javascript"), None),
        (Method::Get, "/crossdomain.xml") => (typed(200, CROSSDOMAIN, "text/xml"), None),
        (Method::Get, "/" | "/flash" | "/flash/") => (text(200, "JDownloader\r\n"), None),
        (Method::Post, "/flash/addcrypted2" | "/flash/add") => {
            let referer = header(&request, "Referer");
            match read_form(&mut request).and_then(|form| decode(&path, form, referer)) {
                Ok(package) => {
                    eprintln!("cnlman: received {} link(s)", package.links.len());
                    (text(200, "success\r\n"), Some(package))
                }
                Err(e) => {
                    eprintln!("cnlman: rejected: {e:#}");
                    (text(400, &format!("failed {e}\r\n")), None)
                }
            }
        }
        (Method::Post, "/flash/addcrypted") => (text(501, "failed DLC is not supported\r\n"), None),
        _ => (text(404, "not found\r\n"), None),
    };
    if let Err(e) = request.respond(response) {
        eprintln!("cnlman: cannot answer {path}: {e}");
    }
    package
}

fn decode(
    path: &str,
    mut form: HashMap<String, String>,
    referer: Option<String>,
) -> Result<Package> {
    let name = non_empty(form.remove("package"));
    let passwords = non_empty(form.remove("passwords"));
    let source = non_empty(form.remove("source")).or(referer);
    let (origin, links) = if path == "/flash/add" {
        let urls = form.remove("urls").unwrap_or_default();
        (Origin::Add, crypto::split_links(&urls))
    } else {
        let jk = form
            .remove("jk")
            .filter(|v| !v.is_empty())
            .context("missing jk")?;
        let crypted = form.remove("crypted").filter(|v| !v.is_empty()).context(
            "missing crypted (an empty value usually means the browser blocked the post)",
        )?;
        (Origin::Addcrypted2, crypto::decrypt(&jk, &crypted)?)
    };
    if links.is_empty() {
        bail!("package contains no links");
    }
    Ok(Package {
        origin,
        name,
        passwords,
        source,
        links,
    })
}

fn read_form(request: &mut Request) -> Result<HashMap<String, String>> {
    let mut body = Vec::new();
    request
        .as_reader()
        .take(MAX_BODY + 1)
        .read_to_end(&mut body)
        .context("reading body")?;
    if body.len() as u64 > MAX_BODY {
        bail!("request body exceeds {MAX_BODY} bytes");
    }
    Ok(form_urlencoded::parse(&body).into_owned().collect())
}

fn header(request: &Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_owned())
}

fn text(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    typed(status, body, "text/plain")
}

fn typed(status: u16, body: &str, content_type: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let content_type = format!("{content_type}; charset=utf-8");
    let headers = [
        ("Content-Type", content_type.as_str()),
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
        ("Access-Control-Allow-Headers", "Content-Type"),
        ("Access-Control-Allow-Private-Network", "true"),
    ];
    headers.into_iter().fold(
        Response::from_string(body).with_status_code(status),
        |r, (k, v)| r.with_header(Header::from_bytes(k, v).expect("static header is valid")),
    )
}
