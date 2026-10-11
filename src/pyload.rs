//! Hands packages to a pyLoad server.
//!
//! pyLoad 0.5 authenticates its `/api/*` endpoints with an API key in the
//! `X-API-Key` header (Settings → API); HTTP Basic auth is obsolete there.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde::Serialize;
use ureq::Agent;
use ureq::http::Uri;

/// Where pyLoad files a new package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Destination {
    /// Start downloading right away.
    Queue,
    /// Park the package in the link collector.
    Collector,
}

impl Destination {
    const fn api_value(self) -> u8 {
        match self {
            Self::Queue => 1,
            Self::Collector => 0,
        }
    }
}

/// A configured pyLoad endpoint.
#[derive(Debug, Clone)]
pub struct PyLoad {
    base: String,
    api_key: String,
    destination: Destination,
    agent: Agent,
}

#[derive(Serialize)]
struct AddPackage<'a> {
    name: &'a str,
    links: &'a [String],
    dest: u8,
}

impl PyLoad {
    /// Configures the client.
    ///
    /// The API key is only ever sent over HTTPS or to a host on the local
    /// network (loopback, RFC 1918, unique-local IPv6, `localhost`, `.local`,
    /// `.lan`, `.home.arpa` or a single-label name). `allow_insecure` lifts
    /// that restriction.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be parsed or would send the key in
    /// clear text over a public network.
    pub fn new(
        base: &str,
        api_key: String,
        destination: Destination,
        allow_insecure: bool,
    ) -> Result<Self> {
        let base = base.trim_end_matches('/').to_owned();
        let uri: Uri = base
            .parse()
            .with_context(|| format!("invalid pyLoad URL {base}"))?;
        let scheme = uri.scheme_str().unwrap_or("");
        let host = uri.host().context("pyLoad URL has no host")?;
        match scheme {
            "https" => {}
            "http" if allow_insecure || is_local_host(host) => {}
            "http" => bail!(
                "refusing to send the pyLoad API key over plain HTTP to {host}; \
                 use https or pass --pyload-insecure"
            ),
            other => bail!("unsupported pyLoad URL scheme {other:?}"),
        }
        if api_key.trim().is_empty() {
            bail!("the pyLoad API key is empty");
        }
        let agent = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Ok(Self {
            base,
            api_key,
            destination,
            agent,
        })
    }

    /// Adds a package and returns pyLoad's package id.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or pyLoad rejects it.
    pub fn add_package(&self, name: &str, links: &[String]) -> Result<u64> {
        if links.is_empty() {
            bail!("refusing to add an empty package");
        }
        let url = format!("{}/api/add_package", self.base);
        let body = AddPackage {
            name,
            links,
            dest: self.destination.api_value(),
        };
        let mut response = self
            .agent
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .send_json(&body)
            .map_err(|e| match e {
                ureq::Error::StatusCode(401 | 403) => {
                    anyhow::anyhow!("pyLoad rejected the API key ({url})")
                }
                other => anyhow::anyhow!("pyLoad request to {url} failed: {other}"),
            })?;
        let text = response
            .body_mut()
            .read_to_string()
            .context("reading pyLoad response")?;
        text.trim()
            .parse()
            .with_context(|| format!("unexpected pyLoad response: {}", text.trim()))
    }
}

fn is_local_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
        };
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost"
        || !host.contains('.')
        || [".localhost", ".local", ".lan", ".home.arpa", ".internal"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(url: &str, insecure: bool) -> Result<PyLoad> {
        PyLoad::new(url, "pl_test".into(), Destination::Queue, insecure)
    }

    #[test]
    fn local_http_is_allowed() {
        for url in [
            "http://127.0.0.1:8000",
            "http://[::1]:8000/",
            "http://192.168.1.5:8000",
            "http://nas:8000",
            "http://nas.local:8000",
            "http://pyload.home.arpa",
        ] {
            assert!(client(url, false).is_ok(), "{url}");
        }
    }

    #[test]
    fn public_http_is_refused_unless_forced() {
        assert!(client("http://pyload.example.org", false).is_err());
        assert!(client("http://8.8.8.8:8000", false).is_err());
        assert!(client("http://pyload.example.org", true).is_ok());
        assert!(client("https://pyload.example.org", false).is_ok());
    }

    #[test]
    fn empty_key_and_odd_scheme_are_refused() {
        assert!(PyLoad::new("https://x.org", " ".into(), Destination::Queue, false).is_err());
        assert!(client("ftp://nas", false).is_err());
    }
}
