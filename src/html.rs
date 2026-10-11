//! Extracts Click'n'Load payloads from page HTML.
//!
//! The button on a link-protector page only wraps values that are already in
//! the markup into a form and posts it to the local listener. Reading them from
//! the page source makes the listener, the open port and the click optional.
//!
//! Two shapes are recognised:
//!
//! - filecrypt's `CNLPOP('<id>', '<hex key>', '<crypted>', '<package>')`
//! - hidden form inputs named `jk` and `crypted`, optionally with `package`,
//!   `passwords` and `source`

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::crypto::{self, CryptoError};
use crate::package::{Origin, Package, non_empty};

/// A JavaScript string literal in single or double quotes, escapes included.
const JS_STRING: &str = r#"(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")"#;

static CNLPOP: LazyLock<Regex> = LazyLock::new(|| {
    let s = JS_STRING;
    Regex::new(&format!(
        r"CNLPOP\s*\(\s*({s})\s*,\s*({s})\s*,\s*({s})(?:\s*,\s*({s}))?"
    ))
    .expect("static regex is valid")
});

static INPUT_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<input\b[^>]*>").expect("static regex is valid"));

static ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)([a-z_:][-a-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#)
        .expect("static regex is valid")
});

/// One payload found in the page, before decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Which pattern matched.
    pub origin: Origin,
    /// The `jk` value or bare hex key.
    pub jk: String,
    /// Base64 ciphertext.
    pub crypted: String,
    /// Package name, if present.
    pub name: Option<String>,
    /// Archive passwords, if present.
    pub passwords: Option<String>,
    /// Source page, if present.
    pub source: Option<String>,
}

impl Candidate {
    /// Decrypts the candidate into a package.
    ///
    /// # Errors
    ///
    /// Returns the decryption error if the payload is malformed.
    pub fn decrypt(self) -> Result<Package, CryptoError> {
        Ok(Package {
            origin: self.origin,
            links: crypto::decrypt(&self.jk, &self.crypted)?,
            name: non_empty(self.name),
            passwords: non_empty(self.passwords),
            source: non_empty(self.source),
        })
    }
}

/// Finds every Click'n'Load payload in `html`, in document order per shape,
/// with duplicates removed.
#[must_use]
pub fn find(html: &str) -> Vec<Candidate> {
    let mut found = cnlpop_calls(html);
    found.extend(form_inputs(html));
    let mut seen = std::collections::HashSet::new();
    found.retain(|c| seen.insert((c.jk.clone(), c.crypted.clone())));
    found
}

fn cnlpop_calls(html: &str) -> Vec<Candidate> {
    CNLPOP
        .captures_iter(html)
        .map(|c| Candidate {
            origin: Origin::Cnlpop,
            jk: unquote_js(&c[2]),
            crypted: unquote_js(&c[3]),
            name: c.get(4).map(|m| unquote_js(m.as_str())),
            passwords: None,
            source: None,
        })
        .collect()
}

/// Groups hidden inputs into packages: a package is complete once both `jk`
/// and `crypted` have been seen; a repeated name starts the next one.
fn form_inputs(html: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut fields: HashMap<String, String> = HashMap::new();
    for tag in INPUT_TAG.find_iter(html) {
        let attrs = attributes(tag.as_str());
        let (Some(name), Some(value)) = (attrs.get("name"), attrs.get("value")) else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        if !matches!(
            name.as_str(),
            "jk" | "crypted" | "package" | "passwords" | "source"
        ) {
            continue;
        }
        if fields.contains_key(&name) {
            flush(&mut fields, &mut out);
            fields.clear();
        }
        fields.insert(name, value.clone());
    }
    flush(&mut fields, &mut out);
    out
}

fn flush(fields: &mut HashMap<String, String>, out: &mut Vec<Candidate>) {
    if let (Some(jk), Some(crypted)) = (fields.get("jk"), fields.get("crypted")) {
        out.push(Candidate {
            origin: Origin::Form,
            jk: jk.clone(),
            crypted: crypted.clone(),
            name: fields.remove("package"),
            passwords: fields.remove("passwords"),
            source: fields.remove("source"),
        });
    }
}

fn attributes(tag: &str) -> HashMap<String, String> {
    ATTRIBUTE
        .captures_iter(tag)
        .map(|c| {
            let value = c
                .get(2)
                .or_else(|| c.get(3))
                .or_else(|| c.get(4))
                .map_or("", |m| m.as_str());
            (c[1].to_ascii_lowercase(), decode_entities(value))
        })
        .collect()
}

/// Strips the quotes of a JavaScript string literal and resolves the escapes
/// that occur in practice.
fn unquote_js(literal: &str) -> String {
    let inner = &literal[1..literal.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    decode_entities(&out)
}

/// Resolves the handful of HTML entities that appear in attribute values and
/// inline handlers.
fn decode_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_owned();
    }
    value
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#039;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = *b"0123456789abcdef";

    #[test]
    fn finds_a_cnlpop_call() {
        let (_, crypted) = crypto::encrypt(&["https://example.org/1"], KEY);
        let html = format!(
            r#"<form onsubmit="try {{ CNLPOP('ABC', '{}', '{crypted}', 'My \'pkg\''); }} catch(e){{}}">"#,
            hex::encode(KEY)
        );
        let found = find(&html);
        assert_eq!(found.len(), 1);
        let package = found[0].clone().decrypt().unwrap();
        assert_eq!(package.origin, Origin::Cnlpop);
        assert_eq!(package.name.as_deref(), Some("My 'pkg'"));
        assert_eq!(package.links, ["https://example.org/1"]);
    }

    #[test]
    fn finds_hidden_inputs_in_any_attribute_order() {
        let (jk, crypted) = crypto::encrypt(&["https://example.org/2"], KEY);
        let jk = jk.replace('\'', "&#39;");
        let html = format!(
            r#"<form><input type="hidden" value="{jk}" name="jk">
               <INPUT NAME='crypted' TYPE=hidden VALUE='{crypted}'>
               <input name="package" value="Pkg &amp; Co" type="hidden"></form>"#
        );
        let found = find(&html);
        assert_eq!(found.len(), 1);
        let package = found[0].clone().decrypt().unwrap();
        assert_eq!(package.origin, Origin::Form);
        assert_eq!(package.name.as_deref(), Some("Pkg & Co"));
        assert_eq!(package.links, ["https://example.org/2"]);
    }

    #[test]
    fn separates_two_forms_and_drops_duplicates() {
        let (jk1, c1) = crypto::encrypt(&["https://example.org/a"], KEY);
        let (jk2, c2) = crypto::encrypt(&["https://example.org/b"], KEY);
        let form = |jk: &str, c: &str| {
            format!(
                r#"<input name="jk" value="{}"><input name="crypted" value="{c}">"#,
                jk.replace('\'', "&#39;")
            )
        };
        let html = [form(&jk1, &c1), form(&jk2, &c2), form(&jk1, &c1)].concat();
        assert_eq!(find(&html).len(), 2);
    }

    #[test]
    fn page_without_payload_yields_nothing() {
        assert_eq!(
            find("<html><body><input name=q value=x></body></html>"),
            Vec::new()
        );
    }
}
