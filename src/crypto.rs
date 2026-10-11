//! Click'n'Load 2 cryptography.
//!
//! A CNL2 package carries two values: `jk`, a JavaScript function whose return
//! value is the AES key in hex, and `crypted`, the base64 ciphertext. The
//! cipher is AES-128-CBC with the key doubling as the IV. The plaintext is the
//! link list, separated by line breaks and filled to the block size either
//! with NUL bytes or, as filecrypt does, with PKCS#7 padding.

use std::sync::LazyLock;

use aes::Aes128;
use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use regex::Regex;

type Decryptor = cbc::Decryptor<Aes128>;
type Encryptor = cbc::Encryptor<Aes128>;

const KEY_LEN: usize = 16;

/// Standard alphabet that tolerates missing `=` padding, which some
/// senders strip.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Matches the hex literal a `jk` function returns, e.g.
/// `function f(){ return '3132…'; }`.
static JK_RETURN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"return\s*\(?\s*["']([0-9A-Fa-f]+)["']"#).expect("static regex is valid")
});

/// Errors from decoding a CNL2 package.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// `jk` held neither a bare hex key nor a function returning one.
    #[error("cannot find a hex key in jk; expected a bare hex string or `return '<hex>'`")]
    NoKey,
    /// The hex key does not decode to exactly 16 bytes.
    #[error("the key must be {KEY_LEN} bytes (AES-128), got {0}")]
    KeyLength(usize),
    /// The key is not valid hex.
    #[error("the key is not valid hex: {0}")]
    KeyHex(#[from] hex::FromHexError),
    /// `crypted` is not valid base64.
    #[error("crypted is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The ciphertext length is not a multiple of the block size.
    #[error("ciphertext length {0} is not a multiple of 16")]
    BlockLength(usize),
    /// The plaintext is not UTF-8, which almost always means a wrong key.
    #[error("decrypted data is not UTF-8; the key is probably wrong")]
    NotUtf8,
}

/// Extracts the 16-byte AES key from a `jk` value.
///
/// Accepts the usual `function f(){ return '<hex>'; }` form as well as a bare
/// hex string, so that a key copied out of a page can be used directly.
///
/// # Errors
///
/// Returns an error if no hex key is found or it is not 16 bytes long.
pub fn key_from_jk(jk: &str) -> Result<[u8; KEY_LEN], CryptoError> {
    let trimmed = jk.trim();
    let hex_key = if !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        trimmed
    } else {
        JK_RETURN
            .captures(trimmed)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .ok_or(CryptoError::NoKey)?
    };
    let bytes = hex::decode(hex_key)?;
    <[u8; KEY_LEN]>::try_from(bytes.as_slice()).map_err(|_| CryptoError::KeyLength(bytes.len()))
}

/// Decrypts a CNL2 package and returns its links.
///
/// # Errors
///
/// Returns an error if the key or the ciphertext is malformed, or the
/// plaintext is not UTF-8.
pub fn decrypt(jk: &str, crypted: &str) -> Result<Vec<String>, CryptoError> {
    let key = key_from_jk(jk)?;
    // Base64 has no whitespace; a space here is a `+` that a sloppy client
    // left unescaped in a form body.
    let cleaned: String = crypted
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\t'))
        .map(|c| if c == ' ' { '+' } else { c })
        .collect();
    let mut buf = LENIENT.decode(cleaned.trim())?;
    if buf.len() % KEY_LEN != 0 {
        return Err(CryptoError::BlockLength(buf.len()));
    }
    let len = buf.len();
    let plain = Decryptor::new(&key.into(), &key.into())
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| CryptoError::BlockLength(len))?;
    let text = std::str::from_utf8(strip_pkcs7(plain)).map_err(|_| CryptoError::NotUtf8)?;
    Ok(split_links(text))
}

/// Removes PKCS#7 padding if the plaintext carries a valid one.
///
/// Senders disagree on padding: some fill the last block with NUL bytes,
/// filecrypt uses PKCS#7. A valid PKCS#7 tail is `n` bytes of value `n`
/// with `1 <= n <= 16`; link text never ends in such a run, so the check
/// cannot cut into a link. Anything else is returned unchanged and NUL
/// padding is left for [`split_links`].
fn strip_pkcs7(plain: &[u8]) -> &[u8] {
    let Some(&last) = plain.last() else {
        return plain;
    };
    let n = usize::from(last);
    if (1..=KEY_LEN).contains(&n)
        && n <= plain.len()
        && plain[plain.len() - n..].iter().all(|&b| b == last)
    {
        &plain[..plain.len() - n]
    } else {
        plain
    }
}

/// Splits a decrypted or plain link list into individual links.
#[must_use]
pub fn split_links(text: &str) -> Vec<String> {
    text.split(|c: char| c.is_whitespace() || c == '\0')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Encrypts links into a CNL2 `(jk, crypted)` pair with the given key.
///
/// This is the inverse of [`decrypt`]; it exists for tests and for feeding
/// the listener in a self-check.
///
/// # Panics
///
/// Does not panic in practice: the buffer is padded to the block size before
/// encryption, which is the only failure condition of unpadded CBC.
#[must_use]
pub fn encrypt(links: &[&str], key: [u8; KEY_LEN]) -> (String, String) {
    let mut buf = links.join("\r\n").into_bytes();
    let padded = buf.len().div_ceil(KEY_LEN).max(1) * KEY_LEN;
    buf.resize(padded, 0);
    let len = buf.len();
    let cipher = Encryptor::new(&key.into(), &key.into())
        .encrypt_padded::<NoPadding>(&mut buf, len)
        .expect("buffer is block aligned");
    let jk = format!("function f(){{ return '{}';}}", hex::encode(key));
    (jk, STANDARD.encode(cipher))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = *b"0123456789abcdef";

    #[test]
    fn round_trip() {
        let links = ["https://example.org/a", "https://example.org/b"];
        let (jk, crypted) = encrypt(&links, KEY);
        assert_eq!(decrypt(&jk, &crypted).unwrap(), links);
    }

    /// Produced independently with
    /// `openssl enc -aes-128-cbc -K <key> -iv <key> -nopad` over the
    /// NUL-padded plaintext; the release smoke test uses the same vector.
    #[test]
    fn decrypts_an_openssl_vector() {
        let crypted = "RnATJ+qxAkpHoFYfjZKfGIoMKq9yo6hLgc5BX1Qe/6qUNj/2AN1z0oQMNXP9K7qwLHW2sRDDJb8R3VaX/+cC8Q==";
        let links = decrypt("30313233343536373839616263646566", crypted).unwrap();
        assert_eq!(
            links,
            ["https://example.org/smoke", "https://example.org/test"]
        );
    }

    /// Produced with `openssl enc -aes-128-cbc -K <key> -iv <key>` and its
    /// default PKCS#7 padding, as filecrypt sends it. The first vector ends
    /// in eight `0x08` bytes right after the last link, the second in a
    /// whole block of `0x10`; neither pad byte is whitespace.
    #[test]
    fn strips_pkcs7_padding() {
        let cases = [
            (
                "RnATJ+qxAkpHoFYfjZKfGIoMKq9yo6hLgc5BX1Qe/6qUNj/2AN1z0oQMNXP9K7qw/4DLUlSvGM+FQOs+zRM2jw==",
                "https://example.org/test-pads",
            ),
            (
                "RnATJ+qxAkpHoFYfjZKfGIoMKq9yo6hLgc5BX1Qe/6qUNj/2AN1z0oQMNXP9K7qwYjz/0yMKanc3rpOMm0gVmw==",
                "https://example.org/t",
            ),
        ];
        for (crypted, last) in cases {
            let links = decrypt("30313233343536373839616263646566", crypted).unwrap();
            assert_eq!(links, ["https://example.org/smoke", last]);
        }
    }

    #[test]
    fn plaintext_without_padding_is_kept() {
        assert_eq!(strip_pkcs7(b"abc"), b"abc");
        assert_eq!(strip_pkcs7(b"abc\0\0"), b"abc\0\0");
        // The last byte claims more padding than the bytes before it hold.
        assert_eq!(strip_pkcs7(b"ab\x03\x03"), b"ab\x03\x03");
        assert_eq!(strip_pkcs7(b""), b"");
    }

    #[test]
    fn bare_hex_key_is_accepted() {
        let (_, crypted) = encrypt(&["https://example.org/x"], KEY);
        assert_eq!(
            decrypt(&hex::encode(KEY), &crypted).unwrap(),
            ["https://example.org/x"]
        );
    }

    #[test]
    fn spaces_in_crypted_are_read_as_plus() {
        // Find a key/link pair whose ciphertext contains a '+'.
        let (jk, crypted) = (0u8..=255)
            .map(|i| {
                let mut k = KEY;
                k[0] = i;
                encrypt(&["https://example.org/plus"], k)
            })
            .find(|(_, c)| c.contains('+'))
            .unwrap();
        assert!(decrypt(&jk, &crypted.replace('+', " ")).is_ok());
    }

    #[test]
    fn wrong_key_is_rejected_or_garbled() {
        let (_, crypted) = encrypt(&["https://example.org/a"], KEY);
        let other = hex::encode(*b"fedcba9876543210");
        let result = decrypt(&other, &crypted);
        assert!(result.map_or(true, |l| l != ["https://example.org/a"]));
    }

    #[test]
    fn short_key_is_rejected() {
        assert!(matches!(
            key_from_jk("return '0011'"),
            Err(CryptoError::KeyLength(2))
        ));
    }

    #[test]
    fn missing_key_is_rejected() {
        assert!(matches!(
            key_from_jk("function f(){ return x; }"),
            Err(CryptoError::NoKey)
        ));
    }

    #[test]
    fn misaligned_ciphertext_is_rejected() {
        let crypted = STANDARD.encode([0u8; 15]);
        assert!(matches!(
            decrypt(&hex::encode(KEY), &crypted),
            Err(CryptoError::BlockLength(15))
        ));
    }
}
