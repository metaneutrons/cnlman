//! The binary end to end: exit codes and stdout contract.

use std::io::Write as _;
use std::process::{Command, Stdio};

use cnlman::crypto;

const KEY: [u8; 16] = *b"0123456789abcdef";

fn cnlman(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cnlman"))
        .args(args)
        .env_remove("PYLOAD_URL")
        .env_remove("PYLOAD_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[test]
fn extract_prints_one_json_line_per_package() {
    let (_, crypted) = crypto::encrypt(&["https://example.org/x"], KEY);
    let page = format!(
        "<script>CNLPOP('id', '{}', '{crypted}', 'Name');</script>",
        hex::encode(KEY)
    );
    let (code, stdout, _) = cnlman(&["extract"], &page);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["origin"], "cnlpop");
    assert_eq!(value["name"], "Name");
    assert_eq!(value["links"][0], "https://example.org/x");
}

#[test]
fn extract_without_payload_exits_3() {
    let (code, stdout, stderr) = cnlman(&["extract", "-"], "<html></html>");
    assert_eq!(code, 3);
    assert_eq!(stdout, "");
    assert!(stderr.contains("no Click'n'Load payload"));
}

#[test]
fn decrypt_links_format() {
    let (jk, crypted) = crypto::encrypt(&["https://example.org/1", "https://example.org/2"], KEY);
    let (code, stdout, _) = cnlman(
        &[
            "decrypt",
            "--jk",
            &jk,
            "--crypted",
            "-",
            "--format",
            "links",
        ],
        &crypted,
    );
    assert_eq!(code, 0);
    assert_eq!(stdout, "https://example.org/1\nhttps://example.org/2\n");
}

#[test]
fn pyload_without_configuration_fails_before_doing_anything() {
    let (code, stdout, stderr) = cnlman(&["listen", "--pyload", "--bind", "127.0.0.1:0"], "");
    assert_eq!(code, 1);
    assert_eq!(stdout, "");
    assert!(stderr.contains("PYLOAD_URL"));
}

#[test]
fn listen_times_out_with_exit_2() {
    let (code, _, stderr) = cnlman(&["listen", "--bind", "127.0.0.1:0", "--timeout", "1"], "");
    assert_eq!(code, 2);
    assert!(stderr.contains("timed out"));
}
