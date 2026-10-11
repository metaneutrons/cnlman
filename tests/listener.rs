//! The listener over a real socket, the way a browser talks to it.

use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use cnlman::crypto;
use cnlman::package::Origin;
use cnlman::server::{Listener, Stop};

const KEY: [u8; 16] = *b"0123456789abcdef";

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

#[test]
fn addcrypted2_post_yields_the_package() {
    let listener = Listener::bind(loopback(), false).unwrap();
    let base = format!("http://{}", listener.local_addr());
    let (jk, crypted) = crypto::encrypt(&["https://example.org/a", "https://example.org/b"], KEY);

    let client = thread::spawn(move || {
        let agent = agent();
        let check = agent.get(format!("{base}/jdcheck.js")).call().unwrap();
        let check = check.into_body().read_to_string().unwrap();
        let mut post = agent
            .post(format!("{base}/flash/addcrypted2"))
            .header("Referer", "https://example.org/container")
            .send_form([
                ("jk", jk.as_str()),
                ("crypted", crypted.as_str()),
                ("package", "Pkg"),
            ])
            .unwrap();
        (
            check,
            post.status().as_u16(),
            post.body_mut().read_to_string().unwrap(),
        )
    });

    let mut packages = Vec::new();
    let stop = listener
        .run(Some(1), Some(Duration::from_secs(10)), |p| {
            packages.push(p);
            Ok(())
        })
        .unwrap();
    let (check, status, body) = client.join().unwrap();

    assert_eq!(stop, Stop::Count);
    assert!(check.contains("jdownloader=true"));
    assert_eq!((status, body.trim()), (200, "success"));
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].origin, Origin::Addcrypted2);
    assert_eq!(packages[0].name.as_deref(), Some("Pkg"));
    assert_eq!(
        packages[0].source.as_deref(),
        Some("https://example.org/container")
    );
    assert_eq!(
        packages[0].links,
        ["https://example.org/a", "https://example.org/b"]
    );
}

#[test]
fn plain_add_and_bad_payload() {
    let listener = Listener::bind(loopback(), false).unwrap();
    let base = format!("http://{}", listener.local_addr());

    let client = thread::spawn(move || {
        let agent = agent();
        let bad = agent
            .post(format!("{base}/flash/addcrypted2"))
            .send_form([("jk", "return 'zz'"), ("crypted", "AAAA")])
            .unwrap()
            .status()
            .as_u16();
        let dlc = agent
            .post(format!("{base}/flash/addcrypted"))
            .send_form([("crypted", "x")]);
        let ok = agent
            .post(format!("{base}/flash/add"))
            .send_form([("urls", "https://example.org/1\r\nhttps://example.org/2")])
            .unwrap()
            .status()
            .as_u16();
        (bad, dlc.unwrap().status().as_u16(), ok)
    });

    let mut packages = Vec::new();
    listener
        .run(Some(1), Some(Duration::from_secs(10)), |p| {
            packages.push(p);
            Ok(())
        })
        .unwrap();
    let (bad, dlc, ok) = client.join().unwrap();

    assert_eq!((bad, dlc, ok), (400, 501, 200));
    assert_eq!(packages.len(), 1, "the rejected post must not count");
    assert_eq!(packages[0].origin, Origin::Add);
    assert_eq!(
        packages[0].links,
        ["https://example.org/1", "https://example.org/2"]
    );
}

#[test]
fn timeout_stops_the_listener() {
    let listener = Listener::bind(loopback(), false).unwrap();
    let stop = listener
        .run(None, Some(Duration::from_millis(200)), |_| Ok(()))
        .unwrap();
    assert_eq!(stop, Stop::Timeout);
}

#[test]
fn non_loopback_bind_needs_consent() {
    let err = Listener::bind("0.0.0.0:0".parse().unwrap(), false).unwrap_err();
    assert!(err.to_string().contains("--allow-remote"));
}
