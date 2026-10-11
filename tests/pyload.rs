//! The pyLoad client against a stand-in server.

use std::thread;

use cnlman::pyload::{Destination, PyLoad};
use tiny_http::{Response, Server};

/// Serves one request, records it and answers with `status` and `body`.
fn one_shot(
    status: u16,
    body: &'static str,
) -> (String, thread::JoinHandle<(String, String, String)>) {
    let server = Server::http("127.0.0.1:0").unwrap();
    let base = format!("http://{}", server.server_addr().to_ip().unwrap());
    let handle = thread::spawn(move || {
        let mut request = server.recv().unwrap();
        let key = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-API-Key"))
            .map(|h| h.value.to_string())
            .unwrap_or_default();
        let mut payload = String::new();
        request.as_reader().read_to_string(&mut payload).unwrap();
        let url = request.url().to_owned();
        request
            .respond(Response::from_string(body).with_status_code(status))
            .unwrap();
        (url, key, payload)
    });
    (base, handle)
}

#[test]
fn add_package_sends_key_and_payload() {
    let (base, server) = one_shot(200, "42\n");
    let client = PyLoad::new(&base, "pl_secret".into(), Destination::Collector, false).unwrap();
    let id = client
        .add_package("Pkg", &["https://example.org/a".into()])
        .unwrap();
    let (url, key, payload) = server.join().unwrap();

    assert_eq!(id, 42);
    assert_eq!(url, "/api/add_package");
    assert_eq!(key, "pl_secret");
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        payload,
        serde_json::json!({
            "name": "Pkg", "links": ["https://example.org/a"], "dest": 0
        })
    );
}

#[test]
fn rejected_key_is_reported_as_such() {
    let (base, server) = one_shot(401, "Obsolete API");
    let client = PyLoad::new(&base, "pl_wrong".into(), Destination::Queue, false).unwrap();
    let err = client
        .add_package("Pkg", &["https://example.org/a".into()])
        .unwrap_err();
    server.join().unwrap();
    assert!(err.to_string().contains("rejected the API key"), "{err}");
}

#[test]
fn unexpected_answer_is_an_error() {
    let (base, server) = one_shot(200, "<html>login</html>");
    let client = PyLoad::new(&base, "pl_x".into(), Destination::Queue, false).unwrap();
    assert!(
        client
            .add_package("Pkg", &["https://example.org/a".into()])
            .is_err()
    );
    server.join().unwrap();
}
