use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

fn spawn_server() -> (Child, String, PathBuf) {
    let probe = TcpListener::bind("127.0.0.1:0").expect("ephemeral bind should work");
    let port = probe.local_addr().expect("local addr should exist").port();
    drop(probe);
    let addr = format!("127.0.0.1:{port}");
    let store = PathBuf::from(format!("/tmp/live_server_test_{port}.json"));
    let _ = fs::remove_file(&store);
    let _ = fs::remove_file(store.with_extension("lock"));

    let child = Command::new(env!("CARGO_BIN_EXE_live_server"))
        .env("LIVE_HOST", "127.0.0.1")
        .env("LIVE_PORT", port.to_string())
        .env("LIVE_STORE", store.display().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("server should spawn");

    let start = std::time::Instant::now();
    loop {
        if TcpStream::connect(&addr).is_ok() {
            break;
        }
        if start.elapsed() > Duration::from_secs(5) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    (child, addr, store)
}

fn request(addr: &str, raw: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect should work");
    stream
        .write_all(raw.as_bytes())
        .expect("write request should work");
    let mut out = Vec::new();
    stream
        .read_to_end(&mut out)
        .expect("read response should work");
    String::from_utf8_lossy(&out).to_string()
}

fn body(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or("")
}

#[test]
fn live_server_health_and_ready() {
    let (mut child, addr, store) = spawn_server();

    let health = request(
        &addr,
        &format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    );
    assert!(health.starts_with("HTTP/1.1 200"));
    assert!(body(&health).contains("ok"));

    let ready = request(
        &addr,
        &format!("GET /readyz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    );
    assert!(ready.starts_with("HTTP/1.1 200"));

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&store);
    let _ = fs::remove_file(store.with_extension("lock"));
}

#[test]
fn live_server_crud_and_metrics() {
    let (mut child, addr, store) = spawn_server();

    let put_body = "{\"value\":\"world\"}";
    let put = request(
        &addr,
        &format!(
            "PUT /v1/items/hello HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            put_body.len(),
            put_body
        ),
    );
    assert!(put.starts_with("HTTP/1.1 200"));

    let get = request(
        &addr,
        &format!("GET /v1/items/hello HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    );
    assert!(get.starts_with("HTTP/1.1 200"));
    assert!(body(&get).contains("world"));

    let metrics = request(
        &addr,
        &format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    );
    assert!(metrics.starts_with("HTTP/1.1 200"));
    assert!(body(&metrics).contains("http_request_total"));

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&store);
    let _ = fs::remove_file(store.with_extension("lock"));
}
