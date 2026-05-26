use std::collections::BTreeMap;
use std::io::Read;
use std::process::Stdio;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use crate::{Finding, FindingKind};

#[derive(Debug)]
pub(crate) enum HostProcDispatch {
    Completed(HostProcOutput),
    TimedOut { stdout: String, stderr: String },
}

#[derive(Debug)]
pub(crate) struct HostProcOutput {
    pub(crate) exit_code: i32,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

#[derive(Debug)]
pub(crate) enum HostHttpDispatch {
    Completed(HostHttpResponse),
    TimedOut,
}

#[derive(Debug, Clone)]
pub(crate) struct HostHttpResponse {
    pub(crate) status: u16,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) body: String,
}

#[derive(Debug)]
enum StreamReadError {
    Io(String),
    LimitExceeded { observed: usize, limit: usize },
}

const HOST_PROC_MAX_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const HOST_PROC_MAX_STDERR_BYTES: usize = 8 * 1024 * 1024;
const HOST_HTTP_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

fn spawn_stream_reader<T>(
    mut stream: T,
    max_bytes: usize,
) -> (
    Arc<Mutex<Vec<u8>>>,
    mpsc::Receiver<Result<(), StreamReadError>>,
)
where
    T: Read + Send + 'static,
{
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        let mut total = 0usize;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => {
                    let _ = tx.send(Ok(()));
                    return;
                }
                Ok(n) => {
                    total = total.saturating_add(n);
                    if let Ok(mut guard) = writer.lock() {
                        let remaining = max_bytes.saturating_sub(guard.len());
                        guard.extend_from_slice(&chunk[..n.min(remaining)]);
                    }
                    if total > max_bytes {
                        let _ = tx.send(Err(StreamReadError::LimitExceeded {
                            observed: total,
                            limit: max_bytes,
                        }));
                        return;
                    }
                }
                Err(err) => {
                    let _ = tx.send(Err(StreamReadError::Io(err.to_string())));
                    return;
                }
            }
        }
    });
    (buffer, rx)
}

fn snapshot_stream(buffer: &Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
    buffer.lock().map(|guard| guard.clone()).unwrap_or_default()
}

fn wait_stream_reader(
    rx: &mpsc::Receiver<Result<(), StreamReadError>>,
    label: &str,
    invocation: &str,
) -> Result<(), String> {
    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(StreamReadError::Io(err))) => Err(format!(
            "host proc {label} read failed for {invocation}: {err}"
        )),
        Ok(Err(StreamReadError::LimitExceeded { observed, limit })) => Err(format!(
            "host proc {label} exceeded limit for {invocation}: {observed} bytes > {limit} bytes"
        )),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "host proc {label} reader did not flush after process exit for {invocation}"
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(format!(
            "host proc {label} reader disconnected for {invocation}"
        )),
    }
}

fn poll_stream_reader(
    rx: &mpsc::Receiver<Result<(), StreamReadError>>,
    label: &str,
    invocation: &str,
) -> Result<bool, String> {
    match rx.try_recv() {
        Ok(Ok(())) => Ok(true),
        Ok(Err(StreamReadError::Io(err))) => Err(format!(
            "host proc {label} read failed for {invocation}: {err}"
        )),
        Ok(Err(StreamReadError::LimitExceeded { observed, limit })) => Err(format!(
            "host proc {label} exceeded limit for {invocation}: {observed} bytes > {limit} bytes"
        )),
        Err(mpsc::TryRecvError::Empty) => Ok(false),
        Err(mpsc::TryRecvError::Disconnected) => Err(format!(
            "host proc {label} reader disconnected for {invocation}"
        )),
    }
}

pub(crate) fn dispatch_host_proc(
    cmd: &str,
    args: &[String],
    deadline: Option<Instant>,
) -> Result<HostProcDispatch, String> {
    let invocation = if args.is_empty() {
        format!("{cmd:?}")
    } else {
        format!("{cmd:?} {:?}", args)
    };
    let mut child = std::process::Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("host proc spawn failed for {cmd:?} {:?}: {e}", args))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("host proc stdout pipe missing for {invocation}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("host proc stderr pipe missing for {invocation}"))?;
    let (stdout_buf, stdout_rx) = spawn_stream_reader(stdout, HOST_PROC_MAX_STDOUT_BYTES);
    let (stderr_buf, stderr_rx) = spawn_stream_reader(stderr, HOST_PROC_MAX_STDERR_BYTES);

    loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            let _ = child.kill();
            let _ = child.wait();
            let _ = wait_stream_reader(&stdout_rx, "stdout", &invocation);
            let _ = wait_stream_reader(&stderr_rx, "stderr", &invocation);
            return Ok(HostProcDispatch::TimedOut {
                stdout: String::from_utf8_lossy(&snapshot_stream(&stdout_buf)).to_string(),
                stderr: String::from_utf8_lossy(&snapshot_stream(&stderr_buf)).to_string(),
            });
        }

        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("host proc wait failed for {invocation}: {e}"))?
        {
            wait_stream_reader(&stdout_rx, "stdout", &invocation)?;
            wait_stream_reader(&stderr_rx, "stderr", &invocation)?;
            return Ok(HostProcDispatch::Completed(HostProcOutput {
                exit_code: status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&snapshot_stream(&stdout_buf)).to_string(),
                stderr: String::from_utf8_lossy(&snapshot_stream(&stderr_buf)).to_string(),
            }));
        }

        let stdout_done = poll_stream_reader(&stdout_rx, "stdout", &invocation)?;
        let stderr_done = poll_stream_reader(&stderr_rx, "stderr", &invocation)?;
        if stdout_done && stderr_done {
            let status = child
                .wait()
                .map_err(|e| format!("host proc wait failed for {invocation}: {e}"))?;
            return Ok(HostProcDispatch::Completed(HostProcOutput {
                exit_code: status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&snapshot_stream(&stdout_buf)).to_string(),
                stderr: String::from_utf8_lossy(&snapshot_stream(&stderr_buf)).to_string(),
            }));
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn canonical_headers(
    headers: Option<&BTreeMap<String, String>>,
) -> Result<BTreeMap<String, String>, Finding> {
    let mut out = BTreeMap::new();
    let Some(headers) = headers else {
        return Ok(out);
    };
    for (k, v) in headers {
        let key = k.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(Finding {
                kind: FindingKind::Checker,
                title: "http_header_invalid".to_string(),
                message: "http header name cannot be empty".to_string(),
                location: None,
            });
        }
        if key.contains('\n') || key.contains('\r') || v.contains('\n') || v.contains('\r') {
            return Err(Finding {
                kind: FindingKind::Checker,
                title: "http_header_invalid".to_string(),
                message: format!("http header contains forbidden newline: {k:?}"),
                location: None,
            });
        }
        out.insert(key, v.to_string());
    }
    Ok(out)
}

pub(crate) fn dispatch_host_http(
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&str>,
    timeout: Option<Duration>,
) -> Result<HostHttpDispatch, String> {
    let method = method.to_ascii_uppercase();
    if !matches!(
        method.as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    ) {
        return Err(format!(
            "unsupported host http method {method:?}; expected GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS"
        ));
    }

    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(format!(
            "invalid host http url {url:?}; expected http(s)://<host>[:port]/path"
        ));
    }
    if matches!(timeout, Some(limit) if limit.is_zero()) {
        return Ok(HostHttpDispatch::TimedOut);
    }
    let mut agent = ureq::AgentBuilder::new();
    if let Some(limit) = timeout {
        agent = agent
            .timeout_connect(limit)
            .timeout_read(limit)
            .timeout_write(limit);
    }
    let mut req = agent.build().request(&method, url);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let result = if let Some(payload) = body {
        req.send_string(payload)
    } else {
        req.call()
    };
    let response = match result {
        Ok(resp) => resp,
        Err(ureq::Error::Status(_, resp)) => resp,
        Err(err) => {
            let message = format!("host http request failed for {method} {url}: {err}");
            if message.contains("timed out") || message.contains("timeout") {
                return Ok(HostHttpDispatch::TimedOut);
            }
            return Err(message);
        }
    };
    let mut out_headers = BTreeMap::new();
    for name in response.headers_names() {
        if let Some(val) = response.header(&name) {
            out_headers.insert(name.to_ascii_lowercase(), val.to_string());
        }
    }
    let status_code = response.status();
    let mut reader = response.into_reader();
    let mut body_bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                body_bytes.extend_from_slice(&chunk[..n]);
                if body_bytes.len() > HOST_HTTP_MAX_BODY_BYTES {
                    return Err(format!(
                        "host http body exceeded limit for {method} {url}: {} bytes > {} bytes",
                        body_bytes.len(),
                        HOST_HTTP_MAX_BODY_BYTES
                    ));
                }
            }
            Err(err) => {
                let message = format!("host http body read failed for {method} {url}: {err}");
                if message.contains("timed out") || message.contains("timeout") {
                    return Ok(HostHttpDispatch::TimedOut);
                }
                return Err(message);
            }
        }
    }
    Ok(HostHttpDispatch::Completed(HostHttpResponse {
        status: status_code,
        headers: out_headers,
        body: String::from_utf8_lossy(&body_bytes).to_string(),
    }))
}

pub(crate) fn host_http_rule_path_supported(path: &str) -> bool {
    path.starts_with("http://") || path.starts_with("https://") || path.starts_with('/')
}

pub(crate) fn host_http_rule_matches(rule_path: &str, request_url: &str) -> bool {
    if rule_path.starts_with("http://") || rule_path.starts_with("https://") {
        return rule_path == request_url;
    }
    if let Some(request_path) = extract_http_path_and_query(request_url) {
        return request_path == rule_path;
    }
    false
}

fn extract_http_path_and_query(url: &str) -> Option<&str> {
    let rest = if let Some(v) = url.strip_prefix("http://") {
        v
    } else if let Some(v) = url.strip_prefix("https://") {
        v
    } else {
        return None;
    };
    if let Some(idx) = rest.find('/') {
        Some(&rest[idx..])
    } else {
        Some("/")
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn assert_http_when_response_matches_host(
    method: &str,
    path: &str,
    expected_status: u16,
    expected_headers: &BTreeMap<String, String>,
    expected_body: Option<&str>,
    expected_json: Option<&serde_json::Value>,
    status_code: u16,
    headers: &BTreeMap<String, String>,
    body: &str,
) -> Result<(), Finding> {
    if status_code != expected_status {
        return Err(Finding {
            kind: FindingKind::Assertion,
            title: "http_when_host_status".to_string(),
            message: format!(
                "http_when expected status {expected_status} for {method} {path}, got {status_code}"
            ),
            location: None,
        });
    }
    for (k, v) in expected_headers {
        let got = headers.get(k);
        if got != Some(v) {
            return Err(Finding {
                kind: FindingKind::Assertion,
                title: "http_when_host_headers".to_string(),
                message: format!(
                    "http_when header mismatch for {method} {path} header {k:?}: expected {v:?}, got {got:?}"
                ),
                location: None,
            });
        }
    }
    if let Some(expected_body) = expected_body
        && body != expected_body
    {
        return Err(Finding {
            kind: FindingKind::Assertion,
            title: "http_when_host_body".to_string(),
            message: format!("http_when body mismatch for {method} {path}"),
            location: None,
        });
    }
    if let Some(expected_json) = expected_json {
        let got: serde_json::Value = serde_json::from_str(body).map_err(|e| Finding {
            kind: FindingKind::Assertion,
            title: "http_when_host_json_parse".to_string(),
            message: format!("http_when expected json response for {method} {path}: {e}"),
            location: None,
        })?;
        if &got != expected_json {
            return Err(Finding {
                kind: FindingKind::Assertion,
                title: "http_when_host_json".to_string(),
                message: format!("http_when json mismatch for {method} {path}"),
                location: None,
            });
        }
    }
    Ok(())
}
