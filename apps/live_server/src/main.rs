use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use core::{Capability, CapabilitySet};
use runtime::service::{RuntimeProfile, ServiceRuntime, ShutdownSignal};
use serde::{Deserialize, Serialize};
use stdlib::durability::{acquire_file_lock, fsync_file, write_atomic};
use stdlib::http::{parse_http_request, HttpResponse, HttpServerLimits};
use stdlib::observability::{
    LogField, LogLevel, Logger, Metrics, RedactionPolicy, RuntimeStats as ObsRuntimeStats, Tracer,
};
use stdlib::process::EnvConfig;
use stdlib::security::{audit_privileged_operation, PrivilegedOperation, ServerHardeningDefaults};

#[derive(Debug, Clone)]
struct AppConfig {
    host: String,
    port: u16,
    store_path: PathBuf,
    worker_count: usize,
    graceful_stop_ms: u64,
    read_buffer_bytes: usize,
    queue_capacity: usize,
    flush_interval_ms: u64,
    sync_writes: bool,
}

impl AppConfig {
    fn from_env() -> Self {
        let env = EnvConfig::from_current_env();
        let host = env
            .get_required("LIVE_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = env.parse_u16("LIVE_PORT").unwrap_or(8080);
        let worker_count = env.parse_usize("LIVE_WORKERS").unwrap_or(8).max(1);
        let graceful_stop_ms = env.parse_usize("LIVE_GRACEFUL_STOP_MS").unwrap_or(5_000) as u64;
        let read_buffer_bytes = env
            .parse_usize("LIVE_READ_BUFFER")
            .unwrap_or(16 * 1024)
            .max(1024);
        let queue_capacity = env.parse_usize("LIVE_QUEUE_CAP").unwrap_or(2048).max(32);
        let flush_interval_ms = env.parse_usize("LIVE_FLUSH_INTERVAL_MS").unwrap_or(100) as u64;
        let sync_writes = env.parse_bool("LIVE_SYNC_WRITES").unwrap_or(false);
        let store_path = PathBuf::from(
            env.get_required("LIVE_STORE")
                .unwrap_or_else(|_| "examples/live_server/store.json".to_string()),
        );

        Self {
            host,
            port,
            store_path,
            worker_count,
            graceful_stop_ms,
            read_buffer_bytes,
            queue_capacity,
            flush_interval_ms,
            sync_writes,
        }
    }

    fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreData {
    items: BTreeMap<String, String>,
}

enum FlushCommand {
    Flush,
    Shutdown,
}

struct SharedState {
    cfg: AppConfig,
    store: RwLock<StoreData>,
    metrics: Mutex<Metrics>,
    logger: Mutex<Logger>,
    tracer: Mutex<Tracer>,
    runtime: Mutex<ServiceRuntime>,
    healthy: AtomicBool,
    ready: AtomicBool,
    shutting_down: AtomicBool,
    pending_connections: AtomicUsize,
    dirty_store: AtomicBool,
    started_at: Instant,
    flush_tx: SyncSender<FlushCommand>,
}

impl SharedState {
    fn new(cfg: AppConfig, store: StoreData, flush_tx: SyncSender<FlushCommand>) -> Self {
        let logger = Logger {
            min_level: LogLevel::Info,
            policy: RedactionPolicy::RedactKnownSecrets,
            ..Logger::default()
        };

        Self {
            cfg,
            store: RwLock::new(store),
            metrics: Mutex::new(Metrics::new()),
            logger: Mutex::new(logger),
            tracer: Mutex::new(Tracer::default()),
            runtime: Mutex::new(ServiceRuntime::default()),
            healthy: AtomicBool::new(true),
            ready: AtomicBool::new(true),
            shutting_down: AtomicBool::new(false),
            pending_connections: AtomicUsize::new(0),
            dirty_store: AtomicBool::new(false),
            started_at: Instant::now(),
            flush_tx,
        }
    }

    fn log(&self, level: LogLevel, message: &str, request_id: Option<String>) {
        if let Ok(mut logger) = self.logger.lock() {
            logger.log(
                level,
                message,
                request_id,
                vec![LogField {
                    key: "service".to_string(),
                    value: "live_server".to_string(),
                    redacted: false,
                }],
            );
        }
    }

    fn inc(&self, key: &str, by: u64) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.inc_counter(key, by);
        }
    }

    fn mark_store_dirty(&self) {
        self.dirty_store.store(true, Ordering::SeqCst);
    }

    fn request_flush(&self) {
        let _ = self.flush_tx.try_send(FlushCommand::Flush);
    }

    fn flush_store_now(&self) -> Result<()> {
        if !self.dirty_store.swap(false, Ordering::SeqCst) {
            return Ok(());
        }

        let parent = self
            .cfg
            .store_path
            .parent()
            .ok_or_else(|| anyhow!("store path has no parent"))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create store parent dir: {}", parent.display()))?;

        let snapshot = self
            .store
            .read()
            .map_err(|_| anyhow!("store lock poisoned"))?
            .clone();
        let bytes = serde_json::to_vec(&snapshot).context("failed to serialize store")?;

        let _lock = acquire_file_lock(&self.cfg.store_path)
            .map_err(|err| anyhow!("failed to lock store: {:?}", err))?;
        write_atomic(&self.cfg.store_path, &bytes)
            .map_err(|err| anyhow!("failed to write store atomically: {:?}", err))?;
        fsync_file(&self.cfg.store_path)
            .map_err(|err| anyhow!("failed to fsync store: {:?}", err))?;

        self.inc("store.flush.total", 1);
        Ok(())
    }

    fn runtime_stats(&self) -> ObsRuntimeStats {
        let stats = self
            .runtime
            .lock()
            .map(|rt| rt.snapshot_stats())
            .unwrap_or_default();
        ObsRuntimeStats {
            task_queue_depth: self.pending_connections.load(Ordering::SeqCst),
            scheduler_lag_ms: stats.scheduler_lag_ms,
            allocation_pressure_bytes: stats.allocation_pressure_bytes,
            open_file_count: stats.open_file_count,
            open_socket_count: stats.open_socket_count,
        }
    }
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    if matches!(args.next().as_deref(), Some("bench")) {
        return run_bench();
    }

    run_server(AppConfig::from_env())
}

fn run_server(cfg: AppConfig) -> Result<()> {
    let store = load_store(&cfg.store_path)?;

    let (flush_tx, flush_rx) = mpsc::sync_channel::<FlushCommand>(64);
    let state = Arc::new(SharedState::new(cfg.clone(), store, flush_tx.clone()));

    if let Ok(mut rt) = state.runtime.lock() {
        rt.set_file_count(1);
        rt.set_socket_count(1);
        rt.set_scheduler_lag(0);
        rt.set_allocation_pressure(0);
    }

    let flusher_state = Arc::clone(&state);
    let flusher = thread::spawn(move || flush_worker(flusher_state, flush_rx));

    let profile = RuntimeProfile::Release.config();
    state.log(
        LogLevel::Info,
        &format!(
            "boot profile=release workers={} det={} strict_verify={} queue={} flush_ms={} sync_writes={}",
            profile.worker_count,
            profile.deterministic,
            profile.strict_verify,
            cfg.queue_capacity,
            cfg.flush_interval_ms,
            cfg.sync_writes
        ),
        None,
    );

    let hardening = ServerHardeningDefaults::default();
    let mut caps = CapabilitySet::default();
    caps.insert(Capability::Http);
    caps.insert(Capability::FileSystem);
    caps.insert(Capability::Process);
    for op in [
        PrivilegedOperation::NetworkBind,
        PrivilegedOperation::FileWrite,
        PrivilegedOperation::ProcessSpawn,
    ] {
        let audit = audit_privileged_operation(&caps, op, "startup audit");
        if !audit.allowed {
            return Err(anyhow!(
                "privileged operation blocked: {:?}",
                audit.operation
            ));
        }
    }

    let listener =
        TcpListener::bind(cfg.addr()).with_context(|| format!("failed to bind {}", cfg.addr()))?;
    listener
        .set_nonblocking(true)
        .context("failed to set listener nonblocking")?;

    let limits = HttpServerLimits {
        max_header_bytes: hardening.max_header_bytes,
        max_body_bytes: hardening.max_body_bytes,
        max_connections: hardening.max_connections,
        read_timeout_ms: hardening.request_timeout_ms,
        write_timeout_ms: hardening.request_timeout_ms,
        parse_timeout_ms: hardening.parse_timeout_ms,
        keepalive_max_requests: 64,
    };

    state.log(
        LogLevel::Info,
        &format!(
            "listening addr={} limits(header={}, body={}, conn={})",
            cfg.addr(),
            limits.max_header_bytes,
            limits.max_body_bytes,
            limits.max_connections
        ),
        None,
    );

    let (work_tx, work_rx) = mpsc::sync_channel::<TcpStream>(cfg.queue_capacity);
    let shared_rx = Arc::new(Mutex::new(work_rx));
    let mut workers = Vec::with_capacity(cfg.worker_count);
    for idx in 0..cfg.worker_count {
        let rx = Arc::clone(&shared_rx);
        let worker_state = Arc::clone(&state);
        let worker_limits = limits.clone();
        workers.push(thread::spawn(move || {
            worker_loop(idx, worker_state, rx, worker_limits)
        }));
    }

    let running = Arc::new(AtomicBool::new(true));
    let running_flag = Arc::clone(&running);
    let state_for_signal = Arc::clone(&state);
    let graceful_ms = cfg.graceful_stop_ms;
    ctrlc::set_handler(move || {
        state_for_signal.shutting_down.store(true, Ordering::SeqCst);
        if let Ok(mut rt) = state_for_signal.runtime.lock() {
            rt.shutdown.begin(ShutdownSignal::Sigint, graceful_ms, 0);
        }
        running_flag.store(false, Ordering::SeqCst);
    })
    .context("failed to register signal handler")?;

    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                if state.shutting_down.load(Ordering::SeqCst) {
                    let _ =
                        write_response(&mut stream, 503, br#"{"error":"shutting down"}"#, false);
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }

                state.pending_connections.fetch_add(1, Ordering::SeqCst);
                match work_tx.try_send(stream) {
                    Ok(()) => {}
                    Err(TrySendError::Full(mut stream)) => {
                        state.pending_connections.fetch_sub(1, Ordering::SeqCst);
                        state.inc("http.queue.full", 1);
                        let _ = write_response(
                            &mut stream,
                            503,
                            br#"{"error":"server overloaded"}"#,
                            false,
                        );
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        state.pending_connections.fetch_sub(1, Ordering::SeqCst);
                        break;
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(err) => {
                state.inc("http.accept.error", 1);
                state.log(LogLevel::Error, &format!("accept error: {err}"), None);
                thread::sleep(Duration::from_millis(5));
            }
        }
    }

    drop(work_tx);
    for handle in workers {
        let _ = handle.join();
    }

    let _ = state.flush_tx.try_send(FlushCommand::Shutdown);
    let _ = flusher.join();

    state.ready.store(false, Ordering::SeqCst);
    state.log(LogLevel::Info, "shutdown complete", None);
    Ok(())
}

fn worker_loop(
    _idx: usize,
    state: Arc<SharedState>,
    rx: Arc<Mutex<Receiver<TcpStream>>>,
    limits: HttpServerLimits,
) {
    loop {
        let stream = {
            let guard = match rx.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            match guard.recv() {
                Ok(stream) => stream,
                Err(_) => return,
            }
        };

        state.pending_connections.fetch_sub(1, Ordering::SeqCst);
        let mut stream = stream;
        if let Err(err) = handle_connection(&state, &mut stream, &limits) {
            state.inc("http.request.error", 1);
            state.log(LogLevel::Error, &format!("request error: {err:#}"), None);
            let _ = write_response(
                &mut stream,
                500,
                br#"{"error":"internal server error"}"#,
                false,
            );
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn flush_worker(state: Arc<SharedState>, rx: Receiver<FlushCommand>) {
    let interval = Duration::from_millis(state.cfg.flush_interval_ms.max(10));
    loop {
        match rx.recv_timeout(interval) {
            Ok(FlushCommand::Flush) => {
                let _ = state.flush_store_now();
            }
            Ok(FlushCommand::Shutdown) => {
                let _ = state.flush_store_now();
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = state.flush_store_now();
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = state.flush_store_now();
                return;
            }
        }
    }
}

fn handle_connection(
    state: &Arc<SharedState>,
    stream: &mut TcpStream,
    limits: &HttpServerLimits,
) -> Result<()> {
    state.inc("http.request.total", 1);

    stream
        .set_read_timeout(Some(Duration::from_millis(limits.read_timeout_ms)))
        .context("failed setting read timeout")?;
    stream
        .set_write_timeout(Some(Duration::from_millis(limits.write_timeout_ms)))
        .context("failed setting write timeout")?;

    let mut buf = vec![0_u8; state.cfg.read_buffer_bytes];
    let read = stream.read(&mut buf).context("failed reading request")?;
    if read == 0 {
        return Ok(());
    }
    buf.truncate(read);

    let req =
        parse_http_request(&buf, limits).map_err(|err| anyhow!("http parse error: {err:?}"))?;
    let request_id = format!(
        "req-{}",
        state.started_at.elapsed().as_nanos() % 1_000_000_000
    );

    if let Ok(mut tracer) = state.tracer.lock() {
        let root = tracer.start_root("http.request", request_id.clone());
        let _ = tracer.start_child(&root, format!("route.{}.{}", req.method, req.path));
    }

    let (status, body, keep_alive) = route_request(state, &req.method, &req.path, &req.body)?;
    write_response(stream, status, body.as_bytes(), keep_alive)?;
    if !keep_alive {
        let _ = stream.shutdown(Shutdown::Both);
    }
    Ok(())
}

fn route_request(
    state: &Arc<SharedState>,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, String, bool)> {
    match (method, path) {
        ("GET", "/healthz") => {
            let healthy = state.healthy.load(Ordering::SeqCst);
            let status = if healthy { "ok" } else { "degraded" };
            Ok((200, format!("{{\"status\":\"{status}\"}}"), true))
        }
        ("GET", "/readyz") => {
            let ready =
                state.ready.load(Ordering::SeqCst) && !state.shutting_down.load(Ordering::SeqCst);
            let code = if ready { 200 } else { 503 };
            let text = if ready { "ready" } else { "not_ready" };
            Ok((code, format!("{{\"status\":\"{text}\"}}"), true))
        }
        ("GET", "/metrics") => {
            let mut out = String::new();
            if let Ok(metrics) = state.metrics.lock() {
                out.push_str(&format!(
                    "http_request_total {}\n",
                    metrics.counter("http.request.total")
                ));
                out.push_str(&format!(
                    "http_request_error {}\n",
                    metrics.counter("http.request.error")
                ));
                out.push_str(&format!(
                    "http_accept_error {}\n",
                    metrics.counter("http.accept.error")
                ));
                out.push_str(&format!(
                    "http_queue_full {}\n",
                    metrics.counter("http.queue.full")
                ));
                out.push_str(&format!(
                    "kv_write_total {}\n",
                    metrics.counter("kv.write.total")
                ));
                out.push_str(&format!(
                    "kv_read_total {}\n",
                    metrics.counter("kv.read.total")
                ));
                out.push_str(&format!(
                    "store_flush_total {}\n",
                    metrics.counter("store.flush.total")
                ));
            }
            let stats = state.runtime_stats();
            out.push_str(&format!("runtime_queue_depth {}\n", stats.task_queue_depth));
            out.push_str(&format!(
                "runtime_scheduler_lag_ms {}\n",
                stats.scheduler_lag_ms
            ));
            Ok((200, out, false))
        }
        ("GET", "/v1/items") => {
            state.inc("kv.read.total", 1);
            let store = state
                .store
                .read()
                .map_err(|_| anyhow!("store lock poisoned"))?;
            let body = serde_json::to_string(&store.items).context("failed serializing items")?;
            Ok((200, body, true))
        }
        _ if path.starts_with("/v1/items/") => {
            let key = path.trim_start_matches("/v1/items/");
            match method {
                "GET" => {
                    state.inc("kv.read.total", 1);
                    let store = state
                        .store
                        .read()
                        .map_err(|_| anyhow!("store lock poisoned"))?;
                    if let Some(value) = store.items.get(key) {
                        Ok((
                            200,
                            format!(
                                "{{\"key\":\"{}\",\"value\":\"{}\"}}",
                                escape_json(key),
                                escape_json(value)
                            ),
                            true,
                        ))
                    } else {
                        Ok((404, "{\"error\":\"not found\"}".to_string(), true))
                    }
                }
                "PUT" => {
                    state.inc("kv.write.total", 1);
                    let value = extract_value(body)
                        .unwrap_or_else(|| String::from_utf8_lossy(body).to_string());
                    {
                        let mut store = state
                            .store
                            .write()
                            .map_err(|_| anyhow!("store lock poisoned"))?;
                        store.items.insert(key.to_string(), value);
                    }
                    state.mark_store_dirty();
                    if state.cfg.sync_writes {
                        state.flush_store_now()?;
                    } else {
                        state.request_flush();
                    }
                    Ok((200, "{\"ok\":true}".to_string(), true))
                }
                "DELETE" => {
                    state.inc("kv.write.total", 1);
                    let removed = {
                        let mut store = state
                            .store
                            .write()
                            .map_err(|_| anyhow!("store lock poisoned"))?;
                        store.items.remove(key).is_some()
                    };
                    state.mark_store_dirty();
                    if state.cfg.sync_writes {
                        state.flush_store_now()?;
                    } else {
                        state.request_flush();
                    }
                    if removed {
                        Ok((200, "{\"deleted\":true}".to_string(), true))
                    } else {
                        Ok((404, "{\"error\":\"not found\"}".to_string(), true))
                    }
                }
                _ => Ok((405, "{\"error\":\"method not allowed\"}".to_string(), true)),
            }
        }
        _ => Ok((404, "{\"error\":\"route not found\"}".to_string(), true)),
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
    keep_alive: bool,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut response = HttpResponse {
        status,
        reason: reason.to_string(),
        headers: BTreeMap::new(),
        body: body.to_vec(),
        chunked: false,
        keep_alive,
    };
    response
        .headers
        .insert("Content-Type".to_string(), "application/json".to_string());

    stream
        .write_all(&response.to_bytes())
        .context("failed writing response")?;
    Ok(())
}

fn load_store(path: &Path) -> Result<StoreData> {
    if !path.exists() {
        return Ok(StoreData::default());
    }
    let bytes = fs::read(path).with_context(|| format!("failed reading {}", path.display()))?;
    if bytes.is_empty() {
        return Ok(StoreData::default());
    }
    serde_json::from_slice(&bytes).with_context(|| format!("invalid json in {}", path.display()))
}

fn extract_value(body: &[u8]) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;
    parsed.get("value")?.as_str().map(ToString::to_string)
}

fn escape_json(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

fn run_bench() -> Result<()> {
    let cfg = AppConfig::from_env();
    let server_addr = cfg.addr();

    let mut cmd = std::process::Command::new(
        std::env::current_exe().context("failed to locate current executable")?,
    );
    cmd.env("LIVE_PORT", cfg.port.to_string())
        .env("LIVE_HOST", cfg.host.clone())
        .env("LIVE_STORE", cfg.store_path.display().to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = cmd.spawn().context("failed to spawn server for bench")?;
    wait_for_server(&server_addr, Duration::from_secs(5))?;

    let requests = 2000usize;
    let workers = 8usize;
    let start = Instant::now();
    let lats = Arc::new(Mutex::new(Vec::<u64>::with_capacity(requests)));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let addr = server_addr.clone();
        let lats = Arc::clone(&lats);
        handles.push(thread::spawn(move || -> Result<()> {
            for i in (w..requests).step_by(workers) {
                let t0 = Instant::now();
                let key = format!("bench_{i}");
                http_put(&addr, &key, "v")?;
                let _ = http_get(&addr, &key)?;
                let us = t0.elapsed().as_micros() as u64;
                if let Ok(mut l) = lats.lock() {
                    l.push(us);
                }
            }
            Ok(())
        }));
    }

    for h in handles {
        h.join().map_err(|_| anyhow!("bench worker panicked"))??;
    }
    let total_ms = start.elapsed().as_millis() as u64;

    let _ = child.kill();
    let _ = child.wait();

    let mut latencies = lats
        .lock()
        .map_err(|_| anyhow!("bench lock poisoned"))?
        .clone();
    latencies.sort_unstable();
    let p50 = percentile(&latencies, 50);
    let p95 = percentile(&latencies, 95);
    let p99 = percentile(&latencies, 99);
    let rps = ((requests as f64 * 1000.0) / total_ms.max(1) as f64) as u64;

    println!(
        "bench requests={} total_ms={} rps={} p50_us={} p95_us={} p99_us={}",
        requests, total_ms, rps, p50, p95, p99
    );
    Ok(())
}

fn wait_for_server(addr: &str, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if TcpStream::connect(addr).is_ok() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("timed out waiting for server at {addr}"));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn percentile(values: &[u64], p: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let idx = ((values.len() - 1) * p) / 100;
    values[idx]
}

fn http_get(addr: &str, key: &str) -> Result<String> {
    let mut stream = TcpStream::connect(addr).with_context(|| format!("connect failed: {addr}"))?;
    let req = format!("GET /v1/items/{key} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .context("write request failed")?;
    read_http_body(&mut stream)
}

fn http_put(addr: &str, key: &str, value: &str) -> Result<()> {
    let mut stream = TcpStream::connect(addr).with_context(|| format!("connect failed: {addr}"))?;
    let body = format!("{{\"value\":\"{}\"}}", escape_json(value));
    let req = format!(
        "PUT /v1/items/{key} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(req.as_bytes())
        .context("write request failed")?;
    let _ = read_http_body(&mut stream)?;
    Ok(())
}

fn read_http_body(stream: &mut TcpStream) -> Result<String> {
    let mut out = Vec::new();
    stream
        .read_to_end(&mut out)
        .context("read response failed")?;
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("invalid http response"))?;
    Ok(String::from_utf8_lossy(&out[(split + 4)..]).to_string())
}

#[cfg(test)]
mod tests {
    use super::{escape_json, extract_value, percentile};

    #[test]
    fn extracts_json_value_payload() {
        let body = br#"{"value":"ok"}"#;
        assert_eq!(extract_value(body).as_deref(), Some("ok"));
    }

    #[test]
    fn percentile_selects_expected_index() {
        let v = vec![10, 20, 30, 40, 50];
        assert_eq!(percentile(&v, 50), 30);
        assert_eq!(percentile(&v, 95), 40);
    }

    #[test]
    fn escape_json_escapes_quotes_and_backslashes() {
        assert_eq!(escape_json("a\\\"b"), "a\\\\\\\"b");
    }
}
