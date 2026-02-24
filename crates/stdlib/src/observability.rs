use std::collections::BTreeMap;
use std::io::Write;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogField {
    pub key: String,
    pub value: String,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogEntry {
    pub timestamp_ms: u64,
    pub level: LogLevel,
    pub message: String,
    pub request_id: Option<String>,
    pub fields: Vec<LogField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionPolicy {
    RedactKnownSecrets,
    AllowAll,
}

#[derive(Debug, Clone)]
pub enum LoggerSink {
    Memory(Arc<Mutex<Vec<LogEntry>>>),
    File(PathBuf),
    UdpJson { addr: String },
    StdoutJson,
}

#[derive(Debug, Clone)]
pub struct Logger {
    pub min_level: LogLevel,
    pub policy: RedactionPolicy,
    pub sinks: Vec<LoggerSink>,
}

impl Default for Logger {
    fn default() -> Self {
        Self {
            min_level: LogLevel::Info,
            policy: RedactionPolicy::RedactKnownSecrets,
            sinks: vec![LoggerSink::Memory(Arc::new(Mutex::new(Vec::new())))],
        }
    }
}

impl Logger {
    pub fn with_sinks(sinks: Vec<LoggerSink>) -> Self {
        Self {
            sinks,
            ..Self::default()
        }
    }

    pub fn log(
        &mut self,
        level: LogLevel,
        message: impl Into<String>,
        request_id: Option<String>,
        mut fields: Vec<LogField>,
    ) {
        if level < self.min_level {
            return;
        }
        if matches!(self.policy, RedactionPolicy::RedactKnownSecrets) {
            for field in &mut fields {
                let key = field.key.to_ascii_lowercase();
                if key.contains("secret")
                    || key.contains("token")
                    || key.contains("password")
                    || key.contains("api_key")
                    || key.contains("bearer")
                    || key.contains("jwt")
                    || key.contains("authorization")
                {
                    field.redacted = true;
                    field.value = "[redacted]".to_string();
                }
            }
        }
        let entry = LogEntry {
            timestamp_ms: now_ms(),
            level,
            message: message.into(),
            request_id,
            fields,
        };
        self.emit(&entry);
    }

    pub fn memory_entries(&self) -> Vec<LogEntry> {
        for sink in &self.sinks {
            if let LoggerSink::Memory(values) = sink {
                return values.lock().map(|v| v.clone()).unwrap_or_default();
            }
        }
        Vec::new()
    }

    fn emit(&self, entry: &LogEntry) {
        for sink in &self.sinks {
            match sink {
                LoggerSink::Memory(values) => {
                    if let Ok(mut values) = values.lock() {
                        values.push(entry.clone());
                    }
                }
                LoggerSink::File(path) => {
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                    {
                        let line =
                            serde_json::to_string(entry).unwrap_or_else(|_| "{}".to_string());
                        let _ = writeln!(file, "{}", line);
                    }
                }
                LoggerSink::UdpJson { addr } => {
                    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                        let line =
                            serde_json::to_string(entry).unwrap_or_else(|_| "{}".to_string());
                        let _ = socket.send_to(line.as_bytes(), addr);
                    }
                }
                LoggerSink::StdoutJson => {
                    let line = serde_json::to_string(entry).unwrap_or_else(|_| "{}".to_string());
                    let _ = writeln!(std::io::stdout(), "{}", line);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricPoint {
    pub timestamp_ms: u64,
    pub value: i64,
}

#[derive(Debug, Clone)]
pub struct Metrics {
    counters: BTreeMap<String, Vec<MetricPoint>>,
    gauges: BTreeMap<String, Vec<MetricPoint>>,
    histograms: BTreeMap<String, Vec<MetricPoint>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            counters: BTreeMap::new(),
            gauges: BTreeMap::new(),
            histograms: BTreeMap::new(),
        }
    }

    pub fn inc_counter(&mut self, name: &str, by: u64) {
        self.counters
            .entry(name.to_string())
            .or_default()
            .push(MetricPoint {
                timestamp_ms: now_ms(),
                value: by as i64,
            });
    }

    pub fn set_gauge(&mut self, name: &str, value: i64) {
        self.gauges
            .entry(name.to_string())
            .or_default()
            .push(MetricPoint {
                timestamp_ms: now_ms(),
                value,
            });
    }

    pub fn observe_histogram(&mut self, name: &str, value: u64) {
        self.histograms
            .entry(name.to_string())
            .or_default()
            .push(MetricPoint {
                timestamp_ms: now_ms(),
                value: value as i64,
            });
    }

    pub fn counter(&self, name: &str) -> u64 {
        self.counters
            .get(name)
            .map(|points| points.iter().map(|point| point.value.max(0) as u64).sum())
            .unwrap_or(0)
    }

    pub fn gauge(&self, name: &str) -> Option<i64> {
        self.gauges
            .get(name)
            .and_then(|points| points.last())
            .map(|point| point.value)
    }

    pub fn histogram(&self, name: &str) -> Vec<u64> {
        self.histograms
            .get(name)
            .map(|points| {
                points
                    .iter()
                    .map(|point| point.value.max(0) as u64)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn percentile(&self, name: &str, pct: f64) -> Option<u64> {
        let mut values = self.histogram(name);
        if values.is_empty() {
            return None;
        }
        values.sort_unstable();
        let index =
            ((pct.clamp(0.0, 100.0) / 100.0) * ((values.len() - 1) as f64)).round() as usize;
        values.get(index).copied()
    }

    pub fn p50(&self, name: &str) -> Option<u64> {
        self.percentile(name, 50.0)
    }

    pub fn p95(&self, name: &str) -> Option<u64> {
        self.percentile(name, 95.0)
    }

    pub fn p99(&self, name: &str) -> Option<u64> {
        self.percentile(name, 99.0)
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub name: String,
    pub correlation_id: String,
    pub baggage: BTreeMap<String, String>,
    pub started_ms: u64,
    pub ended_ms: Option<u64>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Tracer {
    next_span: u64,
    spans: Vec<Span>,
}

impl Default for Tracer {
    fn default() -> Self {
        Self {
            next_span: 1,
            spans: Vec::new(),
        }
    }
}

impl Tracer {
    pub fn start_root(
        &mut self,
        name: impl Into<String>,
        correlation_id: impl Into<String>,
    ) -> Span {
        let span = Span {
            id: self.next_span,
            parent_id: None,
            name: name.into(),
            correlation_id: correlation_id.into(),
            baggage: BTreeMap::new(),
            started_ms: now_ms(),
            ended_ms: None,
            duration_ms: None,
        };
        self.next_span += 1;
        self.spans.push(span.clone());
        span
    }

    pub fn start_child(&mut self, parent: &Span, name: impl Into<String>) -> Span {
        let span = Span {
            id: self.next_span,
            parent_id: Some(parent.id),
            name: name.into(),
            correlation_id: parent.correlation_id.clone(),
            baggage: parent.baggage.clone(),
            started_ms: now_ms(),
            ended_ms: None,
            duration_ms: None,
        };
        self.next_span += 1;
        self.spans.push(span.clone());
        span
    }

    pub fn finish_span(&mut self, id: u64) -> Option<Span> {
        let now = now_ms();
        let span = self.spans.iter_mut().find(|span| span.id == id)?;
        span.ended_ms = Some(now);
        span.duration_ms = Some(now.saturating_sub(span.started_ms));
        Some(span.clone())
    }

    pub fn inject_baggage(&mut self, id: u64, key: impl Into<String>, value: impl Into<String>) {
        if let Some(span) = self.spans.iter_mut().find(|span| span.id == id) {
            span.baggage.insert(key.into(), value.into());
        }
    }

    pub fn spans(&self) -> &[Span] {
        &self.spans
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceContext {
    pub correlation_id: Option<String>,
    pub baggage: BTreeMap<String, String>,
}

impl TraceContext {
    pub fn from_span(span: &Span) -> Self {
        Self {
            correlation_id: Some(span.correlation_id.clone()),
            baggage: span.baggage.clone(),
        }
    }

    pub fn propagate_to_span(&self, span: &mut Span) {
        if let Some(correlation_id) = &self.correlation_id {
            span.correlation_id = correlation_id.clone();
        }
        span.baggage.extend(self.baggage.clone());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStats {
    pub task_queue_depth: usize,
    pub scheduler_lag_ms: u64,
    pub allocation_pressure_bytes: usize,
    pub open_file_count: usize,
    pub open_socket_count: usize,
}

impl RuntimeStats {
    pub fn healthy(&self) -> bool {
        self.scheduler_lag_ms < 1000 && self.allocation_pressure_bytes < 256 * 1024 * 1024
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

use serde::Serialize;

#[cfg(test)]
mod tests {
    use super::{
        LogField, LogLevel, Logger, LoggerSink, Metrics, RuntimeStats, TraceContext, Tracer,
    };

    #[test]
    fn logger_redacts_extended_secret_fields() {
        let sink = LoggerSink::Memory(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let mut logger = Logger::with_sinks(vec![sink]);
        logger.log(
            LogLevel::Info,
            "auth",
            Some("req-1".to_string()),
            vec![
                LogField {
                    key: "authorization".to_string(),
                    value: "Bearer abc".to_string(),
                    redacted: false,
                },
                LogField {
                    key: "jwt".to_string(),
                    value: "token".to_string(),
                    redacted: false,
                },
            ],
        );
        let entries = logger.memory_entries();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].fields.iter().all(|field| field.redacted));
        assert!(entries[0].timestamp_ms > 0);
    }

    #[test]
    fn metrics_have_percentiles_and_timestamps() {
        let mut metrics = Metrics::new();
        for value in [10_u64, 30, 20, 40, 50] {
            metrics.observe_histogram("latency", value);
        }
        assert_eq!(metrics.p50("latency"), Some(30));
        assert_eq!(metrics.p95("latency"), Some(50));
        assert_eq!(metrics.p99("latency"), Some(50));
    }

    #[test]
    fn tracer_tracks_span_duration_and_baggage_propagation() {
        let mut tracer = Tracer::default();
        let root = tracer.start_root("http.request", "corr-1");
        tracer.inject_baggage(root.id, "tenant", "acme");
        let root_with_baggage = tracer
            .spans()
            .iter()
            .find(|span| span.id == root.id)
            .cloned()
            .expect("root span should exist");
        let mut child = tracer.start_child(&root_with_baggage, "db.query");
        let context = TraceContext::from_span(&root_with_baggage);
        context.propagate_to_span(&mut child);
        let _ = tracer.finish_span(root.id).expect("root finished");
        let _ = tracer.finish_span(child.id).expect("child finished");
        let finished_root = tracer
            .spans()
            .iter()
            .find(|span| span.id == root.id)
            .expect("root exists");
        assert!(finished_root.duration_ms.is_some());
        assert_eq!(child.baggage.get("tenant"), Some(&"acme".to_string()));
    }

    #[test]
    fn runtime_stats_has_health_signal() {
        let stats = RuntimeStats {
            task_queue_depth: 10,
            scheduler_lag_ms: 50,
            allocation_pressure_bytes: 1024,
            open_file_count: 2,
            open_socket_count: 3,
        };
        assert!(stats.healthy());
    }
}
