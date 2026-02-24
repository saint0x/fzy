use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogField {
    pub key: String,
    pub value: String,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
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
pub struct Logger {
    pub min_level: LogLevel,
    pub policy: RedactionPolicy,
    pub entries: Vec<LogEntry>,
}

impl Default for Logger {
    fn default() -> Self {
        Self {
            min_level: LogLevel::Info,
            policy: RedactionPolicy::RedactKnownSecrets,
            entries: Vec::new(),
        }
    }
}

impl Logger {
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
                if key.contains("secret") || key.contains("token") || key.contains("password") {
                    field.redacted = true;
                    field.value = "[redacted]".to_string();
                }
            }
        }
        self.entries.push(LogEntry {
            level,
            message: message.into(),
            request_id,
            fields,
        });
    }
}

#[derive(Debug, Clone)]
pub struct Metrics {
    counters: BTreeMap<String, u64>,
    gauges: BTreeMap<String, i64>,
    histograms: BTreeMap<String, Vec<u64>>,
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
        *self.counters.entry(name.to_string()).or_default() += by;
    }

    pub fn set_gauge(&mut self, name: &str, value: i64) {
        self.gauges.insert(name.to_string(), value);
    }

    pub fn observe_histogram(&mut self, name: &str, value: u64) {
        self.histograms
            .entry(name.to_string())
            .or_default()
            .push(value);
    }

    pub fn counter(&self, name: &str) -> u64 {
        self.counters.get(name).copied().unwrap_or(0)
    }

    pub fn gauge(&self, name: &str) -> Option<i64> {
        self.gauges.get(name).copied()
    }

    pub fn histogram(&self, name: &str) -> &[u64] {
        self.histograms.get(name).map(Vec::as_slice).unwrap_or(&[])
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
        };
        self.next_span += 1;
        self.spans.push(span.clone());
        span
    }

    pub fn spans(&self) -> &[Span] {
        &self.spans
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

#[cfg(test)]
mod tests {
    use super::{LogField, LogLevel, Logger, Metrics, RuntimeStats, Tracer};

    #[test]
    fn logger_redacts_secret_fields() {
        let mut logger = Logger::default();
        logger.log(
            LogLevel::Info,
            "login",
            Some("req-1".to_string()),
            vec![LogField {
                key: "api_token".to_string(),
                value: "abcd".to_string(),
                redacted: false,
            }],
        );

        assert_eq!(logger.entries.len(), 1);
        assert_eq!(logger.entries[0].fields[0].value, "[redacted]");
    }

    #[test]
    fn metrics_capture_counter_gauge_histogram() {
        let mut metrics = Metrics::new();
        metrics.inc_counter("req_total", 2);
        metrics.set_gauge("workers", 8);
        metrics.observe_histogram("latency_ms", 10);
        metrics.observe_histogram("latency_ms", 20);

        assert_eq!(metrics.counter("req_total"), 2);
        assert_eq!(metrics.gauge("workers"), Some(8));
        assert_eq!(metrics.histogram("latency_ms"), &[10, 20]);
    }

    #[test]
    fn tracer_propagates_correlation_id() {
        let mut tracer = Tracer::default();
        let root = tracer.start_root("http.request", "corr-1");
        let child = tracer.start_child(&root, "db.query");
        assert_eq!(child.parent_id, Some(root.id));
        assert_eq!(child.correlation_id, "corr-1");
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
