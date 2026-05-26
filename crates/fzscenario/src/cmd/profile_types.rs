use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileFlameFormat {
    Folded,
    Svg,
    Speedscope,
}

impl clap::ValueEnum for ProfileFlameFormat {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Folded, Self::Svg, Self::Speedscope]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Folded => clap::builder::PossibleValue::new("folded"),
            Self::Svg => clap::builder::PossibleValue::new("svg"),
            Self::Speedscope => clap::builder::PossibleValue::new("speedscope"),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileTimelineFormat {
    Json,
    Html,
}

impl clap::ValueEnum for ProfileTimelineFormat {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Json, Self::Html]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Json => clap::builder::PossibleValue::new("json"),
            Self::Html => clap::builder::PossibleValue::new("html"),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileExportFormat {
    Speedscope,
    Pprof,
    Otlp,
}

impl clap::ValueEnum for ProfileExportFormat {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Speedscope, Self::Pprof, Self::Otlp]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Speedscope => clap::builder::PossibleValue::new("speedscope"),
            Self::Pprof => clap::builder::PossibleValue::new("pprof"),
            Self::Otlp => clap::builder::PossibleValue::new("otlp"),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileMetric {
    P99Latency,
    CpuTime,
    AllocBytes,
}

impl clap::ValueEnum for ProfileMetric {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::P99Latency, Self::CpuTime, Self::AllocBytes]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::P99Latency => clap::builder::PossibleValue::new("p99_latency"),
            Self::CpuTime => clap::builder::PossibleValue::new("cpu_time"),
            Self::AllocBytes => clap::builder::PossibleValue::new("alloc_bytes"),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileDirection {
    Increase,
    Decrease,
}

impl clap::ValueEnum for ProfileDirection {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Increase, Self::Decrease]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Increase => clap::builder::PossibleValue::new("increase"),
            Self::Decrease => clap::builder::PossibleValue::new("decrease"),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProfileEventKind {
    SpanStart,
    SpanEnd,
    Event,
    Sample,
    Alloc,
    Free,
    Io,
    Net,
    Sched,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileEvent {
    #[serde(rename = "t_virtual")]
    pub t_virtual: u64,
    #[serde(rename = "t_mono", skip_serializing_if = "Option::is_none")]
    pub t_mono: Option<u64>,
    pub kind: ProfileEventKind,
    #[serde(rename = "run_id")]
    pub run_id: String,
    pub seed: u64,
    pub thread: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(rename = "span_id")]
    pub span_id: String,
    #[serde(rename = "parent_span_id", skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    pub cost: ProfileCost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileTimelineArtifact {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "timeDomains")]
    pub time_domains: TimeDomains,
    pub events: Vec<ProfileEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileCost {
    #[serde(rename = "duration_ms", skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(rename = "bytes", skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(rename = "count", skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetrics {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "timeDomains")]
    pub time_domains: TimeDomains,
    #[serde(rename = "virtualTimeMs")]
    pub virtual_time_ms: u64,
    #[serde(rename = "hostTimeMs")]
    pub host_time_ms: u64,
    #[serde(rename = "cpuTimeMs")]
    pub cpu_time_ms: u64,
    #[serde(rename = "allocBytes")]
    pub alloc_bytes: u64,
    #[serde(rename = "inUseBytes")]
    pub in_use_bytes: u64,
    #[serde(rename = "p50LatencyMs")]
    pub p50_latency_ms: u64,
    #[serde(rename = "p95LatencyMs")]
    pub p95_latency_ms: u64,
    #[serde(rename = "p99LatencyMs")]
    pub p99_latency_ms: u64,
    #[serde(rename = "maxLatencyMs")]
    pub max_latency_ms: u64,
    #[serde(rename = "ioOps")]
    pub io_ops: u64,
    #[serde(rename = "schedOps")]
    pub sched_ops: u64,
    #[serde(rename = "confidence", skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeDomains {
    #[serde(rename = "virtualTime")]
    pub virtual_time: String,
    #[serde(rename = "hostMonotonicTime")]
    pub host_monotonic_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuProfile {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    pub collector: CpuCollectorInfo,
    #[serde(rename = "samplePeriodMs")]
    pub sample_period_ms: u64,
    #[serde(rename = "sampleCount")]
    pub sample_count: usize,
    pub samples: Vec<CpuSample>,
    #[serde(rename = "foldedStacks")]
    pub folded_stacks: Vec<FoldedStack>,
    #[serde(rename = "symbolsRef")]
    pub symbols_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuCollectorInfo {
    pub domain: String,
    #[serde(rename = "primaryCollector")]
    pub primary_collector: String,
    #[serde(rename = "fallbackCollector")]
    pub fallback_collector: String,
    #[serde(rename = "activeCollector")]
    pub active_collector: String,
    #[serde(rename = "hostTimeSemantics")]
    pub host_time_semantics: String,
    #[serde(rename = "linuxPerfEventOpen")]
    pub linux_perf_event_open: bool,
    pub diagnostics: Vec<String>,
    #[serde(rename = "macOsParityChecklist")]
    pub macos_parity_checklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuSample {
    pub thread: String,
    pub stack: Vec<String>,
    #[serde(rename = "weightMs")]
    pub weight_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoldedStack {
    pub stack: String,
    pub weight: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapProfile {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "totalAllocBytes")]
    pub total_alloc_bytes: u64,
    #[serde(rename = "inUseBytes")]
    pub in_use_bytes: u64,
    #[serde(rename = "allocRatePerSec")]
    pub alloc_rate_per_sec: f64,
    #[serde(rename = "hotspots")]
    pub hotspots: Vec<HeapCallsite>,
    #[serde(rename = "lifetimeHistogram")]
    pub lifetime_histogram: Vec<HistogramBin>,
    #[serde(rename = "retentionSuspects")]
    pub retention_suspects: Vec<RetentionSuspect>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapCallsite {
    #[serde(rename = "callsiteHash")]
    pub callsite_hash: String,
    #[serde(rename = "allocCount")]
    pub alloc_count: u64,
    #[serde(rename = "allocBytes")]
    pub alloc_bytes: u64,
    #[serde(rename = "inUseBytes")]
    pub in_use_bytes: u64,
    #[serde(rename = "allocRatePerSec")]
    pub alloc_rate_per_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramBin {
    pub bucket: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionSuspect {
    #[serde(rename = "allocId")]
    pub alloc_id: u64,
    #[serde(rename = "callsiteHash")]
    pub callsite_hash: String,
    pub bytes: u64,
    #[serde(rename = "ageMs")]
    pub age_ms: u64,
    #[serde(rename = "graphAnchor")]
    pub graph_anchor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeapBudgetPolicy {
    #[serde(rename = "allocBytesBudget", skip_serializing_if = "Option::is_none")]
    pub alloc_bytes_budget: Option<u64>,
    #[serde(rename = "inUseBytesBudget", skip_serializing_if = "Option::is_none")]
    pub in_use_bytes_budget: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyProfile {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    pub distribution: LatencyDistribution,
    #[serde(rename = "dependencyGraph")]
    pub dependency_graph: Vec<CriticalPathEdge>,
    #[serde(rename = "criticalPath")]
    pub critical_path: Vec<CriticalPathEdge>,
    #[serde(rename = "waitReasons")]
    pub wait_reasons: Vec<ReasonCount>,
    #[serde(rename = "tailAmplificationSuspects")]
    pub tail_amplification_suspects: Vec<TailAmplificationSuspect>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyDistribution {
    #[serde(rename = "count")]
    pub count: usize,
    #[serde(rename = "p50Ms")]
    pub p50_ms: u64,
    #[serde(rename = "p95Ms")]
    pub p95_ms: u64,
    #[serde(rename = "p99Ms")]
    pub p99_ms: u64,
    #[serde(rename = "maxMs")]
    pub max_ms: u64,
    #[serde(rename = "variance")]
    pub variance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalPathEdge {
    #[serde(rename = "fromSpan")]
    pub from_span: String,
    #[serde(rename = "toSpan")]
    pub to_span: String,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonCount {
    pub reason: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailAmplificationSuspect {
    #[serde(rename = "spanId")]
    pub span_id: String,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolsMap {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    pub modules: Vec<SymbolModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolModule {
    pub name: String,
    #[serde(rename = "buildId")]
    pub build_id: String,
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileExplain {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "run")]
    pub run: String,
    #[serde(rename = "regressionStatement")]
    pub regression_statement: String,
    #[serde(rename = "topShiftedPath")]
    pub top_shifted_path: String,
    #[serde(rename = "likelyCauseDomain")]
    pub likely_cause_domain: String,
    #[serde(rename = "evidencePointers")]
    pub evidence_pointers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDiff {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub left: String,
    pub right: String,
    #[serde(rename = "leftSamples")]
    pub left_samples: usize,
    #[serde(rename = "rightSamples")]
    pub right_samples: usize,
    pub domains: Vec<String>,
    pub summary: DiffSummary,
    #[serde(rename = "regressions")]
    pub regressions: Vec<RegressionFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    #[serde(rename = "verdict")]
    pub verdict: String,
    #[serde(rename = "regressionCount")]
    pub regression_count: usize,
    #[serde(rename = "improvementCount")]
    pub improvement_count: usize,
    #[serde(rename = "significantRegressionCount")]
    pub significant_regression_count: usize,
    #[serde(
        rename = "topRegressionMetric",
        skip_serializing_if = "Option::is_none"
    )]
    pub top_regression_metric: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionFinding {
    pub domain: String,
    pub metric: String,
    #[serde(rename = "left")]
    pub left_value: f64,
    #[serde(rename = "right")]
    pub right_value: f64,
    #[serde(rename = "delta")]
    pub delta: f64,
    #[serde(rename = "deltaPct")]
    pub delta_pct: f64,
    #[serde(rename = "classification")]
    pub classification: String,
    #[serde(rename = "isRegression")]
    pub is_regression: bool,
    #[serde(rename = "isSignificant")]
    pub is_significant: bool,
    #[serde(rename = "severity")]
    pub severity: String,
    #[serde(rename = "analysis")]
    pub analysis: String,
    #[serde(rename = "timeDomain")]
    pub time_domain: String,
    #[serde(rename = "confidence")]
    pub confidence: f64,
    #[serde(
        rename = "confidenceMeta",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub confidence_meta: Option<ConfidenceMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceMeta {
    pub method: String,
    #[serde(rename = "leftSampleCount")]
    pub left_sample_count: usize,
    #[serde(rename = "rightSampleCount")]
    pub right_sample_count: usize,
    #[serde(rename = "leftStdDev")]
    pub left_std_dev: f64,
    #[serde(rename = "rightStdDev")]
    pub right_std_dev: f64,
    #[serde(rename = "pooledStdErr")]
    pub pooled_std_err: f64,
}

#[derive(Debug, Clone)]
pub(super) struct ProfileBundle {
    pub(super) artifacts_dir: PathBuf,
    pub(super) timeline: Option<Vec<ProfileEvent>>,
    pub(super) cpu: Option<CpuProfile>,
    pub(super) heap: Option<HeapProfile>,
    pub(super) latency: Option<LatencyProfile>,
    pub(super) metrics: ProfileMetrics,
    pub(super) symbols: Option<SymbolsMap>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ProfileLoadSpec {
    pub(super) timeline: bool,
    pub(super) cpu: bool,
    pub(super) heap: bool,
    pub(super) latency: bool,
    pub(super) symbols: bool,
}

#[derive(Debug, Clone)]
pub(super) struct CpuCollectorCapability {
    pub(super) primary_collector: String,
    pub(super) fallback_collector: String,
    pub(super) active_collector: String,
    pub(super) linux_perf_event_open: bool,
    pub(super) diagnostics: Vec<String>,
    pub(super) sample_period_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub(super) struct MetricStats {
    pub(super) n: usize,
    pub(super) mean: f64,
    pub(super) std_dev: f64,
}
