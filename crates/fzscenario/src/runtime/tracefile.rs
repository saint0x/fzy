//! Trace file format (.fozzy) read/write.

use serde::{Deserialize, Serialize};

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::{
    CompatibilityInfo, Decision, ExploreTrace, FozzyError, FozzyResult, FuzzTrace, MemoryTrace,
    RecordCollisionPolicy, RunMode, RunSummary, ScenarioV1Steps, VersionInfo,
};

pub const CURRENT_TRACE_VERSION: u32 = 4;
pub const TRACE_FORMAT: &str = "fozzy-trace";

#[derive(Debug, Clone)]
pub struct TracePath {
    path: PathBuf,
}

impl TracePath {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFile {
    pub format: String,
    pub version: u32,
    pub engine: VersionInfo,
    #[serde(default)]
    pub compatibility: TraceCompatibility,
    pub mode: RunMode,
    pub scenario_path: Option<String>,
    pub scenario: Option<ScenarioV1Steps>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuzz: Option<FuzzTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explore: Option<ExploreTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryTrace>,
    pub decisions: Vec<Decision>,
    pub events: Vec<TraceEvent>,
    #[serde(rename = "replayContract", default)]
    pub replay_contract: TraceReplayContract,
    pub summary: RunSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    pub time_ms: u64,
    pub name: String,
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCompatibility {
    #[serde(flatten)]
    pub versions: CompatibilityInfo,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceReplayContract {
    pub scheduler: String,
    pub seed: u64,
    #[serde(rename = "executionOrder")]
    pub execution_order: Vec<u64>,
    #[serde(rename = "asyncSchedule")]
    pub async_schedule: Vec<u64>,
    #[serde(rename = "rpcFrames")]
    pub rpc_frames: Vec<TraceRpcFrame>,
    #[serde(rename = "runtimeEvents")]
    pub runtime_events: Vec<TraceRuntimeEvent>,
    #[serde(rename = "causalLinks")]
    pub causal_links: Vec<TraceCausalLink>,
    #[serde(rename = "capabilitySet")]
    pub capability_set: Vec<String>,
    #[serde(rename = "checkpointCount")]
    pub checkpoint_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRpcFrame {
    pub kind: String,
    pub method: String,
    #[serde(rename = "taskId")]
    pub task_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRuntimeEvent {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCausalLink {
    pub from: String,
    pub to: String,
    pub relation: String,
}

impl Default for TraceCompatibility {
    fn default() -> Self {
        Self {
            versions: crate::compatibility_info(),
        }
    }
}

fn hydrate_legacy_compatibility(trace: &mut TraceFile) {
    if trace.compatibility.versions.trace_schema_version.is_empty() {
        trace.compatibility = TraceCompatibility {
            versions: compatibility_info_for_trace_version(trace.version),
        };
    }
    if trace.engine.compatibility.trace_schema_version.is_empty() {
        trace.engine.compatibility = compatibility_info_for_trace_version(trace.version);
    }
    if trace.version < CURRENT_TRACE_VERSION && trace.replay_contract.scheduler.is_empty() {
        trace.replay_contract =
            trace_replay_contract(trace.summary.identity.seed, &trace.decisions, &trace.events);
    }
}

fn compatibility_info_for_trace_version(version: u32) -> CompatibilityInfo {
    let mut compatibility = crate::compatibility_info();
    compatibility.trace_schema_version = format!("{}.v{}", TRACE_FORMAT, version);
    compatibility
}

impl TraceFile {
    pub fn new(
        mode: RunMode,
        scenario_path: Option<String>,
        scenario: Option<ScenarioV1Steps>,
        decisions: Vec<Decision>,
        events: Vec<TraceEvent>,
        summary: RunSummary,
    ) -> Self {
        let replay_contract = trace_replay_contract(summary.identity.seed, &decisions, &events);
        Self::new_with_contract(
            mode,
            scenario_path,
            scenario,
            decisions,
            events,
            replay_contract,
            summary,
        )
    }

    pub fn new_with_contract(
        mode: RunMode,
        scenario_path: Option<String>,
        scenario: Option<ScenarioV1Steps>,
        decisions: Vec<Decision>,
        events: Vec<TraceEvent>,
        replay_contract: TraceReplayContract,
        summary: RunSummary,
    ) -> Self {
        Self {
            format: TRACE_FORMAT.to_string(),
            version: CURRENT_TRACE_VERSION,
            engine: crate::version_info(),
            compatibility: TraceCompatibility {
                versions: crate::compatibility_info(),
            },
            mode,
            scenario_path,
            scenario,
            fuzz: None,
            explore: None,
            memory: None,
            decisions,
            events,
            replay_contract,
            summary,
            checksum: None,
        }
    }

    pub fn new_fuzz(
        target: String,
        input: &[u8],
        events: Vec<TraceEvent>,
        summary: RunSummary,
    ) -> Self {
        let decisions = Vec::new();
        let replay_contract = trace_replay_contract(summary.identity.seed, &decisions, &events);
        Self::new_fuzz_with_contract(target, input, events, replay_contract, summary)
    }

    pub fn new_fuzz_with_contract(
        target: String,
        input: &[u8],
        events: Vec<TraceEvent>,
        replay_contract: TraceReplayContract,
        summary: RunSummary,
    ) -> Self {
        let decisions = Vec::new();
        Self {
            format: TRACE_FORMAT.to_string(),
            version: CURRENT_TRACE_VERSION,
            engine: crate::version_info(),
            compatibility: TraceCompatibility {
                versions: crate::compatibility_info(),
            },
            mode: RunMode::Fuzz,
            scenario_path: None,
            scenario: None,
            fuzz: Some(FuzzTrace {
                target,
                input_hex: bytes_to_hex(input),
            }),
            explore: None,
            memory: None,
            decisions,
            events,
            replay_contract,
            summary,
            checksum: None,
        }
    }

    pub fn new_explore(
        explore: ExploreTrace,
        decisions: Vec<Decision>,
        events: Vec<TraceEvent>,
        summary: RunSummary,
    ) -> Self {
        let replay_contract = trace_replay_contract(summary.identity.seed, &decisions, &events);
        Self::new_explore_with_contract(explore, decisions, events, replay_contract, summary)
    }

    pub fn new_explore_with_contract(
        explore: ExploreTrace,
        decisions: Vec<Decision>,
        events: Vec<TraceEvent>,
        replay_contract: TraceReplayContract,
        summary: RunSummary,
    ) -> Self {
        Self {
            format: TRACE_FORMAT.to_string(),
            version: CURRENT_TRACE_VERSION,
            engine: crate::version_info(),
            compatibility: TraceCompatibility {
                versions: crate::compatibility_info(),
            },
            mode: RunMode::Explore,
            scenario_path: None,
            scenario: None,
            fuzz: None,
            explore: Some(explore),
            memory: None,
            decisions,
            events,
            replay_contract,
            summary,
            checksum: None,
        }
    }

    pub fn write_json(&self, path: &Path) -> FozzyResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let pretty = std::env::var("FOZZY_TRACE_PRETTY")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let payload = serialize_trace_payload(self, pretty)?;
        let checksum = trace_checksum(self)?;
        // Atomic replace to avoid concurrent writer corruption on shared paths.
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("trace.fozzy");
        let tmp_name = format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let tmp_path = parent.join(tmp_name);
        let mut file = std::fs::File::create(&tmp_path)?;
        write_trace_payload_with_checksum(&mut file, &payload, checksum.as_str(), pretty)?;
        file.flush()?;
        drop(file);
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    pub fn read_json(path: &Path) -> FozzyResult<Self> {
        let bytes = std::fs::read(path)?;
        let mut t: TraceFile = serde_json::from_slice(&bytes).map_err(|e| {
            FozzyError::Trace(format!("failed to parse trace {}: {e}", path.display()))
        })?;
        hydrate_legacy_compatibility(&mut t);
        validate_trace_header(&t, path)?;
        verify_checksum(&t, path)?;
        Ok(t)
    }
}

fn write_trace_json<W: Write>(
    writer: &mut W,
    trace: &TraceFile,
    checksum: Option<&str>,
    pretty: bool,
) -> FozzyResult<()> {
    let view = TraceWriteView {
        format: &trace.format,
        version: trace.version,
        engine: &trace.engine,
        compatibility: &trace.compatibility,
        mode: trace.mode,
        scenario_path: trace.scenario_path.as_ref(),
        scenario: trace.scenario.as_ref(),
        fuzz: trace.fuzz.as_ref(),
        explore: trace.explore.as_ref(),
        memory: trace.memory.as_ref(),
        decisions: &trace.decisions,
        events: &trace.events,
        replay_contract: &trace.replay_contract,
        summary: &trace.summary,
        checksum,
    };
    if pretty {
        let mut serializer =
            serde_json::Serializer::with_formatter(writer, serde_json::ser::PrettyFormatter::new());
        view.serialize(&mut serializer)?;
    } else {
        let mut serializer = serde_json::Serializer::new(writer);
        view.serialize(&mut serializer)?;
    }
    Ok(())
}

fn trace_checksum(trace: &TraceFile) -> FozzyResult<String> {
    let mut writer = Blake3Writer::default();
    write_trace_json(&mut writer, trace, None, false)?;
    Ok(writer.finalize())
}

fn serialize_trace_payload(trace: &TraceFile, pretty: bool) -> FozzyResult<Vec<u8>> {
    let mut writer = Vec::new();
    write_trace_json(&mut writer, trace, None, pretty)?;
    Ok(writer)
}

fn write_trace_payload_with_checksum<W: Write>(
    writer: &mut W,
    payload: &[u8],
    checksum: &str,
    pretty: bool,
) -> FozzyResult<()> {
    if payload.last().copied() != Some(b'}') {
        return Err(FozzyError::Trace(
            "failed to serialize trace payload as a JSON object".to_string(),
        ));
    }
    if pretty {
        let mut object_body_len = payload.len() - 1;
        if object_body_len > 0 && payload[object_body_len - 1] == b'\n' {
            object_body_len -= 1;
        }
        writer.write_all(&payload[..object_body_len])?;
        writer.write_all(b",\n  \"checksum\": \"")?;
        writer.write_all(checksum.as_bytes())?;
        writer.write_all(b"\"\n}")?;
    } else {
        writer.write_all(&payload[..payload.len() - 1])?;
        writer.write_all(b",\"checksum\":\"")?;
        writer.write_all(checksum.as_bytes())?;
        writer.write_all(b"\"}")?;
    }
    Ok(())
}

#[derive(Default)]
struct Blake3Writer {
    hasher: blake3::Hasher,
}

impl Blake3Writer {
    fn finalize(self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }
}

impl Write for Blake3Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct TraceWriteView<'a> {
    format: &'a str,
    version: u32,
    engine: &'a VersionInfo,
    compatibility: &'a TraceCompatibility,
    mode: RunMode,
    scenario_path: Option<&'a String>,
    scenario: Option<&'a ScenarioV1Steps>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fuzz: Option<&'a FuzzTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    explore: Option<&'a ExploreTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    memory: Option<&'a MemoryTrace>,
    decisions: &'a [Decision],
    events: &'a [TraceEvent],
    #[serde(rename = "replayContract")]
    replay_contract: &'a TraceReplayContract,
    summary: &'a RunSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checksum: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceVerifyReport {
    pub ok: bool,
    pub path: String,
    pub version: u32,
    #[serde(rename = "traceSchemaVersion")]
    pub trace_schema_version: String,
    pub compatibility: TraceCompatibility,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<TraceVerifyCheck>,
    #[serde(rename = "checksumPresent")]
    pub checksum_present: bool,
    #[serde(rename = "checksumValid")]
    pub checksum_valid: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceVerifyCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

pub fn trace_schema_warnings(version: u32) -> Vec<String> {
    if version < CURRENT_TRACE_VERSION {
        vec![format!(
            "trace schema v{version} is stale; current schema is v{CURRENT_TRACE_VERSION}"
        )]
    } else {
        Vec::new()
    }
}

pub fn verify_trace_file(path: &Path) -> FozzyResult<TraceVerifyReport> {
    let t = TraceFile::read_json(path)?;
    let mut report = verify_trace(&t);
    report.path = path.display().to_string();
    Ok(report)
}

pub fn verify_trace(trace: &TraceFile) -> TraceVerifyReport {
    let mut warnings = trace_schema_warnings(trace.version);
    warnings.extend(trace_replay_warnings(trace));
    let checks = trace_verify_checks(trace, &mut warnings);
    TraceVerifyReport {
        ok: checks.iter().all(|check| check.ok),
        path: String::new(),
        version: trace.version,
        trace_schema_version: format!("{}.v{}", trace.format, trace.version),
        compatibility: trace.compatibility.clone(),
        checks,
        checksum_present: trace.checksum.is_some(),
        checksum_valid: trace.checksum.is_some(),
        warnings,
    }
}

pub(crate) fn trace_replay_contract(
    seed: u64,
    decisions: &[Decision],
    events: &[TraceEvent],
) -> TraceReplayContract {
    let mut execution_order = Vec::new();
    let mut async_schedule = Vec::new();
    let mut capability_set = BTreeSet::new();
    let mut rpc_frames = Vec::new();
    let mut checkpoint_count = 0usize;
    let mut runtime_event_counts = BTreeMap::<String, usize>::new();

    for decision in decisions {
        match decision {
            Decision::SchedulerPick { task_id, label } => {
                execution_order.push(*task_id);
                if label.to_ascii_lowercase().contains("async")
                    || label.to_ascii_lowercase().contains("await")
                {
                    async_schedule.push(*task_id);
                }
            }
            Decision::Step { .. } => {}
            _ => {}
        }
    }

    for event in events {
        *runtime_event_counts.entry(event.name.clone()).or_insert(0) += 1;
        if event.name == "memory_checkpoint" {
            checkpoint_count += 1;
        }
        if let Some(capability) = event.name.strip_prefix("capability_") {
            capability_set.insert(capability.to_string());
        }
        match event.name.as_str() {
            "proc_spawn" => {
                capability_set.insert("proc".to_string());
            }
            "http_request" => {
                capability_set.insert("http".to_string());
            }
            "memory_checkpoint" => {
                capability_set.insert("memory".to_string());
            }
            _ => {}
        }
        if let Some(frame) = trace_rpc_frame_from_event(event) {
            rpc_frames.push(frame);
        }
    }

    let runtime_events = runtime_event_counts
        .into_iter()
        .map(|(name, count)| TraceRuntimeEvent { name, count })
        .collect::<Vec<_>>();

    let mut causal_links = Vec::new();
    for window in execution_order.windows(2) {
        causal_links.push(TraceCausalLink {
            from: format!("task:{}", window[0]),
            to: format!("task:{}", window[1]),
            relation: "schedule.next".to_string(),
        });
    }
    for window in rpc_frames.windows(2) {
        causal_links.push(TraceCausalLink {
            from: format!(
                "rpc:{}:{}:{}",
                window[0].kind, window[0].method, window[0].task_id
            ),
            to: format!(
                "rpc:{}:{}:{}",
                window[1].kind, window[1].method, window[1].task_id
            ),
            relation: "rpc.frame.order".to_string(),
        });
    }

    TraceReplayContract {
        scheduler: "decision_replay".to_string(),
        seed,
        execution_order,
        async_schedule,
        rpc_frames,
        runtime_events,
        causal_links,
        capability_set: capability_set.into_iter().collect(),
        checkpoint_count,
    }
}

impl Default for TraceRpcFrame {
    fn default() -> Self {
        Self {
            kind: String::new(),
            method: String::new(),
            task_id: 0,
        }
    }
}

impl Default for TraceRuntimeEvent {
    fn default() -> Self {
        Self {
            name: String::new(),
            count: 0,
        }
    }
}

impl Default for TraceCausalLink {
    fn default() -> Self {
        Self {
            from: String::new(),
            to: String::new(),
            relation: String::new(),
        }
    }
}

fn trace_rpc_frame_from_event(event: &TraceEvent) -> Option<TraceRpcFrame> {
    let kind = match event.name.as_str() {
        "rpc_send" | "rpc_recv" | "rpc_deadline" | "rpc_cancel" => event.name.clone(),
        "rpc.frame" => event
            .fields
            .get("event")
            .and_then(|value| value.as_str())
            .unwrap_or("rpc_recv")
            .to_string(),
        _ => return None,
    };
    let method = event
        .fields
        .get("method")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown")
        .to_string();
    let task_id = event
        .fields
        .get("taskId")
        .or_else(|| event.fields.get("task_id"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    Some(TraceRpcFrame {
        kind,
        method,
        task_id,
    })
}

fn trace_verify_checks(trace: &TraceFile, warnings: &mut Vec<String>) -> Vec<TraceVerifyCheck> {
    let mut checks = Vec::new();
    checks.push(TraceVerifyCheck {
        name: "compatibility_set".to_string(),
        ok: trace.compatibility.versions.trace_schema_version
            == format!("{}.v{}", TRACE_FORMAT, trace.version),
        detail: format!(
            "language={} trace={} manifest={} runtimeAbi={} nativeImportTable={} diagnostics={}",
            trace.compatibility.versions.language_version,
            trace.compatibility.versions.trace_schema_version,
            trace.compatibility.versions.manifest_schema_version,
            trace.compatibility.versions.runtime_abi_version,
            trace.compatibility.versions.native_import_table_version,
            trace.compatibility.versions.diagnostic_catalog_version
        ),
    });

    let seed_ok = trace.replay_contract.seed == trace.summary.identity.seed;
    if !seed_ok {
        warnings
            .push("trace replay contract seed does not match summary identity seed".to_string());
    }
    checks.push(TraceVerifyCheck {
        name: "seed_matches_summary".to_string(),
        ok: seed_ok,
        detail: format!(
            "contract_seed={} summary_seed={}",
            trace.replay_contract.seed, trace.summary.identity.seed
        ),
    });

    let execution_order_ok =
        !trace.replay_contract.execution_order.is_empty() || trace.decisions.is_empty();
    if !execution_order_ok {
        warnings.push("trace executionOrder is empty despite recorded decisions".to_string());
    }
    checks.push(TraceVerifyCheck {
        name: "execution_order_present".to_string(),
        ok: execution_order_ok,
        detail: format!(
            "execution_order={} decisions={}",
            trace.replay_contract.execution_order.len(),
            trace.decisions.len()
        ),
    });

    let async_schedule_ok = trace
        .replay_contract
        .async_schedule
        .iter()
        .all(|task_id| trace.replay_contract.execution_order.contains(task_id));
    if !async_schedule_ok {
        warnings.push(
            "trace asyncSchedule references task ids missing from executionOrder".to_string(),
        );
    }
    checks.push(TraceVerifyCheck {
        name: "async_schedule_subset".to_string(),
        ok: async_schedule_ok,
        detail: format!(
            "async_schedule={} execution_order={}",
            trace.replay_contract.async_schedule.len(),
            trace.replay_contract.execution_order.len()
        ),
    });

    let rpc_frames_ok = validate_trace_rpc_frames(&trace.replay_contract.rpc_frames, warnings);
    checks.push(TraceVerifyCheck {
        name: "rpc_frames_ordered".to_string(),
        ok: rpc_frames_ok,
        detail: format!("rpc_frames={}", trace.replay_contract.rpc_frames.len()),
    });

    let runtime_event_count: usize = trace
        .replay_contract
        .runtime_events
        .iter()
        .map(|event| event.count)
        .sum();
    let runtime_events_ok = runtime_event_count == trace.events.len();
    if !runtime_events_ok {
        warnings.push(format!(
            "trace runtimeEvents count {} does not match event list {}",
            runtime_event_count,
            trace.events.len()
        ));
    }
    checks.push(TraceVerifyCheck {
        name: "runtime_events_match".to_string(),
        ok: runtime_events_ok,
        detail: format!(
            "runtime_events={} events={}",
            runtime_event_count,
            trace.events.len()
        ),
    });

    let checkpoints = trace
        .events
        .iter()
        .filter(|event| event.name == "memory_checkpoint")
        .count();
    let checkpoint_ok = checkpoints == trace.replay_contract.checkpoint_count;
    if !checkpoint_ok {
        warnings.push(format!(
            "trace checkpointCount {} does not match memory_checkpoint events {}",
            trace.replay_contract.checkpoint_count, checkpoints
        ));
    }
    checks.push(TraceVerifyCheck {
        name: "checkpoint_count_match".to_string(),
        ok: checkpoint_ok,
        detail: format!(
            "checkpoint_count={} memory_checkpoint_events={}",
            trace.replay_contract.checkpoint_count, checkpoints
        ),
    });

    let causal_links_ok = trace.replay_contract.causal_links.len()
        >= trace
            .replay_contract
            .execution_order
            .len()
            .saturating_sub(1);
    if !causal_links_ok {
        warnings.push("trace causalLinks are incomplete for executionOrder".to_string());
    }
    checks.push(TraceVerifyCheck {
        name: "causal_links_present".to_string(),
        ok: causal_links_ok,
        detail: format!(
            "causal_links={} execution_order={}",
            trace.replay_contract.causal_links.len(),
            trace.replay_contract.execution_order.len()
        ),
    });

    checks
}

fn validate_trace_rpc_frames(frames: &[TraceRpcFrame], warnings: &mut Vec<String>) -> bool {
    let mut inflight = BTreeMap::<String, usize>::new();
    let mut ok = true;
    for frame in frames {
        if frame.method.trim().is_empty() || frame.task_id == 0 {
            ok = false;
            warnings.push(format!(
                "trace rpc frame `{}` has incomplete method/task identity",
                frame.kind
            ));
        }
        match frame.kind.as_str() {
            "rpc_send" => {
                *inflight.entry(frame.method.clone()).or_insert(0) += 1;
            }
            "rpc_recv" | "rpc_deadline" | "rpc_cancel" => {
                let entry = inflight.entry(frame.method.clone()).or_insert(0);
                if *entry == 0 {
                    ok = false;
                    warnings.push(format!(
                        "trace rpc frame `{}` for `{}` is out of order",
                        frame.kind, frame.method
                    ));
                } else {
                    *entry -= 1;
                }
            }
            _ => {}
        }
    }
    for (method, count) in inflight {
        if count > 0 {
            ok = false;
            warnings.push(format!(
                "trace rpcFrames left {count} in-flight request(s) for `{method}`"
            ));
        }
    }
    ok
}

pub fn write_trace_with_policy(
    trace: &TraceFile,
    requested: &Path,
    policy: RecordCollisionPolicy,
) -> FozzyResult<PathBuf> {
    let target = resolve_record_target(requested, policy)?;
    write_trace_to_target(trace, &target)?;
    Ok(target)
}

pub(crate) fn write_trace_to_target(trace: &TraceFile, target: &Path) -> FozzyResult<()> {
    let _lock = acquire_record_lock(&target)?;
    trace.write_json(&target)?;
    Ok(())
}

pub fn trace_replay_warnings(trace: &TraceFile) -> Vec<String> {
    let used_host_fs = trace.events.iter().any(|e| {
        e.name == "capability_fs"
            && e.fields
                .get("backend")
                .and_then(|v| v.as_str())
                .is_some_and(|backend| backend == "host")
    });
    let has_fs_decisions = trace.decisions.iter().any(|d| {
        matches!(
            d,
            Decision::FsWrite { .. }
                | Decision::FsReadAssert { .. }
                | Decision::FsSnapshot { .. }
                | Decision::FsRestore { .. }
        )
    });
    let used_host_proc = trace.events.iter().any(|e| {
        e.name == "proc_spawn"
            && e.fields
                .get("backend")
                .and_then(|v| v.as_str())
                .is_some_and(|backend| backend == "host")
    });
    let has_proc_decisions = trace.decisions.iter().any(|d| {
        matches!(
            d,
            Decision::ProcSpawn { .. } | Decision::ProcSpawnTimeout { .. }
        )
    });
    let used_host_http = trace.events.iter().any(|e| {
        e.name == "http_request"
            && e.fields
                .get("backend")
                .and_then(|v| v.as_str())
                .is_some_and(|backend| backend == "host")
    });
    let has_http_decisions = trace.decisions.iter().any(|d| {
        matches!(
            d,
            Decision::HttpRequest { .. } | Decision::HttpRequestTimeout { .. }
        )
    });

    let mut warnings = Vec::new();
    if used_host_fs && !has_fs_decisions {
        warnings.push(
            "trace used host fs backend but does not include fs decisions; replay may drift"
                .to_string(),
        );
    }
    if used_host_proc && !has_proc_decisions {
        warnings.push(
            "trace used host proc backend but does not include proc decisions; replay may drift"
                .to_string(),
        );
    }
    if used_host_http && !has_http_decisions {
        warnings.push(
            "trace used host http backend but does not include http decisions; replay may drift"
                .to_string(),
        );
    }
    warnings
}

pub(crate) fn resolve_record_target(
    path: &Path,
    policy: RecordCollisionPolicy,
) -> FozzyResult<PathBuf> {
    match policy {
        RecordCollisionPolicy::Overwrite => Ok(path.to_path_buf()),
        RecordCollisionPolicy::Error => {
            if path.exists() {
                Err(FozzyError::Trace(format!(
                    "record collision: {} already exists (--record-collision=error). rerun with --record-collision overwrite (replace) or --record-collision append (keep both)",
                    path.display(),
                )))
            } else {
                Ok(path.to_path_buf())
            }
        }
        RecordCollisionPolicy::Append => {
            if !path.exists() {
                return Ok(path.to_path_buf());
            }
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("trace");
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("fozzy");
            let prefix = format!("{stem}.");
            let suffix = format!(".{ext}");
            let mut max_seen = 0u32;
            for entry in std::fs::read_dir(parent)? {
                let Ok(entry) = entry else {
                    continue;
                };
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if !name.starts_with(&prefix) || !name.ends_with(&suffix) {
                    continue;
                }
                let Some(mid) = name
                    .strip_prefix(&prefix)
                    .and_then(|n| n.strip_suffix(&suffix))
                else {
                    continue;
                };
                if let Ok(i) = mid.parse::<u32>() {
                    max_seen = max_seen.max(i);
                }
            }
            Ok(parent.join(format!("{stem}.{}.{ext}", max_seen.saturating_add(1))))
        }
    }
}

struct RecordLockGuard {
    lock_path: PathBuf,
}

impl Drop for RecordLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

fn acquire_record_lock(target: &Path) -> FozzyResult<RecordLockGuard> {
    let lock_path = PathBuf::from(format!("{}.lock", target.to_string_lossy()));
    let try_open = || {
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
    };

    match try_open() {
        Ok(mut f) => {
            use std::io::Write as _;
            let _ = writeln!(
                &mut f,
                "pid={} created_unix_ms={}",
                std::process::id(),
                unix_time_ms(SystemTime::now())
            );
            Ok(RecordLockGuard { lock_path })
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if is_stale_lock(&lock_path, RECORD_LOCK_STALE_AFTER) {
                let _ = std::fs::remove_file(&lock_path);
                match try_open() {
                    Ok(_) => Ok(RecordLockGuard { lock_path }),
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                        Err(FozzyError::Trace(format!(
                            "record collision: active writer holds lock for {}",
                            target.display()
                        )))
                    }
                    Err(err) => Err(err.into()),
                }
            } else {
                Err(FozzyError::Trace(format!(
                    "record collision: active writer holds lock for {}",
                    target.display()
                )))
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn is_stale_lock(path: &Path, ttl: Duration) -> bool {
    let Ok(md) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = md.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    age > ttl
}

fn unix_time_ms(now: SystemTime) -> u128 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

const RECORD_LOCK_STALE_AFTER: Duration = Duration::from_secs(300);

fn verify_checksum(trace: &TraceFile, path: &Path) -> FozzyResult<()> {
    let Some(expected) = trace.checksum.as_ref() else {
        return Ok(());
    };
    let got = trace_checksum(trace)?;
    if &got != expected {
        return Err(FozzyError::Trace(format!(
            "trace checksum mismatch for {} (expected {}, got {})",
            path.display(),
            expected,
            got
        )));
    }
    Ok(())
}

fn validate_trace_header(trace: &TraceFile, path: &Path) -> FozzyResult<()> {
    if trace.format != TRACE_FORMAT {
        return Err(FozzyError::Trace(format!(
            "unsupported trace format for {}: got {}, expected {}",
            path.display(),
            trace.format,
            TRACE_FORMAT
        )));
    }
    if !(1..=CURRENT_TRACE_VERSION).contains(&trace.version) {
        return Err(FozzyError::Trace(format!(
            "unsupported trace schema version for {}: v{} (supported: 1..={})",
            path.display(),
            trace.version,
            CURRENT_TRACE_VERSION
        )));
    }
    Ok(())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn trace_pretty_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }
    use crate::{ExitStatus, RunIdentity, RunSummary};
    use uuid::Uuid;

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fozzy-trace-tests-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join(name)
    }

    fn sample_summary(trace_path: Option<String>) -> RunSummary {
        RunSummary {
            status: ExitStatus::Pass,
            mode: RunMode::Run,
            identity: RunIdentity {
                run_id: "run-1".to_string(),
                seed: 1,
                trace_path,
                report_path: None,
                artifacts_dir: None,
            },
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: "2026-01-01T00:00:00Z".to_string(),
            duration_ms: 0,
            duration_ns: 0,
            tests: None,
            memory: None,
            findings: Vec::new(),
        }
    }

    #[test]
    fn trace_parses_legacy_scheduler_and_step_decisions() {
        let raw = r#"{
          "format":"fozzy-trace",
          "version":1,
          "engine":{"version":"0.1.0"},
          "mode":"run",
          "scenario_path":"tests/example.fozzy.json",
          "scenario":{"version":1,"name":"example","steps":[]},
          "decisions":[
            {"kind":"scheduler_pick","task_id":1,"label":"step0"},
            {"kind":"step","index":0,"name":"legacy-step"}
          ],
          "events":[],
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r1","seed":1},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          }
        }"#;

        let trace: TraceFile = serde_json::from_str(raw).expect("legacy trace parses");
        assert_eq!(trace.version, 1);
        assert_eq!(trace.decisions.len(), 2);
    }

    #[test]
    fn trace_parses_network_replay_decisions() {
        let raw = r#"{
          "format":"fozzy-trace",
          "version":1,
          "engine":{"version":"0.1.0"},
          "mode":"run",
          "scenario_path":"tests/net.fozzy.json",
          "scenario":{"version":1,"name":"net","steps":[]},
          "decisions":[
            {"kind":"scheduler_pick","task_id":1,"label":"NetDeliverOne"},
            {"kind":"net_deliver_pick","message_id":42},
            {"kind":"net_drop","message_id":42,"dropped":false}
          ],
          "events":[],
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r2","seed":2},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          }
        }"#;

        let trace: TraceFile = serde_json::from_str(raw).expect("network trace parses");
        assert_eq!(trace.decisions.len(), 3);
        let out = serde_json::to_string(&trace).expect("trace serializes");
        assert!(out.contains("net_deliver_pick"));
        assert!(out.contains("net_drop"));
    }

    #[test]
    fn checksum_mismatch_is_rejected() {
        let path = temp_file("bad.fozzy");
        let raw = r#"{
          "format":"fozzy-trace",
          "version":2,
          "engine":{"version":"0.1.0"},
          "mode":"run",
          "scenario_path":null,
          "scenario":{"version":1,"name":"x","steps":[]},
          "decisions":[],
          "events":[],
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r1","seed":1},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          },
          "checksum":"deadbeef"
        }"#;
        std::fs::write(&path, raw).expect("write");
        let err = TraceFile::read_json(&path).expect_err("must reject checksum mismatch");
        assert!(err.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn record_collision_error_policy_rejects_existing_target() {
        let path = temp_file("exists.fozzy");
        std::fs::write(&path, b"old").expect("write existing");
        let trace = TraceFile::new(
            RunMode::Run,
            None,
            Some(ScenarioV1Steps {
                version: 1,
                name: "x".to_string(),
                steps: Vec::new(),
            }),
            Vec::new(),
            Vec::new(),
            sample_summary(Some(path.to_string_lossy().to_string())),
        );
        let err = write_trace_with_policy(&trace, &path, RecordCollisionPolicy::Error)
            .expect_err("must fail");
        assert!(err.to_string().contains("record collision"));
    }

    #[test]
    fn record_collision_append_policy_picks_numbered_path() {
        let path = temp_file("trace.fozzy");
        std::fs::write(&path, b"old").expect("write existing");
        let trace = TraceFile::new(
            RunMode::Run,
            None,
            Some(ScenarioV1Steps {
                version: 1,
                name: "x".to_string(),
                steps: Vec::new(),
            }),
            Vec::new(),
            Vec::new(),
            sample_summary(None),
        );
        let out =
            write_trace_with_policy(&trace, &path, RecordCollisionPolicy::Append).expect("append");
        assert_ne!(out, path);
        assert!(out.to_string_lossy().contains(".1.fozzy"));
        let loaded = TraceFile::read_json(&out).expect("trace exists");
        assert_eq!(loaded.format, "fozzy-trace");
    }

    #[test]
    fn truncated_trace_is_rejected() {
        let path = temp_file("truncated.fozzy");
        std::fs::write(&path, br#"{"format":"fozzy-trace""#).expect("write");
        let err = TraceFile::read_json(&path).expect_err("must fail");
        assert!(err.to_string().contains("failed to parse trace"));
    }

    #[test]
    fn random_bytes_trace_is_rejected() {
        let path = temp_file("random.fozzy");
        std::fs::write(&path, [0_u8, 159, 146, 150, 255, 0, 1, 2]).expect("write");
        let err = TraceFile::read_json(&path).expect_err("must fail");
        assert!(err.to_string().contains("failed to parse trace"));
    }

    #[test]
    fn unsupported_trace_format_is_rejected() {
        let path = temp_file("bad-format.fozzy");
        let raw = r#"{
          "format":"fozzy-trace-vX",
          "version":2,
          "engine":{"version":"0.1.0"},
          "mode":"run",
          "scenario_path":null,
          "scenario":{"version":1,"name":"x","steps":[]},
          "decisions":[],
          "events":[],
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r1","seed":1},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          }
        }"#;
        std::fs::write(&path, raw).expect("write");
        let err = TraceFile::read_json(&path).expect_err("must reject unsupported format");
        assert!(err.to_string().contains("unsupported trace format"));
    }

    #[test]
    fn unsupported_trace_version_is_rejected() {
        let path = temp_file("bad-version.fozzy");
        let raw = r#"{
          "format":"fozzy-trace",
          "version":999,
          "engine":{"version":"0.1.0"},
          "mode":"run",
          "scenario_path":null,
          "scenario":{"version":1,"name":"x","steps":[]},
          "decisions":[],
          "events":[],
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r1","seed":1},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          }
        }"#;
        std::fs::write(&path, raw).expect("write");
        let err = TraceFile::read_json(&path).expect_err("must reject unsupported version");
        assert!(err.to_string().contains("unsupported trace schema version"));
    }

    #[test]
    fn verify_warns_on_legacy_host_proc_trace_without_proc_decisions() {
        let path = temp_file("legacy-host-proc.fozzy");
        let trace = TraceFile::new(
            RunMode::Run,
            None,
            Some(ScenarioV1Steps {
                version: 1,
                name: "x".to_string(),
                steps: Vec::new(),
            }),
            Vec::new(),
            vec![TraceEvent {
                time_ms: 0,
                name: "proc_spawn".to_string(),
                fields: serde_json::Map::from_iter([(
                    "backend".to_string(),
                    serde_json::Value::String("host".to_string()),
                )]),
            }],
            sample_summary(None),
        );
        trace.write_json(&path).expect("write");

        let verify = verify_trace_file(&path).expect("verify");
        assert!(
            verify
                .warnings
                .iter()
                .any(|w| w.contains("host proc backend") && w.contains("replay may drift"))
        );
    }

    #[test]
    fn verify_warns_on_legacy_host_fs_trace_without_fs_decisions() {
        let path = temp_file("legacy-host-fs.fozzy");
        let trace = TraceFile::new(
            RunMode::Run,
            None,
            Some(ScenarioV1Steps {
                version: 1,
                name: "x".to_string(),
                steps: Vec::new(),
            }),
            Vec::new(),
            vec![TraceEvent {
                time_ms: 0,
                name: "capability_fs".to_string(),
                fields: serde_json::Map::from_iter([(
                    "backend".to_string(),
                    serde_json::Value::String("host".to_string()),
                )]),
            }],
            sample_summary(None),
        );
        trace.write_json(&path).expect("write");

        let verify = verify_trace_file(&path).expect("verify");
        assert!(
            verify
                .warnings
                .iter()
                .any(|w| w.contains("host fs backend") && w.contains("replay may drift"))
        );
    }

    #[test]
    fn verify_report_includes_compatibility_and_replay_contract_checks() {
        let path = temp_file("compat.fozzy");
        let trace = TraceFile::new(
            RunMode::Run,
            None,
            Some(ScenarioV1Steps {
                version: 1,
                name: "compat".to_string(),
                steps: Vec::new(),
            }),
            vec![Decision::SchedulerPick {
                task_id: 7,
                label: "async_worker".to_string(),
            }],
            vec![
                TraceEvent {
                    time_ms: 0,
                    name: "capability_proc".to_string(),
                    fields: serde_json::Map::new(),
                },
                TraceEvent {
                    time_ms: 1,
                    name: "memory_checkpoint".to_string(),
                    fields: serde_json::Map::new(),
                },
            ],
            sample_summary(None),
        );
        trace.write_json(&path).expect("write");

        let verify = verify_trace_file(&path).expect("verify");
        assert_eq!(
            verify.compatibility.versions.trace_schema_version,
            format!("{}.v{}", TRACE_FORMAT, CURRENT_TRACE_VERSION)
        );
        assert!(
            verify
                .checks
                .iter()
                .any(|check| check.name == "compatibility_set" && check.ok)
        );
        assert!(
            verify
                .checks
                .iter()
                .any(|check| check.name == "checkpoint_count_match" && check.ok)
        );
        assert!(verify.warnings.is_empty(), "{:#?}", verify.warnings);
    }

    #[test]
    fn verify_warns_on_rpc_frame_order_drift() {
        let path = temp_file("rpc-order.fozzy");
        let raw = r#"{
          "format":"fozzy-trace",
          "version":4,
          "engine":{"version":"0.1.0","compatibility":{"languageVersion":"fozzylang.language.v1","traceSchemaVersion":"fozzy-trace.v4","manifestSchemaVersion":"fozzy.run_manifest.v1","runtimeAbiVersion":"fozzylang.runtime.v0","nativeImportTableVersion":"fozzylang.native_runtime_contracts.v1","diagnosticCatalogVersion":"fozzylang.diagnostic_catalog.v1"}},
          "compatibility":{"languageVersion":"fozzylang.language.v1","traceSchemaVersion":"fozzy-trace.v4","manifestSchemaVersion":"fozzy.run_manifest.v1","runtimeAbiVersion":"fozzylang.runtime.v0","nativeImportTableVersion":"fozzylang.native_runtime_contracts.v1","diagnosticCatalogVersion":"fozzylang.diagnostic_catalog.v1"},
          "mode":"run",
          "scenario_path":null,
          "scenario":{"version":1,"name":"x","steps":[]},
          "decisions":[],
          "events":[
            {"time_ms":0,"name":"rpc_recv","fields":{"method":"Ping","taskId":7}}
          ],
          "replayContract":{
            "scheduler":"decision_replay",
            "seed":1,
            "executionOrder":[],
            "asyncSchedule":[],
            "rpcFrames":[{"kind":"rpc_recv","method":"Ping","taskId":7}],
            "runtimeEvents":[{"name":"rpc_recv","count":1}],
            "causalLinks":[],
            "capabilitySet":["net"],
            "checkpointCount":0
          },
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r1","seed":1},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          }
        }"#;
        std::fs::write(&path, raw).expect("write");

        let verify = verify_trace_file(&path).expect("verify");
        assert!(
            verify
                .warnings
                .iter()
                .any(|warning| warning.contains("rpc frame `rpc_recv` for `Ping` is out of order"))
        );
        assert!(
            verify
                .checks
                .iter()
                .any(|check| check.name == "rpc_frames_ordered" && !check.ok)
        );
    }

    #[test]
    fn pretty_trace_write_round_trips_with_valid_checksum() {
        let _guard = trace_pretty_env_lock().lock().expect("lock pretty env");
        let path = temp_file("pretty.fozzy");
        unsafe {
            std::env::set_var("FOZZY_TRACE_PRETTY", "1");
        }
        let trace = TraceFile::new(
            RunMode::Run,
            Some("tests/pretty.fozzy.json".to_string()),
            Some(ScenarioV1Steps {
                version: 1,
                name: "pretty".to_string(),
                steps: Vec::new(),
            }),
            Vec::new(),
            Vec::new(),
            sample_summary(None),
        );
        trace.write_json(&path).expect("write pretty trace");
        let loaded = TraceFile::read_json(&path).expect("read pretty trace");
        assert_eq!(loaded.format, TRACE_FORMAT);
        assert!(loaded.checksum.is_some());
        unsafe {
            std::env::remove_var("FOZZY_TRACE_PRETTY");
        }
    }

    #[test]
    fn trace_write_json_streams_valid_compact_payload() {
        let _guard = trace_pretty_env_lock().lock().expect("lock pretty env");
        let path = temp_file("compact.fozzy");
        unsafe {
            std::env::remove_var("FOZZY_TRACE_PRETTY");
        }
        let trace = TraceFile::new(
            RunMode::Run,
            Some("tests/compact.fozzy.json".to_string()),
            Some(ScenarioV1Steps {
                version: 1,
                name: "compact".to_string(),
                steps: Vec::new(),
            }),
            Vec::new(),
            Vec::new(),
            sample_summary(None),
        );
        trace.write_json(&path).expect("write compact trace");
        let raw = std::fs::read_to_string(&path).expect("read compact trace");
        assert!(raw.contains("\"checksum\":\""));
        assert!(raw.ends_with("}\n") || raw.ends_with('}'));
        let loaded = TraceFile::read_json(&path).expect("read compact trace");
        assert_eq!(loaded.format, TRACE_FORMAT);
    }
}
