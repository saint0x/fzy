//! Fuzzing engine (v0.2): mutation + simple coverage feedback + crash recording.
//!
//! This is intentionally self-contained so fuzz targets can evolve without
//! entangling the core scenario runner.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore as _, SeedableRng as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{
    Config, ExitStatus, Finding, FindingKind, MemoryOptions, MemoryState, ProfileCaptureLevel,
    RecordCollisionPolicy, Reporter, RunIdentity, RunMode, RunSummary, ScenarioFile, ScenarioPath,
    TraceEvent, TraceFile, should_emit_profile_artifacts, wall_time_iso_utc,
    write_memory_artifacts, write_profile_artifacts_from_trace, write_trace_with_policy,
};

use crate::{FozzyError, FozzyResult};
use crate::{HeapBudgetPolicy, heap_budget_findings_from_trace};

type LastExec = (Vec<u8>, Vec<TraceEvent>, ExitStatus, Vec<Finding>);

fn heap_budget_policy(config: &Config) -> HeapBudgetPolicy {
    HeapBudgetPolicy {
        alloc_bytes_budget: config.profile_heap_alloc_budget,
        in_use_bytes_budget: config.profile_heap_in_use_budget,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    Coverage,
    Property,
}

impl clap::ValueEnum for FuzzMode {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Coverage, Self::Property]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Coverage => clap::builder::PossibleValue::new("coverage"),
            Self::Property => clap::builder::PossibleValue::new("property"),
        })
    }
}

#[derive(Debug, Clone)]
pub enum FuzzTarget {
    Function { id: String },
    Scenario { path: PathBuf },
}

impl std::str::FromStr for FuzzTarget {
    type Err = FozzyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("fn:") {
            let id = rest.trim().to_string();
            if id.is_empty() {
                return Err(FozzyError::InvalidArgument(
                    "fuzz target fn: requires an id".to_string(),
                ));
            }
            return Ok(Self::Function { id });
        }
        if let Some(rest) = s.strip_prefix("scenario:") {
            let path = PathBuf::from(rest.trim());
            if path.as_os_str().is_empty() {
                return Err(FozzyError::InvalidArgument(
                    "fuzz target scenario: requires a path".to_string(),
                ));
            }
            return Ok(Self::Scenario { path });
        }
        if s.ends_with(".fozzy.json") {
            return Ok(Self::Scenario {
                path: PathBuf::from(s),
            });
        }

        Err(FozzyError::InvalidArgument(format!(
            "unsupported fuzz target {s:?} (expected fn:<id> or scenario:<path.fozzy.json>)"
        )))
    }
}

#[derive(Debug, Clone)]
pub struct FuzzOptions {
    pub det: bool,
    pub mode: FuzzMode,
    pub seed: Option<u64>,
    pub time: Option<Duration>,
    pub runs: Option<u64>,
    pub max_input_bytes: usize,
    pub corpus_dir: Option<PathBuf>,
    pub mutator: Option<String>,
    pub shrink: bool,
    pub record_trace_to: Option<PathBuf>,
    pub reporter: Reporter,
    pub crash_only: bool,
    pub minimize: bool,
    pub record_collision: RecordCollisionPolicy,
    pub profile_capture: ProfileCaptureLevel,
    pub memory: MemoryOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTrace {
    pub target: String,
    pub input_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzCoverageStats {
    pub target: String,
    pub executed: u64,
    pub crashes: u64,
    pub unique_edges: usize,
    pub discovered_edges_total: u64,
    pub max_new_edges_per_input: u64,
    pub corpus_entries: usize,
}

pub fn fuzz(
    config: &Config,
    target: &FuzzTarget,
    opt: &FuzzOptions,
) -> FozzyResult<crate::RunResult> {
    if opt.det && opt.time.is_some() {
        return Err(FozzyError::InvalidArgument(
            "fuzz --det requires --runs and does not support wall-clock --time".to_string(),
        ));
    }
    if opt.det && opt.runs.is_none() {
        return Err(FozzyError::InvalidArgument(
            "fuzz --det requires an explicit --runs value".to_string(),
        ));
    }

    let seed = if opt.det {
        opt.seed.unwrap_or(0)
    } else {
        opt.seed.unwrap_or_else(gen_seed)
    };
    let run_id = Uuid::new_v4().to_string();
    let started_at = wall_time_iso_utc();
    let started = Instant::now();

    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;

    let corpus_dir = opt
        .corpus_dir
        .clone()
        .unwrap_or_else(|| config.corpora_dir().join("default"));
    std::fs::create_dir_all(&corpus_dir)?;
    std::fs::create_dir_all(corpus_dir.join("crashes"))?;

    let mut rng = rng_from_seed(seed);
    let deadline = if opt.det {
        None
    } else {
        opt.time.map(|t| started + t)
    };
    let max_runs = opt.runs.unwrap_or(u64::MAX);

    let mut corpus = load_corpus(&corpus_dir)?;
    if corpus.is_empty() {
        corpus.push(Vec::new());
        corpus.push(vec![0u8]);
        corpus.push(vec![1u8, 2u8, 3u8]);
    }

    let mut global_coverage: HashSet<u64> = HashSet::new();
    let mut discovered_edges_total = 0u64;
    let mut max_new_edges_per_input = 0u64;
    let mut findings = Vec::new();
    let mut crash_trace_path: Option<PathBuf> = None;
    let mut crash_count = 0u64;
    let mut last_exec: Option<LastExec> = None;
    let mut memory_state = if opt.memory.track {
        Some(MemoryState::new(opt.memory.clone()))
    } else {
        None
    };

    let mut executed = 0u64;
    while executed < max_runs {
        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            break;
        }

        let base = &corpus[(rng.next_u64() as usize) % corpus.len()];
        let mut input = base.clone();
        mutate_bytes(&mut input, &mut rng, opt.max_input_bytes);

        let mut exec = execute_target(config, target, &input)?;
        if let Some(mem) = memory_state.as_mut() {
            let outcome = mem.allocate(
                input.len() as u64,
                Some("fuzz_input".to_string()),
                "fuzz_loop",
                executed,
            );
            if let Some(reason) = outcome.failed_reason {
                exec.status = ExitStatus::Fail;
                exec.findings.push(Finding {
                    kind: FindingKind::Checker,
                    title: "memory_alloc_failed".to_string(),
                    message: format!(
                        "memory allocation failed during fuzz input execution: {reason}"
                    ),
                    location: None,
                });
            } else if let Some(id) = outcome.alloc_id {
                // Release synthetic fuzz-loop allocation regardless of target outcome;
                // findings should not be dominated by harness-only leaks.
                let _ = mem.free(id, executed);
            }
        }
        last_exec = Some((
            input.clone(),
            exec.events.clone(),
            exec.status,
            exec.findings.clone(),
        ));
        executed += 1;

        let new_edges: Vec<u64> = exec
            .coverage
            .iter()
            .copied()
            .filter(|e| !global_coverage.contains(e))
            .collect();
        if !new_edges.is_empty() {
            discovered_edges_total = discovered_edges_total.saturating_add(new_edges.len() as u64);
            max_new_edges_per_input = max_new_edges_per_input.max(new_edges.len() as u64);
            for e in &new_edges {
                global_coverage.insert(*e);
            }
            if matches!(opt.mode, FuzzMode::Coverage) {
                corpus.push(input.clone());
                persist_corpus_input(&corpus_dir, &input)?;
            }
        }

        if exec.status != ExitStatus::Pass {
            crash_count += 1;
            findings.extend(exec.findings.clone());

            let _crash_path = persist_crash_input(&corpus_dir, &input)?;
            let report_path = artifacts_dir.join("report.json");

            let finished_at = wall_time_iso_utc();
            let (duration_ms, duration_ns) = crate::duration_fields(started.elapsed());

            let mut summary = RunSummary {
                status: exec.status,
                mode: RunMode::Fuzz,
                identity: RunIdentity {
                    run_id: run_id.clone(),
                    seed,
                    trace_path: None,
                    report_path: Some(report_path.to_string_lossy().to_string()),
                    artifacts_dir: Some(artifacts_dir.to_string_lossy().to_string()),
                },
                started_at: started_at.clone(),
                finished_at,
                duration_ms,
                duration_ns,
                tests: None,
                memory: memory_state.as_ref().map(|m| m.clone().finalize().summary),
                findings: exec.findings.clone(),
            };
            let mut budget_trace = TraceFile::new_fuzz(
                target_string(target),
                &input,
                exec.events.clone(),
                summary.clone(),
            );
            budget_trace.memory = memory_state
                .as_ref()
                .map(|m| m.clone().finalize().to_trace());
            let heap_findings =
                heap_budget_findings_from_trace(&budget_trace, &heap_budget_policy(config));
            if !heap_findings.is_empty() {
                summary.findings.extend(heap_findings);
                summary.findings = crate::collapse_findings(summary.findings.clone());
            }

            std::fs::write(&report_path, serde_json::to_vec(&summary)?)?;

            if matches!(opt.reporter, Reporter::Junit) {
                std::fs::write(
                    artifacts_dir.join("junit.xml"),
                    crate::render_junit_xml(&summary),
                )?;
            }
            if matches!(opt.reporter, Reporter::Html) {
                std::fs::write(
                    artifacts_dir.join("report.html"),
                    crate::render_html(&summary),
                )?;
            }

            let trace_out = crash_trace_output_path(
                opt.record_trace_to.as_deref(),
                &artifacts_dir,
                crash_count,
            );
            let trace = TraceFile::new_fuzz(
                target_string(target),
                &input,
                exec.events.clone(),
                summary.clone(),
            );
            let mut trace = trace;
            trace.memory = memory_state
                .as_ref()
                .map(|m| m.clone().finalize().to_trace());
            let written = write_trace_with_policy(&trace, &trace_out, opt.record_collision)?;
            crash_trace_path = Some(written);
            let emit_heavy = should_emit_heavy_artifacts(exec.status, true)
                || matches!(opt.profile_capture, ProfileCaptureLevel::Full);
            if emit_heavy {
                std::fs::write(
                    artifacts_dir.join("events.json"),
                    serde_json::to_vec(&exec.events)?,
                )?;
                crate::write_timeline(&exec.events, &artifacts_dir.join("timeline.json"))?;
            }
            if should_emit_profile_artifacts(opt.profile_capture, exec.status, true) {
                let mut profile_trace = budget_trace;
                profile_trace.summary = summary.clone();
                write_profile_artifacts_from_trace(&profile_trace, &artifacts_dir)?;
            }
            crate::write_run_manifest(&summary, &artifacts_dir)?;

            if opt.minimize || opt.shrink {
                let minimized =
                    minimize_input(config, target, &input, opt.max_input_bytes, exec.status)?;
                let _min_path = persist_crash_min_input(&corpus_dir, &minimized)?;
            }

            if opt.crash_only {
                // Stop on first crash by default when crash-only.
                break;
            }
        }
    }

    let finished_at = wall_time_iso_utc();
    let (duration_ms, duration_ns) = crate::duration_fields(started.elapsed());
    let mut status = if crash_count == 0 {
        ExitStatus::Pass
    } else {
        ExitStatus::Fail
    };
    let report_path = artifacts_dir.join("report.json");

    let memory_report = memory_state.map(|m| m.finalize());
    findings = crate::collapse_findings(findings);
    let mut summary = RunSummary {
        status,
        mode: RunMode::Fuzz,
        identity: RunIdentity {
            run_id: run_id.clone(),
            seed,
            trace_path: crash_trace_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            report_path: Some(report_path.to_string_lossy().to_string()),
            artifacts_dir: Some(artifacts_dir.to_string_lossy().to_string()),
        },
        started_at,
        finished_at,
        duration_ms,
        duration_ns,
        tests: None,
        memory: memory_report.as_ref().map(|m| m.summary.clone()),
        findings,
    };
    let (profile_input, profile_events, profile_status, profile_findings) = last_exec
        .clone()
        .unwrap_or_else(|| (Vec::new(), Vec::new(), ExitStatus::Pass, Vec::new()));
    let mut profile_summary = summary.clone();
    profile_summary.status = profile_status;
    profile_summary.findings = profile_findings;
    let mut profile_trace = TraceFile::new_fuzz(
        target_string(target),
        &profile_input,
        profile_events,
        profile_summary,
    );
    profile_trace.memory = memory_report.as_ref().map(|m| m.to_trace());
    let heap_findings =
        heap_budget_findings_from_trace(&profile_trace, &heap_budget_policy(config));
    if !heap_findings.is_empty() {
        summary.findings.extend(heap_findings);
        summary.findings = crate::collapse_findings(summary.findings.clone());
    }
    if let Some(mem) = memory_report.as_ref() {
        if mem.options.fail_on_leak && mem.summary.leaked_bytes > 0 {
            status = ExitStatus::Fail;
            summary.status = status;
        }
    }

    std::fs::write(&report_path, serde_json::to_vec(&summary)?)?;
    if let Some(mem) = memory_report.as_ref()
        && mem.options.artifacts
    {
        write_memory_artifacts(mem, &artifacts_dir)?;
    }
    profile_trace.summary = {
        let mut s = summary.clone();
        s.status = profile_status;
        s
    };
    let explicit_capture = opt.record_trace_to.is_some() || crash_trace_path.is_some();
    let emit_heavy = should_emit_heavy_artifacts(status, explicit_capture)
        || matches!(opt.profile_capture, ProfileCaptureLevel::Full);
    if emit_heavy {
        write_profile_artifacts_from_trace(&profile_trace, &artifacts_dir)?;
    }
    if !emit_heavy && should_emit_profile_artifacts(opt.profile_capture, status, explicit_capture) {
        write_profile_artifacts_from_trace(&profile_trace, &artifacts_dir)?;
    }
    let coverage_stats = FuzzCoverageStats {
        target: target_string(target),
        executed,
        crashes: crash_count,
        unique_edges: global_coverage.len(),
        discovered_edges_total,
        max_new_edges_per_input,
        corpus_entries: corpus.len(),
    };
    std::fs::write(
        artifacts_dir.join("coverage.json"),
        serde_json::to_vec(&coverage_stats)?,
    )?;

    if let Some(record_path) = &opt.record_trace_to
        && crash_trace_path.is_none()
    {
        let (input, events, exec_status, exec_findings) =
            last_exec.unwrap_or_else(|| (Vec::new(), Vec::new(), ExitStatus::Pass, Vec::new()));
        let mut trace_summary = summary.clone();
        trace_summary.status = exec_status;
        trace_summary.findings = exec_findings;
        trace_summary.identity.trace_path = Some(record_path.to_string_lossy().to_string());
        let trace = TraceFile::new_fuzz(target_string(target), &input, events, trace_summary);
        let mut trace = trace;
        trace.memory = memory_report.as_ref().map(|m| m.to_trace());
        let written = write_trace_with_policy(&trace, record_path, opt.record_collision)?;
        summary.identity.trace_path = Some(written.to_string_lossy().to_string());
    }
    crate::write_run_manifest(&summary, &artifacts_dir)?;

    Ok(crate::RunResult { summary })
}

pub fn replay_fuzz_trace(config: &Config, trace: &TraceFile) -> FozzyResult<crate::RunResult> {
    let Some(fuzz) = trace.fuzz.as_ref() else {
        return Err(FozzyError::Trace("not a fuzz trace".to_string()));
    };
    let target: FuzzTarget = fuzz.target.parse()?;
    let input = hex_decode(&fuzz.input_hex)?;
    let exec = execute_target(config, &target, &input)?;

    let run_id = Uuid::new_v4().to_string();
    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;
    let report_path = artifacts_dir.join("report.json");

    let started_at = wall_time_iso_utc();
    let finished_at = wall_time_iso_utc();
    let mut findings = exec.findings.clone();
    for warning in crate::trace_schema_warnings(trace.version) {
        findings.push(Finding {
            kind: FindingKind::Checker,
            title: "stale_trace_schema".to_string(),
            message: warning,
            location: None,
        });
    }

    let mut summary = RunSummary {
        status: exec.status,
        mode: RunMode::Replay,
        identity: RunIdentity {
            run_id,
            seed: trace.summary.identity.seed,
            trace_path: Some("<embedded>".to_string()),
            report_path: Some(report_path.to_string_lossy().to_string()),
            artifacts_dir: Some(artifacts_dir.to_string_lossy().to_string()),
        },
        started_at,
        finished_at,
        duration_ms: 0,
        duration_ns: 0,
        tests: None,
        memory: trace.memory.as_ref().map(|m| m.summary.clone()),
        findings,
    };
    let mut profile_trace = TraceFile::new_fuzz(
        fuzz.target.clone(),
        &input,
        exec.events.clone(),
        summary.clone(),
    );
    profile_trace.memory = trace.memory.clone();
    let heap_findings =
        heap_budget_findings_from_trace(&profile_trace, &heap_budget_policy(config));
    if !heap_findings.is_empty() {
        summary.findings.extend(heap_findings);
        summary.findings = crate::collapse_findings(summary.findings.clone());
    }

    std::fs::write(&report_path, serde_json::to_vec(&summary)?)?;
    if should_emit_heavy_artifacts(exec.status, true) {
        std::fs::write(
            artifacts_dir.join("events.json"),
            serde_json::to_vec(&exec.events)?,
        )?;
        crate::write_timeline(&exec.events, &artifacts_dir.join("timeline.json"))?;
        profile_trace.summary = summary.clone();
        write_profile_artifacts_from_trace(&profile_trace, &artifacts_dir)?;
    }
    crate::write_run_manifest(&summary, &artifacts_dir)?;
    Ok(crate::RunResult { summary })
}

pub fn shrink_fuzz_trace(
    _config: &Config,
    trace_path: crate::TracePath,
    opt: &crate::ShrinkOptions,
) -> FozzyResult<crate::ShrinkResult> {
    let trace = TraceFile::read_json(trace_path.as_path())?;
    let target_status = trace.summary.status;
    let Some(fuzz) = trace.fuzz.as_ref() else {
        return Err(FozzyError::Trace("not a fuzz trace".to_string()));
    };

    let target: FuzzTarget = fuzz.target.parse()?;
    let input = hex_decode(&fuzz.input_hex)?;

    if opt.minimize != crate::ShrinkMinimize::All && opt.minimize != crate::ShrinkMinimize::Input {
        return Err(FozzyError::InvalidArgument(
            "fuzz shrink only supports --minimize input|all".to_string(),
        ));
    }

    let minimized = minimize_input(_config, &target, &input, 1024 * 1024, target_status)?;
    let exec = execute_target(_config, &target, &minimized)?;

    let out_path = opt
        .out_trace_path
        .clone()
        .unwrap_or_else(|| crate::default_min_trace_path(trace_path.as_path()));

    let started_at = wall_time_iso_utc();
    let finished_at = wall_time_iso_utc();
    let summary = RunSummary {
        status: exec.status,
        mode: RunMode::Fuzz,
        identity: RunIdentity {
            run_id: Uuid::new_v4().to_string(),
            seed: trace.summary.identity.seed,
            trace_path: Some(out_path.to_string_lossy().to_string()),
            report_path: None,
            artifacts_dir: None,
        },
        started_at,
        finished_at,
        duration_ms: 0,
        duration_ns: 0,
        tests: None,
        memory: trace.memory.as_ref().map(|m| m.summary.clone()),
        findings: exec.findings.clone(),
    };

    let trace_out = TraceFile::new_fuzz(
        target_string(&target),
        &minimized,
        exec.events,
        summary.clone(),
    );
    let mut trace_out = trace_out;
    trace_out.memory = trace.memory.clone();
    trace_out.write_json(&out_path).map_err(|err| {
        FozzyError::Trace(format!(
            "failed to write shrunk fuzz trace to {}: {err}",
            out_path.display()
        ))
    })?;

    Ok(crate::ShrinkResult {
        out_trace_path: out_path.to_string_lossy().to_string(),
        result: crate::RunResult { summary },
    })
}

fn target_string(target: &FuzzTarget) -> String {
    match target {
        FuzzTarget::Function { id } => format!("fn:{id}"),
        FuzzTarget::Scenario { path } => format!("scenario:{}", path.display()),
    }
}

#[derive(Debug, Clone)]
struct FuzzExec {
    status: ExitStatus,
    findings: Vec<Finding>,
    events: Vec<TraceEvent>,
    coverage: BTreeSet<u64>,
}

fn execute_target(config: &Config, target: &FuzzTarget, input: &[u8]) -> FozzyResult<FuzzExec> {
    match target {
        FuzzTarget::Function { id } => {
            let Some(plugin) = find_function_target(id) else {
                return Err(FozzyError::InvalidArgument(format!(
                    "unknown fuzz function target {id:?} (supported: {})",
                    supported_fuzz_targets().join(", ")
                )));
            };
            (plugin.exec)(input)
        }
        FuzzTarget::Scenario { path } => execute_scenario_target(config, path, input),
    }
}

#[derive(Clone, Copy)]
struct FunctionTargetPlugin {
    id: &'static str,
    exec: fn(&[u8]) -> FozzyResult<FuzzExec>,
}

const FUNCTION_TARGET_PLUGINS: &[FunctionTargetPlugin] = &[
    FunctionTargetPlugin {
        id: "kv",
        exec: execute_kv,
    },
    FunctionTargetPlugin {
        id: "utf8",
        exec: execute_utf8,
    },
];

fn find_function_target(id: &str) -> Option<FunctionTargetPlugin> {
    FUNCTION_TARGET_PLUGINS.iter().copied().find(|p| p.id == id)
}

fn supported_function_targets() -> Vec<String> {
    FUNCTION_TARGET_PLUGINS
        .iter()
        .map(|p| format!("fn:{}", p.id))
        .collect()
}

fn supported_fuzz_targets() -> Vec<String> {
    let mut out = supported_function_targets();
    out.push("scenario:<path.fozzy.json>".to_string());
    out
}

fn execute_scenario_target(_config: &Config, path: &Path, input: &[u8]) -> FozzyResult<FuzzExec> {
    let seed = seed_from_input(input);
    let scenario_path = ScenarioPath::new(path.to_path_buf());
    let parsed = crate::Scenario::load_file(&scenario_path)?;
    let parsed = match parsed {
        ScenarioFile::Steps(s) => ScenarioTarget::Steps(s),
        ScenarioFile::Distributed(d) => {
            ScenarioTarget::Distributed(crate::distributed_to_explore(d, None)?)
        }
        ScenarioFile::Suites(_) => ScenarioTarget::Suites,
    };
    let (status, findings) = match parsed {
        ScenarioTarget::Steps(scenario) => {
            crate::run_embedded_steps_for_fuzz(&scenario, path, seed, scenario_fuzz_memory())?
        }
        ScenarioTarget::Distributed(scenario) => crate::execute_explore_for_fuzz(&scenario, seed)?,
        ScenarioTarget::Suites => {
            return Err(FozzyError::InvalidArgument(format!(
                "scenario fuzz target {} uses suites variant; provide a steps or distributed scenario",
                path.display()
            )));
        }
    };

    let mut coverage = BTreeSet::new();
    coverage.insert(stable_edge(&format!("scenario_path:{}", path.display())));
    coverage.insert(stable_edge(&format!("scenario_status:{status:?}")));
    coverage.insert(stable_edge(&format!("scenario_seed:{seed}")));
    for finding in &findings {
        coverage.insert(stable_edge(&format!(
            "scenario_finding:{}:{}",
            finding.title, finding.message
        )));
    }

    let event = TraceEvent {
        time_ms: 1,
        name: "scenario_fuzz_exec".to_string(),
        fields: serde_json::Map::from_iter([
            (
                "path".to_string(),
                serde_json::json!(path.display().to_string()),
            ),
            ("seed".to_string(), serde_json::json!(seed)),
            (
                "status".to_string(),
                serde_json::json!(format!("{:?}", status).to_ascii_lowercase()),
            ),
        ]),
    };

    Ok(FuzzExec {
        status,
        findings,
        events: vec![event],
        coverage,
    })
}

#[derive(Clone)]
enum ScenarioTarget {
    Steps(crate::ScenarioV1Steps),
    Distributed(crate::ScenarioV1Explore),
    Suites,
}

fn should_emit_heavy_artifacts(status: ExitStatus, explicit_request: bool) -> bool {
    explicit_request
        || status != ExitStatus::Pass
        || std::env::var("FOZZY_ARTIFACTS_FULL")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn scenario_fuzz_memory() -> MemoryOptions {
    MemoryOptions {
        track: false,
        limit_mb: None,
        fail_after_allocs: None,
        fail_on_leak: false,
        leak_budget_bytes: None,
        fragmentation_seed: None,
        pressure_wave: None,
        artifacts: false,
    }
}

fn execute_kv(input: &[u8]) -> FozzyResult<FuzzExec> {
    let mut map: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut events = Vec::new();
    let mut findings = Vec::new();
    let mut coverage = BTreeSet::new();

    let mut i = 0usize;
    let mut time_ms = 0u64;
    while i < input.len() {
        let op = input[i];
        i += 1;
        time_ms = time_ms.saturating_add(1);

        coverage.insert(stable_edge(&format!("op:{op:02x}")));
        events.push(TraceEvent {
            time_ms,
            name: "op".to_string(),
            fields: serde_json::Map::from_iter([(
                "opcode".to_string(),
                serde_json::Value::String(format!("{op:02x}")),
            )]),
        });

        match op {
            0x00 => {
                coverage.insert(stable_edge("nop"));
            }
            0x01 => {
                let Some((k, v)) = parse_kv(input, &mut i) else {
                    coverage.insert(stable_edge("parse:eof"));
                    break;
                };
                let existed = map.insert(k.clone(), v).is_some();
                coverage.insert(stable_edge(if existed {
                    "set:overwrite"
                } else {
                    "set:new"
                }));
            }
            0x02 => {
                let Some(key) = parse_bytes(input, &mut i) else {
                    coverage.insert(stable_edge("parse:eof"));
                    break;
                };
                let hit = map.contains_key(&key);
                coverage.insert(stable_edge(if hit { "get:hit" } else { "get:miss" }));
            }
            0x03 => {
                let Some((k, v)) = parse_kv(input, &mut i) else {
                    coverage.insert(stable_edge("parse:eof"));
                    break;
                };
                let got = map.get(&k).cloned();
                if got.as_deref() != Some(&v) {
                    findings.push(Finding {
                        kind: FindingKind::TargetBehavior,
                        title: "kv_assert_mismatch".to_string(),
                        message: "built-in target behavior: kv assertion opcode mismatch"
                            .to_string(),
                        location: None,
                    });
                    coverage.insert(stable_edge("assert:fail"));
                    return Ok(FuzzExec {
                        status: ExitStatus::Fail,
                        findings,
                        events,
                        coverage,
                    });
                }
                coverage.insert(stable_edge("assert:pass"));
            }
            0xFE => {
                findings.push(Finding {
                    kind: FindingKind::TargetBehavior,
                    title: "panic_opcode".to_string(),
                    message: "built-in target behavior: panic opcode reached".to_string(),
                    location: None,
                });
                return Ok(FuzzExec {
                    status: ExitStatus::Crash,
                    findings,
                    events,
                    coverage,
                });
            }
            0xFF => {
                findings.push(Finding {
                    kind: FindingKind::TargetBehavior,
                    title: "hang_opcode".to_string(),
                    message: "built-in target behavior: hang opcode reached".to_string(),
                    location: None,
                });
                return Ok(FuzzExec {
                    status: ExitStatus::Timeout,
                    findings,
                    events,
                    coverage,
                });
            }
            _ => {
                // Unknown opcode: ignore, but count towards coverage.
                coverage.insert(stable_edge("op:unknown"));
            }
        }
    }

    Ok(FuzzExec {
        status: ExitStatus::Pass,
        findings,
        events,
        coverage,
    })
}

fn execute_utf8(input: &[u8]) -> FozzyResult<FuzzExec> {
    let mut coverage = BTreeSet::new();
    let mut findings = Vec::new();
    let mut events = Vec::new();

    coverage.insert(stable_edge("utf8:entry"));
    events.push(TraceEvent {
        time_ms: 1,
        name: "input_len".to_string(),
        fields: serde_json::Map::from_iter([(
            "bytes".to_string(),
            serde_json::Value::Number((input.len() as u64).into()),
        )]),
    });

    if std::str::from_utf8(input).is_err() {
        coverage.insert(stable_edge("utf8:invalid"));
        findings.push(Finding {
            kind: FindingKind::InputInvalid,
            title: "utf8_invalid".to_string(),
            message: "generated input is not valid utf-8 (built-in target behavior)".to_string(),
            location: None,
        });
        return Ok(FuzzExec {
            status: ExitStatus::Fail,
            findings,
            events,
            coverage,
        });
    }

    let Ok(s) = std::str::from_utf8(input) else {
        unreachable!("validated utf-8 above");
    };
    coverage.insert(stable_edge("utf8:valid"));
    if s.contains("ASSERT_FAIL") {
        coverage.insert(stable_edge("utf8:assert_fail"));
        findings.push(Finding {
            kind: FindingKind::TargetBehavior,
            title: "utf8_assert".to_string(),
            message: "built-in target behavior: ASSERT_FAIL marker reached".to_string(),
            location: None,
        });
        return Ok(FuzzExec {
            status: ExitStatus::Fail,
            findings,
            events,
            coverage,
        });
    }
    if s.contains("PANIC") {
        coverage.insert(stable_edge("utf8:panic"));
        findings.push(Finding {
            kind: FindingKind::TargetBehavior,
            title: "utf8_panic".to_string(),
            message: "built-in target behavior: PANIC marker reached".to_string(),
            location: None,
        });
        return Ok(FuzzExec {
            status: ExitStatus::Crash,
            findings,
            events,
            coverage,
        });
    }
    if s.contains("TIMEOUT") {
        coverage.insert(stable_edge("utf8:timeout"));
        findings.push(Finding {
            kind: FindingKind::TargetBehavior,
            title: "utf8_timeout".to_string(),
            message: "built-in target behavior: TIMEOUT marker reached".to_string(),
            location: None,
        });
        return Ok(FuzzExec {
            status: ExitStatus::Timeout,
            findings,
            events,
            coverage,
        });
    }

    coverage.insert(stable_edge("utf8:pass"));
    Ok(FuzzExec {
        status: ExitStatus::Pass,
        findings,
        events,
        coverage,
    })
}

fn parse_kv(input: &[u8], i: &mut usize) -> Option<(Vec<u8>, Vec<u8>)> {
    let k = parse_bytes(input, i)?;
    let v = parse_bytes(input, i)?;
    Some((k, v))
}

fn parse_bytes(input: &[u8], i: &mut usize) -> Option<Vec<u8>> {
    if *i >= input.len() {
        return None;
    }
    let len = input[*i] as usize;
    *i += 1;
    if *i + len > input.len() {
        return None;
    }
    let out = input[*i..*i + len].to_vec();
    *i += len;
    Some(out)
}

fn mutate_bytes(buf: &mut Vec<u8>, rng: &mut rand_chacha::ChaCha20Rng, max_len: usize) {
    let choice = (rng.next_u64() % 4) as u8;
    match choice {
        0 => bitflip(buf.as_mut_slice(), rng),
        1 => insert_byte(buf, rng, max_len),
        2 => delete_byte(buf, rng),
        _ => overwrite_byte(buf, rng),
    }
}

fn bitflip(buf: &mut [u8], rng: &mut rand_chacha::ChaCha20Rng) {
    if buf.is_empty() {
        return;
    }
    let idx = (rng.next_u64() as usize) % buf.len();
    let bit = 1u8 << ((rng.next_u64() as usize) % 8);
    buf[idx] ^= bit;
}

fn insert_byte(buf: &mut Vec<u8>, rng: &mut rand_chacha::ChaCha20Rng, max_len: usize) {
    if buf.len() >= max_len {
        return;
    }
    let idx = if buf.is_empty() {
        0
    } else {
        (rng.next_u64() as usize) % (buf.len() + 1)
    };
    let val = (rng.next_u64() & 0xFF) as u8;
    buf.insert(idx, val);
}

fn delete_byte(buf: &mut Vec<u8>, rng: &mut rand_chacha::ChaCha20Rng) {
    if buf.is_empty() {
        return;
    }
    let idx = (rng.next_u64() as usize) % buf.len();
    buf.remove(idx);
}

fn overwrite_byte(buf: &mut Vec<u8>, rng: &mut rand_chacha::ChaCha20Rng) {
    if buf.is_empty() {
        buf.push((rng.next_u64() & 0xFF) as u8);
        return;
    }
    let idx = (rng.next_u64() as usize) % buf.len();
    buf[idx] = (rng.next_u64() & 0xFF) as u8;
}

fn load_corpus(dir: &Path) -> FozzyResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("bin") {
            continue;
        }
        out.push(std::fs::read(p)?);
    }
    Ok(out)
}

fn persist_corpus_input(dir: &Path, bytes: &[u8]) -> FozzyResult<PathBuf> {
    let name = format!("input-{}.bin", blake3::hash(bytes).to_hex());
    let out = dir.join(name);
    if !out.exists() {
        std::fs::write(&out, bytes)?;
    }
    Ok(out)
}

fn persist_crash_input(dir: &Path, bytes: &[u8]) -> FozzyResult<PathBuf> {
    let name = format!("crash-{}.bin", blake3::hash(bytes).to_hex());
    let out = dir.join("crashes").join(name);
    if !out.exists() {
        std::fs::write(&out, bytes)?;
    }
    Ok(out)
}

fn persist_crash_min_input(dir: &Path, bytes: &[u8]) -> FozzyResult<PathBuf> {
    let name = format!("crash-{}.min.bin", blake3::hash(bytes).to_hex());
    let out = dir.join("crashes").join(name);
    if !out.exists() {
        std::fs::write(&out, bytes)?;
    }
    Ok(out)
}

fn crash_trace_output_path(
    record_path: Option<&Path>,
    artifacts_dir: &Path,
    crash_count: u64,
) -> PathBuf {
    let base = record_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| artifacts_dir.join("trace.fozzy"));
    if crash_count <= 1 {
        return base;
    }
    with_numeric_suffix(&base, crash_count - 1)
}

fn with_numeric_suffix(path: &Path, suffix: u64) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("trace");
    match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => parent.join(format!("{stem}.{suffix}.{ext}")),
        None => parent.join(format!("{stem}.{suffix}")),
    }
}

fn minimize_input(
    config: &Config,
    target: &FuzzTarget,
    input: &[u8],
    max_len: usize,
    target_status: ExitStatus,
) -> FozzyResult<Vec<u8>> {
    let mut best = input.to_vec();
    let mut chunk = best.len().max(1).div_ceil(2);
    while chunk > 0 && best.len() > 1 {
        let mut improved = false;
        let mut i = 0usize;
        while i < best.len() {
            let mut trial = best.clone();
            let end = (i + chunk).min(trial.len());
            trial.drain(i..end);
            if trial.is_empty() {
                i += chunk;
                continue;
            }
            if trial.len() > max_len {
                i += chunk;
                continue;
            }
            let exec = execute_target(config, target, &trial)?;
            if crate::shrink_status_matches(target_status, exec.status) {
                best = trial;
                improved = true;
                continue;
            }
            i += chunk;
        }

        if !improved {
            if chunk == 1 {
                break;
            }
            chunk = chunk.div_ceil(2);
        }
    }
    Ok(best)
}

fn stable_edge(label: &str) -> u64 {
    let h = blake3::hash(label.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

fn seed_from_input(input: &[u8]) -> u64 {
    let h = blake3::hash(input);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(out)
}

fn gen_seed() -> u64 {
    let mut seed = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut seed);
    u64::from_le_bytes(seed)
}

fn rng_from_seed(seed: u64) -> ChaCha20Rng {
    let seed_bytes = blake3::hash(&seed.to_le_bytes()).as_bytes().to_owned();
    let mut seed32 = [0u8; 32];
    seed32.copy_from_slice(&seed_bytes[..32]);
    ChaCha20Rng::from_seed(seed32)
}

fn hex_decode(s: &str) -> FozzyResult<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(FozzyError::Trace("invalid hex length".to_string()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> FozzyResult<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(FozzyError::Trace("invalid hex character".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{FuzzTarget, crash_trace_output_path, with_numeric_suffix};
    use std::path::Path;

    #[test]
    fn crash_trace_output_path_uses_base_then_numbered_suffixes() {
        let artifacts_dir = Path::new("/tmp/fozzy-run");
        let first = crash_trace_output_path(None, artifacts_dir, 1);
        let second = crash_trace_output_path(None, artifacts_dir, 2);
        let third = crash_trace_output_path(None, artifacts_dir, 3);
        assert_eq!(first, artifacts_dir.join("trace.fozzy"));
        assert_eq!(second, artifacts_dir.join("trace.1.fozzy"));
        assert_eq!(third, artifacts_dir.join("trace.2.fozzy"));
    }

    #[test]
    fn with_numeric_suffix_handles_paths_without_extension() {
        let out = with_numeric_suffix(Path::new("artifacts/trace"), 4);
        assert_eq!(out, Path::new("artifacts/trace.4"));
    }
    #[test]
    fn fuzz_target_parses_scenario_prefix_and_path_form() {
        let a: FuzzTarget = "scenario:tests/example.fozzy.json".parse().expect("prefix");
        let b: FuzzTarget = "tests/example.fozzy.json".parse().expect("path form");
        assert!(matches!(a, FuzzTarget::Scenario { .. }));
        assert!(matches!(b, FuzzTarget::Scenario { .. }));
    }
}
