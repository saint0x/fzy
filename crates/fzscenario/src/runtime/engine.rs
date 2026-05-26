//! Core engine: scenario execution, deterministic runtime, record/replay, shrinking.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore as _, SeedableRng as _};
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{
    Config, Decision, DecisionLog, ExitStatus, Finding, FindingKind, FindingLocation,
    MemoryOptions, MemoryRunReport, MemoryState, Reporter, RunMode, RunSummary, Scenario,
    ScenarioPath, ScenarioV1Steps, TraceEvent,
};

use crate::host::{
    HostHttpDispatch, HostProcDispatch, assert_http_when_response_matches_host, canonical_headers,
    dispatch_host_http, dispatch_host_proc, host_http_rule_matches, host_http_rule_path_supported,
};
use crate::{FozzyError, FozzyResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcBackend {
    Scripted,
    Host,
}

impl clap::ValueEnum for ProcBackend {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Scripted, Self::Host]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Scripted => clap::builder::PossibleValue::new("scripted"),
            Self::Host => clap::builder::PossibleValue::new("host"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsBackend {
    Virtual,
    Host,
}

impl clap::ValueEnum for FsBackend {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Virtual, Self::Host]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Virtual => clap::builder::PossibleValue::new("virtual"),
            Self::Host => clap::builder::PossibleValue::new("host"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpBackend {
    Scripted,
    Host,
}

impl clap::ValueEnum for HttpBackend {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Scripted, Self::Host]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Scripted => clap::builder::PossibleValue::new("scripted"),
            Self::Host => clap::builder::PossibleValue::new("host"),
        })
    }
}

#[derive(Debug, Clone)]
pub enum InitTemplate {
    Ts,
    Rust,
    Minimal,
}

impl clap::ValueEnum for InitTemplate {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Ts, Self::Rust, Self::Minimal]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Ts => clap::builder::PossibleValue::new("ts"),
            Self::Rust => clap::builder::PossibleValue::new("rust"),
            Self::Minimal => clap::builder::PossibleValue::new("minimal"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitTestType {
    Run,
    Fuzz,
    Explore,
    Memory,
    Host,
    All,
}

impl clap::ValueEnum for InitTestType {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Run,
            Self::Fuzz,
            Self::Explore,
            Self::Memory,
            Self::Host,
            Self::All,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Run => clap::builder::PossibleValue::new("run"),
            Self::Fuzz => clap::builder::PossibleValue::new("fuzz"),
            Self::Explore => clap::builder::PossibleValue::new("explore"),
            Self::Memory => clap::builder::PossibleValue::new("memory"),
            Self::Host => clap::builder::PossibleValue::new("host"),
            Self::All => clap::builder::PossibleValue::new("all"),
        })
    }
}

impl InitTemplate {
    pub fn from_option(opt: Option<&InitTemplate>) -> Self {
        opt.cloned().unwrap_or(Self::Minimal)
    }
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub det: bool,
    pub seed: Option<u64>,
    pub timeout: Option<Duration>,
    pub reporter: Reporter,
    pub record_trace_to: Option<PathBuf>,
    pub filter: Option<String>,
    pub jobs: Option<usize>,
    pub fail_fast: bool,
    pub record_collision: RecordCollisionPolicy,
    pub profile_capture: ProfileCaptureLevel,
    pub proc_backend: ProcBackend,
    pub fs_backend: FsBackend,
    pub http_backend: HttpBackend,
    pub memory: MemoryOptions,
}

#[derive(Debug, Clone)]
pub struct ReplayOptions {
    pub step: bool,
    pub until: Option<Duration>,
    pub dump_events: bool,
    pub profile_capture: ProfileCaptureLevel,
    pub reporter: Reporter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileCaptureLevel {
    Baseline,
    Sampled,
    Full,
}

impl clap::ValueEnum for ProfileCaptureLevel {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Baseline, Self::Sampled, Self::Full]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Baseline => clap::builder::PossibleValue::new("baseline"),
            Self::Sampled => clap::builder::PossibleValue::new("sampled"),
            Self::Full => clap::builder::PossibleValue::new("full"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShrinkMinimize {
    Input,
    Schedule,
    Faults,
    All,
}

impl clap::ValueEnum for ShrinkMinimize {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Input, Self::Schedule, Self::Faults, Self::All]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Input => clap::builder::PossibleValue::new("input"),
            Self::Schedule => clap::builder::PossibleValue::new("schedule"),
            Self::Faults => clap::builder::PossibleValue::new("faults"),
            Self::All => clap::builder::PossibleValue::new("all"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ShrinkOptions {
    pub out_trace_path: Option<PathBuf>,
    pub budget: Option<Duration>,
    pub aggressive: bool,
    pub minimize: ShrinkMinimize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordCollisionPolicy {
    Error,
    Overwrite,
    Append,
}

impl clap::ValueEnum for RecordCollisionPolicy {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Error, Self::Overwrite, Self::Append]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Error => clap::builder::PossibleValue::new("error"),
            Self::Overwrite => clap::builder::PossibleValue::new("overwrite"),
            Self::Append => clap::builder::PossibleValue::new("append"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub summary: RunSummary,
}

#[derive(Debug, Clone)]
pub struct ShrinkResult {
    pub out_trace_path: String,
    pub result: RunResult,
}

pub(crate) fn shrink_status_matches(target: ExitStatus, candidate: ExitStatus) -> bool {
    if target == ExitStatus::Pass {
        candidate == ExitStatus::Pass
    } else {
        candidate != ExitStatus::Pass
    }
}

pub fn should_emit_profile_artifacts(
    capture: ProfileCaptureLevel,
    status: ExitStatus,
    explicit_request: bool,
) -> bool {
    match capture {
        ProfileCaptureLevel::Baseline => should_emit_heavy_artifacts(status, explicit_request),
        ProfileCaptureLevel::Sampled | ProfileCaptureLevel::Full => true,
    }
}

fn should_emit_heavy_artifacts(status: ExitStatus, explicit_request: bool) -> bool {
    explicit_request
        || status != ExitStatus::Pass
        || std::env::var("FOZZY_ARTIFACTS_FULL")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

#[derive(Debug, Clone)]
pub(crate) struct ScenarioRun {
    pub(crate) status: ExitStatus,
    pub(crate) findings: Vec<Finding>,
    pub(crate) memory: Option<MemoryRunReport>,
    pub(crate) decisions: DecisionLog,
    pub(crate) events: Vec<TraceEvent>,
    pub(crate) scenario_path: PathBuf,
    pub(crate) scenario_embedded: ScenarioV1Steps,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_scenario_inner(
    _config: &Config,
    _mode: RunMode,
    scenario_path: ScenarioPath,
    seed: u64,
    det: bool,
    timeout: Option<Duration>,
    proc_backend: ProcBackend,
    fs_backend: FsBackend,
    http_backend: HttpBackend,
    memory: MemoryOptions,
) -> FozzyResult<ScenarioRun> {
    let loaded = Scenario::load(&scenario_path)?;
    loaded.validate()?;

    let embedded = ScenarioV1Steps {
        version: 1,
        name: loaded.name.clone(),
        steps: loaded.steps.clone(),
    };

    run_embedded_scenario_inner(
        embedded,
        scenario_path.as_path().to_path_buf(),
        seed,
        det,
        timeout,
        proc_backend,
        fs_backend,
        http_backend,
        memory,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_embedded_scenario_inner(
    scenario: ScenarioV1Steps,
    scenario_path: PathBuf,
    seed: u64,
    det: bool,
    timeout: Option<Duration>,
    proc_backend: ProcBackend,
    fs_backend: FsBackend,
    http_backend: HttpBackend,
    memory: MemoryOptions,
) -> FozzyResult<ScenarioRun> {
    let started = Instant::now();
    let deadline = timeout.map(|t| started + t);
    let mut ctx = ExecCtx::new(
        seed,
        det,
        deadline,
        proc_backend,
        fs_backend,
        http_backend,
        memory,
    );
    let start_virtual_ms = ctx.clock.now_ms();
    let mut scheduler = crate::DeterministicScheduler::new(crate::SchedulerMode::Fifo, seed);
    for (idx, step) in scenario.steps.iter().enumerate() {
        scheduler.enqueue(step.kind_name().to_string(), idx);
    }

    while let Some(item) = scheduler.pop_next() {
        let idx = item.payload;
        let step = &scenario.steps[idx];
        if timeout_reached(&ctx, det, timeout, deadline, start_virtual_ms) {
            ctx.findings.push(Finding {
                kind: FindingKind::Hang,
                title: "timeout".to_string(),
                message: "scenario timed out".to_string(),
                location: None,
            });
            return Ok(ctx.finish(ExitStatus::Timeout, scenario_path, scenario));
        }

        ctx.decisions.push(Decision::SchedulerPick {
            task_id: item.id,
            label: item.label,
        });
        let step_kind = step.kind_name().to_string();
        let span_id = format!("step-{idx}");
        let step_start_ms = ctx.clock.now_ms();
        ctx.events.push(TraceEvent {
            time_ms: step_start_ms,
            name: "sched_pick".to_string(),
            fields: serde_json::Map::from_iter([
                ("task_id".to_string(), serde_json::json!(item.id)),
                ("step_index".to_string(), serde_json::json!(idx as u64)),
                (
                    "step_kind".to_string(),
                    serde_json::json!(step_kind.clone()),
                ),
            ]),
        });
        ctx.events.push(TraceEvent {
            time_ms: step_start_ms,
            name: "span_start".to_string(),
            fields: serde_json::Map::from_iter([
                ("span".to_string(), serde_json::json!(span_id.clone())),
                ("task".to_string(), serde_json::json!("step")),
                ("step_index".to_string(), serde_json::json!(idx as u64)),
                (
                    "step_kind".to_string(),
                    serde_json::json!(step_kind.clone()),
                ),
            ]),
        });
        ctx.set_active_step(&scenario_path, idx);
        if let Err(finding) = ctx.exec_step(step) {
            let end_ms = ctx.clock.now_ms();
            ctx.events.push(TraceEvent {
                time_ms: end_ms,
                name: "span_end".to_string(),
                fields: serde_json::Map::from_iter([
                    ("span".to_string(), serde_json::json!(span_id)),
                    ("status".to_string(), serde_json::json!("error")),
                    (
                        "duration_ms".to_string(),
                        serde_json::json!(end_ms.saturating_sub(step_start_ms)),
                    ),
                ]),
            });
            let status = if finding_is_timeout(&finding) {
                ExitStatus::Timeout
            } else {
                ExitStatus::Fail
            };
            ctx.findings.push(finding);
            return Ok(ctx.finish(status, scenario_path, scenario));
        }
        let end_ms = ctx.clock.now_ms();
        ctx.events.push(TraceEvent {
            time_ms: end_ms,
            name: "span_end".to_string(),
            fields: serde_json::Map::from_iter([
                ("span".to_string(), serde_json::json!(span_id)),
                ("status".to_string(), serde_json::json!("ok")),
                (
                    "duration_ms".to_string(),
                    serde_json::json!(end_ms.saturating_sub(step_start_ms)),
                ),
            ]),
        });

        if timeout_reached(&ctx, det, timeout, deadline, start_virtual_ms) {
            ctx.findings.push(Finding {
                kind: FindingKind::Hang,
                title: "timeout".to_string(),
                message: "scenario timed out".to_string(),
                location: None,
            });
            return Ok(ctx.finish(ExitStatus::Timeout, scenario_path, scenario));
        }
    }

    Ok(ctx.finish(ExitStatus::Pass, scenario_path, scenario))
}

pub(crate) fn run_embedded_steps_for_fuzz(
    scenario: &ScenarioV1Steps,
    scenario_path: &Path,
    seed: u64,
    memory: MemoryOptions,
) -> FozzyResult<(ExitStatus, Vec<Finding>)> {
    let run = run_embedded_scenario_inner(
        scenario.clone(),
        scenario_path.to_path_buf(),
        seed,
        true,
        None,
        ProcBackend::Scripted,
        FsBackend::Virtual,
        HttpBackend::Scripted,
        memory,
    )?;
    Ok((run.status, run.findings))
}

fn timeout_reached(
    ctx: &ExecCtx<'_>,
    det: bool,
    timeout: Option<Duration>,
    deadline: Option<Instant>,
    start_virtual_ms: u64,
) -> bool {
    let Some(limit) = timeout else {
        return false;
    };
    if det {
        let elapsed_ms = ctx.clock.now_ms().saturating_sub(start_virtual_ms);
        elapsed_ms >= limit.as_millis().min(u128::from(u64::MAX)) as u64
    } else {
        deadline.is_some_and(|dl| Instant::now() > dl)
    }
}

fn finding_is_timeout(finding: &Finding) -> bool {
    finding.kind == FindingKind::Hang && finding.title == "timeout"
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_scenario_replay_inner<'a>(
    _config: &Config,
    _mode: RunMode,
    scenario: &ScenarioV1Steps,
    scenario_path: &str,
    seed: u64,
    decisions: Option<&'a [Decision]>,
    until: Option<Duration>,
    step: bool,
    proc_backend: ProcBackend,
    fs_backend: FsBackend,
    http_backend: HttpBackend,
    memory: MemoryOptions,
) -> FozzyResult<ScenarioRun> {
    if scenario.version != 1 {
        return Err(FozzyError::Scenario(format!(
            "unsupported scenario version {} (expected 1)",
            scenario.version
        )));
    }

    let has_scheduler_pick = decisions
        .map(|d| {
            d.iter()
                .any(|x| matches!(x, Decision::SchedulerPick { .. }))
        })
        .unwrap_or(false);

    let started = Instant::now();
    let deadline = until.map(|t| started + t);
    let mut ctx = ExecCtx::new(
        seed,
        true,
        deadline,
        proc_backend,
        fs_backend,
        http_backend,
        memory,
    );
    if let Some(d) = decisions {
        ctx.replay = Some(ReplayCursor::new(d));
    }

    if has_scheduler_pick {
        let mut scheduler = crate::DeterministicScheduler::new(crate::SchedulerMode::Fifo, seed);
        for (idx, step) in scenario.steps.iter().enumerate() {
            scheduler.enqueue(step.kind_name().to_string(), idx);
        }
        while let Some(item) = scheduler.pop_next() {
            let idx = item.payload;
            let step_def = &scenario.steps[idx];
            if let Some(dl) = deadline
                && Instant::now() > dl
            {
                ctx.findings.push(Finding {
                    kind: FindingKind::Hang,
                    title: "until".to_string(),
                    message: "replay stopped at --until budget".to_string(),
                    location: None,
                });
                return Ok(ctx.finish(
                    ExitStatus::Timeout,
                    PathBuf::from(scenario_path),
                    scenario.clone(),
                ));
            }

            if step {
                std::thread::sleep(Duration::from_millis(10));
            }

            ctx.expect_scheduler_pick(item.id, &item.label)?;
            let step_kind = step_def.kind_name().to_string();
            let span_id = format!("step-{idx}");
            let step_start_ms = ctx.clock.now_ms();
            ctx.events.push(TraceEvent {
                time_ms: step_start_ms,
                name: "sched_pick".to_string(),
                fields: serde_json::Map::from_iter([
                    ("task_id".to_string(), serde_json::json!(item.id)),
                    ("step_index".to_string(), serde_json::json!(idx as u64)),
                    (
                        "step_kind".to_string(),
                        serde_json::json!(step_kind.clone()),
                    ),
                ]),
            });
            ctx.events.push(TraceEvent {
                time_ms: step_start_ms,
                name: "span_start".to_string(),
                fields: serde_json::Map::from_iter([
                    ("span".to_string(), serde_json::json!(span_id.clone())),
                    ("task".to_string(), serde_json::json!("step")),
                    ("step_index".to_string(), serde_json::json!(idx as u64)),
                    (
                        "step_kind".to_string(),
                        serde_json::json!(step_kind.clone()),
                    ),
                ]),
            });
            if let Err(finding) = ctx.exec_step(step_def) {
                let end_ms = ctx.clock.now_ms();
                ctx.events.push(TraceEvent {
                    time_ms: end_ms,
                    name: "span_end".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("span".to_string(), serde_json::json!(span_id)),
                        ("status".to_string(), serde_json::json!("error")),
                        (
                            "duration_ms".to_string(),
                            serde_json::json!(end_ms.saturating_sub(step_start_ms)),
                        ),
                    ]),
                });
                let status = if finding_is_timeout(&finding) {
                    ExitStatus::Timeout
                } else {
                    ExitStatus::Fail
                };
                ctx.findings.push(finding);
                return Ok(ctx.finish(status, PathBuf::from(scenario_path), scenario.clone()));
            }
            let end_ms = ctx.clock.now_ms();
            ctx.events.push(TraceEvent {
                time_ms: end_ms,
                name: "span_end".to_string(),
                fields: serde_json::Map::from_iter([
                    ("span".to_string(), serde_json::json!(span_id)),
                    ("status".to_string(), serde_json::json!("ok")),
                    (
                        "duration_ms".to_string(),
                        serde_json::json!(end_ms.saturating_sub(step_start_ms)),
                    ),
                ]),
            });
        }
    } else {
        for (idx, step_def) in scenario.steps.iter().enumerate() {
            if let Some(dl) = deadline
                && Instant::now() > dl
            {
                ctx.findings.push(Finding {
                    kind: FindingKind::Hang,
                    title: "until".to_string(),
                    message: "replay stopped at --until budget".to_string(),
                    location: None,
                });
                return Ok(ctx.finish(
                    ExitStatus::Timeout,
                    PathBuf::from(scenario_path),
                    scenario.clone(),
                ));
            }

            if step {
                std::thread::sleep(Duration::from_millis(10));
            }

            ctx.expect_step(idx)?;
            let step_kind = step_def.kind_name().to_string();
            let span_id = format!("step-{idx}");
            let step_start_ms = ctx.clock.now_ms();
            ctx.events.push(TraceEvent {
                time_ms: step_start_ms,
                name: "sched_pick".to_string(),
                fields: serde_json::Map::from_iter([
                    ("task_id".to_string(), serde_json::json!(idx as u64 + 1)),
                    ("step_index".to_string(), serde_json::json!(idx as u64)),
                    (
                        "step_kind".to_string(),
                        serde_json::json!(step_kind.clone()),
                    ),
                ]),
            });
            ctx.events.push(TraceEvent {
                time_ms: step_start_ms,
                name: "span_start".to_string(),
                fields: serde_json::Map::from_iter([
                    ("span".to_string(), serde_json::json!(span_id.clone())),
                    ("task".to_string(), serde_json::json!("step")),
                    ("step_index".to_string(), serde_json::json!(idx as u64)),
                    (
                        "step_kind".to_string(),
                        serde_json::json!(step_kind.clone()),
                    ),
                ]),
            });
            if let Err(finding) = ctx.exec_step(step_def) {
                let end_ms = ctx.clock.now_ms();
                ctx.events.push(TraceEvent {
                    time_ms: end_ms,
                    name: "span_end".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("span".to_string(), serde_json::json!(span_id)),
                        ("status".to_string(), serde_json::json!("error")),
                        (
                            "duration_ms".to_string(),
                            serde_json::json!(end_ms.saturating_sub(step_start_ms)),
                        ),
                    ]),
                });
                let status = if finding_is_timeout(&finding) {
                    ExitStatus::Timeout
                } else {
                    ExitStatus::Fail
                };
                ctx.findings.push(finding);
                return Ok(ctx.finish(status, PathBuf::from(scenario_path), scenario.clone()));
            }
            let end_ms = ctx.clock.now_ms();
            ctx.events.push(TraceEvent {
                time_ms: end_ms,
                name: "span_end".to_string(),
                fields: serde_json::Map::from_iter([
                    ("span".to_string(), serde_json::json!(span_id)),
                    ("status".to_string(), serde_json::json!("ok")),
                    (
                        "duration_ms".to_string(),
                        serde_json::json!(end_ms.saturating_sub(step_start_ms)),
                    ),
                ]),
            });
        }
    }

    if let Some(cursor) = ctx.replay.as_ref()
        && cursor.remaining() > 0
    {
        ctx.findings.push(Finding {
            kind: FindingKind::Checker,
            title: "replay_unused_decisions".to_string(),
            message: format!(
                "replay finished with {} unused decisions",
                cursor.remaining()
            ),
            location: None,
        });
        return Ok(ctx.finish(
            ExitStatus::Fail,
            PathBuf::from(scenario_path),
            scenario.clone(),
        ));
    }

    Ok(ctx.finish(
        ExitStatus::Pass,
        PathBuf::from(scenario_path),
        scenario.clone(),
    ))
}

#[derive(Debug, Clone)]
struct ExecCtx<'a> {
    det: bool,
    proc_backend: ProcBackend,
    fs_backend: FsBackend,
    http_backend: HttpBackend,
    host_deadline: Option<Instant>,
    host_root: PathBuf,
    rng: ChaCha20Rng,
    clock: crate::VirtualClock,
    kv: BTreeMap<String, String>,
    fs: BTreeMap<String, String>,
    fs_snapshots: BTreeMap<String, BTreeMap<String, String>>,
    replay_host_fs: BTreeMap<String, Vec<u8>>,
    replay_host_fs_snapshots: BTreeMap<String, BTreeMap<String, Option<Vec<u8>>>>,
    host_fs_touched: BTreeSet<PathBuf>,
    host_fs_snapshots: BTreeMap<String, BTreeMap<PathBuf, Option<Vec<u8>>>>,
    http_rules: Vec<HttpRule>,
    proc_rules: Vec<ProcRule>,
    net_queue: VecDeque<NetMessage>,
    net_inbox: BTreeMap<String, Vec<NetMessage>>,
    net_partitions: BTreeSet<(String, String)>,
    net_next_id: u64,
    net_drop_rate: f64,
    net_reorder: bool,
    memory: MemoryState,
    decisions: DecisionLog,
    events: Vec<TraceEvent>,
    findings: Vec<Finding>,
    replay: Option<ReplayCursor<'a>>,
    current_step_index: Option<usize>,
    scenario_path: Option<PathBuf>,
}

impl<'a> ExecCtx<'a> {
    fn new(
        seed: u64,
        det: bool,
        host_deadline: Option<Instant>,
        proc_backend: ProcBackend,
        fs_backend: FsBackend,
        http_backend: HttpBackend,
        memory: MemoryOptions,
    ) -> Self {
        let seed_bytes = blake3::hash(&seed.to_le_bytes()).as_bytes().to_owned();
        let mut seed32 = [0u8; 32];
        seed32.copy_from_slice(&seed_bytes[..32]);
        let rng = ChaCha20Rng::from_seed(seed32);
        Self {
            det,
            proc_backend,
            fs_backend,
            http_backend,
            host_deadline,
            host_root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            rng,
            clock: crate::VirtualClock::default(),
            kv: BTreeMap::new(),
            fs: BTreeMap::new(),
            fs_snapshots: BTreeMap::new(),
            replay_host_fs: BTreeMap::new(),
            replay_host_fs_snapshots: BTreeMap::new(),
            host_fs_touched: BTreeSet::new(),
            host_fs_snapshots: BTreeMap::new(),
            http_rules: Vec::new(),
            proc_rules: Vec::new(),
            net_queue: VecDeque::new(),
            net_inbox: BTreeMap::new(),
            net_partitions: BTreeSet::new(),
            net_next_id: 1,
            net_drop_rate: 0.0,
            net_reorder: false,
            memory: MemoryState::new(memory),
            decisions: DecisionLog::default(),
            events: Vec::new(),
            findings: Vec::new(),
            replay: None,
            current_step_index: None,
            scenario_path: None,
        }
    }

    fn set_active_step(&mut self, scenario_path: &Path, step_index: usize) {
        self.current_step_index = Some(step_index);
        self.scenario_path = Some(scenario_path.to_path_buf());
    }

    fn current_finding_location(&self) -> Option<FindingLocation> {
        self.scenario_path.as_ref().map(|path| FindingLocation {
            file: Some(path.display().to_string()),
            line: None,
            col: None,
        })
    }

    fn remaining_host_timeout(&self) -> Option<Duration> {
        let deadline = self.host_deadline?;
        Some(deadline.saturating_duration_since(Instant::now()))
    }

    fn finish(
        mut self,
        mut status: ExitStatus,
        scenario_path: PathBuf,
        embedded: ScenarioV1Steps,
    ) -> ScenarioRun {
        let mut memory_report = None;
        if self.memory.options.track {
            let report = self.memory.finalize();
            if report.summary.leaked_bytes > 0 {
                self.findings.push(Finding {
                    kind: FindingKind::Checker,
                    title: "memory_leak".to_string(),
                    message: format!(
                        "detected {} leaked allocation(s), leaked_bytes={}",
                        report.summary.leaked_allocs, report.summary.leaked_bytes
                    ),
                    location: None,
                });
            }
            if let Some(budget) = report.options.leak_budget_bytes
                && report.summary.leaked_bytes > budget
            {
                self.findings.push(Finding {
                    kind: FindingKind::Checker,
                    title: "memory_leak_budget".to_string(),
                    message: format!(
                        "leak budget exceeded: leaked_bytes={} budget_bytes={}",
                        report.summary.leaked_bytes, budget
                    ),
                    location: None,
                });
                if status == ExitStatus::Pass {
                    status = ExitStatus::Fail;
                }
            }
            if report.options.fail_on_leak
                && report.summary.leaked_bytes > 0
                && status == ExitStatus::Pass
            {
                status = ExitStatus::Fail;
            }
            memory_report = Some(report);
        }
        ScenarioRun {
            status,
            findings: self.findings,
            memory: memory_report,
            decisions: self.decisions,
            events: self.events,
            scenario_path,
            scenario_embedded: embedded,
        }
    }

    fn expect_step(&mut self, idx: usize) -> FozzyResult<()> {
        let Some(cursor) = self.replay.as_mut() else {
            return Ok(());
        };
        match cursor.next() {
            Some(Decision::Step { index, .. }) if *index == idx => Ok(()),
            Some(other) => Err(FozzyError::Trace(format!(
                "replay drift at step {idx}: expected step decision, got {other:?}"
            ))),
            None => Err(FozzyError::Trace(format!(
                "replay drift at step {idx}: missing decision"
            ))),
        }
    }

    fn expect_scheduler_pick(&mut self, task_id: u64, _label: &str) -> FozzyResult<()> {
        let Some(cursor) = self.replay.as_mut() else {
            return Ok(());
        };
        match cursor.next() {
            Some(Decision::SchedulerPick {
                task_id: expected_id,
                ..
            }) if *expected_id == task_id => Ok(()),
            Some(other) => Err(FozzyError::Trace(format!(
                "replay drift: expected SchedulerPick(task_id={task_id}), got {other:?}"
            ))),
            None => Err(FozzyError::Trace(
                "replay drift: missing SchedulerPick decision".to_string(),
            )),
        }
    }

    fn replay_peek(&self) -> Option<&Decision> {
        self.replay.as_ref().and_then(|c| c.peek())
    }

    fn replay_take_if<F>(&mut self, pred: F) -> Option<Decision>
    where
        F: FnOnce(&Decision) -> bool,
    {
        let cursor = self.replay.as_mut()?;
        let next = cursor.peek()?;
        if pred(next) {
            cursor.next().cloned()
        } else {
            None
        }
    }

    fn replay_host_fs_write(&mut self, path: &str, data: &[u8]) {
        self.replay_host_fs.insert(path.to_string(), data.to_vec());
    }

    fn replay_host_fs_read_assert(&mut self, path: &str, expected: &str) -> Result<(), Finding> {
        let Some(bytes) = self.replay_host_fs.get(path) else {
            return Err(Finding {
                kind: FindingKind::Assertion,
                title: "fs_read_assert".to_string(),
                message: format!(
                    "expected host fs replay data for {path:?}, but none was recorded"
                ),
                location: None,
            });
        };
        let got = String::from_utf8(bytes.clone()).map_err(|_| Finding {
            kind: FindingKind::Assertion,
            title: "fs_read_assert".to_string(),
            message: format!("recorded host fs bytes for {path:?} are not valid utf-8"),
            location: None,
        })?;
        if got != expected {
            return Err(Finding {
                kind: FindingKind::Assertion,
                title: "fs_read_assert".to_string(),
                message: format!("expected {path:?} == {expected:?}, got {got:?}"),
                location: None,
            });
        }
        Ok(())
    }

    fn apply_replay_host_fs_snapshot(
        &mut self,
        name: &str,
        entries: &BTreeMap<String, Option<String>>,
    ) -> Result<(), Finding> {
        let mut decoded = BTreeMap::new();
        for (path, value) in entries {
            let bytes = match value {
                Some(hex) => Some(decode_hex(hex).map_err(|message| Finding {
                    kind: FindingKind::Checker,
                    title: "replay_fs_snapshot".to_string(),
                    message: format!(
                        "invalid recorded host fs snapshot bytes for {name:?} {path:?}: {message}"
                    ),
                    location: None,
                })?),
                None => None,
            };
            decoded.insert(path.clone(), bytes.clone());
            match bytes {
                Some(bytes) => {
                    self.replay_host_fs.insert(path.clone(), bytes);
                }
                None => {
                    self.replay_host_fs.remove(path);
                }
            }
        }
        self.replay_host_fs_snapshots
            .insert(name.to_string(), decoded);
        Ok(())
    }

    fn apply_replay_host_fs_restore(&mut self, name: &str) -> Result<(), Finding> {
        let Some(snapshot) = self.replay_host_fs_snapshots.get(name).cloned() else {
            return Err(Finding {
                kind: FindingKind::Checker,
                title: "fs_restore_missing_snapshot".to_string(),
                message: format!("missing replay host fs snapshot {name:?}"),
                location: None,
            });
        };
        self.replay_host_fs
            .retain(|path, _| snapshot.contains_key(path));
        for (path, value) in snapshot {
            match value {
                Some(bytes) => {
                    self.replay_host_fs.insert(path, bytes);
                }
                None => {
                    self.replay_host_fs.remove(&path);
                }
            }
        }
        Ok(())
    }

    fn resolve_host_fs_path(&self, raw: &str) -> Result<PathBuf, Finding> {
        let path = Path::new(raw);
        if path.is_absolute() {
            return Err(Finding {
                kind: FindingKind::Checker,
                title: "host_fs_path".to_string(),
                message: format!("host fs path must be relative to cwd root: {raw:?}"),
                location: None,
            });
        }
        for c in path.components() {
            match c {
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "host_fs_path".to_string(),
                        message: format!("host fs path escapes cwd root: {raw:?}"),
                        location: None,
                    });
                }
                Component::CurDir | Component::Normal(_) => {}
            }
        }
        Ok(self.host_root.join(path))
    }

    fn host_fs_write(&mut self, raw_path: &str, data: &str) -> Result<(), Finding> {
        let resolved = self.resolve_host_fs_path(raw_path)?;
        if let Some(parent) = resolved.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Finding {
                kind: FindingKind::Assertion,
                title: "host_fs_write".to_string(),
                message: format!("failed to create parent dir for {raw_path:?}: {e}"),
                location: None,
            })?;
        }
        std::fs::write(&resolved, data).map_err(|e| Finding {
            kind: FindingKind::Assertion,
            title: "host_fs_write".to_string(),
            message: format!("failed to write host fs path {raw_path:?}: {e}"),
            location: None,
        })?;
        self.host_fs_touched.insert(resolved);
        Ok(())
    }

    fn host_fs_read_assert(&mut self, raw_path: &str, equals: &str) -> Result<(), Finding> {
        let resolved = self.resolve_host_fs_path(raw_path)?;
        self.host_fs_touched.insert(resolved.clone());
        let got = std::fs::read_to_string(&resolved).map_err(|e| Finding {
            kind: FindingKind::Assertion,
            title: "host_fs_read_assert".to_string(),
            message: format!("failed to read host fs path {raw_path:?}: {e}"),
            location: None,
        })?;
        if got != equals {
            return Err(Finding {
                kind: FindingKind::Assertion,
                title: "host_fs_read_assert".to_string(),
                message: format!("expected {raw_path:?} == {equals:?}, got {got:?}"),
                location: None,
            });
        }
        Ok(())
    }

    fn host_fs_snapshot(&mut self, name: &str) -> Result<(), Finding> {
        let mut snap = BTreeMap::new();
        for path in &self.host_fs_touched {
            let value = if path.exists() {
                Some(std::fs::read(path).map_err(|e| Finding {
                    kind: FindingKind::Assertion,
                    title: "host_fs_snapshot".to_string(),
                    message: format!("failed to read host fs path {:?}: {e}", path),
                    location: None,
                })?)
            } else {
                None
            };
            snap.insert(path.clone(), value);
        }
        self.host_fs_snapshots.insert(name.to_string(), snap);
        Ok(())
    }

    fn host_fs_restore(&mut self, name: &str) -> Result<(), Finding> {
        let Some(snapshot) = self.host_fs_snapshots.get(name) else {
            return Err(Finding {
                kind: FindingKind::Checker,
                title: "host_fs_restore_missing_snapshot".to_string(),
                message: format!("missing host fs snapshot {name:?}"),
                location: None,
            });
        };

        for path in snapshot.keys() {
            match snapshot.get(path) {
                Some(Some(bytes)) => {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| Finding {
                            kind: FindingKind::Assertion,
                            title: "host_fs_restore".to_string(),
                            message: format!("failed to create parent dir for {:?}: {e}", path),
                            location: None,
                        })?;
                    }
                    std::fs::write(path, bytes).map_err(|e| Finding {
                        kind: FindingKind::Assertion,
                        title: "host_fs_restore".to_string(),
                        message: format!("failed to restore file {:?}: {e}", path),
                        location: None,
                    })?;
                }
                Some(None) | None => {
                    if path.exists() {
                        std::fs::remove_file(path).map_err(|e| Finding {
                            kind: FindingKind::Assertion,
                            title: "host_fs_restore".to_string(),
                            message: format!("failed to remove restored file {:?}: {e}", path),
                            location: None,
                        })?;
                    }
                }
            }
        }
        let snapshot_paths = snapshot.keys().cloned().collect::<BTreeSet<_>>();
        for path in self.host_fs_touched.iter() {
            if snapshot_paths.contains(path) {
                continue;
            }
            if path.exists() {
                std::fs::remove_file(path).map_err(|e| Finding {
                    kind: FindingKind::Assertion,
                    title: "host_fs_restore".to_string(),
                    message: format!("failed to remove restored file {:?}: {e}", path),
                    location: None,
                })?;
            }
        }
        self.host_fs_touched = snapshot.keys().cloned().collect();
        Ok(())
    }

    fn exec_step(&mut self, step: &crate::Step) -> Result<(), Finding> {
        match step {
            crate::Step::TraceEvent { name, fields } => {
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: name.clone(),
                    fields: fields.clone(),
                });
                Ok(())
            }

            crate::Step::RandU64 { key } => {
                let value = self.rng.next_u64();
                self.decisions.push(Decision::RandU64 { value });
                if let Some(cur) = self.replay.as_mut() {
                    match cur.next() {
                        Some(Decision::RandU64 { value: expected }) if *expected == value => {}
                        Some(other) => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!("expected RandU64({value}), got {other:?}"),
                                location: None,
                            });
                        }
                        None => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: "missing RandU64 decision".to_string(),
                                location: None,
                            });
                        }
                    }
                }
                if let Some(key) = key {
                    self.kv.insert(key.clone(), value.to_string());
                }
                Ok(())
            }

            crate::Step::AssertOk { value, msg } => {
                if !value {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "assert_ok".to_string(),
                        message: msg
                            .clone()
                            .unwrap_or_else(|| "assert_ok failed".to_string()),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::AssertEqInt { a, b, msg } => {
                if a != b {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "assert_eq_int".to_string(),
                        message: msg
                            .clone()
                            .unwrap_or_else(|| format!("expected {a} == {b}")),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::AssertNeInt { a, b, msg } => {
                if a == b {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "assert_ne_int".to_string(),
                        message: msg
                            .clone()
                            .unwrap_or_else(|| format!("expected {a} != {b}")),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::AssertEqStr { a, b, msg } => {
                if a != b {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "assert_eq_str".to_string(),
                        message: msg
                            .clone()
                            .unwrap_or_else(|| format!("expected {a:?} == {b:?}")),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::AssertNeStr { a, b, msg } => {
                if a == b {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "assert_ne_str".to_string(),
                        message: msg
                            .clone()
                            .unwrap_or_else(|| format!("expected {a:?} != {b:?}")),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::Sleep { duration } => {
                let d = crate::parse_duration(duration).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;
                let ms = d.as_millis().min(u128::from(u64::MAX)) as u64;
                if self.det {
                    self.clock.sleep(d);
                    self.decisions.push(Decision::TimeSleepMs { ms });
                } else {
                    std::thread::sleep(d);
                }
                if let Some(cur) = self.replay.as_mut() {
                    match cur.next() {
                        Some(Decision::TimeSleepMs { ms: expected }) if *expected == ms => {}
                        Some(other) => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!("expected TimeSleepMs({ms}), got {other:?}"),
                                location: None,
                            });
                        }
                        None => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: "missing TimeSleepMs decision".to_string(),
                                location: None,
                            });
                        }
                    }
                }
                Ok(())
            }

            crate::Step::Advance { duration } => {
                let d = crate::parse_duration(duration).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;
                let ms = d.as_millis().min(u128::from(u64::MAX)) as u64;
                if !self.det {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "advance_requires_det".to_string(),
                        message: "Advance is only supported in deterministic mode (--det)"
                            .to_string(),
                        location: None,
                    });
                }

                self.clock.advance(d);
                self.decisions.push(Decision::TimeAdvanceMs { ms });
                if let Some(cur) = self.replay.as_mut() {
                    match cur.next() {
                        Some(Decision::TimeAdvanceMs { ms: expected }) if *expected == ms => {}
                        Some(other) => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!("expected TimeAdvanceMs({ms}), got {other:?}"),
                                location: None,
                            });
                        }
                        None => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: "missing TimeAdvanceMs decision".to_string(),
                                location: None,
                            });
                        }
                    }
                }
                Ok(())
            }

            crate::Step::Freeze { at_ms } => {
                self.clock.freeze(*at_ms);
                Ok(())
            }

            crate::Step::Unfreeze => {
                self.clock.unfreeze();
                Ok(())
            }

            crate::Step::SetKv { key, value } => {
                self.kv.insert(key.clone(), value.clone());
                Ok(())
            }

            crate::Step::GetKvAssert {
                key,
                equals,
                is_null,
            } => {
                let v = self.kv.get(key).cloned();
                if is_null.unwrap_or(false) {
                    if v.is_some() {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "get_kv_assert".to_string(),
                            message: format!("expected {key:?} to be null"),
                            location: None,
                        });
                    }
                    return Ok(());
                }

                if let Some(expected) = equals {
                    if v.as_deref() != Some(expected.as_str()) {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "get_kv_assert".to_string(),
                            message: format!("expected {key:?} == {expected:?}, got {v:?}"),
                            location: None,
                        });
                    }
                } else if v.is_none() {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "get_kv_assert".to_string(),
                        message: format!("expected {key:?} to exist"),
                        location: None,
                    });
                }

                Ok(())
            }

            crate::Step::FsWrite { path, data } => {
                let start_ms = self.clock.now_ms();
                if let Some(Decision::FsWrite {
                    path: replay_path,
                    data_hex,
                }) = self.replay_peek().cloned()
                {
                    if replay_path != *path {
                        return Err(Finding {
                            kind: FindingKind::Checker,
                            title: "replay_drift".to_string(),
                            message: format!(
                                "replay fs write drift: expected path {replay_path:?}, got {path:?}"
                            ),
                            location: None,
                        });
                    }
                    let expected = decode_hex(&data_hex).map_err(|message| Finding {
                        kind: FindingKind::Checker,
                        title: "replay_drift".to_string(),
                        message: format!(
                            "replay fs write drift: invalid recorded bytes for {path:?}: {message}"
                        ),
                        location: None,
                    })?;
                    if expected != data.as_bytes() {
                        return Err(Finding {
                            kind: FindingKind::Checker,
                            title: "replay_drift".to_string(),
                            message: format!(
                                "replay fs write drift: expected payload for {path:?} to match recorded host bytes"
                            ),
                            location: None,
                        });
                    }
                    let _ = self.replay_take_if(|d| matches!(d, Decision::FsWrite { .. }));
                    self.replay_host_fs_write(path, data.as_bytes());
                } else if matches!(self.fs_backend, FsBackend::Host) {
                    self.host_fs_write(path, data)?;
                    self.decisions.push(Decision::FsWrite {
                        path: path.clone(),
                        data_hex: encode_hex(data.as_bytes()),
                    });
                } else {
                    self.fs.insert(path.clone(), data.clone());
                }
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "capability_fs".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("op".to_string(), serde_json::json!("write")),
                        ("path".to_string(), serde_json::json!(path)),
                        (
                            "backend".to_string(),
                            serde_json::json!(match self.fs_backend {
                                FsBackend::Virtual => "virtual",
                                FsBackend::Host => "host",
                            }),
                        ),
                        (
                            "payload_bytes".to_string(),
                            serde_json::json!(data.len() as u64),
                        ),
                        (
                            "duration_ms".to_string(),
                            serde_json::json!(self.clock.now_ms().saturating_sub(start_ms)),
                        ),
                    ]),
                });
                Ok(())
            }

            crate::Step::FsReadAssert { path, equals } => {
                let start_ms = self.clock.now_ms();
                if let Some(Decision::FsReadAssert {
                    path: replay_path,
                    data_hex,
                }) = self.replay_peek().cloned()
                {
                    if replay_path != *path {
                        return Err(Finding {
                            kind: FindingKind::Checker,
                            title: "replay_drift".to_string(),
                            message: format!(
                                "replay fs read drift: expected path {replay_path:?}, got {path:?}"
                            ),
                            location: None,
                        });
                    }
                    let bytes = decode_hex(&data_hex).map_err(|message| Finding {
                        kind: FindingKind::Checker,
                        title: "replay_drift".to_string(),
                        message: format!(
                            "replay fs read drift: invalid recorded bytes for {path:?}: {message}"
                        ),
                        location: None,
                    })?;
                    let _ = self.replay_take_if(|d| matches!(d, Decision::FsReadAssert { .. }));
                    self.replay_host_fs_write(path, &bytes);
                    self.replay_host_fs_read_assert(path, equals)?;
                } else if matches!(self.fs_backend, FsBackend::Host) {
                    self.host_fs_read_assert(path, equals)?;
                    self.decisions.push(Decision::FsReadAssert {
                        path: path.clone(),
                        data_hex: encode_hex(equals.as_bytes()),
                    });
                } else {
                    let got = self.fs.get(path).cloned();
                    if got.as_deref() != Some(equals.as_str()) {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "fs_read_assert".to_string(),
                            message: format!("expected {path:?} == {equals:?}, got {got:?}"),
                            location: None,
                        });
                    }
                }
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "capability_fs".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("op".to_string(), serde_json::json!("read_assert")),
                        ("path".to_string(), serde_json::json!(path)),
                        (
                            "backend".to_string(),
                            serde_json::json!(match self.fs_backend {
                                FsBackend::Virtual => "virtual",
                                FsBackend::Host => "host",
                            }),
                        ),
                        (
                            "payload_bytes".to_string(),
                            serde_json::json!(equals.len() as u64),
                        ),
                        (
                            "duration_ms".to_string(),
                            serde_json::json!(self.clock.now_ms().saturating_sub(start_ms)),
                        ),
                    ]),
                });
                Ok(())
            }

            crate::Step::FsSnapshot { name } => {
                let start_ms = self.clock.now_ms();
                if let Some(Decision::FsSnapshot {
                    name: replay_name,
                    entries,
                }) = self.replay_peek().cloned()
                {
                    if replay_name != *name {
                        return Err(Finding {
                            kind: FindingKind::Checker,
                            title: "replay_drift".to_string(),
                            message: format!(
                                "replay fs snapshot drift: expected snapshot {replay_name:?}, got {name:?}"
                            ),
                            location: None,
                        });
                    }
                    let _ = self.replay_take_if(|d| matches!(d, Decision::FsSnapshot { .. }));
                    self.apply_replay_host_fs_snapshot(name, &entries)?;
                } else if matches!(self.fs_backend, FsBackend::Host) {
                    self.host_fs_snapshot(name)?;
                    let entries = self
                        .host_fs_snapshots
                        .get(name)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(path, value)| {
                            (
                                path.to_string_lossy().to_string(),
                                value.map(|bytes| encode_hex(&bytes)),
                            )
                        })
                        .collect();
                    self.decisions.push(Decision::FsSnapshot {
                        name: name.clone(),
                        entries,
                    });
                } else {
                    self.fs_snapshots.insert(name.clone(), self.fs.clone());
                }
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "capability_fs".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("op".to_string(), serde_json::json!("snapshot")),
                        ("name".to_string(), serde_json::json!(name)),
                        (
                            "backend".to_string(),
                            serde_json::json!(match self.fs_backend {
                                FsBackend::Virtual => "virtual",
                                FsBackend::Host => "host",
                            }),
                        ),
                        (
                            "duration_ms".to_string(),
                            serde_json::json!(self.clock.now_ms().saturating_sub(start_ms)),
                        ),
                    ]),
                });
                Ok(())
            }

            crate::Step::FsRestore { name } => {
                let start_ms = self.clock.now_ms();
                if let Some(Decision::FsRestore { name: replay_name }) = self.replay_peek().cloned()
                {
                    if replay_name != *name {
                        return Err(Finding {
                            kind: FindingKind::Checker,
                            title: "replay_drift".to_string(),
                            message: format!(
                                "replay fs restore drift: expected snapshot {replay_name:?}, got {name:?}"
                            ),
                            location: None,
                        });
                    }
                    let _ = self.replay_take_if(|d| matches!(d, Decision::FsRestore { .. }));
                    self.apply_replay_host_fs_restore(name)?;
                } else if matches!(self.fs_backend, FsBackend::Host) {
                    self.host_fs_restore(name)?;
                    self.decisions
                        .push(Decision::FsRestore { name: name.clone() });
                } else {
                    let Some(snapshot) = self.fs_snapshots.get(name).cloned() else {
                        return Err(Finding {
                            kind: FindingKind::Checker,
                            title: "fs_restore_missing_snapshot".to_string(),
                            message: format!("missing fs snapshot {name:?}"),
                            location: None,
                        });
                    };
                    self.fs = snapshot;
                }
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "capability_fs".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("op".to_string(), serde_json::json!("restore")),
                        ("name".to_string(), serde_json::json!(name)),
                        (
                            "backend".to_string(),
                            serde_json::json!(match self.fs_backend {
                                FsBackend::Virtual => "virtual",
                                FsBackend::Host => "host",
                            }),
                        ),
                        (
                            "duration_ms".to_string(),
                            serde_json::json!(self.clock.now_ms().saturating_sub(start_ms)),
                        ),
                    ]),
                });
                Ok(())
            }

            crate::Step::HttpWhen {
                method,
                path,
                status,
                headers,
                body,
                json,
                delay,
                times,
            } => {
                if body.is_some() && json.is_some() {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "http_when_invalid".to_string(),
                        message: "HttpWhen: cannot set both body and json".to_string(),
                        location: None,
                    });
                }

                let delay_ms = if let Some(d) = delay {
                    let dur = crate::parse_duration(d).map_err(|e| Finding {
                        kind: FindingKind::Checker,
                        title: "invalid_duration".to_string(),
                        message: e.to_string(),
                        location: None,
                    })?;
                    dur.as_millis().min(u128::from(u64::MAX)) as u64
                } else {
                    0
                };
                if matches!(self.http_backend, HttpBackend::Host)
                    && !host_http_rule_path_supported(path)
                {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "http_when_host_path".to_string(),
                        message: format!(
                            "http_when path {path:?} is not supported with host backend; use an absolute http(s) url or a path beginning with '/'. examples: \
                             {{\"type\":\"http_when\",\"method\":\"GET\",\"path\":\"https://api.example.com/v1/me\",...}} \
                             or {{\"type\":\"http_when\",\"method\":\"GET\",\"path\":\"/v1/me\",...}}"
                        ),
                        location: None,
                    });
                }

                self.http_rules.push(HttpRule {
                    method: method.clone(),
                    path: path.clone(),
                    status: *status,
                    headers: canonical_headers(headers.as_ref())?,
                    body: body.clone(),
                    json: json.clone(),
                    delay_ms,
                    remaining: times.unwrap_or(u64::MAX),
                });
                Ok(())
            }

            crate::Step::HttpRequest {
                method,
                path,
                headers,
                body,
                expect_status,
                expect_headers,
                expect_body,
                expect_json,
                save_body_as,
            } => {
                let start_ms = self.clock.now_ms();
                if expect_body.is_some() && expect_json.is_some() {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "http_request_invalid".to_string(),
                        message: "HttpRequest: cannot set both expect_body and expect_json"
                            .to_string(),
                        location: None,
                    });
                }
                let (status_code, resp_headers, resp_body, backend) = match self
                    .replay_peek()
                    .cloned()
                {
                    Some(Decision::HttpRequest {
                        method: replay_method,
                        path: replay_path,
                        status_code,
                        headers,
                        body,
                    }) => {
                        if replay_method != *method || replay_path != *path {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!(
                                    "replay http drift: expected {replay_method} {replay_path}, got {method} {path}"
                                ),
                                location: None,
                            });
                        }
                        let _ = self.replay_take_if(|d| matches!(d, Decision::HttpRequest { .. }));
                        (status_code, headers, body, "replay".to_string())
                    }
                    Some(Decision::HttpRequestTimeout {
                        method: replay_method,
                        path: replay_path,
                    }) => {
                        if replay_method != *method || replay_path != *path {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!(
                                    "replay http timeout drift: expected {replay_method} {replay_path}, got {method} {path}"
                                ),
                                location: None,
                            });
                        }
                        let _ = self
                            .replay_take_if(|d| matches!(d, Decision::HttpRequestTimeout { .. }));
                        return Err(Finding {
                            kind: FindingKind::Hang,
                            title: "timeout".to_string(),
                            message: format!("host http request timed out for {method} {path}"),
                            location: self.current_finding_location(),
                        });
                    }
                    _ if matches!(self.http_backend, HttpBackend::Host) => {
                        if !path.starts_with("http://") && !path.starts_with("https://") {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "http_host_url".to_string(),
                                message: format!(
                                    "host http backend requires absolute http/https url, got {path:?}"
                                ),
                                location: None,
                            });
                        }
                        let host_rule_idx = self.http_rules.iter().position(|r| {
                            r.remaining > 0
                                && r.method == *method
                                && host_http_rule_matches(&r.path, path)
                        });
                        if !self.http_rules.is_empty() && host_rule_idx.is_none() {
                            return Err(Finding {
                                kind: FindingKind::Assertion,
                                title: "http_when_host_unmatched".to_string(),
                                message: format!(
                                    "no http_when matched host request {method} {path}. remediation: \
                                 1) align http_when.method/path with this request (absolute url or '/path'), \
                                 2) run with --http-backend scripted to use mocked responses. example: \
                                 fz run <scenario.fozzy.json> --http-backend scripted --json"
                                ),
                                location: None,
                            });
                        }
                        let request_headers = canonical_headers(headers.as_ref())?;
                        let response = dispatch_host_http(
                            method,
                            path,
                            &request_headers,
                            body.as_deref(),
                            self.remaining_host_timeout(),
                        )
                        .map_err(|message| Finding {
                            kind: FindingKind::Assertion,
                            title: "http_host_request".to_string(),
                            message,
                            location: None,
                        })?;
                        let response = match response {
                            HostHttpDispatch::Completed(response) => {
                                self.decisions.push(Decision::HttpRequest {
                                    method: method.clone(),
                                    path: path.clone(),
                                    status_code: response.status,
                                    headers: response.headers.clone(),
                                    body: response.body.clone(),
                                });
                                response
                            }
                            HostHttpDispatch::TimedOut => {
                                self.decisions.push(Decision::HttpRequestTimeout {
                                    method: method.clone(),
                                    path: path.clone(),
                                });
                                return Err(Finding {
                                    kind: FindingKind::Hang,
                                    title: "timeout".to_string(),
                                    message: format!(
                                        "host http request timed out for {method} {path}"
                                    ),
                                    location: self.current_finding_location(),
                                });
                            }
                        };
                        if let Some(idx) = host_rule_idx {
                            let mut rule = self.http_rules[idx].clone();
                            if rule.remaining != u64::MAX {
                                rule.remaining = rule.remaining.saturating_sub(1);
                            }
                            self.http_rules[idx] = rule.clone();
                            assert_http_when_response_matches_host(
                                method,
                                path,
                                rule.status,
                                &rule.headers,
                                rule.body.as_deref(),
                                rule.json.as_ref(),
                                response.status,
                                &response.headers,
                                &response.body,
                            )?;
                        }
                        (
                            response.status,
                            response.headers,
                            response.body,
                            "host".to_string(),
                        )
                    }
                    _ => {
                        let rule_idx = self.http_rules.iter().position(|r| {
                            r.remaining > 0 && r.method == *method && r.path == *path
                        });
                        let Some(idx) = rule_idx else {
                            return Err(Finding {
                                kind: FindingKind::Assertion,
                                title: "http_unmatched".to_string(),
                                message: format!("no http mock matched {method} {path}"),
                                location: None,
                            });
                        };

                        let mut rule = self.http_rules[idx].clone();
                        if rule.remaining != u64::MAX {
                            rule.remaining = rule.remaining.saturating_sub(1);
                        }
                        self.http_rules[idx] = rule.clone();

                        if self.det && rule.delay_ms > 0 {
                            self.clock.advance(Duration::from_millis(rule.delay_ms));
                        } else if !self.det && rule.delay_ms > 0 {
                            std::thread::sleep(Duration::from_millis(rule.delay_ms));
                        }

                        let resp_body = if let Some(j) = &rule.json {
                            serde_json::to_string(j).map_err(|e| Finding {
                                kind: FindingKind::Checker,
                                title: "http_json_serialize".to_string(),
                                message: e.to_string(),
                                location: None,
                            })?
                        } else {
                            rule.body.clone().unwrap_or_default()
                        };
                        (
                            rule.status,
                            rule.headers.clone(),
                            resp_body,
                            "scripted".to_string(),
                        )
                    }
                };

                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "http_request".to_string(),
                    fields: serde_json::Map::from_iter([
                        (
                            "method".to_string(),
                            serde_json::Value::String(method.clone()),
                        ),
                        ("path".to_string(), serde_json::Value::String(path.clone())),
                        ("backend".to_string(), serde_json::Value::String(backend)),
                        (
                            "status".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(status_code)),
                        ),
                        (
                            "has_body".to_string(),
                            serde_json::Value::Bool(!resp_body.is_empty()),
                        ),
                        (
                            "header_count".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(
                                resp_headers.len() as u64
                            )),
                        ),
                        (
                            "request_payload_bytes".to_string(),
                            serde_json::json!(body.as_ref().map(|s| s.len() as u64).unwrap_or(0)),
                        ),
                        (
                            "response_payload_bytes".to_string(),
                            serde_json::json!(resp_body.len() as u64),
                        ),
                        (
                            "duration_ms".to_string(),
                            serde_json::json!(self.clock.now_ms().saturating_sub(start_ms)),
                        ),
                    ]),
                });
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "capability_http".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("op".to_string(), serde_json::json!("request")),
                        ("method".to_string(), serde_json::json!(method)),
                        ("path".to_string(), serde_json::json!(path)),
                        (
                            "payload_bytes".to_string(),
                            serde_json::json!(resp_body.len() as u64),
                        ),
                        (
                            "duration_ms".to_string(),
                            serde_json::json!(self.clock.now_ms().saturating_sub(start_ms)),
                        ),
                    ]),
                });

                if let Some(expected) = expect_status
                    && status_code != *expected
                {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "http_status".to_string(),
                        message: format!("expected status {expected}, got {}", status_code),
                        location: None,
                    });
                }

                if let Some(expected) = expect_body
                    && resp_body != *expected
                {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "http_body".to_string(),
                        message: "http response body mismatch".to_string(),
                        location: None,
                    });
                }

                if let Some(expected) = expect_json {
                    let got: serde_json::Value =
                        serde_json::from_str(&resp_body).map_err(|e| Finding {
                            kind: FindingKind::Assertion,
                            title: "http_json_parse".to_string(),
                            message: e.to_string(),
                            location: None,
                        })?;
                    if got != *expected {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "http_json".to_string(),
                            message: "http response json mismatch".to_string(),
                            location: None,
                        });
                    }
                }

                if let Some(expected_headers) = expect_headers {
                    let expected = canonical_headers(Some(expected_headers))?;
                    for (k, v) in expected {
                        let got = resp_headers.get(&k);
                        if got != Some(&v) {
                            return Err(Finding {
                                kind: FindingKind::Assertion,
                                title: "http_headers".to_string(),
                                message: format!(
                                    "http response header mismatch for {k:?}: expected {v:?}, got {got:?}"
                                ),
                                location: None,
                            });
                        }
                    }
                }

                if let Some(key) = save_body_as {
                    self.kv.insert(key.clone(), resp_body);
                }
                Ok(())
            }

            crate::Step::ProcWhen {
                cmd,
                args,
                exit_code,
                stdout,
                stderr,
                times,
            } => {
                self.proc_rules.push(ProcRule {
                    cmd: cmd.clone(),
                    args: args.clone().unwrap_or_default(),
                    exit_code: *exit_code,
                    stdout: stdout.clone().unwrap_or_default(),
                    stderr: stderr.clone().unwrap_or_default(),
                    remaining: times.unwrap_or(u64::MAX),
                });
                Ok(())
            }

            crate::Step::ProcSpawn {
                cmd,
                args,
                expect_exit,
                expect_stdout,
                expect_stderr,
                save_stdout_as,
            } => {
                let start_ms = self.clock.now_ms();
                let call_args = args.clone().unwrap_or_default();
                let replay_rule = match self.replay_peek().cloned() {
                    Some(Decision::ProcSpawn {
                        cmd: replay_cmd,
                        args: replay_args,
                        exit_code,
                        stdout,
                        stderr,
                    }) => {
                        if replay_cmd != *cmd || replay_args != call_args {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!(
                                    "replay proc drift: expected {replay_cmd:?} {:?}, got {cmd:?} {:?}",
                                    replay_args, call_args
                                ),
                                location: None,
                            });
                        }
                        let _ = self.replay_take_if(|d| matches!(d, Decision::ProcSpawn { .. }));
                        Some(ProcRule {
                            cmd: cmd.clone(),
                            args: call_args.clone(),
                            exit_code,
                            stdout,
                            stderr,
                            remaining: 0,
                        })
                    }
                    Some(Decision::ProcSpawnTimeout {
                        cmd: replay_cmd,
                        args: replay_args,
                        ..
                    }) => {
                        if replay_cmd != *cmd || replay_args != call_args {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!(
                                    "replay proc timeout drift: expected {replay_cmd:?} {:?}, got {cmd:?} {:?}",
                                    replay_args, call_args
                                ),
                                location: None,
                            });
                        }
                        let _ =
                            self.replay_take_if(|d| matches!(d, Decision::ProcSpawnTimeout { .. }));
                        return Err(Finding {
                            kind: FindingKind::Hang,
                            title: "timeout".to_string(),
                            message: format!("host proc timed out for {cmd:?} {:?}", call_args),
                            location: self.current_finding_location(),
                        });
                    }
                    Some(_) | None => None,
                };

                let idx = self
                    .proc_rules
                    .iter()
                    .position(|r| r.remaining > 0 && r.cmd == *cmd && r.args == call_args);
                let rule = if let Some(rule) = replay_rule {
                    rule
                } else if let Some(idx) = idx {
                    let mut rule = self.proc_rules[idx].clone();
                    if rule.remaining != u64::MAX {
                        rule.remaining = rule.remaining.saturating_sub(1);
                    }
                    self.proc_rules[idx] = rule.clone();
                    rule
                } else if matches!(self.proc_backend, ProcBackend::Host) {
                    match dispatch_host_proc(cmd, &call_args, self.host_deadline).map_err(
                        |message| Finding {
                            kind: FindingKind::Assertion,
                            title: "proc_spawn_host".to_string(),
                            message,
                            location: None,
                        },
                    )? {
                        HostProcDispatch::Completed(output) => ProcRule {
                            cmd: cmd.clone(),
                            args: call_args.clone(),
                            exit_code: output.exit_code,
                            stdout: output.stdout,
                            stderr: output.stderr,
                            remaining: 0,
                        },
                        HostProcDispatch::TimedOut { stdout, stderr } => {
                            self.decisions.push(Decision::ProcSpawnTimeout {
                                cmd: cmd.clone(),
                                args: call_args.clone(),
                                stdout,
                                stderr,
                            });
                            return Err(Finding {
                                kind: FindingKind::Hang,
                                title: "timeout".to_string(),
                                message: format!("host proc timed out for {cmd:?} {:?}", call_args),
                                location: self.current_finding_location(),
                            });
                        }
                    }
                } else {
                    let step_index = self.current_step_index.unwrap_or_default();
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "proc_unmatched".to_string(),
                        message: proc_unmatched_message(
                            cmd,
                            &call_args,
                            self.scenario_path.as_deref(),
                            step_index,
                        ),
                        location: self.current_finding_location(),
                    });
                };
                self.decisions.push(Decision::ProcSpawn {
                    cmd: cmd.clone(),
                    args: call_args.clone(),
                    exit_code: rule.exit_code,
                    stdout: rule.stdout.clone(),
                    stderr: rule.stderr.clone(),
                });

                let mut proc_fields = serde_json::Map::new();
                proc_fields.insert("cmd".to_string(), serde_json::Value::String(cmd.clone()));
                proc_fields.insert(
                    "backend".to_string(),
                    serde_json::Value::String(match self.proc_backend {
                        ProcBackend::Scripted => "scripted".to_string(),
                        ProcBackend::Host => "host".to_string(),
                    }),
                );
                proc_fields.insert(
                    "exit_code".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(rule.exit_code)),
                );
                proc_fields.insert(
                    "stdout".to_string(),
                    serde_json::Value::String(truncate_event_text(&rule.stdout)),
                );
                proc_fields.insert(
                    "stderr".to_string(),
                    serde_json::Value::String(truncate_event_text(&rule.stderr)),
                );
                proc_fields.insert(
                    "stdout_bytes".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(rule.stdout.len() as u64)),
                );
                proc_fields.insert(
                    "stderr_bytes".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(rule.stderr.len() as u64)),
                );
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "proc_spawn".to_string(),
                    fields: proc_fields,
                });
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "capability_proc".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("op".to_string(), serde_json::json!("spawn")),
                        ("cmd".to_string(), serde_json::json!(cmd)),
                        (
                            "payload_bytes".to_string(),
                            serde_json::json!((rule.stdout.len() + rule.stderr.len()) as u64),
                        ),
                        (
                            "duration_ms".to_string(),
                            serde_json::json!(self.clock.now_ms().saturating_sub(start_ms)),
                        ),
                    ]),
                });

                if let Some(expected) = expect_exit
                    && rule.exit_code != *expected
                {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "proc_exit".to_string(),
                        message: format!("expected exit {expected}, got {}", rule.exit_code),
                        location: None,
                    });
                }
                if let Some(expected) = expect_stdout
                    && &rule.stdout != expected
                {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "proc_stdout".to_string(),
                        message: "proc stdout mismatch".to_string(),
                        location: None,
                    });
                }
                if let Some(expected) = expect_stderr
                    && &rule.stderr != expected
                {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "proc_stderr".to_string(),
                        message: "proc stderr mismatch".to_string(),
                        location: None,
                    });
                }
                if let Some(key) = save_stdout_as {
                    self.kv.insert(key.clone(), rule.stdout.clone());
                }

                Ok(())
            }

            crate::Step::NetPartition { a, b } => {
                self.net_partitions.insert(sorted_pair(a, b));
                Ok(())
            }

            crate::Step::NetHeal { a, b } => {
                self.net_partitions.remove(&sorted_pair(a, b));
                Ok(())
            }

            crate::Step::NetSetDropRate { rate } => {
                if !(0.0..=1.0).contains(rate) {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "net_drop_rate".to_string(),
                        message: format!("invalid drop rate {rate}; expected [0,1]"),
                        location: None,
                    });
                }
                self.net_drop_rate = *rate;
                Ok(())
            }

            crate::Step::NetSetReorder { enabled } => {
                self.net_reorder = *enabled;
                Ok(())
            }

            crate::Step::NetSend { from, to, payload } => {
                let id = self.net_next_id;
                self.net_next_id = self.net_next_id.saturating_add(1);
                self.net_queue.push_back(NetMessage {
                    id,
                    from: from.clone(),
                    to: to.clone(),
                    payload: payload.clone(),
                });
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "net_send".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("id".to_string(), serde_json::json!(id)),
                        ("from".to_string(), serde_json::json!(from)),
                        ("to".to_string(), serde_json::json!(to)),
                        (
                            "payload_size".to_string(),
                            serde_json::json!(payload.len() as u64),
                        ),
                    ]),
                });
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "capability_net".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("op".to_string(), serde_json::json!("send")),
                        (
                            "payload_bytes".to_string(),
                            serde_json::json!(payload.len() as u64),
                        ),
                        ("duration_ms".to_string(), serde_json::json!(0u64)),
                    ]),
                });
                Ok(())
            }

            crate::Step::NetDeliverOne { strategy } => {
                let mut deliverable = Vec::new();
                for (idx, msg) in self.net_queue.iter().enumerate() {
                    if self
                        .net_partitions
                        .contains(&sorted_pair(&msg.from, &msg.to))
                    {
                        continue;
                    }
                    deliverable.push((idx, msg.id));
                }
                if deliverable.is_empty() {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "net_deliver".to_string(),
                        message: "no deliverable network message".to_string(),
                        location: None,
                    });
                }

                let use_random = strategy
                    .as_deref()
                    .map(|s| s.eq_ignore_ascii_case("random"))
                    .unwrap_or(self.net_reorder);

                let picked_message_id = match self.replay_peek() {
                    Some(Decision::NetDeliverPick { message_id }) => {
                        let id = *message_id;
                        if !deliverable.iter().any(|(_, m)| *m == id) {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!(
                                    "replay net delivery drift: message id {id} is not deliverable"
                                ),
                                location: None,
                            });
                        }
                        let _ =
                            self.replay_take_if(|d| matches!(d, Decision::NetDeliverPick { .. }));
                        id
                    }
                    _ => {
                        let pick_pos = if use_random {
                            (self.rng.next_u64() as usize) % deliverable.len()
                        } else {
                            0
                        };
                        deliverable[pick_pos].1
                    }
                };
                self.decisions.push(Decision::NetDeliverPick {
                    message_id: picked_message_id,
                });

                let Some((idx, _)) = deliverable
                    .into_iter()
                    .find(|(_, id)| *id == picked_message_id)
                else {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "net_deliver".to_string(),
                        message: format!(
                            "selected message id {picked_message_id} no longer in queue"
                        ),
                        location: None,
                    });
                };
                let msg = self.net_queue.remove(idx).expect("queue index exists");

                if let Some(Decision::NetDrop { message_id, .. }) = self.replay_peek()
                    && *message_id != msg.id
                {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "replay_drift".to_string(),
                        message: format!(
                            "replay net drop drift: expected message id {}, got {}",
                            msg.id, message_id
                        ),
                        location: None,
                    });
                }

                let should_drop = match self.replay_take_if(
                    |d| matches!(d, Decision::NetDrop { message_id, .. } if *message_id == msg.id),
                ) {
                    Some(Decision::NetDrop { dropped, .. }) => dropped,
                    _ => {
                        if self.net_drop_rate <= 0.0 {
                            false
                        } else {
                            let sample = (self.rng.next_u64() as f64) / (u64::MAX as f64);
                            sample < self.net_drop_rate
                        }
                    }
                };
                self.decisions.push(Decision::NetDrop {
                    message_id: msg.id,
                    dropped: should_drop,
                });

                if should_drop {
                    self.events.push(TraceEvent {
                        time_ms: self.clock.now_ms(),
                        name: "net_drop".to_string(),
                        fields: serde_json::Map::from_iter([
                            ("id".to_string(), serde_json::Value::Number(msg.id.into())),
                            ("from".to_string(), serde_json::Value::String(msg.from)),
                            ("to".to_string(), serde_json::Value::String(msg.to)),
                            (
                                "payload_size".to_string(),
                                serde_json::json!(msg.payload.len() as u64),
                            ),
                        ]),
                    });
                    return Ok(());
                }

                self.net_inbox
                    .entry(msg.to.clone())
                    .or_default()
                    .push(msg.clone());
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "net_deliver".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("id".to_string(), serde_json::Value::Number(msg.id.into())),
                        ("from".to_string(), serde_json::Value::String(msg.from)),
                        ("to".to_string(), serde_json::Value::String(msg.to)),
                        (
                            "payload_size".to_string(),
                            serde_json::json!(msg.payload.len() as u64),
                        ),
                    ]),
                });
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "capability_net".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("op".to_string(), serde_json::json!("deliver")),
                        (
                            "payload_bytes".to_string(),
                            serde_json::json!(msg.payload.len() as u64),
                        ),
                        ("duration_ms".to_string(), serde_json::json!(0u64)),
                    ]),
                });
                Ok(())
            }

            crate::Step::NetRecvAssert {
                node,
                from,
                payload,
            } => {
                let inbox = self.net_inbox.entry(node.clone()).or_default();
                let pos = inbox.iter().position(|m| {
                    if let Some(f) = from
                        && &m.from != f
                    {
                        return false;
                    }
                    m.payload == *payload
                });
                let Some(pos) = pos else {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "net_recv_assert".to_string(),
                        message: format!(
                            "no matching inbox message for node {node:?} payload {payload:?}"
                        ),
                        location: None,
                    });
                };
                inbox.remove(pos);
                Ok(())
            }

            crate::Step::MemoryAlloc { bytes, key, tag } => {
                let outcome = self.memory.allocate(
                    *bytes,
                    tag.clone(),
                    "step:memory_alloc",
                    self.clock.now_ms(),
                );
                self.decisions.push(Decision::MemoryAlloc {
                    bytes: *bytes,
                    alloc_id: outcome.alloc_id,
                    callsite_hash: outcome.callsite_hash.clone(),
                    failed_reason: outcome.failed_reason.clone(),
                });
                if let Some(cur) = self.replay.as_mut() {
                    match cur.next() {
                        Some(Decision::MemoryAlloc {
                            bytes: expected_bytes,
                            alloc_id: expected_alloc_id,
                            failed_reason: expected_failed,
                            ..
                        }) if *expected_bytes == *bytes
                            && *expected_alloc_id == outcome.alloc_id
                            && *expected_failed == outcome.failed_reason => {}
                        Some(other) => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!("expected MemoryAlloc({bytes}), got {other:?}"),
                                location: None,
                            });
                        }
                        None => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: "missing MemoryAlloc decision".to_string(),
                                location: None,
                            });
                        }
                    }
                }
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "memory_alloc".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("bytes".to_string(), serde_json::json!(bytes)),
                        ("alloc_id".to_string(), serde_json::json!(outcome.alloc_id)),
                        (
                            "failed_reason".to_string(),
                            serde_json::json!(outcome.failed_reason.clone()),
                        ),
                        (
                            "callsite_hash".to_string(),
                            serde_json::json!(outcome.callsite_hash.clone()),
                        ),
                    ]),
                });
                if let Some(id) = outcome.alloc_id
                    && let Some(k) = key
                {
                    self.kv.insert(k.clone(), id.to_string());
                }
                if let Some(reason) = outcome.failed_reason {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "memory_alloc_failed".to_string(),
                        message: format!("memory allocation failed: {reason}"),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::MemoryFree { alloc_id, key } => {
                let id = if let Some(v) = alloc_id {
                    *v
                } else if let Some(k) = key {
                    let Some(raw) = self.kv.get(k) else {
                        return Err(Finding {
                            kind: FindingKind::Checker,
                            title: "memory_free".to_string(),
                            message: format!("missing alloc id key {k:?}"),
                            location: None,
                        });
                    };
                    raw.parse::<u64>().map_err(|_| Finding {
                        kind: FindingKind::Checker,
                        title: "memory_free".to_string(),
                        message: format!("alloc id key {k:?} is not a u64"),
                        location: None,
                    })?
                } else {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "memory_free".to_string(),
                        message: "set alloc_id or key".to_string(),
                        location: None,
                    });
                };
                let existed = self.memory.free(id, self.clock.now_ms());
                self.decisions.push(Decision::MemoryFree {
                    alloc_id: id,
                    existed,
                });
                if let Some(cur) = self.replay.as_mut() {
                    match cur.next() {
                        Some(Decision::MemoryFree {
                            alloc_id: expected_id,
                            existed: expected_existed,
                        }) if *expected_id == id && *expected_existed == existed => {}
                        Some(other) => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!("expected MemoryFree({id}), got {other:?}"),
                                location: None,
                            });
                        }
                        None => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: "missing MemoryFree decision".to_string(),
                                location: None,
                            });
                        }
                    }
                }
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "memory_free".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("alloc_id".to_string(), serde_json::json!(id)),
                        ("existed".to_string(), serde_json::json!(existed)),
                    ]),
                });
                if !existed {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "memory_free_missing".to_string(),
                        message: format!("allocation id {id} was not live"),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::MemoryLimitMb { mb } => {
                self.memory.options.limit_mb = Some(*mb);
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "memory_limit_mb".to_string(),
                    fields: serde_json::Map::from_iter([("mb".to_string(), serde_json::json!(mb))]),
                });
                Ok(())
            }

            crate::Step::MemoryFailAfterAllocs { count } => {
                self.memory.options.fail_after_allocs = Some(*count);
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "memory_fail_after_allocs".to_string(),
                    fields: serde_json::Map::from_iter([(
                        "count".to_string(),
                        serde_json::json!(count),
                    )]),
                });
                Ok(())
            }

            crate::Step::MemoryFragmentation { seed } => {
                self.memory.options.fragmentation_seed = Some(*seed);
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "memory_fragmentation".to_string(),
                    fields: serde_json::Map::from_iter([(
                        "seed".to_string(),
                        serde_json::json!(seed),
                    )]),
                });
                Ok(())
            }

            crate::Step::MemoryPressureWave { pattern } => {
                self.memory.options.pressure_wave = Some(pattern.clone());
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "memory_pressure_wave".to_string(),
                    fields: serde_json::Map::from_iter([(
                        "pattern".to_string(),
                        serde_json::json!(pattern),
                    )]),
                });
                Ok(())
            }

            crate::Step::MemoryCheckpoint { name } => {
                self.memory.checkpoint(name, self.clock.now_ms());
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "memory_checkpoint".to_string(),
                    fields: serde_json::Map::from_iter([(
                        "name".to_string(),
                        serde_json::json!(name),
                    )]),
                });
                Ok(())
            }

            crate::Step::MemoryAssertInUseBytes { equals } => {
                let got = self.memory.in_use_bytes();
                if got != *equals {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "memory_assert_in_use_bytes".to_string(),
                        message: format!("expected in_use_bytes={equals}, got {got}"),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::AssertThrows { steps } => self.exec_expect_failure("assert_throws", steps),
            crate::Step::AssertRejects { steps } => {
                self.exec_expect_failure("assert_rejects", steps)
            }

            crate::Step::AssertEventuallyKv {
                key,
                equals,
                within,
                poll,
                msg,
            } => {
                let within_d = crate::parse_duration(within).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;
                let poll_d = crate::parse_duration(poll).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;

                let start_virtual_ms = self.clock.now_ms();
                let deadline = start_virtual_ms.saturating_add(duration_to_ms(within_d));
                loop {
                    if self.kv.get(key).is_some_and(|v| v == equals) {
                        return Ok(());
                    }
                    if self.clock.now_ms() >= deadline {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "assert_eventually_kv".to_string(),
                            message: msg.clone().unwrap_or_else(|| {
                                format!("key {key:?} did not become {equals:?} within {}", within)
                            }),
                            location: None,
                        });
                    }
                    self.sleep_poll(poll_d);
                }
            }

            crate::Step::AssertNeverKv {
                key,
                equals,
                within,
                poll,
                msg,
            } => {
                let within_d = crate::parse_duration(within).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;
                let poll_d = crate::parse_duration(poll).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;

                let start_virtual_ms = self.clock.now_ms();
                let deadline = start_virtual_ms.saturating_add(duration_to_ms(within_d));
                loop {
                    if self.kv.get(key).is_some_and(|v| v == equals) {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "assert_never_kv".to_string(),
                            message: msg.clone().unwrap_or_else(|| {
                                format!("key {key:?} became forbidden value {equals:?}")
                            }),
                            location: None,
                        });
                    }
                    if self.clock.now_ms() >= deadline {
                        return Ok(());
                    }
                    self.sleep_poll(poll_d);
                }
            }

            crate::Step::Fail { message } => Err(Finding {
                kind: FindingKind::Assertion,
                title: "fail".to_string(),
                message: message.clone(),
                location: None,
            }),

            crate::Step::Panic { message } => Err(Finding {
                kind: FindingKind::Panic,
                title: "panic".to_string(),
                message: message.clone(),
                location: None,
            }),
        }
    }

    fn exec_expect_failure(&mut self, title: &str, steps: &[crate::Step]) -> Result<(), Finding> {
        let replay = self.replay;
        let checkpoint = self.checkpoint();
        self.replay = None;
        self.decisions = DecisionLog::default();
        self.events.clear();
        self.findings.clear();
        for s in steps {
            if self.exec_step(s).is_err() {
                self.restore(checkpoint);
                self.replay = replay;
                return Ok(());
            }
        }
        self.restore(checkpoint);
        self.replay = replay;

        Err(Finding {
            kind: FindingKind::Assertion,
            title: title.to_string(),
            message: format!("{title} expected failure but nested steps passed"),
            location: None,
        })
    }

    fn sleep_poll(&mut self, d: Duration) {
        if self.det {
            self.clock.advance(d);
        } else {
            std::thread::sleep(d);
        }
    }

    fn checkpoint(&self) -> ExecCheckpoint {
        ExecCheckpoint {
            rng: self.rng.clone(),
            clock: self.clock.clone(),
            kv: self.kv.clone(),
            fs: self.fs.clone(),
            fs_snapshots: self.fs_snapshots.clone(),
            replay_host_fs: self.replay_host_fs.clone(),
            replay_host_fs_snapshots: self.replay_host_fs_snapshots.clone(),
            host_fs_touched: self.host_fs_touched.clone(),
            host_fs_snapshots: self.host_fs_snapshots.clone(),
            http_rules: self.http_rules.clone(),
            proc_rules: self.proc_rules.clone(),
            net_queue: self.net_queue.clone(),
            net_inbox: self.net_inbox.clone(),
            net_partitions: self.net_partitions.clone(),
            net_next_id: self.net_next_id,
            net_drop_rate: self.net_drop_rate,
            net_reorder: self.net_reorder,
            memory: self.memory.clone(),
        }
    }

    fn restore(&mut self, checkpoint: ExecCheckpoint) {
        self.rng = checkpoint.rng;
        self.clock = checkpoint.clock;
        self.kv = checkpoint.kv;
        self.fs = checkpoint.fs;
        self.fs_snapshots = checkpoint.fs_snapshots;
        self.replay_host_fs = checkpoint.replay_host_fs;
        self.replay_host_fs_snapshots = checkpoint.replay_host_fs_snapshots;
        self.host_fs_touched = checkpoint.host_fs_touched;
        self.host_fs_snapshots = checkpoint.host_fs_snapshots;
        self.http_rules = checkpoint.http_rules;
        self.proc_rules = checkpoint.proc_rules;
        self.net_queue = checkpoint.net_queue;
        self.net_inbox = checkpoint.net_inbox;
        self.net_partitions = checkpoint.net_partitions;
        self.net_next_id = checkpoint.net_next_id;
        self.net_drop_rate = checkpoint.net_drop_rate;
        self.net_reorder = checkpoint.net_reorder;
        self.memory = checkpoint.memory;
    }
}

#[derive(Clone)]
struct ExecCheckpoint {
    rng: ChaCha20Rng,
    clock: crate::VirtualClock,
    kv: BTreeMap<String, String>,
    fs: BTreeMap<String, String>,
    fs_snapshots: BTreeMap<String, BTreeMap<String, String>>,
    replay_host_fs: BTreeMap<String, Vec<u8>>,
    replay_host_fs_snapshots: BTreeMap<String, BTreeMap<String, Option<Vec<u8>>>>,
    host_fs_touched: BTreeSet<PathBuf>,
    host_fs_snapshots: BTreeMap<String, BTreeMap<PathBuf, Option<Vec<u8>>>>,
    http_rules: Vec<HttpRule>,
    proc_rules: Vec<ProcRule>,
    net_queue: VecDeque<NetMessage>,
    net_inbox: BTreeMap<String, Vec<NetMessage>>,
    net_partitions: BTreeSet<(String, String)>,
    net_next_id: u64,
    net_drop_rate: f64,
    net_reorder: bool,
    memory: MemoryState,
}

#[derive(Debug, Clone)]
struct HttpRule {
    method: String,
    path: String,
    status: u16,
    headers: BTreeMap<String, String>,
    body: Option<String>,
    json: Option<serde_json::Value>,
    delay_ms: u64,
    remaining: u64,
}

#[derive(Debug, Clone)]
struct ProcRule {
    cmd: String,
    args: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
    remaining: u64,
}

#[derive(Debug, Clone)]
struct NetMessage {
    id: u64,
    from: String,
    to: String,
    payload: String,
}

fn sorted_pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

#[derive(Debug, Clone, Copy)]
struct ReplayCursor<'a> {
    decisions: &'a [Decision],
    index: usize,
}

impl<'a> ReplayCursor<'a> {
    fn new(decisions: &'a [Decision]) -> Self {
        Self {
            decisions,
            index: 0,
        }
    }

    fn next(&mut self) -> Option<&Decision> {
        let d = self.decisions.get(self.index);
        self.index = self.index.saturating_add(1);
        d
    }

    fn peek(&self) -> Option<&Decision> {
        self.decisions.get(self.index)
    }

    fn remaining(&self) -> usize {
        self.decisions.len().saturating_sub(self.index)
    }
}

fn duration_to_ms(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

fn encode_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0F) as usize] as char);
    }
    out
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex payload must contain an even number of characters".to_string());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = decode_hex_nibble(bytes[i])
            .ok_or_else(|| format!("invalid hex character {:?}", bytes[i] as char))?;
        let lo = decode_hex_nibble(bytes[i + 1])
            .ok_or_else(|| format!("invalid hex character {:?}", bytes[i + 1] as char))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

const TRACE_EVENT_TEXT_LIMIT_BYTES: usize = 16 * 1024;

fn proc_unmatched_message(
    cmd: &str,
    args: &[String],
    scenario_path: Option<&Path>,
    step_index: usize,
) -> String {
    let invocation = if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{cmd} {}", args.join(" "))
    };
    let args_json = serde_json::to_string(args).unwrap_or_else(|_| "[]".to_string());
    let snippet = format!(
        concat!(
            "{{\n",
            "  \"type\": \"proc_when\",\n",
            "  \"cmd\": {cmd:?},\n",
            "  \"args\": {args_json},\n",
            "  \"exit_code\": 0,\n",
            "  \"stdout\": \"\",\n",
            "  \"stderr\": \"\",\n",
            "  \"times\": 1\n",
            "}}"
        ),
        cmd = cmd,
        args_json = args_json
    );
    let scenario_hint = scenario_path
        .map(|path| format!(" in {}", path.display()))
        .unwrap_or_default();
    format!(
        "Strict proc backend blocked an undeclared subprocess: {invocation:?}. \
Add a `proc_when` step for `cmd={cmd}` and `args={args_json}` before step #{} (`proc_spawn`){scenario_hint}. \
Example:\n{snippet}",
        step_index + 1
    )
}

fn truncate_event_text(text: &str) -> String {
    if text.len() <= TRACE_EVENT_TEXT_LIMIT_BYTES {
        return text.to_string();
    }
    let mut out = text
        .chars()
        .take(TRACE_EVENT_TEXT_LIMIT_BYTES)
        .collect::<String>();
    out.push_str("...[truncated]");
    out
}
