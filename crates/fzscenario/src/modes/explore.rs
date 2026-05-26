//! Deterministic distributed exploration runner (single-host simulation).

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore as _, SeedableRng as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::{
    Config, DistributedInvariant, DistributedStep, ExitStatus, Finding, FindingKind,
    MemoryRunReport, MemoryState, ProfileCaptureLevel, RecordCollisionPolicy, Reporter,
    RunIdentity, RunMode, RunSummary, ScenarioFile, ScenarioPath, ScenarioV1Distributed,
    TraceEvent, TraceFile, should_emit_profile_artifacts, wall_time_iso_utc,
    write_memory_artifacts, write_profile_artifacts_from_trace, write_trace_with_policy,
};

use crate::{FozzyError, FozzyResult};
use crate::{HeapBudgetPolicy, heap_budget_findings_from_trace};

type ExploreExecResult = (
    ExitStatus,
    Vec<Finding>,
    Vec<TraceEvent>,
    u64,
    Vec<crate::Decision>,
);

fn heap_budget_policy(config: &Config) -> HeapBudgetPolicy {
    HeapBudgetPolicy {
        alloc_bytes_budget: config.profile_heap_alloc_budget,
        in_use_bytes_budget: config.profile_heap_in_use_budget,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStrategy {
    Fifo,
    Bfs,
    Dfs,
    Random,
    Pct,
    CoverageGuided,
}

impl clap::ValueEnum for ScheduleStrategy {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Fifo,
            Self::Bfs,
            Self::Dfs,
            Self::Random,
            Self::Pct,
            Self::CoverageGuided,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Fifo => clap::builder::PossibleValue::new("fifo"),
            Self::Bfs => clap::builder::PossibleValue::new("bfs"),
            Self::Dfs => clap::builder::PossibleValue::new("dfs"),
            Self::Random => clap::builder::PossibleValue::new("random"),
            Self::Pct => clap::builder::PossibleValue::new("pct"),
            Self::CoverageGuided => clap::builder::PossibleValue::new("coverage_guided"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ExploreOptions {
    pub seed: Option<u64>,
    pub time: Option<Duration>,
    pub steps: Option<u64>,
    pub nodes: Option<usize>,
    pub faults: Option<String>,
    pub schedule: ScheduleStrategy,
    pub checker: Option<String>,
    pub record_trace_to: Option<PathBuf>,
    pub shrink: bool,
    pub minimize: bool,
    pub reporter: Reporter,
    pub record_collision: RecordCollisionPolicy,
    pub profile_capture: ProfileCaptureLevel,
    pub memory: crate::MemoryOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploreTrace {
    pub scenario_path: String,
    pub scenario: ScenarioV1Explore,
    pub schedule: ScheduleStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioV1Explore {
    pub version: u32,
    pub name: String,
    pub nodes: Vec<String>,
    pub steps: Vec<DistributedStep>,
    #[serde(default)]
    pub invariants: Vec<DistributedInvariant>,
}

#[derive(Debug, Clone)]
struct Node {
    running: bool,
    kv: BTreeMap<String, String>,
    kv_version: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
struct Message {
    id: u64,
    from: String,
    to: String,
    kind: String,
    key: String,
    value: String,
    version: u64,
}

#[derive(Debug, Clone, Default)]
struct NetRules {
    partitions: BTreeSet<(String, String)>,
}

impl NetRules {
    fn is_blocked(&self, a: &str, b: &str) -> bool {
        let (x, y) = ordered_pair(a, b);
        self.partitions.contains(&(x.to_string(), y.to_string()))
    }

    fn partition(&mut self, a: &str, b: &str) {
        let (x, y) = ordered_pair(a, b);
        self.partitions.insert((x.to_string(), y.to_string()));
    }

    fn heal(&mut self, a: &str, b: &str) {
        let (x, y) = ordered_pair(a, b);
        self.partitions.remove(&(x.to_string(), y.to_string()));
    }
}

pub fn explore(
    config: &Config,
    scenario_path: ScenarioPath,
    opt: &ExploreOptions,
) -> FozzyResult<crate::RunResult> {
    let seed = opt.seed.unwrap_or_else(gen_seed);
    let run_id = Uuid::new_v4().to_string();
    let started_at = wall_time_iso_utc();
    let started = Instant::now();

    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;

    let mut scenario = load_explore_scenario(&scenario_path, opt.nodes)?;
    apply_faults_preset(&mut scenario, opt.faults.as_deref())?;
    apply_checker_override(&mut scenario, opt.checker.as_deref())?;
    let (status, findings, events, delivered, decisions) =
        run_explore_inner(&scenario, seed, opt.schedule, opt.steps, opt.time)?;
    let _ = delivered;
    let memory_report = if opt.memory.track {
        Some(MemoryState::new(opt.memory.clone()).finalize())
    } else {
        None
    };

    let finished_at = wall_time_iso_utc();
    let (duration_ms, duration_ns) = crate::duration_fields(started.elapsed());
    let report_path = artifacts_dir.join("report.json");

    let mut summary = RunSummary {
        status,
        mode: RunMode::Explore,
        identity: RunIdentity {
            run_id: run_id.clone(),
            seed,
            trace_path: None,
            report_path: Some(report_path.to_string_lossy().to_string()),
            artifacts_dir: Some(artifacts_dir.to_string_lossy().to_string()),
        },
        started_at,
        finished_at,
        duration_ms,
        duration_ns,
        tests: None,
        memory: memory_report.as_ref().map(|m| m.summary.clone()),
        findings: findings.clone(),
    };
    let mut profile_trace = TraceFile::new_explore(
        ExploreTrace {
            scenario_path: scenario_path.as_path().to_string_lossy().to_string(),
            scenario: scenario.clone(),
            schedule: opt.schedule,
        },
        decisions.clone(),
        events.clone(),
        summary.clone(),
    );
    profile_trace.memory = memory_report.as_ref().map(|m| m.to_trace());
    let heap_findings =
        heap_budget_findings_from_trace(&profile_trace, &heap_budget_policy(config));
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

    let should_record = opt.record_trace_to.is_some() || status != ExitStatus::Pass;
    if should_record {
        let out = opt
            .record_trace_to
            .clone()
            .unwrap_or_else(|| artifacts_dir.join("trace.fozzy"));
        let trace = TraceFile::new_explore(
            ExploreTrace {
                scenario_path: scenario_path.as_path().to_string_lossy().to_string(),
                scenario: scenario.clone(),
                schedule: opt.schedule,
            },
            decisions.clone(),
            events.clone(),
            summary.clone(),
        );
        let mut trace = trace;
        trace.memory = memory_report.as_ref().map(|m| m.to_trace());
        let written = write_trace_with_policy(&trace, &out, opt.record_collision)?;
        summary.identity.trace_path = Some(written.to_string_lossy().to_string());
    }
    let emit_heavy = should_emit_heavy_artifacts(status, should_record)
        || matches!(opt.profile_capture, ProfileCaptureLevel::Full);
    if emit_heavy {
        std::fs::write(
            artifacts_dir.join("events.json"),
            serde_json::to_vec(&events)?,
        )?;
        crate::write_timeline(&events, &artifacts_dir.join("timeline.json"))?;
        if let Some(mem) = memory_report.as_ref()
            && mem.options.artifacts
        {
            write_memory_artifacts(mem, &artifacts_dir)?;
        }
    }
    if should_emit_profile_artifacts(opt.profile_capture, status, should_record) {
        profile_trace.summary = summary.clone();
        write_profile_artifacts_from_trace(&profile_trace, &artifacts_dir)?;
    }
    crate::write_run_manifest(&summary, &artifacts_dir)?;

    Ok(crate::RunResult { summary })
}

pub fn replay_explore_trace(config: &Config, trace: &TraceFile) -> FozzyResult<crate::RunResult> {
    let Some(explore) = trace.explore.as_ref() else {
        return Err(FozzyError::Trace("not an explore trace".to_string()));
    };
    let seed = trace.summary.identity.seed;
    let run_id = Uuid::new_v4().to_string();
    let started_at = wall_time_iso_utc();
    let finished_at = wall_time_iso_utc();

    let (status, findings, events, _delivered, _decisions) =
        run_explore_replay_inner(&explore.scenario, seed, explore.schedule, &trace.decisions)?;
    let memory_report = trace.memory.as_ref().map(|m| MemoryRunReport {
        schema_version: "fozzy.memory_report.v1".to_string(),
        options: m.options.clone(),
        summary: m.summary.clone(),
        leaks: m.leaks.clone(),
        timeline: Vec::new(),
        graph: crate::MemoryGraph::default(),
    });

    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;
    let report_path = artifacts_dir.join("report.json");

    let mut findings = findings.clone();
    for warning in crate::trace_schema_warnings(trace.version) {
        findings.push(Finding {
            kind: FindingKind::Checker,
            title: "stale_trace_schema".to_string(),
            message: warning,
            location: None,
        });
    }

    let mut summary = RunSummary {
        status,
        mode: RunMode::Replay,
        identity: RunIdentity {
            run_id,
            seed,
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
    let mut profile_trace = TraceFile::new_explore(
        explore.clone(),
        trace.decisions.clone(),
        events.clone(),
        summary.clone(),
    );
    profile_trace.memory = memory_report.as_ref().map(|m| m.to_trace());
    let heap_findings =
        heap_budget_findings_from_trace(&profile_trace, &heap_budget_policy(config));
    if !heap_findings.is_empty() {
        summary.findings.extend(heap_findings);
        summary.findings = crate::collapse_findings(summary.findings.clone());
    }

    std::fs::write(&report_path, serde_json::to_vec(&summary)?)?;
    if should_emit_heavy_artifacts(status, true) {
        std::fs::write(
            artifacts_dir.join("events.json"),
            serde_json::to_vec(&events)?,
        )?;
        crate::write_timeline(&events, &artifacts_dir.join("timeline.json"))?;
        if let Some(mem) = memory_report.as_ref()
            && mem.options.artifacts
        {
            write_memory_artifacts(mem, &artifacts_dir)?;
        }
    }
    profile_trace.summary = summary.clone();
    write_profile_artifacts_from_trace(&profile_trace, &artifacts_dir)?;
    crate::write_run_manifest(&summary, &artifacts_dir)?;

    Ok(crate::RunResult { summary })
}

pub fn shrink_explore_trace(
    _config: &Config,
    trace_path: crate::TracePath,
    opt: &crate::ShrinkOptions,
) -> FozzyResult<crate::ShrinkResult> {
    let trace = TraceFile::read_json(trace_path.as_path())?;
    let target_status = trace.summary.status;
    let Some(explore) = trace.explore.as_ref() else {
        return Err(FozzyError::Trace("not an explore trace".to_string()));
    };
    if opt.minimize != crate::ShrinkMinimize::All && opt.minimize != crate::ShrinkMinimize::Schedule
    {
        return Err(FozzyError::InvalidArgument(
            "explore shrink only supports --minimize schedule|all (v0.2)".to_string(),
        ));
    }

    let seed = trace.summary.identity.seed;
    let mut best_decisions = trace.decisions.clone();
    let mut candidate = best_decisions.clone();
    let budget = opt.budget.unwrap_or(Duration::from_secs(15));
    let deadline = Instant::now() + budget;

    if opt.minimize == crate::ShrinkMinimize::Schedule || opt.minimize == crate::ShrinkMinimize::All
    {
        let mut chunk = candidate.len().max(1).div_ceil(2);
        while chunk > 0 && Instant::now() < deadline && candidate.len() > 1 {
            let mut improved = false;
            let mut i = 0usize;
            while i < candidate.len() && Instant::now() < deadline {
                let mut trial = candidate.clone();
                let end = (i + chunk).min(trial.len());
                trial.drain(i..end);
                if trial.is_empty() {
                    i += chunk;
                    continue;
                }

                let (status, _findings, _events, _delivered, _decisions) =
                    run_explore_replay_inner(&explore.scenario, seed, explore.schedule, &trial)?;
                if crate::shrink_status_matches(target_status, status) {
                    candidate = trial;
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
        best_decisions = candidate;
    }

    let mut shrunk_scenario = explore.scenario.clone();
    if opt.minimize == crate::ShrinkMinimize::All {
        let mut steps = shrunk_scenario.steps.clone();
        let mut chunk = steps.len().max(1).div_ceil(2);
        while chunk > 0 && Instant::now() < deadline && steps.len() > 1 {
            let mut improved = false;
            let mut i = 0usize;
            while i < steps.len() && Instant::now() < deadline {
                let end = (i + chunk).min(steps.len());
                if !steps[i..end].iter().all(is_shrinkable_setup_step) {
                    i += chunk;
                    continue;
                }
                let mut trial = steps.clone();
                trial.drain(i..end);
                if trial.is_empty() {
                    i += chunk;
                    continue;
                }
                let trial_scenario = ScenarioV1Explore {
                    version: shrunk_scenario.version,
                    name: shrunk_scenario.name.clone(),
                    nodes: shrunk_scenario.nodes.clone(),
                    steps: trial.clone(),
                    invariants: shrunk_scenario.invariants.clone(),
                };
                let (status, _findings, _events, _delivered, _decisions) = run_explore_inner(
                    &trial_scenario,
                    seed,
                    explore.schedule,
                    None,
                    Some(Duration::from_secs(2)),
                )?;
                if crate::shrink_status_matches(target_status, status) {
                    steps = trial;
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
        shrunk_scenario.steps = steps;
    }

    let out_path = opt
        .out_trace_path
        .clone()
        .unwrap_or_else(|| crate::default_min_trace_path(trace_path.as_path()));

    let (status, findings, events, _delivered, out_decisions) = if opt.minimize
        == crate::ShrinkMinimize::All
    {
        let trial = run_explore_inner(
            &shrunk_scenario,
            seed,
            explore.schedule,
            None,
            Some(Duration::from_secs(2)),
        )?;
        if crate::shrink_status_matches(target_status, trial.0) {
            trial
        } else {
            run_explore_replay_inner(&explore.scenario, seed, explore.schedule, &best_decisions)?
        }
    } else {
        run_explore_replay_inner(&explore.scenario, seed, explore.schedule, &best_decisions)?
    };

    let started_at = wall_time_iso_utc();
    let finished_at = wall_time_iso_utc();
    let summary = RunSummary {
        status,
        mode: RunMode::Explore,
        identity: RunIdentity {
            run_id: Uuid::new_v4().to_string(),
            seed,
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
        findings,
    };

    let out_explore = if opt.minimize == crate::ShrinkMinimize::All {
        ExploreTrace {
            scenario_path: explore.scenario_path.clone(),
            scenario: shrunk_scenario,
            schedule: explore.schedule,
        }
    } else {
        explore.clone()
    };

    let trace_out = TraceFile::new_explore(out_explore, out_decisions, events, summary.clone());
    trace_out.write_json(&out_path).map_err(|err| {
        FozzyError::Trace(format!(
            "failed to write shrunk explore trace to {}: {err}",
            out_path.display()
        ))
    })?;

    Ok(crate::ShrinkResult {
        out_trace_path: out_path.to_string_lossy().to_string(),
        result: crate::RunResult { summary },
    })
}

fn is_shrinkable_setup_step(step: &DistributedStep) -> bool {
    matches!(
        step,
        DistributedStep::Partition { .. }
            | DistributedStep::Heal { .. }
            | DistributedStep::Crash { .. }
            | DistributedStep::Restart { .. }
            | DistributedStep::Tick { .. }
    )
}

fn load_explore_scenario(
    path: &ScenarioPath,
    nodes_override: Option<usize>,
) -> FozzyResult<ScenarioV1Explore> {
    let bytes = std::fs::read(path.as_path())?;
    let file: ScenarioFile = serde_json::from_slice(&bytes)?;
    let ScenarioFile::Distributed(d) = file else {
        return Err(FozzyError::Scenario(format!(
            "scenario file {} is not a distributed scenario (use `distributed` section)",
            path.as_path().display()
        )));
    };
    d.validate()?;
    distributed_to_explore(d, nodes_override)
}

pub(crate) fn distributed_to_explore(
    d: ScenarioV1Distributed,
    nodes_override: Option<usize>,
) -> FozzyResult<ScenarioV1Explore> {
    d.validate()?;
    let nodes = if let Some(n) = nodes_override {
        (0..n).map(|i| format!("n{i}")).collect()
    } else if let Some(nodes) = d.distributed.nodes.clone() {
        nodes
    } else if let Some(n) = d.distributed.node_count {
        (0..n).map(|i| format!("n{i}")).collect()
    } else {
        unreachable!("distributed validation requires nodes or node_count")
    };

    Ok(ScenarioV1Explore {
        version: 1,
        name: d.name,
        nodes,
        steps: d.distributed.steps,
        invariants: d.distributed.invariants,
    })
}

pub(crate) fn execute_explore_for_fuzz(
    scenario: &ScenarioV1Explore,
    seed: u64,
) -> FozzyResult<(ExitStatus, Vec<Finding>)> {
    let (status, findings, _, _, _) = run_explore_inner(
        scenario,
        seed,
        ScheduleStrategy::CoverageGuided,
        Some(200),
        None,
    )?;
    Ok((status, findings))
}

fn should_emit_heavy_artifacts(status: ExitStatus, explicit_request: bool) -> bool {
    explicit_request
        || status != ExitStatus::Pass
        || std::env::var("FOZZY_ARTIFACTS_FULL")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn run_explore_inner(
    scenario: &ScenarioV1Explore,
    seed: u64,
    schedule: ScheduleStrategy,
    max_steps: Option<u64>,
    max_time: Option<Duration>,
) -> FozzyResult<ExploreExecResult> {
    let mut rng = rng_from_seed(seed);
    let started = Instant::now();
    let deadline = max_time.map(|d| started + d);
    let step_budget = max_steps.unwrap_or(u64::MAX);

    let mut nodes: BTreeMap<String, Node> = scenario
        .nodes
        .iter()
        .map(|n| {
            (
                n.clone(),
                Node {
                    running: true,
                    kv: BTreeMap::new(),
                    kv_version: BTreeMap::new(),
                },
            )
        })
        .collect();

    let mut net = NetRules::default();
    let mut queue: VecDeque<Message> = VecDeque::new();
    let mut next_id = 1u64;
    let mut events = Vec::new();
    let mut findings = Vec::new();
    let mut decisions: Vec<crate::Decision> = Vec::new();
    let mut seen_strategy_edges: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut delivered = 0u64;
    let mut time_ms = 0u64;

    // Scripted setup actions enqueue replication messages, faults, etc.
    for step in &scenario.steps {
        if let DistributedStep::Tick { duration } = step {
            let d = crate::parse_duration(duration)?;
            time_ms = time_ms.saturating_add(d.as_millis().min(u128::from(u64::MAX)) as u64);
        }

        apply_script_step(
            step,
            &mut nodes,
            &mut net,
            &mut queue,
            &mut next_id,
            &mut events,
            &mut time_ms,
        )?;
    }

    while delivered < step_budget {
        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            findings.push(Finding {
                kind: FindingKind::Hang,
                title: "timeout".to_string(),
                message: "explore timed out".to_string(),
                location: None,
            });
            return Ok((ExitStatus::Timeout, findings, events, delivered, decisions));
        }

        let deliverable = deliverable_indices(&queue, &nodes, &net);
        if deliverable.is_empty() {
            events.push(TraceEvent {
                time_ms,
                name: if queue.is_empty() {
                    "sched_wait".to_string()
                } else {
                    "sched_starvation".to_string()
                },
                fields: serde_json::Map::from_iter([
                    (
                        "queue_len".to_string(),
                        serde_json::json!(queue.len() as u64),
                    ),
                    (
                        "deliverable_len".to_string(),
                        serde_json::json!(deliverable.len() as u64),
                    ),
                ]),
            });
            break;
        }

        let pick = pick_index(
            &queue,
            &deliverable,
            schedule,
            &mut rng,
            &mut seen_strategy_edges,
        );
        let idx = deliverable[pick];
        let msg = queue.remove(idx).expect("index exists");
        let msg_id = msg.id;
        delivered += 1;
        time_ms = time_ms.saturating_add(1);
        decisions.push(crate::Decision::SchedulerPick {
            task_id: msg.id,
            label: "deliver".to_string(),
        });
        events.push(TraceEvent {
            time_ms,
            name: "sched_pick".to_string(),
            fields: serde_json::Map::from_iter([
                ("task_id".to_string(), serde_json::json!(msg.id)),
                (
                    "queue_len".to_string(),
                    serde_json::json!(queue.len() as u64),
                ),
            ]),
        });
        events.push(TraceEvent {
            time_ms,
            name: "span_start".to_string(),
            fields: serde_json::Map::from_iter([
                (
                    "span".to_string(),
                    serde_json::json!(format!("deliver-{}", msg.id)),
                ),
                ("task".to_string(), serde_json::json!("deliver")),
            ]),
        });
        events.push(TraceEvent {
            time_ms,
            name: "deliver".to_string(),
            fields: serde_json::Map::from_iter([
                ("id".to_string(), serde_json::Value::Number(msg.id.into())),
                (
                    "from".to_string(),
                    serde_json::Value::String(msg.from.clone()),
                ),
                ("to".to_string(), serde_json::Value::String(msg.to.clone())),
                (
                    "kind".to_string(),
                    serde_json::Value::String(msg.kind.clone()),
                ),
                (
                    "key".to_string(),
                    serde_json::Value::String(msg.key.clone()),
                ),
                (
                    "payload_size".to_string(),
                    serde_json::json!(msg.value.len() as u64),
                ),
            ]),
        });
        events.push(TraceEvent {
            time_ms,
            name: "capability_net".to_string(),
            fields: serde_json::Map::from_iter([
                ("op".to_string(), serde_json::json!("deliver")),
                (
                    "payload_bytes".to_string(),
                    serde_json::json!(msg.value.len() as u64),
                ),
                ("duration_ms".to_string(), serde_json::json!(1u64)),
            ]),
        });

        deliver_message(
            msg,
            &mut nodes,
            &mut queue,
            &mut next_id,
            &mut events,
            &mut time_ms,
        )?;
        events.push(TraceEvent {
            time_ms,
            name: "span_end".to_string(),
            fields: serde_json::Map::from_iter([
                (
                    "span".to_string(),
                    serde_json::json!(format!("deliver-{}", msg_id)),
                ),
                ("status".to_string(), serde_json::json!("ok")),
                ("duration_ms".to_string(), serde_json::json!(1u64)),
            ]),
        });

        if let Some(finding) = check_invariants(scenario, &nodes, InvariantPhase::Progress) {
            findings.push(finding);
            return Ok((ExitStatus::Fail, findings, events, delivered, decisions));
        }
    }

    if let Some(finding) = check_invariants(scenario, &nodes, InvariantPhase::Final) {
        findings.push(finding);
        return Ok((ExitStatus::Fail, findings, events, delivered, decisions));
    }

    Ok((ExitStatus::Pass, findings, events, delivered, decisions))
}

fn run_explore_replay_inner(
    scenario: &ScenarioV1Explore,
    seed: u64,
    schedule: ScheduleStrategy,
    decisions: &[crate::Decision],
) -> FozzyResult<ExploreExecResult> {
    // Replay uses the recorded "deliver:<id>" sequence (encoded in Step name for v0.2).
    let mut rng = rng_from_seed(seed);

    let mut nodes: BTreeMap<String, Node> = scenario
        .nodes
        .iter()
        .map(|n| {
            (
                n.clone(),
                Node {
                    running: true,
                    kv: BTreeMap::new(),
                    kv_version: BTreeMap::new(),
                },
            )
        })
        .collect();

    let mut net = NetRules::default();
    let mut queue: VecDeque<Message> = VecDeque::new();
    let mut next_id = 1u64;
    let mut events = Vec::new();
    let mut findings = Vec::new();
    let mut delivered = 0u64;
    let mut time_ms = 0u64;

    for step in &scenario.steps {
        if let DistributedStep::Tick { duration } = step {
            let d = crate::parse_duration(duration)?;
            time_ms = time_ms.saturating_add(d.as_millis().min(u128::from(u64::MAX)) as u64);
        }
        apply_script_step(
            step,
            &mut nodes,
            &mut net,
            &mut queue,
            &mut next_id,
            &mut events,
            &mut time_ms,
        )?;
    }

    for d in decisions {
        let msg_id = match d {
            crate::Decision::ExploreDeliver { msg_id } => *msg_id,
            crate::Decision::SchedulerPick { task_id, .. } => *task_id,
            crate::Decision::Step { name, .. } => {
                let Some(id_str) = name.strip_prefix("deliver:") else {
                    continue;
                };
                id_str
                    .parse()
                    .map_err(|_| FozzyError::Trace("invalid deliver decision".to_string()))?
            }
            _ => continue,
        };

        let idx = queue.iter().position(|m| m.id == msg_id).ok_or_else(|| {
            FozzyError::Trace(format!("replay drift: message id {msg_id} not found"))
        })?;
        let msg = queue.remove(idx).expect("position exists");
        let msg_id = msg.id;
        delivered += 1;
        time_ms = time_ms.saturating_add(1);
        events.push(TraceEvent {
            time_ms,
            name: "sched_pick".to_string(),
            fields: serde_json::Map::from_iter([
                ("task_id".to_string(), serde_json::json!(msg.id)),
                (
                    "queue_len".to_string(),
                    serde_json::json!(queue.len() as u64),
                ),
            ]),
        });
        events.push(TraceEvent {
            time_ms,
            name: "span_start".to_string(),
            fields: serde_json::Map::from_iter([
                (
                    "span".to_string(),
                    serde_json::json!(format!("deliver-{}", msg.id)),
                ),
                ("task".to_string(), serde_json::json!("deliver")),
            ]),
        });
        events.push(TraceEvent {
            time_ms,
            name: "deliver".to_string(),
            fields: serde_json::Map::from_iter([
                ("id".to_string(), serde_json::Value::Number(msg.id.into())),
                (
                    "from".to_string(),
                    serde_json::Value::String(msg.from.clone()),
                ),
                ("to".to_string(), serde_json::Value::String(msg.to.clone())),
                (
                    "kind".to_string(),
                    serde_json::Value::String(msg.kind.clone()),
                ),
                (
                    "key".to_string(),
                    serde_json::Value::String(msg.key.clone()),
                ),
                (
                    "payload_size".to_string(),
                    serde_json::json!(msg.value.len() as u64),
                ),
            ]),
        });
        events.push(TraceEvent {
            time_ms,
            name: "capability_net".to_string(),
            fields: serde_json::Map::from_iter([
                ("op".to_string(), serde_json::json!("deliver")),
                (
                    "payload_bytes".to_string(),
                    serde_json::json!(msg.value.len() as u64),
                ),
                ("duration_ms".to_string(), serde_json::json!(1u64)),
            ]),
        });
        deliver_message(
            msg,
            &mut nodes,
            &mut queue,
            &mut next_id,
            &mut events,
            &mut time_ms,
        )?;
        events.push(TraceEvent {
            time_ms,
            name: "span_end".to_string(),
            fields: serde_json::Map::from_iter([
                (
                    "span".to_string(),
                    serde_json::json!(format!("deliver-{}", msg_id)),
                ),
                ("status".to_string(), serde_json::json!("ok")),
                ("duration_ms".to_string(), serde_json::json!(1u64)),
            ]),
        });

        if let Some(finding) = check_invariants(scenario, &nodes, InvariantPhase::Progress) {
            findings.push(finding);
            return Ok((
                ExitStatus::Fail,
                findings,
                events,
                delivered,
                decisions.to_vec(),
            ));
        }
    }

    // If no decisions were provided (or didn't cover all), we still can progress with the configured schedule.
    // This is intentionally permissive for shrink trials.
    let deliverable = deliverable_indices(&queue, &nodes, &net);
    if !deliverable.is_empty() {
        let mut seen_strategy_edges: std::collections::HashSet<u64> =
            std::collections::HashSet::new();
        let idx = deliverable[pick_index(
            &queue,
            &deliverable,
            schedule,
            &mut rng,
            &mut seen_strategy_edges,
        )];
        let msg = queue.remove(idx).expect("index exists");
        let msg_id = msg.id;
        delivered += 1;
        time_ms = time_ms.saturating_add(1);
        events.push(TraceEvent {
            time_ms,
            name: "sched_pick".to_string(),
            fields: serde_json::Map::from_iter([
                ("task_id".to_string(), serde_json::json!(msg.id)),
                (
                    "queue_len".to_string(),
                    serde_json::json!(queue.len() as u64),
                ),
            ]),
        });
        events.push(TraceEvent {
            time_ms,
            name: "span_start".to_string(),
            fields: serde_json::Map::from_iter([
                (
                    "span".to_string(),
                    serde_json::json!(format!("deliver-{}", msg.id)),
                ),
                ("task".to_string(), serde_json::json!("deliver")),
            ]),
        });
        deliver_message(
            msg,
            &mut nodes,
            &mut queue,
            &mut next_id,
            &mut events,
            &mut time_ms,
        )?;
        events.push(TraceEvent {
            time_ms,
            name: "span_end".to_string(),
            fields: serde_json::Map::from_iter([
                (
                    "span".to_string(),
                    serde_json::json!(format!("deliver-{}", msg_id)),
                ),
                ("status".to_string(), serde_json::json!("ok")),
                ("duration_ms".to_string(), serde_json::json!(1u64)),
            ]),
        });
    } else {
        events.push(TraceEvent {
            time_ms,
            name: if queue.is_empty() {
                "sched_wait".to_string()
            } else {
                "sched_starvation".to_string()
            },
            fields: serde_json::Map::from_iter([
                (
                    "queue_len".to_string(),
                    serde_json::json!(queue.len() as u64),
                ),
                ("deliverable_len".to_string(), serde_json::json!(0u64)),
            ]),
        });
    }

    if let Some(finding) = check_invariants(scenario, &nodes, InvariantPhase::Final) {
        findings.push(finding);
        return Ok((
            ExitStatus::Fail,
            findings,
            events,
            delivered,
            decisions.to_vec(),
        ));
    }

    Ok((
        ExitStatus::Pass,
        findings,
        events,
        delivered,
        decisions.to_vec(),
    ))
}

fn apply_script_step(
    step: &DistributedStep,
    nodes: &mut BTreeMap<String, Node>,
    net: &mut NetRules,
    queue: &mut VecDeque<Message>,
    next_id: &mut u64,
    events: &mut Vec<TraceEvent>,
    time_ms: &mut u64,
) -> FozzyResult<()> {
    match step {
        DistributedStep::ClientPut { node, key, value } => {
            let Some(n) = nodes.get_mut(node) else {
                return Err(FozzyError::Scenario(format!("unknown node {node:?}")));
            };
            if !n.running {
                return Ok(());
            }
            let version = n
                .kv_version
                .get(key)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            n.kv_version.insert(key.clone(), version);
            n.kv.insert(key.clone(), value.clone());
            // Replicate to every other node via messages.
            for to in nodes.keys().cloned().collect::<Vec<_>>() {
                if to == *node {
                    continue;
                }
                queue.push_back(Message {
                    id: bump(next_id),
                    from: node.clone(),
                    to,
                    kind: "kv_repl".to_string(),
                    key: key.clone(),
                    value: value.clone(),
                    version,
                });
            }
            events.push(TraceEvent {
                time_ms: *time_ms,
                name: "client_put".to_string(),
                fields: serde_json::Map::from_iter([
                    ("node".to_string(), serde_json::Value::String(node.clone())),
                    ("key".to_string(), serde_json::Value::String(key.clone())),
                ]),
            });
            Ok(())
        }

        DistributedStep::ClientGetAssert {
            node,
            key,
            equals,
            is_null,
        } => {
            let Some(n) = nodes.get(node) else {
                return Err(FozzyError::Scenario(format!("unknown node {node:?}")));
            };
            if !n.running {
                return Ok(());
            }
            let got = n.kv.get(key).cloned();
            if is_null.unwrap_or(false) {
                if got.is_some() {
                    return Err(FozzyError::Scenario(format!(
                        "expected {node}.{key} to be null"
                    )));
                }
                return Ok(());
            }
            if let Some(expected) = equals {
                if got.as_deref() != Some(expected.as_str()) {
                    return Err(FozzyError::Scenario(format!(
                        "expected {node}.{key} == {expected:?}, got {got:?}"
                    )));
                }
            } else if got.is_none() {
                return Err(FozzyError::Scenario(format!(
                    "expected {node}.{key} to exist"
                )));
            }
            Ok(())
        }

        DistributedStep::Partition { a, b } => {
            net.partition(a, b);
            events.push(TraceEvent {
                time_ms: *time_ms,
                name: "partition".to_string(),
                fields: serde_json::Map::from_iter([
                    ("a".to_string(), serde_json::Value::String(a.clone())),
                    ("b".to_string(), serde_json::Value::String(b.clone())),
                ]),
            });
            Ok(())
        }

        DistributedStep::Heal { a, b } => {
            net.heal(a, b);
            events.push(TraceEvent {
                time_ms: *time_ms,
                name: "heal".to_string(),
                fields: serde_json::Map::from_iter([
                    ("a".to_string(), serde_json::Value::String(a.clone())),
                    ("b".to_string(), serde_json::Value::String(b.clone())),
                ]),
            });
            Ok(())
        }

        DistributedStep::Crash { node } => {
            if let Some(n) = nodes.get_mut(node) {
                n.running = false;
            }
            events.push(TraceEvent {
                time_ms: *time_ms,
                name: "crash".to_string(),
                fields: serde_json::Map::from_iter([(
                    "node".to_string(),
                    serde_json::Value::String(node.clone()),
                )]),
            });
            Ok(())
        }

        DistributedStep::Restart { node } => {
            if let Some(n) = nodes.get_mut(node) {
                n.running = true;
            }
            events.push(TraceEvent {
                time_ms: *time_ms,
                name: "restart".to_string(),
                fields: serde_json::Map::from_iter([(
                    "node".to_string(),
                    serde_json::Value::String(node.clone()),
                )]),
            });
            Ok(())
        }

        DistributedStep::Tick { duration: _ } => Ok(()),
    }
}

fn deliver_message(
    msg: Message,
    nodes: &mut BTreeMap<String, Node>,
    queue: &mut VecDeque<Message>,
    next_id: &mut u64,
    _events: &mut Vec<TraceEvent>,
    _time_ms: &mut u64,
) -> FozzyResult<()> {
    let Some(to) = nodes.get_mut(&msg.to) else {
        return Ok(());
    };
    if !to.running {
        return Ok(());
    }
    if msg.kind == "kv_repl" {
        let current = to.kv_version.get(&msg.key).copied().unwrap_or(0);
        if msg.version >= current {
            to.kv_version.insert(msg.key.clone(), msg.version);
            to.kv.insert(msg.key.clone(), msg.value.clone());
        }
        // No further messages in this v0.2 protocol.
    } else if msg.kind == "kv_forward" {
        // Example: forward message to all peers.
        for peer in nodes.keys().cloned().collect::<Vec<_>>() {
            if peer == msg.to {
                continue;
            }
            queue.push_back(Message {
                id: bump(next_id),
                from: msg.to.clone(),
                to: peer,
                kind: "kv_repl".to_string(),
                key: msg.key.clone(),
                value: msg.value.clone(),
                version: msg.version,
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InvariantPhase {
    Progress,
    Final,
}

fn check_invariants(
    scenario: &ScenarioV1Explore,
    nodes: &BTreeMap<String, Node>,
    phase: InvariantPhase,
) -> Option<Finding> {
    for inv in &scenario.invariants {
        match inv {
            DistributedInvariant::KvAllEqual { key } => {
                if phase == InvariantPhase::Progress {
                    // UX: treat kv_all_equal as convergence/final-state invariant, not per-step transient.
                    continue;
                }
                let mut expected: Option<String> = None;
                for n in nodes.values() {
                    if !n.running {
                        continue;
                    }
                    let v = n.kv.get(key).cloned();
                    if expected.is_none() {
                        expected = v;
                        continue;
                    }
                    if v != expected {
                        return Some(Finding {
                            kind: FindingKind::Invariant,
                            title: "kv_all_equal".to_string(),
                            message: format!(
                                "invariant violated for key {key:?}: values diverged across nodes"
                            ),
                            location: None,
                        });
                    }
                }
            }
            DistributedInvariant::KvPresentOnAll { key } => {
                for (name, n) in nodes {
                    if !n.running {
                        continue;
                    }
                    if !n.kv.contains_key(key) {
                        return Some(Finding {
                            kind: FindingKind::Invariant,
                            title: "kv_present_on_all".to_string(),
                            message: format!(
                                "invariant violated: key {key:?} missing on node {name:?}"
                            ),
                            location: None,
                        });
                    }
                }
            }
            DistributedInvariant::KvNodeEquals { node, key, equals } => {
                let Some(n) = nodes.get(node) else {
                    return Some(Finding {
                        kind: FindingKind::Invariant,
                        title: "kv_node_equals".to_string(),
                        message: format!("invariant references unknown node {node:?}"),
                        location: None,
                    });
                };
                if !n.running {
                    continue;
                }
                if n.kv.get(key).map(String::as_str) != Some(equals.as_str()) {
                    return Some(Finding {
                        kind: FindingKind::Invariant,
                        title: "kv_node_equals".to_string(),
                        message: format!(
                            "invariant violated: expected {node}.{key} == {equals:?}, got {:?}",
                            n.kv.get(key)
                        ),
                        location: None,
                    });
                }
            }
        }
    }
    None
}

fn apply_faults_preset(scenario: &mut ScenarioV1Explore, faults: Option<&str>) -> FozzyResult<()> {
    let Some(faults) = faults else {
        return Ok(());
    };
    let mut injected = Vec::new();
    for token in faults.split(',').map(str::trim).filter(|x| !x.is_empty()) {
        match token {
            "none" => {}
            "partition-first-two" => {
                if scenario.nodes.len() < 2 {
                    return Err(FozzyError::Scenario(
                        "fault preset partition-first-two requires at least 2 nodes".to_string(),
                    ));
                }
                injected.push(DistributedStep::Partition {
                    a: scenario.nodes[0].clone(),
                    b: scenario.nodes[1].clone(),
                });
            }
            "heal-first-two" => {
                if scenario.nodes.len() < 2 {
                    return Err(FozzyError::Scenario(
                        "fault preset heal-first-two requires at least 2 nodes".to_string(),
                    ));
                }
                injected.push(DistributedStep::Heal {
                    a: scenario.nodes[0].clone(),
                    b: scenario.nodes[1].clone(),
                });
            }
            "crash-first" => {
                if scenario.nodes.is_empty() {
                    return Err(FozzyError::Scenario(
                        "fault preset crash-first requires at least 1 node".to_string(),
                    ));
                }
                injected.push(DistributedStep::Crash {
                    node: scenario.nodes[0].clone(),
                });
            }
            "restart-first" => {
                if scenario.nodes.is_empty() {
                    return Err(FozzyError::Scenario(
                        "fault preset restart-first requires at least 1 node".to_string(),
                    ));
                }
                injected.push(DistributedStep::Restart {
                    node: scenario.nodes[0].clone(),
                });
            }
            other => {
                return Err(FozzyError::InvalidArgument(format!(
                    "unknown --faults preset {other:?} (supported: none,partition-first-two,heal-first-two,crash-first,restart-first)"
                )));
            }
        }
    }
    if !injected.is_empty() {
        let mut merged = injected;
        merged.extend(std::mem::take(&mut scenario.steps));
        scenario.steps = merged;
    }
    Ok(())
}

fn apply_checker_override(
    scenario: &mut ScenarioV1Explore,
    checker: Option<&str>,
) -> FozzyResult<()> {
    let Some(checker) = checker else {
        return Ok(());
    };
    let mut parsed = Vec::new();
    for token in checker.split(',').map(str::trim).filter(|x| !x.is_empty()) {
        parsed.push(parse_checker_token(token)?);
    }
    if parsed.is_empty() {
        return Err(FozzyError::InvalidArgument(
            "empty --checker override; provide at least one checker token".to_string(),
        ));
    }

    // Override semantics: replace scenario invariants instead of appending.
    scenario.invariants = parsed;
    Ok(())
}

fn parse_checker_token(token: &str) -> FozzyResult<DistributedInvariant> {
    // Supported forms:
    // - kv_all_equal:<key>
    // - kv_present_on_all:<key>
    // - kv_node_equals:<node>:<key>:<value>
    if let Some(key) = token.strip_prefix("kv_all_equal:") {
        return Ok(DistributedInvariant::KvAllEqual {
            key: key.to_string(),
        });
    }
    if let Some(key) = token.strip_prefix("kv_present_on_all:") {
        return Ok(DistributedInvariant::KvPresentOnAll {
            key: key.to_string(),
        });
    }
    if let Some(rest) = token.strip_prefix("kv_node_equals:") {
        let mut parts = rest.splitn(3, ':');
        let node = parts.next().unwrap_or_default().trim();
        let key = parts.next().unwrap_or_default().trim();
        let equals = parts.next().unwrap_or_default().trim();
        if node.is_empty() || key.is_empty() || equals.is_empty() {
            return Err(FozzyError::InvalidArgument(
                "invalid --checker kv_node_equals syntax; expected kv_node_equals:<node>:<key>:<value>".to_string(),
            ));
        }
        return Ok(DistributedInvariant::KvNodeEquals {
            node: node.to_string(),
            key: key.to_string(),
            equals: equals.to_string(),
        });
    }

    Err(FozzyError::InvalidArgument(format!(
        "unknown --checker {token:?} (supported: kv_all_equal:<key>, kv_present_on_all:<key>, kv_node_equals:<node>:<key>:<value>)"
    )))
}

fn deliverable_indices(
    queue: &VecDeque<Message>,
    nodes: &BTreeMap<String, Node>,
    net: &NetRules,
) -> Vec<usize> {
    let mut out = Vec::new();
    for (idx, m) in queue.iter().enumerate() {
        let Some(from) = nodes.get(&m.from) else {
            continue;
        };
        let Some(to) = nodes.get(&m.to) else { continue };
        if !from.running || !to.running {
            continue;
        }
        if net.is_blocked(&m.from, &m.to) {
            continue;
        }
        out.push(idx);
    }
    out
}

fn pick_index(
    queue: &VecDeque<Message>,
    deliverable: &[usize],
    strategy: ScheduleStrategy,
    rng: &mut ChaCha20Rng,
    seen_edges: &mut std::collections::HashSet<u64>,
) -> usize {
    match strategy {
        ScheduleStrategy::Fifo | ScheduleStrategy::Bfs => 0,
        ScheduleStrategy::Dfs => deliverable.len().saturating_sub(1),
        ScheduleStrategy::Random | ScheduleStrategy::Pct => {
            if deliverable.is_empty() {
                0
            } else {
                (rng.next_u64() as usize) % deliverable.len()
            }
        }
        ScheduleStrategy::CoverageGuided => {
            for (pos, idx) in deliverable.iter().enumerate() {
                let m = &queue[*idx];
                let edge = stable_edge(&format!("{}|{}|{}|{}", m.kind, m.from, m.to, m.key));
                if seen_edges.insert(edge) {
                    return pos;
                }
            }
            if deliverable.is_empty() {
                0
            } else {
                (rng.next_u64() as usize) % deliverable.len()
            }
        }
    }
}

fn bump(next_id: &mut u64) -> u64 {
    let id = *next_id;
    *next_id = next_id.saturating_add(1);
    id
}

fn ordered_pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b { (a, b) } else { (b, a) }
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

fn stable_edge(label: &str) -> u64 {
    let h = blake3::hash(label.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(b)
}
