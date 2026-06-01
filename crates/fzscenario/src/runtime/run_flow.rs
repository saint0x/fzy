use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rand_core::RngCore as _;
use uuid::Uuid;

use crate::engine::{
    FsBackend, HttpBackend, ProcBackend, ProfileCaptureLevel, ReplayOptions, RunOptions, RunResult,
    ScenarioRun, ShrinkMinimize, ShrinkOptions, ShrinkResult, run_embedded_scenario_inner,
    run_scenario_inner, run_scenario_replay_inner,
};
use crate::finalize::{
    build_run_summary, build_shrink_preview_trace, write_reporter_artifacts, write_summary_report,
};
use crate::{
    Config, ExitStatus, Finding, FindingKind, FozzyError, FozzyResult, HeapBudgetPolicy,
    MemoryRunReport, RunMode, ScenarioPath, ScenarioV1Steps, TraceFile, TracePath,
    heap_budget_findings_from_trace, wall_time_iso_utc, write_memory_artifacts,
    write_memory_delta_artifact, write_profile_artifacts_from_trace,
};

#[derive(Debug, Clone)]
struct ShrinkCandidateResult {
    run: ScenarioRun,
    objective_ok: bool,
}

pub fn run_scenario(
    config: &Config,
    scenario_path: ScenarioPath,
    opt: &RunOptions,
) -> FozzyResult<RunResult> {
    let seed = opt.seed.unwrap_or_else(gen_seed);
    let run_id = Uuid::new_v4().to_string();

    let started_at = wall_time_iso_utc();
    let started = Instant::now();

    let run = run_scenario_inner(
        config,
        RunMode::Run,
        scenario_path.clone(),
        seed,
        opt.det,
        opt.timeout,
        opt.proc_backend,
        opt.fs_backend,
        opt.http_backend,
        opt.memory.clone(),
    )?;
    let finished_at = wall_time_iso_utc();
    let (duration_ms, duration_ns) = crate::duration_fields(started.elapsed());

    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;

    let report_path = artifacts_dir.join("report.json");
    let mut trace_path: Option<PathBuf> = None;
    let crate::engine::ScenarioRun {
        status,
        findings,
        memory,
        decisions,
        events,
        scenario_path,
        scenario_embedded,
    } = run;
    let scenario_path_string = scenario_path.to_string_lossy().to_string();
    let explicit_capture = opt.record_trace_to.is_some();
    let emit_heavy = should_emit_heavy_artifacts(status, explicit_capture)
        || matches!(opt.profile_capture, ProfileCaptureLevel::Full);
    let emit_profile =
        crate::should_emit_profile_artifacts(opt.profile_capture, status, explicit_capture);
    let should_record = opt.record_trace_to.is_some() || status != ExitStatus::Pass;

    let mut report_summary = build_run_summary(
        status,
        RunMode::Run,
        run_id.clone(),
        seed,
        None,
        Some(report_path.to_string_lossy().to_string()),
        Some(artifacts_dir.to_string_lossy().to_string()),
        started_at,
        finished_at,
        duration_ms,
        duration_ns,
        None,
        memory.as_ref().map(|m| m.summary.clone()),
        findings,
    );
    let mut trace = if should_record || emit_profile || heap_policy_enabled(config) {
        let mut trace = TraceFile::new(
            RunMode::Run,
            Some(scenario_path_string),
            Some(scenario_embedded),
            decisions.decisions,
            events.clone(),
            report_summary.clone(),
        );
        trace.memory = memory.as_ref().map(|m| m.to_trace());
        Some(trace)
    } else {
        None
    };
    if let Some(trace) = trace.as_ref() {
        let heap_findings = heap_budget_findings_from_trace(trace, &heap_budget_policy(config));
        if !heap_findings.is_empty() {
            report_summary.findings.extend(heap_findings);
            report_summary.findings = crate::collapse_findings(report_summary.findings.clone());
        }
    }
    if emit_heavy {
        std::fs::write(
            artifacts_dir.join("events.json"),
            serde_json::to_vec(&events)?,
        )?;
        crate::write_timeline(&events, &artifacts_dir.join("timeline.json"))?;
        if let Some(mem) = memory.as_ref()
            && opt.memory.artifacts
        {
            write_memory_artifacts(mem, &artifacts_dir)?;
        }
    }
    if should_record {
        let path = opt
            .record_trace_to
            .clone()
            .unwrap_or_else(|| artifacts_dir.join("trace.fozzy"));
        if let Some(trace) = trace.as_mut() {
            trace.summary = report_summary.clone();
        }
        let target = crate::resolve_record_target(&path, opt.record_collision)?;
        crate::write_trace_to_target(
            trace.as_ref().expect("trace should exist when recording"),
            &target,
        )?;
        let written = target;
        trace_path = Some(written);
    }

    let mut summary = report_summary;
    summary.identity.trace_path = trace_path.map(|p| p.to_string_lossy().to_string());
    write_summary_report(&summary, &report_path, &artifacts_dir)?;
    if emit_profile {
        if let Some(trace) = trace.as_mut() {
            trace.summary = summary.clone();
            write_profile_artifacts_from_trace(trace, &artifacts_dir)?;
        }
    }
    write_reporter_artifacts(&summary, &artifacts_dir, opt.reporter)?;

    Ok(RunResult { summary })
}

pub fn replay_trace(
    config: &Config,
    trace_path: TracePath,
    opt: &ReplayOptions,
) -> FozzyResult<RunResult> {
    let trace = TraceFile::read_json(trace_path.as_path())?;
    replay_loaded_trace(config, trace_path, trace, opt)
}

pub fn replay_loaded_trace(
    config: &Config,
    trace_path: TracePath,
    trace: TraceFile,
    opt: &ReplayOptions,
) -> FozzyResult<RunResult> {
    if trace.fuzz.is_some() && trace.scenario.is_none() {
        return crate::replay_fuzz_trace(config, &trace);
    }
    if trace.explore.is_some() && trace.scenario.is_none() {
        return crate::replay_explore_trace(config, &trace);
    }

    let seed = trace.summary.identity.seed;
    let run_id = Uuid::new_v4().to_string();

    let scenario = trace.scenario.clone().ok_or_else(|| {
        FozzyError::Trace("trace missing embedded scenario; cannot replay".to_string())
    })?;

    let scenario_path = trace
        .scenario_path
        .clone()
        .unwrap_or_else(|| "<embedded>".to_string());

    let started_at = wall_time_iso_utc();
    let started = Instant::now();

    let run = run_scenario_replay_inner(
        config,
        RunMode::Replay,
        &scenario,
        &scenario_path,
        seed,
        Some(&trace.decisions),
        opt.until,
        opt.step,
        ProcBackend::Scripted,
        FsBackend::Virtual,
        HttpBackend::Scripted,
        trace
            .memory
            .as_ref()
            .map(|m| m.options.clone())
            .unwrap_or_default(),
    )?;

    let finished_at = wall_time_iso_utc();
    let (duration_ms, duration_ns) = crate::duration_fields(started.elapsed());

    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;
    let report_path = artifacts_dir.join("report.json");

    let crate::engine::ScenarioRun {
        status,
        findings: run_findings,
        memory,
        decisions,
        events,
        scenario_path: _,
        scenario_embedded: _,
    } = run;
    let mut findings = run_findings;
    for warning in crate::trace_schema_warnings(trace.version)
        .into_iter()
        .chain(crate::trace_replay_warnings(&trace))
    {
        findings.push(Finding {
            kind: FindingKind::Checker,
            title: "stale_trace_schema".to_string(),
            message: warning,
            location: None,
        });
    }
    if let (Some(expected), Some(actual)) = (trace.memory.as_ref(), memory.as_ref())
        && expected.summary != actual.summary
    {
        findings.push(Finding {
            kind: FindingKind::Checker,
            title: "replay_memory_drift".to_string(),
            message: format!(
                "replay memory drift: expected leaked_bytes={} leaked_allocs={}, got leaked_bytes={} leaked_allocs={}",
                expected.summary.leaked_bytes,
                expected.summary.leaked_allocs,
                actual.summary.leaked_bytes,
                actual.summary.leaked_allocs
            ),
            location: None,
        });
    }

    let mut summary = build_run_summary(
        status,
        RunMode::Replay,
        run_id,
        seed,
        Some(trace_path.as_path().to_string_lossy().to_string()),
        Some(report_path.to_string_lossy().to_string()),
        Some(artifacts_dir.to_string_lossy().to_string()),
        started_at,
        finished_at,
        duration_ms,
        duration_ns,
        None,
        memory.as_ref().map(|m| m.summary.clone()),
        findings,
    );
    let explicit_capture = opt.dump_events || opt.step;
    let emit_heavy = should_emit_heavy_artifacts(status, explicit_capture)
        || matches!(opt.profile_capture, ProfileCaptureLevel::Full);
    let emit_profile =
        crate::should_emit_profile_artifacts(opt.profile_capture, status, explicit_capture);
    let mut profile_trace = if emit_profile || heap_policy_enabled(config) {
        let mut profile_trace = TraceFile::new(
            RunMode::Replay,
            Some(scenario_path.clone()),
            Some(scenario.clone()),
            decisions.decisions,
            events.clone(),
            summary.clone(),
        );
        profile_trace.memory = memory.as_ref().map(|m| m.to_trace());
        Some(profile_trace)
    } else {
        None
    };
    if let Some(trace) = profile_trace.as_ref() {
        let heap_findings = heap_budget_findings_from_trace(trace, &heap_budget_policy(config));
        if !heap_findings.is_empty() {
            summary.findings.extend(heap_findings);
            summary.findings = crate::collapse_findings(summary.findings.clone());
        }
    }

    write_summary_report(&summary, &report_path, &artifacts_dir)?;
    if emit_heavy {
        std::fs::write(
            artifacts_dir.join("events.json"),
            serde_json::to_vec(&events)?,
        )?;
        crate::write_timeline(&events, &artifacts_dir.join("timeline.json"))?;
        if let Some(mem) = memory.as_ref()
            && mem.options.artifacts
        {
            write_memory_artifacts(mem, &artifacts_dir)?;
        }
    }
    if emit_profile {
        if let Some(trace) = profile_trace.as_mut() {
            trace.summary = summary.clone();
            write_profile_artifacts_from_trace(trace, &artifacts_dir)?;
        }
    }
    Ok(RunResult { summary })
}

pub fn shrink_trace(
    config: &Config,
    trace_path: TracePath,
    opt: &ShrinkOptions,
) -> FozzyResult<ShrinkResult> {
    shrink_trace_inner(config, trace_path, opt, None)
}

pub fn shrink_trace_with_predicate(
    config: &Config,
    trace_path: TracePath,
    opt: &ShrinkOptions,
    objective: &dyn Fn(&TraceFile) -> FozzyResult<bool>,
) -> FozzyResult<ShrinkResult> {
    shrink_trace_inner(config, trace_path, opt, Some(objective))
}

fn shrink_trace_inner(
    config: &Config,
    trace_path: TracePath,
    opt: &ShrinkOptions,
    objective: Option<&dyn Fn(&TraceFile) -> FozzyResult<bool>>,
) -> FozzyResult<ShrinkResult> {
    let trace = TraceFile::read_json(trace_path.as_path())?;
    if trace.fuzz.is_some() && trace.scenario.is_none() {
        return crate::shrink_fuzz_trace(config, trace_path, opt);
    }
    if trace.explore.is_some() && trace.scenario.is_none() {
        return crate::shrink_explore_trace(config, trace_path, opt);
    }
    let target_status = trace.summary.status;
    let seed = trace.summary.identity.seed;

    let scenario = trace.scenario.clone().ok_or_else(|| {
        FozzyError::Trace("trace missing embedded scenario; cannot shrink".to_string())
    })?;

    if opt.minimize != ShrinkMinimize::All && opt.minimize != ShrinkMinimize::Input {
        return Err(FozzyError::InvalidArgument(
            "v0.1 shrink only supports input/step shrinking (use --minimize input|all)".to_string(),
        ));
    }

    let budget = opt.budget.unwrap_or(Duration::from_secs(15));
    let deadline = Instant::now() + budget;

    let mut candidate = scenario.steps.clone();
    let mut best_run = run_embedded_scenario_inner(
        scenario.clone(),
        PathBuf::from("<shrink-baseline>"),
        seed,
        true,
        None,
        ProcBackend::Scripted,
        FsBackend::Virtual,
        HttpBackend::Scripted,
        trace
            .memory
            .as_ref()
            .map(|m| m.options.clone())
            .unwrap_or_default(),
    )?;
    if !crate::shrink_status_matches(target_status, best_run.status) {
        return Err(FozzyError::Trace(
            "baseline trace no longer matches shrink target status".to_string(),
        ));
    }
    if let Some(pred) = objective {
        let preview = build_shrink_preview_trace(&scenario, seed, &best_run);
        let _ = pred(&preview)?;
    }

    let mut chunk = candidate.len().max(1).div_ceil(2);
    let mut candidate_cache = HashMap::<String, ShrinkCandidateResult>::new();
    while chunk > 0 && Instant::now() < deadline && candidate.len() > 1 {
        let mut improved = false;
        let mut i = 0usize;
        while i < candidate.len() && Instant::now() < deadline {
            let end = (i + chunk).min(candidate.len());
            let trial = remove_step_range(&candidate, i, end);
            if trial.is_empty() {
                i += chunk;
                continue;
            }

            let trial_scenario = ScenarioV1Steps {
                version: 1,
                name: scenario.name.clone(),
                steps: trial.clone(),
            };

            let fingerprint = shrink_candidate_fingerprint(&trial_scenario)?;
            let cached = if let Some(existing) = candidate_cache.get(&fingerprint) {
                Some(existing.clone())
            } else {
                let res = run_embedded_scenario_inner(
                    trial_scenario.clone(),
                    PathBuf::from("<shrunk>"),
                    seed,
                    true,
                    None,
                    ProcBackend::Scripted,
                    FsBackend::Virtual,
                    HttpBackend::Scripted,
                    trace
                        .memory
                        .as_ref()
                        .map(|m| m.options.clone())
                        .unwrap_or_default(),
                )?;
                let objective_ok = if crate::shrink_status_matches(target_status, res.status) {
                    if let Some(pred) = objective {
                        let preview = build_shrink_preview_trace(&trial_scenario, seed, &res);
                        pred(&preview)?
                    } else {
                        true
                    }
                } else {
                    false
                };
                let entry = ShrinkCandidateResult {
                    run: res,
                    objective_ok,
                };
                candidate_cache.insert(fingerprint, entry.clone());
                Some(entry)
            };

            let Some(result) = cached else {
                i += chunk;
                continue;
            };
            if !crate::shrink_status_matches(target_status, result.run.status) || !result.objective_ok
            {
                i += chunk;
                continue;
            }
            candidate = trial;
            best_run = result.run;
            improved = true;
        }

        if !improved {
            if chunk == 1 {
                break;
            }
            chunk = chunk.div_ceil(2);
        }
    }

    let out_scenario = ScenarioV1Steps {
        version: 1,
        name: scenario.name.clone(),
        steps: candidate,
    };

    let out_path = opt
        .out_trace_path
        .clone()
        .unwrap_or_else(|| crate::default_min_trace_path(trace_path.as_path()));

    let run_id = Uuid::new_v4().to_string();
    let started_at = wall_time_iso_utc();
    let finished_at = wall_time_iso_utc();
    let summary = build_run_summary(
        best_run.status,
        RunMode::Run,
        run_id,
        seed,
        Some(out_path.to_string_lossy().to_string()),
        None,
        None,
        started_at,
        finished_at,
        0,
        0,
        None,
        best_run.memory.as_ref().map(|m| m.summary.clone()),
        best_run.findings.clone(),
    );

    let mut trace_out = TraceFile::new(
        RunMode::Run,
        None,
        Some(out_scenario),
        best_run.decisions.decisions.clone(),
        best_run.events.clone(),
        summary.clone(),
    );
    trace_out.memory = best_run.memory.as_ref().map(|m| m.to_trace());
    trace_out.write_json(&out_path).map_err(|err| {
        FozzyError::Trace(format!(
            "failed to write shrunk trace to {}: {err}",
            out_path.display()
        ))
    })?;
    if let (Some(before), Some(after)) = (trace.memory.as_ref(), best_run.memory.as_ref()) {
        let before_report = MemoryRunReport {
            schema_version: "fozzy.memory_report.v1".to_string(),
            options: before.options.clone(),
            summary: before.summary.clone(),
            leaks: before.leaks.clone(),
            timeline: Vec::new(),
            graph: crate::MemoryGraph::default(),
        };
        write_memory_delta_artifact(
            &before_report,
            after,
            &out_path.with_extension("memory.delta.json"),
        )?;
    }

    Ok(ShrinkResult {
        out_trace_path: out_path.to_string_lossy().to_string(),
        result: RunResult { summary },
    })
}

fn remove_step_range(steps: &[crate::Step], start: usize, end: usize) -> Vec<crate::Step> {
    let remove_len = end.saturating_sub(start);
    let mut out = Vec::with_capacity(steps.len().saturating_sub(remove_len));
    out.extend_from_slice(&steps[..start.min(steps.len())]);
    if end < steps.len() {
        out.extend_from_slice(&steps[end..]);
    }
    out
}

fn shrink_candidate_fingerprint(scenario: &ScenarioV1Steps) -> FozzyResult<String> {
    let bytes = serde_json::to_vec(scenario)
        .map_err(|err| FozzyError::Trace(format!("failed to serialize shrink candidate: {err}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn gen_seed() -> u64 {
    let mut seed = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut seed);
    u64::from_le_bytes(seed)
}

fn should_emit_heavy_artifacts(status: ExitStatus, explicit_request: bool) -> bool {
    explicit_request
        || status != ExitStatus::Pass
        || std::env::var("FOZZY_ARTIFACTS_FULL")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn heap_budget_policy(config: &Config) -> HeapBudgetPolicy {
    HeapBudgetPolicy {
        alloc_bytes_budget: config.profile_heap_alloc_budget,
        in_use_bytes_budget: config.profile_heap_in_use_budget,
    }
}

fn heap_policy_enabled(config: &Config) -> bool {
    let policy = heap_budget_policy(config);
    policy.alloc_bytes_budget.is_some() || policy.in_use_bytes_budget.is_some()
}
