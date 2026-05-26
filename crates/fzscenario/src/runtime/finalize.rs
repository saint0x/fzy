use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::engine::ScenarioRun;
use crate::{
    ExitStatus, FozzyResult, MemorySummary, RecordCollisionPolicy, Reporter, RunIdentity, RunMode,
    RunSummary, TestCounts, TraceFile, wall_time_iso_utc,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_run_summary(
    status: ExitStatus,
    mode: RunMode,
    run_id: String,
    seed: u64,
    trace_path: Option<String>,
    report_path: Option<String>,
    artifacts_dir: Option<String>,
    started_at: String,
    finished_at: String,
    duration_ms: u64,
    duration_ns: u64,
    tests: Option<TestCounts>,
    memory: Option<MemorySummary>,
    findings: Vec<crate::Finding>,
) -> RunSummary {
    RunSummary {
        status,
        mode,
        identity: RunIdentity {
            run_id,
            seed,
            trace_path,
            report_path,
            artifacts_dir,
        },
        started_at,
        finished_at,
        duration_ms,
        duration_ns,
        tests,
        memory,
        findings,
    }
}

pub(crate) fn build_single_scenario_trace(
    out_path: &Path,
    run: &ScenarioRun,
    seed: u64,
    mode: RunMode,
) -> TraceFile {
    let summary = build_run_summary(
        run.status,
        mode,
        Uuid::new_v4().to_string(),
        seed,
        Some(out_path.to_string_lossy().to_string()),
        None,
        None,
        wall_time_iso_utc(),
        wall_time_iso_utc(),
        0,
        0,
        None,
        run.memory.as_ref().map(|m| m.summary.clone()),
        run.findings.clone(),
    );
    let mut trace = TraceFile::new(
        mode,
        Some(run.scenario_path.to_string_lossy().to_string()),
        Some(run.scenario_embedded.clone()),
        run.decisions.decisions.clone(),
        run.events.clone(),
        summary,
    );
    trace.memory = run.memory.as_ref().map(|m| m.to_trace());
    trace
}

pub(crate) fn write_single_scenario_trace(
    requested_path: &Path,
    run: &ScenarioRun,
    seed: u64,
    policy: RecordCollisionPolicy,
    mode: RunMode,
) -> FozzyResult<PathBuf> {
    let target = crate::resolve_record_target(requested_path, policy)?;
    let trace = build_single_scenario_trace(&target, run, seed, mode);
    crate::write_trace_to_target(&trace, &target)?;
    Ok(target)
}

pub(crate) fn build_shrink_preview_trace(
    scenario: &crate::ScenarioV1Steps,
    seed: u64,
    run: &ScenarioRun,
) -> TraceFile {
    let summary = build_run_summary(
        run.status,
        RunMode::Run,
        "shrink-preview".to_string(),
        seed,
        None,
        None,
        None,
        String::new(),
        String::new(),
        0,
        0,
        None,
        run.memory.as_ref().map(|m| m.summary.clone()),
        run.findings.clone(),
    );
    let mut out = TraceFile::new(
        RunMode::Run,
        None,
        Some(scenario.clone()),
        run.decisions.decisions.clone(),
        run.events.clone(),
        summary,
    );
    out.memory = run.memory.as_ref().map(|m| m.to_trace());
    out
}

pub(crate) fn write_summary_report(
    summary: &RunSummary,
    report_path: &Path,
    artifacts_dir: &Path,
) -> FozzyResult<()> {
    std::fs::write(report_path, serde_json::to_vec(summary)?)?;
    crate::write_run_manifest(summary, artifacts_dir)?;
    Ok(())
}

pub(crate) fn write_reporter_artifacts(
    summary: &RunSummary,
    artifacts_dir: &Path,
    reporter: Reporter,
) -> FozzyResult<()> {
    if matches!(reporter, Reporter::Junit) {
        std::fs::write(
            artifacts_dir.join("junit.xml"),
            crate::render_junit_xml(summary),
        )?;
    }
    if matches!(reporter, Reporter::Html) {
        std::fs::write(
            artifacts_dir.join("report.html"),
            crate::render_html(summary),
        )?;
    }
    Ok(())
}
