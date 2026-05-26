use rand_core::RngCore as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;

use uuid::Uuid;

use crate::engine::{
    RecordCollisionPolicy, RunOptions, RunResult, ScenarioRun, run_scenario_inner,
};
use crate::finalize::{
    build_run_summary, write_reporter_artifacts, write_single_scenario_trace, write_summary_report,
};
use crate::{
    Config, ExitStatus, Finding, FindingKind, FozzyError, FozzyResult, RunMode, ScenarioPath,
    wall_time_iso_utc,
};

pub fn run_tests(config: &Config, globs: &[String], opt: &RunOptions) -> FozzyResult<RunResult> {
    let patterns = if globs.is_empty() {
        vec!["tests/**/*.fozzy.json".to_string()]
    } else {
        globs.to_vec()
    };

    let resolved_inputs = crate::resolve_matching_files(&patterns)?;
    if !resolved_inputs.missing_literal_files.is_empty() {
        let missing = resolved_inputs
            .missing_literal_files
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(FozzyError::InvalidArgument(format!(
            "explicit scenario path(s) not found: {missing}"
        )));
    }
    let scenario_paths = resolved_inputs.files;
    if scenario_paths.is_empty() {
        return Err(FozzyError::InvalidArgument(format!(
            "no scenario files matched (patterns={patterns:?})"
        )));
    }

    let started_at = wall_time_iso_utc();
    let started = Instant::now();
    let seed = opt.seed.unwrap_or_else(gen_seed);
    let run_id = Uuid::new_v4().to_string();

    let mut filtered_paths = Vec::new();
    let mut skipped = 0u64;
    for p in scenario_paths {
        if let Some(filter) = &opt.filter
            && !p.to_string_lossy().contains(filter)
        {
            skipped += 1;
            continue;
        }
        filtered_paths.push(p);
    }

    let mut distributed_paths = Vec::new();
    for path in &filtered_paths {
        let scenario_path = ScenarioPath::new(path.clone());
        if matches!(
            crate::Scenario::load_file(&scenario_path)?,
            crate::ScenarioFile::Distributed(_)
        ) {
            distributed_paths.push(path.display().to_string());
        }
    }
    if !distributed_paths.is_empty() {
        return Err(FozzyError::InvalidArgument(format!(
            "fz test discovered distributed scenario(s) that must be run with `fz explore`: {}",
            distributed_paths.join(", ")
        )));
    }

    let jobs = if opt.fail_fast {
        1
    } else {
        opt.jobs.unwrap_or(1).max(1)
    };
    let mut outcome = TestOutcome::new(skipped, opt.record_trace_to.is_some());
    if jobs == 1 || filtered_paths.len() <= 1 {
        run_serial_tests(config, &filtered_paths, opt, seed, &mut outcome)?;
    } else {
        run_parallel_tests(config, &filtered_paths, opt, seed, jobs, &mut outcome);
    }

    let finished_at = wall_time_iso_utc();
    let (duration_ms, duration_ns) = crate::duration_fields(started.elapsed());
    let status = if outcome.failed == 0 {
        ExitStatus::Pass
    } else {
        ExitStatus::Fail
    };

    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;
    let report_path = artifacts_dir.join("report.json");

    let summary = build_run_summary(
        status,
        RunMode::Test,
        run_id,
        seed,
        None,
        Some(report_path.to_string_lossy().to_string()),
        Some(artifacts_dir.to_string_lossy().to_string()),
        started_at,
        finished_at,
        duration_ms,
        duration_ns,
        Some(crate::TestCounts {
            passed: outcome.passed,
            failed: outcome.failed,
            skipped: outcome.skipped,
        }),
        outcome.memory_summary(),
        crate::collapse_findings(outcome.findings.clone()),
    );

    write_summary_report(&summary, &report_path, &artifacts_dir)?;
    if let Some(record_base) = &opt.record_trace_to {
        write_test_traces(record_base, &outcome.trace_runs, seed, opt.record_collision)?;
    }
    write_reporter_artifacts(&summary, &artifacts_dir, opt.reporter)?;

    Ok(RunResult { summary })
}

fn run_serial_tests(
    config: &Config,
    filtered_paths: &[PathBuf],
    opt: &RunOptions,
    seed: u64,
    outcome: &mut TestOutcome,
) -> FozzyResult<()> {
    for path in filtered_paths {
        let run = run_scenario_inner(
            config,
            RunMode::Test,
            ScenarioPath::new(path.clone()),
            seed,
            opt.det,
            opt.timeout,
            opt.proc_backend,
            opt.fs_backend,
            opt.http_backend,
            opt.memory.clone(),
        )?;
        outcome.record_run(run);
        if opt.fail_fast && outcome.failed > 0 {
            break;
        }
    }
    Ok(())
}

fn run_parallel_tests(
    config: &Config,
    filtered_paths: &[PathBuf],
    opt: &RunOptions,
    seed: u64,
    jobs: usize,
    outcome: &mut TestOutcome,
) {
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let mut in_flight = 0usize;
        let mut next = 0usize;
        while next < filtered_paths.len() || in_flight > 0 {
            while next < filtered_paths.len() && in_flight < jobs {
                let path = filtered_paths[next].clone();
                let tx = tx.clone();
                let memory = opt.memory.clone();
                let timeout = opt.timeout;
                let proc_backend = opt.proc_backend;
                let fs_backend = opt.fs_backend;
                let http_backend = opt.http_backend;
                let det = opt.det;
                scope.spawn(move || {
                    let result = run_scenario_inner(
                        config,
                        RunMode::Test,
                        ScenarioPath::new(path),
                        seed,
                        det,
                        timeout,
                        proc_backend,
                        fs_backend,
                        http_backend,
                        memory,
                    );
                    let _ = tx.send(result);
                });
                next += 1;
                in_flight += 1;
            }

            if in_flight > 0 {
                if let Ok(result) = rx.recv() {
                    in_flight = in_flight.saturating_sub(1);
                    match result {
                        Ok(run) => outcome.record_run(run),
                        Err(err) => outcome.record_worker_error(err),
                    }
                } else {
                    break;
                }
            }
        }
    });
}

fn write_test_traces(
    record_base: &Path,
    runs: &[ScenarioRun],
    seed: u64,
    policy: RecordCollisionPolicy,
) -> FozzyResult<()> {
    if runs.is_empty() {
        return Ok(());
    }
    if runs.len() == 1 {
        let run = &runs[0];
        write_single_scenario_trace(record_base, run, seed, policy, RunMode::Test)?;
        return Ok(());
    }

    let parent = record_base
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let file_name = record_base
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("test-trace.fozzy");
    let base = if file_name.ends_with(".fozzy") {
        file_name.trim_end_matches(".fozzy")
    } else {
        file_name
    };
    std::fs::create_dir_all(parent)?;

    for (idx, run) in runs.iter().enumerate() {
        let out = parent.join(format!("{base}.{}.fozzy", idx + 1));
        write_single_scenario_trace(&out, run, seed, policy, RunMode::Test)?;
    }
    Ok(())
}

#[derive(Default)]
struct TestOutcome {
    passed: u64,
    failed: u64,
    skipped: u64,
    findings: Vec<Finding>,
    trace_runs: Vec<ScenarioRun>,
    memory_summary: crate::MemorySummary,
    has_memory: bool,
    record_traces: bool,
}

impl TestOutcome {
    fn new(skipped: u64, record_traces: bool) -> Self {
        Self {
            skipped,
            record_traces,
            ..Self::default()
        }
    }

    fn record_run(&mut self, run: ScenarioRun) {
        if run.status == ExitStatus::Pass {
            self.passed += 1;
        } else {
            self.failed += 1;
            self.findings.extend(run.findings.clone());
        }
        if let Some(mem) = run.memory.as_ref() {
            self.has_memory = true;
            self.memory_summary.alloc_count = self
                .memory_summary
                .alloc_count
                .saturating_add(mem.summary.alloc_count);
            self.memory_summary.free_count = self
                .memory_summary
                .free_count
                .saturating_add(mem.summary.free_count);
            self.memory_summary.failed_alloc_count = self
                .memory_summary
                .failed_alloc_count
                .saturating_add(mem.summary.failed_alloc_count);
            self.memory_summary.in_use_bytes = self
                .memory_summary
                .in_use_bytes
                .saturating_add(mem.summary.in_use_bytes);
            self.memory_summary.peak_bytes =
                self.memory_summary.peak_bytes.max(mem.summary.peak_bytes);
            self.memory_summary.leaked_bytes = self
                .memory_summary
                .leaked_bytes
                .saturating_add(mem.summary.leaked_bytes);
            self.memory_summary.leaked_allocs = self
                .memory_summary
                .leaked_allocs
                .saturating_add(mem.summary.leaked_allocs);
        }
        if self.record_traces {
            self.trace_runs.push(run);
        }
    }

    fn record_worker_error(&mut self, err: FozzyError) {
        self.findings.push(Finding {
            kind: FindingKind::Checker,
            title: "test_worker_error".to_string(),
            message: err.to_string(),
            location: None,
        });
        self.failed += 1;
    }

    fn memory_summary(&self) -> Option<crate::MemorySummary> {
        if self.has_memory {
            Some(self.memory_summary.clone())
        } else {
            None
        }
    }
}

fn gen_seed() -> u64 {
    let mut seed = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut seed);
    u64::from_le_bytes(seed)
}
