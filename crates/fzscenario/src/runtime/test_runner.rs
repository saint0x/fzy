use rand_core::RngCore as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Instant;

use uuid::Uuid;

use crate::engine::{
    RecordCollisionPolicy, RunOptions, RunResult, ScenarioRun, run_embedded_scenario_inner,
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

    let planned_scenarios = plan_test_scenarios(&filtered_paths)?;
    let distributed_paths = planned_scenarios
        .iter()
        .filter_map(|planned| match planned {
            PlannedScenario::Distributed { path } => Some(path.display().to_string()),
            PlannedScenario::Executable { .. } => None,
        })
        .collect::<Vec<_>>();
    if !distributed_paths.is_empty() {
        return Err(FozzyError::InvalidArgument(format!(
            "fz test discovered distributed scenario(s) that must be run with `fz explore`: {}",
            distributed_paths.join(", ")
        )));
    }
    let executable_scenarios = planned_scenarios
        .into_iter()
        .filter_map(|planned| match planned {
            PlannedScenario::Executable { path, scenario } => {
                Some(PreparedScenario { path, scenario })
            }
            PlannedScenario::Distributed { .. } => None,
        })
        .collect::<Vec<_>>();

    let jobs = if opt.fail_fast {
        1
    } else {
        opt.jobs.unwrap_or(1).max(1)
    };
    let mut outcome = TestOutcome::new(skipped, opt.record_trace_to.is_some());
    if jobs == 1 || executable_scenarios.len() <= 1 {
        run_serial_tests(config, &executable_scenarios, opt, seed, &mut outcome)?;
    } else {
        run_parallel_tests(config, &executable_scenarios, opt, seed, jobs, &mut outcome);
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
    _config: &Config,
    planned_scenarios: &[PreparedScenario],
    opt: &RunOptions,
    seed: u64,
    outcome: &mut TestOutcome,
) -> FozzyResult<()> {
    for planned in planned_scenarios {
        let run = run_embedded_scenario_inner(
            planned.scenario.clone(),
            planned.path.clone(),
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
    _config: &Config,
    planned_scenarios: &[PreparedScenario],
    opt: &RunOptions,
    seed: u64,
    jobs: usize,
    outcome: &mut TestOutcome,
) {
    let (tx, rx) = mpsc::channel();
    let next = AtomicUsize::new(0);
    let worker_count = jobs.min(planned_scenarios.len()).max(1);
    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            let tx = tx.clone();
            let memory = opt.memory.clone();
            let timeout = opt.timeout;
            let proc_backend = opt.proc_backend;
            let fs_backend = opt.fs_backend;
            let http_backend = opt.http_backend;
            let det = opt.det;
            let planned_scenarios = planned_scenarios;
            let next = &next;
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(planned) = planned_scenarios.get(index).cloned() else {
                        break;
                    };
                    let result = run_embedded_scenario_inner(
                        planned.scenario,
                        planned.path,
                        seed,
                        det,
                        timeout,
                        proc_backend,
                        fs_backend,
                        http_backend,
                        memory.clone(),
                    );
                    if tx.send(result).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);

        for _ in 0..planned_scenarios.len() {
            match rx.recv() {
                Ok(Ok(run)) => outcome.record_run(run),
                Ok(Err(err)) => outcome.record_worker_error(err),
                Err(_) => {
                    outcome.record_worker_error(FozzyError::Scenario(
                        "parallel test worker exited before reporting all scenario results"
                            .to_string(),
                    ));
                    break;
                }
            }
        }
    });
}

#[derive(Debug, Clone)]
struct PreparedScenario {
    path: PathBuf,
    scenario: crate::ScenarioV1Steps,
}

#[derive(Debug, Clone)]
enum PlannedScenario {
    Executable {
        path: PathBuf,
        scenario: crate::ScenarioV1Steps,
    },
    Distributed {
        path: PathBuf,
    },
}

fn plan_test_scenarios(paths: &[PathBuf]) -> FozzyResult<Vec<PlannedScenario>> {
    let mut planned = Vec::with_capacity(paths.len());
    for path in paths {
        let scenario_path = ScenarioPath::new(path.clone());
        match crate::Scenario::load_file(&scenario_path)? {
            crate::ScenarioFile::Steps(scenario) => {
                scenario.validate()?;
                planned.push(PlannedScenario::Executable {
                    path: path.clone(),
                    scenario,
                });
            }
            crate::ScenarioFile::Distributed(_) => {
                planned.push(PlannedScenario::Distributed { path: path.clone() });
            }
            crate::ScenarioFile::Suites(_) => {
                return Err(FozzyError::Scenario(format!(
                    "scenario file {} uses `suites` without an executable step DSL (v0.1 only supports `steps`)",
                    path.display()
                )));
            }
        }
    }
    Ok(planned)
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

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("fozzy-test-runner-{name}-{}", Uuid::new_v4()))
    }

    #[test]
    fn plan_test_scenarios_preloads_steps_once() {
        let path = temp_path("steps.fozzy.json");
        std::fs::write(
            &path,
            br#"{"version":1,"name":"demo","steps":[{"type":"trace_event","name":"ok","fields":{}}]}"#,
        )
        .expect("write scenario");

        let planned = plan_test_scenarios(std::slice::from_ref(&path)).expect("plan scenarios");
        assert_eq!(planned.len(), 1);
        match &planned[0] {
            PlannedScenario::Executable {
                path: planned_path,
                scenario,
            } => {
                assert_eq!(planned_path, &path);
                assert_eq!(scenario.name, "demo");
                assert_eq!(scenario.steps.len(), 1);
            }
            PlannedScenario::Distributed { .. } => panic!("expected executable scenario"),
        }
    }

    #[test]
    fn plan_test_scenarios_flags_distributed_inputs() {
        let path = temp_path("distributed.fozzy.json");
        std::fs::write(
            &path,
            br#"{"version":1,"name":"dist","distributed":{"node_count":2,"steps":[]}}"#,
        )
        .expect("write distributed scenario");

        let planned = plan_test_scenarios(std::slice::from_ref(&path)).expect("plan scenarios");
        assert!(matches!(
            &planned[0],
            PlannedScenario::Distributed { path: planned_path } if planned_path == &path
        ));
    }

    #[test]
    fn run_tests_parallel_executes_all_scenarios() {
        let root = temp_path("parallel-suite");
        std::fs::create_dir_all(&root).expect("suite dir");
        let first = root.join("a.fozzy.json");
        let second = root.join("b.fozzy.json");
        let scenario =
            br#"{"version":1,"name":"demo","steps":[{"type":"trace_event","name":"ok","fields":{}}]}"#;
        std::fs::write(&first, scenario).expect("write first scenario");
        std::fs::write(&second, scenario).expect("write second scenario");

        let config = crate::Config {
            base_dir: root.join(".fozzy"),
            ..crate::Config::default()
        };
        let globs = vec![
            first.to_string_lossy().to_string(),
            second.to_string_lossy().to_string(),
        ];
        let result = run_tests(
            &config,
            &globs,
            &RunOptions {
                det: true,
                seed: Some(7),
                timeout: None,
                reporter: crate::Reporter::Json,
                record_trace_to: None,
                filter: None,
                jobs: Some(2),
                fail_fast: false,
                record_collision: RecordCollisionPolicy::Append,
                profile_capture: crate::ProfileCaptureLevel::Baseline,
                proc_backend: crate::ProcBackend::Scripted,
                fs_backend: crate::FsBackend::Virtual,
                http_backend: crate::HttpBackend::Scripted,
                memory: crate::MemoryOptions::default(),
            },
        )
        .expect("parallel run should succeed");

        let tests = result.summary.tests.expect("test counts");
        assert_eq!(tests.passed, 2);
        assert_eq!(tests.failed, 0);
        assert!(result.summary.findings.is_empty());
    }
}
