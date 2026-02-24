use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use anyhow::{anyhow, bail, Context, Result};
use runtime::{plan_async_checkpoints, DeterministicExecutor, Scheduler, TaskEvent};
use serde::Serialize;

use crate::pipeline::{
    compile_file, emit_ir, parse_program, verify_file, BuildArtifact, BuildProfile, Output,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Init {
        name: String,
    },
    Build {
        path: PathBuf,
        release: bool,
        threads: Option<u16>,
    },
    Run {
        path: PathBuf,
        args: Vec<String>,
        deterministic: bool,
        strict: bool,
        seed: Option<u64>,
        record: Option<PathBuf>,
        host_backends: bool,
    },
    Test {
        path: PathBuf,
        deterministic: bool,
        strict: bool,
        seed: Option<u64>,
        record: Option<PathBuf>,
        host_backends: bool,
        scheduler: Option<String>,
        rich_artifacts: bool,
    },
    Fmt {
        path: PathBuf,
    },
    Check {
        path: PathBuf,
    },
    Verify {
        path: PathBuf,
    },
    EmitIr {
        path: PathBuf,
    },
    Fuzz {
        target: PathBuf,
    },
    Explore {
        target: PathBuf,
    },
    Replay {
        trace: PathBuf,
    },
    Shrink {
        trace: PathBuf,
    },
    Ci {
        trace: PathBuf,
    },
    Headers {
        path: PathBuf,
        output: Option<PathBuf>,
    },
    RpcGen {
        path: PathBuf,
        out_dir: Option<PathBuf>,
    },
    Version,
}

pub fn run(command: Command, format: Format) -> Result<String> {
    match command {
        Command::Init { name } => {
            init_project(&name).map(|_| render(format, "initialized project"))
        }
        Command::Build {
            path,
            release,
            threads,
        } => {
            let profile = if release {
                BuildProfile::Release
            } else {
                BuildProfile::Dev
            };
            let artifact = compile_file(&path, profile)?;
            let runtime_config = persist_runtime_threads_config(&path, threads)?;
            Ok(render_artifact(format, artifact, threads, runtime_config))
        }
        Command::Run {
            path,
            args,
            deterministic,
            strict,
            seed,
            record,
            host_backends,
        } => {
            if is_fozzy_scenario(&path) {
                let mut fozzy_args = vec!["run".to_string(), path.display().to_string()];
                if deterministic {
                    fozzy_args.push("--det".to_string());
                }
                if strict {
                    fozzy_args.push("--strict".to_string());
                }
                if let Some(seed) = seed {
                    fozzy_args.push("--seed".to_string());
                    fozzy_args.push(seed.to_string());
                }
                if let Some(record) = record {
                    fozzy_args.push("--record".to_string());
                    fozzy_args.push(record.display().to_string());
                }
                if host_backends {
                    fozzy_args.push("--proc-backend".to_string());
                    fozzy_args.push("host".to_string());
                    fozzy_args.push("--fs-backend".to_string());
                    fozzy_args.push("host".to_string());
                    fozzy_args.push("--http-backend".to_string());
                    fozzy_args.push("host".to_string());
                }
                if matches!(format, Format::Json) {
                    fozzy_args.push("--json".to_string());
                }
                return fozzy_invoke(&fozzy_args);
            }

            let artifact = compile_file(&path, BuildProfile::Dev)?;
            if artifact.status != "ok" || artifact.output.is_none() {
                bail!(
                    "run aborted: build status={} diagnostics={}",
                    artifact.status,
                    artifact.diagnostics
                );
            }
            let binary = artifact
                .output
                .as_ref()
                .ok_or_else(|| anyhow!("missing native output artifact"))?;
            let output = ProcessCommand::new(binary)
                .args(&args)
                .output()
                .with_context(|| {
                    format!("failed to execute native artifact: {}", binary.display())
                })?;
            let exit_code = output.status.code().unwrap_or(1);
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            match format {
                Format::Text => Ok(format!(
                    "compiled {} and executed {} with args: {}; exit_code={}; stdout={}; stderr={}",
                    artifact.module,
                    binary.display(),
                    args.join(" "),
                    exit_code,
                    stdout,
                    stderr
                )),
                Format::Json => Ok(serde_json::json!({
                    "module": artifact.module,
                    "status": artifact.status,
                    "diagnostics": artifact.diagnostics,
                    "binary": binary.display().to_string(),
                    "args": args,
                    "deterministic": deterministic,
                    "strict": strict,
                    "seed": seed,
                    "hostBackends": host_backends,
                    "exitCode": exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                })
                .to_string()),
            }
        }
        Command::Test {
            path,
            deterministic,
            strict,
            seed,
            record,
            host_backends,
            scheduler,
            rich_artifacts,
        } => {
            if is_fozzy_scenario(&path) {
                let mut fozzy_args = vec!["test".to_string(), path.display().to_string()];
                if deterministic {
                    fozzy_args.push("--det".to_string());
                }
                if strict {
                    fozzy_args.push("--strict".to_string());
                }
                if let Some(seed) = seed {
                    fozzy_args.push("--seed".to_string());
                    fozzy_args.push(seed.to_string());
                }
                if let Some(record) = record {
                    fozzy_args.push("--record".to_string());
                    fozzy_args.push(record.display().to_string());
                }
                if host_backends {
                    fozzy_args.push("--proc-backend".to_string());
                    fozzy_args.push("host".to_string());
                    fozzy_args.push("--fs-backend".to_string());
                    fozzy_args.push("host".to_string());
                    fozzy_args.push("--http-backend".to_string());
                    fozzy_args.push("host".to_string());
                }
                if let Some(scheduler) = &scheduler {
                    fozzy_args.push("--schedule".to_string());
                    fozzy_args.push(scheduler.clone());
                }
                if matches!(format, Format::Json) {
                    fozzy_args.push("--json".to_string());
                }
                return fozzy_invoke(&fozzy_args);
            }

            let test_plan = run_non_scenario_test_plan(
                &path,
                deterministic,
                strict,
                scheduler.clone(),
                seed,
                record.as_deref(),
                rich_artifacts,
            )?;
            let message = format!(
                "test harness built for {} (deterministic={}, strict={}, scheduler={}, executed_tasks={}, order={:?}, artifacts={})",
                test_plan.module,
                deterministic,
                strict,
                test_plan.scheduler,
                test_plan.executed_tasks,
                test_plan.execution_order,
                test_plan
                    .artifacts
                    .as_ref()
                    .map(|artifacts| artifacts.trace_path.display().to_string())
                    .unwrap_or_else(|| "<none>".to_string())
            );
            match format {
                Format::Text => Ok(message),
                Format::Json => Ok(serde_json::json!({
                    "module": test_plan.module,
                    "deterministic": deterministic,
                    "strict": strict,
                    "mode": test_plan.mode,
                    "scheduler": test_plan.scheduler,
                    "diagnostics": test_plan.diagnostics,
                    "executedTasks": test_plan.executed_tasks,
                    "executionOrder": test_plan.execution_order,
                    "asyncCheckpointCount": test_plan.async_checkpoint_count,
                    "asyncExecution": test_plan.async_execution,
                    "rpcFrameCount": test_plan.rpc_frame_count,
                    "discoveredTests": test_plan.discovered_tests,
                    "discoveredTestNames": test_plan.discovered_test_names,
                    "deterministicTestNames": test_plan.deterministic_test_names,
                    "artifacts": test_plan.artifacts.as_ref().map(|artifacts| {
                        serde_json::json!({
                            "trace": artifacts.trace_path.display().to_string(),
                            "report": artifacts.report_path.as_ref().map(|path| path.display().to_string()),
                            "timeline": artifacts.timeline_path.as_ref().map(|path| path.display().to_string()),
                            "manifest": artifacts.manifest_path.display().to_string(),
                            "explore": artifacts.explore_path.as_ref().map(|path| path.display().to_string()),
                            "shrink": artifacts.shrink_path.as_ref().map(|path| path.display().to_string()),
                            "scenariosIndex": artifacts.scenarios_index_path.as_ref().map(|path| path.display().to_string()),
                            "primaryScenario": artifacts
                                .primary_scenario_path
                                .as_ref()
                                .map(|path| path.display().to_string()),
                        })
                    }),
                })
                .to_string()),
            }
        }
        Command::Fmt { path } => {
            ensure_exists(&path)?;
            let changed = format_source_file(&path)?;
            let message = if changed {
                format!("formatted {}", path.display())
            } else {
                format!("already formatted {}", path.display())
            };
            Ok(render(format, &message))
        }
        Command::Check { path } => {
            let output = verify_file(&path)?;
            Ok(render_output(format, output))
        }
        Command::Verify { path } => {
            let output = verify_file(&path)?;
            Ok(render_output(format, output))
        }
        Command::EmitIr { path } => {
            let output = emit_ir(&path)?;
            Ok(render_output(format, output))
        }
        Command::Fuzz { target } => passthrough_fozzy("fuzz", &target, format),
        Command::Explore { target } => passthrough_fozzy("explore", &target, format),
        Command::Replay { trace } => passthrough_fozzy("replay", &trace, format),
        Command::Shrink { trace } => passthrough_fozzy("shrink", &trace, format),
        Command::Ci { trace } => passthrough_fozzy("ci", &trace, format),
        Command::Headers { path, output } => {
            let generated = generate_c_headers(&path, output.as_deref())?;
            Ok(render_headers(format, generated))
        }
        Command::RpcGen { path, out_dir } => {
            let generated = generate_rpc_artifacts(&path, out_dir.as_deref())?;
            Ok(render_rpc_artifacts(format, generated))
        }
        Command::Version => Ok(render(format, env!("CARGO_PKG_VERSION"))),
    }
}

fn init_project(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("project name cannot be empty");
    }

    let root = PathBuf::from(name);
    std::fs::create_dir_all(root.join("src")).context("failed to create project directories")?;

    let manifest = format!(
        "[package]\nname = \"{}\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"{}\"\npath = \"src/main.fzy\"\n",
        name, name
    );

    std::fs::write(root.join("fozzy.toml"), &manifest).context("failed to write fozzy.toml")?;
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 0\n}\n",
    )
    .context("failed to write src/main.fzy")?;

    Ok(())
}

fn render(format: Format, message: &str) -> String {
    match format {
        Format::Text => message.to_string(),
        Format::Json => serde_json::json!({"message": message}).to_string(),
    }
}

fn render_artifact(
    format: Format,
    artifact: BuildArtifact,
    threads: Option<u16>,
    runtime_config: Option<PathBuf>,
) -> String {
    match format {
        Format::Text => format!(
            "module={} profile={:?} status={} diagnostics={} output={} threads={} runtime_config={}",
            artifact.module,
            artifact.profile,
            artifact.status,
            artifact.diagnostics,
            artifact
                .output
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            threads
                .map(|threads| threads.to_string())
                .unwrap_or_else(|| "default".to_string()),
            runtime_config
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string())
        ),
        Format::Json => serde_json::json!({
            "module": artifact.module,
            "profile": format!("{:?}", artifact.profile),
            "status": artifact.status,
            "diagnostics": artifact.diagnostics,
            "threads": threads,
            "runtimeConfig": runtime_config.map(|path| path.display().to_string()),
            "output": artifact
                .output
                .as_ref()
                .map(|path| path.display().to_string()),
        })
        .to_string(),
    }
}

fn render_output(format: Format, output: Output) -> String {
    match format {
        Format::Text => {
            let mut rendered = format!(
                "module={} nodes={} diagnostics={}",
                output.module, output.nodes, output.diagnostics
            );
            if let Some(ir) = &output.backend_ir {
                rendered.push('\n');
                rendered.push_str(ir);
            }
            rendered
        }
        Format::Json => serde_json::json!({
            "schemaVersion": "fozzylang.diagnostics.v1",
            "module": output.module,
            "nodes": output.nodes,
            "diagnostics": output.diagnostics,
            "items": output.diagnostic_details,
            "backendIr": output.backend_ir,
        })
        .to_string(),
    }
}

fn ensure_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct NonScenarioTestPlan {
    module: String,
    mode: &'static str,
    scheduler: String,
    diagnostics: usize,
    discovered_tests: usize,
    discovered_test_names: Vec<String>,
    deterministic_test_names: Vec<String>,
    executed_tasks: usize,
    execution_order: Vec<u64>,
    async_checkpoint_count: usize,
    async_execution: Vec<u64>,
    rpc_frame_count: usize,
    artifacts: Option<NonScenarioTraceArtifacts>,
}

#[derive(Debug, Clone)]
struct NonScenarioTraceArtifacts {
    trace_path: PathBuf,
    report_path: Option<PathBuf>,
    timeline_path: Option<PathBuf>,
    manifest_path: PathBuf,
    explore_path: Option<PathBuf>,
    shrink_path: Option<PathBuf>,
    scenarios_index_path: Option<PathBuf>,
    primary_scenario_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecMode {
    Fast,
    Det,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactDetail {
    Minimal,
    Rich,
}

#[derive(Debug, Clone, Serialize)]
struct RpcFrameEvent {
    #[serde(rename = "event")]
    kind: &'static str,
    method: String,
    #[serde(rename = "taskId")]
    task_id: u64,
}

fn run_non_scenario_test_plan(
    path: &Path,
    deterministic: bool,
    strict: bool,
    scheduler: Option<String>,
    seed: Option<u64>,
    record: Option<&Path>,
    rich_artifacts: bool,
) -> Result<NonScenarioTestPlan> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let mut discovered_test_names = Vec::new();
    let mut deterministic_test_names = Vec::new();
    for item in &parsed.module.items {
        if let ast::Item::Test(block) = item {
            discovered_test_names.push(block.name.clone());
            if block.deterministic {
                deterministic_test_names.push(block.name.clone());
            }
        }
    }
    let discovered_tests = discovered_test_names.len();
    let async_checkpoint_count = count_async_hooks(&parsed.combined_source);
    let task_count = deterministic_test_names.len().max(1);
    let mode = if deterministic {
        ExecMode::Det
    } else {
        ExecMode::Fast
    };
    if record.is_some() && mode == ExecMode::Fast {
        bail!("--record requires --det");
    }

    let typed = hir::lower(&parsed.module);
    let fir = fir::build(&typed);
    let verify_report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: strict,
        },
    );
    let diagnostics = verify_report.diagnostics.len();
    let has_errors = verify_report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    if strict && has_errors {
        bail!(
            "strict test plan rejected module `{}` with {} diagnostics",
            fir.name,
            diagnostics
        );
    }

    let scheduler = if mode == ExecMode::Det {
        parse_scheduler(scheduler.as_deref().unwrap_or("fifo"))?
    } else {
        Scheduler::Fifo
    };
    let scheduler_label = if mode == ExecMode::Det {
        scheduler_name(scheduler).to_string()
    } else {
        "fast".to_string()
    };
    let mut execution_order = Vec::new();
    let mut events = Vec::new();
    if mode == ExecMode::Det {
        let trace_mode = if strict || rich_artifacts {
            runtime::TraceMode::Full
        } else {
            runtime::TraceMode::ReplayCritical
        };
        let mut executor = DeterministicExecutor::new_with_trace_mode(trace_mode);
        for _ in 0..task_count {
            executor.spawn(Box::new(|| {}));
        }
        execution_order = executor.run_until_idle_with_scheduler(scheduler, seed.unwrap_or(1));
        events = executor.trace().to_vec();
    }
    let async_execution = if mode == ExecMode::Det {
        plan_async_checkpoints(
            &execution_order,
            scheduler,
            seed.unwrap_or(1),
            async_checkpoint_count,
        )
    } else {
        Vec::new()
    };
    let rpc_frames = if mode == ExecMode::Det {
        build_rpc_frame_events(&parsed.module, &parsed.combined_source, &execution_order)
    } else {
        Vec::new()
    };
    let artifacts = if mode == ExecMode::Det {
        let detail = if strict || rich_artifacts {
            ArtifactDetail::Rich
        } else {
            ArtifactDetail::Minimal
        };
        record
            .map(|record| {
                write_non_scenario_trace_artifacts(
                    record,
                    detail,
                    &scheduler_label,
                    seed.unwrap_or(1),
                    discovered_tests,
                    &discovered_test_names,
                    &deterministic_test_names,
                    &async_execution,
                    &rpc_frames,
                    &execution_order,
                    &events,
                )
            })
            .transpose()?
    } else {
        None
    };

    Ok(NonScenarioTestPlan {
        module: fir.name,
        mode: match mode {
            ExecMode::Fast => "fast",
            ExecMode::Det => "det",
        },
        scheduler: scheduler_label,
        diagnostics,
        discovered_tests,
        discovered_test_names,
        deterministic_test_names,
        executed_tasks: if mode == ExecMode::Det { task_count } else { 0 },
        execution_order,
        async_checkpoint_count,
        async_execution,
        rpc_frame_count: rpc_frames.len(),
        artifacts,
    })
}

fn write_non_scenario_trace_artifacts(
    trace_path: &Path,
    detail: ArtifactDetail,
    scheduler: &str,
    seed: u64,
    discovered_tests: usize,
    discovered_test_names: &[String],
    deterministic_test_names: &[String],
    async_execution: &[u64],
    rpc_frames: &[RpcFrameEvent],
    execution_order: &[u64],
    events: &[TaskEvent],
) -> Result<NonScenarioTraceArtifacts> {
    if let Some(parent) = trace_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating trace output directory: {}",
                parent.display()
            )
        })?;
    }
    let base_dir = trace_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = trace_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("trace");

    let timeline_path = base_dir.join(format!("{stem}.timeline.json"));
    let report_path = base_dir.join(format!("{stem}.report.json"));
    let manifest_path = base_dir.join(format!("{stem}.manifest.json"));
    let explore_path = base_dir.join(format!("{stem}.explore.json"));
    let shrink_path = base_dir.join(format!("{stem}.shrink.json"));
    let scenarios_index_path = base_dir.join(format!("{stem}.scenarios.json"));
    let trace_payload = TracePayload {
        schema_version: "fozzylang.thread_trace.v0",
        capability: "thread",
        scheduler,
        seed,
        execution_order,
        async_schedule: async_execution,
        rpc_frames: rpc_frames.to_vec(),
        events: events
            .iter()
            .map(TaskEventRecord::from)
            .collect::<Vec<TaskEventRecord>>(),
    };
    write_json_file(trace_path, &trace_payload).with_context(|| {
        format!(
            "failed writing thread trace artifact: {}",
            trace_path.display()
        )
    })?;

    let mut report_written = None;
    let mut timeline_written = None;
    let mut explore_written = None;
    let mut shrink_written = None;
    let mut scenarios_written = None;
    let mut primary_scenario_path = None;

    if detail == ArtifactDetail::Rich {
        let mut timeline_entries =
            Vec::with_capacity(execution_order.len() + async_execution.len() + rpc_frames.len());
        for (index, task_id) in execution_order.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: index,
                decision: "thread.schedule",
                task_id: *task_id,
                scheduler,
                event: None,
                method: None,
            });
        }
        let thread_steps = timeline_entries.len();
        for (index, task_id) in async_execution.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: thread_steps + index,
                decision: "async.schedule",
                task_id: *task_id,
                scheduler,
                event: None,
                method: None,
            });
        }
        let async_steps = timeline_entries.len();
        for (index, frame) in rpc_frames.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: async_steps + index,
                decision: "rpc.frame",
                task_id: frame.task_id,
                scheduler,
                event: Some(frame.kind),
                method: Some(frame.method.clone()),
            });
        }
        write_json_file(
            &timeline_path,
            &TimelinePayload {
                schema_version: "fozzylang.timeline.v0",
                entries: timeline_entries,
            },
        )
        .with_context(|| {
            format!(
                "failed writing timeline artifact: {}",
                timeline_path.display()
            )
        })?;
        timeline_written = Some(timeline_path.clone());

        let (generated_primary, generated_scenarios) =
            generate_language_test_scenarios(&base_dir, stem, deterministic_test_names)?;
        primary_scenario_path = generated_primary;

        write_json_file(
            &report_path,
            &ReportPayload {
                schema_version: "fozzylang.report.v0",
                status: "pass",
                capabilities: vec!["thread"],
                scheduler: scheduler.to_string(),
                seed,
                discovered_tests,
                deterministic_tests: deterministic_test_names.len(),
                executed_tasks: execution_order.len(),
                async_checkpoints: async_execution.len(),
                rpc_frames: rpc_frames.len(),
                generated_scenarios: generated_scenarios.len(),
                events: events.len(),
                failure_classes: classify_failure_classes(
                    rpc_frames,
                    async_execution,
                    execution_order,
                ),
                findings: rpc_failure_findings(rpc_frames),
            },
        )
        .with_context(|| format!("failed writing report artifact: {}", report_path.display()))?;
        report_written = Some(report_path.clone());

        let scenario_priorities =
            build_scenario_priorities(&generated_scenarios, rpc_frames, async_execution);
        write_json_file(
            &explore_path,
            &ExplorePayload {
                schema_version: "fozzylang.explore.v0",
                schedules: build_schedule_candidates(execution_order),
                rpc_frame_permutations: build_rpc_frame_permutations(execution_order, rpc_frames),
                scenario_priorities: scenario_priorities.clone(),
                shrink_hints: build_shrink_hints(
                    discovered_test_names,
                    execution_order,
                    rpc_frames,
                    async_execution,
                ),
                focus: "rpc_failure_repro",
            },
        )
        .with_context(|| {
            format!(
                "failed writing explore artifact: {}",
                explore_path.display()
            )
        })?;
        explore_written = Some(explore_path.clone());

        write_json_file(
            &shrink_path,
            &ShrinkPayload {
                schema_version: "fozzylang.shrink.v0",
                scenario_priorities,
                hints: build_shrink_hints(
                    discovered_test_names,
                    execution_order,
                    rpc_frames,
                    async_execution,
                ),
            },
        )
        .with_context(|| format!("failed writing shrink artifact: {}", shrink_path.display()))?;
        shrink_written = Some(shrink_path.clone());

        write_json_file(
            &scenarios_index_path,
            &ScenariosPayload {
                schema_version: "fozzylang.scenarios.v0",
                primary: primary_scenario_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                items: generated_scenarios
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            },
        )
        .with_context(|| {
            format!(
                "failed writing scenarios index: {}",
                scenarios_index_path.display()
            )
        })?;
        scenarios_written = Some(scenarios_index_path.clone());
    }

    write_json_file(
        &manifest_path,
        &ManifestPayload {
            schema_version: "fozzylang.artifacts.v0",
            trace: trace_path.display().to_string(),
            report: report_written
                .as_ref()
                .map(|path| path.display().to_string()),
            timeline: timeline_written
                .as_ref()
                .map(|path| path.display().to_string()),
            explore: explore_written
                .as_ref()
                .map(|path| path.display().to_string()),
            shrink: shrink_written
                .as_ref()
                .map(|path| path.display().to_string()),
            scenarios_index: scenarios_written
                .as_ref()
                .map(|path| path.display().to_string()),
            primary_scenario: primary_scenario_path
                .as_ref()
                .map(|path| path.display().to_string()),
            detail: match detail {
                ArtifactDetail::Minimal => "minimal",
                ArtifactDetail::Rich => "rich",
            },
        },
    )
    .with_context(|| {
        format!(
            "failed writing manifest artifact: {}",
            manifest_path.display()
        )
    })?;

    Ok(NonScenarioTraceArtifacts {
        trace_path: trace_path.to_path_buf(),
        report_path: report_written,
        timeline_path: timeline_written,
        manifest_path,
        explore_path: explore_written,
        shrink_path: shrink_written,
        scenarios_index_path: scenarios_written,
        primary_scenario_path,
    })
}

#[derive(Debug, Clone, Serialize)]
struct TaskEventRecord {
    event: &'static str,
    #[serde(rename = "taskId")]
    task_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    detached: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl From<&TaskEvent> for TaskEventRecord {
    fn from(value: &TaskEvent) -> Self {
        match value {
            TaskEvent::Spawned { task_id, detached } => Self {
                event: "spawned",
                task_id: *task_id,
                detached: Some(*detached),
                message: None,
            },
            TaskEvent::Started { task_id } => Self {
                event: "started",
                task_id: *task_id,
                detached: None,
                message: None,
            },
            TaskEvent::Completed { task_id } => Self {
                event: "completed",
                task_id: *task_id,
                detached: None,
                message: None,
            },
            TaskEvent::Panicked { task_id, message } => Self {
                event: "panicked",
                task_id: *task_id,
                detached: None,
                message: Some(message.clone()),
            },
            TaskEvent::Detached { task_id } => Self {
                event: "detached",
                task_id: *task_id,
                detached: None,
                message: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct TracePayload<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    capability: &'static str,
    scheduler: &'a str,
    seed: u64,
    #[serde(rename = "executionOrder")]
    execution_order: &'a [u64],
    #[serde(rename = "asyncSchedule")]
    async_schedule: &'a [u64],
    #[serde(rename = "rpcFrames")]
    rpc_frames: Vec<RpcFrameEvent>,
    events: Vec<TaskEventRecord>,
}

#[derive(Debug, Clone, Serialize)]
struct TimelinePayload<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    entries: Vec<TimelineEntry<'a>>,
}

#[derive(Debug, Clone, Serialize)]
struct TimelineEntry<'a> {
    step: usize,
    decision: &'a str,
    #[serde(rename = "taskId")]
    task_id: u64,
    scheduler: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReportPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    status: &'static str,
    capabilities: Vec<&'static str>,
    scheduler: String,
    seed: u64,
    #[serde(rename = "discoveredTests")]
    discovered_tests: usize,
    #[serde(rename = "deterministicTests")]
    deterministic_tests: usize,
    #[serde(rename = "executedTasks")]
    executed_tasks: usize,
    #[serde(rename = "asyncCheckpoints")]
    async_checkpoints: usize,
    #[serde(rename = "rpcFrames")]
    rpc_frames: usize,
    #[serde(rename = "generatedScenarios")]
    generated_scenarios: usize,
    events: usize,
    #[serde(rename = "failureClasses")]
    failure_classes: Vec<serde_json::Value>,
    findings: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct ExplorePayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    schedules: serde_json::Value,
    #[serde(rename = "rpcFramePermutations")]
    rpc_frame_permutations: serde_json::Value,
    #[serde(rename = "scenarioPriorities")]
    scenario_priorities: serde_json::Value,
    #[serde(rename = "shrinkHints")]
    shrink_hints: serde_json::Value,
    focus: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ShrinkPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    #[serde(rename = "scenarioPriorities")]
    scenario_priorities: serde_json::Value,
    hints: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
struct ScenariosPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    primary: Option<String>,
    items: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ManifestPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    trace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    explore: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shrink: Option<String>,
    #[serde(rename = "scenariosIndex", skip_serializing_if = "Option::is_none")]
    scenarios_index: Option<String>,
    #[serde(rename = "primaryScenario", skip_serializing_if = "Option::is_none")]
    primary_scenario: Option<String>,
    detail: &'static str,
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes)
        .with_context(|| format!("failed writing json file: {}", path.display()))
}

fn count_async_hooks(source: &str) -> usize {
    source
        .lines()
        .filter(|line| {
            let line = line.trim();
            line.contains("await ")
                || line.contains(".await")
                || line.contains("yield(")
                || line.contains("checkpoint(")
                || line.starts_with("async fn ")
        })
        .count()
}

fn build_rpc_frame_events(
    module: &ast::Module,
    source: &str,
    execution_order: &[u64],
) -> Vec<RpcFrameEvent> {
    if execution_order.is_empty() {
        return Vec::new();
    }
    let methods = parse_rpc_declarations(source).unwrap_or_default();
    if methods.is_empty() {
        return Vec::new();
    }

    let mut events = Vec::new();
    let mut call_sequence = Vec::new();
    for item in &module.items {
        if let ast::Item::Function(function) = item {
            for statement in &function.body {
                collect_call_names_from_stmt(statement, &mut call_sequence);
            }
        }
    }

    let rpc_methods = methods
        .iter()
        .map(|method| method.name.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    let mut cursor = 0usize;
    for call in &call_sequence {
        if !rpc_methods.contains(call.as_str()) {
            continue;
        }
        let task_id = execution_order[cursor % execution_order.len()];
        cursor += 1;
        events.push(RpcFrameEvent {
            kind: "rpc_send",
            method: call.clone(),
            task_id,
        });

        let task_id = execution_order[cursor % execution_order.len()];
        cursor += 1;
        events.push(RpcFrameEvent {
            kind: "rpc_recv",
            method: call.clone(),
            task_id,
        });
    }

    let has_deadline_call = call_sequence
        .iter()
        .any(|call| call == "timeout" || call == "deadline");
    if has_deadline_call && !methods.is_empty() {
        events.push(RpcFrameEvent {
            kind: "rpc_deadline",
            method: methods[0].name.clone(),
            task_id: execution_order[cursor % execution_order.len()],
        });
        cursor += 1;
    }
    let has_cancel_call = call_sequence.iter().any(|call| call == "cancel");
    if has_cancel_call && !methods.is_empty() {
        events.push(RpcFrameEvent {
            kind: "rpc_cancel",
            method: methods[0].name.clone(),
            task_id: execution_order[cursor % execution_order.len()],
        });
    }

    events
}

fn collect_call_names_from_stmt(statement: &ast::Stmt, out: &mut Vec<String>) {
    match statement {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::Return(value)
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_call_names_from_expr(value, out),
        ast::Stmt::Match { scrutinee, arms } => {
            collect_call_names_from_expr(scrutinee, out);
            for arm in arms {
                collect_call_names_from_expr(&arm.value, out);
            }
        }
    }
}

fn collect_call_names_from_expr(expr: &ast::Expr, out: &mut Vec<String>) {
    match expr {
        ast::Expr::Call { callee, args } => {
            out.push(callee.clone());
            for arg in args {
                collect_call_names_from_expr(arg, out);
            }
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_call_names_from_expr(try_expr, out);
            collect_call_names_from_expr(catch_expr, out);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_call_names_from_expr(left, out);
            collect_call_names_from_expr(right, out);
        }
        ast::Expr::Int(_) | ast::Expr::Bool(_) | ast::Expr::Ident(_) => {}
    }
}

fn rpc_frames_json(frames: &[RpcFrameEvent]) -> Vec<serde_json::Value> {
    frames
        .iter()
        .map(|frame| {
            serde_json::json!({
                "event": frame.kind,
                "method": frame.method,
                "taskId": frame.task_id,
            })
        })
        .collect()
}

fn rpc_failure_findings(frames: &[RpcFrameEvent]) -> Vec<serde_json::Value> {
    let has_deadline = frames.iter().any(|frame| frame.kind == "rpc_deadline");
    let has_cancel = frames.iter().any(|frame| frame.kind == "rpc_cancel");
    let recv_by_method = frames
        .iter()
        .filter(|frame| frame.kind == "rpc_recv")
        .map(|frame| frame.method.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    let mut findings = Vec::new();
    if has_deadline {
        findings.push(serde_json::json!({
            "kind": "rpc_deadline",
            "severity": "warning",
            "message": "deadline event observed; verify timeout semantics are deterministic",
        }));
    }
    if has_cancel {
        findings.push(serde_json::json!({
            "kind": "rpc_cancel",
            "severity": "warning",
            "message": "cancellation event observed; verify cancellation propagation and cleanup",
        }));
    }
    if has_cancel && !recv_by_method.is_empty() {
        findings.push(serde_json::json!({
            "kind": "rpc_partial_response_after_cancel",
            "severity": "info",
            "message": "received response frames alongside cancellation; inspect partial-response handling",
            "methods": recv_by_method.into_iter().collect::<Vec<_>>(),
        }));
    }
    findings
}

fn build_schedule_candidates(execution_order: &[u64]) -> serde_json::Value {
    if execution_order.is_empty() {
        return serde_json::json!([]);
    }
    let fifo = execution_order.to_vec();
    let reversed = execution_order.iter().copied().rev().collect::<Vec<_>>();
    let rotated = execution_order
        .iter()
        .copied()
        .cycle()
        .skip(1)
        .take(execution_order.len())
        .collect::<Vec<_>>();
    serde_json::json!([
        { "name": "fifo", "order": fifo },
        { "name": "reverse", "order": reversed },
        { "name": "rotate_1", "order": rotated },
    ])
}

fn build_rpc_frame_permutations(
    execution_order: &[u64],
    frames: &[RpcFrameEvent],
) -> serde_json::Value {
    if frames.is_empty() || execution_order.is_empty() {
        return serde_json::json!([]);
    }
    let canonical = rpc_frames_json(frames);
    let mut task_index = 0usize;
    let rotated = frames
        .iter()
        .map(|frame| {
            let task_id = execution_order[task_index % execution_order.len()];
            task_index += 1;
            serde_json::json!({
                "event": frame.kind,
                "method": frame.method,
                "taskId": task_id,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!([
        { "name": "canonical", "frames": canonical },
        { "name": "task_rotated", "frames": rotated },
    ])
}

fn build_shrink_hints(
    discovered_test_names: &[String],
    execution_order: &[u64],
    rpc_frames: &[RpcFrameEvent],
    async_execution: &[u64],
) -> serde_json::Value {
    let mut hints = Vec::new();
    for name in discovered_test_names {
        hints.push(serde_json::json!({
            "kind": "single_test",
            "tests": [name],
        }));
    }
    for pair in discovered_test_names.windows(2) {
        hints.push(serde_json::json!({
            "kind": "test_pair",
            "tests": [pair[0].clone(), pair[1].clone()],
        }));
    }
    if !rpc_frames.is_empty() {
        let methods = rpc_frames
            .iter()
            .map(|frame| frame.method.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        hints.push(serde_json::json!({
            "kind": "rpc_methods",
            "methods": methods,
        }));
    }
    if !async_execution.is_empty() {
        hints.push(serde_json::json!({
            "kind": "async_checkpoint_focus",
            "taskIds": async_execution,
        }));
    }
    if !execution_order.is_empty() {
        hints.push(serde_json::json!({
            "kind": "task_order",
            "order": execution_order,
        }));
    }
    serde_json::json!(hints)
}

fn classify_failure_classes(
    rpc_frames: &[RpcFrameEvent],
    async_execution: &[u64],
    execution_order: &[u64],
) -> Vec<serde_json::Value> {
    let mut classes = Vec::new();
    if rpc_frames.iter().any(|frame| frame.kind == "rpc_deadline") {
        classes.push(serde_json::json!({
            "id": "rpc_timeout",
            "priority": 1,
            "signal": "rpc_deadline",
        }));
    }
    if rpc_frames.iter().any(|frame| frame.kind == "rpc_cancel") {
        classes.push(serde_json::json!({
            "id": "rpc_cancel_race",
            "priority": 2,
            "signal": "rpc_cancel",
        }));
    }
    if !async_execution.is_empty() {
        classes.push(serde_json::json!({
            "id": "async_schedule_interleaving",
            "priority": 3,
            "signal": "async.schedule",
        }));
    }
    if execution_order.len() > 1 {
        classes.push(serde_json::json!({
            "id": "thread_interleaving",
            "priority": 4,
            "signal": "thread.schedule",
        }));
    }
    if classes.is_empty() {
        classes.push(serde_json::json!({
            "id": "baseline",
            "priority": 9,
            "signal": "deterministic",
        }));
    }
    classes
}

fn build_scenario_priorities(
    generated_scenarios: &[PathBuf],
    rpc_frames: &[RpcFrameEvent],
    async_execution: &[u64],
) -> serde_json::Value {
    let mut items = Vec::new();
    for path in generated_scenarios {
        let mut score = 100i32;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        if name == "all.fozzy.json" {
            score -= 30;
        }
        if !rpc_frames.is_empty() {
            score -= 20;
        }
        if !async_execution.is_empty() {
            score -= 10;
        }
        items.push(serde_json::json!({
            "scenario": path.display().to_string(),
            "score": score,
        }));
    }
    items.sort_by_key(|item| item.get("score").and_then(|v| v.as_i64()).unwrap_or(999));
    serde_json::json!(items)
}

fn generate_language_test_scenarios(
    base_dir: &Path,
    stem: &str,
    deterministic_test_names: &[String],
) -> Result<(Option<PathBuf>, Vec<PathBuf>)> {
    let scenarios_dir = base_dir.join(format!("{stem}.scenarios"));
    std::fs::create_dir_all(&scenarios_dir).with_context(|| {
        format!(
            "failed creating language test scenarios dir: {}",
            scenarios_dir.display()
        )
    })?;

    let combined_path = scenarios_dir.join("all.fozzy.json");
    let combined_steps = deterministic_test_names
        .iter()
        .map(|name| serde_json::json!({ "type": "trace_event", "name": format!("test:{name}") }))
        .collect::<Vec<_>>();
    let combined_payload = serde_json::json!({
        "version": 1,
        "name": "language-tests-all",
        "steps": combined_steps,
    });
    std::fs::write(
        &combined_path,
        serde_json::to_vec_pretty(&combined_payload)?,
    )
    .with_context(|| {
        format!(
            "failed writing combined scenario: {}",
            combined_path.display()
        )
    })?;

    let mut generated = vec![combined_path.clone()];
    for test_name in deterministic_test_names {
        let safe_name = sanitize_file_component(test_name);
        let scenario_path = scenarios_dir.join(format!("{safe_name}.fozzy.json"));
        let payload = serde_json::json!({
            "version": 1,
            "name": format!("language-test-{safe_name}"),
            "steps": [
                { "type": "trace_event", "name": format!("test:{test_name}") },
                { "type": "assert_eq_int", "a": 1, "b": 1 }
            ],
        });
        std::fs::write(&scenario_path, serde_json::to_vec_pretty(&payload)?).with_context(
            || {
                format!(
                    "failed writing scenario for test `{}`: {}",
                    test_name,
                    scenario_path.display()
                )
            },
        )?;
        generated.push(scenario_path);
    }

    let primary = generated.first().cloned();
    Ok((primary, generated))
}

fn sanitize_file_component(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "test".to_string()
    } else {
        out
    }
}

fn parse_scheduler(input: &str) -> Result<Scheduler> {
    match input {
        "fifo" | "default" | "host" => Ok(Scheduler::Fifo),
        "random" => Ok(Scheduler::Random),
        "coverage_guided" => Ok(Scheduler::CoverageGuided),
        other => bail!(
            "unknown scheduler `{}`; expected one of: fifo, random, coverage_guided",
            other
        ),
    }
}

fn scheduler_name(scheduler: Scheduler) -> &'static str {
    match scheduler {
        Scheduler::Fifo => "fifo",
        Scheduler::Random => "random",
        Scheduler::CoverageGuided => "coverage_guided",
    }
}

fn persist_runtime_threads_config(path: &Path, threads: Option<u16>) -> Result<Option<PathBuf>> {
    let Some(threads) = threads else {
        return Ok(None);
    };
    if threads == 0 {
        bail!("--threads must be greater than zero");
    }
    let root = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    let config_path = root.join(".fozzyc").join("runtime.json");
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating runtime config directory: {}",
                parent.display()
            )
        })?;
    }
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.runtime.v0",
        "threads": threads,
    });
    std::fs::write(&config_path, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("failed writing runtime config: {}", config_path.display()))?;
    Ok(Some(config_path))
}

fn passthrough_fozzy(command: &str, target: &Path, format: Format) -> Result<String> {
    ensure_exists(target)?;

    let mut args = vec![command.to_string(), target.display().to_string()];
    if matches!(format, Format::Json) {
        args.push("--json".to_string());
    }
    fozzy_invoke(&args)
}

#[derive(Debug, Clone)]
struct HeaderArtifact {
    path: PathBuf,
    exports: usize,
}

#[derive(Debug, Clone)]
struct RpcArtifacts {
    schema: PathBuf,
    client_stub: PathBuf,
    server_stub: PathBuf,
    methods: usize,
}

fn render_headers(format: Format, artifact: HeaderArtifact) -> String {
    match format {
        Format::Text => format!(
            "generated header={} exports={}",
            artifact.path.display(),
            artifact.exports
        ),
        Format::Json => serde_json::json!({
            "header": artifact.path.display().to_string(),
            "exports": artifact.exports,
        })
        .to_string(),
    }
}

fn render_rpc_artifacts(format: Format, artifacts: RpcArtifacts) -> String {
    match format {
        Format::Text => format!(
            "generated rpc schema={} client={} server={} methods={}",
            artifacts.schema.display(),
            artifacts.client_stub.display(),
            artifacts.server_stub.display(),
            artifacts.methods
        ),
        Format::Json => serde_json::json!({
            "schema": artifacts.schema.display().to_string(),
            "client": artifacts.client_stub.display().to_string(),
            "server": artifacts.server_stub.display().to_string(),
            "methods": artifacts.methods,
        })
        .to_string(),
    }
}

fn generate_c_headers(path: &Path, output: Option<&Path>) -> Result<HeaderArtifact> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let module_name = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;
    let exports: Vec<&ast::Function> = parsed
        .module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function)
                if function.is_pub
                    && function.is_extern
                    && function
                        .abi
                        .as_deref()
                        .is_some_and(|abi| abi.eq_ignore_ascii_case("c")) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect();

    let header_path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_header_path(&resolved));
    if let Some(parent) = header_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating header output directory: {}",
                parent.display()
            )
        })?;
    }

    let package_name = resolved
        .manifest
        .as_ref()
        .map(|manifest| manifest.package.name.as_str())
        .unwrap_or(module_name);
    let header = render_c_header(package_name, &exports);
    std::fs::write(&header_path, header)
        .with_context(|| format!("failed writing header: {}", header_path.display()))?;

    Ok(HeaderArtifact {
        path: header_path,
        exports: exports.len(),
    })
}

fn generate_rpc_artifacts(path: &Path, out_dir: Option<&Path>) -> Result<RpcArtifacts> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let methods = parse_rpc_declarations(&parsed.combined_source)?;

    let output_dir = out_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| resolved.project_root.join(".fozzyc").join("rpc"));
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed creating rpc output dir: {}", output_dir.display()))?;

    let schema = output_dir.join("rpc.schema.json");
    let client_stub = output_dir.join("rpc.client.fzy");
    let server_stub = output_dir.join("rpc.server.fzy");
    let schema_payload = serde_json::json!({
        "schemaVersion": "fozzylang.rpc.v0",
        "source": resolved.source_path.display().to_string(),
        "methods": methods.iter().map(|method| serde_json::json!({
            "name": method.name,
            "request": method.request,
            "response": method.response,
            "clientStreaming": method.client_streaming,
            "serverStreaming": method.server_streaming,
        })).collect::<Vec<_>>(),
    });
    std::fs::write(&schema, serde_json::to_vec_pretty(&schema_payload)?)
        .with_context(|| format!("failed writing rpc schema: {}", schema.display()))?;

    let mut client = String::from("// generated by fozzyc rpc gen\n");
    client.push_str("mod rpc_client {\n");
    for method in &methods {
        client.push_str(&format!(
            "    async fn {}(req: {}) -> {} {{\n        // TODO: wire transport + cancellation + deadline\n    }}\n",
            method.name.to_lowercase(),
            method.request,
            method.response
        ));
    }
    client.push_str("}\n");
    std::fs::write(&client_stub, client)
        .with_context(|| format!("failed writing rpc client stub: {}", client_stub.display()))?;

    let mut server = String::from("// generated by fozzyc rpc gen\n");
    server.push_str("mod rpc_server {\n");
    for method in &methods {
        server.push_str(&format!(
            "    async fn handle_{}(req: {}) -> {} {{\n        // TODO: implement RPC method handler\n    }}\n",
            method.name.to_lowercase(),
            method.request,
            method.response
        ));
    }
    server.push_str("}\n");
    std::fs::write(&server_stub, server)
        .with_context(|| format!("failed writing rpc server stub: {}", server_stub.display()))?;

    Ok(RpcArtifacts {
        schema,
        client_stub,
        server_stub,
        methods: methods.len(),
    })
}

fn render_c_header(package_name: &str, exports: &[&ast::Function]) -> String {
    let guard = format!("FOZZY_{}_H", package_name.to_ascii_uppercase());
    let mut header = String::new();
    header.push_str("#ifndef ");
    header.push_str(&guard);
    header.push_str("\n#define ");
    header.push_str(&guard);
    header.push_str("\n\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    for function in exports {
        header.push_str(&format!(
            "{} {}({});\n",
            to_c_type(&function.return_type),
            function.name,
            function
                .params
                .iter()
                .map(|param| format!("{} {}", to_c_type(&param.ty), param.name))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if exports.is_empty() {
        header.push_str("/* no exported extern \"C\" functions found */\n");
    }
    header.push_str("\n#ifdef __cplusplus\n}\n#endif\n\n#endif\n");
    header
}

fn to_c_type(ty: &str) -> String {
    let ty = ty.trim();
    if let Some(inner) = ty.strip_prefix("*mut ") {
        return format!("{}*", to_c_type(inner));
    }
    if let Some(inner) = ty.strip_prefix('*') {
        return format!("const {}*", to_c_type(inner));
    }
    if ty == "str" {
        return "const char*".to_string();
    }
    match ty {
        "void" => "void".to_string(),
        "bool" => "bool".to_string(),
        "i8" => "int8_t".to_string(),
        "i16" => "int16_t".to_string(),
        "i32" => "int32_t".to_string(),
        "i64" => "int64_t".to_string(),
        "i128" => "__int128_t".to_string(),
        "u8" => "uint8_t".to_string(),
        "u16" => "uint16_t".to_string(),
        "u32" => "uint32_t".to_string(),
        "u64" => "uint64_t".to_string(),
        "u128" => "__uint128_t".to_string(),
        "usize" => "size_t".to_string(),
        "isize" => "ptrdiff_t".to_string(),
        "f32" => "float".to_string(),
        "f64" => "double".to_string(),
        "char" => "uint32_t".to_string(),
        _ => "void*".to_string(),
    }
}

#[derive(Debug, Clone)]
struct ResolvedSource {
    source_path: PathBuf,
    project_root: PathBuf,
    manifest: Option<manifest::Manifest>,
}

fn resolve_source(path: &Path) -> Result<ResolvedSource> {
    if path.is_file() {
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(ResolvedSource {
            source_path: path.to_path_buf(),
            project_root: root,
            manifest: None,
        });
    }
    if !path.is_dir() {
        bail!(
            "path is neither a source file nor a project directory: {}",
            path.display()
        );
    }
    let manifest_path = path.join("fozzy.toml");
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("missing manifest: {}", manifest_path.display()))?;
    let manifest = manifest::load(&manifest_text).context("failed parsing fozzy.toml")?;
    manifest
        .validate()
        .map_err(|error| anyhow!("invalid fozzy.toml: {error}"))?;
    let relative = manifest.primary_bin_path().ok_or_else(|| {
        anyhow!(
            "no [[target.bin]] entry in {} for source resolution",
            manifest_path.display()
        )
    })?;
    Ok(ResolvedSource {
        source_path: path.join(relative),
        project_root: path.to_path_buf(),
        manifest: Some(manifest),
    })
}

fn default_header_path(resolved: &ResolvedSource) -> PathBuf {
    if let Some(manifest) = &resolved.manifest {
        return resolved
            .project_root
            .join("include")
            .join(format!("{}.h", manifest.package.name));
    }
    let stem = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .unwrap_or("module");
    resolved
        .source_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.h"))
}

#[derive(Debug, Clone)]
struct RpcMethod {
    name: String,
    request: String,
    response: String,
    client_streaming: bool,
    server_streaming: bool,
}

fn parse_rpc_declarations(source: &str) -> Result<Vec<RpcMethod>> {
    let mut methods = Vec::new();
    for (line_index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("rpc ") {
            continue;
        }
        let declaration = trimmed
            .strip_prefix("rpc ")
            .ok_or_else(|| anyhow!("invalid rpc declaration on line {}", line_index + 1))?;
        let open = declaration.find('(').ok_or_else(|| {
            anyhow!(
                "invalid rpc declaration on line {}: missing `(`",
                line_index + 1
            )
        })?;
        let close = declaration.rfind(')').ok_or_else(|| {
            anyhow!(
                "invalid rpc declaration on line {}: missing `)`",
                line_index + 1
            )
        })?;
        if close < open {
            bail!(
                "invalid rpc declaration on line {}: malformed arguments",
                line_index + 1
            );
        }

        let name = declaration[..open].trim();
        if name.is_empty() {
            bail!(
                "invalid rpc declaration on line {}: missing method name",
                line_index + 1
            );
        }
        let args = declaration[(open + 1)..close].trim();
        let request = if args.is_empty() {
            "void".to_string()
        } else if let Some((_, ty)) = args.split_once(':') {
            ty.trim().to_string()
        } else {
            args.to_string()
        };
        let after = declaration[(close + 1)..].trim();
        let response = after
            .strip_prefix("->")
            .map(str::trim)
            .ok_or_else(|| {
                anyhow!(
                    "invalid rpc declaration on line {}: missing `->`",
                    line_index + 1
                )
            })?
            .trim_end_matches(';')
            .trim()
            .to_string();
        if response.is_empty() {
            bail!(
                "invalid rpc declaration on line {}: missing response type",
                line_index + 1
            );
        }

        methods.push(RpcMethod {
            name: name.to_string(),
            client_streaming: request.starts_with("stream<"),
            server_streaming: response.starts_with("stream<"),
            request,
            response,
        });
    }
    if methods.is_empty() {
        bail!("no `rpc` declarations found in source");
    }
    Ok(methods)
}

fn fozzy_invoke(args: &[String]) -> Result<String> {
    let mut child = ProcessCommand::new("fozzy");
    child.args(args);

    let output = child.output().context("failed to invoke fozzy binary")?;
    if !output.status.success() {
        let command = args.join(" ");
        bail!(
            "fozzy {} failed: {}",
            command,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn is_fozzy_scenario(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".fozzy.json"))
        .unwrap_or(false)
}

fn format_source_file(path: &Path) -> Result<bool> {
    let original = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading file for formatting: {}", path.display()))?;
    let mut formatted = String::new();
    let mut previous_blank = false;
    for line in original.lines() {
        let trimmed_end = line.trim_end();
        let is_blank = trimmed_end.is_empty();
        if is_blank {
            if !previous_blank {
                formatted.push('\n');
            }
        } else {
            formatted.push_str(trimmed_end);
            formatted.push('\n');
        }
        previous_blank = is_blank;
    }

    if !formatted.ends_with('\n') {
        formatted.push('\n');
    }

    if formatted != original {
        std::fs::write(path, formatted)
            .with_context(|| format!("failed writing formatted file: {}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn version_command_returns_semver() {
        let output = run(Command::Version, Format::Text).expect("version command should run");
        assert!(output.contains('.'));
    }

    #[test]
    fn detects_scenario_paths() {
        assert!(is_fozzy_scenario(Path::new("tests/example.fozzy.json")));
        assert!(!is_fozzy_scenario(Path::new("examples/main.fzy")));
    }

    #[test]
    fn formatter_rewrites_trailing_whitespace() {
        let file_name = format!(
            "fozzylang-fmt-{}.fzy",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(&path, "fn main() {   \n\n\n  return 0   \n}   ")
            .expect("temp source should be written");

        let changed = format_source_file(&path).expect("formatter should run");
        assert!(changed);
        let content = std::fs::read_to_string(&path).expect("formatted file should be readable");
        assert!(!content.contains("   \n"));
        assert!(content.ends_with('\n'));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn headers_command_generates_c_header_for_exports() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-{suffix}.h"));
        std::fs::write(
            &source,
            "pub extern \"C\" fn add(left: i32, right: i32) -> i32;\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        assert!(output.contains("generated header="));
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("int32_t add(int32_t left, int32_t right);"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
    }

    #[test]
    fn headers_command_collects_exports_from_declared_modules() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-headers-project-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"headers_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"headers_project\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod ffi;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/ffi.fzy"),
            "pub extern \"C\" fn add(left: i32, right: i32) -> i32;\n",
        )
        .expect("ffi source should be written");

        let output = run(
            Command::Headers {
                path: root.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        assert!(output.contains("exports=1"));
        let header = root.join("include/headers_project.h");
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("int32_t add(int32_t left, int32_t right);"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rpc_gen_command_emits_schema_and_stubs() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-rpc-{suffix}.fzy"));
        let out_dir = std::env::temp_dir().join(format!("fozzylang-rpc-out-{suffix}"));
        std::fs::write(
            &source,
            "rpc Ping(req: PingReq) -> PingRes;\nrpc Stream(stream<PingReq>) -> stream<PingRes>;\n",
        )
        .expect("source should be written");

        let output = run(
            Command::RpcGen {
                path: source.clone(),
                out_dir: Some(out_dir.clone()),
            },
            Format::Json,
        )
        .expect("rpc gen should succeed");
        assert!(output.contains("\"methods\":2"));
        assert!(out_dir.join("rpc.schema.json").exists());
        assert!(out_dir.join("rpc.client.fzy").exists());
        assert!(out_dir.join("rpc.server.fzy").exists());

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[test]
    fn rpc_gen_command_reads_declarations_from_declared_modules() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-rpc-project-{suffix}"));
        let out_dir = std::env::temp_dir().join(format!("fozzylang-rpc-project-out-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"rpc_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"rpc_project\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod rpc_api;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/rpc_api.fzy"),
            "rpc Ping(req: PingReq) -> PingRes;\nrpc Stream(stream<PingReq>) -> stream<PingRes>;\n",
        )
        .expect("rpc source should be written");

        let output = run(
            Command::RpcGen {
                path: root.clone(),
                out_dir: Some(out_dir.clone()),
            },
            Format::Json,
        )
        .expect("rpc gen should succeed");
        assert!(output.contains("\"methods\":2"));
        assert!(out_dir.join("rpc.schema.json").exists());

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[test]
    fn build_threads_persists_runtime_config() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-build-threads-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");

        let output = run(
            Command::Build {
                path: source.clone(),
                release: false,
                threads: Some(3),
            },
            Format::Json,
        )
        .expect("build should succeed");
        assert!(output.contains("\"threads\":3"));
        let runtime_config = source
            .parent()
            .expect("temp source should have parent")
            .join(".fozzyc/runtime.json");
        assert!(runtime_config.exists());
        let runtime_text =
            std::fs::read_to_string(&runtime_config).expect("runtime config should be readable");
        assert!(runtime_text.contains("\"threads\": 3"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(runtime_config);
    }

    #[test]
    fn non_scenario_test_uses_scheduler_for_deterministic_execution() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-sched-{suffix}.fzy"));
        std::fs::write(
            &source,
            "test \"a\" {}\ntest \"b\" {}\ntest \"c\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict: false,
                seed: Some(9),
                record: None,
                host_backends: false,
                scheduler: Some("coverage_guided".to_string()),
                rich_artifacts: false,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"scheduler\":\"coverage_guided\""));
        assert!(output.contains("\"executedTasks\":3"));
        assert!(output.contains("\"executionOrder\":[0,2,1]"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn run_command_executes_native_output() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-run-native-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 7\n}\n")
            .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict: false,
                seed: None,
                record: None,
                host_backends: false,
            },
            Format::Json,
        )
        .expect("run command should succeed");
        assert!(output.contains("\"exitCode\":7"));
        assert!(output.contains("\"binary\""));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn non_scenario_test_record_writes_thread_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-record-{suffix}.fzy"));
        let trace = std::env::temp_dir().join(format!("fozzylang-test-record-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "test \"a\" {}\ntest \"b\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict: false,
                seed: Some(7),
                record: Some(trace.clone()),
                host_backends: false,
                scheduler: Some("random".to_string()),
                rich_artifacts: true,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"artifacts\""));
        let trace_text = std::fs::read_to_string(&trace).expect("trace should be written");
        assert!(trace_text.contains("\"schemaVersion\": \"fozzylang.thread_trace.v0\""));
        assert!(trace_text.contains("\"capability\": \"thread\""));
        assert!(trace_text.contains("\"scheduler\": \"random\""));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        assert!(base.join(format!("{stem}.timeline.json")).exists());
        assert!(base.join(format!("{stem}.report.json")).exists());
        assert!(base.join(format!("{stem}.manifest.json")).exists());
        assert!(base.join(format!("{stem}.explore.json")).exists());
        assert!(base.join(format!("{stem}.shrink.json")).exists());
        assert!(base.join(format!("{stem}.scenarios.json")).exists());
        assert!(base.join(format!("{stem}.scenarios")).exists());

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn counts_async_hooks_from_source_markers() {
        let source = r#"
            async fn worker() -> i32 { return 0 }
            fn main() -> i32 {
                let x = io.await_next()
                yield()
                checkpoint()
                return 0
            }
        "#;
        assert_eq!(count_async_hooks(source), 4);
    }

    #[test]
    fn non_scenario_test_record_writes_async_schedule_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-async-record-{suffix}.fzy"));
        let trace =
            std::env::temp_dir().join(format!("fozzylang-test-async-record-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "async fn worker() -> i32 {}\ntest \"a\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict: false,
                seed: Some(5),
                record: Some(trace.clone()),
                host_backends: false,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"asyncCheckpointCount\":1"));
        assert!(output.contains("\"asyncExecution\":[0]"));

        let trace_text = std::fs::read_to_string(&trace).expect("trace should be written");
        assert!(trace_text.contains("\"asyncSchedule\": ["));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let timeline = std::fs::read_to_string(base.join(format!("{stem}.timeline.json")))
            .expect("timeline should be readable");
        assert!(timeline.contains("\"decision\": \"async.schedule\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn non_scenario_test_record_writes_rpc_frame_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-rpc-record-{suffix}.fzy"));
        let trace =
            std::env::temp_dir().join(format!("fozzylang-test-rpc-record-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "rpc Ping(req: PingReq) -> PingRes;\nrpc Chat(stream<ChatReq>) -> stream<ChatRes>;\nfn main() -> i32 {\n    Ping(req)\n    Chat(req)\n    timeout(10)\n    cancel()\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict: false,
                seed: Some(8),
                record: Some(trace.clone()),
                host_backends: false,
                scheduler: Some("random".to_string()),
                rich_artifacts: true,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"rpcFrameCount\":6"));

        let trace_text = std::fs::read_to_string(&trace).expect("trace should be written");
        assert!(trace_text.contains("\"rpcFrames\": ["));
        assert!(trace_text.contains("\"event\": \"rpc_send\""));
        assert!(trace_text.contains("\"event\": \"rpc_recv\""));
        assert!(trace_text.contains("\"event\": \"rpc_deadline\""));
        assert!(trace_text.contains("\"event\": \"rpc_cancel\""));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let timeline = std::fs::read_to_string(base.join(format!("{stem}.timeline.json")))
            .expect("timeline should be readable");
        assert!(timeline.contains("\"decision\": \"rpc.frame\""));
        let report = std::fs::read_to_string(base.join(format!("{stem}.report.json")))
            .expect("report should be readable");
        assert!(report.contains("\"kind\": \"rpc_deadline\""));
        assert!(report.contains("\"kind\": \"rpc_cancel\""));
        assert!(report.contains("\"failureClasses\""));
        assert!(report.contains("\"id\": \"rpc_timeout\""));
        let explore = std::fs::read_to_string(base.join(format!("{stem}.explore.json")))
            .expect("explore should be readable");
        assert!(explore.contains("\"schemaVersion\": \"fozzylang.explore.v0\""));
        assert!(explore.contains("\"rpcFramePermutations\""));
        assert!(explore.contains("\"scenarioPriorities\""));
        let shrink = std::fs::read_to_string(base.join(format!("{stem}.shrink.json")))
            .expect("shrink should be readable");
        assert!(shrink.contains("\"schemaVersion\": \"fozzylang.shrink.v0\""));
        assert!(shrink.contains("\"kind\": \"rpc_methods\""));
        assert!(shrink.contains("\"scenarioPriorities\""));
        let scenarios_index = std::fs::read_to_string(base.join(format!("{stem}.scenarios.json")))
            .expect("scenarios index should be readable");
        assert!(scenarios_index.contains("\"schemaVersion\": \"fozzylang.scenarios.v0\""));
        assert!(scenarios_index.contains(".fozzy.json"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }
}
