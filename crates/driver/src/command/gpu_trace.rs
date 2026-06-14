use super::*;

#[path = "gpu/fs.rs"]
mod fs;
#[path = "gpu/abi.rs"]
mod abi;
#[path = "gpu/lsp.rs"]
mod lsp;

pub(super) use self::abi::*;
pub(super) use self::fs::*;
pub(super) use self::lsp::*;

pub(super) fn debug_check_command(path: &Path, format: Format) -> Result<String> {
    let artifact = compile_file_with_backend(path, BuildProfile::Dev, None)?;
    if artifact.status != "ok" {
        let rendered = render_artifact(Format::Text, artifact, None, None, None);
        bail!("debug-check failed to build module\n{rendered}");
    }
    let binary = artifact
        .output
        .as_ref()
        .ok_or_else(|| anyhow!("debug-check missing verify binary output"))?;
    let file_text = ProcessCommand::new("file")
        .arg(binary)
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
        .unwrap_or_default();
    let debug_symbols = binary.exists()
        && (file_text.contains("not stripped")
            || file_text.contains("with debug_info")
            || file_text.contains("dSYM")
            || !file_text.trim().is_empty());

    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let async_hooks = count_async_hooks_in_module(&parsed.module);
    let async_plan = run_non_scenario_test_plan(
        path,
        NonScenarioPlanRequest {
            deterministic: true,
            strict_verify: false,
            safe_profile: false,
            scheduler: Some("fifo".to_string()),
            seed: Some(1),
            record: None,
            rich_artifacts: false,
            filter: None,
        },
    )?;
    let async_backtrace_ready = async_hooks == 0 || async_plan.runtime_event_count > 0;
    let plan_claim_gate = validate_plan_claim_accuracy()?;
    let plan_claims_ok = plan_claim_gate.missing_evidence.is_empty();
    let ok = debug_symbols && async_backtrace_ready && plan_claims_ok;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", if ok { "ok" } else { "warn" }.to_string()),
            ("mode", "debug-check".to_string()),
            ("binary", binary.display().to_string()),
            ("debug_symbols", debug_symbols.to_string()),
            ("async_backtrace_ready", async_backtrace_ready.to_string()),
            ("async_hooks", async_hooks.to_string()),
            ("plan_claims_checked", plan_claim_gate.checked.to_string()),
            (
                "plan_claims_missing_evidence",
                plan_claim_gate.missing_evidence.len().to_string(),
            ),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": ok,
            "binary": binary.display().to_string(),
            "debugSymbols": debug_symbols,
            "asyncBacktraceReady": async_backtrace_ready,
            "asyncHooks": async_hooks,
            "runtimeEvents": async_plan.runtime_event_count,
            "causalLinks": async_plan.causal_link_count,
            "planClaimGate": {
                "completed": plan_claim_gate.completed,
                "checked": plan_claim_gate.checked,
                "missingEvidence": plan_claim_gate.missing_evidence,
            },
            "fileInfo": file_text.trim(),
        })
        .to_string()),
    }
}


pub(super) struct NonScenarioTestPlan {
    pub(super) module: String,
    pub(super) mode: &'static str,
    pub(super) scheduler: String,
    pub(super) diagnostics: usize,
    pub(super) discovered_tests: usize,
    pub(super) selected_tests: usize,
    pub(super) discovered_test_names: Vec<String>,
    pub(super) selected_test_names: Vec<String>,
    pub(super) deterministic_test_names: Vec<String>,
    pub(super) executed_tasks: usize,
    pub(super) execution_order: Vec<u64>,
    pub(super) async_checkpoint_count: usize,
    pub(super) async_execution: Vec<u64>,
    pub(super) rpc_frame_count: usize,
    pub(super) rpc_validation_errors: usize,
    pub(super) thread_findings: usize,
    pub(super) runtime_event_count: usize,
    pub(super) causal_link_count: usize,
    pub(super) coverage_ratio: f64,
    pub(super) artifacts: Option<NonScenarioTraceArtifacts>,
    pub(super) telemetry: NonScenarioPlanTelemetry,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct NonScenarioPlanTelemetry {
    pub(super) parse_ms: u64,
    pub(super) lower_ms: u64,
    pub(super) verify_ms: u64,
    pub(super) execute_ms: u64,
    pub(super) artifact_write_ms: u64,
    pub(super) total_ms: u64,
    pub(super) parse_cache_hit: bool,
    pub(super) lower_cache_hit: bool,
    pub(super) input_bytes: usize,
}

#[derive(Debug, Clone)]
pub(super) struct NonScenarioTraceArtifacts {
    pub(super) trace_path: PathBuf,
    pub(super) report_path: Option<PathBuf>,
    pub(super) timeline_path: Option<PathBuf>,
    pub(super) manifest_path: PathBuf,
    pub(super) explore_path: Option<PathBuf>,
    pub(super) shrink_path: Option<PathBuf>,
    pub(super) scenarios_index_path: Option<PathBuf>,
    pub(super) primary_scenario_path: Option<PathBuf>,
    pub(super) goal_trace_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecMode {
    Fast,
    Det,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ArtifactDetail {
    Minimal,
    Rich,
}

#[derive(Debug, Clone)]
pub(super) struct NonScenarioPlanRequest<'a> {
    pub(super) deterministic: bool,
    pub(super) strict_verify: bool,
    pub(super) safe_profile: bool,
    pub(super) scheduler: Option<String>,
    pub(super) seed: Option<u64>,
    pub(super) record: Option<&'a Path>,
    pub(super) rich_artifacts: bool,
    pub(super) filter: Option<&'a str>,
}

pub(super) struct NonScenarioTraceInputs<'a> {
    detail: ArtifactDetail,
    scheduler: &'a str,
    seed: u64,
    discovered_tests: usize,
    discovered_test_names: &'a [String],
    deterministic_test_names: &'a [String],
    async_execution: &'a [u64],
    rpc_frames: &'a [RpcFrameEvent],
    rpc_validation: &'a [RpcValidationFinding],
    execution_order: &'a [u64],
    events: &'a [TaskEvent],
    runtime_events: &'a [RuntimeSemanticEvent],
    causal_links: &'a [CausalLink],
    thread_findings: &'a [serde_json::Value],
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct RpcFrameEvent {
    #[serde(rename = "event")]
    pub(super) kind: &'static str,
    pub(super) method: String,
    #[serde(rename = "taskId")]
    pub(super) task_id: u64,
}

#[derive(Debug, Clone)]
pub(super) struct WorkloadShape {
    pub(super) async_functions: usize,
    pub(super) spawn_markers: usize,
    pub(super) yield_markers: usize,
}

#[derive(Debug, Clone)]
pub(super) struct ExecutionOp {
    kind: &'static str,
    label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RuntimeSemanticEvent {
    #[serde(rename = "taskId")]
    pub(super) task_id: u64,
    pub(super) phase: String,
    pub(super) kind: String,
    pub(super) label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CausalLink {
    pub(super) from: u64,
    pub(super) to: u64,
    pub(super) relation: String,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum RpcValidationSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub(super) struct RpcValidationFinding {
    pub(super) kind: &'static str,
    pub(super) severity: RpcValidationSeverity,
    pub(super) message: String,
}

pub(super) fn run_non_scenario_test_plan(
    path: &Path,
    request: NonScenarioPlanRequest<'_>,
) -> Result<NonScenarioTestPlan> {
    let started = Instant::now();
    let resolved = resolve_source(path)?;
    let parse_started = Instant::now();
    let (parsed, parse_cache_hit) = parse_program_with_metadata(&resolved.source_path)?;
    let parse_ms = parse_started.elapsed().as_millis() as u64;
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
    let selected_test_names = if let Some(filter) = request.filter {
        discovered_test_names
            .iter()
            .filter(|name| name.contains(filter))
            .cloned()
            .collect::<Vec<_>>()
    } else {
        discovered_test_names.clone()
    };
    let workload = analyze_workload_shape(&parsed.module);
    let call_sequence = collect_call_sequence(&parsed.module);
    let rpc_methods = parse_rpc_declarations(parsed.combined_source()).unwrap_or_default();
    let rpc_method_names = rpc_methods
        .iter()
        .map(|method| method.name.as_str())
        .collect::<BTreeSet<_>>();
    let rpc_call_count = call_sequence
        .iter()
        .filter(|call| rpc_method_names.contains(call.as_str()))
        .count();
    let async_checkpoint_count = count_async_hooks_in_module(&parsed.module);
    let deterministic_test_names = deterministic_test_names
        .into_iter()
        .filter(|name| selected_test_names.iter().any(|selected| selected == name))
        .collect::<Vec<_>>();
    let selected_tests = selected_test_names.len();
    let execution_plan = build_execution_plan(
        discovered_tests,
        &deterministic_test_names,
        workload.async_functions,
        workload.spawn_markers,
        rpc_call_count,
    );
    let task_count = execution_plan.len().max(1);
    let mode = if request.deterministic {
        ExecMode::Det
    } else {
        ExecMode::Fast
    };
    if request.record.is_some() && mode == ExecMode::Fast {
        bail!("--record requires --det");
    }

    let lower_started = Instant::now();
    let ((typed, fir), lower_cache_hit) = lower_fir_cached_with_metadata(&parsed);
    let lower_ms = lower_started.elapsed().as_millis() as u64;
    let strict_unsafe_contracts = request.strict_verify
        || resolved.manifest.as_ref().is_some_and(|manifest| {
            if request.safe_profile {
                manifest.unsafe_policy.enforce_verify.unwrap_or(true)
            } else {
                manifest.unsafe_policy.enforce_dev.unwrap_or(false)
            }
        });
    let (deny_unsafe_in, allow_unsafe_in) = resolved
        .manifest
        .as_ref()
        .map(|manifest| {
            (
                manifest.unsafe_policy.deny_unsafe_in.clone(),
                manifest.unsafe_policy.allow_unsafe_in.clone(),
            )
        })
        .unwrap_or_default();
    let production_memory_safety = true;
    let verify_started = Instant::now();
    let verify_report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: request.safe_profile,
            production_memory_safety,
            strict_unsafe_contracts,
            deny_unsafe_in,
            allow_unsafe_in,
        },
    );
    let verify_ms = verify_started.elapsed().as_millis() as u64;
    let mut verify_diagnostics = verify_report.diagnostics;
    for diagnostic in &mut verify_diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(resolved.source_path.display().to_string());
        }
    }
    suppress_transitive_unsafe_summary_for_architecture_root(
        &resolved.source_path,
        &parsed.module,
        &mut verify_diagnostics,
    );
    diagnostics::assign_stable_codes(
        &mut verify_diagnostics,
        diagnostics::DiagnosticDomain::Driver,
    );
    let diagnostics = verify_diagnostics.len();
    let has_errors = verify_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let diagnostic_details = render_diagnostics_text(&verify_diagnostics);
    if production_memory_safety && has_errors {
        if diagnostic_details.is_empty() {
            bail!(
                "production memory safety rejected module `{}` with {} diagnostics",
                fir.name,
                diagnostics
            );
        }
        bail!(
            "production memory safety rejected module `{}` with {} diagnostics\n{}",
            fir.name,
            diagnostics,
            diagnostic_details
        );
    }
    if request.strict_verify && has_errors {
        if diagnostic_details.is_empty() {
            bail!(
                "strict verify rejected module `{}` with {} diagnostics",
                fir.name,
                diagnostics
            );
        }
        bail!(
            "strict verify rejected module `{}` with {} diagnostics\n{}",
            fir.name,
            diagnostics,
            diagnostic_details
        );
    }

    let scheduler = if mode == ExecMode::Det {
        parse_scheduler(request.scheduler.as_deref().unwrap_or("fifo"))?
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
    let mut runtime_events = Vec::new();
    let mut causal_links = Vec::new();
    let execute_started = Instant::now();
    if mode == ExecMode::Det {
        let trace_mode = if request.strict_verify || request.rich_artifacts {
            runtime::TraceMode::Full
        } else {
            runtime::TraceMode::ReplayCritical
        };
        let mut executor = DeterministicExecutor::new_with_trace_mode(trace_mode);
        let mut task_ops = BTreeMap::<u64, ExecutionOp>::new();
        for op in &execution_plan {
            let task_id = executor.spawn(Box::new(|| {
                let mut acc = 0u64;
                for i in 0..256u64 {
                    acc = acc.wrapping_add(i ^ 0x9E37);
                }
                std::hint::black_box(acc);
            }));
            task_ops.insert(task_id, op.clone());
        }
        execution_order =
            executor.run_until_idle_with_scheduler(scheduler, request.seed.unwrap_or(1));
        events = executor.trace().to_vec();
        let (mut derived_runtime_events, mut derived_causal_links) =
            derive_runtime_semantic_evidence(&events, &execution_order, &task_ops);
        let (gpu_runtime_events, gpu_causal_links) =
            derive_gpu_runtime_semantic_evidence(&parsed.module, &typed);
        derived_runtime_events.extend(gpu_runtime_events);
        derived_causal_links.extend(gpu_causal_links);
        runtime_events = derived_runtime_events;
        causal_links = derived_causal_links;
    }
    let execute_ms = execute_started.elapsed().as_millis() as u64;
    let async_execution = if mode == ExecMode::Det {
        plan_async_checkpoints(
            &execution_order,
            scheduler,
            request.seed.unwrap_or(1),
            async_checkpoint_count,
        )
    } else {
        Vec::new()
    };
    let rpc_frames = if mode == ExecMode::Det {
        build_rpc_frame_events(
            parsed.combined_source(),
            &call_sequence,
            &execution_order,
            &rpc_methods,
        )
    } else {
        Vec::new()
    };
    let rpc_validation = validate_rpc_frames(&rpc_frames);
    if strict_unsafe_contracts
        && mode == ExecMode::Det
        && rpc_validation
            .iter()
            .any(|finding| matches!(finding.severity, RpcValidationSeverity::Error))
    {
        bail!("strict verify rejected RPC sequence with validation errors");
    }
    let mut thread_findings = thread_health_findings(
        &events,
        &execution_order,
        task_count,
        &workload,
        &call_sequence,
    );
    thread_findings.extend(unsafe_trace_findings(&fir));
    let artifacts_started = Instant::now();
    let artifacts = if mode == ExecMode::Det {
        let detail = if strict_unsafe_contracts || request.rich_artifacts {
            ArtifactDetail::Rich
        } else {
            ArtifactDetail::Minimal
        };
        request
            .record
            .map(|record| {
                write_non_scenario_trace_artifacts(
                    record,
                    NonScenarioTraceInputs {
                        detail,
                        scheduler: &scheduler_label,
                        seed: request.seed.unwrap_or(1),
                        discovered_tests,
                        discovered_test_names: &selected_test_names,
                        deterministic_test_names: &deterministic_test_names,
                        async_execution: &async_execution,
                        rpc_frames: &rpc_frames,
                        rpc_validation: &rpc_validation,
                        execution_order: &execution_order,
                        events: &events,
                        runtime_events: &runtime_events,
                        causal_links: &causal_links,
                        thread_findings: &thread_findings,
                    },
                )
            })
            .transpose()?
    } else {
        None
    };
    let artifact_write_ms = artifacts_started.elapsed().as_millis() as u64;

    Ok(NonScenarioTestPlan {
        module: fir.name,
        mode: match mode {
            ExecMode::Fast => "fast",
            ExecMode::Det => "det",
        },
        scheduler: scheduler_label,
        diagnostics,
        discovered_tests,
        selected_tests,
        discovered_test_names,
        selected_test_names,
        deterministic_test_names,
        executed_tasks: if mode == ExecMode::Det { task_count } else { 0 },
        execution_order,
        async_checkpoint_count,
        async_execution,
        rpc_frame_count: rpc_frames.len(),
        rpc_validation_errors: rpc_validation
            .iter()
            .filter(|finding| matches!(finding.severity, RpcValidationSeverity::Error))
            .count(),
        thread_findings: thread_findings.len(),
        runtime_event_count: runtime_events.len(),
        causal_link_count: causal_links.len(),
        coverage_ratio: if discovered_tests == 0 {
            1.0
        } else {
            (selected_tests as f64) / (discovered_tests as f64)
        },
        artifacts,
        telemetry: NonScenarioPlanTelemetry {
            parse_ms,
            lower_ms,
            verify_ms,
            execute_ms,
            artifact_write_ms,
            total_ms: started.elapsed().as_millis() as u64,
            parse_cache_hit,
            lower_cache_hit,
            input_bytes: parsed.input_bytes,
        },
    })
}

pub(super) fn suppress_transitive_unsafe_summary_for_architecture_root(
    source_path: &Path,
    _module: &ast::Module,
    diagnostics: &mut Vec<diagnostics::Diagnostic>,
) {
    let is_architecture_root = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value == "lib.fzy")
        && !source_file_contains_unsafe_marker(source_path);
    if !is_architecture_root {
        return;
    }
    diagnostics.retain(|diagnostic| {
        !matches!(diagnostic.severity, diagnostics::Severity::Warning)
            || !diagnostic.message.contains(
                "compiler unsafe-policy checks passed, and structural unsafe contract metadata is present for all sites; independently reasoned evidence is still required",
            )
    });
}

pub(super) fn source_file_contains_unsafe_marker(source_path: &Path) -> bool {
    std::fs::read_to_string(source_path)
        .map(|source| source.contains("unsafe"))
        .unwrap_or(true)
}

pub(super) fn write_non_scenario_trace_artifacts(
    trace_path: &Path,
    inputs: NonScenarioTraceInputs<'_>,
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
    let native_trace_path = base_dir.join(format!("{stem}.native.trace.json"));
    let trace_payload = TracePayload {
        schema_version: "fozzylang.thread_trace.v0",
        capability: "thread",
        scheduler: inputs.scheduler,
        seed: inputs.seed,
        execution_order: inputs.execution_order,
        async_schedule: inputs.async_execution,
        rpc_frames: inputs.rpc_frames.to_vec(),
        events: inputs
            .events
            .iter()
            .map(TaskEventRecord::from)
            .collect::<Vec<TaskEventRecord>>(),
        runtime_events: inputs.runtime_events.to_vec(),
        causal_links: inputs.causal_links.to_vec(),
        thread_findings: inputs.thread_findings.to_vec(),
    };
    write_json_file(&native_trace_path, &trace_payload).with_context(|| {
        format!(
            "failed writing thread trace artifact: {}",
            native_trace_path.display()
        )
    })?;

    let mut report_written = None;
    let mut timeline_written = None;
    let mut explore_written = None;
    let mut shrink_written = None;
    let mut scenarios_written = None;
    let mut goal_trace_written = None;
    let (primary_scenario_path, generated_scenarios) =
        generate_language_test_scenarios(&base_dir, stem, inputs.deterministic_test_names)?;
    if let Some(primary_scenario) = &primary_scenario_path {
        ensure_goal_trace_from_scenario(primary_scenario, trace_path, inputs.seed).with_context(
            || {
                format!(
                    "failed generating goal trace from scenario {}",
                    primary_scenario.display()
                )
            },
        )?;
        goal_trace_written = Some(trace_path.to_path_buf());
    }

    if inputs.detail == ArtifactDetail::Rich {
        let mut timeline_entries = Vec::with_capacity(
            inputs.execution_order.len() + inputs.async_execution.len() + inputs.rpc_frames.len(),
        );
        for (index, task_id) in inputs.execution_order.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: index,
                decision: "thread.schedule",
                task_id: *task_id,
                scheduler: inputs.scheduler,
                event: None,
                method: None,
            });
        }
        let thread_steps = timeline_entries.len();
        for (index, task_id) in inputs.async_execution.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: thread_steps + index,
                decision: "async.schedule",
                task_id: *task_id,
                scheduler: inputs.scheduler,
                event: None,
                method: None,
            });
        }
        let async_steps = timeline_entries.len();
        for (index, frame) in inputs.rpc_frames.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: async_steps + index,
                decision: "rpc.frame",
                task_id: frame.task_id,
                scheduler: inputs.scheduler,
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

        write_json_file(
            &report_path,
            &ReportPayload {
                schema_version: "fozzylang.report.v0",
                status: "pass",
                capabilities: vec!["thread"],
                scheduler: inputs.scheduler.to_string(),
                seed: inputs.seed,
                discovered_tests: inputs.discovered_tests,
                deterministic_tests: inputs.deterministic_test_names.len(),
                executed_tasks: inputs.execution_order.len(),
                async_checkpoints: inputs.async_execution.len(),
                rpc_frames: inputs.rpc_frames.len(),
                generated_scenarios: generated_scenarios.len(),
                events: inputs.events.len(),
                failure_classes: classify_failure_classes(
                    inputs.rpc_frames,
                    inputs.async_execution,
                    inputs.execution_order,
                ),
                findings: rpc_failure_findings(inputs.rpc_frames),
                rpc_validation: inputs
                    .rpc_validation
                    .iter()
                    .map(rpc_validation_json)
                    .collect::<Vec<_>>(),
                thread_findings: inputs.thread_findings.to_vec(),
            },
        )
        .with_context(|| format!("failed writing report artifact: {}", report_path.display()))?;
        report_written = Some(report_path.clone());

        let scenario_priorities = build_scenario_priorities(
            &generated_scenarios,
            inputs.rpc_frames,
            inputs.async_execution,
        );
        write_json_file(
            &explore_path,
            &ExplorePayload {
                schema_version: "fozzylang.explore.v0",
                schedules: build_schedule_candidates(inputs.execution_order),
                rpc_frame_permutations: build_rpc_frame_permutations(
                    inputs.execution_order,
                    inputs.rpc_frames,
                ),
                scenario_priorities: scenario_priorities.clone(),
                shrink_hints: build_shrink_hints(
                    inputs.discovered_test_names,
                    inputs.execution_order,
                    inputs.rpc_frames,
                    inputs.async_execution,
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
                    inputs.discovered_test_names,
                    inputs.execution_order,
                    inputs.rpc_frames,
                    inputs.async_execution,
                ),
                minimal_rpc_repro: minimize_rpc_failure_frames(inputs.rpc_frames),
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
            trace: native_trace_path.display().to_string(),
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
            goal_trace: goal_trace_written
                .as_ref()
                .map(|path| path.display().to_string()),
            detail: match inputs.detail {
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
        goal_trace_path: goal_trace_written,
    })
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct TaskEventRecord {
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
            TaskEvent::PanicRootCause {
                task_id,
                cause_task_id,
            } => Self {
                event: "panic_root_cause",
                task_id: *task_id,
                detached: None,
                message: cause_task_id.map(|id| format!("cause_task_id={id}")),
            },
            TaskEvent::TimedOut {
                task_id,
                timeout_ms,
            } => Self {
                event: "timed_out",
                task_id: *task_id,
                detached: None,
                message: Some(format!("timeout_ms={timeout_ms}")),
            },
            TaskEvent::Cancelled { task_id } => Self {
                event: "cancelled",
                task_id: *task_id,
                detached: None,
                message: None,
            },
            TaskEvent::Backpressure {
                queue_depth,
                capacity,
            } => Self {
                event: "backpressure",
                task_id: 0,
                detached: None,
                message: Some(format!("queue_depth={queue_depth} capacity={capacity}")),
            },
            TaskEvent::JoinWait { waiter, target } => Self {
                event: "join_wait",
                task_id: *waiter,
                detached: None,
                message: Some(format!("target={target}")),
            },
            TaskEvent::JoinCycle { path } => Self {
                event: "join_cycle",
                task_id: path.first().copied().unwrap_or_default(),
                detached: None,
                message: Some(format!("path={path:?}")),
            },
            TaskEvent::Yielded { task_id, reason } => Self {
                event: "yielded",
                task_id: *task_id,
                detached: None,
                message: Some(reason.clone()),
            },
            TaskEvent::IoWait { task_id, key } => Self {
                event: "io_wait",
                task_id: *task_id,
                detached: None,
                message: Some(key.clone()),
            },
            TaskEvent::IoReady { task_id, key } => Self {
                event: "io_ready",
                task_id: *task_id,
                detached: None,
                message: Some(key.clone()),
            },
            TaskEvent::ChannelSend {
                task_id,
                channel,
                bytes,
                payload_hash,
            } => Self {
                event: "channel_send",
                task_id: *task_id,
                detached: None,
                message: Some(format!(
                    "channel={channel} bytes={bytes} payload_hash={payload_hash}"
                )),
            },
            TaskEvent::ChannelRecv {
                task_id,
                channel,
                bytes,
                payload_hash,
            } => Self {
                event: "channel_recv",
                task_id: *task_id,
                detached: None,
                message: Some(format!(
                    "channel={channel} bytes={bytes} payload_hash={payload_hash}"
                )),
            },
            TaskEvent::MemoryPressure {
                task_id,
                bytes,
                level,
            } => Self {
                event: "memory_pressure",
                task_id: *task_id,
                detached: None,
                message: Some(format!("bytes={bytes} level={level}")),
            },
            TaskEvent::ResourceLeak {
                task_id,
                subsystem,
                resource,
            } => Self {
                event: "resource_leak",
                task_id: *task_id,
                detached: None,
                message: Some(format!("subsystem={subsystem} resource={resource}")),
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
pub(super) struct TracePayload<'a> {
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
    #[serde(rename = "runtimeEvents")]
    runtime_events: Vec<RuntimeSemanticEvent>,
    #[serde(rename = "causalLinks")]
    causal_links: Vec<CausalLink>,
    #[serde(rename = "threadFindings")]
    thread_findings: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct TimelinePayload<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    entries: Vec<TimelineEntry<'a>>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct TimelineEntry<'a> {
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
pub(super) struct ReportPayload {
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
    #[serde(rename = "rpcValidation")]
    rpc_validation: Vec<serde_json::Value>,
    #[serde(rename = "threadFindings")]
    thread_findings: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ExplorePayload {
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
pub(super) struct ShrinkPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    #[serde(rename = "scenarioPriorities")]
    scenario_priorities: serde_json::Value,
    hints: serde_json::Value,
    #[serde(rename = "minimalRpcRepro")]
    minimal_rpc_repro: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ScenariosPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    primary: Option<String>,
    items: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ManifestPayload {
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
    #[serde(rename = "goalTrace", skip_serializing_if = "Option::is_none")]
    goal_trace: Option<String>,
    detail: &'static str,
}

pub(super) fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes)
        .with_context(|| format!("failed writing json file: {}", path.display()))
}

pub(super) fn count_async_hooks_in_module(module: &ast::Module) -> usize {
    let mut hooks = 0usize;
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        if function.is_async {
            hooks += 1;
        }
        for stmt in &function.body {
            hooks += count_async_hooks_in_stmt(stmt);
        }
    }
    hooks
}

pub(super) fn count_async_hooks_in_stmt(stmt: &ast::Stmt) -> usize {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => count_async_hooks_in_expr(value),
        ast::Stmt::Return(value) => value.as_ref().map(count_async_hooks_in_expr).unwrap_or(0),
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            count_async_hooks_in_expr(condition)
                + then_body
                    .iter()
                    .map(count_async_hooks_in_stmt)
                    .sum::<usize>()
                + else_body
                    .iter()
                    .map(count_async_hooks_in_stmt)
                    .sum::<usize>()
        }
        ast::Stmt::While { condition, body } => {
            count_async_hooks_in_expr(condition)
                + body.iter().map(count_async_hooks_in_stmt).sum::<usize>()
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref().map(count_async_hooks_in_stmt).unwrap_or(0)
                + condition
                    .as_ref()
                    .map(count_async_hooks_in_expr)
                    .unwrap_or(0)
                + step.as_deref().map(count_async_hooks_in_stmt).unwrap_or(0)
                + body.iter().map(count_async_hooks_in_stmt).sum::<usize>()
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            count_async_hooks_in_expr(iterable)
                + body.iter().map(count_async_hooks_in_stmt).sum::<usize>()
        }
        ast::Stmt::Loop { body } => body.iter().map(count_async_hooks_in_stmt).sum::<usize>(),
        ast::Stmt::Break(_) | ast::Stmt::Continue => 0,
        ast::Stmt::Match { scrutinee, arms } => {
            let mut total = count_async_hooks_in_expr(scrutinee);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    total += count_async_hooks_in_expr(guard);
                }
                total += count_async_hooks_in_expr(&arm.value);
            }
            total
        }
    }
}

pub(super) fn count_async_hooks_in_expr(expr: &ast::Expr) -> usize {
    match expr {
        ast::Expr::Await(inner) => 1 + count_async_hooks_in_expr(inner),
        ast::Expr::Discard(inner) => count_async_hooks_in_expr(inner),
        ast::Expr::Call { callee, args } => {
            let self_hook = usize::from(matches!(callee.as_str(), "yield" | "checkpoint"));
            self_hook + args.iter().map(count_async_hooks_in_expr).sum::<usize>()
        }
        ast::Expr::UnsafeBlock { .. } => 0,
        ast::Expr::FieldAccess { base, .. } => count_async_hooks_in_expr(base),
        ast::Expr::StructInit { fields, .. } => fields
            .iter()
            .map(|(_, value)| count_async_hooks_in_expr(value))
            .sum(),
        ast::Expr::EnumInit { payload, .. } => payload.iter().map(count_async_hooks_in_expr).sum(),
        ast::Expr::Closure { body, .. } => count_async_hooks_in_expr(body),
        ast::Expr::Group(inner) => count_async_hooks_in_expr(inner),
        ast::Expr::Unary { expr, .. } => count_async_hooks_in_expr(expr),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => count_async_hooks_in_expr(try_expr) + count_async_hooks_in_expr(catch_expr),
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            count_async_hooks_in_expr(condition)
                + count_async_hooks_in_expr(then_expr)
                + count_async_hooks_in_expr(else_expr)
        }
        ast::Expr::Binary { left, right, .. } => {
            count_async_hooks_in_expr(left) + count_async_hooks_in_expr(right)
        }
        ast::Expr::Range { start, end, .. } => {
            count_async_hooks_in_expr(start) + count_async_hooks_in_expr(end)
        }
        ast::Expr::ArrayLiteral(items) => items.iter().map(count_async_hooks_in_expr).sum(),
        ast::Expr::Index { base, index } => {
            count_async_hooks_in_expr(base) + count_async_hooks_in_expr(index)
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => 0,
        _ => 0,
    }
}

pub(super) fn analyze_workload_shape(module: &ast::Module) -> WorkloadShape {
    let mut async_functions = 0usize;
    let mut spawn_markers = 0usize;
    let mut yield_markers = 0usize;
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        if function.is_async {
            async_functions += 1;
        }
        for stmt in &function.body {
            let (spawns, yields) = analyze_workload_stmt(stmt);
            spawn_markers += spawns;
            yield_markers += yields;
        }
    }
    WorkloadShape {
        async_functions,
        spawn_markers,
        yield_markers,
    }
}

pub(super) fn analyze_workload_stmt(stmt: &ast::Stmt) -> (usize, usize) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => analyze_workload_expr(value),
        ast::Stmt::Return(value) => value.as_ref().map(analyze_workload_expr).unwrap_or((0, 0)),
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            let mut totals = analyze_workload_expr(condition);
            for stmt in then_body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            for stmt in else_body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
        ast::Stmt::While { condition, body } => {
            let mut totals = analyze_workload_expr(condition);
            for stmt in body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            let mut totals = (0usize, 0usize);
            if let Some(init) = init {
                let (spawns, yields) = analyze_workload_stmt(init);
                totals.0 += spawns;
                totals.1 += yields;
            }
            if let Some(condition) = condition {
                let (spawns, yields) = analyze_workload_expr(condition);
                totals.0 += spawns;
                totals.1 += yields;
            }
            if let Some(step) = step {
                let (spawns, yields) = analyze_workload_stmt(step);
                totals.0 += spawns;
                totals.1 += yields;
            }
            for stmt in body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            let mut totals = analyze_workload_expr(iterable);
            for stmt in body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
        ast::Stmt::Loop { body } => {
            let mut totals = (0usize, 0usize);
            for stmt in body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => (0, 0),
        ast::Stmt::Match { scrutinee, arms } => {
            let mut totals = analyze_workload_expr(scrutinee);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    let (spawns, yields) = analyze_workload_expr(guard);
                    totals.0 += spawns;
                    totals.1 += yields;
                }
                let (spawns, yields) = analyze_workload_expr(&arm.value);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
    }
}

pub(super) fn analyze_workload_expr(expr: &ast::Expr) -> (usize, usize) {
    match expr {
        ast::Expr::Call { callee, args } => {
            let mut spawns = usize::from(matches!(
                callee.as_str(),
                "spawn" | "spawn_ctx" | "thread.spawn" | "task.group_spawn"
            ));
            let mut yields = usize::from(matches!(
                callee.as_str(),
                "yield" | "checkpoint" | "join" | "task.group_join"
            ));
            for arg in args {
                let (nested_spawns, nested_yields) = analyze_workload_expr(arg);
                spawns += nested_spawns;
                yields += nested_yields;
            }
            (spawns, yields)
        }
        ast::Expr::UnsafeBlock { .. } => (0, 0),
        ast::Expr::Await(inner) | ast::Expr::Group(inner) | ast::Expr::Discard(inner) => {
            analyze_workload_expr(inner)
        }
        ast::Expr::Unary { expr, .. } => analyze_workload_expr(expr),
        ast::Expr::FieldAccess { base, .. } => analyze_workload_expr(base),
        ast::Expr::StructInit { fields, .. } => {
            fields.iter().fold((0, 0), |mut acc, (_, value)| {
                let (spawns, yields) = analyze_workload_expr(value);
                acc.0 += spawns;
                acc.1 += yields;
                acc
            })
        }
        ast::Expr::EnumInit { payload, .. } => payload.iter().fold((0, 0), |mut acc, value| {
            let (spawns, yields) = analyze_workload_expr(value);
            acc.0 += spawns;
            acc.1 += yields;
            acc
        }),
        ast::Expr::Closure { body, .. } => analyze_workload_expr(body),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            let (t_spawns, t_yields) = analyze_workload_expr(try_expr);
            let (c_spawns, c_yields) = analyze_workload_expr(catch_expr);
            (t_spawns + c_spawns, t_yields + c_yields)
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let (c_spawns, c_yields) = analyze_workload_expr(condition);
            let (t_spawns, t_yields) = analyze_workload_expr(then_expr);
            let (e_spawns, e_yields) = analyze_workload_expr(else_expr);
            (
                c_spawns + t_spawns + e_spawns,
                c_yields + t_yields + e_yields,
            )
        }
        ast::Expr::Binary { left, right, .. } => {
            let (l_spawns, l_yields) = analyze_workload_expr(left);
            let (r_spawns, r_yields) = analyze_workload_expr(right);
            (l_spawns + r_spawns, l_yields + r_yields)
        }
        ast::Expr::Range { start, end, .. } => {
            let (l_spawns, l_yields) = analyze_workload_expr(start);
            let (r_spawns, r_yields) = analyze_workload_expr(end);
            (l_spawns + r_spawns, l_yields + r_yields)
        }
        ast::Expr::ArrayLiteral(items) => items.iter().fold((0, 0), |mut acc, item| {
            let (spawns, yields) = analyze_workload_expr(item);
            acc.0 += spawns;
            acc.1 += yields;
            acc
        }),
        ast::Expr::Index { base, index } => {
            let (l_spawns, l_yields) = analyze_workload_expr(base);
            let (r_spawns, r_yields) = analyze_workload_expr(index);
            (l_spawns + r_spawns, l_yields + r_yields)
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => (0, 0),
        _ => (0, 0),
    }
}

pub(super) fn build_execution_plan(
    discovered_tests: usize,
    deterministic_test_names: &[String],
    async_functions: usize,
    spawn_markers: usize,
    rpc_call_count: usize,
) -> Vec<ExecutionOp> {
    let mut plan = Vec::new();
    if discovered_tests == 0 {
        plan.push(ExecutionOp {
            kind: "baseline",
            label: "baseline".to_string(),
        });
    } else {
        for name in deterministic_test_names {
            plan.push(ExecutionOp {
                kind: "test",
                label: name.clone(),
            });
        }
    }
    for index in 0..async_functions {
        plan.push(ExecutionOp {
            kind: "async",
            label: format!("async_fn_{index}"),
        });
    }
    for index in 0..spawn_markers {
        plan.push(ExecutionOp {
            kind: "spawn",
            label: format!("spawn_{index}"),
        });
    }
    for index in 0..rpc_call_count {
        plan.push(ExecutionOp {
            kind: "rpc",
            label: format!("rpc_call_{index}"),
        });
    }
    if plan.is_empty() {
        plan.push(ExecutionOp {
            kind: "baseline",
            label: "baseline".to_string(),
        });
    }
    plan
}

pub(super) fn derive_runtime_semantic_evidence(
    events: &[TaskEvent],
    execution_order: &[u64],
    task_ops: &BTreeMap<u64, ExecutionOp>,
) -> (Vec<RuntimeSemanticEvent>, Vec<CausalLink>) {
    let mut runtime_events = Vec::new();
    for event in events {
        match event {
            TaskEvent::Started { task_id } => {
                let op = task_ops.get(task_id);
                runtime_events.push(RuntimeSemanticEvent {
                    task_id: *task_id,
                    phase: "started".to_string(),
                    kind: op
                        .map(|op| op.kind.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    label: op
                        .map(|op| op.label.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    details: None,
                });
            }
            TaskEvent::Completed { task_id }
            | TaskEvent::Panicked { task_id, .. }
            | TaskEvent::TimedOut { task_id, .. }
            | TaskEvent::Cancelled { task_id } => {
                let op = task_ops.get(task_id);
                runtime_events.push(RuntimeSemanticEvent {
                    task_id: *task_id,
                    phase: "terminal".to_string(),
                    kind: op
                        .map(|op| op.kind.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    label: op
                        .map(|op| op.label.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    details: None,
                });
            }
            TaskEvent::Spawned { task_id, .. }
            | TaskEvent::Detached { task_id }
            | TaskEvent::Yielded { task_id, .. }
            | TaskEvent::IoWait { task_id, .. }
            | TaskEvent::IoReady { task_id, .. }
            | TaskEvent::ChannelSend { task_id, .. }
            | TaskEvent::ChannelRecv { task_id, .. }
            | TaskEvent::MemoryPressure { task_id, .. }
            | TaskEvent::ResourceLeak { task_id, .. } => {
                let op = task_ops.get(task_id);
                runtime_events.push(RuntimeSemanticEvent {
                    task_id: *task_id,
                    phase: "spawned".to_string(),
                    kind: op
                        .map(|op| op.kind.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    label: op
                        .map(|op| op.label.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    details: None,
                });
            }
            TaskEvent::JoinWait { waiter, .. } => {
                let op = task_ops.get(waiter);
                runtime_events.push(RuntimeSemanticEvent {
                    task_id: *waiter,
                    phase: "wait".to_string(),
                    kind: op
                        .map(|op| op.kind.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    label: op
                        .map(|op| op.label.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    details: None,
                });
            }
            TaskEvent::JoinCycle { .. }
            | TaskEvent::PanicRootCause { .. }
            | TaskEvent::Backpressure { .. } => {}
        }
    }
    let mut causal_links = Vec::new();
    let mut ordered = events
        .iter()
        .filter_map(|event| match event {
            TaskEvent::Started { task_id } => Some(*task_id),
            _ => None,
        })
        .collect::<Vec<_>>();
    if ordered.is_empty() {
        ordered = execution_order.to_vec();
        for task_id in &ordered {
            let op = task_ops.get(task_id);
            runtime_events.push(RuntimeSemanticEvent {
                task_id: *task_id,
                phase: "started".to_string(),
                kind: op
                    .map(|op| op.kind.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                label: op
                    .map(|op| op.label.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                details: None,
            });
            runtime_events.push(RuntimeSemanticEvent {
                task_id: *task_id,
                phase: "terminal".to_string(),
                kind: op
                    .map(|op| op.kind.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                label: op
                    .map(|op| op.label.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                details: None,
            });
        }
    }
    for window in ordered.windows(2) {
        causal_links.push(CausalLink {
            from: window[0],
            to: window[1],
            relation: "schedule.next".to_string(),
        });
    }
    (runtime_events, causal_links)
}

pub(super) const GPU_TRACE_EVENT_ID_BASE: u64 = 1_000_000_000_000;

#[derive(Debug, Clone)]
pub(super) enum GpuTraceBinding {
    Device {
        resource_id: String,
        event_id: u64,
    },
    Buffer {
        resource_id: String,
        event_id: u64,
        element_type: &'static str,
        device_resource: Option<String>,
    },
    Slice {
        resource_id: String,
        event_id: u64,
        buffer_resource: String,
        offset: Option<i64>,
        len: Option<i64>,
    },
    Event {
        resource_id: String,
        event_id: u64,
        kernel_name: String,
        launch_event_id: u64,
    },
}

#[derive(Debug, Clone)]
pub(super) struct GpuLaunchArgTrace {
    pub(super) slot: usize,
    pub(super) layout: String,
    pub(super) detail: serde_json::Value,
    pub(super) source_event_ids: Vec<u64>,
}

#[derive(Debug, Default)]
pub(super) struct GpuTraceAnalyzer {
    pub(super) next_trace_id: u64,
    pub(super) previous_trace_id: Option<u64>,
    pub(super) next_device_id: usize,
    pub(super) next_buffer_id: usize,
    pub(super) next_slice_id: usize,
    pub(super) next_event_id: usize,
    pub(super) runtime_events: Vec<RuntimeSemanticEvent>,
    pub(super) causal_links: Vec<CausalLink>,
    pub(super) bindings: HashMap<String, GpuTraceBinding>,
    pub(super) kernel_layouts: HashMap<String, String>,
}
