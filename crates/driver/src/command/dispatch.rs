use super::*;

pub fn run(command: Command, format: Format) -> Result<String> {
    match command {
        Command::Init {
            path,
            package_name,
            template,
            with,
            force,
        } => init_project(
            &path,
            package_name.as_deref(),
            template.as_deref(),
            &with,
            force,
        )
        .map(|_| render(format, "initialized project")),
        Command::Build {
            path,
            release,
            strict,
            incremental,
            lib,
            threads,
            backend,
            pgo_generate,
            pgo_use,
            link_libs,
            link_search,
            frameworks,
        } => {
            if release && strict {
                bail!("`fz build` accepts either `--release` or `--strict`, not both");
            }
            let profile = if strict {
                BuildProfile::Strict
            } else if release {
                BuildProfile::Release
            } else {
                BuildProfile::Dev
            };
            let runtime_config = persist_runtime_threads_config(&path, threads)?;
            let _link_scope = BuildLinkArgsScope::new(&link_libs, &link_search, &frameworks);
            let _compile_scope =
                BuildCompileEnvScope::new(threads, pgo_generate, pgo_use.as_deref(), &path)?;
            if lib {
                let artifact = if incremental {
                    compile_library_incremental_with_backend_with_root_guidance(
                        &path,
                        profile,
                        backend.as_deref(),
                    )?
                } else {
                    compile_library_with_backend_with_root_guidance(
                        &path,
                        profile,
                        backend.as_deref(),
                    )?
                };
                let headers = generate_c_headers(&path, None)?;
                let interop = finalize_build_interop_artifacts(&path, &artifact, headers)?;
                let rendered = render_library_artifact(
                    format,
                    artifact,
                    threads,
                    runtime_config,
                    Some(&interop),
                );
                let unsafe_docs = maybe_generate_unsafe_docs(&path);
                Ok(append_unsafe_docs_field(rendered, format, unsafe_docs))
            } else {
                let artifact = if incremental {
                    compile_file_incremental_with_backend_with_root_guidance(
                        &path,
                        profile,
                        backend.as_deref(),
                    )?
                } else {
                    compile_file_with_backend_with_root_guidance(
                        &path,
                        profile,
                        backend.as_deref(),
                    )?
                };
                let interop = if artifact.status == "ok" {
                    maybe_generate_build_interop_artifacts(&path, profile, backend.as_deref())?
                } else {
                    None
                };
                let rendered =
                    render_artifact(format, artifact, threads, runtime_config, interop.as_ref());
                let unsafe_docs = maybe_generate_unsafe_docs(&path);
                Ok(append_unsafe_docs_field(rendered, format, unsafe_docs))
            }
        }
        Command::Run {
            path,
            args,
            deterministic,
            strict_verify,
            safe_profile,
            seed,
            record,
            host_backends,
            backend,
            max_seconds,
            exit_on_healthcheck,
            smoke_http,
        } => {
            if is_fozzy_scenario(&path) {
                let config = scenario_config_with_backends(host_backends)?;
                let run = fzscenario::run_scenario(
                    &config,
                    fzscenario::ScenarioPath::new(path.clone()),
                    &fzscenario::RunOptions {
                        det: deterministic,
                        seed,
                        timeout: None,
                        reporter: scenario_reporter(format),
                        record_trace_to: record.clone(),
                        filter: None,
                        jobs: None,
                        fail_fast: false,
                        record_collision: fzscenario::RecordCollisionPolicy::Append,
                        profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
                        proc_backend: config.proc_backend,
                        fs_backend: config.fs_backend,
                        http_backend: config.http_backend,
                        memory: scenario_memory_options(&config),
                    },
                )
                .map_err(scenario_error)?;
                return render_scenario_run_result(format, run, strict_verify);
            }
            if host_backends && deterministic {
                bail!(
                    "deterministic execution is unavailable for host-backed native `fz run`; use a `.fozzy.json` scenario for deterministic host-backed execution"
                );
            }
            if host_backends && record.is_some() {
                bail!(
                    "trace recording is unavailable for host-backed native `fz run`; use a `.fozzy.json` scenario or a deterministic native test run"
                );
            }
            let unsafe_docs =
                maybe_generate_unsafe_docs(&path).map(|value| value.display().to_string());
            if deterministic && !host_backends {
                let plan = run_non_scenario_test_plan_with_root_guidance(
                    &path,
                    NonScenarioPlanRequest {
                        deterministic: true,
                        strict_verify,
                        safe_profile,
                        scheduler: Some("fifo".to_string()),
                        seed,
                        record: record.as_deref(),
                        rich_artifacts: true,
                        filter: None,
                    },
                )?;
                return match format {
                    Format::Text => Ok(render_text_fields(&[
                        ("status", "ok".to_string()),
                        ("mode", "deterministic-run".to_string()),
                        ("module", plan.module.clone()),
                        ("scheduler", plan.scheduler.clone()),
                        ("deterministic", "true".to_string()),
                        ("routing", "deterministic-language-async-model".to_string()),
                        ("diagnostics", plan.diagnostics.to_string()),
                        ("tasks", plan.executed_tasks.to_string()),
                        (
                            "async_checkpoints",
                            plan.async_checkpoint_count.to_string(),
                        ),
                        ("rpc_frames", plan.rpc_frame_count.to_string()),
                        (
                            "policy",
                            policy_summary_text(
                                "verify",
                                Some(if strict_verify { "strict" } else { "profile-driven" }),
                                Some("deterministic-model"),
                                true,
                            ),
                        ),
                        ("parse_ms", plan.telemetry.parse_ms.to_string()),
                        ("lower_ms", plan.telemetry.lower_ms.to_string()),
                        ("verify_ms", plan.telemetry.verify_ms.to_string()),
                        ("execute_ms", plan.telemetry.execute_ms.to_string()),
                        ("artifact_write_ms", plan.telemetry.artifact_write_ms.to_string()),
                        ("total_ms", plan.telemetry.total_ms.to_string()),
                        (
                            "unsafe_docs",
                            unsafe_docs.clone().unwrap_or_else(|| "<none>".to_string()),
                        ),
                    ])),
                    Format::Json => Ok(serde_json::json!({
                        "module": plan.module,
                        "status": "ok",
                        "diagnostics": plan.diagnostics,
                        "deterministicRequested": deterministic,
                        "deterministicApplied": true,
                        "strictVerify": strict_verify,
                        "safeProfile": safe_profile,
                        "productionMemorySafety": true,
                        "seed": seed,
                        "hostBackends": host_backends,
                        "maxSeconds": max_seconds,
                        "exitOnHealthcheck": exit_on_healthcheck,
                        "smokeHttp": smoke_http,
                        "policy": {
                            "profile": "verify",
                            "unsafeEnforcement": if strict_verify { "strict" } else { "profile-driven" },
                            "memorySafetyMode": "production",
                            "backend": "deterministic-model",
                            "lockfileState": "present-or-created",
                        },
                        "unsafeDocs": unsafe_docs,
                        "routing": {
                            "mode": "deterministic-language-async-model",
                            "reason": "non-scenario deterministic run uses parser/AST/HIR semantics and runtime deterministic model directly",
                        },
                        "execution": {
                            "scheduler": plan.scheduler,
                            "executedTasks": plan.executed_tasks,
                            "asyncCheckpointCount": plan.async_checkpoint_count,
                            "asyncExecution": plan.async_execution,
                            "rpcFrameCount": plan.rpc_frame_count,
                            "threadFindings": plan.thread_findings,
                            "runtimeEvents": plan.runtime_event_count,
                            "causalLinks": plan.causal_link_count,
                        },
                        "telemetry": {
                            "parseMs": plan.telemetry.parse_ms,
                            "lowerMs": plan.telemetry.lower_ms,
                            "verifyMs": plan.telemetry.verify_ms,
                            "executeMs": plan.telemetry.execute_ms,
                            "artifactWriteMs": plan.telemetry.artifact_write_ms,
                            "totalMs": plan.telemetry.total_ms,
                            "parseCacheHit": plan.telemetry.parse_cache_hit,
                            "lowerCacheHit": plan.telemetry.lower_cache_hit,
                            "inputBytes": plan.telemetry.input_bytes,
                        },
                        "artifacts": plan.artifacts.as_ref().map(|artifacts| {
                            serde_json::json!({
                                "trace": artifacts.trace_path.display().to_string(),
                                "report": artifacts.report_path.as_ref().map(|path| path.display().to_string()),
                                "timeline": artifacts.timeline_path.as_ref().map(|path| path.display().to_string()),
                                "manifest": artifacts.manifest_path.display().to_string(),
                            })
                        }),
                    })
                    .to_string()),
                };
            }

            let artifact = compile_file_with_backend_with_root_guidance(
                &path,
                if strict_verify {
                    BuildProfile::Strict
                } else if safe_profile {
                    BuildProfile::Verify
                } else {
                    BuildProfile::Dev
                },
                backend.as_deref(),
            )?;
            if artifact.status != "ok" || artifact.output.is_none() {
                let rendered = render_run_compile_abort(format, &artifact);
                return Err(CommandFailure {
                    exit_code: 1,
                    output: rendered,
                }
                .into());
            }
            let binary = artifact
                .output
                .as_ref()
                .ok_or_else(|| anyhow!("missing native output artifact"))?;
            let routing_mode = if host_backends {
                "native-host-runtime"
            } else {
                "native"
            };
            let rendered = match format {
                Format::Text => {
                    let outcome = run_native_binary_with_bounds(
                        binary,
                        &args,
                        RunBounds {
                            max_seconds,
                            exit_on_healthcheck: exit_on_healthcheck.as_deref(),
                            smoke_http: smoke_http.as_deref(),
                        },
                        false,
                    )?;
                    let message = render_text_fields(&[
                        (
                            "status",
                            if outcome.exit_code == 0 {
                                "ok".to_string()
                            } else {
                                "error".to_string()
                            },
                        ),
                        ("mode", "run".to_string()),
                        ("module", artifact.module.clone()),
                        ("binary", binary.display().to_string()),
                        ("routing", routing_mode.to_string()),
                        (
                            "args",
                            if args.is_empty() {
                                "<none>".to_string()
                            } else {
                                args.join(" ")
                            },
                        ),
                        (
                            "stdout",
                            if outcome.stdout.trim().is_empty() {
                                "<empty>".to_string()
                            } else {
                                outcome.stdout.clone()
                            },
                        ),
                        (
                            "stderr",
                            if outcome.stderr.trim().is_empty() {
                                "<empty>".to_string()
                            } else {
                                outcome.stderr.clone()
                            },
                        ),
                        ("exit_code", outcome.exit_code.to_string()),
                        (
                            "policy",
                            policy_summary_text(
                                if strict_verify {
                                    "strict"
                                } else if safe_profile {
                                    "verify"
                                } else {
                                    "dev"
                                },
                                Some(if strict_verify {
                                    "strict"
                                } else {
                                    "profile-driven"
                                }),
                                Some(routing_mode),
                                true,
                            ),
                        ),
                        (
                            "unsafe_docs",
                            unsafe_docs.clone().unwrap_or_else(|| "<none>".to_string()),
                        ),
                    ]);
                    if outcome.exit_code != 0 {
                        return Err(CommandFailure {
                            exit_code: outcome.exit_code,
                            output: message,
                        }
                        .into());
                    }
                    message
                }
                Format::Json => {
                    let outcome = run_native_binary_with_bounds(
                        binary,
                        &args,
                        RunBounds {
                            max_seconds,
                            exit_on_healthcheck: exit_on_healthcheck.as_deref(),
                            smoke_http: smoke_http.as_deref(),
                        },
                        false,
                    )?;
                    let payload = serde_json::json!({
                        "module": artifact.module,
                        "status": artifact.status,
                        "diagnostics": artifact.diagnostics,
                        "items": artifact.diagnostic_details,
                        "binary": binary.display().to_string(),
                        "args": args,
                        "deterministic": deterministic,
                        "strictVerify": strict_verify,
                        "safeProfile": safe_profile,
                        "productionMemorySafety": true,
                        "seed": seed,
                        "hostBackends": host_backends,
                        "maxSeconds": max_seconds,
                        "exitOnHealthcheck": exit_on_healthcheck,
                        "smokeHttp": smoke_http,
                        "deterministicApplied": deterministic && !host_backends,
                        "policy": {
                            "profile": if strict_verify { "strict" } else if safe_profile { "verify" } else { "dev" },
                            "unsafeEnforcement": if strict_verify { "strict" } else { "profile-driven" },
                            "memorySafetyMode": "production",
                            "backend": routing_mode,
                            "lockfileState": "present-or-created",
                        },
                        "unsafeDocs": unsafe_docs,
                        "routing": {
                            "mode": routing_mode,
                            "reason": if host_backends {
                                "host-backed native live run"
                            } else {
                                "native run"
                            }
                        },
                        "exitCode": outcome.exit_code,
                        "stdout": outcome.stdout,
                        "stderr": outcome.stderr,
                    });
                    if outcome.exit_code != 0 {
                        return Err(CommandFailure {
                            exit_code: outcome.exit_code,
                            output: payload.to_string(),
                        }
                        .into());
                    }
                    payload.to_string()
                }
            };
            Ok(rendered)
        }
        Command::Test {
            path,
            deterministic,
            strict_verify,
            safe_profile,
            seed,
            record,
            host_backends,
            backend: _backend,
            scheduler,
            rich_artifacts,
            filter,
        } => {
            if is_fozzy_scenario(&path) {
                let config = scenario_config_with_backends(host_backends)?;
                let globs = vec![path.display().to_string()];
                let run = fzscenario::run_tests(
                    &config,
                    &globs,
                    &fzscenario::RunOptions {
                        det: deterministic,
                        seed,
                        timeout: None,
                        reporter: scenario_reporter(format),
                        record_trace_to: record.clone(),
                        filter: filter.clone(),
                        jobs: None,
                        fail_fast: false,
                        record_collision: fzscenario::RecordCollisionPolicy::Append,
                        profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
                        proc_backend: config.proc_backend,
                        fs_backend: config.fs_backend,
                        http_backend: config.http_backend,
                        memory: scenario_memory_options(&config),
                    },
                )
                .map_err(scenario_error)?;
                return render_scenario_run_result(format, run, strict_verify);
            }
            if host_backends {
                bail!(
                    "host-backed execution is unavailable for native `fz test`; native tests run in the built-in test executor, and host-backed system tests must be expressed as `.fozzy.json` scenarios"
                );
            }
            let unsafe_docs =
                maybe_generate_unsafe_docs(&path).map(|value| value.display().to_string());

            let test_plan = run_non_scenario_test_plan_with_root_guidance(
                &path,
                NonScenarioPlanRequest {
                    deterministic,
                    strict_verify,
                    safe_profile,
                    scheduler: scheduler.clone(),
                    seed,
                    record: record.as_deref(),
                    rich_artifacts,
                    filter: filter.as_deref(),
                },
            )?;
            let message = render_text_fields(&[
                ("status", "ok".to_string()),
                ("mode", "test".to_string()),
                ("module", test_plan.module.clone()),
                ("deterministic", deterministic.to_string()),
                ("strict_verify", strict_verify.to_string()),
                ("scheduler", test_plan.scheduler.clone()),
                ("executed_tasks", test_plan.executed_tasks.to_string()),
                ("order", format!("{:?}", test_plan.execution_order)),
                ("parse_ms", test_plan.telemetry.parse_ms.to_string()),
                ("lower_ms", test_plan.telemetry.lower_ms.to_string()),
                ("verify_ms", test_plan.telemetry.verify_ms.to_string()),
                ("execute_ms", test_plan.telemetry.execute_ms.to_string()),
                (
                    "artifact_write_ms",
                    test_plan.telemetry.artifact_write_ms.to_string(),
                ),
                ("total_ms", test_plan.telemetry.total_ms.to_string()),
                (
                    "policy",
                    policy_summary_text(
                        if strict_verify { "strict" } else { "dev" },
                        Some(if strict_verify {
                            "strict"
                        } else {
                            "profile-driven"
                        }),
                        Some("deterministic-model"),
                        true,
                    ),
                ),
                (
                    "unsafe_docs",
                    unsafe_docs.clone().unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "artifacts",
                    test_plan
                        .artifacts
                        .as_ref()
                        .map(|artifacts| artifacts.trace_path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
            ]);
            match format {
                Format::Text => {
                    if test_plan.failed_tests > 0 {
                        return Err(CommandFailure {
                            exit_code: 1,
                            output: message,
                        }
                        .into());
                    }
                    Ok(message)
                }
                Format::Json => {
                    let payload = serde_json::json!({
                    "module": test_plan.module,
                    "deterministic": deterministic,
                    "strictVerify": strict_verify,
                    "safeProfile": safe_profile,
                    "productionMemorySafety": true,
                    "policy": {
                        "profile": if strict_verify { "strict" } else { "dev" },
                        "unsafeEnforcement": if strict_verify { "strict" } else { "profile-driven" },
                        "memorySafetyMode": "production",
                        "backend": "deterministic-model",
                        "lockfileState": "present-or-created",
                    },
                    "unsafeDocs": unsafe_docs,
                    "mode": test_plan.mode,
                    "scheduler": test_plan.scheduler,
                    "diagnostics": test_plan.diagnostics,
                    "executedTasks": test_plan.executed_tasks,
                    "executionOrder": test_plan.execution_order,
                    "asyncCheckpointCount": test_plan.async_checkpoint_count,
                    "asyncExecution": test_plan.async_execution,
                    "rpcFrameCount": test_plan.rpc_frame_count,
                    "rpcValidationErrors": test_plan.rpc_validation_errors,
                    "threadFindings": test_plan.thread_findings,
                    "runtimeEventCount": test_plan.runtime_event_count,
                    "causalLinkCount": test_plan.causal_link_count,
                    "discoveredTests": test_plan.discovered_tests,
                    "selectedTests": test_plan.selected_tests,
                    "discoveredTestNames": test_plan.discovered_test_names,
                    "selectedTestNames": test_plan.selected_test_names,
                    "deterministicTestNames": test_plan.deterministic_test_names,
                    "nondeterministicTestNames": test_plan.nondeterministic_test_names,
                    "passedTests": test_plan.passed_tests,
                    "failedTests": test_plan.failed_tests,
                    "coverageRatio": test_plan.coverage_ratio,
                    "telemetry": {
                        "parseMs": test_plan.telemetry.parse_ms,
                        "lowerMs": test_plan.telemetry.lower_ms,
                        "verifyMs": test_plan.telemetry.verify_ms,
                        "executeMs": test_plan.telemetry.execute_ms,
                        "artifactWriteMs": test_plan.telemetry.artifact_write_ms,
                        "totalMs": test_plan.telemetry.total_ms,
                        "parseCacheHit": test_plan.telemetry.parse_cache_hit,
                        "lowerCacheHit": test_plan.telemetry.lower_cache_hit,
                        "inputBytes": test_plan.telemetry.input_bytes,
                    },
                    "artifacts": test_plan.artifacts.as_ref().map(|artifacts| {
                        serde_json::json!({
                            "trace": artifacts.trace_path.display().to_string(),
                            "report": artifacts.report_path.as_ref().map(|path| path.display().to_string()),
                            "timeline": artifacts.timeline_path.as_ref().map(|path| path.display().to_string()),
                            "manifest": artifacts.manifest_path.display().to_string(),
                        })
                    }),
                    });
                    if test_plan.failed_tests > 0 {
                        return Err(CommandFailure {
                            exit_code: 1,
                            output: payload.to_string(),
                        }
                        .into());
                    }
                    Ok(payload.to_string())
                }
            }
        }
        Command::Fmt { targets, check } => fmt_command(&targets, check, format),
        Command::Check { path } => {
            let output = check_file_with_root_guidance(&path)?;
            let rendered = render_output(format, output);
            let unsafe_docs = maybe_generate_unsafe_docs(&path);
            Ok(append_unsafe_docs_field(rendered, format, unsafe_docs))
        }
        Command::Verify { path } => {
            let output = verify_file_with_root_guidance(&path)?;
            let rendered = render_output(format, output);
            let unsafe_docs = maybe_generate_unsafe_docs(&path);
            Ok(append_unsafe_docs_field(rendered, format, unsafe_docs))
        }
        Command::Lint { path, tier } => lint_command(&path, &tier, format),
        Command::Explain { diag_code } => explain_command(&diag_code, format),
        Command::DoctorProject { path, strict } => doctor_project_command(&path, strict, format),
        Command::ScenarioDoctor {
            scenario,
            runs,
            seed,
            strict,
            deep,
            host_backends,
        } => {
            ensure_exists(&scenario)?;
            let config = scenario_config_with_backends(host_backends)?;
            let report = fzscenario::doctor(
                &config,
                &fzscenario::DoctorOptions {
                    deep,
                    scenario: Some(fzscenario::ScenarioPath::new(scenario.clone())),
                    runs: runs.unwrap_or(5) as u32,
                    seed,
                },
            )
            .map_err(scenario_error)?;
            render_doctor_report(format, report, strict)
        }
        Command::DevLoop { path, backend } => devloop_command(&path, backend.as_deref(), format),
        Command::DxCheck { path, strict } => dx_check_command(&path, strict, format),
        Command::SpecCheck => spec_check(format),
        Command::EmitIr { path, backend } => {
            let output = emit_ir(&path, backend.as_deref())?;
            Ok(render_output(format, output))
        }
        Command::Perf { artifact } => perf_command(artifact.as_deref(), format),
        Command::ArtifactsLsLatest => {
            let config = scenario_config()?;
            let output = fzscenario::artifacts_command(
                &config,
                &fzscenario::ArtifactCommand::Ls {
                    run: "latest".to_string(),
                },
            )
            .map_err(scenario_error)?;
            render_value_output(format, &output)
        }
        Command::ReportShowLatest { output_format } => {
            let config = scenario_config()?;
            let reporter = parse_scenario_reporter(&output_format)?;
            let output = fzscenario::report_command(
                &config,
                &fzscenario::ReportCommand::Show {
                    run: "latest".to_string(),
                    format: reporter,
                },
            )
            .map_err(scenario_error)?;
            render_report_show_output(format, reporter, output)
        }
        Command::ReportQueryLatest { jq, list_paths } => {
            let config = scenario_config()?;
            let output = fzscenario::report_command(
                &config,
                &fzscenario::ReportCommand::Query {
                    run: "latest".to_string(),
                    jq,
                    list_paths,
                },
            )
            .map_err(scenario_error)?;
            render_value_output(format, &output)
        }
        Command::StabilityDashboard => stability_dashboard_command(format),
        Command::Parity { path, seed } => parity_command(&path, seed.unwrap_or(1), format),
        Command::AuditUnsafe { path, workspace } => audit_unsafe_command(&path, workspace, format),
        Command::AuditFfi { path } => audit_ffi_command(&path, format),
        Command::AuditMemory { path } => audit_memory_command(&path, format),
        Command::Vendor { path } => vendor_command(&path, format),
        Command::AbiCheck { current, baseline } => abi_check_command(&current, &baseline, format),
        Command::DebugCheck { path } => debug_check_command(&path, format),
        Command::PgoMerge { path, output } => pgo_merge_command(&path, output.as_deref(), format),
        Command::LspDiagnostics { path } => lsp_diagnostics_command(&path, format),
        Command::LspDefinition { path, symbol } => lsp_definition_command(&path, &symbol, format),
        Command::LspHover { path, symbol } => lsp_hover_command(&path, &symbol, format),
        Command::LspRename { path, from, to } => lsp_rename_command(&path, &from, &to, format),
        Command::LspSmoke { path } => lsp_smoke_command(&path, format),
        Command::LspServe { path } => {
            lsp::serve_stdio(path.as_deref())?;
            Ok(render(format, "lsp server exited cleanly"))
        }
        Command::Fuzz { target } => scenario_fuzz(&target, format),
        Command::Explore { target } => {
            if is_native_trace_or_manifest(&target) {
                native_explore(&target, format)
            } else {
                scenario_explore(&target, format)
            }
        }
        Command::MapSuites {
            root,
            scenario_root,
            profile,
        } => {
            let config = scenario_config()?;
            let output = fzscenario::map_command(
                &config,
                &fzscenario::MapCommand::Suites {
                    root,
                    scenario_root,
                    min_risk: 60,
                    profile: parse_topology_profile(&profile)?,
                    shrink_policy: fzscenario::ShrinkCoveragePolicy::NoKnownFailures,
                    limit: 100,
                    offset: 0,
                    max_matched_scenarios: 25,
                },
            )
            .map_err(scenario_error)?;
            render_value_output(format, &output)
        }
        Command::Usage => match format {
            Format::Text => Ok(native_usage_text()),
            Format::Json => Ok(native_usage_doc().to_string()),
        },
        Command::Env => {
            let config = scenario_config()?;
            let output = fzscenario::env_info(&config);
            let output = serde_json::json!({
                "os": output.os,
                "arch": output.arch,
                "fz": output.fz,
                "capabilities": output.capabilities,
                "install": output.install,
            });
            render_value_output(format, &output)
        }
        Command::Schema => {
            let output = fzscenario::schema_doc();
            render_value_output(format, &output)
        }
        Command::Validate { scenario } => {
            ensure_exists(&scenario)?;
            validate_scenario_file(&scenario)?;
            let output = serde_json::json!({
                "ok": true,
                "scenario": scenario.display().to_string(),
            });
            render_value_output(format, &output)
        }
        Command::TraceVerify { trace, strict } => {
            ensure_exists(&trace)?;
            if is_native_test_artifact_target(&trace)? {
                let output = verify_native_test_artifacts(&trace)?;
                let rendered = render_value_output(format, &output)?;
                let ok = output
                    .get("ok")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false);
                if !ok {
                    return Err(CommandFailure {
                        exit_code: 1,
                        output: rendered,
                    }
                    .into());
                }
                return Ok(rendered);
            }
            let output = fzscenario::verify_trace_file(&trace).map_err(scenario_error)?;
            render_trace_verify_report(format, output, strict)
        }
        Command::Replay { trace } => replay_like("replay", &trace, false, format),
        Command::Shrink { trace } => replay_like("shrink", &trace, false, format),
        Command::Ci { trace, strict } => replay_like("ci", &trace, strict, format),
        Command::TraceNative { trace, output } => {
            let converted = convert_fozzy_trace_to_native(&trace, output.as_deref())?;
            Ok(render_trace_native_artifacts(format, converted))
        }
        Command::Headers { path, output } => {
            let generated = generate_c_headers(&path, output.as_deref())?;
            Ok(render_headers(format, generated))
        }
        Command::RpcGen { path, out_dir } => {
            let generated = generate_rpc_artifacts(&path, out_dir.as_deref())?;
            Ok(render_rpc_artifacts(format, generated))
        }
        Command::DocGen {
            path,
            format: doc_format,
            out,
            reference,
        } => {
            let generated =
                generate_doc_artifacts(&path, &doc_format, out.as_deref(), reference.as_deref())?;
            Ok(render_doc_artifacts(format, generated))
        }
        Command::InspectSurface => Ok(render_surface_inspection(format)),
        Command::InspectArtifacts {
            path,
            release,
            backend,
        } => inspect_artifacts_command(&path, release, backend.as_deref(), format),
        Command::InspectEmbedding { path } => inspect_embedding_command(&path, format),
        Command::InspectStdlib { module } => inspect_stdlib_command(&module, format),
        Command::Version => {
            let version = fzscenario::version_info();
            match format {
                Format::Json => Ok(serde_json::to_string(&version)?),
                Format::Text => {
                    let mut fields = vec![("version", version.version)];
                    if let Some(commit) = version.commit {
                        fields.push(("commit", commit));
                    }
                    if let Some(build_date) = version.build_date {
                        fields.push(("build_date", build_date));
                    }
                    fields.push(("language_version", version.compatibility.language_version));
                    fields.push((
                        "trace_schema_version",
                        version.compatibility.trace_schema_version,
                    ));
                    fields.push((
                        "manifest_schema_version",
                        version.compatibility.manifest_schema_version,
                    ));
                    fields.push((
                        "runtime_abi_version",
                        version.compatibility.runtime_abi_version,
                    ));
                    fields.push((
                        "native_import_table_version",
                        version.compatibility.native_import_table_version,
                    ));
                    fields.push((
                        "diagnostic_catalog_version",
                        version.compatibility.diagnostic_catalog_version,
                    ));
                    Ok(render_text_fields(&fields))
                }
            }
        }
    }
}

pub fn run_with_metadata(command: Command, format: Format) -> Result<CommandResult> {
    let output = run(command.clone(), format)?;
    Ok(CommandResult {
        exit_code: infer_success_exit_code(&command, &output, format),
        output,
    })
}

pub(super) fn infer_success_exit_code(
    command: &Command,
    output: &str,
    format: Format,
) -> Option<i32> {
    match command {
        Command::Build { .. } => output_contains_status_error(output, format).then_some(1),
        Command::DoctorProject { .. }
        | Command::DevLoop { .. }
        | Command::Lint { .. }
        | Command::Fmt { .. } => output_contains_status_error(output, format).then_some(1),
        Command::Run { .. } => extract_json_i32(output, "\"exitCode\":")
            .or_else(|| extract_text_i32(output, "exit_code"))
            .filter(|code| *code != 0),
        Command::Check { .. } | Command::Verify { .. } | Command::LspDiagnostics { .. } => {
            let errors = extract_json_usize(output, "\"errors\":")
                .or_else(|| extract_text_usize(output, "errors"))
                .unwrap_or(0);
            if errors > 0
                || output_contains_ok_false(output)
                || output_contains_status_error(output, format)
            {
                Some(1)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(super) fn output_contains_status_error(output: &str, format: Format) -> bool {
    match format {
        Format::Json => output.contains("\"status\":\"error\""),
        Format::Text => output.contains("status: error") || output.contains("status:error"),
    }
}

pub(super) fn output_contains_ok_false(output: &str) -> bool {
    output.contains("\"ok\":false") || output.contains("ok=false")
}

pub(super) fn extract_json_i32(output: &str, key: &str) -> Option<i32> {
    let rest = output.split(key).nth(1)?;
    let digits = rest
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '-')
        .collect::<String>();
    digits.parse::<i32>().ok()
}

pub(super) fn extract_json_usize(output: &str, key: &str) -> Option<usize> {
    let rest = output.split(key).nth(1)?;
    let digits = rest
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse::<usize>().ok()
}

pub(super) fn extract_text_i32(output: &str, key: &str) -> Option<i32> {
    let rest = output.split(&format!("{key}:")).nth(1)?;
    rest.lines().next()?.trim().parse::<i32>().ok()
}

pub(super) fn extract_text_usize(output: &str, key: &str) -> Option<usize> {
    let rest = output.split(&format!("{key}:")).nth(1)?;
    rest.lines().next()?.trim().parse::<usize>().ok()
}

pub(super) struct BuildLinkArgsScope {
    previous: Option<String>,
    active: bool,
}

pub(super) struct BuildCompileEnvScope {
    previous_codegen_jobs: Option<String>,
    previous_pgo_generate: Option<String>,
    previous_pgo_use: Option<String>,
}

impl BuildCompileEnvScope {
    fn new(
        threads: Option<u16>,
        pgo_generate: bool,
        pgo_use: Option<&Path>,
        path: &Path,
    ) -> Result<Self> {
        let previous_codegen_jobs = std::env::var("FZ_CODEGEN_JOBS").ok();
        let previous_pgo_generate = std::env::var("FZ_PGO_GENERATE").ok();
        let previous_pgo_use = std::env::var("FZ_PGO_USE").ok();

        if let Some(threads) = threads {
            if threads == 0 {
                bail!("--threads must be greater than zero");
            }
            std::env::set_var("FZ_CODEGEN_JOBS", threads.to_string());
        } else {
            std::env::remove_var("FZ_CODEGEN_JOBS");
        }

        if pgo_generate {
            let resolved = resolve_pgo_dir(path);
            std::fs::create_dir_all(&resolved).with_context(|| {
                format!(
                    "failed creating PGO profile generation directory: {}",
                    resolved.display()
                )
            })?;
            std::env::set_var("FZ_PGO_GENERATE", resolved.display().to_string());
            std::env::remove_var("FZ_PGO_USE");
        } else if let Some(profile) = pgo_use {
            if !profile.exists() {
                bail!("PGO profile data not found: {}", profile.display());
            }
            std::env::set_var("FZ_PGO_USE", profile.display().to_string());
            std::env::remove_var("FZ_PGO_GENERATE");
        } else {
            std::env::remove_var("FZ_PGO_GENERATE");
            std::env::remove_var("FZ_PGO_USE");
        }

        Ok(Self {
            previous_codegen_jobs,
            previous_pgo_generate,
            previous_pgo_use,
        })
    }
}

impl Drop for BuildCompileEnvScope {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous_codegen_jobs {
            std::env::set_var("FZ_CODEGEN_JOBS", previous);
        } else {
            std::env::remove_var("FZ_CODEGEN_JOBS");
        }
        if let Some(previous) = &self.previous_pgo_generate {
            std::env::set_var("FZ_PGO_GENERATE", previous);
        } else {
            std::env::remove_var("FZ_PGO_GENERATE");
        }
        if let Some(previous) = &self.previous_pgo_use {
            std::env::set_var("FZ_PGO_USE", previous);
        } else {
            std::env::remove_var("FZ_PGO_USE");
        }
    }
}

pub(super) fn resolve_pgo_dir(path: &Path) -> PathBuf {
    let root = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    root.join(".fz").join("pgo").join("default")
}

pub(super) fn collect_pgo_profile_inputs(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.exists() {
        bail!("PGO input path not found: {}", path.display());
    }
    if !path.is_dir() {
        bail!(
            "PGO input path is neither a file nor directory: {}",
            path.display()
        );
    }

    let mut inputs = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("failed reading PGO input directory: {}", dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!(
                    "failed reading directory entry while scanning {}",
                    dir.display()
                )
            })?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
                continue;
            }
            let ext = entry_path.extension().and_then(|value| value.to_str());
            if matches!(ext, Some("profraw") | Some("profdata")) {
                inputs.push(entry_path);
            }
        }
    }
    inputs.sort();
    inputs.dedup();
    Ok(inputs)
}

pub(super) fn pgo_merge_command(
    path: &Path,
    output: Option<&Path>,
    format: Format,
) -> Result<String> {
    let inputs = collect_pgo_profile_inputs(path)?;
    if inputs.is_empty() {
        bail!(
            "no PGO profile inputs found under {}; expected .profraw or .profdata files",
            path.display()
        );
    }
    let output_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| path.join("merged.profdata"));
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating output directory for merged profile: {}",
                parent.display()
            )
        })?;
    }

    let mut command = ProcessCommand::new("llvm-profdata");
    command
        .arg("merge")
        .arg("-sparse")
        .arg("-o")
        .arg(&output_path);
    for input in &inputs {
        command.arg(input);
    }
    let output = command.output().with_context(|| {
        "failed invoking llvm-profdata; ensure LLVM toolchain is installed and llvm-profdata is in PATH"
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "llvm-profdata merge failed for {} input(s): {}",
            inputs.len(),
            if stderr.is_empty() {
                "<no stderr>".to_string()
            } else {
                stderr
            }
        );
    }

    let rendered = match format {
        Format::Text => render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "pgo-merge".to_string()),
            ("input_count", inputs.len().to_string()),
            ("output", output_path.display().to_string()),
        ]),
        Format::Json => serde_json::json!({
            "status": "ok",
            "mode": "pgo-merge",
            "inputCount": inputs.len(),
            "output": output_path.display().to_string(),
            "inputs": inputs
                .iter()
                .map(|value| value.display().to_string())
                .collect::<Vec<_>>(),
        })
        .to_string(),
    };
    Ok(rendered)
}

impl BuildLinkArgsScope {
    fn new(link_libs: &[String], link_search: &[String], frameworks: &[String]) -> Self {
        let mut args = Vec::new();
        for path in link_search {
            if !path.trim().is_empty() {
                args.push(format!("-L{}", path.trim()));
            }
        }
        for lib in link_libs {
            if !lib.trim().is_empty() {
                args.push(format!("-l{}", lib.trim()));
            }
        }
        if cfg!(target_vendor = "apple") {
            for framework in frameworks {
                if !framework.trim().is_empty() {
                    args.push("-framework".to_string());
                    args.push(framework.trim().to_string());
                }
            }
        }
        if args.is_empty() {
            return Self {
                previous: None,
                active: false,
            };
        }
        let previous = std::env::var("FZ_LINKER_ARGS").ok();
        let mut merged = previous.clone().unwrap_or_default();
        if !merged.trim().is_empty() {
            merged.push(' ');
        }
        merged.push_str(&args.join(" "));
        // Build executes synchronously in this process; scope restores previous value.
        std::env::set_var("FZ_LINKER_ARGS", merged);
        Self {
            previous,
            active: true,
        }
    }
}

impl Drop for BuildLinkArgsScope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(previous) = &self.previous {
            std::env::set_var("FZ_LINKER_ARGS", previous);
        } else {
            std::env::remove_var("FZ_LINKER_ARGS");
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg(test)]
pub(super) struct ScenarioRunRouting {
    pub(super) deterministic_applied: bool,
    pub(super) mode: &'static str,
    pub(super) reason: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RunBounds<'a> {
    pub(super) max_seconds: Option<u64>,
    pub(super) exit_on_healthcheck: Option<&'a str>,
    pub(super) smoke_http: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub(super) struct NativeRunOutcome {
    pub(super) exit_code: i32,
    pub(super) stdout: String,
    pub(super) stderr: String,
}
