use super::profile_support::aggregate_metric_bundle;
use super::*;

pub(super) fn dispatch_profile_command(
    config: &Config,
    command: &ProfileCommand,
    strict: bool,
) -> FozzyResult<serde_json::Value> {
    match command {
        ProfileCommand::Top {
            run,
            cpu,
            heap,
            latency,
            io,
            sched,
            limit,
        } => {
            let domains = normalize_domains(*cpu, *heap, *latency, *io, *sched);
            let bundle = match load_profile_bundle(
                config,
                run,
                ProfileLoadSpec {
                    timeline: domains.iter().any(|d| d == "io" || d == "sched"),
                    cpu: domains.iter().any(|d| d == "cpu"),
                    heap: domains.iter().any(|d| d == "heap"),
                    latency: domains.iter().any(|d| d == "latency"),
                    symbols: false,
                },
            ) {
                Ok(v) => v,
                Err(err) => return profile_contract_or_error(strict, "top", run, err),
            };
            enforce_cpu_contract(strict, domains.contains(&"cpu".to_string()))?;
            let mut out = serde_json::Map::new();
            let mut empty_domains = Vec::<serde_json::Value>::new();
            let mut warnings = Vec::<String>::new();
            if let Some(warn) = relaxed_cpu_warning(strict, domains.iter().any(|d| d == "cpu")) {
                warnings.push(warn);
            }
            out.insert(
                "schemaVersion".to_string(),
                serde_json::json!("fozzy.profile_top.v1"),
            );
            out.insert("run".to_string(), serde_json::json!(run));
            out.insert("limit".to_string(), serde_json::json!(limit));
            if domains.iter().any(|d| d == "cpu") {
                let top = bundle
                    .cpu
                    .as_ref()
                    .expect("cpu domain requested")
                    .folded_stacks
                    .iter()
                    .take(*limit)
                    .map(|s| {
                        serde_json::json!({
                            "stack": s.stack,
                            "weight": s.weight
                        })
                    })
                    .collect::<Vec<_>>();
                if top.is_empty() {
                    empty_domains.push(empty_domain("cpu", "no cpu samples in trace"));
                }
                out.insert("cpu".to_string(), serde_json::json!(top));
            }
            if domains.iter().any(|d| d == "heap") {
                let heap_rows = bundle
                    .heap
                    .as_ref()
                    .expect("heap domain requested")
                    .hotspots
                    .iter()
                    .take(*limit)
                    .cloned()
                    .collect::<Vec<_>>();
                if heap_rows.is_empty() {
                    empty_domains.push(empty_domain("heap", "no heap samples in trace"));
                }
                out.insert("heap".to_string(), serde_json::to_value(heap_rows)?);
            }
            if domains.iter().any(|d| d == "latency") {
                let latency_profile = bundle.latency.as_ref().expect("latency domain requested");
                let latency_rows = latency_profile
                    .critical_path
                    .iter()
                    .take(*limit)
                    .cloned()
                    .collect::<Vec<_>>();
                if latency_rows.is_empty() {
                    empty_domains.push(empty_domain("latency", "no latency edges in trace"));
                }
                out.insert(
                    "latency".to_string(),
                    serde_json::json!({
                        "distribution": latency_profile.distribution.clone(),
                        "criticalPath": latency_rows,
                        "dependencyGraph": latency_profile.dependency_graph.iter().take(*limit).cloned().collect::<Vec<_>>(),
                        "waitReasons": latency_profile.wait_reasons.clone(),
                        "tailAmplificationSuspects": latency_profile.tail_amplification_suspects.iter().take(*limit).cloned().collect::<Vec<_>>(),
                    }),
                );
            }
            if domains.iter().any(|d| d == "io") {
                let io_top = top_by_tag(
                    bundle.timeline.as_ref().expect("io domain requested"),
                    ProfileEventKind::Io,
                    *limit,
                );
                if io_top.is_empty() {
                    empty_domains.push(empty_domain("io", "no io events in trace"));
                }
                out.insert("io".to_string(), serde_json::to_value(io_top)?);
            }
            if domains.iter().any(|d| d == "sched") {
                let sched_top = top_by_tag(
                    bundle.timeline.as_ref().expect("sched domain requested"),
                    ProfileEventKind::Sched,
                    *limit,
                );
                if sched_top.is_empty() {
                    empty_domains.push(empty_domain("sched", "no scheduler events in trace"));
                }
                out.insert("sched".to_string(), serde_json::to_value(sched_top)?);
            }
            out.insert(
                "emptyDomains".to_string(),
                serde_json::to_value(empty_domains)?,
            );
            out.insert("warnings".to_string(), serde_json::to_value(warnings)?);
            out.insert("metrics".to_string(), serde_json::to_value(bundle.metrics)?);
            Ok(serde_json::Value::Object(out))
        }
        ProfileCommand::Flame {
            run,
            cpu,
            heap,
            out,
            format,
        } => {
            let use_heap = *heap || !*cpu;
            let bundle = match load_profile_bundle(
                config,
                run,
                ProfileLoadSpec {
                    cpu: !use_heap,
                    heap: use_heap,
                    ..ProfileLoadSpec::default()
                },
            ) {
                Ok(v) => v,
                Err(err) => return profile_contract_or_error(strict, "flame", run, err),
            };
            if *cpu {
                enforce_cpu_contract(strict, true)?;
            }
            let folded = if use_heap {
                heap_folded(bundle.heap.as_ref().expect("heap requested"))
            } else {
                bundle
                    .cpu
                    .as_ref()
                    .expect("cpu requested")
                    .folded_stacks
                    .clone()
            };
            let domain = if use_heap { "heap" } else { "cpu" };
            let empty_reason = match domain {
                "heap" => "no heap samples in trace",
                _ => "no cpu samples in trace",
            };
            let warnings = if let Some(warn) = relaxed_cpu_warning(strict, *cpu) {
                vec![warn]
            } else {
                Vec::new()
            };
            let payload = match format {
                ProfileFlameFormat::Folded => folded_to_text(&folded),
                ProfileFlameFormat::Svg => folded_to_svg(&folded),
                ProfileFlameFormat::Speedscope => {
                    serde_json::to_string_pretty(&folded_to_speedscope(run, &folded))?
                }
            };
            if let Some(path) = out {
                write_text(path, &payload)?;
            }
            Ok(serde_json::json!({
                "schemaVersion": "fozzy.profile_flame.v1",
                "run": run,
                "domain": domain,
                "empty": folded.is_empty(),
                "reason": if folded.is_empty() { Some(empty_reason) } else { None::<&str> },
                "warnings": warnings,
                "format": format,
                "content": payload
            }))
        }
        ProfileCommand::Timeline { run, out, format } => {
            let bundle = match load_profile_bundle(
                config,
                run,
                ProfileLoadSpec {
                    timeline: true,
                    ..ProfileLoadSpec::default()
                },
            ) {
                Ok(v) => v,
                Err(err) => return profile_contract_or_error(strict, "timeline", run, err),
            };
            match format {
                ProfileTimelineFormat::Json => {
                    let payload = serde_json::json!({
                        "schemaVersion": "fozzy.profile_timeline.v1",
                        "run": run,
                        "format": "json",
                        "timeDomains": {
                            "virtualTime": "deterministic, replay-critical",
                            "hostMonotonicTime": "non-deterministic ordering/perf context"
                        },
                        "events": bundle.timeline.as_ref().expect("timeline requested")
                    });
                    if let Some(path) = out {
                        write_json(path, &payload)?;
                    }
                    Ok(payload)
                }
                ProfileTimelineFormat::Html => {
                    let html = timeline_html(bundle.timeline.as_ref().expect("timeline requested"));
                    if let Some(path) = out {
                        write_text(path, &html)?;
                    }
                    Ok(serde_json::json!({
                        "schemaVersion": "fozzy.profile_timeline.v1",
                        "run": run,
                        "format": "html",
                        "timeDomains": {
                            "virtualTime": "deterministic, replay-critical",
                            "hostMonotonicTime": "non-deterministic ordering/perf context"
                        },
                        "content": html
                    }))
                }
            }
        }
        ProfileCommand::Diff {
            left,
            right,
            cpu,
            heap,
            latency,
            io,
            sched,
        } => {
            let domains = normalize_domains(*cpu, *heap, *latency, *io, *sched);
            if domains.iter().any(|d| d == "cpu") {
                enforce_cpu_contract(strict, true)?;
            }
            let left_selectors = parse_selector_group(left);
            let right_selectors = parse_selector_group(right);
            let left_bundles = match load_profile_bundle_group(
                config,
                &left_selectors,
                ProfileLoadSpec {
                    heap: domains.iter().any(|d| d == "heap"),
                    ..ProfileLoadSpec::default()
                },
            ) {
                Ok(v) => v,
                Err(err) => return profile_contract_or_error(strict, "diff", left, err),
            };
            let right_bundles = match load_profile_bundle_group(
                config,
                &right_selectors,
                ProfileLoadSpec {
                    heap: domains.iter().any(|d| d == "heap"),
                    ..ProfileLoadSpec::default()
                },
            ) {
                Ok(v) => v,
                Err(err) => return profile_contract_or_error(strict, "diff", right, err),
            };
            let (l, l_stats) = aggregate_metric_bundle(&left_bundles)?;
            let (r, r_stats) = aggregate_metric_bundle(&right_bundles)?;
            let l_heap = left_bundles.first().and_then(|b| b.heap.as_ref());
            let r_heap = right_bundles.first().and_then(|b| b.heap.as_ref());
            let diff = compute_diff(
                left,
                right,
                &domains,
                &l,
                &r,
                l_heap,
                r_heap,
                &l_stats,
                &r_stats,
                left_bundles.len(),
                right_bundles.len(),
            );
            let mut out = serde_json::to_value(diff)?;
            if let Some(warn) = relaxed_cpu_warning(strict, domains.iter().any(|d| d == "cpu"))
                && let Some(obj) = out.as_object_mut()
            {
                obj.insert("warnings".to_string(), serde_json::json!([warn]));
            }
            Ok(out)
        }
        ProfileCommand::Explain { run, diff_with } => {
            let base = match load_profile_bundle(
                config,
                run,
                ProfileLoadSpec {
                    latency: diff_with.is_none(),
                    ..ProfileLoadSpec::default()
                },
            ) {
                Ok(v) => v,
                Err(err) => return profile_contract_or_error(strict, "explain", run, err),
            };
            let explain = if let Some(right) = diff_with {
                let other = match load_profile_bundle(config, right, ProfileLoadSpec::default()) {
                    Ok(v) => v,
                    Err(err) => return profile_contract_or_error(strict, "explain", right, err),
                };
                explain_from_diff(run, right, &base.metrics, &other.metrics)
            } else {
                explain_single(
                    run,
                    &base.artifacts_dir,
                    &base.metrics,
                    base.latency
                        .as_ref()
                        .expect("latency profile required for single-run explain"),
                )
            };
            Ok(serde_json::to_value(explain)?)
        }
        ProfileCommand::Export { run, format, out } => {
            let bundle = match load_profile_bundle(
                config,
                run,
                ProfileLoadSpec {
                    timeline: matches!(format, ProfileExportFormat::Otlp),
                    cpu: matches!(
                        format,
                        ProfileExportFormat::Speedscope | ProfileExportFormat::Pprof
                    ),
                    symbols: matches!(format, ProfileExportFormat::Pprof),
                    ..ProfileLoadSpec::default()
                },
            ) {
                Ok(v) => v,
                Err(err) => return profile_contract_or_error(strict, "export", run, err),
            };
            enforce_cpu_contract(
                strict,
                matches!(
                    format,
                    ProfileExportFormat::Speedscope | ProfileExportFormat::Pprof
                ),
            )?;
            let warnings = if let Some(warn) = relaxed_cpu_warning(
                strict,
                matches!(
                    format,
                    ProfileExportFormat::Speedscope | ProfileExportFormat::Pprof
                ),
            ) {
                vec![warn]
            } else {
                Vec::new()
            };
            let value = match format {
                ProfileExportFormat::Speedscope => serde_json::to_value(folded_to_speedscope(
                    run,
                    &bundle
                        .cpu
                        .as_ref()
                        .expect("cpu profile required")
                        .folded_stacks,
                ))?,
                ProfileExportFormat::Pprof => serde_json::json!({
                    "schemaVersion": "fozzy.profile_pprof.v1",
                    "run": run,
                    "sampleType": "cpu",
                    "samples": bundle.cpu.as_ref().expect("cpu profile required").samples,
                    "symbols": bundle.symbols.as_ref().expect("symbols required"),
                }),
                ProfileExportFormat::Otlp => serde_json::json!({
                    "schemaVersion": "fozzy.profile_otlp.v1",
                    "run": run,
                    "resource": {
                        "service.name": "fozzy",
                        "run.id": bundle.metrics.run_id,
                    },
                    "metrics": bundle.metrics,
                    "spans": bundle.timeline.as_ref().expect("timeline required"),
                }),
            };
            write_json(out, &value)?;
            Ok(serde_json::json!({
                "schemaVersion": "fozzy.profile_export_result.v1",
                "run": run,
                "format": format,
                "out": out,
                "warnings": warnings,
            }))
        }
        ProfileCommand::Shrink {
            run,
            metric,
            direction,
            budget,
            minimize,
        } => {
            let (artifacts_dir, trace_path) = match resolve_profile_trace(config, run) {
                Ok(v) => v,
                Err(err) => return profile_contract_or_error(strict, "shrink", run, err),
            };
            let input = TraceFile::read_json(&trace_path)?;
            let baseline = metric_value(*metric, &input)?;
            let baseline_for_predicate = baseline;
            let metric_for_predicate = *metric;
            let direction_for_predicate = *direction;
            let shrunk = shrink_trace_with_predicate(
                config,
                TracePath::new(trace_path.clone()),
                &ShrinkOptions {
                    out_trace_path: None,
                    budget: budget.map(|b| b.0),
                    aggressive: false,
                    minimize: *minimize,
                },
                &move |candidate_trace: &TraceFile| {
                    let candidate_value = metric_value(metric_for_predicate, candidate_trace)?;
                    let keep = match direction_for_predicate {
                        ProfileDirection::Increase => candidate_value >= baseline_for_predicate,
                        ProfileDirection::Decrease => candidate_value <= baseline_for_predicate,
                    };
                    Ok(keep)
                },
            )?;
            let shrunk_trace = TraceFile::read_json(Path::new(&shrunk.out_trace_path))?;
            let after = metric_value(*metric, &shrunk_trace)?;
            let preserved = match direction {
                ProfileDirection::Increase => after >= baseline,
                ProfileDirection::Decrease => after <= baseline,
            };
            let out_parent = Path::new(&shrunk.out_trace_path)
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or(artifacts_dir);
            write_profile_artifacts_from_trace(&shrunk_trace, &out_parent)?;
            let direction_name = match direction {
                ProfileDirection::Increase => "increase",
                ProfileDirection::Decrease => "decrease",
            };
            let comparator = match direction {
                ProfileDirection::Increase => ">=",
                ProfileDirection::Decrease => "<=",
            };
            let status = if preserved {
                "ok"
            } else {
                "no_feasible_shrink_found"
            };
            let baseline_out = normalize_metric_value(baseline);
            let after_out = normalize_metric_value(after);
            Ok(serde_json::json!({
                "schemaVersion": "fozzy.profile_shrink.v1",
                "status": status,
                "run": run,
                "trace": trace_path,
                "outTrace": shrunk.out_trace_path,
                "metric": metric,
                "direction": direction,
                "minimize": shrink_minimize_name(*minimize),
                "baseline": baseline_out,
                "after": after_out,
                "preserved": preserved,
                "contract": {
                    "expected": format!("after {comparator} baseline"),
                    "direction": direction_name,
                },
                "reason": if preserved {
                    None::<String>
                } else {
                    Some(format!(
                        "no feasible shrink found that preserves metric direction: expected after {comparator} baseline for direction={direction_name} (baseline={}, after={})",
                        format_metric_value(baseline),
                        format_metric_value(after)
                    ))
                },
            }))
        }
        ProfileCommand::Env => Ok(profile_env_report(config, strict)),
        ProfileCommand::Doctor { run, deep } => profile_doctor(config, strict, run, *deep),
    }
}
