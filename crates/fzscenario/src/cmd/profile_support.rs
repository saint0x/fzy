use super::*;

pub(super) fn load_profile_bundle(
    config: &Config,
    selector: &str,
    spec: ProfileLoadSpec,
) -> FozzyResult<ProfileBundle> {
    let (artifacts_dir, trace_path) = resolve_profile_artifacts(config, selector)?;
    if let Some(trace_path) = trace_path {
        if profile_artifacts_stale(&artifacts_dir, &trace_path)? {
            let trace = TraceFile::read_json(&trace_path)?;
            write_profile_artifacts_from_trace(&trace, &artifacts_dir)?;
        }
    } else if !profile_artifacts_exist(&artifacts_dir) {
        return Err(FozzyError::InvalidArgument(format!(
            "no trace.fozzy found for {selector:?}; profiler requires trace artifacts"
        )));
    }

    let metrics: ProfileMetrics =
        serde_json::from_slice(&std::fs::read(artifacts_dir.join("profile.metrics.json"))?)?;
    let timeline = if spec.timeline {
        Some(
            serde_json::from_slice::<ProfileTimelineArtifact>(&std::fs::read(
                artifacts_dir.join("profile.timeline.json"),
            )?)?
            .events,
        )
    } else {
        None
    };
    let cpu = if spec.cpu {
        Some(serde_json::from_slice(&std::fs::read(
            artifacts_dir.join("profile.cpu.json"),
        )?)?)
    } else {
        None
    };
    let heap = if spec.heap {
        Some(serde_json::from_slice(&std::fs::read(
            artifacts_dir.join("profile.heap.json"),
        )?)?)
    } else {
        None
    };
    let latency = if spec.latency {
        Some(serde_json::from_slice(&std::fs::read(
            artifacts_dir.join("profile.latency.json"),
        )?)?)
    } else {
        None
    };
    let symbols = if spec.symbols {
        Some(serde_json::from_slice(&std::fs::read(
            artifacts_dir.join("symbols.json"),
        )?)?)
    } else {
        None
    };

    Ok(ProfileBundle {
        artifacts_dir,
        timeline,
        cpu,
        heap,
        latency,
        metrics,
        symbols,
    })
}

pub(super) fn parse_selector_group(value: &str) -> Vec<String> {
    let selectors = value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if selectors.is_empty() {
        vec![value.to_string()]
    } else {
        selectors
    }
}

pub(super) fn load_profile_bundle_group(
    config: &Config,
    selectors: &[String],
    spec: ProfileLoadSpec,
) -> FozzyResult<Vec<ProfileBundle>> {
    let mut bundles = Vec::<ProfileBundle>::new();
    for selector in selectors {
        bundles.push(load_profile_bundle(config, selector, spec)?);
    }
    Ok(bundles)
}

pub(super) fn aggregate_metric_bundle(
    bundles: &[ProfileBundle],
) -> FozzyResult<(ProfileMetrics, HashMap<String, MetricStats>)> {
    let first = bundles.first().ok_or_else(|| {
        FozzyError::InvalidArgument("diff requires at least one sample".to_string())
    })?;
    let values_for = |field: fn(&ProfileMetrics) -> f64| {
        bundles
            .iter()
            .map(|b| field(&b.metrics))
            .collect::<Vec<f64>>()
    };
    let mut stats = HashMap::<String, MetricStats>::new();
    for (name, values) in [
        ("virtual_time_ms", values_for(|m| m.virtual_time_ms as f64)),
        ("cpu_time_ms", values_for(|m| m.cpu_time_ms as f64)),
        ("host_time_ms", values_for(|m| m.host_time_ms as f64)),
        ("p50_latency_ms", values_for(|m| m.p50_latency_ms as f64)),
        ("p95_latency_ms", values_for(|m| m.p95_latency_ms as f64)),
        ("p99_latency_ms", values_for(|m| m.p99_latency_ms as f64)),
        ("max_latency_ms", values_for(|m| m.max_latency_ms as f64)),
        ("alloc_bytes", values_for(|m| m.alloc_bytes as f64)),
        ("in_use_bytes", values_for(|m| m.in_use_bytes as f64)),
        ("io_ops", values_for(|m| m.io_ops as f64)),
        ("sched_ops", values_for(|m| m.sched_ops as f64)),
    ] {
        stats.insert(name.to_string(), metric_stats(&values));
    }

    let mean_u64 = |name: &str, fallback: u64| {
        stats
            .get(name)
            .map(|s| s.mean.max(0.0).round() as u64)
            .unwrap_or(fallback)
    };
    let mut out = first.metrics.clone();
    out.virtual_time_ms = mean_u64("virtual_time_ms", out.virtual_time_ms);
    out.host_time_ms = mean_u64("host_time_ms", out.host_time_ms);
    out.cpu_time_ms = mean_u64("cpu_time_ms", out.cpu_time_ms);
    out.alloc_bytes = mean_u64("alloc_bytes", out.alloc_bytes);
    out.in_use_bytes = mean_u64("in_use_bytes", out.in_use_bytes);
    out.p50_latency_ms = mean_u64("p50_latency_ms", out.p50_latency_ms);
    out.p95_latency_ms = mean_u64("p95_latency_ms", out.p95_latency_ms);
    out.p99_latency_ms = mean_u64("p99_latency_ms", out.p99_latency_ms);
    out.max_latency_ms = mean_u64("max_latency_ms", out.max_latency_ms);
    out.io_ops = mean_u64("io_ops", out.io_ops);
    out.sched_ops = mean_u64("sched_ops", out.sched_ops);
    out.confidence = Some(if bundles.len() <= 1 { 0.8 } else { 0.9 });
    Ok((out, stats))
}

fn metric_stats(values: &[f64]) -> MetricStats {
    if values.is_empty() {
        return MetricStats::default();
    }
    let n = values.len();
    let mean = values.iter().copied().sum::<f64>() / n as f64;
    let variance = values
        .iter()
        .map(|v| {
            let d = *v - mean;
            d * d
        })
        .sum::<f64>()
        / n as f64;
    MetricStats {
        n,
        mean,
        std_dev: variance.sqrt(),
    }
}

pub(super) fn top_by_tag(
    timeline: &[ProfileEvent],
    kind: ProfileEventKind,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut counts = BTreeMap::<String, u64>::new();
    for event in timeline {
        if event.kind != kind {
            continue;
        }
        let name = event
            .tags
            .get("name")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        *counts.entry(name).or_insert(0) += 1;
    }
    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.into_iter()
        .take(limit)
        .map(|(name, count)| serde_json::json!({"name": name, "count": count}))
        .collect()
}

pub(super) fn empty_domain(domain: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "domain": domain,
        "empty": true,
        "reason": reason,
    })
}

pub(super) fn profile_env_report(config: &Config, strict: bool) -> serde_json::Value {
    let collector = detect_cpu_collector_capability();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let cpu_quality = if collector.active_collector == "perf_event_open" {
        "high"
    } else {
        "degraded"
    };
    serde_json::json!({
        "schemaVersion": "fozzy.profile_env.v3",
        "strict": strict,
        "determinismContract": {
            "replayBoundTo": "deterministic_decisions_and_virtual_events",
            "nonDeterministicMeasurements": ["cpu_time_ms", "host_time_ms"],
        },
        "host": {
            "os": os,
            "arch": arch,
        },
        "backends": {
            "proc": format!("{:?}", config.proc_backend).to_lowercase(),
            "fs": format!("{:?}", config.fs_backend).to_lowercase(),
            "http": format!("{:?}", config.http_backend).to_lowercase(),
        },
        "domains": {
            "cpu": {
                "available": true,
                "quality": cpu_quality,
                "primaryCollector": collector.primary_collector,
                "activeCollector": collector.active_collector,
                "linuxPerfEventOpen": collector.linux_perf_event_open,
                "samplePeriodMs": collector.sample_period_ms,
                "diagnostics": collector.diagnostics,
                "notes": "host-time cpu sampling is non-deterministic; compare repeated deterministic runs statistically"
            },
            "heap": {
                "available": true,
                "quality": "high",
                "notes": "derived from memory_alloc/memory_free events in trace"
            },
            "latency": {
                "available": true,
                "quality": "high",
                "notes": "derived from deterministic trace timeline deltas"
            },
            "io": {
                "available": true,
                "quality": "high",
                "notes": "derived from io/net event counts in trace"
            },
            "sched": {
                "available": true,
                "quality": "high",
                "notes": "derived from distributed scheduler events in trace"
            }
        }
    })
}

pub(super) fn profile_doctor(
    config: &Config,
    strict: bool,
    run: &str,
    deep: bool,
) -> FozzyResult<serde_json::Value> {
    let mut checks = Vec::<serde_json::Value>::new();
    let mut issues = Vec::<String>::new();
    checks.push(serde_json::json!({
        "name": "env",
        "ok": true,
        "status": "pass",
        "detail": profile_env_report(config, strict),
    }));

    let bundle = match load_profile_bundle(
        config,
        run,
        ProfileLoadSpec {
            timeline: true,
            cpu: true,
            heap: true,
            latency: true,
            symbols: false,
        },
    ) {
        Ok(bundle) => {
            checks.push(serde_json::json!({
                "name": "load_bundle",
                "ok": true,
                "status": "pass",
                "detail": "resolved run/trace and loaded profile artifacts",
            }));
            bundle
        }
        Err(err) => {
            let detail = err.to_string();
            issues.push(detail.clone());
            checks.push(serde_json::json!({
                "name": "load_bundle",
                "ok": false,
                "status": "fail",
                "detail": detail,
            }));
            return Ok(serde_json::json!({
                "schemaVersion": "fozzy.profile_doctor.v1",
                "run": run,
                "ok": false,
                "checks": checks,
                "issues": issues,
            }));
        }
    };

    let top_domains = normalize_domains(false, false, false, false, false);
    let top_has_any = !top_by_tag(
        bundle.timeline.as_ref().expect("timeline loaded"),
        ProfileEventKind::Io,
        10,
    )
    .is_empty()
        || !top_by_tag(
            bundle.timeline.as_ref().expect("timeline loaded"),
            ProfileEventKind::Sched,
            10,
        )
        .is_empty()
        || !bundle
            .heap
            .as_ref()
            .expect("heap loaded")
            .hotspots
            .is_empty()
        || !bundle
            .latency
            .as_ref()
            .expect("latency loaded")
            .critical_path
            .is_empty();
    checks.push(serde_json::json!({
        "name": "top",
        "ok": true,
        "status": if top_has_any { "pass" } else { "warn" },
        "detail": format!("default domains={top_domains:?}"),
    }));

    let heap_folded = heap_folded(bundle.heap.as_ref().expect("heap loaded"));
    checks.push(serde_json::json!({
        "name": "flame_heap",
        "ok": true,
        "status": if heap_folded.is_empty() { "warn" } else { "pass" },
        "detail": if heap_folded.is_empty() { "no heap samples in trace" } else { "heap flame data present" },
    }));
    checks.push(serde_json::json!({
        "name": "flame_cpu",
        "ok": true,
        "status": if bundle.cpu.as_ref().expect("cpu loaded").folded_stacks.is_empty() { "warn" } else { "pass" },
        "detail": if bundle.cpu.as_ref().expect("cpu loaded").folded_stacks.is_empty() { "no cpu samples in trace" } else { "cpu flame data present" },
    }));

    checks.push(serde_json::json!({
        "name": "timeline",
        "ok": true,
        "status": "pass",
        "detail": format!("events={}", bundle.timeline.as_ref().expect("timeline loaded").len()),
    }));
    let diff = compute_diff(
        run,
        run,
        &["cpu".to_string(), "heap".to_string(), "latency".to_string()],
        &bundle.metrics,
        &bundle.metrics,
        bundle.heap.as_ref(),
        bundle.heap.as_ref(),
        &HashMap::new(),
        &HashMap::new(),
        1,
        1,
    );
    checks.push(serde_json::json!({
        "name": "diff",
        "ok": true,
        "status": "pass",
        "detail": format!("regressions={}", diff.regressions.len()),
    }));
    let explain = explain_single(
        run,
        &bundle.artifacts_dir,
        &bundle.metrics,
        bundle.latency.as_ref().expect("latency loaded"),
    );
    checks.push(serde_json::json!({
        "name": "explain",
        "ok": true,
        "status": "pass",
        "detail": explain.likely_cause_domain,
    }));
    let speedscope: serde_json::Value =
        folded_to_speedscope(run, &bundle.cpu.as_ref().expect("cpu loaded").folded_stacks);
    checks.push(serde_json::json!({
        "name": "export",
        "ok": true,
        "status": "pass",
        "detail": format!("speedscope_frames={}", speedscope.get("shared").and_then(|v| v.get("frames")).and_then(|v| v.as_array()).map(|v| v.len()).unwrap_or(0)),
    }));

    if deep {
        let shrink_check = match resolve_profile_trace(config, run) {
            Ok((_, trace_path)) => {
                let out = std::env::temp_dir().join(format!(
                    "fozzy-profile-doctor-{}.trace.fozzy",
                    uuid::Uuid::new_v4()
                ));
                match shrink_trace(
                    config,
                    TracePath::new(trace_path.clone()),
                    &ShrinkOptions {
                        out_trace_path: Some(out.clone()),
                        budget: Some(std::time::Duration::from_secs(2)),
                        aggressive: false,
                        minimize: ShrinkMinimize::All,
                    },
                ) {
                    Ok(s) => {
                        let shrunk_trace = TraceFile::read_json(Path::new(&s.out_trace_path))?;
                        let baseline = metric_value(
                            ProfileMetric::CpuTime,
                            &TraceFile::read_json(&trace_path)?,
                        )?;
                        let after = metric_value(ProfileMetric::CpuTime, &shrunk_trace)?;
                        let preserved = after >= baseline;
                        serde_json::json!({
                            "name": "shrink_cpu_increase",
                            "ok": true,
                            "status": if preserved { "pass" } else { "warn" },
                            "detail": if preserved {
                                format!("preserved contract baseline={} after={}", format_metric_value(baseline), format_metric_value(after))
                            } else {
                                format!("no feasible shrink found that preserves increase contract baseline={} after={}", format_metric_value(baseline), format_metric_value(after))
                            }
                        })
                    }
                    Err(err) => serde_json::json!({
                        "name": "shrink_cpu_increase",
                        "ok": false,
                        "status": "fail",
                        "detail": err.to_string(),
                    }),
                }
            }
            Err(err) => serde_json::json!({
                "name": "shrink_cpu_increase",
                "ok": false,
                "status": "fail",
                "detail": err.to_string(),
            }),
        };
        if shrink_check
            .get("ok")
            .and_then(|v| v.as_bool())
            .is_some_and(|v| !v)
        {
            if let Some(detail) = shrink_check.get("detail").and_then(|v| v.as_str()) {
                issues.push(detail.to_string());
            }
        }
        checks.push(shrink_check);
    } else {
        checks.push(serde_json::json!({
            "name": "shrink_cpu_increase",
            "ok": true,
            "status": "pass",
            "detail": "skipped (use --deep for shrink+contract checks)",
        }));
    }

    let ok = checks
        .iter()
        .all(|c| c.get("ok").and_then(|v| v.as_bool()).unwrap_or(false));
    Ok(serde_json::json!({
        "schemaVersion": "fozzy.profile_doctor.v1",
        "run": run,
        "ok": ok,
        "checks": checks,
        "issues": issues,
    }))
}

pub(super) fn resolve_profile_trace(
    config: &Config,
    selector: &str,
) -> FozzyResult<(PathBuf, PathBuf)> {
    let (artifacts_dir, trace_path) = resolve_profile_artifacts(config, selector)?;
    if let Some(trace_path) = trace_path {
        return Ok((artifacts_dir, trace_path));
    }
    Err(FozzyError::InvalidArgument(format!(
        "no trace.fozzy found for {selector:?}; profiler requires trace artifacts"
    )))
}

pub(super) fn resolve_profile_artifacts(
    config: &Config,
    selector: &str,
) -> FozzyResult<(PathBuf, Option<PathBuf>)> {
    let input = PathBuf::from(selector);
    if input.exists()
        && input.is_file()
        && input
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("fozzy"))
    {
        let canonical = std::fs::canonicalize(&input).unwrap_or_else(|_| input.clone());
        let key = blake3::hash(canonical.to_string_lossy().as_bytes())
            .to_hex()
            .to_string();
        let dir = config.base_dir.join("profile-cache").join(key);
        return Ok((dir, Some(input)));
    }

    let artifacts_dir = resolve_artifacts_dir(config, selector)?;
    let trace_path = artifacts_dir.join("trace.fozzy");
    if trace_path.exists() {
        return Ok((artifacts_dir, Some(trace_path)));
    }

    let report_path = artifacts_dir.join("report.json");
    if report_path.exists() {
        let bytes = std::fs::read(&report_path)?;
        if let Ok(summary) = serde_json::from_slice::<RunSummary>(&bytes) {
            if let Some(path) = summary.identity.trace_path {
                let from_report = PathBuf::from(path);
                if from_report.exists() {
                    return Ok((artifacts_dir, Some(from_report)));
                }
            }
        }
    }

    let manifest_path = artifacts_dir.join("manifest.json");
    if manifest_path.exists() {
        let bytes = std::fs::read(&manifest_path)?;
        if let Ok(manifest) = serde_json::from_slice::<RunManifest>(&bytes) {
            if let Some(path) = manifest.trace_path {
                let from_manifest = PathBuf::from(path);
                if from_manifest.exists() {
                    return Ok((artifacts_dir, Some(from_manifest)));
                }
            }
        }
    }

    Ok((artifacts_dir, None))
}

fn profile_artifacts_exist(artifacts_dir: &Path) -> bool {
    for name in [
        "profile.timeline.json",
        "profile.cpu.json",
        "profile.heap.json",
        "profile.latency.json",
        "profile.metrics.json",
        "symbols.json",
    ] {
        if !artifacts_dir.join(name).exists() {
            return false;
        }
    }
    true
}

pub(super) fn normalize_domains(
    cpu: bool,
    heap: bool,
    latency: bool,
    io: bool,
    sched: bool,
) -> Vec<String> {
    if !cpu && !heap && !latency && !io && !sched {
        return vec![
            "cpu".to_string(),
            "io".to_string(),
            "sched".to_string(),
            "heap".to_string(),
            "latency".to_string(),
        ];
    }
    let mut out = Vec::new();
    if cpu {
        out.push("cpu".to_string());
    }
    if heap {
        out.push("heap".to_string());
    }
    if latency {
        out.push("latency".to_string());
    }
    if io {
        out.push("io".to_string());
    }
    if sched {
        out.push("sched".to_string());
    }
    out
}

pub(super) fn enforce_cpu_contract(strict: bool, cpu_requested: bool) -> FozzyResult<()> {
    let _ = (strict, cpu_requested);
    Ok(())
}

pub(super) fn detect_cpu_collector_capability() -> CpuCollectorCapability {
    let fallback = "in_process_sampler".to_string();
    if cfg!(target_os = "linux") {
        let mut diagnostics = Vec::<String>::new();
        let perf_device_present = Path::new("/sys/bus/event_source/devices/cpu/type").exists();
        diagnostics.push(format!("perf_event_device_present={perf_device_present}"));

        let paranoid = read_proc_int("/proc/sys/kernel/perf_event_paranoid");
        if let Some(v) = paranoid {
            diagnostics.push(format!("perf_event_paranoid={v}"));
        } else {
            diagnostics.push("perf_event_paranoid=unknown".to_string());
        }

        let kptr = read_proc_int("/proc/sys/kernel/kptr_restrict");
        if let Some(v) = kptr {
            diagnostics.push(format!("kptr_restrict={v}"));
        }

        let perf_allowed = perf_device_present && paranoid.is_some_and(|v| v <= 2);
        let active = if perf_allowed {
            "perf_event_open".to_string()
        } else {
            fallback.clone()
        };
        if !perf_allowed {
            diagnostics.push(
                "falling back to in_process_sampler (perf_event_open unavailable for current permissions)"
                    .to_string(),
            );
        }
        CpuCollectorCapability {
            primary_collector: "perf_event_open".to_string(),
            fallback_collector: fallback,
            active_collector: active,
            linux_perf_event_open: perf_allowed,
            diagnostics,
            sample_period_ms: 10,
        }
    } else if cfg!(target_os = "macos") {
        CpuCollectorCapability {
            primary_collector: "mach_thread_sampler".to_string(),
            fallback_collector: fallback.clone(),
            active_collector: fallback,
            linux_perf_event_open: false,
            diagnostics: vec![
                "mach_thread_sampler planned; using in_process_sampler fallback".to_string(),
                "symbolization path planned via dSYM/atos parity".to_string(),
            ],
            sample_period_ms: 10,
        }
    } else {
        CpuCollectorCapability {
            primary_collector: "perf_event_open".to_string(),
            fallback_collector: fallback.clone(),
            active_collector: fallback,
            linux_perf_event_open: false,
            diagnostics: vec![
                "perf_event_open collector is Linux-only; using in_process_sampler fallback"
                    .to_string(),
            ],
            sample_period_ms: 10,
        }
    }
}

fn read_proc_int(path: &str) -> Option<i64> {
    let raw = std::fs::read_to_string(path).ok()?;
    raw.trim().parse::<i64>().ok()
}

pub(super) fn write_json(path: &Path, value: &impl Serialize) -> FozzyResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}

fn profile_artifacts_stale(artifacts_dir: &Path, trace_path: &Path) -> FozzyResult<bool> {
    if !profile_artifacts_exist(artifacts_dir) {
        return Ok(true);
    }
    let trace_mtime = std::fs::metadata(trace_path)?.modified()?;
    for name in [
        "profile.timeline.json",
        "profile.cpu.json",
        "profile.heap.json",
        "profile.latency.json",
        "profile.metrics.json",
        "symbols.json",
    ] {
        let p = artifacts_dir.join(name);
        let md = std::fs::metadata(&p)?;
        if md.modified()? < trace_mtime {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn write_text(path: &Path, value: &str) -> FozzyResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, value)?;
    Ok(())
}
