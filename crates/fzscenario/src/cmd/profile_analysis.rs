use super::*;

pub(super) fn compute_diff(
    left: &str,
    right: &str,
    domains: &[String],
    l: &ProfileMetrics,
    r: &ProfileMetrics,
    l_heap: Option<&HeapProfile>,
    r_heap: Option<&HeapProfile>,
    l_stats: &HashMap<String, MetricStats>,
    r_stats: &HashMap<String, MetricStats>,
    left_samples: usize,
    right_samples: usize,
) -> ProfileDiff {
    let mut regressions = Vec::<RegressionFinding>::new();

    for domain in domains {
        let pairs: Vec<(&str, f64, f64)> = match domain.as_str() {
            "cpu" => vec![("cpu_time_ms", l.cpu_time_ms as f64, r.cpu_time_ms as f64)],
            "heap" => vec![
                ("alloc_bytes", l.alloc_bytes as f64, r.alloc_bytes as f64),
                ("in_use_bytes", l.in_use_bytes as f64, r.in_use_bytes as f64),
            ],
            "latency" => vec![
                (
                    "p95_latency_ms",
                    l.p95_latency_ms as f64,
                    r.p95_latency_ms as f64,
                ),
                (
                    "p99_latency_ms",
                    l.p99_latency_ms as f64,
                    r.p99_latency_ms as f64,
                ),
                (
                    "max_latency_ms",
                    l.max_latency_ms as f64,
                    r.max_latency_ms as f64,
                ),
            ],
            "io" => vec![("io_ops", l.io_ops as f64, r.io_ops as f64)],
            "sched" => vec![("sched_ops", l.sched_ops as f64, r.sched_ops as f64)],
            _ => Vec::new(),
        };
        for (metric, lv, rv) in pairs {
            let delta = rv - lv;
            let delta_pct = if lv.abs() < f64::EPSILON {
                if rv.abs() < f64::EPSILON { 0.0 } else { 100.0 }
            } else {
                (delta / lv) * 100.0
            };
            let time_domain = metric_time_domain(metric);
            let confidence = regression_confidence(metric, delta, l_stats, r_stats);
            let (classification, is_regression, is_significant, severity, analysis) =
                classify_regression(metric, delta, delta_pct, confidence, time_domain);
            regressions.push(RegressionFinding {
                domain: domain.clone(),
                metric: metric.to_string(),
                left_value: lv,
                right_value: rv,
                delta,
                delta_pct,
                classification,
                is_regression,
                is_significant,
                severity,
                analysis,
                time_domain: time_domain.to_string(),
                confidence,
                confidence_meta: Some(confidence_meta(metric, l_stats, r_stats)),
            });
        }
        if domain == "heap"
            && let (Some(left_heap), Some(right_heap)) = (l_heap, r_heap)
        {
            regressions.extend(heap_callsite_regressions(
                left_heap, right_heap, l_stats, r_stats,
            ));
        }
    }

    regressions.sort_by(|a, b| {
        regression_priority_score(b)
            .partial_cmp(&regression_priority_score(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b.delta
                    .abs()
                    .partial_cmp(&a.delta.abs())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.metric.cmp(&b.metric))
    });

    let regression_count = regressions.iter().filter(|r| r.is_regression).count();
    let improvement_count = regressions
        .iter()
        .filter(|r| r.classification == "improvement")
        .count();
    let significant_regression_count = regressions
        .iter()
        .filter(|r| r.is_regression && r.is_significant)
        .count();
    let top_regression_metric = regressions
        .iter()
        .find(|r| r.is_regression)
        .map(|r| r.metric.clone());
    let verdict = if significant_regression_count > 0 {
        "regression_detected"
    } else if regression_count > 0 {
        "minor_regression"
    } else if improvement_count > 0 {
        "improvement"
    } else {
        "stable"
    };

    ProfileDiff {
        schema_version: "fozzy.profile_diff.v2".to_string(),
        left: left.to_string(),
        right: right.to_string(),
        left_samples,
        right_samples,
        domains: domains.to_vec(),
        summary: DiffSummary {
            verdict: verdict.to_string(),
            regression_count,
            improvement_count,
            significant_regression_count,
            top_regression_metric,
        },
        regressions,
    }
}

pub(super) fn heap_callsite_regressions(
    left: &HeapProfile,
    right: &HeapProfile,
    l_stats: &HashMap<String, MetricStats>,
    r_stats: &HashMap<String, MetricStats>,
) -> Vec<RegressionFinding> {
    let mut left_map = BTreeMap::<String, &HeapCallsite>::new();
    let mut right_map = BTreeMap::<String, &HeapCallsite>::new();
    for callsite in &left.hotspots {
        left_map.insert(callsite.callsite_hash.clone(), callsite);
    }
    for callsite in &right.hotspots {
        right_map.insert(callsite.callsite_hash.clone(), callsite);
    }
    let mut keys = BTreeSet::<String>::new();
    keys.extend(left_map.keys().cloned());
    keys.extend(right_map.keys().cloned());

    let mut out = Vec::<RegressionFinding>::new();
    for hash in keys {
        let l = left_map.get(&hash).copied();
        let r = right_map.get(&hash).copied();
        let pairs = [
            (
                format!("callsite:{hash}.alloc_bytes"),
                l.map(|v| v.alloc_bytes as f64).unwrap_or(0.0),
                r.map(|v| v.alloc_bytes as f64).unwrap_or(0.0),
            ),
            (
                format!("callsite:{hash}.in_use_bytes"),
                l.map(|v| v.in_use_bytes as f64).unwrap_or(0.0),
                r.map(|v| v.in_use_bytes as f64).unwrap_or(0.0),
            ),
            (
                format!("callsite:{hash}.alloc_rate_per_sec"),
                l.map(|v| v.alloc_rate_per_sec).unwrap_or(0.0),
                r.map(|v| v.alloc_rate_per_sec).unwrap_or(0.0),
            ),
        ];
        for (metric, lv, rv) in pairs {
            let delta = rv - lv;
            if delta.abs() < f64::EPSILON {
                continue;
            }
            let delta_pct = if lv.abs() < f64::EPSILON {
                100.0
            } else {
                (delta / lv) * 100.0
            };
            let time_domain = metric_time_domain("alloc_bytes");
            let confidence = regression_confidence("alloc_bytes", delta, l_stats, r_stats);
            let (classification, is_regression, is_significant, severity, analysis) =
                classify_regression("alloc_bytes", delta, delta_pct, confidence, time_domain);
            out.push(RegressionFinding {
                domain: "heap".to_string(),
                metric,
                left_value: lv,
                right_value: rv,
                delta,
                delta_pct,
                classification,
                is_regression,
                is_significant,
                severity,
                analysis,
                time_domain: time_domain.to_string(),
                confidence,
                confidence_meta: Some(confidence_meta("alloc_bytes", l_stats, r_stats)),
            });
        }
    }
    out
}

pub(super) fn metric_time_domain(metric: &str) -> &'static str {
    if metric == "cpu_time_ms" || metric == "host_time_ms" {
        "host_monotonic_time"
    } else {
        "virtual_time"
    }
}

pub(super) fn confidence_meta(
    metric: &str,
    l_stats: &HashMap<String, MetricStats>,
    r_stats: &HashMap<String, MetricStats>,
) -> ConfidenceMeta {
    let l = l_stats.get(metric).cloned().unwrap_or_default();
    let r = r_stats.get(metric).cloned().unwrap_or_default();
    let pooled_std_err =
        ((l.std_dev.powi(2) / l.n.max(1) as f64) + (r.std_dev.powi(2) / r.n.max(1) as f64)).sqrt();
    ConfidenceMeta {
        method: if metric_time_domain(metric) == "host_monotonic_time" {
            "effect_size_over_pooled_stderr".to_string()
        } else {
            "deterministic_domain".to_string()
        },
        left_sample_count: l.n,
        right_sample_count: r.n,
        left_std_dev: l.std_dev,
        right_std_dev: r.std_dev,
        pooled_std_err,
    }
}

pub(super) fn regression_confidence(
    metric: &str,
    delta: f64,
    l_stats: &HashMap<String, MetricStats>,
    r_stats: &HashMap<String, MetricStats>,
) -> f64 {
    if metric_time_domain(metric) == "virtual_time" {
        return 1.0;
    }
    let meta = confidence_meta(metric, l_stats, r_stats);
    if meta.left_sample_count < 2 || meta.right_sample_count < 2 {
        return 0.75;
    }
    if meta.pooled_std_err <= f64::EPSILON {
        return 0.99;
    }
    let effect = delta.abs() / meta.pooled_std_err;
    (effect / (1.0 + effect)).clamp(0.5, 0.99)
}

pub(super) fn classify_regression(
    metric: &str,
    delta: f64,
    delta_pct: f64,
    confidence: f64,
    time_domain: &str,
) -> (String, bool, bool, String, String) {
    let classification = if delta > 0.0 {
        "regression"
    } else if delta < 0.0 {
        "improvement"
    } else {
        "stable"
    };
    let abs_pct = delta_pct.abs();
    let abs_delta = delta.abs();
    let significant = if time_domain == "virtual_time" {
        abs_delta >= 1.0 && abs_pct >= 2.0
    } else {
        confidence >= 0.8 && abs_pct >= 5.0
    };
    let is_regression = classification == "regression";
    let severity = if classification == "stable" || !significant {
        "none"
    } else if abs_pct >= 30.0 {
        "critical"
    } else if abs_pct >= 15.0 {
        "high"
    } else if abs_pct >= 5.0 {
        "medium"
    } else {
        "low"
    };
    let analysis = if classification == "stable" {
        format!("{metric} unchanged")
    } else if time_domain == "virtual_time" {
        format!(
            "deterministic-domain change {} with replay-stable confidence",
            format_metric_value(delta)
        )
    } else {
        format!(
            "host-time change {} at confidence {}",
            format_metric_value(delta),
            format_metric_value(confidence)
        )
    };
    (
        classification.to_string(),
        is_regression,
        significant,
        severity.to_string(),
        analysis,
    )
}

pub(super) fn regression_priority_score(finding: &RegressionFinding) -> f64 {
    let severity = match finding.severity.as_str() {
        "critical" => 4.0,
        "high" => 3.0,
        "medium" => 2.0,
        "low" => 1.0,
        _ => 0.0,
    };
    let class = match finding.classification.as_str() {
        "regression" => 2.0,
        "improvement" => 1.0,
        _ => 0.0,
    };
    severity * 10.0 + class + finding.confidence
}

pub(super) fn explain_single(
    run: &str,
    artifacts_dir: &Path,
    metrics: &ProfileMetrics,
    latency: &LatencyProfile,
) -> ProfileExplain {
    let top_path = latency
        .critical_path
        .first()
        .map(|p| format!("{} -> {} ({}ms)", p.from_span, p.to_span, p.duration_ms))
        .unwrap_or_else(|| "no critical path edges".to_string());
    let top_reason = latency
        .critical_path
        .first()
        .map(|p| p.reason.clone())
        .unwrap_or_else(|| "other".to_string());

    let domain = if matches!(
        top_reason.as_str(),
        "io" | "sched" | "heap" | "payload" | "cpu"
    ) {
        top_reason.as_str()
    } else if metrics.alloc_bytes > 0 {
        "heap"
    } else if metrics.io_ops > 0 {
        "io"
    } else {
        "sched"
    };

    ProfileExplain {
        schema_version: "fozzy.profile_explain.v1".to_string(),
        run: run.to_string(),
        regression_statement: format!(
            "run {} shows p50/p95/p99/max={}/{}/{}/{}ms, alloc_bytes={}, io_ops={}, sched_ops={}",
            metrics.run_id,
            metrics.p50_latency_ms,
            metrics.p95_latency_ms,
            metrics.p99_latency_ms,
            metrics.max_latency_ms,
            metrics.alloc_bytes,
            metrics.io_ops,
            metrics.sched_ops
        ),
        top_shifted_path: top_path,
        likely_cause_domain: domain.to_string(),
        evidence_pointers: vec![
            format!("{}/profile.metrics.json", artifacts_dir.display()),
            format!("{}/profile.latency.json", artifacts_dir.display()),
            format!("{}/profile.heap.json", artifacts_dir.display()),
        ],
    }
}

pub(super) fn explain_from_diff(
    left: &str,
    right: &str,
    l: &ProfileMetrics,
    r: &ProfileMetrics,
) -> ProfileExplain {
    let diff = compute_diff(
        left,
        right,
        &[
            "cpu".to_string(),
            "heap".to_string(),
            "latency".to_string(),
            "io".to_string(),
            "sched".to_string(),
        ],
        l,
        r,
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
        1,
        1,
    );
    let top = diff.regressions.first();
    let (statement, path, domain) = if let Some(top) = top {
        let cause_domain = if top.metric.contains("latency") {
            "latency".to_string()
        } else if top.metric.contains("alloc") || top.metric.contains("in_use") {
            "heap".to_string()
        } else {
            top.domain.clone()
        };
        (
            format!(
                "{} {} changed from {:.2} to {:.2} ({:+.2}%)",
                top.domain, top.metric, top.left_value, top.right_value, top.delta_pct
            ),
            format!("metric::{}", top.metric),
            cause_domain,
        )
    } else {
        (
            "no measurable regression shift found".to_string(),
            "n/a".to_string(),
            "unknown".to_string(),
        )
    };

    ProfileExplain {
        schema_version: "fozzy.profile_explain.v1".to_string(),
        run: left.to_string(),
        regression_statement: statement,
        top_shifted_path: path,
        likely_cause_domain: domain,
        evidence_pointers: vec![
            "profile.metrics.json".to_string(),
            "profile.latency.json".to_string(),
            "profile.cpu.json".to_string(),
            "profile.heap.json".to_string(),
        ],
    }
}

pub(super) fn metric_value(metric: ProfileMetric, trace: &TraceFile) -> FozzyResult<f64> {
    let timeline = build_profile_timeline(trace);
    let value = match metric {
        ProfileMetric::P99Latency => {
            build_latency_profile(trace, &timeline).distribution.p99_ms as f64
        }
        ProfileMetric::CpuTime => build_cpu_profile(trace, &timeline)
            .folded_stacks
            .iter()
            .map(|f| f.weight as f64)
            .sum(),
        ProfileMetric::AllocBytes => build_heap_profile(trace, &timeline).total_alloc_bytes as f64,
    };
    Ok(value)
}

pub(super) fn format_metric_value(value: f64) -> String {
    let normalized = if value == 0.0 { 0.0 } else { value };
    let mut out = format!("{normalized:.6}");
    while out.contains('.') && out.ends_with('0') {
        out.pop();
    }
    if out.ends_with('.') {
        out.pop();
    }
    out
}

pub(super) fn normalize_metric_value(value: f64) -> f64 {
    if value == 0.0 { 0.0 } else { value }
}

pub(super) fn shrink_minimize_name(minimize: ShrinkMinimize) -> &'static str {
    match minimize {
        ShrinkMinimize::Input => "input",
        ShrinkMinimize::Schedule => "schedule",
        ShrinkMinimize::Faults => "faults",
        ShrinkMinimize::All => "all",
    }
}
