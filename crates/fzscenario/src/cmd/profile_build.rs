use super::profile_support::detect_cpu_collector_capability;
use super::*;

pub(super) fn build_profile_timeline(trace: &TraceFile) -> Vec<ProfileEvent> {
    let run_id = trace.summary.identity.run_id.clone();
    let seed = trace.summary.identity.seed;
    let mut out = Vec::new();
    let mut open_spans = Vec::<String>::new();
    for (idx, event) in trace.events.iter().enumerate() {
        let kind = map_event_kind(&event.name);
        let t_next = trace.events.get(idx + 1).map(|n| n.time_ms);
        let duration = t_next.and_then(|n| n.checked_sub(event.time_ms));
        let mut tags = BTreeMap::new();
        tags.insert("name".to_string(), event.name.clone());
        for (k, v) in &event.fields {
            match v {
                serde_json::Value::String(s) => {
                    tags.insert(k.clone(), s.clone());
                }
                serde_json::Value::Number(n) => {
                    tags.insert(k.clone(), n.to_string());
                }
                serde_json::Value::Bool(b) => {
                    tags.insert(k.clone(), b.to_string());
                }
                _ => {}
            }
        }
        let bytes = event
            .fields
            .get("bytes")
            .and_then(|v| v.as_u64())
            .or_else(|| event.fields.get("payload_size").and_then(|v| v.as_u64()));
        let task = event
            .fields
            .get("task")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let explicit_span = event
            .fields
            .get("span")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let mut span_id = explicit_span.unwrap_or_else(|| {
            open_spans
                .last()
                .cloned()
                .unwrap_or_else(|| format!("e-{idx}"))
        });
        let mut parent_span_id = event
            .fields
            .get("parent_span")
            .and_then(|v| v.as_str())
            .map(ToString::to_string)
            .or_else(|| {
                if matches!(kind, ProfileEventKind::SpanStart) {
                    open_spans.last().cloned()
                } else {
                    None
                }
            });
        if matches!(kind, ProfileEventKind::SpanStart) {
            if !open_spans.contains(&span_id) {
                open_spans.push(span_id.clone());
            }
        } else if matches!(kind, ProfileEventKind::SpanEnd) {
            if let Some(explicit) = event.fields.get("span").and_then(|v| v.as_str()) {
                span_id = explicit.to_string();
                if let Some(pos) = open_spans.iter().rposition(|s| s == explicit) {
                    parent_span_id = if pos > 0 {
                        open_spans.get(pos - 1).cloned()
                    } else {
                        None
                    };
                    open_spans.remove(pos);
                }
            }
        } else if parent_span_id.is_none() {
            parent_span_id = open_spans.last().cloned();
        }
        out.push(ProfileEvent {
            t_virtual: event.time_ms,
            t_mono: Some(idx as u64),
            kind,
            run_id: run_id.clone(),
            seed,
            thread: event
                .fields
                .get("thread")
                .and_then(|v| v.as_str())
                .unwrap_or("main")
                .to_string(),
            task,
            span_id,
            parent_span_id,
            tags,
            cost: ProfileCost {
                duration_ms: duration,
                bytes,
                count: Some(1),
            },
        });
    }
    out
}

fn map_event_kind(name: &str) -> ProfileEventKind {
    match name {
        "span_start" => ProfileEventKind::SpanStart,
        "span_end" => ProfileEventKind::SpanEnd,
        "sample" => ProfileEventKind::Sample,
        "memory_alloc" => ProfileEventKind::Alloc,
        "memory_free" => ProfileEventKind::Free,
        "http_request" | "proc_spawn" | "capability_http" | "capability_proc" | "capability_fs" => {
            ProfileEventKind::Io
        }
        "net_send" | "net_drop" | "net_deliver" | "capability_net" => ProfileEventKind::Net,
        "deliver" | "partition" | "heal" | "crash" | "restart" | "sched_pick" | "sched_wait"
        | "sched_starvation" => ProfileEventKind::Sched,
        _ => ProfileEventKind::Event,
    }
}

pub(super) fn build_cpu_profile(trace: &TraceFile, timeline: &[ProfileEvent]) -> CpuProfile {
    let capability = detect_cpu_collector_capability();
    let mut stacks = HashMap::<String, u64>::new();
    let mut samples = build_cpu_samples(timeline, capability.sample_period_ms);
    if samples.is_empty() {
        for event in timeline {
            let stack_parts = vec![
                "fozzy::runtime".to_string(),
                format!(
                    "event::{}",
                    event.tags.get("name").cloned().unwrap_or_default()
                ),
            ];
            let weight = event.cost.duration_ms.unwrap_or(1).max(1);
            samples.push(CpuSample {
                thread: event.thread.clone(),
                stack: stack_parts,
                weight_ms: weight,
            });
        }
    }
    for sample in &samples {
        let stack = sample.stack.join(";");
        *stacks.entry(stack).or_insert(0) += sample.weight_ms.max(1);
    }

    let mut folded_stacks: Vec<FoldedStack> = stacks
        .into_iter()
        .map(|(stack, weight)| FoldedStack { stack, weight })
        .collect();
    folded_stacks.sort_by(|a, b| b.weight.cmp(&a.weight).then_with(|| a.stack.cmp(&b.stack)));

    CpuProfile {
        schema_version: "fozzy.profile_cpu.v2".to_string(),
        run_id: trace.summary.identity.run_id.clone(),
        collector: CpuCollectorInfo {
            domain: "host_time".to_string(),
            primary_collector: capability.primary_collector,
            fallback_collector: capability.fallback_collector,
            active_collector: capability.active_collector,
            host_time_semantics: "host-time CPU samples are not replay-deterministic; compare distributions across repeated deterministic replays".to_string(),
            linux_perf_event_open: capability.linux_perf_event_open,
            diagnostics: capability.diagnostics,
            macos_parity_checklist: vec![
                "collector: mach thread sampling wired".to_string(),
                "symbols: atos/dsym resolution parity".to_string(),
                "exports: folded/speedscope/pprof parity".to_string(),
            ],
        },
        sample_period_ms: capability.sample_period_ms,
        sample_count: samples.len(),
        samples,
        folded_stacks,
        symbols_ref: "symbols.json".to_string(),
    }
}

fn build_cpu_samples(timeline: &[ProfileEvent], sample_period_ms: u64) -> Vec<CpuSample> {
    let mut samples = Vec::<CpuSample>::new();

    for event in timeline {
        if event.kind != ProfileEventKind::Sample {
            continue;
        }
        let stack = event
            .tags
            .get("stack")
            .map(|s| {
                s.split(';')
                    .filter(|f| !f.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|frames| !frames.is_empty())
            .unwrap_or_else(|| vec!["fozzy::runtime".to_string(), "sample::unknown".to_string()]);
        let weight = event
            .tags
            .get("weight_ms")
            .and_then(|v| v.parse::<u64>().ok())
            .or(event.cost.duration_ms)
            .unwrap_or(sample_period_ms)
            .max(1);
        samples.push(CpuSample {
            thread: event.thread.clone(),
            stack,
            weight_ms: weight,
        });
    }

    if !samples.is_empty() {
        return samples;
    }

    let mut span_step_kind = HashMap::<String, String>::new();
    for event in timeline {
        if event.kind == ProfileEventKind::SpanStart
            && let Some(span) = event.tags.get("span")
        {
            let step_kind = event
                .tags
                .get("step_kind")
                .cloned()
                .or_else(|| event.tags.get("task").cloned())
                .or_else(|| event.tags.get("name").cloned())
                .unwrap_or_else(|| "unknown".to_string());
            span_step_kind.insert(span.clone(), step_kind);
        }
    }

    for event in timeline {
        if event.kind != ProfileEventKind::SpanEnd {
            continue;
        }
        let step_kind = event
            .tags
            .get("span")
            .and_then(|span| span_step_kind.get(span).cloned())
            .or_else(|| event.tags.get("step_kind").cloned())
            .or_else(|| event.tags.get("task").cloned())
            .or_else(|| event.tags.get("name").cloned())
            .unwrap_or_else(|| "unknown".to_string());
        let weight = event
            .tags
            .get("duration_ms")
            .and_then(|v| v.parse::<u64>().ok())
            .or(event.cost.duration_ms)
            .unwrap_or(sample_period_ms)
            .max(1);
        samples.push(CpuSample {
            thread: event.thread.clone(),
            stack: vec!["fozzy::runtime".to_string(), format!("step::{step_kind}")],
            weight_ms: weight,
        });
    }

    samples
}

pub(super) fn build_heap_profile(trace: &TraceFile, timeline: &[ProfileEvent]) -> HeapProfile {
    #[derive(Clone)]
    struct LiveAlloc {
        bytes: u64,
        callsite_hash: String,
        start: u64,
        end: Option<u64>,
    }

    let mut live = HashMap::<u64, LiveAlloc>::new();
    let mut completed: Vec<LiveAlloc> = Vec::new();

    for event in timeline {
        if event.kind == ProfileEventKind::Alloc {
            let alloc_id = event
                .tags
                .get("alloc_id")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let failed = event
                .tags
                .get("failed_reason")
                .is_some_and(|r| !r.is_empty() && r != "null");
            if failed || alloc_id == 0 {
                continue;
            }
            let callsite = event
                .tags
                .get("callsite_hash")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let bytes = event.cost.bytes.unwrap_or(0);
            live.insert(
                alloc_id,
                LiveAlloc {
                    bytes,
                    callsite_hash: callsite,
                    start: event.t_virtual,
                    end: None,
                },
            );
        } else if event.kind == ProfileEventKind::Free {
            let alloc_id = event
                .tags
                .get("alloc_id")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            if let Some(mut alloc) = live.remove(&alloc_id) {
                alloc.end = Some(event.t_virtual);
                completed.push(alloc);
            }
        }
    }

    let mut hotspots = HashMap::<String, HeapCallsite>::new();
    let mut total_alloc_bytes = 0u64;
    for alloc in live.values().chain(completed.iter()) {
        total_alloc_bytes = total_alloc_bytes.saturating_add(alloc.bytes);
        let entry = hotspots
            .entry(alloc.callsite_hash.clone())
            .or_insert(HeapCallsite {
                callsite_hash: alloc.callsite_hash.clone(),
                alloc_count: 0,
                alloc_bytes: 0,
                in_use_bytes: 0,
                alloc_rate_per_sec: 0.0,
            });
        entry.alloc_count = entry.alloc_count.saturating_add(1);
        entry.alloc_bytes = entry.alloc_bytes.saturating_add(alloc.bytes);
        if alloc.end.is_none() {
            entry.in_use_bytes = entry.in_use_bytes.saturating_add(alloc.bytes);
        }
    }

    let mut hotspot_list: Vec<HeapCallsite> = hotspots.into_values().collect();
    hotspot_list.sort_by(|a, b| {
        b.in_use_bytes
            .cmp(&a.in_use_bytes)
            .then_with(|| b.alloc_bytes.cmp(&a.alloc_bytes))
            .then_with(|| a.callsite_hash.cmp(&b.callsite_hash))
    });

    let end_t = timeline.last().map(|e| e.t_virtual).unwrap_or(0);
    let mut bins = BTreeMap::<String, u64>::new();
    let mut suspects = Vec::<RetentionSuspect>::new();

    for (alloc_id, alloc) in &live {
        let age = end_t.saturating_sub(alloc.start);
        suspects.push(RetentionSuspect {
            alloc_id: *alloc_id,
            callsite_hash: alloc.callsite_hash.clone(),
            bytes: alloc.bytes,
            age_ms: age,
            graph_anchor: format!("alloc:{alloc_id}"),
        });
    }
    suspects.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| b.age_ms.cmp(&a.age_ms)));

    for alloc in completed {
        let d = alloc.end.unwrap_or(alloc.start).saturating_sub(alloc.start);
        let bucket = if d <= 1 {
            "0-1ms"
        } else if d <= 10 {
            "2-10ms"
        } else if d <= 100 {
            "11-100ms"
        } else {
            "101ms+"
        };
        *bins.entry(bucket.to_string()).or_insert(0) += 1;
    }

    let lifetime_histogram = bins
        .into_iter()
        .map(|(bucket, count)| HistogramBin { bucket, count })
        .collect::<Vec<_>>();

    let in_use_bytes = live
        .values()
        .fold(0u64, |acc, a| acc.saturating_add(a.bytes));
    let span_s = (end_t.max(1) as f64) / 1000.0;
    let alloc_rate_per_sec = (total_alloc_bytes as f64) / span_s;
    for callsite in &mut hotspot_list {
        callsite.alloc_rate_per_sec = (callsite.alloc_bytes as f64) / span_s;
    }

    let trace_memory_in_use = trace
        .memory
        .as_ref()
        .map(|m| m.summary.in_use_bytes)
        .unwrap_or(0);

    HeapProfile {
        schema_version: "fozzy.profile_heap.v2".to_string(),
        run_id: trace.summary.identity.run_id.clone(),
        total_alloc_bytes,
        in_use_bytes: in_use_bytes.max(trace_memory_in_use),
        alloc_rate_per_sec,
        hotspots: hotspot_list,
        lifetime_histogram,
        retention_suspects: suspects,
    }
}

pub(super) fn build_latency_profile(
    trace: &TraceFile,
    timeline: &[ProfileEvent],
) -> LatencyProfile {
    #[derive(Debug, Clone)]
    struct SpanRec {
        span_id: String,
        parent: Option<String>,
        start: u64,
        duration: u64,
        wait_reason: String,
    }

    let mut starts = HashMap::<String, (&ProfileEvent, usize)>::new();
    let mut spans = Vec::<SpanRec>::new();
    let mut reasons = BTreeMap::<String, u64>::new();
    let mut io_edges = Vec::<CriticalPathEdge>::new();
    let mut sched_edges = Vec::<CriticalPathEdge>::new();

    for (idx, event) in timeline.iter().enumerate() {
        match event.kind {
            ProfileEventKind::SpanStart => {
                starts.insert(event.span_id.clone(), (event, idx));
            }
            ProfileEventKind::SpanEnd => {
                if let Some((start, start_idx)) = starts.remove(&event.span_id) {
                    let duration = event.t_virtual.saturating_sub(start.t_virtual);
                    let mut wait_reason = "other".to_string();
                    for inner in timeline
                        .iter()
                        .skip(start_idx)
                        .take(idx.saturating_sub(start_idx) + 1)
                    {
                        wait_reason = dominant_reason_for_event(inner).to_string();
                        if wait_reason != "other" {
                            break;
                        }
                    }
                    *reasons.entry(wait_reason.clone()).or_insert(0) += 1;
                    spans.push(SpanRec {
                        span_id: event.span_id.clone(),
                        parent: start.parent_span_id.clone(),
                        start: start.t_virtual,
                        duration,
                        wait_reason,
                    });
                }
            }
            ProfileEventKind::Io | ProfileEventKind::Net => {
                if let Some(parent) = event.parent_span_id.clone() {
                    io_edges.push(CriticalPathEdge {
                        from_span: parent,
                        to_span: event.span_id.clone(),
                        duration_ms: event.cost.duration_ms.unwrap_or(0),
                        reason: dominant_reason_for_event(event).to_string(),
                    });
                }
            }
            ProfileEventKind::Sched => {
                if let Some(parent) = event.parent_span_id.clone() {
                    sched_edges.push(CriticalPathEdge {
                        from_span: parent,
                        to_span: event.span_id.clone(),
                        duration_ms: event.cost.duration_ms.unwrap_or(0),
                        reason: "sched".to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| a.span_id.cmp(&b.span_id))
    });
    let mut deltas = spans.iter().map(|s| s.duration).collect::<Vec<_>>();
    let distribution = if deltas.is_empty() {
        LatencyDistribution {
            count: 0,
            p50_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
            max_ms: 0,
            variance: 0.0,
        }
    } else {
        deltas.sort_unstable();
        let max_ms = *deltas.last().unwrap_or(&0);
        let p50_ms = percentile(&deltas, 0.50);
        let p95_ms = percentile(&deltas, 0.95);
        let p99_ms = percentile(&deltas, 0.99);
        let mean = deltas.iter().copied().map(|v| v as f64).sum::<f64>() / (deltas.len() as f64);
        let variance = deltas
            .iter()
            .map(|v| {
                let d = (*v as f64) - mean;
                d * d
            })
            .sum::<f64>()
            / (deltas.len() as f64);
        LatencyDistribution {
            count: deltas.len(),
            p50_ms,
            p95_ms,
            p99_ms,
            max_ms,
            variance,
        }
    };

    let span_map = spans
        .iter()
        .map(|s| (s.span_id.clone(), s.clone()))
        .collect::<HashMap<_, _>>();
    let mut dependency_graph = Vec::<CriticalPathEdge>::new();
    for span in &spans {
        if let Some(parent) = &span.parent
            && let Some(p) = span_map.get(parent)
        {
            dependency_graph.push(CriticalPathEdge {
                from_span: parent.clone(),
                to_span: span.span_id.clone(),
                duration_ms: p.duration.saturating_add(span.duration),
                reason: "parent_child".to_string(),
            });
        }
    }
    dependency_graph.extend(io_edges);
    dependency_graph.extend(sched_edges);
    dependency_graph.sort_by(|a, b| {
        b.duration_ms
            .cmp(&a.duration_ms)
            .then_with(|| a.from_span.cmp(&b.from_span))
    });

    let mut critical_path = spans
        .iter()
        .map(|span| CriticalPathEdge {
            from_span: span.parent.clone().unwrap_or_else(|| "root".to_string()),
            to_span: span.span_id.clone(),
            duration_ms: span.duration,
            reason: span.wait_reason.clone(),
        })
        .collect::<Vec<_>>();
    critical_path.sort_by(|a, b| {
        b.duration_ms
            .cmp(&a.duration_ms)
            .then_with(|| a.from_span.cmp(&b.from_span))
    });

    let wait_reasons = reasons
        .into_iter()
        .map(|(reason, count)| ReasonCount { reason, count })
        .collect();
    let tail_amplification_suspects = spans
        .iter()
        .filter(|s| s.duration >= distribution.p95_ms.max(1))
        .map(|s| TailAmplificationSuspect {
            span_id: s.span_id.clone(),
            duration_ms: s.duration,
            reason: s.wait_reason.clone(),
        })
        .take(10)
        .collect::<Vec<_>>();

    LatencyProfile {
        schema_version: "fozzy.profile_latency.v1".to_string(),
        run_id: trace.summary.identity.run_id.clone(),
        distribution,
        dependency_graph,
        critical_path,
        wait_reasons,
        tail_amplification_suspects,
    }
}

fn dominant_reason_for_event(event: &ProfileEvent) -> &'static str {
    match event.kind {
        ProfileEventKind::Io => "io",
        ProfileEventKind::Sched => "sched",
        ProfileEventKind::Alloc | ProfileEventKind::Free => "heap",
        ProfileEventKind::Net => "payload",
        ProfileEventKind::Sample => "cpu",
        _ => "other",
    }
}

pub fn heap_budget_findings_from_trace(
    trace: &TraceFile,
    policy: &HeapBudgetPolicy,
) -> Vec<Finding> {
    let mut findings = Vec::<Finding>::new();
    if policy.alloc_bytes_budget.is_none() && policy.in_use_bytes_budget.is_none() {
        return findings;
    }
    let timeline = build_profile_timeline(trace);
    let heap = build_heap_profile(trace, &timeline);
    if let Some(budget) = policy.alloc_bytes_budget
        && heap.total_alloc_bytes > budget
    {
        findings.push(Finding {
            kind: FindingKind::Checker,
            title: "heap_alloc_budget".to_string(),
            message: format!(
                "heap allocation budget exceeded: alloc_bytes={} budget_bytes={}",
                heap.total_alloc_bytes, budget
            ),
            location: None,
        });
    }
    if let Some(budget) = policy.in_use_bytes_budget
        && heap.in_use_bytes > budget
    {
        findings.push(Finding {
            kind: FindingKind::Checker,
            title: "heap_in_use_budget".to_string(),
            message: format!(
                "heap in-use budget exceeded: in_use_bytes={} budget_bytes={}",
                heap.in_use_bytes, budget
            ),
            location: None,
        });
    }
    findings
}

pub(super) fn build_symbols_map(
    trace: &TraceFile,
    timeline: &[ProfileEvent],
    cpu: &CpuProfile,
) -> SymbolsMap {
    let mut symbols = BTreeSet::<String>::new();
    for event in timeline {
        if let Some(name) = event.tags.get("name") {
            symbols.insert(name.clone());
        }
    }
    for sample in &cpu.samples {
        for frame in &sample.stack {
            symbols.insert(frame.clone());
        }
    }
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|v| v.to_string_lossy().to_string()))
        .unwrap_or_else(|| "fozzy".to_string());
    SymbolsMap {
        schema_version: "fozzy.profile_symbols.v1".to_string(),
        run_id: trace.summary.identity.run_id.clone(),
        modules: vec![
            SymbolModule {
                name: "fozzy-runtime".to_string(),
                build_id: format!(
                    "{}-{}",
                    trace.engine.version,
                    trace.engine.commit.as_deref().unwrap_or("dev")
                ),
                symbols: symbols.iter().cloned().collect(),
            },
            SymbolModule {
                name: exe,
                build_id: trace
                    .engine
                    .commit
                    .clone()
                    .unwrap_or_else(|| "dev".to_string()),
                symbols: vec!["main".to_string(), "fozzy::runtime".to_string()],
            },
        ],
    }
}

pub(super) fn build_profile_metrics(
    trace: &TraceFile,
    timeline: &[ProfileEvent],
    cpu: &CpuProfile,
    heap: &HeapProfile,
    latency: &LatencyProfile,
) -> ProfileMetrics {
    let virtual_time_ms = timeline.last().map(|e| e.t_virtual).unwrap_or(0);
    let host_time_ms = trace.summary.duration_ms;
    let cpu_time_ms = cpu
        .folded_stacks
        .iter()
        .fold(0u64, |acc, s| acc.saturating_add(s.weight));
    let io_ops = timeline
        .iter()
        .filter(|e| e.kind == ProfileEventKind::Io || e.kind == ProfileEventKind::Net)
        .count() as u64;
    let sched_ops = timeline
        .iter()
        .filter(|e| e.kind == ProfileEventKind::Sched)
        .count() as u64;
    ProfileMetrics {
        schema_version: "fozzy.profile_metrics.v2".to_string(),
        run_id: trace.summary.identity.run_id.clone(),
        time_domains: TimeDomains {
            virtual_time: "deterministic, replay-critical".to_string(),
            host_monotonic_time: "non-deterministic, statistical comparison only".to_string(),
        },
        virtual_time_ms,
        host_time_ms,
        cpu_time_ms,
        alloc_bytes: heap.total_alloc_bytes,
        in_use_bytes: heap.in_use_bytes,
        p50_latency_ms: latency.distribution.p50_ms,
        p95_latency_ms: latency.distribution.p95_ms,
        p99_latency_ms: latency.distribution.p99_ms,
        max_latency_ms: latency.distribution.max_ms,
        io_ops,
        sched_ops,
        confidence: if host_time_ms == 0 {
            Some(0.0)
        } else {
            Some(0.8)
        },
    }
}

pub(super) fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
