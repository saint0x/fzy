//! Deterministic profiler commands (`fozzy profile ...`).

#[path = "profile_analysis.rs"]
mod profile_analysis;
#[path = "profile_build.rs"]
mod profile_build;
#[path = "profile_dispatch.rs"]
mod profile_dispatch;
#[path = "profile_render.rs"]
mod profile_render;
#[path = "profile_support.rs"]
mod profile_support;
#[path = "profile_types.rs"]
mod profile_types;

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use profile_analysis::{
    compute_diff, explain_from_diff, explain_single, format_metric_value, metric_value,
    normalize_metric_value, shrink_minimize_name,
};
use profile_build::{
    build_cpu_profile, build_heap_profile, build_latency_profile, build_profile_metrics,
    build_profile_timeline, build_symbols_map,
};
use profile_render::{
    folded_to_speedscope, folded_to_svg, folded_to_text, heap_folded, timeline_html,
};
use profile_support::{
    empty_domain, enforce_cpu_contract, load_profile_bundle, load_profile_bundle_group,
    normalize_domains, parse_selector_group, profile_doctor, profile_env_report,
    resolve_profile_trace, top_by_tag, write_json, write_text,
};
pub use profile_types::*;

pub use profile_build::heap_budget_findings_from_trace;

use crate::{
    Config, Finding, FindingKind, FozzyError, FozzyResult, RunManifest, RunSummary, ShrinkMinimize,
    ShrinkOptions, TraceFile, TracePath, resolve_artifacts_dir, shrink_trace,
    shrink_trace_with_predicate,
};

const RUN_OR_TRACE_HELP: &str =
    "Run selector: run id, trace path (*.fozzy), or alias (latest|last-pass|last-fail).";
const RUN_OR_TRACE_LONG_HELP: &str = "Accepted forms:\n- run id directory under .fozzy/runs/<run-id>\n- direct trace path (*.fozzy)\n- aliases: latest, last-pass, last-fail\nResolution order:\n1) existing *.fozzy path\n2) .fozzy/runs/<selector>/trace.fozzy\n3) tracePath from report.json\n4) tracePath from manifest.json\n5) existing profile artifacts in the run directory";

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Show top profiler hotspots and metrics.
    Top {
        #[arg(
            value_name = "RUN_OR_TRACE",
            help = RUN_OR_TRACE_HELP,
            long_help = RUN_OR_TRACE_LONG_HELP
        )]
        run: String,
        #[arg(long)]
        cpu: bool,
        #[arg(long)]
        heap: bool,
        #[arg(long)]
        latency: bool,
        #[arg(long)]
        io: bool,
        #[arg(long)]
        sched: bool,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Export flamegraph-compatible data.
    Flame {
        #[arg(
            value_name = "RUN_OR_TRACE",
            help = RUN_OR_TRACE_HELP,
            long_help = RUN_OR_TRACE_LONG_HELP
        )]
        run: String,
        #[arg(long)]
        cpu: bool,
        #[arg(long)]
        heap: bool,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "folded")]
        format: ProfileFlameFormat,
    },
    /// Export canonical profiler timeline.
    Timeline {
        #[arg(
            value_name = "RUN_OR_TRACE",
            help = RUN_OR_TRACE_HELP,
            long_help = RUN_OR_TRACE_LONG_HELP
        )]
        run: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "json")]
        format: ProfileTimelineFormat,
    },
    /// Compare two profiler runs/traces.
    Diff {
        #[arg(
            value_name = "LEFT_RUN_OR_TRACE",
            help = RUN_OR_TRACE_HELP,
            long_help = RUN_OR_TRACE_LONG_HELP
        )]
        left: String,
        #[arg(
            value_name = "RIGHT_RUN_OR_TRACE",
            help = RUN_OR_TRACE_HELP,
            long_help = RUN_OR_TRACE_LONG_HELP
        )]
        right: String,
        #[arg(long)]
        cpu: bool,
        #[arg(long)]
        heap: bool,
        #[arg(long)]
        latency: bool,
        #[arg(long)]
        io: bool,
        #[arg(long)]
        sched: bool,
    },
    /// Explain likely root causes for runtime behavior or regression.
    Explain {
        #[arg(
            value_name = "RUN_OR_TRACE",
            help = RUN_OR_TRACE_HELP,
            long_help = RUN_OR_TRACE_LONG_HELP
        )]
        run: String,
        #[arg(long = "diff-with")]
        diff_with: Option<String>,
    },
    /// Export profiler data into external formats.
    Export {
        #[arg(
            value_name = "RUN_OR_TRACE",
            help = RUN_OR_TRACE_HELP,
            long_help = RUN_OR_TRACE_LONG_HELP
        )]
        run: String,
        #[arg(long)]
        format: ProfileExportFormat,
        #[arg(long)]
        out: PathBuf,
    },
    /// Shrink a trace while preserving a profiler metric direction.
    Shrink {
        #[arg(
            value_name = "RUN_OR_TRACE",
            help = RUN_OR_TRACE_HELP,
            long_help = RUN_OR_TRACE_LONG_HELP
        )]
        run: String,
        #[arg(long)]
        metric: ProfileMetric,
        #[arg(long)]
        direction: ProfileDirection,
        #[arg(long)]
        budget: Option<crate::FozzyDuration>,
        #[arg(long, value_enum, default_value = "all")]
        minimize: ShrinkMinimize,
    },
    /// Show profiler capability visibility for this host/backend setup.
    Env,
    /// Run one-shot profile sanity checks for a run/trace.
    Doctor {
        #[arg(
            value_name = "RUN_OR_TRACE",
            help = RUN_OR_TRACE_HELP,
            long_help = RUN_OR_TRACE_LONG_HELP
        )]
        run: String,
        /// Include expensive shrink + metric-preservation checks.
        #[arg(long)]
        deep: bool,
    },
}

pub fn profile_command(
    config: &Config,
    command: &ProfileCommand,
    strict: bool,
) -> FozzyResult<serde_json::Value> {
    profile_dispatch::dispatch_profile_command(config, command, strict)
}

fn profile_contract_or_error(
    strict: bool,
    command: &str,
    selector: &str,
    err: FozzyError,
) -> FozzyResult<serde_json::Value> {
    if strict {
        return Err(err);
    }
    match err {
        FozzyError::InvalidArgument(msg) => Ok(serde_json::json!({
            "schemaVersion": "fozzy.profile_contract_warning.v1",
            "status": "warn",
            "command": command,
            "run": selector,
            "detail": msg,
            "hint": "rerun with --strict for hard-fail contract enforcement",
        })),
        other => Err(other),
    }
}

fn relaxed_cpu_warning(_strict: bool, cpu_requested: bool) -> Option<String> {
    if !cpu_requested {
        return None;
    }
    Some(
        "cpu domain uses host-time sampling and is non-deterministic per replay; compare across repeated deterministic replays"
            .to_string(),
    )
}

pub fn write_profile_artifacts_from_trace(
    trace: &TraceFile,
    artifacts_dir: &Path,
) -> FozzyResult<()> {
    std::fs::create_dir_all(artifacts_dir)?;
    let timeline = build_profile_timeline(trace);
    let cpu = build_cpu_profile(trace, &timeline);
    let heap = build_heap_profile(trace, &timeline);
    let latency = build_latency_profile(trace, &timeline);
    let symbols = build_symbols_map(trace, &timeline, &cpu);
    let metrics = build_profile_metrics(trace, &timeline, &cpu, &heap, &latency);

    write_json(
        &artifacts_dir.join("profile.timeline.json"),
        &ProfileTimelineArtifact {
            schema_version: "fozzy.profile_timeline_artifact.v3".to_string(),
            run_id: trace.summary.identity.run_id.clone(),
            time_domains: TimeDomains {
                virtual_time: "deterministic, replay-critical timeline derived from virtual clock"
                    .to_string(),
                host_monotonic_time:
                    "non-deterministic host monotonic ordering used for performance comparison"
                        .to_string(),
            },
            events: timeline,
        },
    )?;
    write_json(&artifacts_dir.join("profile.cpu.json"), &cpu)?;
    write_json(&artifacts_dir.join("profile.heap.json"), &heap)?;
    write_json(&artifacts_dir.join("profile.latency.json"), &latency)?;
    write_json(&artifacts_dir.join("profile.metrics.json"), &metrics)?;
    write_json(&artifacts_dir.join("symbols.json"), &symbols)?;
    Ok(())
}

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
