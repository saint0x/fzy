//! CLI report commands (`fozzy report ...`).

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use std::path::PathBuf;

use crate::{
    Config, FlakeBudget, FozzyError, FozzyResult, ProfileCommand, Reporter, RunSummary, TraceFile,
    render_html, render_junit_xml,
};

#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    Show {
        run: String,
        #[arg(long, default_value = "pretty")]
        format: Reporter,
    },
    Query {
        run: String,
        #[arg(long)]
        jq: Option<String>,
        #[arg(long, default_value_t = false)]
        list_paths: bool,
    },
    Flaky {
        runs: Vec<String>,
        #[arg(long)]
        flake_budget: Option<FlakeBudget>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEnvelope {
    pub format: Reporter,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlakyReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runCount")]
    pub run_count: usize,
    #[serde(rename = "statusCounts")]
    pub status_counts: std::collections::BTreeMap<String, usize>,
    #[serde(rename = "findingTitleSets")]
    pub finding_title_sets: Vec<Vec<String>>,
    #[serde(rename = "isFlaky")]
    pub is_flaky: bool,
    #[serde(rename = "flakeRatePct")]
    pub flake_rate_pct: f64,
}

pub fn report_command(config: &Config, command: &ReportCommand) -> FozzyResult<serde_json::Value> {
    match command {
        ReportCommand::Show { run, format } => {
            let summary = load_summary(config, run)?;
            let doc = report_doc_with_profile(config, run, &summary);
            match format {
                Reporter::Json => Ok(doc),
                Reporter::Pretty => Ok(serde_json::to_value(ReportEnvelope {
                    format: *format,
                    content: render_pretty_with_profile(&summary, &doc),
                })?),
                Reporter::Junit => Ok(serde_json::to_value(ReportEnvelope {
                    format: *format,
                    content: render_junit_xml(&summary),
                })?),
                Reporter::Html => Ok(serde_json::to_value(ReportEnvelope {
                    format: *format,
                    content: render_html(&summary),
                })?),
            }
        }

        ReportCommand::Query {
            run,
            jq,
            list_paths,
        } => {
            let summary = load_summary(config, run)?;
            let value = report_doc_with_profile(config, run, &summary);
            if *list_paths {
                return Ok(serde_json::json!({
                    "paths": list_query_paths(&value)
                }));
            }
            let expr = jq.as_deref().ok_or_else(|| {
                FozzyError::Report(
                    "missing --jq expression (or pass --list-paths to inspect available paths)"
                        .to_string(),
                )
            })?;
            query_value(&value, expr)
        }
        ReportCommand::Flaky { runs, flake_budget } => flaky_command(config, runs, *flake_budget),
    }
}

fn report_doc_with_profile(config: &Config, run: &str, summary: &RunSummary) -> serde_json::Value {
    let mut value = serde_json::to_value(summary).unwrap_or_else(|_| serde_json::json!({}));
    let explain = crate::profile_command(
        config,
        &ProfileCommand::Explain {
            run: run.to_string(),
            diff_with: None,
        },
        false,
    )
    .ok();
    if let Some(obj) = value.as_object_mut()
        && let Some(explain) = explain
    {
        obj.insert("profileDiagnosis".to_string(), explain);
    }
    value
}

fn render_pretty_with_profile(summary: &RunSummary, doc: &serde_json::Value) -> String {
    let mut content = summary.pretty();
    if let Some(profile) = doc.get("profileDiagnosis") {
        let statement = profile
            .get("regressionStatement")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let path = profile
            .get("topShiftedPath")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let cause = profile
            .get("likelyCauseDomain")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !statement.is_empty() || !path.is_empty() || !cause.is_empty() {
            content.push_str("\nprofile:\n");
            if !statement.is_empty() {
                content.push_str(&format!("- regression_statement: {statement}\n"));
            }
            if !path.is_empty() {
                content.push_str(&format!("- top_shifted_path: {path}\n"));
            }
            if !cause.is_empty() {
                content.push_str(&format!("- likely_cause_domain: {cause}\n"));
            }
        }
    }
    content.trim_end().to_string()
}

fn flaky_command(
    config: &Config,
    runs: &[String],
    flake_budget: Option<FlakeBudget>,
) -> FozzyResult<serde_json::Value> {
    if runs.len() < 2 {
        return Err(FozzyError::Report(
            "flaky analysis requires at least two runs/traces".to_string(),
        ));
    }

    let mut status_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut finding_sets = std::collections::BTreeSet::<Vec<String>>::new();
    let mut signatures = std::collections::BTreeMap::<String, usize>::new();
    let mut seen_run_ids = std::collections::BTreeSet::<String>::new();

    for run in runs {
        let summary = load_summary(config, run)?;
        if !seen_run_ids.insert(summary.identity.run_id.clone()) {
            return Err(FozzyError::Report(format!(
                "duplicate run reference detected for runId={} (duplicates are not allowed in flaky analysis)",
                summary.identity.run_id
            )));
        }
        let status_key = format!("{:?}", summary.status).to_lowercase();
        *status_counts.entry(status_key.clone()).or_insert(0) += 1;

        let mut titles: Vec<String> = summary.findings.iter().map(|f| f.title.clone()).collect();
        titles.sort();
        titles.dedup();
        finding_sets.insert(titles);
        let sig = format!(
            "{status_key}|{}",
            summary
                .findings
                .iter()
                .map(|f| f.title.as_str())
                .collect::<Vec<_>>()
                .join("|")
        );
        *signatures.entry(sig).or_insert(0) += 1;
    }

    let is_flaky = status_counts.len() > 1 || finding_sets.len() > 1;
    let dominant = signatures.values().copied().max().unwrap_or(0) as f64;
    let total = runs.len() as f64;
    let flake_rate_pct = if total == 0.0 {
        0.0
    } else {
        ((total - dominant) / total) * 100.0
    };
    if let Some(budget) = flake_budget
        && flake_rate_pct > budget.pct()
    {
        return Err(FozzyError::Report(format!(
            "flake budget exceeded: {:.2}% > {:.2}%",
            flake_rate_pct,
            budget.pct()
        )));
    }
    let out = FlakyReport {
        schema_version: "fozzy.flaky_report.v1".to_string(),
        run_count: runs.len(),
        status_counts,
        finding_title_sets: finding_sets.into_iter().collect(),
        is_flaky,
        flake_rate_pct,
    };
    Ok(serde_json::to_value(out)?)
}

fn load_summary(config: &Config, run: &str) -> FozzyResult<RunSummary> {
    let artifacts_dir = crate::resolve_artifacts_dir(config, run)?;
    let report_json = artifacts_dir.join("report.json");
    if report_json.exists() {
        let bytes = std::fs::read(report_json)?;
        let summary: RunSummary = serde_json::from_slice(&bytes)?;
        return Ok(summary);
    }

    let input_path = PathBuf::from(run);
    let trace_path = if input_path.exists() {
        let is_trace = input_path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("fozzy"));
        if !is_trace {
            return Err(FozzyError::Report(format!(
                "invalid run identifier {run:?}: expected run id or .fozzy trace path"
            )));
        }
        input_path
    } else {
        artifacts_dir.join("trace.fozzy")
    };
    if trace_path.exists() {
        let trace = TraceFile::read_json(&trace_path)?;
        return Ok(trace.summary);
    }

    Err(FozzyError::Report(format!(
        "no report found for {run:?} (looked for {} and {})",
        report_json.display(),
        trace_path.display()
    )))
}

fn query_value(root: &serde_json::Value, expr: &str) -> FozzyResult<serde_json::Value> {
    let expr = expr.trim();
    if expr == "." || expr == "$" {
        return Ok(root.clone());
    }
    let normalized = apply_query_aliases(&normalize_query_expr(expr)?);
    let tokens = parse_expr(&normalized)?;
    let mut current: Vec<&serde_json::Value> = vec![root];
    for token in tokens {
        let mut next = Vec::new();
        match token {
            QueryToken::Field(name) => {
                for v in &current {
                    if let Some(arr) = v.as_array()
                        && let Ok(idx) = name.parse::<usize>()
                        && let Some(item) = arr.get(idx)
                    {
                        next.push(item);
                        continue;
                    }
                    if let Some(field) = v.get(&name) {
                        next.push(field);
                    }
                }
            }
            QueryToken::Index(idx) => {
                for v in &current {
                    if let Some(item) = v.get(idx) {
                        next.push(item);
                    }
                }
            }
            QueryToken::AllIndices => {
                for v in &current {
                    if let Some(arr) = v.as_array() {
                        for item in arr {
                            next.push(item);
                        }
                    }
                }
            }
        }
        current = next;
    }

    if current.is_empty() {
        let suggestions = suggest_query_paths(root, &normalized, 4);
        let suggestion_text = if suggestions.is_empty() {
            String::new()
        } else {
            format!("; did you mean {}", suggestions.join(", "))
        };
        return Err(FozzyError::Report(format!(
            "query matched no values for expression {expr:?}{suggestion_text}"
        )));
    }
    if current.len() == 1 {
        return Ok(current[0].clone());
    }
    Ok(serde_json::Value::Array(
        current.into_iter().cloned().collect(),
    ))
}

fn list_query_paths(root: &serde_json::Value) -> Vec<String> {
    fn visit(
        value: &serde_json::Value,
        path: String,
        out: &mut std::collections::BTreeSet<String>,
    ) {
        out.insert(path.clone());
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let next = if path == "." {
                        format!(".{k}")
                    } else {
                        format!("{path}.{k}")
                    };
                    visit(v, next, out);
                }
            }
            serde_json::Value::Array(arr) => {
                out.insert(format!("{path}[]"));
                if let Some(first) = arr.first() {
                    visit(first, format!("{path}[0]"), out);
                }
            }
            _ => {}
        }
    }

    let mut out = std::collections::BTreeSet::new();
    visit(root, ".".to_string(), &mut out);
    out.into_iter()
        .map(|p| p.trim_start_matches('.').to_string())
        .collect()
}

fn suggest_query_paths(
    root: &serde_json::Value,
    normalized_expr: &str,
    limit: usize,
) -> Vec<String> {
    let paths = list_query_paths(root);
    let needle = normalized_expr.trim_start_matches('.');
    let needle_lc = needle.to_ascii_lowercase();
    if needle.is_empty() {
        return paths.into_iter().take(limit).collect();
    }

    let mut exact_prefix: Vec<String> = paths
        .iter()
        .filter(|p| p.to_ascii_lowercase().starts_with(&needle_lc))
        .cloned()
        .collect();
    if exact_prefix.is_empty() {
        let tail_lc = needle_lc
            .rsplit('.')
            .next()
            .unwrap_or(&needle_lc)
            .to_string();
        exact_prefix = paths
            .iter()
            .filter(|p| {
                let p_lc = p.to_ascii_lowercase();
                p_lc.ends_with(&tail_lc) || p_lc.contains(&needle_lc)
            })
            .cloned()
            .collect();
    }
    exact_prefix.sort();
    exact_prefix.dedup();
    exact_prefix.into_iter().take(limit).collect()
}

fn apply_query_aliases(expr: &str) -> String {
    // Common DX aliases for top-level identity fields.
    // Example: `runId` -> `.identity.runId`.
    const ALIASES: &[(&str, &str)] = &[
        (".runId", ".identity.runId"),
        (".seed", ".identity.seed"),
        (".tracePath", ".identity.tracePath"),
        (".reportPath", ".identity.reportPath"),
        (".artifactsDir", ".identity.artifactsDir"),
    ];
    for (from, to) in ALIASES {
        if expr == *from {
            return (*to).to_string();
        }
        if let Some(rest) = expr.strip_prefix(from)
            && (rest.starts_with('.') || rest.starts_with('['))
        {
            return format!("{to}{rest}");
        }
    }
    expr.to_string()
}

fn normalize_query_expr(expr: &str) -> FozzyResult<String> {
    if expr.is_empty() {
        return Err(FozzyError::Report(
            "empty jq expression; examples: '.', '.identity.runId', 'findings[0].title', '.findings[].title'"
                .to_string(),
        ));
    }

    if let Some(rest) = expr.strip_prefix("$.") {
        return Ok(format!(".{rest}"));
    }
    if let Some(rest) = expr.strip_prefix('$') {
        if rest.starts_with('[') {
            return Ok(format!(".{rest}"));
        }
        return Err(FozzyError::Report(format!(
            "unsupported jq expression {expr:?}; supported path subset examples: '.', '.a.b', 'a.b', '.arr[0]', '.arr[].field'"
        )));
    }
    if expr.starts_with('.') {
        return Ok(expr.to_string());
    }
    if expr.starts_with('[')
        || expr
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        return Ok(format!(".{expr}"));
    }
    Err(FozzyError::Report(format!(
        "unsupported jq expression {expr:?}; supported path subset examples: '.', '.a.b', 'a.b', '.arr[0]', '.arr[].field'"
    )))
}

#[derive(Debug, Clone)]
enum QueryToken {
    Field(String),
    Index(usize),
    AllIndices,
}

fn parse_expr(expr: &str) -> FozzyResult<Vec<QueryToken>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 1usize; // skip leading '.'

    while i < chars.len() {
        if chars[i] == '.' {
            i += 1;
            continue;
        }
        if chars[i] == '[' {
            i += 1;
            if i < chars.len() && chars[i] == ']' {
                i += 1;
                tokens.push(QueryToken::AllIndices);
                continue;
            }
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i >= chars.len() || chars[i] != ']' || start == i {
                return Err(FozzyError::Report(format!(
                    "invalid index expression in {expr:?}"
                )));
            }
            let idx_str: String = chars[start..i].iter().collect();
            i += 1; // skip ]
            let idx: usize = idx_str
                .parse()
                .map_err(|_| FozzyError::Report(format!("invalid index {idx_str:?}")))?;
            tokens.push(QueryToken::Index(idx));
            continue;
        }

        let start = i;
        while i < chars.len() && chars[i] != '.' && chars[i] != '[' {
            i += 1;
        }
        let field: String = chars[start..i].iter().collect();
        if field.is_empty() {
            return Err(FozzyError::Report(format!(
                "invalid field expression in {expr:?}"
            )));
        }
        tokens.push(QueryToken::Field(field));
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExitStatus, Finding, FindingKind, RunIdentity, RunMode};
    use uuid::Uuid;

    fn write_summary(base: &std::path::Path, run_id: &str, status: ExitStatus) -> String {
        let dir = base.join(run_id);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let summary = RunSummary {
            status,
            mode: RunMode::Run,
            identity: RunIdentity {
                run_id: run_id.to_string(),
                seed: 1,
                trace_path: None,
                report_path: Some(dir.join("report.json").to_string_lossy().to_string()),
                artifacts_dir: Some(dir.to_string_lossy().to_string()),
            },
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: "2026-01-01T00:00:00Z".to_string(),
            duration_ms: 0,
            duration_ns: 0,
            tests: None,
            memory: None,
            findings: if status == ExitStatus::Pass {
                Vec::new()
            } else {
                vec![Finding {
                    kind: FindingKind::Assertion,
                    title: "boom".to_string(),
                    message: "x".to_string(),
                    location: None,
                }]
            },
        };
        std::fs::write(
            dir.join("report.json"),
            serde_json::to_vec_pretty(&summary).expect("json"),
        )
        .expect("write");
        run_id.to_string()
    }

    #[test]
    fn query_accepts_dot_index_form() {
        let value = serde_json::json!({
            "findings": [{"title": "oops"}]
        });
        let out = query_value(&value, ".findings.0.title").expect("query");
        assert_eq!(out, serde_json::Value::String("oops".to_string()));
    }

    #[test]
    fn query_run_id_alias_maps_to_identity() {
        let value = serde_json::json!({
            "identity": {"runId": "run-123"}
        });
        let out = query_value(&value, "runId").expect("query");
        assert_eq!(out, serde_json::Value::String("run-123".to_string()));
    }

    #[test]
    fn query_identity_aliases_cover_all_documented_fields() {
        let value = serde_json::json!({
            "identity": {
                "runId": "run-123",
                "seed": 7,
                "tracePath": "t.fozzy",
                "reportPath": "r.json",
                "artifactsDir": ".fozzy/runs/run-123"
            }
        });
        let cases = [
            ("runId", serde_json::json!("run-123")),
            ("seed", serde_json::json!(7)),
            ("tracePath", serde_json::json!("t.fozzy")),
            ("reportPath", serde_json::json!("r.json")),
            ("artifactsDir", serde_json::json!(".fozzy/runs/run-123")),
            ("identity.runId", serde_json::json!("run-123")),
        ];
        for (expr, expected) in cases {
            let out = query_value(&value, expr).expect("query");
            assert_eq!(out, expected, "expr={expr}");
        }
    }

    #[test]
    fn query_miss_reports_suggestion() {
        let value = serde_json::json!({
            "identity": {"runId": "run-123"}
        });
        let err = query_value(&value, "runid").expect_err("must miss");
        assert!(err.to_string().contains("did you mean"));
        assert!(err.to_string().contains("identity.runId"));
    }

    #[test]
    fn list_paths_exposes_identity_shape() {
        let value = serde_json::json!({
            "identity": {"runId": "run-123", "seed": 1},
            "findings": [{"title": "oops"}]
        });
        let paths = list_query_paths(&value);
        assert!(paths.contains(&"identity.runId".to_string()));
        assert!(paths.contains(&"findings[0].title".to_string()));
    }

    #[test]
    fn flaky_budget_enforced() {
        let root = std::env::temp_dir().join(format!("fozzy-flaky-{}", Uuid::new_v4()));
        let runs = root.join(".fozzy").join("runs");
        std::fs::create_dir_all(&runs).expect("mkdir");
        let a = write_summary(&runs, "r1", ExitStatus::Pass);
        let b = write_summary(&runs, "r2", ExitStatus::Fail);
        let cfg = crate::Config {
            base_dir: root.join(".fozzy"),
            reporter: Reporter::Json,
            proc_backend: crate::ProcBackend::Scripted,
            fs_backend: crate::FsBackend::Virtual,
            http_backend: crate::HttpBackend::Scripted,
            mem_track: false,
            mem_limit_mb: None,
            mem_fail_after: None,
            fail_on_leak: false,
            leak_budget: None,
            mem_artifacts: false,
            profile_heap_alloc_budget: None,
            profile_heap_in_use_budget: None,
            mem_fragmentation_seed: None,
            mem_pressure_wave: None,
        };

        let out = flaky_command(
            &cfg,
            &[a.clone(), b.clone()],
            Some("60".parse::<crate::FlakeBudget>().expect("budget parse")),
        )
        .expect("within budget");
        let obj = out.as_object().expect("obj");
        assert!(obj.get("flakeRatePct").is_some());

        let err = flaky_command(
            &cfg,
            &[a, b],
            Some("10".parse::<crate::FlakeBudget>().expect("budget parse")),
        )
        .expect_err("over budget");
        assert!(err.to_string().contains("flake budget exceeded"));
    }

    #[test]
    fn flaky_rejects_duplicate_run_references() {
        let root = std::env::temp_dir().join(format!("fozzy-flaky-dup-{}", Uuid::new_v4()));
        let runs = root.join(".fozzy").join("runs");
        std::fs::create_dir_all(&runs).expect("mkdir");
        let a = write_summary(&runs, "r1", ExitStatus::Pass);
        let b = write_summary(&runs, "r2", ExitStatus::Fail);
        let cfg = crate::Config {
            base_dir: root.join(".fozzy"),
            reporter: Reporter::Json,
            proc_backend: crate::ProcBackend::Scripted,
            fs_backend: crate::FsBackend::Virtual,
            http_backend: crate::HttpBackend::Scripted,
            mem_track: false,
            mem_limit_mb: None,
            mem_fail_after: None,
            fail_on_leak: false,
            leak_budget: None,
            mem_artifacts: false,
            profile_heap_alloc_budget: None,
            profile_heap_in_use_budget: None,
            mem_fragmentation_seed: None,
            mem_pressure_wave: None,
        };

        let err =
            flaky_command(&cfg, &[a.clone(), a, b], None).expect_err("must reject duplicates");
        assert!(err.to_string().contains("duplicate run reference"));
    }
}
