//! Reporting types and renderers.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reporter {
    Pretty,
    Json,
    Junit,
    Html,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FlakeBudget(f64);

impl FlakeBudget {
    pub fn pct(self) -> f64 {
        self.0
    }
}

impl FromStr for FlakeBudget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v: f64 = s
            .parse()
            .map_err(|_| format!("invalid flake budget {s:?}: expected number in range 0..=100"))?;
        if !v.is_finite() {
            return Err(format!(
                "invalid flake budget {s:?}: must be finite and in range 0..=100"
            ));
        }
        if !(0.0..=100.0).contains(&v) {
            return Err(format!(
                "invalid flake budget {s:?}: must be finite and in range 0..=100"
            ));
        }
        Ok(Self(v))
    }
}

impl clap::ValueEnum for Reporter {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Pretty, Self::Json, Self::Junit, Self::Html]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Pretty => clap::builder::PossibleValue::new("pretty"),
            Self::Json => clap::builder::PossibleValue::new("json"),
            Self::Junit => clap::builder::PossibleValue::new("junit"),
            Self::Html => clap::builder::PossibleValue::new("html"),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    Pass,
    Fail,
    Error,
    Timeout,
    Crash,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Test,
    Run,
    Fuzz,
    Explore,
    Replay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunIdentity {
    #[serde(rename = "runId")]
    pub run_id: String,
    pub seed: u64,
    #[serde(rename = "tracePath", skip_serializing_if = "Option::is_none")]
    pub trace_path: Option<String>,
    #[serde(rename = "reportPath", skip_serializing_if = "Option::is_none")]
    pub report_path: Option<String>,
    #[serde(rename = "artifactsDir", skip_serializing_if = "Option::is_none")]
    pub artifacts_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub title: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<FindingLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Assertion,
    Panic,
    Hang,
    Invariant,
    Checker,
    InputInvalid,
    TargetBehavior,
}

pub fn collapse_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut grouped = BTreeMap::<
        (
            FindingKind,
            String,
            String,
            Option<String>,
            Option<u32>,
            Option<u32>,
        ),
        (Finding, u32),
    >::new();

    for finding in findings {
        let key = (
            finding.kind.clone(),
            finding.title.clone(),
            finding.message.clone(),
            finding.location.as_ref().and_then(|l| l.file.clone()),
            finding.location.as_ref().and_then(|l| l.line),
            finding.location.as_ref().and_then(|l| l.col),
        );
        grouped
            .entry(key)
            .and_modify(|(_, n)| *n = n.saturating_add(1))
            .or_insert((finding, 1));
    }

    grouped
        .into_values()
        .map(|(mut finding, n)| {
            if n > 1 {
                finding.message = format!("{} (repeated {} times)", finding.message, n);
            }
            finding
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub status: ExitStatus,
    pub mode: RunMode,
    pub identity: RunIdentity,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "finishedAt")]
    pub finished_at: String,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(rename = "durationNs", default)]
    pub duration_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tests: Option<TestCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<crate::MemorySummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCounts {
    pub passed: u64,
    pub failed: u64,
    pub skipped: u64,
}

impl RunSummary {
    pub fn pretty(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "status={:?} mode={:?} runId={} seed={}\n",
            self.status, self.mode, self.identity.run_id, self.identity.seed
        ));
        if let Some(path) = &self.identity.trace_path {
            out.push_str(&format!("trace={path}\n"));
        }
        if let Some(path) = &self.identity.report_path {
            out.push_str(&format!("report={path}\n"));
        }
        if let Some(dir) = &self.identity.artifacts_dir {
            out.push_str(&format!("artifacts={dir}\n"));
        }
        if let Some(tests) = &self.tests {
            out.push_str(&format!(
                "tests: passed={} failed={} skipped={}\n",
                tests.passed, tests.failed, tests.skipped
            ));
        }
        if let Some(mem) = &self.memory {
            out.push_str(&format!(
                "memory: allocs={} frees={} failed_allocs={} in_use={} peak={} leaked_bytes={} leaked_allocs={}\n",
                mem.alloc_count,
                mem.free_count,
                mem.failed_alloc_count,
                mem.in_use_bytes,
                mem.peak_bytes,
                mem.leaked_bytes,
                mem.leaked_allocs
            ));
        }
        for finding in &self.findings {
            let location_suffix = finding
                .location
                .as_ref()
                .and_then(|location| location.file.as_ref())
                .map(|file| format!(" ({file})"))
                .unwrap_or_default();
            out.push_str(&format!(
                "- {:?}: {}{}: {}\n",
                finding.kind, finding.title, location_suffix, finding.message
            ));
        }
        out.trim_end().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportOutput {
    pub format: Reporter,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    pub mode: RunMode,
    pub status: ExitStatus,
    pub seed: u64,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "finishedAt")]
    pub finished_at: String,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(rename = "durationNs", default)]
    pub duration_ns: u64,
    #[serde(rename = "tracePath", skip_serializing_if = "Option::is_none")]
    pub trace_path: Option<String>,
    #[serde(rename = "reportPath", skip_serializing_if = "Option::is_none")]
    pub report_path: Option<String>,
    #[serde(rename = "artifactsDir", skip_serializing_if = "Option::is_none")]
    pub artifacts_dir: Option<String>,
    #[serde(rename = "findingsCount")]
    pub findings_count: usize,
    #[serde(rename = "testsPassed", skip_serializing_if = "Option::is_none")]
    pub tests_passed: Option<u64>,
    #[serde(rename = "testsFailed", skip_serializing_if = "Option::is_none")]
    pub tests_failed: Option<u64>,
    #[serde(rename = "testsSkipped", skip_serializing_if = "Option::is_none")]
    pub tests_skipped: Option<u64>,
    #[serde(rename = "memoryLeakedBytes", skip_serializing_if = "Option::is_none")]
    pub memory_leaked_bytes: Option<u64>,
    #[serde(rename = "memoryLeakedAllocs", skip_serializing_if = "Option::is_none")]
    pub memory_leaked_allocs: Option<u64>,
    #[serde(rename = "memoryPeakBytes", skip_serializing_if = "Option::is_none")]
    pub memory_peak_bytes: Option<u64>,
    #[serde(
        rename = "profileCapabilities",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub profile_capabilities: Vec<String>,
    #[serde(
        rename = "profileArtifacts",
        skip_serializing_if = "std::collections::BTreeMap::is_empty",
        default
    )]
    pub profile_artifacts: std::collections::BTreeMap<String, String>,
    #[serde(
        rename = "profileSchemaVersions",
        skip_serializing_if = "std::collections::BTreeMap::is_empty",
        default
    )]
    pub profile_schema_versions: std::collections::BTreeMap<String, String>,
}

pub fn write_run_manifest(
    summary: &RunSummary,
    artifacts_dir: &Path,
) -> crate::FozzyResult<PathBuf> {
    std::fs::create_dir_all(artifacts_dir)?;
    let mut profile_capabilities = Vec::new();
    let mut profile_artifacts = std::collections::BTreeMap::new();
    let mut profile_schema_versions = std::collections::BTreeMap::new();
    for (capability, file_name) in [
        ("timeline", "profile.timeline.json"),
        ("cpu", "profile.cpu.json"),
        ("heap", "profile.heap.json"),
        ("latency", "profile.latency.json"),
        ("metrics", "profile.metrics.json"),
        ("symbols", "symbols.json"),
    ] {
        let path = artifacts_dir.join(file_name);
        if path.exists() {
            profile_capabilities.push(capability.to_string());
            profile_artifacts.insert(capability.to_string(), path.to_string_lossy().to_string());
            if let Ok(Some(schema_version)) = profile_schema_version(&path) {
                profile_schema_versions.insert(capability.to_string(), schema_version);
            }
        }
    }
    let manifest = RunManifest {
        schema_version: "fozzy.run_manifest.v1".to_string(),
        run_id: summary.identity.run_id.clone(),
        mode: summary.mode,
        status: summary.status,
        seed: summary.identity.seed,
        started_at: summary.started_at.clone(),
        finished_at: summary.finished_at.clone(),
        duration_ms: summary.duration_ms,
        duration_ns: summary.duration_ns,
        trace_path: summary.identity.trace_path.clone(),
        report_path: summary.identity.report_path.clone(),
        artifacts_dir: summary.identity.artifacts_dir.clone(),
        findings_count: summary.findings.len(),
        tests_passed: summary.tests.as_ref().map(|t| t.passed),
        tests_failed: summary.tests.as_ref().map(|t| t.failed),
        tests_skipped: summary.tests.as_ref().map(|t| t.skipped),
        memory_leaked_bytes: summary.memory.as_ref().map(|m| m.leaked_bytes),
        memory_leaked_allocs: summary.memory.as_ref().map(|m| m.leaked_allocs),
        memory_peak_bytes: summary.memory.as_ref().map(|m| m.peak_bytes),
        profile_capabilities,
        profile_artifacts,
        profile_schema_versions,
    };
    let out = artifacts_dir.join("manifest.json");
    std::fs::write(&out, serde_json::to_vec_pretty(&manifest)?)?;
    Ok(out)
}

fn profile_schema_version(path: &Path) -> crate::FozzyResult<Option<String>> {
    let bytes = std::fs::read(path)?;
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    Ok(value
        .get("schemaVersion")
        .and_then(|v| v.as_str())
        .map(ToString::to_string))
}

pub fn duration_fields(elapsed: Duration) -> (u64, u64) {
    let duration_ns = elapsed.as_nanos().min(u128::from(u64::MAX)) as u64;
    if duration_ns == 0 {
        return (0, 0);
    }
    let rounded_ms = duration_ns.saturating_add(999_999) / 1_000_000;
    (rounded_ms.max(1), duration_ns)
}

pub fn render_junit_xml(summary: &RunSummary) -> String {
    // Minimal JUnit report: one suite, one testcase per finding (or one testcase for pass).
    let tests = summary.findings.len().max(1);
    let failures = summary
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::Assertion | FindingKind::Invariant | FindingKind::Checker
            )
        })
        .count();

    let mut out = String::new();
    out.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    out.push('\n');
    out.push_str(&format!(
        r#"<testsuite name="fozzy" tests="{tests}" failures="{failures}" time="{}">"#,
        (summary.duration_ms as f64) / 1000.0
    ));
    out.push('\n');

    if summary.findings.is_empty() {
        out.push_str(&format!(
            r#"<testcase classname="fozzy" name="{}"/>"#,
            xml_escape(&summary.identity.run_id)
        ));
        out.push('\n');
    } else {
        for (i, f) in summary.findings.iter().enumerate() {
            out.push_str(&format!(
                r#"<testcase classname="fozzy" name="finding_{i}">"#
            ));
            out.push('\n');
            out.push_str(&format!(
                r#"<failure message="{}">{}</failure>"#,
                xml_escape(&f.title),
                xml_escape(&f.message)
            ));
            out.push('\n');
            out.push_str(r#"</testcase>"#);
            out.push('\n');
        }
    }

    out.push_str(r#"</testsuite>"#);
    out.push('\n');
    out
}

pub fn render_html(summary: &RunSummary) -> String {
    let status = format!("{:?}", summary.status);
    let mut items = String::new();
    for f in &summary.findings {
        items.push_str("<li>");
        items.push_str(&html_escape(&format!(
            "{:?}: {}: {}",
            f.kind, f.title, f.message
        )));
        items.push_str("</li>");
    }
    if summary.findings.is_empty() {
        items.push_str("<li>no findings</li>");
    }

    format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>fozzy report</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; padding: 24px; }}
    .meta {{ opacity: 0.8; }}
    .status {{ font-weight: 700; }}
  </style>
</head>
<body>
  <div class="status">status: {status}</div>
  <div class="meta">runId: {run_id} seed: {seed}</div>
  <div class="meta">startedAt: {started_at}</div>
  <div class="meta">finishedAt: {finished_at}</div>
  <h2>findings</h2>
  <ul>{items}</ul>
</body>
</html>"#,
        status = html_escape(&status),
        run_id = html_escape(&summary.identity.run_id),
        seed = summary.identity.seed,
        started_at = html_escape(&summary.started_at),
        finished_at = html_escape(&summary.finished_at),
        items = items
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&apos;")
}

fn html_escape(s: &str) -> String {
    xml_escape(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_findings_groups_identical_entries() {
        let findings = vec![
            Finding {
                kind: FindingKind::Checker,
                title: "http_when_backend".to_string(),
                message: "http_when requires scripted backend".to_string(),
                location: None,
            },
            Finding {
                kind: FindingKind::Checker,
                title: "http_when_backend".to_string(),
                message: "http_when requires scripted backend".to_string(),
                location: None,
            },
        ];
        let collapsed = collapse_findings(findings);
        assert_eq!(collapsed.len(), 1);
        assert!(
            collapsed[0].message.contains("repeated 2 times"),
            "expected repetition count to be appended"
        );
    }

    #[test]
    fn duration_fields_round_sub_ms_to_non_zero_ms() {
        let (ms, ns) = duration_fields(Duration::from_nanos(500_000));
        assert_eq!(ms, 1);
        assert_eq!(ns, 500_000);
    }
}
