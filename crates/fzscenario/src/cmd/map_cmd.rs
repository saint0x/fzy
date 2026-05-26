//! Topology and hotspot mapping commands (`fozzy map ...`).

use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::{Config, FozzyError, FozzyResult};

const SUITE_TEST_DET: &str = "test_det";
const SUITE_RUN_REPLAY_CI: &str = "run_record_replay_ci";
const SUITE_FUZZ: &str = "fuzz_inputs";
const SUITE_EXPLORE: &str = "explore_schedule_faults";
const SUITE_HOST: &str = "host_backends_run";
const SUITE_MEMORY: &str = "memory_graph_diff_top";
const SUITE_SHRINK_EXERCISED: &str = "shrink_exercised";
const SUITE_SHRINK_FAILURE: &str = "shrink_failure_trace";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TopologyProfile {
    Balanced,
    Pedantic,
    Overkill,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShrinkCoveragePolicy {
    FailureOnly,
    ExercisedOk,
    NoKnownFailures,
}

#[derive(Debug, Subcommand)]
pub enum MapCommand {
    /// Analyze repository hotspots and risk-ranked candidate areas for granular suites
    Hotspots {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value_t = 60)]
        min_risk: u8,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Discover service/module boundaries from language-agnostic repo signals
    Services {
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    /// Build suite recommendations and scenario-coverage gaps for high-risk hotspots
    Suites {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value = "tests")]
        scenario_root: PathBuf,
        #[arg(long, default_value_t = 60)]
        min_risk: u8,
        #[arg(long, default_value = "pedantic")]
        profile: TopologyProfile,
        #[arg(long, default_value = "no-known-failures")]
        shrink_policy: ShrinkCoveragePolicy,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 25)]
        max_matched_scenarios: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapHotspotsReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "scannedFiles")]
    pub scanned_files: usize,
    #[serde(rename = "minRisk")]
    pub min_risk: u8,
    pub hotspots: Vec<MapHotspot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapServicesReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "scannedFiles")]
    pub scanned_files: usize,
    pub services: Vec<ServiceBoundary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapSuitesReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "scenarioRoot")]
    pub scenario_root: String,
    #[serde(rename = "scannedFiles")]
    pub scanned_files: usize,
    pub profile: TopologyProfile,
    #[serde(rename = "shrinkPolicy")]
    pub shrink_policy: ShrinkCoveragePolicy,
    #[serde(rename = "baseMinRisk")]
    pub base_min_risk: u8,
    #[serde(rename = "effectiveMinRisk")]
    pub effective_min_risk: u8,
    #[serde(rename = "scenarioCount")]
    pub scenario_count: usize,
    #[serde(
        rename = "skippedSourceFiles",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub skipped_source_files: Vec<String>,
    #[serde(
        rename = "unreadableScenarios",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub unreadable_scenarios: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(rename = "requiredHotspotCount")]
    pub required_hotspot_count: usize,
    #[serde(rename = "coveredHotspotCount")]
    pub covered_hotspot_count: usize,
    #[serde(rename = "uncoveredHotspotCount")]
    pub uncovered_hotspot_count: usize,
    #[serde(rename = "totalSuites")]
    pub total_suites: usize,
    #[serde(rename = "returnedSuites")]
    pub returned_suites: usize,
    pub offset: usize,
    pub limit: usize,
    pub truncated: bool,
    pub suites: Vec<SuiteRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapHotspot {
    pub id: String,
    pub component: String,
    pub path: String,
    #[serde(rename = "riskScore")]
    pub risk_score: u8,
    pub reasons: Vec<String>,
    pub signals: HotspotSignals,
    #[serde(rename = "recommendedSuites")]
    pub recommended_suites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HotspotSignals {
    #[serde(rename = "lineCount")]
    pub line_count: usize,
    #[serde(rename = "branchSignals")]
    pub branch_signals: usize,
    #[serde(rename = "concurrencySignals")]
    pub concurrency_signals: usize,
    #[serde(rename = "externalSignals")]
    pub external_signals: usize,
    #[serde(rename = "failureSignals")]
    pub failure_signals: usize,
    #[serde(rename = "memorySignals")]
    pub memory_signals: usize,
    #[serde(rename = "entrypointSignals")]
    pub entrypoint_signals: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceBoundary {
    pub name: String,
    pub path: String,
    pub kind: String,
    #[serde(rename = "fileCount")]
    pub file_count: usize,
    #[serde(rename = "entrypointSignals")]
    pub entrypoint_signals: usize,
    #[serde(rename = "externalSignals")]
    pub external_signals: usize,
    #[serde(rename = "concurrencySignals")]
    pub concurrency_signals: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteRecommendation {
    #[serde(rename = "hotspotId")]
    pub hotspot_id: String,
    pub component: String,
    pub path: String,
    #[serde(rename = "riskScore")]
    pub risk_score: u8,
    #[serde(rename = "requiredByPolicy")]
    pub required_by_policy: bool,
    pub covered: bool,
    #[serde(rename = "coverageHints")]
    pub coverage_hints: Vec<String>,
    #[serde(rename = "requiredSuites")]
    pub required_suites: Vec<String>,
    #[serde(rename = "coveredSuites")]
    pub covered_suites: Vec<String>,
    #[serde(rename = "coverageEvidence")]
    pub coverage_evidence: Vec<SuiteCoverageEvidence>,
    #[serde(rename = "missingRequiredSuites")]
    pub missing_required_suites: Vec<String>,
    #[serde(rename = "whyRequired")]
    pub why_required: Vec<String>,
    pub reasons: Vec<String>,
    #[serde(rename = "recommendedSuites")]
    pub recommended_suites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteCoverageEvidence {
    pub suite: String,
    #[serde(rename = "matchedScenarios")]
    pub matched_scenarios: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct MapSuitesOptions {
    pub root: PathBuf,
    pub scenario_root: PathBuf,
    pub min_risk: u8,
    pub profile: TopologyProfile,
    pub shrink_policy: ShrinkCoveragePolicy,
    pub limit: usize,
    pub offset: usize,
    pub max_matched_scenarios: usize,
}

#[derive(Debug, Clone)]
struct RepoFacts {
    root: PathBuf,
    scanned_files: usize,
    skipped_source_files: Vec<String>,
    hotspots: Vec<MapHotspot>,
    services: Vec<ServiceBoundary>,
}

#[derive(Debug, Clone)]
struct ScanRecord {
    rel: PathBuf,
    component: String,
    signal: HotspotSignals,
    risk_score: u8,
    reasons: Vec<String>,
}

#[derive(Debug, Clone)]
struct ScenarioFact {
    path: String,
    tokens: BTreeSet<String>,
    has_explore: bool,
    has_fuzz: bool,
    has_host: bool,
    has_memory: bool,
    has_failure: bool,
    has_shrink: bool,
}

#[derive(Debug, Clone)]
struct ScenarioFactBuild {
    facts: Vec<ScenarioFact>,
    unreadable_scenarios: Vec<String>,
}

pub fn map_command(_config: &Config, command: &MapCommand) -> FozzyResult<serde_json::Value> {
    match command {
        MapCommand::Hotspots {
            root,
            min_risk,
            limit,
        } => {
            let facts = scan_repo(root)?;
            let mut hotspots: Vec<MapHotspot> = facts
                .hotspots
                .into_iter()
                .filter(|h| h.risk_score >= *min_risk)
                .collect();
            hotspots.sort_by(|a, b| {
                b.risk_score
                    .cmp(&a.risk_score)
                    .then_with(|| a.path.cmp(&b.path))
            });
            hotspots.truncate(*limit);
            Ok(serde_json::to_value(MapHotspotsReport {
                schema_version: "fozzy.map_hotspots.v2".to_string(),
                root: facts.root.display().to_string(),
                scanned_files: facts.scanned_files,
                min_risk: *min_risk,
                hotspots,
            })?)
        }
        MapCommand::Services { root } => {
            let facts = scan_repo(root)?;
            Ok(serde_json::to_value(MapServicesReport {
                schema_version: "fozzy.map_services.v2".to_string(),
                root: facts.root.display().to_string(),
                scanned_files: facts.scanned_files,
                services: facts.services,
            })?)
        }
        MapCommand::Suites {
            root,
            scenario_root,
            min_risk,
            profile,
            shrink_policy,
            limit,
            offset,
            max_matched_scenarios,
        } => {
            let report = map_suites(&MapSuitesOptions {
                root: root.clone(),
                scenario_root: scenario_root.clone(),
                min_risk: *min_risk,
                profile: *profile,
                shrink_policy: *shrink_policy,
                limit: *limit,
                offset: *offset,
                max_matched_scenarios: *max_matched_scenarios,
            })?;
            Ok(serde_json::to_value(report)?)
        }
    }
}

pub fn map_suites(opt: &MapSuitesOptions) -> FozzyResult<MapSuitesReport> {
    let facts = scan_repo(&opt.root)?;
    let scenario_files = discover_scenarios(&opt.scenario_root)?;
    let scenario_build = build_scenario_facts(&scenario_files);
    let scenario_facts = scenario_build.facts;
    let coverage_index = ScenarioCoverageIndex::new(&scenario_facts);
    let has_known_shrink_failure = scenario_facts.iter().any(|s| s.has_shrink && s.has_failure);

    let effective_min_risk = effective_min_risk(opt.min_risk, opt.profile);
    let mut suites = Vec::<SuiteRecommendation>::new();
    let mut required_hotspot_count = 0usize;
    let mut covered_hotspot_count = 0usize;

    for hotspot in facts.hotspots {
        let hints = hotspot_hints(&hotspot);
        let required_by_policy = hotspot.risk_score >= effective_min_risk;
        if required_by_policy {
            required_hotspot_count += 1;
        }

        let required_suites = required_suites_for_hotspot(
            opt.profile,
            opt.shrink_policy,
            &hotspot.signals,
            has_known_shrink_failure,
        );
        let coverage_evidence = covered_suites_for_hotspot(
            &required_suites,
            &hints,
            &scenario_facts,
            &coverage_index,
            opt.max_matched_scenarios.max(1),
        );
        let covered_suites = coverage_evidence
            .iter()
            .map(|e| e.suite.clone())
            .collect::<Vec<_>>();
        let missing_required_suites = required_suites
            .iter()
            .filter(|s| !covered_suites.contains(*s))
            .cloned()
            .collect::<Vec<_>>();
        let covered = !required_by_policy || missing_required_suites.is_empty();
        if required_by_policy && covered {
            covered_hotspot_count += 1;
        }

        let why_required = why_required(hotspot.risk_score, effective_min_risk, &hotspot.signals);
        let mut recommended = required_suites.clone();
        for extra in recommended_suites_for_hotspot(&hotspot.signals) {
            if !recommended.contains(&extra) {
                recommended.push(extra);
            }
        }

        suites.push(SuiteRecommendation {
            hotspot_id: hotspot.id,
            component: hotspot.component,
            path: hotspot.path,
            risk_score: hotspot.risk_score,
            required_by_policy,
            covered,
            coverage_hints: hints,
            required_suites,
            covered_suites,
            coverage_evidence,
            missing_required_suites,
            why_required,
            reasons: hotspot.reasons,
            recommended_suites: recommended,
        });
    }

    suites.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| a.path.cmp(&b.path))
    });
    let total_suites = suites.len();
    let suites = suites
        .into_iter()
        .skip(opt.offset)
        .take(opt.limit)
        .collect::<Vec<_>>();
    let returned_suites = suites.len();
    let truncated = opt.offset.saturating_add(returned_suites) < total_suites;

    let uncovered_hotspot_count = required_hotspot_count.saturating_sub(covered_hotspot_count);

    Ok(MapSuitesReport {
        schema_version: "fozzy.map_suites.v5".to_string(),
        root: facts.root.display().to_string(),
        scenario_root: opt.scenario_root.display().to_string(),
        scanned_files: facts.scanned_files,
        profile: opt.profile,
        shrink_policy: opt.shrink_policy,
        base_min_risk: opt.min_risk,
        effective_min_risk,
        scenario_count: scenario_files.len(),
        skipped_source_files: facts.skipped_source_files.clone(),
        unreadable_scenarios: scenario_build.unreadable_scenarios.clone(),
        warnings: map_warnings(
            &facts.skipped_source_files,
            &scenario_build.unreadable_scenarios,
        ),
        required_hotspot_count,
        covered_hotspot_count,
        uncovered_hotspot_count,
        total_suites,
        returned_suites,
        offset: opt.offset,
        limit: opt.limit,
        truncated,
        suites,
    })
}

fn effective_min_risk(base: u8, profile: TopologyProfile) -> u8 {
    match profile {
        TopologyProfile::Balanced => base.saturating_add(15).min(100),
        TopologyProfile::Pedantic => base.saturating_sub(5),
        TopologyProfile::Overkill => base.saturating_sub(15),
    }
}

fn required_suites_for_hotspot(
    profile: TopologyProfile,
    shrink_policy: ShrinkCoveragePolicy,
    s: &HotspotSignals,
    has_known_shrink_failure: bool,
) -> Vec<String> {
    let mut out = BTreeSet::<String>::new();
    out.insert(SUITE_TEST_DET.to_string());
    out.insert(SUITE_RUN_REPLAY_CI.to_string());
    let mut require_shrink_exercised = false;
    let mut require_shrink_failure = false;

    match profile {
        TopologyProfile::Balanced => {
            if s.concurrency_signals > 0 {
                out.insert(SUITE_EXPLORE.to_string());
            }
            if s.external_signals > 0 {
                out.insert(SUITE_HOST.to_string());
            }
            if s.failure_signals > 0 || s.branch_signals > 25 {
                require_shrink_exercised = true;
            }
            if s.failure_signals > 0 {
                require_shrink_failure = true;
            }
            if s.memory_signals > 2 {
                out.insert(SUITE_MEMORY.to_string());
            }
            if s.branch_signals > 20 {
                out.insert(SUITE_FUZZ.to_string());
            }
        }
        TopologyProfile::Pedantic => {
            require_shrink_exercised = true;
            if s.failure_signals > 0 {
                require_shrink_failure = true;
            }
            if s.concurrency_signals > 0 || s.failure_signals >= 4 {
                out.insert(SUITE_EXPLORE.to_string());
            }
            if s.external_signals > 0 || s.entrypoint_signals > 0 {
                out.insert(SUITE_HOST.to_string());
            }
            if s.memory_signals > 0 {
                out.insert(SUITE_MEMORY.to_string());
            }
            if s.branch_signals > 6 || s.failure_signals > 0 {
                out.insert(SUITE_FUZZ.to_string());
            }
        }
        TopologyProfile::Overkill => {
            out.insert(SUITE_FUZZ.to_string());
            out.insert(SUITE_EXPLORE.to_string());
            out.insert(SUITE_HOST.to_string());
            out.insert(SUITE_MEMORY.to_string());
            require_shrink_exercised = true;
            require_shrink_failure = true;
        }
    }
    if require_shrink_failure {
        require_shrink_exercised = true;
    }
    if require_shrink_exercised {
        out.insert(SUITE_SHRINK_EXERCISED.to_string());
    }
    if require_shrink_failure {
        match shrink_policy {
            ShrinkCoveragePolicy::FailureOnly => {
                out.insert(SUITE_SHRINK_FAILURE.to_string());
            }
            ShrinkCoveragePolicy::ExercisedOk => {}
            ShrinkCoveragePolicy::NoKnownFailures => {
                if has_known_shrink_failure {
                    out.insert(SUITE_SHRINK_FAILURE.to_string());
                }
            }
        }
    }

    out.into_iter().collect()
}

fn recommended_suites_for_hotspot(s: &HotspotSignals) -> Vec<String> {
    let mut out = BTreeSet::<String>::new();
    out.insert(SUITE_TEST_DET.to_string());
    out.insert(SUITE_RUN_REPLAY_CI.to_string());
    if s.concurrency_signals > 0 {
        out.insert(SUITE_EXPLORE.to_string());
    }
    if s.external_signals > 0 {
        out.insert(SUITE_HOST.to_string());
    }
    if s.failure_signals > 0 {
        out.insert(SUITE_SHRINK_FAILURE.to_string());
    }
    if s.failure_signals > 0 || s.branch_signals > 20 {
        out.insert(SUITE_SHRINK_EXERCISED.to_string());
    }
    if s.memory_signals > 0 {
        out.insert(SUITE_MEMORY.to_string());
    }
    if s.branch_signals > 8 {
        out.insert(SUITE_FUZZ.to_string());
    }
    out.into_iter().collect()
}

fn why_required(risk: u8, threshold: u8, s: &HotspotSignals) -> Vec<String> {
    let mut out = Vec::<String>::new();
    if risk >= threshold {
        out.push(format!("risk_score {} >= threshold {}", risk, threshold));
    }
    if s.concurrency_signals > 0 {
        out.push("concurrency hotspot".to_string());
    }
    if s.external_signals > 0 {
        out.push("external side-effects present".to_string());
    }
    if s.failure_signals > 0 {
        out.push("failure/retry/timeout behavior present".to_string());
    }
    if s.memory_signals > 0 {
        out.push("memory behavior present".to_string());
    }
    out
}

fn covered_suites_for_hotspot(
    required: &[String],
    hints: &[String],
    scenarios: &[ScenarioFact],
    index: &ScenarioCoverageIndex,
    max_matched_scenarios: usize,
) -> Vec<SuiteCoverageEvidence> {
    let attribution_hints = AttributionHints::from_hotspot_hints(hints);

    let mut out = Vec::new();
    for suite in required {
        let matches = index
            .candidates(suite)
            .into_iter()
            .filter_map(|idx| scenarios.get(*idx))
            .filter(|s| suite_allows_attribution_match(suite, &attribution_hints, &s.tokens))
            .collect::<Vec<_>>();
        if matches.is_empty() {
            continue;
        }
        let total_matches = matches.len();
        let mut matched_scenarios = matches
            .iter()
            .take(max_matched_scenarios)
            .map(|s| s.path.clone())
            .collect::<Vec<_>>();
        if total_matches > matched_scenarios.len() {
            matched_scenarios.push(format!(
                "... {} more scenario(s) omitted",
                total_matches - matched_scenarios.len()
            ));
        }
        let shared = matches
            .iter()
            .flat_map(|s| attribution_hints.tokens.intersection(&s.tokens).cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(6)
            .collect::<Vec<_>>();
        let reason = if shared.is_empty() {
            "suite signal matched".to_string()
        } else {
            format!(
                "suite signal matched; shared attribution tokens: {}",
                shared.join(", ")
            )
        };
        out.push(SuiteCoverageEvidence {
            suite: suite.clone(),
            matched_scenarios,
            reason,
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
struct AttributionHints {
    tokens: BTreeSet<String>,
    exact_stems: BTreeSet<String>,
}

impl AttributionHints {
    fn from_hotspot_hints(hints: &[String]) -> Self {
        let tokens = hints
            .iter()
            .flat_map(|hint| tokenize(hint).into_iter())
            .collect::<BTreeSet<_>>();
        let exact_stems = hints
            .iter()
            .filter(|hint| hint.chars().all(|c| c.is_ascii_alphanumeric()))
            .cloned()
            .collect::<BTreeSet<_>>();
        Self {
            tokens,
            exact_stems,
        }
    }
}

struct ScenarioCoverageIndex {
    by_suite: BTreeMap<String, Vec<usize>>,
}

impl ScenarioCoverageIndex {
    fn new(scenarios: &[ScenarioFact]) -> Self {
        let mut by_suite: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (idx, s) in scenarios.iter().enumerate() {
            for suite in [
                SUITE_TEST_DET,
                SUITE_RUN_REPLAY_CI,
                SUITE_FUZZ,
                SUITE_EXPLORE,
                SUITE_HOST,
                SUITE_MEMORY,
                SUITE_SHRINK_EXERCISED,
                SUITE_SHRINK_FAILURE,
            ] {
                if matches_suite_signal(s, suite) {
                    by_suite.entry(suite.to_string()).or_default().push(idx);
                }
            }
        }
        Self { by_suite }
    }

    fn candidates<'a>(&'a self, suite: &str) -> &'a [usize] {
        self.by_suite.get(suite).map(Vec::as_slice).unwrap_or(&[])
    }
}

fn matches_suite_signal(s: &ScenarioFact, suite: &str) -> bool {
    match suite {
        SUITE_TEST_DET => true,
        SUITE_RUN_REPLAY_CI => true,
        SUITE_FUZZ => s.has_fuzz,
        SUITE_EXPLORE => s.has_explore,
        SUITE_HOST => s.has_host,
        SUITE_MEMORY => s.has_memory,
        SUITE_SHRINK_EXERCISED => s.has_shrink,
        SUITE_SHRINK_FAILURE => s.has_failure && s.has_shrink,
        _ => false,
    }
}

fn build_scenario_facts(paths: &[PathBuf]) -> ScenarioFactBuild {
    let mut facts = Vec::new();
    let mut unreadable_scenarios = Vec::new();
    for path in paths {
        match scenario_fact(path) {
            Ok(fact) => facts.push(fact),
            Err(err) => unreadable_scenarios.push(format!("{}: {err}", path.display())),
        }
    }
    ScenarioFactBuild {
        facts,
        unreadable_scenarios,
    }
}

fn scenario_fact(path: &Path) -> FozzyResult<ScenarioFact> {
    let content = std::fs::read_to_string(path)?;
    let lower = content.to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut tokens = tokenize(&lower);
    tokens.extend(tokenize(&path.to_string_lossy().to_ascii_lowercase()));

    let has_explore = name.contains("explore") || lower.contains("\"distributed\"");
    let has_fuzz = name.contains("fuzz") || lower.contains("\"mode\":\"fuzz\"");
    let has_host = name.contains("host")
        || lower.contains("proc_spawn")
        || lower.contains("http_request")
        || lower.contains("fs_write");
    let has_memory = name.contains("memory") || lower.contains("memory_");
    let has_failure = name.contains("fail")
        || name.contains("timeout")
        || name.contains("panic")
        || lower.contains("\"type\":\"fail\"")
        || lower.contains("\"type\":\"panic\"");
    let has_shrink = name.contains("shrink")
        || lower.contains("\"minimize\"")
        || lower.contains("shrink_trace")
        || lower.contains("shrink");

    Ok(ScenarioFact {
        path: path.display().to_string(),
        tokens,
        has_explore,
        has_fuzz,
        has_host,
        has_memory,
        has_failure,
        has_shrink,
    })
}

fn scan_repo(root: &Path) -> FozzyResult<RepoFacts> {
    if !root.exists() {
        return Err(FozzyError::InvalidArgument(format!(
            "map root does not exist: {}",
            root.display()
        )));
    }

    let mut records = Vec::<ScanRecord>::new();
    let mut scanned_files = 0usize;
    let mut skipped_source_files = Vec::new();
    for entry in WalkDir::new(root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if should_skip_path(p) || !is_candidate_file(p) {
            continue;
        }
        let Ok(file) = std::fs::File::open(p) else {
            skipped_source_files.push(format!("{}: failed to open", p.display()));
            continue;
        };
        let mut signal = HotspotSignals::default();
        let mut line_count = 0usize;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    line_count = line_count.saturating_add(1);
                    accumulate_signals_line(&mut signal, &line);
                }
                Err(err) => {
                    skipped_source_files
                        .push(format!("{}: failed to read line: {err}", p.display()));
                    break;
                }
            }
        }
        signal.line_count = line_count;
        let rel = p.strip_prefix(root).unwrap_or(p).to_path_buf();
        scanned_files += 1;
        let (risk_score, reasons) = score_signals(&signal);
        if risk_score == 0 {
            continue;
        }
        records.push(ScanRecord {
            component: component_for_path(&rel),
            rel,
            signal,
            risk_score,
            reasons,
        });
    }

    let mut hotspots = Vec::<MapHotspot>::new();
    for rec in &records {
        hotspots.push(MapHotspot {
            id: format!("{}:{}", rec.component, rec.rel.display()),
            component: rec.component.clone(),
            path: rec.rel.display().to_string(),
            risk_score: rec.risk_score,
            reasons: rec.reasons.clone(),
            signals: rec.signal.clone(),
            recommended_suites: recommended_suites_for_hotspot(&rec.signal),
        });
    }
    hotspots.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| a.path.cmp(&b.path))
    });

    let mut by_component = BTreeMap::<String, (usize, usize, usize, usize)>::new();
    for rec in &records {
        let e = by_component
            .entry(rec.component.clone())
            .or_insert((0usize, 0usize, 0usize, 0usize));
        e.0 += 1;
        e.1 += rec.signal.entrypoint_signals;
        e.2 += rec.signal.external_signals;
        e.3 += rec.signal.concurrency_signals;
    }

    let mut services = Vec::<ServiceBoundary>::new();
    for (name, (file_count, entrypoint, external, concurrency)) in by_component {
        if file_count < 2 {
            continue;
        }
        let kind = if entrypoint > 0 && external > 0 {
            "service"
        } else if concurrency > 0 {
            "worker"
        } else {
            "library"
        };
        services.push(ServiceBoundary {
            path: name.clone(),
            name,
            kind: kind.to_string(),
            file_count,
            entrypoint_signals: entrypoint,
            external_signals: external,
            concurrency_signals: concurrency,
        });
    }
    services.sort_by(|a, b| {
        b.file_count
            .cmp(&a.file_count)
            .then_with(|| a.path.cmp(&b.path))
    });

    Ok(RepoFacts {
        root: root.to_path_buf(),
        scanned_files,
        skipped_source_files,
        hotspots,
        services,
    })
}

fn map_warnings(skipped_source_files: &[String], unreadable_scenarios: &[String]) -> Vec<String> {
    let mut warnings = Vec::new();
    if !skipped_source_files.is_empty() {
        warnings.push(format!(
            "map scan skipped {} source file(s); hotspot coverage is incomplete",
            skipped_source_files.len()
        ));
    }
    if !unreadable_scenarios.is_empty() {
        warnings.push(format!(
            "map suites skipped {} unreadable scenario file(s); suite attribution confidence is reduced",
            unreadable_scenarios.len()
        ));
    }
    warnings
}

fn discover_scenarios(root: &Path) -> FozzyResult<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::<PathBuf>::new();
    for entry in WalkDir::new(root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if p.file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n.ends_with(".fozzy.json"))
        {
            out.push(p.to_path_buf());
        }
    }
    out.sort();
    Ok(out)
}

fn hotspot_hints(h: &MapHotspot) -> Vec<String> {
    let mut out = BTreeSet::<String>::new();
    out.insert(h.component.to_ascii_lowercase());
    out.insert(h.path.to_ascii_lowercase());
    if let Some(stem) = Path::new(&h.path).file_stem().and_then(|s| s.to_str()) {
        out.insert(stem.to_ascii_lowercase().replace('.', "-"));
        out.insert(stem.to_ascii_lowercase().replace('.', "_"));
    }
    out.into_iter().filter(|s| s.len() >= 3).collect()
}

fn suite_allows_attribution_match(
    suite: &str,
    hints: &AttributionHints,
    scenario_tokens: &BTreeSet<String>,
) -> bool {
    if suite == SUITE_TEST_DET || suite == SUITE_RUN_REPLAY_CI {
        return true;
    }

    let shared = hints
        .tokens
        .intersection(scenario_tokens)
        .collect::<Vec<_>>();
    if shared.len() >= 2 {
        return true;
    }

    if shared
        .into_iter()
        .any(|token| is_strong_attribution_token(token))
    {
        return true;
    }

    hints
        .exact_stems
        .iter()
        .any(|stem| is_exact_hotspot_stem(stem) && scenario_tokens.contains(stem))
}

fn is_strong_attribution_token(token: &str) -> bool {
    token.len() >= 4 && !is_generic_attribution_token(token)
}

fn is_exact_hotspot_stem(token: &str) -> bool {
    token.len() == 3 && !is_generic_attribution_token(token)
}

fn is_generic_attribution_token(token: &str) -> bool {
    matches!(
        token,
        "app"
            | "apps"
            | "artifact"
            | "artifacts"
            | "bin"
            | "ci"
            | "cli"
            | "cmd"
            | "config"
            | "crate"
            | "crates"
            | "dist"
            | "engine"
            | "example"
            | "examples"
            | "explore"
            | "fail"
            | "file"
            | "files"
            | "fuzz"
            | "host"
            | "json"
            | "main"
            | "memory"
            | "mode"
            | "modes"
            | "module"
            | "modules"
            | "package"
            | "packages"
            | "pass"
            | "proc"
            | "replay"
            | "root"
            | "run"
            | "scenario"
            | "scenarios"
            | "service"
            | "services"
            | "shrink"
            | "src"
            | "test"
            | "tests"
            | "timeout"
            | "trace"
    )
}

fn tokenize(input: &str) -> BTreeSet<String> {
    input
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| s.len() >= 3)
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

fn should_skip_path(p: &Path) -> bool {
    let Some(parent) = p.parent() else {
        return false;
    };
    parent.components().any(|component| {
        component.as_os_str().to_str().is_some_and(|segment| {
            [
                ".git",
                "target",
                "node_modules",
                ".fozzy",
                "dist",
                "build",
                "out",
                "coverage",
                "vendor",
                ".next",
                ".tmp",
            ]
            .iter()
            .any(|needle| segment.eq_ignore_ascii_case(needle))
        })
    })
}

fn is_candidate_file(p: &Path) -> bool {
    if p.file_name().and_then(|s| s.to_str()).is_some_and(|n| {
        matches!(
            n.to_ascii_lowercase().as_str(),
            "package-lock.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "npm-shrinkwrap.json"
                | "bun.lockb"
                | "bun.lock"
                | "Cargo.lock"
                | "go.sum"
                | "Gemfile.lock"
                | "Pipfile.lock"
                | "poetry.lock"
                | "composer.lock"
        )
    }) {
        return false;
    }
    if p.file_name().and_then(|s| s.to_str()).is_some_and(|n| {
        let lower = n.to_ascii_lowercase();
        lower.ends_with(".lock")
            || lower.ends_with(".min.js")
            || lower.ends_with(".min.css")
            || lower.contains(".generated.")
            || lower.contains(".gen.")
    }) {
        return false;
    }
    if p.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("dockerfile"))
    {
        return true;
    }
    let Some(ext) = p.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "rs" | "go"
            | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "py"
            | "java"
            | "kt"
            | "c"
            | "cc"
            | "cpp"
            | "h"
            | "hpp"
            | "cs"
            | "swift"
            | "rb"
            | "php"
            | "scala"
            | "sql"
            | "sh"
    )
}

fn accumulate_signals_line(s: &mut HotspotSignals, line: &str) {
    let lower = line.to_ascii_lowercase();
    s.branch_signals = s.branch_signals.saturating_add(count_hits(
        &lower,
        &[" if ", " else ", " match ", " switch ", " case ", " catch "],
    ));
    s.concurrency_signals = s.concurrency_signals.saturating_add(count_hits(
        &lower,
        &[
            " async ",
            ".await",
            "thread",
            "mutex",
            "rwlock",
            "channel",
            "spawn",
            "tokio::",
            "select!",
            "goroutine",
            "go func",
        ],
    ));
    s.external_signals = s.external_signals.saturating_add(count_hits(
        &lower,
        &[
            "http://",
            "https://",
            "grpc",
            "sql",
            "redis",
            "kafka",
            "rabbit",
            "nats",
            "s3",
            "command::new",
            "std::fs",
            "subprocess",
            "socket",
            "database",
            "postgres",
            "mysql",
            "mongodb",
        ],
    ));
    s.failure_signals = s.failure_signals.saturating_add(count_hits(
        &lower,
        &[
            "timeout",
            "retry",
            "backoff",
            "circuit",
            "panic",
            "throw",
            "except",
            "rollback",
            "compensat",
            "fail",
            "error",
        ],
    ));
    s.memory_signals = s.memory_signals.saturating_add(count_hits(
        &lower,
        &["alloc", "free", "leak", "memory", "heap"],
    ));
    s.entrypoint_signals = s.entrypoint_signals.saturating_add(count_hits(
        &lower,
        &[
            "fn main",
            "main(",
            "applisten",
            "listen(",
            "router",
            "fastapi",
            "express(",
            "httpserver",
            "grpcserver",
            "deployment",
            "kind: service",
        ],
    ));
}

fn count_hits(haystack: &str, needles: &[&str]) -> usize {
    needles.iter().map(|n| haystack.matches(n).count()).sum()
}

fn score_signals(s: &HotspotSignals) -> (u8, Vec<String>) {
    let mut reasons = Vec::<String>::new();
    let mut score = 0usize;

    score += s.branch_signals.min(30);
    if s.branch_signals > 8 {
        reasons.push(format!("high branch density ({})", s.branch_signals));
    }

    score += s.concurrency_signals.saturating_mul(6).min(30);
    if s.concurrency_signals > 0 {
        reasons.push(format!("concurrency signals ({})", s.concurrency_signals));
    }

    score += s.external_signals.saturating_mul(5).min(25);
    if s.external_signals > 0 {
        reasons.push(format!(
            "external side-effect signals ({})",
            s.external_signals
        ));
    }

    score += s.failure_signals.saturating_mul(3).min(15);
    if s.failure_signals > 3 {
        reasons.push(format!(
            "failure/timeout/retry signals ({})",
            s.failure_signals
        ));
    }

    if s.memory_signals > 2 {
        score += 8;
        reasons.push(format!("memory management signals ({})", s.memory_signals));
    }

    if s.entrypoint_signals > 0 {
        score += 5;
        reasons.push("service/entrypoint boundary indicators".to_string());
    }

    if s.line_count > 500 {
        score += 7;
        reasons.push(format!("large file size ({} lines)", s.line_count));
    } else if s.line_count > 250 {
        score += 4;
    }

    (score.min(100) as u8, reasons)
}

fn component_for_path(rel: &Path) -> String {
    let parts: Vec<String> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    if parts.is_empty() {
        return "root".to_string();
    }
    for marker in ["services", "apps", "packages", "crates", "modules"] {
        if let Some(i) = parts.iter().position(|p| p == marker)
            && let Some(next) = parts.get(i + 1)
        {
            return format!("{marker}/{next}");
        }
    }
    parts.first().cloned().unwrap_or_else(|| "root".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fozzy-map-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn map_suites_reports_uncovered_hotspots() {
        let root = temp_dir("coverage");
        let src = root.join("services/payments");
        let tests = root.join("tests");
        std::fs::create_dir_all(&src).expect("src");
        std::fs::create_dir_all(&tests).expect("tests");
        std::fs::write(
            src.join("handler.rs"),
            r#"
            async fn handle() {
                if retry { tokio::spawn(async move {}); }
                let _ = std::fs::read("x");
                if timeout { panic!("boom"); }
            }
            "#,
        )
        .expect("write source");

        let report = map_suites(&MapSuitesOptions {
            root: root.clone(),
            scenario_root: tests.clone(),
            min_risk: 10,
            profile: TopologyProfile::Pedantic,
            shrink_policy: ShrinkCoveragePolicy::NoKnownFailures,
            limit: 50,
            offset: 0,
            max_matched_scenarios: 25,
        })
        .expect("map suites");
        assert!(report.required_hotspot_count > 0);
        assert!(report.uncovered_hotspot_count > 0);
    }

    #[test]
    fn profiles_are_progressively_stricter() {
        let signals = HotspotSignals {
            line_count: 300,
            branch_signals: 10,
            concurrency_signals: 1,
            external_signals: 1,
            failure_signals: 1,
            memory_signals: 1,
            entrypoint_signals: 1,
        };
        let balanced = required_suites_for_hotspot(
            TopologyProfile::Balanced,
            ShrinkCoveragePolicy::FailureOnly,
            &signals,
            true,
        )
        .len();
        let pedantic = required_suites_for_hotspot(
            TopologyProfile::Pedantic,
            ShrinkCoveragePolicy::FailureOnly,
            &signals,
            true,
        )
        .len();
        let overkill = required_suites_for_hotspot(
            TopologyProfile::Overkill,
            ShrinkCoveragePolicy::FailureOnly,
            &signals,
            true,
        )
        .len();
        assert!(balanced <= pedantic, "balanced should be least strict");
        assert!(pedantic <= overkill, "overkill should be most strict");
    }

    #[test]
    fn no_known_failures_policy_downgrades_shrink_failure_requirement() {
        let signals = HotspotSignals {
            line_count: 50,
            branch_signals: 4,
            concurrency_signals: 0,
            external_signals: 0,
            failure_signals: 1,
            memory_signals: 0,
            entrypoint_signals: 0,
        };
        let required = required_suites_for_hotspot(
            TopologyProfile::Pedantic,
            ShrinkCoveragePolicy::NoKnownFailures,
            &signals,
            false,
        );
        assert!(required.iter().any(|s| s == SUITE_SHRINK_EXERCISED));
        assert!(!required.iter().any(|s| s == SUITE_SHRINK_FAILURE));
    }

    #[test]
    fn no_known_failures_policy_requires_failure_if_failure_trace_exists() {
        let signals = HotspotSignals {
            line_count: 50,
            branch_signals: 4,
            concurrency_signals: 0,
            external_signals: 0,
            failure_signals: 1,
            memory_signals: 0,
            entrypoint_signals: 0,
        };
        let required = required_suites_for_hotspot(
            TopologyProfile::Pedantic,
            ShrinkCoveragePolicy::NoKnownFailures,
            &signals,
            true,
        );
        assert!(required.iter().any(|s| s == SUITE_SHRINK_FAILURE));
    }

    #[test]
    fn candidate_file_filter_excludes_dependency_and_generated_artifacts() {
        assert!(!is_candidate_file(Path::new("/repo/package-lock.json")));
        assert!(!is_candidate_file(Path::new("/repo/Cargo.lock")));
        assert!(!is_candidate_file(Path::new("/repo/dist/app.min.js")));
        assert!(!is_candidate_file(Path::new(
            "/repo/src/types.generated.ts"
        )));
        assert!(!is_candidate_file(Path::new("/repo/config/runtime.json")));
        assert!(is_candidate_file(Path::new("/repo/src/main.rs")));
    }

    #[test]
    fn should_skip_repo_local_tmp_outputs() {
        assert!(should_skip_path(Path::new("./.tmp/map.suites.json")));
        assert!(should_skip_path(Path::new("/repo/.tmp/report.json")));
        assert!(!should_skip_path(Path::new("./src/map_cmd.rs")));
    }

    #[test]
    fn map_suites_credits_natural_fetch_host_scenario() {
        let root = temp_dir("fetch-host-credit");
        let src = root.join("crates/cli/src/cmd");
        let tests = root.join("tests");
        std::fs::create_dir_all(&src).expect("src");
        std::fs::create_dir_all(&tests).expect("tests");
        std::fs::write(
            src.join("fetch.rs"),
            r#"
            pub fn fetch() {
                let _ = std::fs::read("config.json");
            }
            "#,
        )
        .expect("write source");
        std::fs::write(
            tests.join("fetch.host.fozzy.json"),
            r#"
            {
              "version": 1,
              "name": "fetch-host",
              "steps": [
                { "type": "fs_write", "path": "tmp/fetch.txt", "data": "ok" },
                { "type": "fs_read_assert", "path": "tmp/fetch.txt", "equals": "ok" }
              ]
            }
            "#,
        )
        .expect("write scenario");

        let report = map_suites(&MapSuitesOptions {
            root: root.clone(),
            scenario_root: tests,
            min_risk: 1,
            profile: TopologyProfile::Pedantic,
            shrink_policy: ShrinkCoveragePolicy::NoKnownFailures,
            limit: 50,
            offset: 0,
            max_matched_scenarios: 25,
        })
        .expect("map suites");
        let suite = report.suites.first().expect("suite");
        assert!(
            suite.covered_suites.iter().any(|s| s == SUITE_HOST),
            "expected host suite to be credited from natural fetch.host scenario: {:?}",
            suite.coverage_evidence
        );
    }

    #[test]
    fn map_suites_reports_unreadable_scenarios() {
        let root = temp_dir("unreadable-scenarios");
        let src = root.join("src");
        let tests = root.join("tests");
        std::fs::create_dir_all(&src).expect("src");
        std::fs::create_dir_all(&tests).expect("tests");
        std::fs::write(
            src.join("main.rs"),
            "fn main() { if true { std::thread::spawn(|| {}); } }",
        )
        .expect("write source");
        std::fs::write(
            tests.join("good.fozzy.json"),
            r#"{"version":1,"name":"good","steps":[{"type":"assert_ok","value":true}]}"#,
        )
        .expect("write good");
        std::fs::write(tests.join("bad.fozzy.json"), [0_u8, 159, 146, 150]).expect("write bad");

        let report = map_suites(&MapSuitesOptions {
            root: root.clone(),
            scenario_root: tests,
            min_risk: 1,
            profile: TopologyProfile::Pedantic,
            shrink_policy: ShrinkCoveragePolicy::NoKnownFailures,
            limit: 50,
            offset: 0,
            max_matched_scenarios: 25,
        })
        .expect("map suites");

        assert_eq!(report.unreadable_scenarios.len(), 1);
        assert!(
            !report.warnings.is_empty(),
            "expected degraded-confidence warning when scenarios are unreadable"
        );
    }

    #[test]
    fn suite_specific_attribution_ignores_generic_token_only_overlap() {
        let hints = AttributionHints::from_hotspot_hints(&hotspot_hints(&MapHotspot {
            id: "src:src/runtime/memory.rs".to_string(),
            component: "src".to_string(),
            path: "src/runtime/memory.rs".to_string(),
            risk_score: 10,
            reasons: Vec::new(),
            signals: HotspotSignals {
                memory_signals: 1,
                ..HotspotSignals::default()
            },
            recommended_suites: vec![SUITE_MEMORY.to_string()],
        }));
        let scenario_tokens =
            tokenize("tests/memory.pass.fozzy.json memory-pass memory_alloc memory_free");

        assert!(
            !suite_allows_attribution_match(SUITE_MEMORY, &hints, &scenario_tokens),
            "generic suite words alone should not count as hotspot attribution"
        );
    }

    #[test]
    fn suite_specific_attribution_accepts_exact_three_letter_stem_matches() {
        let hints = AttributionHints::from_hotspot_hints(&hotspot_hints(&MapHotspot {
            id: "cli:crates/cli/src/cmd/tag.rs".to_string(),
            component: "cli".to_string(),
            path: "crates/cli/src/cmd/tag.rs".to_string(),
            risk_score: 10,
            reasons: Vec::new(),
            signals: HotspotSignals {
                branch_signals: 10,
                ..HotspotSignals::default()
            },
            recommended_suites: vec![SUITE_FUZZ.to_string()],
        }));

        assert!(suite_allows_attribution_match(
            SUITE_FUZZ,
            &hints,
            &tokenize("tests/tag.fuzz.fozzy.json name=tag-fuzz")
        ));
        assert!(suite_allows_attribution_match(
            SUITE_EXPLORE,
            &hints,
            &tokenize("tests/tag.explore.fozzy.json name=tag-explore")
        ));
        assert!(suite_allows_attribution_match(
            SUITE_SHRINK_EXERCISED,
            &hints,
            &tokenize("tests/tag.shrink.fozzy.json name=tag-shrink")
        ));
    }

    #[test]
    fn map_suites_credits_short_natural_hotspot_names() {
        let root = temp_dir("short-natural-hotspot-credit");
        let src_cmd = root.join("crates/cli/src/cmd");
        let src_cli = root.join("crates/cli/src");
        let tests = root.join("tests");
        std::fs::create_dir_all(&src_cmd).expect("src cmd");
        std::fs::create_dir_all(&src_cli).expect("src cli");
        std::fs::create_dir_all(&tests).expect("tests");

        std::fs::write(
            src_cmd.join("tag.rs"),
            r#"
            pub fn tag() {
                if true {}
                if true {}
                if true {}
                if true {}
                if true {}
                if true {}
                if true {}
                if true {}
                if std::env::var("FOZZY_FAIL").is_err() { panic!("tag failure"); }
                if "retry".contains("retry") { let _ = "error"; }
                if "timeout".contains("timeout") { let _ = "fail"; }
                if "backoff".contains("backoff") { let _ = "error"; }
            }
            "#,
        )
        .expect("write tag source");
        std::fs::write(
            src_cli.join("ipc.rs"),
            r#"
            pub fn ipc() {
                std::thread::spawn(|| {
                    if true {
                        let _ = 1 + 1;
                    }
                });
            }
            "#,
        )
        .expect("write ipc source");
        std::fs::write(
            src_cmd.join("log.rs"),
            r#"
            pub fn log_output() {
                let first_error = std::env::var("FOZZY_FAIL").is_err();
                if first_error { panic!("boom"); }
                if "retry".contains("retry") { let _ = "error"; }
                if "timeout".contains("timeout") { let _ = "fail"; }
                if "backoff".contains("backoff") { let _ = "error"; }
            }
            "#,
        )
        .expect("write log source");

        std::fs::write(
            tests.join("tag.explore.fozzy.json"),
            r#"{ "version": 1, "name": "tag-explore", "distributed": true }"#,
        )
        .expect("write tag explore");
        std::fs::write(
            tests.join("tag.fuzz.fozzy.json"),
            r#"{ "version": 1, "name": "tag-fuzz", "mode": "fuzz" }"#,
        )
        .expect("write tag fuzz");
        std::fs::write(
            tests.join("tag.shrink.fozzy.json"),
            r#"{ "version": 1, "name": "tag-shrink", "shrink_trace": true }"#,
        )
        .expect("write tag shrink");
        std::fs::write(
            tests.join("ipc.explore.fozzy.json"),
            r#"{ "version": 1, "name": "ipc-explore", "distributed": true }"#,
        )
        .expect("write ipc explore");
        std::fs::write(
            tests.join("log.explore.fozzy.json"),
            r#"{ "version": 1, "name": "log-explore", "distributed": true }"#,
        )
        .expect("write log explore");

        let report = map_suites(&MapSuitesOptions {
            root: root.clone(),
            scenario_root: tests,
            min_risk: 1,
            profile: TopologyProfile::Pedantic,
            shrink_policy: ShrinkCoveragePolicy::ExercisedOk,
            limit: 50,
            offset: 0,
            max_matched_scenarios: 25,
        })
        .expect("map suites");

        let by_path = report
            .suites
            .iter()
            .map(|suite| (suite.path.as_str(), suite))
            .collect::<BTreeMap<_, _>>();

        let tag = by_path.get("crates/cli/src/cmd/tag.rs").expect("tag suite");
        assert!(
            tag.covered_suites
                .iter()
                .any(|suite| suite == SUITE_EXPLORE)
        );
        assert!(tag.covered_suites.iter().any(|suite| suite == SUITE_FUZZ));
        assert!(
            tag.covered_suites
                .iter()
                .any(|suite| suite == SUITE_SHRINK_EXERCISED)
        );

        let ipc = by_path.get("crates/cli/src/ipc.rs").expect("ipc suite");
        assert!(
            ipc.covered_suites
                .iter()
                .any(|suite| suite == SUITE_EXPLORE)
        );

        let log = by_path.get("crates/cli/src/cmd/log.rs").expect("log suite");
        assert!(
            log.covered_suites
                .iter()
                .any(|suite| suite == SUITE_EXPLORE)
        );
    }
}
