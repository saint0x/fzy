use super::*;

pub(super) fn scenario_error(err: impl fmt::Display) -> anyhow::Error {
    anyhow!(err.to_string())
}

pub(super) fn scenario_config() -> Result<fzscenario::Config> {
    let cwd = std::env::current_dir().context("failed to resolve current working directory")?;
    let config_path = cwd.join("fozzy.toml");
    fzscenario::Config::load_optional_checked(&config_path).map_err(scenario_error)
}

pub(super) fn scenario_config_with_backends(host_backends: bool) -> Result<fzscenario::Config> {
    let mut config = scenario_config()?;
    if host_backends {
        config.proc_backend = fzscenario::ProcBackend::Host;
        config.fs_backend = fzscenario::FsBackend::Host;
        config.http_backend = fzscenario::HttpBackend::Host;
    }
    Ok(config)
}

pub(super) fn scenario_memory_options(config: &fzscenario::Config) -> fzscenario::MemoryOptions {
    fzscenario::MemoryOptions {
        track: config.mem_track,
        limit_mb: config.mem_limit_mb,
        fail_after_allocs: config.mem_fail_after,
        fail_on_leak: config.fail_on_leak,
        leak_budget_bytes: config.leak_budget,
        fragmentation_seed: config.mem_fragmentation_seed,
        pressure_wave: config.mem_pressure_wave.clone(),
        artifacts: config.mem_artifacts,
    }
}

pub(super) fn scenario_reporter(format: Format) -> fzscenario::Reporter {
    match format {
        Format::Text => fzscenario::Reporter::Pretty,
        Format::Json => fzscenario::Reporter::Json,
    }
}

pub(super) fn parse_scenario_reporter(raw: &str) -> Result<fzscenario::Reporter> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "pretty" => Ok(fzscenario::Reporter::Pretty),
        "json" => Ok(fzscenario::Reporter::Json),
        "junit" => Ok(fzscenario::Reporter::Junit),
        "html" => Ok(fzscenario::Reporter::Html),
        other => bail!("unsupported report format `{other}`"),
    }
}

pub(super) fn parse_topology_profile(raw: &str) -> Result<fzscenario::TopologyProfile> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "balanced" => Ok(fzscenario::TopologyProfile::Balanced),
        "pedantic" => Ok(fzscenario::TopologyProfile::Pedantic),
        "overkill" => Ok(fzscenario::TopologyProfile::Overkill),
        other => bail!("unsupported topology profile `{other}`"),
    }
}

pub(super) fn scenario_exit_code(status: fzscenario::ExitStatus) -> i32 {
    match status {
        fzscenario::ExitStatus::Pass => 0,
        fzscenario::ExitStatus::Fail => 1,
        fzscenario::ExitStatus::Error => 2,
        fzscenario::ExitStatus::Timeout => 3,
        fzscenario::ExitStatus::Crash => 4,
    }
}

pub(super) fn strict_checker_failure(summary: &fzscenario::RunSummary) -> bool {
    summary.status == fzscenario::ExitStatus::Pass
        && summary
            .findings
            .iter()
            .any(|finding| finding.kind == fzscenario::FindingKind::Checker)
}

pub(super) fn render_value_output(value_format: Format, value: &impl Serialize) -> Result<String> {
    match value_format {
        Format::Text => Ok(serde_json::to_string_pretty(value)?),
        Format::Json => Ok(serde_json::to_string(value)?),
    }
}

pub(super) fn render_report_show_output(
    format: Format,
    reporter: fzscenario::Reporter,
    value: serde_json::Value,
) -> Result<String> {
    match (format, reporter) {
        (Format::Text, fzscenario::Reporter::Pretty)
        | (Format::Text, fzscenario::Reporter::Junit)
        | (Format::Text, fzscenario::Reporter::Html) => Ok(value
            .get("content")
            .and_then(|content| content.as_str())
            .unwrap_or_default()
            .to_string()),
        _ => render_value_output(format, &value),
    }
}

pub(super) fn native_usage_doc() -> serde_json::Value {
    serde_json::json!({
        "title": "FZ CLI usage",
        "items": [
            {
                "command": "fz map suites",
                "when": "Start production validation with hotspot coverage mapping.",
                "how": "fz map suites --root . --scenario-root tests --profile pedantic --json"
            },
            {
                "command": "fz doctor",
                "when": "Audit determinism and environment behavior for a scenario.",
                "how": "fz doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 123 --json"
            },
            {
                "command": "fz test",
                "when": "Run strict deterministic scenario suites, or execute native `.fzy` test bodies directly.",
                "how": "fz test tests/example.fozzy.json --det --strict-verify --json"
            },
            {
                "command": "fz run",
                "when": "Run a single scenario or native source target with production runtime checks.",
                "how": "fz run tests/example.fozzy.json --det --record artifacts/example.trace.fozzy --json"
            },
            {
                "command": "fz fuzz",
                "when": "Coverage-fuzz a scenario target natively through the local scenario engine.",
                "how": "fz fuzz tests/example.fozzy.json --json"
            },
            {
                "command": "fz explore",
                "when": "Explore distributed schedules deterministically.",
                "how": "fz explore tests/distributed.pass.fozzy.json --json"
            },
            {
                "command": "fz replay | shrink | ci",
                "when": "Validate recorded traces, replay them, shrink them, and run the CI bundle locally.",
                "how": "fz trace verify artifacts/example.trace.fozzy --strict --json && fz replay artifacts/example.trace.fozzy --json && fz ci artifacts/example.trace.fozzy --json"
            },
            {
                "command": "fz artifacts ls latest | fz report show latest",
                "when": "Inspect the most recent run artifacts and rendered report output.",
                "how": "fz artifacts ls latest --json && fz report show latest --format pretty"
            },
            {
                "command": "fz env | schema | validate",
                "when": "Inspect execution capabilities, authoring schema, and scenario validity.",
                "how": "fz env --json && fz schema --json && fz validate tests/example.fozzy.json --json"
            },
            {
                "command": "fz inspect surface | artifacts | embedding",
                "when": "Explain what is builtin vs `use core.*`, inspect emitted interop artifacts, and read the embedding contract without spelunking generated files.",
                "how": "fz inspect surface --json && fz inspect artifacts examples/fullstack --release --json && fz inspect embedding examples/fullstack --json"
            },
            {
                "command": "fz inspect stdlib <module>",
                "when": "Dump the embedded core stdlib source the compiler merges for `use core.*` facades and confirm it parses on the active toolchain.",
                "how": "fz inspect stdlib process --json"
            }
        ]
    })
}

pub(super) fn native_usage_text() -> String {
    let items = native_usage_doc()
        .get("items")
        .and_then(|items| items.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = String::from("FZ CLI usage\n\n");
    for item in items {
        let command = item
            .get("command")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let when = item
            .get("when")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let how = item
            .get("how")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        out.push_str(&format!("{command}:\n  when: {when}\n  how:  {how}\n\n"));
    }
    out.trim_end().to_string()
}

pub(super) fn render_scenario_run_result(
    format: Format,
    run: fzscenario::RunResult,
    strict: bool,
) -> Result<String> {
    let status = run.summary.status;
    let strict_failure = strict && strict_checker_failure(&run.summary);
    let rendered = match format {
        Format::Text => run.summary.pretty(),
        Format::Json => serde_json::to_string(&run.summary)?,
    };
    if status != fzscenario::ExitStatus::Pass || strict_failure {
        return Err(CommandFailure {
            exit_code: if strict_failure {
                1
            } else {
                scenario_exit_code(status)
            },
            output: rendered,
        }
        .into());
    }
    Ok(rendered)
}

pub(super) fn render_doctor_report(
    format: Format,
    report: fzscenario::DoctorReport,
    strict: bool,
) -> Result<String> {
    let rendered = render_value_output(format, &report)?;
    if strict && !report.ok {
        return Err(CommandFailure {
            exit_code: 1,
            output: rendered,
        }
        .into());
    }
    Ok(rendered)
}

pub(super) fn render_trace_verify_report(
    format: Format,
    report: fzscenario::TraceVerifyReport,
    strict: bool,
) -> Result<String> {
    let rendered = render_value_output(format, &report)?;
    if !report.ok || (strict && !report.warnings.is_empty()) {
        return Err(CommandFailure {
            exit_code: 1,
            output: rendered,
        }
        .into());
    }
    Ok(rendered)
}

pub(super) fn validate_scenario_file(path: &Path) -> Result<()> {
    let scenario_path = fzscenario::ScenarioPath::new(path.to_path_buf());
    let file = fzscenario::Scenario::load_file(&scenario_path).map_err(scenario_error)?;
    match file {
        fzscenario::ScenarioFile::Steps(_) => {
            let scenario = fzscenario::Scenario::load(&scenario_path).map_err(scenario_error)?;
            scenario.validate().map_err(scenario_error)?;
        }
        fzscenario::ScenarioFile::Suites(_) => {}
        fzscenario::ScenarioFile::Distributed(distributed) => {
            distributed.validate().map_err(scenario_error)?;
        }
    }
    Ok(())
}

pub(super) fn scenario_fuzz(target: &Path, format: Format) -> Result<String> {
    ensure_exists(target)?;
    let config = scenario_config()?;
    let target_spec = format!("scenario:{}", target.display());
    let parsed_target: fzscenario::FuzzTarget = target_spec.parse().map_err(scenario_error)?;
    let corpus_name = target
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(|stem| {
            stem.chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
                .collect::<String>()
        })
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| "scenario".to_string());
    let corpus_dir = config.corpora_dir().join("native-fz").join(corpus_name);
    let run = fzscenario::fuzz(
        &config,
        &parsed_target,
        &fzscenario::FuzzOptions {
            det: true,
            mode: fzscenario::FuzzMode::Coverage,
            seed: Some(1),
            time: None,
            runs: Some(16),
            max_input_bytes: 4096,
            corpus_dir: Some(corpus_dir),
            mutator: None,
            shrink: false,
            record_trace_to: None,
            reporter: scenario_reporter(format),
            crash_only: false,
            minimize: false,
            record_collision: fzscenario::RecordCollisionPolicy::Append,
            profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
            memory: scenario_memory_options(&config),
        },
    )
    .map_err(scenario_error)?;
    render_scenario_run_result(format, run, true)
}

pub(super) fn scenario_explore(target: &Path, format: Format) -> Result<String> {
    ensure_exists(target)?;
    let config = scenario_config()?;
    let run = fzscenario::explore(
        &config,
        fzscenario::ScenarioPath::new(target.to_path_buf()),
        &fzscenario::ExploreOptions {
            seed: Some(1),
            time: None,
            steps: Some(200),
            nodes: None,
            faults: None,
            schedule: fzscenario::ScheduleStrategy::CoverageGuided,
            checker: None,
            record_trace_to: None,
            shrink: true,
            minimize: true,
            reporter: scenario_reporter(format),
            record_collision: fzscenario::RecordCollisionPolicy::Append,
            profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
            memory: scenario_memory_options(&config),
        },
    )
    .map_err(scenario_error)?;
    render_scenario_run_result(format, run, true)
}

pub(super) fn scenario_replay_like(
    command: &str,
    target: &Path,
    strict: bool,
    format: Format,
) -> Result<String> {
    if is_native_test_artifact_target(target)? {
        return match command {
            "replay" => replay_native_test_artifacts(target, strict, format),
            "ci" => ci_native_test_artifacts(target, strict, format),
            "shrink" => bail!(
                "native test manifests do not support `fz shrink`; rerun `fz test` with a narrower `--filter` and deterministic seed instead"
            ),
            other => bail!("unsupported native test replay-like command `{other}`"),
        };
    }
    let config = scenario_config()?;
    let replay_target = resolve_replay_target(target)?;
    match command {
        "replay" => {
            let run = fzscenario::replay_trace(
                &config,
                fzscenario::TracePath::new(replay_target.clone()),
                &fzscenario::ReplayOptions {
                    step: false,
                    until: None,
                    dump_events: false,
                    profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
                    reporter: scenario_reporter(format),
                },
            )
            .map_err(scenario_error)?;
            render_scenario_run_result(format, run, true)
        }
        "shrink" => {
            let result = fzscenario::shrink_trace(
                &config,
                fzscenario::TracePath::new(replay_target.clone()),
                &fzscenario::ShrinkOptions {
                    out_trace_path: None,
                    budget: Some(Duration::from_secs(30)),
                    aggressive: false,
                    minimize: fzscenario::ShrinkMinimize::All,
                },
            )
            .map_err(scenario_error)?;
            let status = result.result.summary.status;
            let rendered = match format {
                Format::Text => format!(
                    "{}\nout_trace={}",
                    result.result.summary.pretty(),
                    result.out_trace_path
                ),
                Format::Json => serde_json::to_string(&serde_json::json!({
                    "outTrace": &result.out_trace_path,
                    "summary": &result.result.summary,
                }))?,
            };
            if status != fzscenario::ExitStatus::Pass {
                return Err(CommandFailure {
                    exit_code: scenario_exit_code(status),
                    output: rendered,
                }
                .into());
            }
            Ok(rendered)
        }
        "ci" => {
            let report = fzscenario::ci_evaluate(
                &config,
                &fzscenario::CiOptions {
                    trace: replay_target.clone(),
                    flake_runs: Vec::new(),
                    flake_budget_pct: None,
                    perf_baseline: None,
                    max_p99_delta_pct: None,
                    strict,
                },
            )
            .map_err(scenario_error)?;
            let rendered = render_value_output(format, &report)?;
            if !report.ok {
                return Err(CommandFailure {
                    exit_code: 1,
                    output: rendered,
                }
                .into());
            }
            Ok(rendered)
        }
        other => bail!("unsupported replay-like command `{other}`"),
    }
}

pub(super) fn record_goal_trace_from_scenario(
    primary_scenario: &Path,
    goal_trace_path: &Path,
    seed: u64,
) -> Result<()> {
    let config = scenario_config()?;
    let run = fzscenario::run_scenario(
        &config,
        fzscenario::ScenarioPath::new(primary_scenario.to_path_buf()),
        &fzscenario::RunOptions {
            det: true,
            seed: Some(seed),
            timeout: None,
            reporter: fzscenario::Reporter::Json,
            record_trace_to: Some(goal_trace_path.to_path_buf()),
            filter: None,
            jobs: None,
            fail_fast: false,
            record_collision: fzscenario::RecordCollisionPolicy::Overwrite,
            profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
            proc_backend: config.proc_backend,
            fs_backend: config.fs_backend,
            http_backend: config.http_backend,
            memory: scenario_memory_options(&config),
        },
    )
    .map_err(scenario_error)?;
    if run.summary.status != fzscenario::ExitStatus::Pass {
        return Err(CommandFailure {
            exit_code: scenario_exit_code(run.summary.status),
            output: run.summary.pretty(),
        }
        .into());
    }
    Ok(())
}

pub(super) fn is_fozzy_scenario(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".fozzy.json"))
        .unwrap_or(false)
}

pub(super) fn fmt_command(targets: &[PathBuf], check: bool, format: Format) -> Result<String> {
    let effective_targets = if targets.is_empty() {
        vec![std::env::current_dir().context("failed to resolve current working directory")?]
    } else {
        targets.to_vec()
    };
    for target in &effective_targets {
        ensure_exists(target)?;
    }
    let mut changed_files = Vec::<PathBuf>::new();
    for target in &effective_targets {
        changed_files.extend(format_source_target(target, check)?);
    }
    changed_files.sort();
    changed_files.dedup();

    let status = if check && !changed_files.is_empty() {
        "error"
    } else {
        "ok"
    };
    match format {
        Format::Text => {
            let mut out = render_text_fields(&[
                ("status", status.to_string()),
                ("mode", "fmt".to_string()),
                ("check", check.to_string()),
                ("targets", effective_targets.len().to_string()),
                ("changed_files", changed_files.len().to_string()),
            ]);
            for file in changed_files {
                out.push('\n');
                out.push_str(&format!("file: {}", file.display()));
            }
            Ok(out)
        }
        Format::Json => Ok(serde_json::json!({
            "status": status,
            "mode": "fmt",
            "check": check,
            "targets": effective_targets.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "changedFiles": changed_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        })
        .to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct DocItem {
    pub(super) kind: String,
    pub(super) name: String,
    pub(super) signature: String,
    pub(super) module: String,
    pub(super) path: String,
    pub(super) line: usize,
    pub(super) docs: String,
}

#[derive(Debug, Clone)]
pub(super) struct DocArtifacts {
    pub(super) mode: String,
    pub(super) output_format: String,
    pub(super) item_count: usize,
    pub(super) output_path: Option<PathBuf>,
    pub(super) reference_path: Option<PathBuf>,
    pub(super) rendered: String,
}

pub(super) const DOC_REF_START: &str = "<!-- fozzydoc:api:start -->";
pub(super) const DOC_REF_END: &str = "<!-- fozzydoc:api:end -->";

pub(super) fn generate_doc_artifacts(
    path: &Path,
    output_format: &str,
    out: Option<&Path>,
    reference: Option<&Path>,
) -> Result<DocArtifacts> {
    let module_set = load_resolved_module_set(path)?;
    let mut items = Vec::<DocItem>::new();
    for module in &module_set.modules {
        items.extend(extract_doc_items_from_module(module));
    }
    items.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    let rendered = match output_format.trim().to_ascii_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(&serde_json::json!({
            "schemaVersion": "fozzylang.doc.v1",
            "source": module_set.resolved.source_path.display().to_string(),
            "projectRoot": module_set.resolved.project_root.display().to_string(),
            "items": items,
        }))?,
        "markdown" | "md" => render_docs_markdown(&items),
        "html" => render_docs_html(&items),
        other => bail!("unsupported doc format `{other}` (expected json|html|markdown)"),
    };

    if let Some(reference_path) = reference {
        integrate_doc_reference(reference_path, &items)?;
    }
    if let Some(out_path) = out {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }
        std::fs::write(out_path, rendered.as_bytes())
            .with_context(|| format!("failed writing {}", out_path.display()))?;
    }

    Ok(DocArtifacts {
        mode: "doc-gen".to_string(),
        output_format: output_format.to_ascii_lowercase(),
        item_count: items.len(),
        output_path: out.map(Path::to_path_buf),
        reference_path: reference.map(Path::to_path_buf),
        rendered,
    })
}
