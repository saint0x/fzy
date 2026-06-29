use super::*;

pub(super) fn perf_command(artifact: Option<&Path>, format: Format) -> Result<String> {
    let path = artifact
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("artifacts/bench_core_rust_vs_fzy.json"));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed reading benchmark artifact {}", path.display()))?;
    let payload: serde_json::Value =
        serde_json::from_str(&text).context("invalid benchmark artifact JSON")?;
    let benches = payload
        .get("benches")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("benchmark artifact missing `benches` array"))?;
    let mut worst = ("".to_string(), 0.0f64);
    let mut sum = 0.0f64;
    let mut count = 0usize;
    for bench in benches {
        let name = bench
            .get("bench")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let ratio = bench
            .get("ratio_fzy_over_rust")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0);
        if ratio > worst.1 {
            worst = (name, ratio);
        }
        sum += ratio;
        count += 1;
    }
    let avg = if count == 0 { 0.0 } else { sum / count as f64 };
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "perf".to_string()),
            ("artifact", path.display().to_string()),
            ("bench_count", count.to_string()),
            ("average_ratio_fzy_over_rust", format!("{avg:.6}")),
            ("worst_kernel", worst.0),
            ("worst_ratio_fzy_over_rust", format!("{:.6}", worst.1)),
        ])),
        Format::Json => Ok(serde_json::json!({
            "status": "ok",
            "mode": "perf",
            "artifact": path.display().to_string(),
            "benchCount": count,
            "averageRatioFzyOverRust": avg,
            "worstKernel": worst.0,
            "worstRatioFzyOverRust": worst.1,
        })
        .to_string()),
    }
}

pub(super) fn stability_dashboard_command(format: Format) -> Result<String> {
    let repo_root = repo_root();
    let exit_criteria_script = repo_root.join("scripts/exit_criteria.py");
    let exit_status = ProcessCommand::new("python3")
        .arg(&exit_criteria_script)
        .arg("status")
        .current_dir(&repo_root)
        .output()
        .context("failed to run exit criteria status command")?;
    if !exit_status.status.success() {
        bail!(
            "exit criteria status failed for {}",
            exit_criteria_script.display()
        );
    }
    let exit_payload: serde_json::Value =
        serde_json::from_slice(&exit_status.stdout).context("invalid exit criteria payload")?;
    let dashboard = serde_json::json!({
        "schemaVersion": "fozzylang.stability_dashboard.v1",
        "generatedAt": chrono_like_now_utc(),
        "compatibility": fzscenario::compatibility_info(),
        "maturity": exit_payload.get("seriousSystemsLanguageMaturity").cloned().unwrap_or(serde_json::Value::Bool(false)),
        "criteria": exit_payload.get("criteria").cloned().unwrap_or(serde_json::json!({})),
        "performance": {
            "summaryCommand": "fz perf [--artifact artifacts/bench_core_rust_vs_fzy.json]",
            "artifact": "artifacts/bench_core_rust_vs_fzy.json",
            "workloads": [
                {"name": "cli_startup", "description": "CLI startup latency"},
                {"name": "http_throughput", "description": "HTTP request throughput"},
                {"name": "json_build_parse", "description": "JSON construction and parsing"},
                {"name": "proc_spawn_wait", "description": "process spawn and wait"},
                {"name": "stream_reading", "description": "stream reading throughput"},
                {"name": "task_group_execution", "description": "task-group execution"},
                {"name": "compiler_parse_lower_build", "description": "compiler parse, lower, and build time"},
                {"name": "native_binary_size", "description": "native binary size"},
            ],
        },
        "sources": {
            "exitCriteria": "release/exit_criteria_state.json",
            "plan": "PLAN.md",
            "perfArtifact": "artifacts/bench_core_rust_vs_fzy.json"
        }
    });
    let path = PathBuf::from("artifacts/stability_dashboard.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&dashboard)?)
        .with_context(|| format!("failed writing {}", path.display()))?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "stability-dashboard".to_string()),
            ("artifact", path.display().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "status": "ok",
            "mode": "stability-dashboard",
            "artifact": path.display().to_string(),
            "dashboard": dashboard,
        })
        .to_string()),
    }
}

pub(super) fn chrono_like_now_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct DoctorCheck {
    pub(super) name: String,
    pub(super) status: String,
    pub(super) detail: String,
    pub(super) fix: String,
}

pub(super) fn doctor_project_command(path: &Path, strict: bool, format: Format) -> Result<String> {
    let project_root = if path.is_file() {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        path.to_path_buf()
    };
    if !project_root.is_dir() {
        bail!(
            "doctor project requires a project directory (or file within a project): {}",
            path.display()
        );
    }
    let manifest_path = project_root.join("fozzy.toml");
    let mut checks = Vec::<DoctorCheck>::new();
    let mut errors = 0usize;
    let mut warnings = 0usize;

    let manifest_text = match std::fs::read_to_string(&manifest_path) {
        Ok(text) => {
            checks.push(DoctorCheck {
                name: "manifest".to_string(),
                status: "ok".to_string(),
                detail: format!("loaded {}", manifest_path.display()),
                fix: "n/a".to_string(),
            });
            text
        }
        Err(_) => {
            checks.push(DoctorCheck {
                name: "manifest".to_string(),
                status: "error".to_string(),
                detail: format!("missing {}", manifest_path.display()),
                fix: "add fozzy.toml or run `fz init [path]`".to_string(),
            });
            errors += 1;
            String::new()
        }
    };

    let manifest = if manifest_text.is_empty() {
        None
    } else {
        if !manifest::looks_like_compiler_manifest(&manifest_text) {
            checks.push(DoctorCheck {
                name: "manifest-validate".to_string(),
                status: "error".to_string(),
                detail: format!("{} is not a compiler manifest", manifest_path.display()),
                fix: "point doctor at a Fozzy project root or add a valid [package] manifest"
                    .to_string(),
            });
            errors += 1;
            None
        } else {
            match manifest::load(&manifest_text)
                .map_err(anyhow::Error::from)
                .and_then(|loaded| loaded.validate().map(|_| loaded).map_err(|e| anyhow!(e)))
            {
                Ok(parsed) => Some(parsed),
                Err(err) => {
                    checks.push(DoctorCheck {
                        name: "manifest-validate".to_string(),
                        status: "error".to_string(),
                        detail: err.to_string(),
                        fix: "fix fozzy.toml to satisfy manifest schema".to_string(),
                    });
                    errors += 1;
                    None
                }
            }
        }
    };

    if manifest.is_some() {
        let lock_status = match refresh_lockfile(&project_root) {
            Ok(lock_hash) => DoctorCheck {
                name: "lockfile".to_string(),
                status: "ok".to_string(),
                detail: format!("fozzy.lock validated (hash={lock_hash})"),
                fix: "n/a".to_string(),
            },
            Err(err) => {
                errors += 1;
                DoctorCheck {
                    name: "lockfile".to_string(),
                    status: "error".to_string(),
                    detail: err.to_string(),
                    fix: "run `fz vendor <project-root>` after fixing dependency graph issues"
                        .to_string(),
                }
            }
        };
        checks.push(lock_status);
        let vendor_manifest = project_root.join("vendor/fozzy-vendor.json");
        if vendor_manifest.exists() {
            checks.push(DoctorCheck {
                name: "vendor".to_string(),
                status: "ok".to_string(),
                detail: format!("found {}", vendor_manifest.display()),
                fix: "n/a".to_string(),
            });
        } else {
            warnings += 1;
            checks.push(DoctorCheck {
                name: "vendor".to_string(),
                status: "warn".to_string(),
                detail: "vendor manifest missing".to_string(),
                fix: "run `fz vendor <project-root>` for fully reproducible dependency snapshots"
                    .to_string(),
            });
        }
    }

    if let Ok(resolved) = resolve_source(&project_root) {
        if let Ok(parsed) = parse_program(&resolved.source_path) {
            let mut deprecated_unsafe_meta = 0usize;
            let mut async_unsafe_overlap = 0usize;
            let mut backend_risk_ops = 0usize;
            for module_path in &parsed.module_paths {
                if let Ok(text) = std::fs::read_to_string(module_path) {
                    deprecated_unsafe_meta += text.matches("unsafe_reason(").count();
                    deprecated_unsafe_meta += text.matches("unsafe(").count();
                    if text.contains("async fn") && text.contains("unsafe") {
                        async_unsafe_overlap += 1;
                    }
                    if text.contains("proc.run(") || text.contains("http.poll_next") {
                        backend_risk_ops += 1;
                    }
                }
            }
            if deprecated_unsafe_meta > 0 {
                errors += 1;
                checks.push(DoctorCheck {
                    name: "unsupported-syntax".to_string(),
                    status: "error".to_string(),
                    detail: format!("detected {deprecated_unsafe_meta} removed unsafe metadata syntax use(s)"),
                    fix: "remove inline unsafe metadata and rely on compiler-generated contracts/docs".to_string(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "unsupported-syntax".to_string(),
                    status: "ok".to_string(),
                    detail: "no removed unsafe metadata syntax detected".to_string(),
                    fix: "n/a".to_string(),
                });
            }
            if async_unsafe_overlap > 0 {
                warnings += 1;
                checks.push(DoctorCheck {
                    name: "async-unsafe".to_string(),
                    status: "warn".to_string(),
                    detail: format!(
                        "{async_unsafe_overlap} module(s) combine async and unsafe constructs"
                    ),
                    fix: "audit unsafe invariants in async contexts and keep strict verify enabled"
                        .to_string(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "async-unsafe".to_string(),
                    status: "ok".to_string(),
                    detail: "no async+unsafe overlap detected".to_string(),
                    fix: "n/a".to_string(),
                });
            }
            if backend_risk_ops > 0 {
                warnings += 1;
                checks.push(DoctorCheck {
                    name: "backend-risk".to_string(),
                    status: "warn".to_string(),
                    detail: format!("{backend_risk_ops} backend-risk operation pattern(s) detected"),
                    fix: "prefer host-backed `fozzy run` plus explicit backend in CI for these modules".to_string(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "backend-risk".to_string(),
                    status: "ok".to_string(),
                    detail: "no obvious backend-risk operations detected".to_string(),
                    fix: "n/a".to_string(),
                });
            }
            if let Some(manifest) = manifest.as_ref() {
                let strict_release = manifest.unsafe_policy.enforce_release.unwrap_or(true);
                let strict_verify = manifest.unsafe_policy.enforce_verify.unwrap_or(true);
                if strict_release && strict_verify {
                    checks.push(DoctorCheck {
                        name: "unsafe-posture".to_string(),
                        status: "ok".to_string(),
                        detail: "verify/release unsafe enforcement enabled".to_string(),
                        fix: "n/a".to_string(),
                    });
                } else {
                    warnings += 1;
                    checks.push(DoctorCheck {
                        name: "unsafe-posture".to_string(),
                        status: "warn".to_string(),
                        detail: "unsafe enforcement is relaxed for verify/release".to_string(),
                        fix: "set [unsafe].enforce_verify=true and enforce_release=true"
                            .to_string(),
                    });
                }
            }
        }
    }

    if strict && warnings > 0 {
        errors += warnings;
    }
    let status = if errors > 0 { "error" } else { "ok" };
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", status.to_string()),
            ("mode", "doctor-project".to_string()),
            ("project", project_root.display().to_string()),
            ("errors", errors.to_string()),
            ("warnings", warnings.to_string()),
            (
                "policy",
                policy_summary_text("verify", Some("profile-driven"), Some("compiler"), true),
            ),
            ("checks", doctor_checks_summary_text(&checks)),
        ])),
        Format::Json => Ok(serde_json::json!({
            "status": status,
            "mode": "doctor-project",
            "project": project_root.display().to_string(),
            "strict": strict,
            "errors": errors,
            "warnings": warnings,
            "policy": {
                "profile": "verify",
                "unsafeEnforcement": "profile-driven",
                "memorySafetyMode": "production",
                "backend": "compiler",
                "lockfileState": "present-or-created",
            },
            "checks": checks,
        })
        .to_string()),
    }
}

pub(super) fn devloop_command(
    path: &Path,
    backend: Option<&str>,
    format: Format,
) -> Result<String> {
    let verify = verify_file_with_root_guidance(path)?;
    let compile = compile_file_with_backend_with_root_guidance(path, BuildProfile::Dev, backend)?;
    let plan = run_non_scenario_test_plan_with_root_guidance(
        path,
        NonScenarioPlanRequest {
            deterministic: true,
            strict_verify: true,
            safe_profile: false,
            scheduler: Some("fifo".to_string()),
            seed: Some(1),
            record: None,
            rich_artifacts: false,
            filter: None,
        },
    )?;
    let unsafe_docs = maybe_generate_unsafe_docs(path).map(|value| value.display().to_string());
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", compile.status.to_string()),
            ("mode", "devloop".to_string()),
            ("module", compile.module),
            ("verify_diagnostics", verify.diagnostics.to_string()),
            ("compile_diagnostics", compile.diagnostics.to_string()),
            ("scheduler", plan.scheduler),
            ("executed_tasks", plan.executed_tasks.to_string()),
            ("backend", backend.unwrap_or("cranelift").to_string()),
            (
                "policy",
                policy_summary_text("dev", Some("strict-verify"), backend, true),
            ),
            (
                "unsafe_docs",
                unsafe_docs.unwrap_or_else(|| "<none>".to_string()),
            ),
        ])),
        Format::Json => Ok(serde_json::json!({
            "status": compile.status,
            "mode": "devloop",
            "module": compile.module,
            "verifyDiagnostics": verify.diagnostics,
            "compileDiagnostics": compile.diagnostics,
            "scheduler": plan.scheduler,
            "executedTasks": plan.executed_tasks,
            "backend": backend.unwrap_or("cranelift"),
            "policy": {
                "profile": "dev",
                "unsafeEnforcement": "strict-verify",
                "memorySafetyMode": "production",
                "backend": backend.unwrap_or("cranelift"),
                "lockfileState": "present-or-created",
            },
            "unsafeDocs": unsafe_docs,
        })
        .to_string()),
    }
}

pub(super) fn spec_doc_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("FZ_SPEC_PATH") {
        if !explicit.trim().is_empty() {
            return PathBuf::from(explicit);
        }
    }
    PathBuf::from("docs/language-reference-v0.md")
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct DxIssue {
    level: &'static str,
    file: String,
    message: String,
}

pub(super) fn dx_check_command(path: &Path, strict: bool, format: Format) -> Result<String> {
    if !path.is_dir() {
        bail!("dx-check requires a project directory: {}", path.display());
    }
    let resolved = resolve_source(path)?;
    let main_path = path.join("src/main.fzy");
    ensure_exists(&main_path)?;
    let main_source = std::fs::read_to_string(&main_path)
        .with_context(|| format!("failed reading {}", main_path.display()))?;
    let main_name = main_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("main");
    let main_ast = parser::parse(&main_source, main_name).map_err(|diagnostics| {
        anyhow!(
            "failed parsing {}: {} diagnostics",
            main_path.display(),
            diagnostics.len()
        )
    })?;
    let mut issues = Vec::<DxIssue>::new();
    let required = vec!["api", "model", "services", "runtime", "cli", "tests"];
    for module in &required {
        if !main_ast.modules.iter().any(|decl| decl == module) {
            issues.push(DxIssue {
                level: "error",
                file: main_path.display().to_string(),
                message: format!("missing `mod {module};` declaration in main.fzy"),
            });
        }
    }
    let observed = main_ast
        .modules
        .iter()
        .filter_map(|decl| {
            let root = decl.split("::").next()?.to_string();
            if required.iter().any(|expected| expected == &root) {
                Some(root)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if observed != required {
        issues.push(DxIssue {
            level: "error",
            file: main_path.display().to_string(),
            message: format!(
                "module declaration order must be `mod api; mod model; mod services; mod runtime; mod cli; mod tests;` (observed: {})",
                observed.join(", ")
            ),
        });
    }
    if main_source
        .lines()
        .any(|line| line.trim_start().starts_with("test \""))
    {
        issues.push(DxIssue {
            level: "error",
            file: main_path.display().to_string(),
            message: "test declarations are forbidden in main.fzy; move tests under src/tests/*"
                .to_string(),
        });
    }
    let main_is_last = matches!(
        main_ast.items.last(),
        Some(ast::Item::Function(function)) if function.name == "main"
    );
    if !main_is_last {
        issues.push(DxIssue {
            level: "error",
            file: main_path.display().to_string(),
            message: "fn main must be the last top-level item in main.fzy".to_string(),
        });
    }
    let required_mod_files = vec![
        path.join("src/api/mod.fzy"),
        path.join("src/model/mod.fzy"),
        path.join("src/services/mod.fzy"),
        path.join("src/runtime/mod.fzy"),
        path.join("src/cli/mod.fzy"),
        path.join("src/tests/mod.fzy"),
    ];
    for mod_file in required_mod_files {
        if !mod_file.exists() {
            issues.push(DxIssue {
                level: "error",
                file: mod_file.display().to_string(),
                message: "missing module entry file (mod.fzy)".to_string(),
            });
        }
    }
    let pre_orchestration_errors = issues.iter().filter(|issue| issue.level == "error").count();
    if pre_orchestration_errors == 0 {
        let combined = parsed_module_source(&resolved.project_root, &resolved.source_path)?;
        for module in ["api", "model", "services", "runtime", "cli"] {
            let needle = format!("{module}.");
            if !combined.contains(&needle) {
                issues.push(DxIssue {
                    level: "warning",
                    file: main_path.display().to_string(),
                    message: format!(
                        "module `{module}` appears declared but not orchestrated from main flow"
                    ),
                });
            }
        }
    }
    if strict && issues.iter().any(|issue| issue.level == "warning") {
        for issue in &mut issues {
            if issue.level == "warning" {
                issue.level = "error";
            }
        }
    }
    let error_count = issues.iter().filter(|issue| issue.level == "error").count();
    if error_count > 0 {
        bail!(
            "dx-check failed for {}: {} issue(s): {}",
            path.display(),
            issues.len(),
            issues
                .iter()
                .map(|issue| format!("[{}] {}", issue.level, issue.message))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "dx-check".to_string()),
            ("project", path.display().to_string()),
            ("strict", strict.to_string()),
            ("issues", issues.len().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "project": path.display().to_string(),
            "strict": strict,
            "issues": issues,
        })
        .to_string()),
    }
}

pub(super) fn parsed_module_source(project_root: &Path, source_path: &Path) -> Result<String> {
    let parsed = parse_program(source_path)?;
    let mut combined = String::new();
    for path in parsed.module_paths {
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("failed reading module source: {}", path.display()))?;
        combined.push_str("// ");
        combined.push_str(
            path.strip_prefix(project_root)
                .unwrap_or(&path)
                .display()
                .to_string()
                .as_str(),
        );
        combined.push('\n');
        combined.push_str(&source);
        combined.push('\n');
    }
    Ok(combined)
}
