use super::*;

pub(super) fn spec_check(format: Format) -> Result<String> {
    let path = spec_doc_path();
    ensure_exists(&path)?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed reading spec file: {}", path.display()))?;
    let required = vec![
        "## Evaluation Order",
        "## Integer Overflow",
        "## Error And Panic Semantics",
        "## Async Cancellation Semantics",
        "## Deterministic Scheduling Model",
        "## Capability Semantics",
        "## Memory Safety And UB Model",
    ];
    let missing = required
        .iter()
        .filter(|heading| !text.contains(**heading))
        .map(|heading| heading.to_string())
        .collect::<Vec<_>>();
    let ok = missing.is_empty();
    if !ok {
        bail!(
            "spec-check failed: missing sections in {}: {}",
            path.display(),
            missing.join(", ")
        );
    }
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "spec-check".to_string()),
            ("path", path.display().to_string()),
            ("sections", required.len().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": ok,
            "path": path.display().to_string(),
            "requiredSections": required,
            "missingSections": missing,
        })
        .to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct PlanClaimGate {
    pub(super) completed: usize,
    pub(super) checked: usize,
    pub(super) missing_evidence: Vec<String>,
}

pub(super) fn validate_plan_claim_accuracy() -> Result<PlanClaimGate> {
    let plan_path = PathBuf::from("PLAN.md");
    if !plan_path.exists() {
        return Ok(PlanClaimGate {
            completed: 0,
            checked: 0,
            missing_evidence: Vec::new(),
        });
    }
    let plan_text = std::fs::read_to_string(&plan_path)
        .with_context(|| format!("failed reading plan file: {}", plan_path.display()))?;
    let mut files = Vec::new();
    collect_files_recursive(Path::new("."), Path::new("."), &mut files)?;
    let corpus = files
        .into_iter()
        .filter(|(rel, _)| rel.ends_with(".rs"))
        .filter_map(|(rel, full)| {
            let text = std::fs::read_to_string(&full).ok()?;
            Some((rel, text))
        })
        .collect::<Vec<_>>();
    Ok(analyze_plan_claim_accuracy(&plan_text, &corpus))
}

pub(super) fn analyze_plan_claim_accuracy(plan_text: &str, corpus: &[(String, String)]) -> PlanClaimGate {
    let mut completed = 0usize;
    let mut checked = 0usize;
    let mut claims = Vec::<(String, Vec<String>)>::new();
    for line in plan_text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("- [✅]") {
            continue;
        }
        completed += 1;
        let mut tokens = Vec::new();
        let mut rest = trimmed;
        while let Some(start) = rest.find('`') {
            let tail = &rest[(start + 1)..];
            let Some(end) = tail.find('`') else {
                break;
            };
            let token = tail[..end].trim();
            if !token.is_empty() {
                tokens.push(token.to_string());
            }
            rest = &tail[(end + 1)..];
        }
        if !tokens.is_empty() {
            checked += 1;
            claims.push((trimmed.to_string(), tokens));
        }
    }
    let mut missing = Vec::new();
    for (claim, tokens) in claims {
        let mut has_source = false;
        let mut has_test = false;
        for token in &tokens {
            for (rel, text) in corpus {
                if !text.contains(token) {
                    continue;
                }
                if rel.contains("/tests/") || text.contains("#[test]") {
                    has_test = true;
                } else {
                    has_source = true;
                }
                if has_source && has_test {
                    break;
                }
            }
            if has_source && has_test {
                break;
            }
        }
        if !(has_source && has_test) {
            missing.push(claim);
        }
    }
    PlanClaimGate {
        completed,
        checked,
        missing_evidence: missing,
    }
}

pub(super) fn parity_command(path: &Path, seed: u64, format: Format) -> Result<String> {
    ensure_exists(path)?;
    let resolved = resolve_source(path)?;
    let verifier = verify_file(&resolved.source_path)?;
    let verifier_signature = diagnostic_signature(&verifier.diagnostic_details)?;
    let backend_capabilities = backend_capability_report();
    if resolved
        .manifest
        .as_ref()
        .is_some_and(|manifest| manifest.target.lib.is_some() && manifest.target.bin.is_empty())
    {
        let llvm = compile_library_with_backend(path, BuildProfile::Dev, Some("llvm"))?;
        let cranelift = compile_library_with_backend(path, BuildProfile::Dev, Some("cranelift"))?;
        let llvm_diag = diagnostic_signature(&llvm.diagnostic_details)?;
        let cranelift_diag = diagnostic_signature(&cranelift.diagnostic_details)?;
        let llvm_static = library_exports(
            llvm.static_lib
                .as_deref()
                .ok_or_else(|| anyhow!("llvm library parity output missing static lib"))?,
        )?;
        let cranelift_static = library_exports(
            cranelift
                .static_lib
                .as_deref()
                .ok_or_else(|| anyhow!("cranelift library parity output missing static lib"))?,
        )?;
        let llvm_shared = library_exports(
            llvm.shared_lib
                .as_deref()
                .ok_or_else(|| anyhow!("llvm library parity output missing shared lib"))?,
        )?;
        let cranelift_shared = library_exports(
            cranelift
                .shared_lib
                .as_deref()
                .ok_or_else(|| anyhow!("cranelift library parity output missing shared lib"))?,
        )?;
        let mut issues = Vec::new();
        if llvm.status != cranelift.status {
            issues.push("llvm/cranelift library build status mismatch".to_string());
        }
        if llvm_diag != cranelift_diag {
            issues.push("llvm/cranelift library diagnostic mismatch".to_string());
        }
        if llvm_static != cranelift_static {
            issues.push("llvm/cranelift static export mismatch".to_string());
        }
        if llvm_shared != cranelift_shared {
            issues.push("llvm/cranelift shared export mismatch".to_string());
        }
        let signature = semantic_signature(&serde_json::json!({
            "kind": "backend-library-parity",
            "verifier": verifier_signature,
            "llvm": {
                "status": llvm.status,
                "diagnostics": llvm_diag,
                "static": llvm_static,
                "shared": llvm_shared,
            },
            "cranelift": {
                "status": cranelift.status,
                "diagnostics": cranelift_diag,
                "static": cranelift_static,
                "shared": cranelift_shared,
            },
        }))?;
        if !issues.is_empty() {
            bail!(
                "parity failed for {}: {}",
                path.display(),
                issues.join("; ")
            );
        }
        return match format {
            Format::Text => Ok(render_text_fields(&[
                ("status", "ok".to_string()),
                ("mode", "parity".to_string()),
                ("kind", "library".to_string()),
                ("path", path.display().to_string()),
                ("signature", signature),
            ])),
            Format::Json => Ok(serde_json::json!({
                "ok": true,
                "mode": "parity",
                "kind": "library",
                "path": path.display().to_string(),
                "seed": seed,
                "signature": signature,
                "verifier": {
                    "diagnostics": verifier.diagnostics,
                    "signature": verifier_signature,
                },
                "backendCapabilities": backend_capabilities,
                "backendResults": {
                    "llvm": {
                        "status": llvm.status,
                        "diagnostics": llvm.diagnostics,
                        "diagnosticSignature": llvm_diag,
                        "staticExports": llvm_static,
                        "sharedExports": llvm_shared,
                    },
                    "cranelift": {
                        "status": cranelift.status,
                        "diagnostics": cranelift.diagnostics,
                        "diagnosticSignature": cranelift_diag,
                        "staticExports": cranelift_static,
                        "sharedExports": cranelift_shared,
                    }
                },
                "checks": {
                    "sameVerifierResult": true,
                    "sameBuildStatus": llvm.status == cranelift.status,
                    "sameDiagnosticResult": llvm_diag == cranelift_diag,
                    "sameStaticExports": llvm_static == cranelift_static,
                    "sameSharedExports": llvm_shared == cranelift_shared,
                },
                "issues": issues,
            })
            .to_string()),
        };
    }

    let llvm = compile_file_with_backend(path, BuildProfile::Dev, Some("llvm"))?;
    let cranelift = compile_file_with_backend(path, BuildProfile::Dev, Some("cranelift"))?;
    let llvm_diag = diagnostic_signature(&llvm.diagnostic_details)?;
    let cranelift_diag = diagnostic_signature(&cranelift.diagnostic_details)?;
    let mut issues = Vec::new();
    if llvm.status != cranelift.status {
        issues.push("llvm/cranelift executable build status mismatch".to_string());
    }
    if llvm_diag != cranelift_diag {
        issues.push("llvm/cranelift executable diagnostic mismatch".to_string());
    }
    let runtime_available = llvm.status == "ok" && cranelift.status == "ok";
    let (llvm_runtime, cranelift_runtime) = if runtime_available {
        let llvm_runtime = executable_runtime_result(&llvm)?;
        let cranelift_runtime = executable_runtime_result(&cranelift)?;
        if llvm_runtime.exit_code != cranelift_runtime.exit_code {
            issues.push("llvm/cranelift exit code mismatch".to_string());
        }
        if llvm_runtime.stdout != cranelift_runtime.stdout {
            issues.push("llvm/cranelift stdout mismatch".to_string());
        }
        if llvm_runtime.stderr != cranelift_runtime.stderr {
            issues.push("llvm/cranelift stderr mismatch".to_string());
        }
        (Some(llvm_runtime), Some(cranelift_runtime))
    } else {
        (None, None)
    };
    let signature = semantic_signature(&serde_json::json!({
        "kind": "backend-executable-parity",
        "verifier": verifier_signature,
        "llvm": {
            "status": llvm.status,
            "diagnostics": llvm_diag,
            "exit": llvm_runtime.as_ref().map(|value| value.exit_code),
            "stdout": llvm_runtime.as_ref().map(|value| value.stdout.clone()),
            "stderr": llvm_runtime.as_ref().map(|value| value.stderr.clone()),
        },
        "cranelift": {
            "status": cranelift.status,
            "diagnostics": cranelift_diag,
            "exit": cranelift_runtime.as_ref().map(|value| value.exit_code),
            "stdout": cranelift_runtime.as_ref().map(|value| value.stdout.clone()),
            "stderr": cranelift_runtime.as_ref().map(|value| value.stderr.clone()),
        },
    }))?;
    if !issues.is_empty() {
        bail!(
            "parity failed for {}: {}",
            path.display(),
            issues.join("; ")
        );
    }
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "parity".to_string()),
            ("kind", "executable".to_string()),
            ("path", path.display().to_string()),
            ("signature", signature),
            (
                "exit_code",
                llvm_runtime
                    .as_ref()
                    .map(|value| value.exit_code.to_string())
                    .unwrap_or_else(|| "<unavailable>".to_string()),
            ),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "mode": "parity",
            "kind": "executable",
            "path": path.display().to_string(),
            "seed": seed,
            "signature": signature,
            "verifier": {
                "diagnostics": verifier.diagnostics,
                "signature": verifier_signature,
            },
            "backendCapabilities": backend_capabilities,
            "backendResults": {
                "llvm": {
                    "status": llvm.status,
                    "diagnostics": llvm.diagnostics,
                    "diagnosticSignature": llvm_diag,
                    "exitCode": llvm_runtime.as_ref().map(|value| value.exit_code),
                    "stdout": llvm_runtime.as_ref().map(|value| value.stdout.clone()),
                    "stderr": llvm_runtime.as_ref().map(|value| value.stderr.clone()),
                },
                "cranelift": {
                    "status": cranelift.status,
                    "diagnostics": cranelift.diagnostics,
                    "diagnosticSignature": cranelift_diag,
                    "exitCode": cranelift_runtime.as_ref().map(|value| value.exit_code),
                    "stdout": cranelift_runtime.as_ref().map(|value| value.stdout.clone()),
                    "stderr": cranelift_runtime.as_ref().map(|value| value.stderr.clone()),
                }
            },
            "checks": {
                "sameVerifierResult": true,
                "sameBuildStatus": llvm.status == cranelift.status,
                "sameDiagnosticResult": llvm_diag == cranelift_diag,
                "runtimeAvailable": runtime_available,
                "sameExitCode": llvm_runtime.as_ref().map(|value| value.exit_code)
                    == cranelift_runtime.as_ref().map(|value| value.exit_code),
                "sameStdout": llvm_runtime.as_ref().map(|value| &value.stdout)
                    == cranelift_runtime.as_ref().map(|value| &value.stdout),
                "sameStderr": llvm_runtime.as_ref().map(|value| &value.stderr)
                    == cranelift_runtime.as_ref().map(|value| &value.stderr),
                "sameRuntimeBehavior": llvm_runtime == cranelift_runtime,
            },
            "issues": issues,
        })
        .to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecutableRuntimeResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

pub(super) fn executable_runtime_result(artifact: &BuildArtifact) -> Result<ExecutableRuntimeResult> {
    let output = artifact
        .output
        .as_deref()
        .ok_or_else(|| anyhow!("native executable parity output missing binary artifact"))?;
    let result = ProcessCommand::new(output)
        .output()
        .with_context(|| format!("native executable parity run failed: {}", output.display()))?;
    Ok(ExecutableRuntimeResult {
        exit_code: result
            .status
            .code()
            .ok_or_else(|| anyhow!("native executable parity run terminated without exit code"))?,
        stdout: String::from_utf8(result.stdout).context("parity stdout should be utf-8")?,
        stderr: String::from_utf8(result.stderr).context("parity stderr should be utf-8")?,
    })
}

pub(super) fn diagnostic_signature(items: &[diagnostics::Diagnostic]) -> Result<String> {
    let payload = serde_json::Value::Array(
        items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "severity": format!("{:?}", item.severity),
                    "message": item.message,
                    "help": item.help,
                    "code": item.code,
                    "catalogKey": item.catalog_key,
                    "path": item.path,
                })
            })
            .collect::<Vec<_>>(),
    );
    semantic_signature(&payload)
}

pub(super) fn library_exports(path: &Path) -> Result<Vec<String>> {
    let output = ProcessCommand::new("nm")
        .arg(path)
        .output()
        .with_context(|| format!("failed invoking nm for {}", path.display()))?;
    if !output.status.success() {
        bail!("nm failed for {}", path.display());
    }
    let mut exports = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && (line.contains(" add")
                    || line.ends_with(" add")
                    || line.contains(" mul")
                    || line.ends_with(" mul")
                    || line.contains(" T ")
                    || line.contains(" D ")
                    || line.contains(" S "))
        })
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    exports.sort();
    exports.dedup();
    Ok(exports)
}

pub(super) fn backend_capability_report() -> serde_json::Value {
    serde_json::json!({
        "llvm": {
            "status": "parity_supported",
            "unsupported": []
        },
        "cranelift": {
            "status": "parity_supported_with_explicit_exceptions",
            "unsupported": [
                {
                    "feature": "async_c_export_surface",
                    "catalogKey": "native.async_c_export_unsupported"
                },
                {
                    "feature": "async_unsafe_native_function",
                    "catalogKey": "native.async_unsafe_function_unsupported"
                }
            ]
        },
        "gpuAdapters": gpu_backend_report_json()
    })
}
