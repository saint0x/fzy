fn render(format: Format, message: &str) -> String {
    cli_output::format_message(format, message)
}

fn render_text_fields(fields: &[(&str, String)]) -> String {
    cli_output::format_fields(fields)
}

fn render_json(value: serde_json::Value) -> String {
    cli_output::format_json_value(&value)
}

fn policy_summary_text(
    profile: &str,
    unsafe_enforcement: Option<&str>,
    backend: Option<&str>,
    lockfile_present: bool,
) -> String {
    format!(
        "profile={profile}; unsafe={}; memory=production; backend={}; lockfile={}",
        unsafe_enforcement.unwrap_or("profile-driven"),
        backend.unwrap_or("auto"),
        if lockfile_present { "present" } else { "n/a" }
    )
}

fn doctor_checks_summary_text(checks: &[DoctorCheck]) -> String {
    checks
        .iter()
        .map(|check| format!("- {}:{}:{}", check.name, check.status, check.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

fn append_unsafe_docs_field(
    rendered: String,
    format: Format,
    unsafe_docs: Option<PathBuf>,
) -> String {
    match format {
        Format::Text => {
            if let Some(path) = unsafe_docs {
                format!("{rendered}\nunsafe_docs: {}", path.display())
            } else {
                rendered
            }
        }
        Format::Json => {
            let Ok(mut payload) = serde_json::from_str::<serde_json::Value>(&rendered) else {
                return rendered;
            };
            if let Some(path) = unsafe_docs {
                payload["unsafeDocs"] = serde_json::Value::String(path.display().to_string());
            }
            render_json(payload)
        }
    }
}

fn render_artifact(
    format: Format,
    artifact: BuildArtifact,
    threads: Option<u16>,
    runtime_config: Option<PathBuf>,
    interop: Option<&BuildInteropArtifacts>,
) -> String {
    match format {
        Format::Text => {
            let mut rendered = render_text_fields(&[
                ("status", artifact.status.to_string()),
                ("module", artifact.module.clone()),
                ("profile", format!("{:?}", artifact.profile)),
                ("diagnostics", artifact.diagnostics.to_string()),
                (
                    "output",
                    artifact
                        .output
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "threads",
                    threads
                        .map(|threads| threads.to_string())
                        .unwrap_or_else(|| "default".to_string()),
                ),
                (
                    "runtime_config",
                    runtime_config
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "dep_graph_hash",
                    artifact
                        .dependency_graph_hash
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "policy",
                    policy_summary_text(
                        artifact.profile.as_str(),
                        Some("compiler"),
                        None,
                        artifact.dependency_graph_hash.is_some(),
                    ),
                ),
            ]);
            if let Some(interop) = interop {
                rendered.push('\n');
                rendered.push_str(&render_text_fields(&[
                    (
                        "interop_static_lib",
                        interop
                            .library
                            .static_lib
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "<none>".to_string()),
                    ),
                    (
                        "interop_shared_lib",
                        interop
                            .library
                            .shared_lib
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "<none>".to_string()),
                    ),
                    ("interop_header", interop.headers.path.display().to_string()),
                    (
                        "interop_abi_manifest",
                        interop.headers.abi_manifest.display().to_string(),
                    ),
                    ("interop_exports", interop.headers.exports.to_string()),
                ]));
            }
            let details = render_diagnostics_text(&artifact.diagnostic_details);
            if !details.is_empty() {
                rendered.push('\n');
                rendered.push_str(&details);
            }
            rendered
        }
        Format::Json => {
            let mut payload = serde_json::json!({
                "module": artifact.module,
                "profile": format!("{:?}", artifact.profile),
                "status": artifact.status,
                "diagnostics": artifact.diagnostics,
                "items": artifact.diagnostic_details,
                "dependencyGraphHash": artifact.dependency_graph_hash,
                "policy": {
                    "profile": artifact.profile.as_str(),
                    "unsafeEnforcement": "profile-driven",
                    "memorySafetyMode": "production",
                    "backend": "compiler",
                    "lockfileState": if artifact.dependency_graph_hash.is_some() { "present" } else { "n/a" },
                },
                "threads": threads,
                "runtimeConfig": runtime_config.map(|path| path.display().to_string()),
                "output": artifact
                    .output
                    .as_ref()
                    .map(|path| path.display().to_string()),
            });
            if let Some(interop) = interop {
                payload["interop"] = serde_json::json!({
                    "buildMode": "lib",
                    "exports": interop.headers.exports,
                    "exportSymbols": interop.export_symbols,
                    "staticLib": interop
                        .library
                        .static_lib
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    "sharedLib": interop
                        .library
                        .shared_lib
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    "header": interop.headers.path.display().to_string(),
                    "abiManifest": interop.headers.abi_manifest.display().to_string(),
                    "artifactManifest": interop.artifact_manifest.display().to_string(),
                    "hostLifecycle": {
                        "init": "fz_host_init",
                        "shutdown": "fz_host_shutdown",
                        "cleanup": "fz_host_cleanup",
                        "lastErrorCode": "fz_host_last_error_code",
                        "lastErrorClass": "fz_host_last_error_class",
                        "lastErrorMessage": "fz_host_last_error_message",
                    },
                });
            }
            payload.to_string()
        }
    }
}

fn render_library_artifact(
    format: Format,
    artifact: LibraryArtifact,
    threads: Option<u16>,
    runtime_config: Option<PathBuf>,
    interop: Option<&BuildInteropArtifacts>,
) -> String {
    match format {
        Format::Text => {
            let mut fields = vec![
                ("status", artifact.status.to_string()),
                ("module", artifact.module.clone()),
                ("profile", format!("{:?}", artifact.profile)),
                ("diagnostics", artifact.diagnostics.to_string()),
                (
                    "static_lib",
                    artifact
                        .static_lib
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "shared_lib",
                    artifact
                        .shared_lib
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "threads",
                    threads
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "default".to_string()),
                ),
                (
                    "runtime_config",
                    runtime_config
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "dep_graph_hash",
                    artifact
                        .dependency_graph_hash
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "policy",
                    policy_summary_text(
                        artifact.profile.as_str(),
                        Some("compiler"),
                        None,
                        artifact.dependency_graph_hash.is_some(),
                    ),
                ),
            ];
            if let Some(interop) = interop {
                fields.push(("header", interop.headers.path.display().to_string()));
                fields.push((
                    "abi_manifest",
                    interop.headers.abi_manifest.display().to_string(),
                ));
                fields.push((
                    "artifact_manifest",
                    interop.artifact_manifest.display().to_string(),
                ));
                fields.push(("exports", interop.headers.exports.to_string()));
                if !interop.export_symbols.is_empty() {
                    fields.push(("export_symbols", interop.export_symbols.join(", ")));
                }
            }
            let mut rendered = render_text_fields(&fields);
            let details = render_diagnostics_text(&artifact.diagnostic_details);
            if !details.is_empty() {
                rendered.push('\n');
                rendered.push_str(&details);
            }
            rendered
        }
        Format::Json => serde_json::json!({
            "module": artifact.module,
            "profile": format!("{:?}", artifact.profile),
            "status": artifact.status,
            "diagnostics": artifact.diagnostics,
            "items": artifact.diagnostic_details,
            "dependencyGraphHash": artifact.dependency_graph_hash,
            "policy": {
                "profile": artifact.profile.as_str(),
                "unsafeEnforcement": "profile-driven",
                "memorySafetyMode": "production",
                "backend": "compiler",
                "lockfileState": if artifact.dependency_graph_hash.is_some() { "present" } else { "n/a" },
            },
            "threads": threads,
            "runtimeConfig": runtime_config.map(|path| path.display().to_string()),
            "buildMode": "lib",
            "staticLib": artifact
                .static_lib
                .as_ref()
                .map(|path| path.display().to_string()),
            "sharedLib": artifact
                .shared_lib
                .as_ref()
                .map(|path| path.display().to_string()),
            "header": interop.map(|value| value.headers.path.display().to_string()),
            "abiManifest": interop.map(|value| value.headers.abi_manifest.display().to_string()),
            "artifactManifest": interop.map(|value| value.artifact_manifest.display().to_string()),
            "exports": interop.map(|value| value.headers.exports),
            "exportSymbols": interop.map(|value| value.export_symbols.clone()).unwrap_or_default(),
        })
        .to_string(),
    }
}

fn render_output(format: Format, output: Output) -> String {
    let errors = output
        .diagnostic_details
        .iter()
        .filter(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error))
        .count();
    let warnings = output
        .diagnostic_details
        .iter()
        .filter(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Warning))
        .count();
    let unsafe_enforcement = match output.validation_tier {
        crate::pipeline::ValidationTier::Check => "structural",
        crate::pipeline::ValidationTier::Verify => "strict",
    };
    match format {
        Format::Text => {
            let mut rendered = render_text_fields(&[
                ("module", output.module.clone()),
                ("nodes", output.nodes.to_string()),
                ("diagnostics", output.diagnostics.to_string()),
                ("errors", errors.to_string()),
                ("warnings", warnings.to_string()),
                (
                    "policy",
                    policy_summary_text(
                        output.validation_tier.as_str(),
                        Some(unsafe_enforcement),
                        None,
                        true,
                    ),
                ),
                ("parse_ms", output.telemetry.parse_ms.to_string()),
                ("lower_ms", output.telemetry.lower_ms.to_string()),
                ("verify_ms", output.telemetry.verify_ms.to_string()),
                ("backend_ms", output.telemetry.backend_ms.to_string()),
                ("contract_ms", output.telemetry.contract_ms.to_string()),
                ("total_ms", output.telemetry.total_ms.to_string()),
                (
                    "parse_cache_hit",
                    output.telemetry.parse_cache_hit.to_string(),
                ),
                (
                    "lower_cache_hit",
                    output.telemetry.lower_cache_hit.to_string(),
                ),
                ("input_bytes", output.telemetry.input_bytes.to_string()),
            ]);
            let details = render_diagnostics_text(&output.diagnostic_details);
            if !details.is_empty() {
                rendered.push('\n');
                rendered.push_str(&details);
            }
            if let Some(ir) = &output.backend_ir {
                rendered.push('\n');
                rendered.push_str(ir);
            }
            rendered
        }
        Format::Json => serde_json::json!({
            "schemaVersion": diagnostics::DIAGNOSTICS_SCHEMA_VERSION,
            "module": output.module,
            "nodes": output.nodes,
            "diagnostics": output.diagnostics,
            "errors": errors,
            "warnings": warnings,
            "policy": {
                "profile": output.validation_tier.as_str(),
                "unsafeEnforcement": unsafe_enforcement,
                "memorySafetyMode": "production",
                "backend": "compiler",
                "lockfileState": "present-or-created",
            },
            "telemetry": {
                "parseMs": output.telemetry.parse_ms,
                "lowerMs": output.telemetry.lower_ms,
                "verifyMs": output.telemetry.verify_ms,
                "backendMs": output.telemetry.backend_ms,
                "contractMs": output.telemetry.contract_ms,
                "totalMs": output.telemetry.total_ms,
                "parseCacheHit": output.telemetry.parse_cache_hit,
                "lowerCacheHit": output.telemetry.lower_cache_hit,
                "inputBytes": output.telemetry.input_bytes,
            },
            "items": output.diagnostic_details,
            "backendIr": output.backend_ir,
        })
        .to_string(),
    }
}

fn render_run_compile_abort(format: Format, artifact: &BuildArtifact) -> String {
    match format {
        Format::Text => {
            let mut rendered =
                String::from("run aborted before execution due to compile-time diagnostics\n");
            rendered.push_str(&render_artifact(
                Format::Text,
                artifact.clone(),
                None,
                None,
                None,
            ));
            rendered
        }
        Format::Json => serde_json::json!({
            "status": "error",
            "phase": "compile",
            "message": "run aborted before execution due to compile-time diagnostics",
            "module": artifact.module,
            "profile": format!("{:?}", artifact.profile),
            "diagnostics": artifact.diagnostics,
            "items": artifact.diagnostic_details,
            "output": artifact.output.as_ref().map(|path| path.display().to_string()),
            "dependencyGraphHash": artifact.dependency_graph_hash,
        })
        .to_string(),
    }
}

fn render_diagnostics_text(items: &[diagnostics::Diagnostic]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let mut source_cache: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut out = String::new();
    for (index, diagnostic) in items.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let severity = match diagnostic.severity {
            diagnostics::Severity::Error => "error",
            diagnostics::Severity::Warning => "warning",
            diagnostics::Severity::Note => "note",
        };
        if let Some(code) = &diagnostic.code {
            out.push_str(&format!("{severity}[{code}]: {}\n", diagnostic.message));
        } else {
            out.push_str(&format!("{severity}: {}\n", diagnostic.message));
        }
        if let (Some(path), Some(span)) = (&diagnostic.path, &diagnostic.span) {
            out.push_str(&format!(
                " --> {path}:{}:{}\n",
                span.start_line, span.start_col
            ));
            if let Some(frame) = render_code_frame(path, span, &mut source_cache) {
                out.push_str(&frame);
            }
        } else if let Some(path) = &diagnostic.path {
            out.push_str(&format!(" --> {path}\n"));
            if let Some(snippet) = &diagnostic.snippet {
                out.push_str(&format!(" snippet: {snippet}\n"));
            }
        }
        for label in &diagnostic.labels {
            let role = if label.primary { "primary" } else { "related" };
            if let Some(span) = &label.span {
                out.push_str(&format!(
                    " {role}: {} ({}:{}-{}:{})\n",
                    label.message, span.start_line, span.start_col, span.end_line, span.end_col
                ));
                if !label.primary {
                    let path = diagnostic.path.as_deref().unwrap_or("<unknown>");
                    out.push_str(&format!(
                        "  related --> {path}:{}:{}\n",
                        span.start_line, span.start_col
                    ));
                    if let Some(frame) = render_code_frame(path, span, &mut source_cache) {
                        out.push_str(&frame);
                    }
                }
            } else {
                out.push_str(&format!(" {role}: {}\n", label.message));
            }
        }
        if let Some(help) = &diagnostic.help {
            out.push_str(&format!(" help: {help}\n"));
        }
        if let Some(fix) = &diagnostic.fix {
            out.push_str(&format!(" fix: {fix}\n"));
        }
        out.push_str(&format!(" root_cause: {}\n", diagnostic.message));
        if let Some(catalog_key) = &diagnostic.catalog_key {
            out.push_str(&format!(" catalog_key: {catalog_key}\n"));
        }
        let verify_with = diagnostic
            .path
            .as_deref()
            .map(|path| format!("fz check {path}"))
            .unwrap_or_else(|| "fz check <path>".to_string());
        if let Some(catalog_key) = &diagnostic.catalog_key {
            out.push_str(&format!(" explain: fz explain {catalog_key}\n"));
        } else if let Some(code) = &diagnostic.code {
            out.push_str(&format!(" explain: fz explain {code}\n"));
        }
        out.push_str(&format!(" verify_with: {verify_with}\n"));
        out.push_str(&format!(
            " repro_token: {}\n",
            diagnostic_repro_token(diagnostic)
        ));
        out.push_str(&format!(
            " repro_with: {}\n",
            diagnostic_repro_command(diagnostic)
        ));
        for note in &diagnostic.notes {
            out.push_str(&format!(" note: {note}\n"));
        }
        for suggestion in &diagnostic.suggested_fixes {
            out.push_str(&format!(" suggestion: {suggestion}\n"));
        }
    }
    out.trim_end().to_string()
}

fn diagnostic_repro_token(diagnostic: &diagnostics::Diagnostic) -> String {
    let code = diagnostic.code.as_deref().unwrap_or("NO-CODE");
    let path = diagnostic.path.as_deref().unwrap_or("<path>");
    format!("schema=v1;code={code};profile=verify;backend=compiler;seed=1;path={path}")
}

fn diagnostic_repro_command(diagnostic: &diagnostics::Diagnostic) -> String {
    if let Some(path) = &diagnostic.path {
        format!(
            "fz check {} --json && fz verify {} --json",
            shell_escape(path),
            shell_escape(path)
        )
    } else {
        "fz check <path> --json && fz verify <path> --json".to_string()
    }
}

fn shell_escape(input: &str) -> String {
    if input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    {
        return input.to_string();
    }
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

fn render_code_frame(
    path: &str,
    span: &diagnostics::Span,
    cache: &mut BTreeMap<String, Vec<String>>,
) -> Option<String> {
    let lines = if let Some(lines) = cache.get(path) {
        lines
    } else {
        let source = std::fs::read_to_string(path).ok()?;
        let loaded = source.lines().map(ToString::to_string).collect::<Vec<_>>();
        cache.insert(path.to_string(), loaded);
        cache.get(path)?
    };
    if span.start_line == 0 || span.start_line > lines.len() {
        return None;
    }
    let start_line = span.start_line.max(1).min(lines.len());
    let end_line = span.end_line.max(start_line).min(lines.len());
    let first_context = start_line.saturating_sub(1).max(1);
    let last_context = (end_line + 1).min(lines.len());
    let gutter_width = last_context.to_string().len();
    let mut frame = String::new();
    for line_no in first_context..=last_context {
        let line = &lines[line_no - 1];
        frame.push_str(&format!(
            " {:>width$} | {line}\n",
            line_no,
            width = gutter_width
        ));
        if (start_line..=end_line).contains(&line_no) {
            let line_len = line.chars().count();
            let highlight_start = if line_no == start_line {
                span.start_col.max(1)
            } else {
                1
            };
            let highlight_end = if line_no == end_line {
                span.end_col.max(highlight_start)
            } else {
                line_len.max(highlight_start)
            };
            let mut marker = String::new();
            marker.push_str(&" ".repeat(highlight_start.saturating_sub(1)));
            marker.push_str(&"^".repeat(highlight_end.saturating_sub(highlight_start) + 1));
            frame.push_str(&format!(
                " {:>width$} | {marker}\n",
                "",
                width = gutter_width
            ));
        }
    }
    Some(frame)
}

