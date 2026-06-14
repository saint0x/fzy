use super::*;

pub fn check_file(path: &Path) -> Result<Output> {
    validate_file_with_root_source(path, None, ValidationTier::Check)
}

pub fn verify_file(path: &Path) -> Result<Output> {
    validate_file_with_root_source(path, None, ValidationTier::Verify)
}

pub(crate) fn is_supported_source_file(path: &Path) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some("fzy")
}

pub fn verify_file_with_root_source(
    path: &Path,
    root_source_override: Option<&str>,
) -> Result<Output> {
    validate_file_with_root_source(path, root_source_override, ValidationTier::Verify)
}

pub(crate) fn validate_file_with_root_source(
    path: &Path,
    root_source_override: Option<&str>,
    tier: ValidationTier,
) -> Result<Output> {
    let started = Instant::now();
    let resolved = resolve_validation_source_path(path)?;
    let module_name = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;
    let parse_started = Instant::now();
    let (parsed, parse_cache_hit) = match parse_program_shared_with_root_source_telemetry(
        &resolved.source_path,
        root_source_override,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            let mut diagnostics = collect_parse_diagnostics_with_root_source(
                &resolved.source_path,
                root_source_override,
            )
            .unwrap_or_else(|_| {
                vec![diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    error.to_string(),
                    None,
                )]
            });
            for diagnostic in &mut diagnostics {
                if diagnostic.path.is_none() {
                    diagnostic.path = Some(resolved.source_path.display().to_string());
                }
            }
            enrich_diagnostics_context(&mut diagnostics);
            diagnostics::assign_stable_codes(
                &mut diagnostics,
                diagnostics::DiagnosticDomain::Driver,
            );
            return Ok(Output {
                module: module_name.to_string(),
                nodes: 0,
                diagnostics: diagnostics.len(),
                diagnostic_details: diagnostics,
                backend_ir: None,
                validation_tier: tier,
                telemetry: ValidationTelemetry {
                    total_ms: started.elapsed().as_millis() as u64,
                    parse_ms: parse_started.elapsed().as_millis() as u64,
                    input_bytes: root_source_override.map(str::len).unwrap_or_else(|| {
                        std::fs::metadata(&resolved.source_path)
                            .map(|m| m.len() as usize)
                            .unwrap_or(0)
                    }),
                    ..ValidationTelemetry::default()
                },
            });
        }
    };
    let parse_ms = parse_started.elapsed().as_millis() as u64;
    let mut diagnostics =
        experimental_feature_diagnostics(&parsed.module, resolved.manifest.as_ref());
    let lower_started = Instant::now();
    let (lowered, lower_cache_hit) = lower_fir_cached_shared_telemetry(&parsed);
    let lower_ms = lower_started.elapsed().as_millis() as u64;
    let verify_ms;
    let mut backend_ms = 0u64;
    let mut contract_ms = 0u64;
    match tier {
        ValidationTier::Check => {
            let verify_started = Instant::now();
            diagnostics.extend(verifier::verify(&lowered.fir).diagnostics);
            verify_ms = verify_started.elapsed().as_millis() as u64;
        }
        ValidationTier::Verify => {
            let backend_started = Instant::now();
            diagnostics.extend(native_lowerability_diagnostics(&parsed.module));
            let backend = resolve_native_backend(BuildProfile::Verify, None)?;
            diagnostics.extend(backend_capability_diagnostics(
                &parsed.module,
                &backend,
                false,
            ));
            let gpu_backend = resolve_gpu_backend(module_uses_gpu(&lowered.typed), None)?;
            diagnostics.extend(gpu_backend_execution_diagnostics(
                &lowered.typed,
                gpu_backend,
            ));
            backend_ms = backend_started.elapsed().as_millis() as u64;
            let verify_started = Instant::now();
            let (deny_unsafe_in, allow_unsafe_in) = unsafe_scope_policy(resolved.manifest.as_ref());
            let report = verifier::verify_with_policy(
                &lowered.fir,
                verifier::VerifyPolicy {
                    safe_profile: false,
                    production_memory_safety: true,
                    strict_unsafe_contracts: true,
                    deny_unsafe_in,
                    allow_unsafe_in,
                },
            );
            diagnostics.extend(report.diagnostics);
            verify_ms = verify_started.elapsed().as_millis() as u64;
            let contract_started = Instant::now();
            diagnostics.extend(compile_time_contract_diagnostics(
                &parsed.module,
                &lowered.fir,
                true,
                BuildProfile::Strict,
            ));
            diagnostics.extend(kernel_ir_diagnostics(&lowered.typed));
            contract_ms = contract_started.elapsed().as_millis() as u64;
        }
    }
    for diagnostic in &mut diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(resolved.source_path.display().to_string());
        }
    }
    suppress_transitive_unsafe_summary_for_architecture_root(
        &resolved.source_path,
        &parsed.module,
        &mut diagnostics,
    );
    enrich_diagnostics_context(&mut diagnostics);
    diagnostics::assign_stable_codes(&mut diagnostics, diagnostics::DiagnosticDomain::Driver);

    Ok(Output {
        module: lowered.fir.name.clone(),
        nodes: lowered.fir.nodes,
        diagnostics: diagnostics.len(),
        diagnostic_details: diagnostics,
        backend_ir: None,
        validation_tier: tier,
        telemetry: ValidationTelemetry {
            total_ms: started.elapsed().as_millis() as u64,
            parse_ms,
            lower_ms,
            verify_ms,
            backend_ms,
            contract_ms,
            parse_cache_hit,
            lower_cache_hit,
            input_bytes: parsed.input_bytes,
        },
    })
}

pub(crate) fn suppress_transitive_unsafe_summary_for_architecture_root(
    source_path: &Path,
    _module: &ast::Module,
    diagnostics: &mut Vec<diagnostics::Diagnostic>,
) {
    let is_architecture_root = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value == "lib.fzy")
        && !source_file_contains_unsafe_marker(source_path);
    if !is_architecture_root {
        return;
    }
    diagnostics.retain(|diagnostic| {
        !matches!(diagnostic.severity, diagnostics::Severity::Warning)
            || !diagnostic.message.contains(
                "compiler unsafe-policy checks passed, and structural unsafe contract metadata is present for all sites; independently reasoned evidence is still required",
            )
    });
}

pub(crate) fn source_file_contains_unsafe_marker(source_path: &Path) -> bool {
    std::fs::read_to_string(source_path)
        .map(|source| source.contains("unsafe"))
        .unwrap_or(true)
}

pub(crate) fn resolve_validation_source_path(input: &Path) -> Result<ResolvedSource> {
    match resolve_source_path(input) {
        Ok(resolved) => Ok(resolved),
        Err(err) if input.is_dir() => {
            let rendered = err.to_string();
            if rendered.contains("no [[target.bin]] entry in") {
                resolve_source_path_with_target(input, true)
            } else {
                Err(err)
            }
        }
        Err(err) => Err(err),
    }
}

pub(crate) fn normalize_diagnostics_for_path(path: &Path, diagnostics: &mut [diagnostics::Diagnostic]) {
    for diagnostic in diagnostics.iter_mut() {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(path.display().to_string());
        }
    }
    enrich_diagnostics_context(diagnostics);
    diagnostics::assign_stable_codes(diagnostics, diagnostics::DiagnosticDomain::Driver);
}

pub(crate) fn kernel_ir_diagnostics(typed: &hir::TypedModule) -> Vec<diagnostics::Diagnostic> {
    match kernel_ir::lower(typed) {
        Ok(_) => Vec::new(),
        Err(diagnostics) => diagnostics,
    }
}

pub fn emit_ir(path: &Path, backend: Option<&str>) -> Result<Output> {
    let resolved = resolve_source_path(path)?;
    let source_path = resolved.source_path;
    let module_name = source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;

    let parsed = match parse_program_shared(&source_path) {
        Ok(parsed) => parsed,
        Err(error) => {
            let mut diagnostics = vec![diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                error.to_string(),
                None,
            )];
            for diagnostic in &mut diagnostics {
                if diagnostic.path.is_none() {
                    diagnostic.path = Some(source_path.display().to_string());
                }
            }
            enrich_diagnostics_context(&mut diagnostics);
            diagnostics::assign_stable_codes(
                &mut diagnostics,
                diagnostics::DiagnosticDomain::Driver,
            );
            return Ok(Output {
                module: module_name.to_string(),
                nodes: 0,
                diagnostics: diagnostics.len(),
                diagnostic_details: diagnostics,
                backend_ir: None,
                validation_tier: ValidationTier::Verify,
                telemetry: ValidationTelemetry::default(),
            });
        }
    };
    let mut diagnostics = native_lowerability_diagnostics(&parsed.module);
    let lowered = lower_fir_cached_shared(&parsed);
    let report = verifier::verify(&lowered.fir);
    diagnostics.extend(report.diagnostics);
    let rendered_kernel_ir = match kernel_ir::lower(&lowered.typed) {
        Ok(module) if !module.functions.is_empty() => Some(kernel_ir::render(&module)),
        Ok(_) => None,
        Err(mut kernel_ir_errors) => {
            diagnostics.append(&mut kernel_ir_errors);
            None
        }
    };
    for diagnostic in &mut diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(source_path.display().to_string());
        }
    }
    enrich_diagnostics_context(&mut diagnostics);
    diagnostics::assign_stable_codes(&mut diagnostics, diagnostics::DiagnosticDomain::Driver);
    let mut backend_ir = String::new();
    for backend_kind in selected_emit_ir_backends(backend)? {
        let (label, ir) = match backend_kind {
            BackendKind::Llvm => ("llvm", lower_backend_ir(&lowered.fir, BackendKind::Llvm)?),
            BackendKind::Cranelift => (
                "cranelift",
                lower_backend_ir(&lowered.fir, BackendKind::Cranelift)?,
            ),
        };
        if !backend_ir.is_empty() {
            backend_ir.push('\n');
        }
        backend_ir.push_str(&format!("; backend={label}\n{ir}\n"));
    }

    Ok(Output {
        module: lowered.fir.name.clone(),
        nodes: lowered.fir.nodes,
        diagnostics: diagnostics.len(),
        diagnostic_details: diagnostics,
        validation_tier: ValidationTier::Verify,
        telemetry: ValidationTelemetry::default(),
        backend_ir: Some(match rendered_kernel_ir {
            Some(kernel_ir) if !kernel_ir.is_empty() => {
                format!("; backend=kernel_ir\n{kernel_ir}\n{backend_ir}")
            }
            _ => backend_ir,
        }),
    })
}

pub(crate) fn selected_emit_ir_backends(backend: Option<&str>) -> Result<Vec<BackendKind>> {
    match backend.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(vec![BackendKind::Llvm, BackendKind::Cranelift]),
        Some("llvm") => Ok(vec![BackendKind::Llvm]),
        Some("cranelift") => Ok(vec![BackendKind::Cranelift]),
        Some(other) => bail!("invalid emit-ir backend `{other}`; expected `llvm` or `cranelift`"),
    }
}

