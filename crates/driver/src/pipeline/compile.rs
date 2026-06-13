pub fn compile_file(path: &Path, profile: BuildProfile) -> Result<BuildArtifact> {
    compile_file_with_backend(path, profile, None)
}

pub fn compile_file_with_backend(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<BuildArtifact> {
    let resolved = resolve_source_path(path)?;
    let parsed = parse_program_shared(&resolved.source_path)?;
    let experimental_diagnostics =
        experimental_feature_diagnostics(&parsed.module, resolved.manifest.as_ref());
    let backend = resolve_native_backend(profile, backend_override)?;
    let pgo = configured_pgo();
    if (pgo.generate_dir.is_some() || pgo.use_profile.is_some()) && backend != "llvm" {
        bail!(
            "PGO is only supported with backend `llvm`; current backend is `{}`",
            backend
        );
    }
    let native_lowerability_errors = native_lowerability_diagnostics(&parsed.module);
    let backend_risks = backend_capability_diagnostics(&parsed.module, &backend, false);
    let lowered = lower_fir_cached_shared(&parsed);
    let gpu_backend = resolve_gpu_backend(module_uses_gpu(&lowered.typed), None)?;
    policy_artifacts::write_safety_artifacts(
        &resolved.project_root,
        &parsed,
        &lowered.typed,
        &lowered.fir,
        resolved.manifest.as_ref(),
    )?;
    let strict_unsafe_contracts = unsafe_contracts_enforced(resolved.manifest.as_ref(), profile);
    let (deny_unsafe_in, allow_unsafe_in) = unsafe_scope_policy(resolved.manifest.as_ref());
    let report = verifier::verify_with_policy(
        &lowered.fir,
        verifier::VerifyPolicy {
            safe_profile: matches!(profile, BuildProfile::Verify),
            production_memory_safety: true,
            strict_unsafe_contracts,
            deny_unsafe_in,
            allow_unsafe_in,
        },
    );

    let checks_enabled = resolved
        .manifest
        .as_ref()
        .and_then(|manifest| profile_config(manifest, profile).and_then(|config| config.checks))
        .unwrap_or(true);
    let contract_diagnostics =
        compile_time_contract_diagnostics(&parsed.module, &lowered.fir, checks_enabled, profile);
    let kernel_ir_diagnostics = kernel_ir_diagnostics(&lowered.typed);
    let gpu_backend_diagnostics = gpu_backend_execution_diagnostics(&lowered.typed, gpu_backend);
    let has_verifier_errors = report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_experimental_errors = experimental_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_native_lowerability_errors = !native_lowerability_errors.is_empty();
    let has_backend_risks = backend_risks
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_contract_errors = !contract_diagnostics.is_empty();
    let has_kernel_ir_errors = kernel_ir_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_gpu_backend_errors = gpu_backend_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let status = if has_experimental_errors
        || has_native_lowerability_errors
        || has_backend_risks
        || has_contract_errors
        || has_kernel_ir_errors
        || has_gpu_backend_errors
        || has_verifier_errors
    {
        "error"
    } else {
        "ok"
    };
    let mut diagnostic_details = experimental_diagnostics;
    diagnostic_details.extend(native_lowerability_errors);
    diagnostic_details.extend(backend_risks);
    diagnostic_details.extend(report.diagnostics);
    diagnostic_details.extend(contract_diagnostics);
    diagnostic_details.extend(kernel_ir_diagnostics);
    diagnostic_details.extend(gpu_backend_diagnostics);
    normalize_diagnostics_for_path(&resolved.source_path, &mut diagnostic_details);
    let output = if status == "ok" {
        Some(emit_native_artifact(
            &lowered.fir,
            &resolved.project_root,
            &resolved.artifact_stem,
            profile,
            resolved.manifest.as_ref(),
            Some(backend.as_str()),
        )?)
    } else {
        None
    };

    Ok(BuildArtifact {
        module: lowered.fir.name.clone(),
        profile,
        status,
        diagnostics: diagnostic_details.len(),
        diagnostic_details,
        output,
        dependency_graph_hash: resolved.dependency_graph_hash,
    })
}

pub fn compile_library_with_backend(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<LibraryArtifact> {
    let resolved = resolve_source_path_with_target(path, true)?;
    let parsed = parse_program_shared(&resolved.source_path)?;
    let experimental_diagnostics =
        experimental_feature_diagnostics(&parsed.module, resolved.manifest.as_ref());
    let backend = resolve_native_backend(profile, backend_override)?;
    let pgo = configured_pgo();
    if (pgo.generate_dir.is_some() || pgo.use_profile.is_some()) && backend != "llvm" {
        bail!(
            "PGO is only supported with backend `llvm`; current backend is `{}`",
            backend
        );
    }
    let native_lowerability_errors = native_lowerability_diagnostics(&parsed.module);
    let backend_risks = backend_capability_diagnostics(&parsed.module, &backend, true);
    let lowered = lower_fir_cached_shared(&parsed);
    let gpu_backend = resolve_gpu_backend(module_uses_gpu(&lowered.typed), None)?;
    policy_artifacts::write_safety_artifacts(
        &resolved.project_root,
        &parsed,
        &lowered.typed,
        &lowered.fir,
        resolved.manifest.as_ref(),
    )?;
    let strict_unsafe_contracts = unsafe_contracts_enforced(resolved.manifest.as_ref(), profile);
    let (deny_unsafe_in, allow_unsafe_in) = unsafe_scope_policy(resolved.manifest.as_ref());
    let report = verifier::verify_with_policy(
        &lowered.fir,
        verifier::VerifyPolicy {
            safe_profile: matches!(profile, BuildProfile::Verify),
            production_memory_safety: true,
            strict_unsafe_contracts,
            deny_unsafe_in,
            allow_unsafe_in,
        },
    );

    let checks_enabled = resolved
        .manifest
        .as_ref()
        .and_then(|manifest| profile_config(manifest, profile).and_then(|config| config.checks))
        .unwrap_or(true);
    let contract_diagnostics =
        compile_time_contract_diagnostics(&parsed.module, &lowered.fir, checks_enabled, profile);
    let kernel_ir_diagnostics = kernel_ir_diagnostics(&lowered.typed);
    let gpu_backend_diagnostics = gpu_backend_execution_diagnostics(&lowered.typed, gpu_backend);
    let has_verifier_errors = report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_experimental_errors = experimental_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_native_lowerability_errors = !native_lowerability_errors.is_empty();
    let has_backend_risks = backend_risks
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_contract_errors = !contract_diagnostics.is_empty();
    let has_kernel_ir_errors = kernel_ir_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_gpu_backend_errors = gpu_backend_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let status = if has_experimental_errors
        || has_native_lowerability_errors
        || has_backend_risks
        || has_contract_errors
        || has_kernel_ir_errors
        || has_gpu_backend_errors
        || has_verifier_errors
    {
        "error"
    } else {
        "ok"
    };
    let mut diagnostic_details = experimental_diagnostics;
    diagnostic_details.extend(native_lowerability_errors);
    diagnostic_details.extend(backend_risks);
    diagnostic_details.extend(report.diagnostics);
    diagnostic_details.extend(contract_diagnostics);
    diagnostic_details.extend(kernel_ir_diagnostics);
    diagnostic_details.extend(gpu_backend_diagnostics);
    normalize_diagnostics_for_path(&resolved.source_path, &mut diagnostic_details);
    let (static_lib, shared_lib) = if status == "ok" {
        emit_native_libraries(
            &lowered.fir,
            &resolved.project_root,
            &resolved.artifact_stem,
            profile,
            resolved.manifest.as_ref(),
            Some(backend.as_str()),
        )?
    } else {
        (None, None)
    };

    Ok(LibraryArtifact {
        module: lowered.fir.name.clone(),
        profile,
        status,
        diagnostics: diagnostic_details.len(),
        diagnostic_details,
        static_lib,
        shared_lib,
        dependency_graph_hash: resolved.dependency_graph_hash,
    })
}

pub fn check_file(path: &Path) -> Result<Output> {
    validate_file_with_root_source(path, None, ValidationTier::Check)
}

pub fn verify_file(path: &Path) -> Result<Output> {
    validate_file_with_root_source(path, None, ValidationTier::Verify)
}

fn is_supported_source_file(path: &Path) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some("fzy")
}

pub fn check_file_with_root_source(
    path: &Path,
    root_source_override: Option<&str>,
) -> Result<Output> {
    validate_file_with_root_source(path, root_source_override, ValidationTier::Check)
}

pub fn verify_file_with_root_source(
    path: &Path,
    root_source_override: Option<&str>,
) -> Result<Output> {
    validate_file_with_root_source(path, root_source_override, ValidationTier::Verify)
}

fn validate_file_with_root_source(
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

fn suppress_transitive_unsafe_summary_for_architecture_root(
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

fn source_file_contains_unsafe_marker(source_path: &Path) -> bool {
    std::fs::read_to_string(source_path)
        .map(|source| source.contains("unsafe"))
        .unwrap_or(true)
}

fn resolve_validation_source_path(input: &Path) -> Result<ResolvedSource> {
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

fn normalize_diagnostics_for_path(path: &Path, diagnostics: &mut [diagnostics::Diagnostic]) {
    for diagnostic in diagnostics.iter_mut() {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(path.display().to_string());
        }
    }
    enrich_diagnostics_context(diagnostics);
    diagnostics::assign_stable_codes(diagnostics, diagnostics::DiagnosticDomain::Driver);
}

fn kernel_ir_diagnostics(typed: &hir::TypedModule) -> Vec<diagnostics::Diagnostic> {
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

fn selected_emit_ir_backends(backend: Option<&str>) -> Result<Vec<BackendKind>> {
    match backend.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(vec![BackendKind::Llvm, BackendKind::Cranelift]),
        Some("llvm") => Ok(vec![BackendKind::Llvm]),
        Some("cranelift") => Ok(vec![BackendKind::Cranelift]),
        Some(other) => bail!("invalid emit-ir backend `{other}`; expected `llvm` or `cranelift`"),
    }
}

pub fn parse_program(source_path: &Path) -> Result<ParsedProgram> {
    Ok((*parse_program_shared_with_root_source(source_path, None)?).clone())
}

pub(crate) fn parse_program_with_metadata(source_path: &Path) -> Result<(ParsedProgram, bool)> {
    let (parsed, cache_hit) = parse_program_shared_with_root_source_telemetry(source_path, None)?;
    Ok(((*parsed).clone(), cache_hit))
}

pub fn parse_program_with_root_source(
    source_path: &Path,
    root_source_override: Option<&str>,
) -> Result<ParsedProgram> {
    Ok((*parse_program_shared_with_root_source(source_path, root_source_override)?).clone())
}

fn parse_program_shared(source_path: &Path) -> Result<Arc<ParsedProgram>> {
    parse_program_shared_with_root_source(source_path, None)
}

fn parse_program_shared_with_root_source(
    source_path: &Path,
    root_source_override: Option<&str>,
) -> Result<Arc<ParsedProgram>> {
    Ok(parse_program_shared_with_root_source_telemetry(source_path, root_source_override)?.0)
}

fn parse_program_shared_with_root_source_telemetry(
    source_path: &Path,
    root_source_override: Option<&str>,
) -> Result<(Arc<ParsedProgram>, bool)> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    let parse_context = parse_project_context_for_source(&canonical)?;
    if let Some(source_override) = root_source_override {
        return parse_program_uncached_with_root_source(
            &canonical,
            Some(source_override),
            parse_context.as_ref(),
        )
        .map(Arc::new)
        .map(|parsed| (parsed, false));
    }
    if let Some(cached) = cached_parsed_program(&canonical) {
        return Ok((cached, true));
    }
    let parsed = Arc::new(parse_program_uncached_with_root_source(
        &canonical,
        None,
        parse_context.as_ref(),
    )?);
    store_parsed_program_cache(&canonical, Arc::clone(&parsed));
    Ok((parsed, false))
}

pub fn lower_fir_cached(parsed: &ParsedProgram) -> (hir::TypedModule, fir::FirModule) {
    let lowered = lower_fir_cached_shared(parsed);
    ((*lowered.typed).clone(), (*lowered.fir).clone())
}

pub(crate) fn lower_fir_cached_with_metadata(
    parsed: &ParsedProgram,
) -> ((hir::TypedModule, fir::FirModule), bool) {
    let (lowered, cache_hit) = lower_fir_cached_shared_telemetry(parsed);
    (
        ((*lowered.typed).clone(), (*lowered.fir).clone()),
        cache_hit,
    )
}

fn lower_fir_cached_shared(parsed: &ParsedProgram) -> SharedLoweredProgram {
    lower_fir_cached_shared_telemetry(parsed).0
}

fn lower_fir_cached_shared_telemetry(parsed: &ParsedProgram) -> (SharedLoweredProgram, bool) {
    let module_hash = parsed.module_fingerprint.clone();
    let cache = LOWER_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(guard) = cache.read() {
        if let Some(cached) = guard.get(&module_hash) {
            return (
                SharedLoweredProgram {
                    typed: Arc::clone(&cached.typed),
                    fir: Arc::clone(&cached.fir),
                },
                true,
            );
        }
    }
    let typed = Arc::new(hir::lower(&parsed.module));
    let fir_module = Arc::new(fir::build_owned((*typed).clone()));
    if let Ok(mut guard) = cache.write() {
        guard.insert(
            module_hash,
            LowerCacheEntry {
                typed: Arc::clone(&typed),
                fir: Arc::clone(&fir_module),
            },
        );
    }
    (
        SharedLoweredProgram {
            typed,
            fir: fir_module,
        },
        false,
    )
}

// Safety policy and artifact emission helpers live in `pipeline/policy_artifacts.rs`
// to keep this driver file focused on orchestration, analysis, and lowering.

