use super::*;

pub fn compile_file(path: &Path, profile: BuildProfile) -> Result<BuildArtifact> {
    compile_file_with_backend(path, profile, None)
}

pub fn compile_file_with_backend(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<BuildArtifact> {
    let resolved = resolve_source_path(path)?;
    let backend = resolve_native_backend(profile, backend_override)?;
    let pgo = configured_pgo();
    if (pgo.generate_dir.is_some() || pgo.use_profile.is_some()) && backend != "llvm" {
        bail!(
            "PGO is only supported with backend `llvm`; current backend is `{}`",
            backend
        );
    }
    if let Some(cached) = cached_compile_file_artifact(&resolved, profile, &backend, &pgo) {
        return Ok(cached);
    }
    let parsed = parse_program_shared(&resolved.source_path)?;
    let experimental_diagnostics =
        experimental_feature_diagnostics(&parsed.module, resolved.manifest.as_ref());
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
        let output = emit_native_artifact(
            &lowered.fir,
            &resolved.project_root,
            &resolved.artifact_stem,
            profile,
            resolved.manifest.as_ref(),
            Some(backend.as_str()),
        )?;
        write_successful_compile_file_cache(
            &resolved,
            &parsed,
            &lowered.fir.name,
            profile,
            &backend,
            &pgo,
            &output,
        )?;
        Some(output)
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
        incremental: None,
    })
}

pub fn compile_file_incremental_with_backend(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<BuildArtifact> {
    let resolved = resolve_source_path(path)?;
    let backend = resolve_native_backend(profile, backend_override)?;
    let build_project_root = find_project_root_for_source(&resolved.source_path)
        .unwrap_or_else(|| resolved.project_root.clone());
    let snapshot = prepare_build_snapshot(&build_project_root)?;
    let snapshot_input = if path.is_file() {
        map_path_into_snapshot(&snapshot, &resolved.source_path)?
    } else {
        snapshot.snapshot_project_root.clone()
    };
    let snapshot_resolved = resolve_source_path(&snapshot_input)?;
    let pgo = configured_pgo();
    if (pgo.generate_dir.is_some() || pgo.use_profile.is_some()) && backend != "llvm" {
        bail!(
            "PGO is only supported with backend `llvm`; current backend is `{}`",
            backend
        );
    }
    let parsed = parse_program_shared(&snapshot_resolved.source_path)?;
    let experimental_diagnostics =
        experimental_feature_diagnostics(&parsed.module, snapshot_resolved.manifest.as_ref());
    let native_lowerability_errors = native_lowerability_diagnostics(&parsed.module);
    let backend_risks = backend_capability_diagnostics(&parsed.module, &backend, false);
    let lowered = lower_fir_cached_shared(&parsed);
    let gpu_backend = resolve_gpu_backend(module_uses_gpu(&lowered.typed), None)?;
    policy_artifacts::write_safety_artifacts(
        &snapshot_resolved.project_root,
        &parsed,
        &lowered.typed,
        &lowered.fir,
        snapshot_resolved.manifest.as_ref(),
    )?;
    let strict_unsafe_contracts =
        unsafe_contracts_enforced(snapshot_resolved.manifest.as_ref(), profile);
    let (deny_unsafe_in, allow_unsafe_in) =
        unsafe_scope_policy(snapshot_resolved.manifest.as_ref());
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
    normalize_diagnostics_for_path(&snapshot_resolved.source_path, &mut diagnostic_details);
    remap_snapshot_diagnostic_paths(&snapshot, &mut diagnostic_details);
    let module_plans =
        build_incremental_module_plans(&parsed, &lowered.fir, &snapshot_resolved.project_root);
    let (output, incremental) = if status == "ok" {
        let (output, mut report) = emit_native_incremental_binary(
            &lowered.fir,
            &parsed,
            &snapshot_resolved.project_root,
            &snapshot.object_store_root,
            &snapshot_resolved.artifact_stem,
            profile,
            snapshot_resolved.manifest.as_ref(),
            Some(backend.as_str()),
            &module_plans,
        )?;
        remap_snapshot_incremental_report(&snapshot, &mut report);
        (Some(output), Some(report))
    } else {
        (None, None)
    };
    Ok(BuildArtifact {
        module: lowered.fir.name.clone(),
        profile,
        status,
        diagnostics: diagnostic_details.len(),
        diagnostic_details,
        output,
        dependency_graph_hash: resolved.dependency_graph_hash,
        incremental,
    })
}
