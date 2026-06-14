use super::*;

#[derive(Debug, Clone)]
pub(super) struct IncrementalModuleObjectResult {
    pub(super) plan: IncrementalModuleUnitPlan,
    pub(super) object_path: Option<PathBuf>,
    pub(super) rebuilt: bool,
}

pub(crate) fn emit_native_incremental_binary(
    fir: &fir::FirModule,
    parsed: &ParsedProgram,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
    module_plans: &[IncrementalModuleUnitPlan],
) -> Result<(PathBuf, IncrementalBuildReport)> {
    let backend = resolve_native_backend(profile, backend_override)?;
    let build_dir = project_root.join(".fz").join("build").join("incremental");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;
    let shim_plan = build_native_runtime_shim_plan(fir)?;
    let lowered_fir = &shim_plan.lowered_fir;
    let string_literals = collect_native_string_literals_with_gpu(lowered_fir);
    let spawn_task_symbols = collect_spawn_task_symbols(lowered_fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &shim_plan.async_exports,
        &shim_plan.sync_exports,
    )?;
    let shim_obj_path = build_dir.join(format!("{artifact_stem}.incremental.runtime.o"));
    compile_runtime_shim_object(
        &runtime_shim_path,
        &shim_obj_path,
        profile,
        manifest,
        native_runtime_shim_uses_objc(lowered_fir),
    )?;
    let manifest_fingerprint = manifest
        .map(manifest_fingerprint_for_incremental)
        .transpose()?
        .unwrap_or_default();
    let global_interface_fingerprint = parsed.global_interface_fingerprint.clone();
    let module_results = module_plans
        .par_iter()
        .map(|plan| {
            emit_incremental_module_object(
                lowered_fir,
                &build_dir,
                profile,
                manifest,
                &backend,
                &global_interface_fingerprint,
                &manifest_fingerprint,
                plan,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let object_paths = module_results
        .iter()
        .filter_map(|result| result.object_path.as_ref())
        .collect::<Vec<_>>();
    let bin_path = build_dir.join(artifact_stem);
    link_incremental_binary(
        &bin_path,
        &object_paths,
        &shim_obj_path,
        lowered_fir,
        manifest,
    )?;
    let rebuilt_modules = module_results.iter().filter(|result| result.rebuilt).count();
    let module_details = module_results
        .into_iter()
        .map(|result| IncrementalModuleReport {
            path: result.plan.path.display().to_string(),
            namespace: result.plan.namespace,
            source_fingerprint: result.plan.source_fingerprint,
            rebuilt: result.rebuilt,
            object: result
                .object_path
                .as_ref()
                .map(|path| path.display().to_string()),
        })
        .collect::<Vec<_>>();
    let report = IncrementalBuildReport {
        enabled: true,
        module_count: module_details.len(),
        rebuilt_modules,
        reused_modules: module_details.len().saturating_sub(rebuilt_modules),
        global_interface_fingerprint,
        module_details,
    };
    Ok((bin_path, report))
}

pub(crate) fn emit_native_incremental_libraries(
    fir: &fir::FirModule,
    parsed: &ParsedProgram,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
    module_plans: &[IncrementalModuleUnitPlan],
) -> Result<((Option<PathBuf>, Option<PathBuf>), IncrementalBuildReport)> {
    let backend = resolve_native_backend(profile, backend_override)?;
    let build_dir = project_root.join(".fz").join("build").join("incremental");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;
    let shim_plan = build_native_runtime_shim_plan(fir)?;
    let lowered_fir = &shim_plan.lowered_fir;
    let string_literals = collect_native_string_literals_with_gpu(lowered_fir);
    let spawn_task_symbols = collect_spawn_task_symbols(lowered_fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &shim_plan.async_exports,
        &shim_plan.sync_exports,
    )?;
    let shim_obj_path = build_dir.join(format!("{artifact_stem}.incremental.runtime.o"));
    compile_runtime_shim_object(
        &runtime_shim_path,
        &shim_obj_path,
        profile,
        manifest,
        native_runtime_shim_uses_objc(lowered_fir),
    )?;
    let manifest_fingerprint = manifest
        .map(manifest_fingerprint_for_incremental)
        .transpose()?
        .unwrap_or_default();
    let global_interface_fingerprint = parsed.global_interface_fingerprint.clone();
    let module_results = module_plans
        .par_iter()
        .map(|plan| {
            emit_incremental_module_object(
                lowered_fir,
                &build_dir,
                profile,
                manifest,
                &backend,
                &global_interface_fingerprint,
                &manifest_fingerprint,
                plan,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let object_paths = module_results
        .iter()
        .filter_map(|result| result.object_path.as_ref())
        .collect::<Vec<_>>();
    let static_path = build_dir.join(format!("lib{artifact_stem}.a"));
    let shared_path = build_dir.join(format!(
        "lib{artifact_stem}.{}",
        super::link::shared_lib_extension()
    ));
    let mut archive_objects = object_paths.iter().map(|path| path.as_path()).collect::<Vec<_>>();
    archive_objects.push(shim_obj_path.as_path());
    super::link::create_static_archive(&static_path, &archive_objects)?;
    let mut shared_objects = object_paths.iter().map(|path| path.as_path()).collect::<Vec<_>>();
    shared_objects.push(shim_obj_path.as_path());
    let allow_undefined = !collect_extern_c_imports(lowered_fir).is_empty();
    super::link::link_shared_library(
        &shared_path,
        &shared_objects,
        lowered_fir,
        manifest,
        allow_undefined,
    )?;
    let rebuilt_modules = module_results.iter().filter(|result| result.rebuilt).count();
    let module_details = module_results
        .into_iter()
        .map(|result| IncrementalModuleReport {
            path: result.plan.path.display().to_string(),
            namespace: result.plan.namespace,
            source_fingerprint: result.plan.source_fingerprint,
            rebuilt: result.rebuilt,
            object: result
                .object_path
                .as_ref()
                .map(|path| path.display().to_string()),
        })
        .collect::<Vec<_>>();
    let report = IncrementalBuildReport {
        enabled: true,
        module_count: module_details.len(),
        rebuilt_modules,
        reused_modules: module_details.len().saturating_sub(rebuilt_modules),
        global_interface_fingerprint,
        module_details,
    };
    Ok(((Some(static_path), Some(shared_path)), report))
}

pub(super) fn emit_incremental_module_object(
    fir: &fir::FirModule,
    build_dir: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend: &str,
    global_interface_fingerprint: &str,
    manifest_fingerprint: &str,
    plan: &IncrementalModuleUnitPlan,
) -> Result<IncrementalModuleObjectResult> {
    if plan.local_functions.is_empty() && plan.local_mutable_globals.is_empty() {
        return Ok(IncrementalModuleObjectResult {
            plan: plan.clone(),
            object_path: None,
            rebuilt: false,
        });
    }
    let object_path = incremental_module_object_path(build_dir, backend, profile, plan);
    let cache_marker = native_artifact_cache_marker(
        build_dir,
        &incremental_module_object_stem(plan),
        "module",
        backend,
    );
    let cache_key = incremental_module_cache_key(
        backend,
        profile,
        global_interface_fingerprint,
        manifest_fingerprint,
        plan,
    );
    if native_artifact_cache_hit(&cache_marker, &cache_key, &[&object_path]) {
        return Ok(IncrementalModuleObjectResult {
            plan: plan.clone(),
            object_path: Some(object_path),
            rebuilt: false,
        });
    }
    match backend {
        "llvm" => super::ll::emit_incremental_module_object_llvm(
            fir,
            &object_path,
            profile,
            manifest,
            &plan.local_functions,
            &plan.local_mutable_globals,
        )?,
        "cranelift" => super::crane::emit_incremental_module_object_cranelift(
            fir,
            &object_path,
            profile,
            manifest,
            &plan.local_functions,
            &plan.local_mutable_globals,
        )?,
        other => bail!("unknown backend `{other}`"),
    }
    write_native_artifact_cache_key(&cache_marker, &cache_key)?;
    Ok(IncrementalModuleObjectResult {
        plan: plan.clone(),
        object_path: Some(object_path),
        rebuilt: true,
    })
}

pub(super) fn link_incremental_binary(
    output: &Path,
    objects: &[&PathBuf],
    shim_obj_path: &Path,
    fir: &fir::FirModule,
    manifest: Option<&manifest::Manifest>,
) -> Result<()> {
    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        for object in objects {
            cmd.arg(object);
        }
        cmd.arg(shim_obj_path).arg("-o").arg(output).arg("-lpthread");
        apply_target_link_flags(&mut cmd);
        apply_gpu_backend_link_args(&mut cmd, fir);
        apply_manifest_link_args(&mut cmd, manifest);
        apply_extra_linker_args(&mut cmd);
        apply_pgo_flags(&mut cmd)?;
        match cmd.output() {
            Ok(output_result) if output_result.status.success() => return Ok(()),
            Ok(output_result) => {
                last_error = Some(format!(
                    "{} failed linking incremental binary: {}",
                    tool,
                    String::from_utf8_lossy(&output_result.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    Err(anyhow!(
        "failed to link incremental binary {}: {}",
        output.display(),
        last_error.unwrap_or_else(|| "unknown linker error".to_string())
    ))
}

pub(super) fn incremental_module_object_path(
    build_dir: &Path,
    backend: &str,
    profile: BuildProfile,
    plan: &IncrementalModuleUnitPlan,
) -> PathBuf {
    build_dir.join(format!(
        "{}.{}.{}.o",
        incremental_module_object_stem(plan),
        backend,
        profile.as_str()
    ))
}

pub(super) fn incremental_module_object_stem(plan: &IncrementalModuleUnitPlan) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plan.path.to_string_lossy().as_bytes());
    let digest = hex_encode(hasher.finalize().as_slice());
    format!("module-{}", &digest[..16])
}

pub(super) fn incremental_module_cache_key(
    backend: &str,
    profile: BuildProfile,
    global_interface_fingerprint: &str,
    manifest_fingerprint: &str,
    plan: &IncrementalModuleUnitPlan,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(backend.as_bytes());
    hasher.update(profile.as_str().as_bytes());
    hasher.update(global_interface_fingerprint.as_bytes());
    hasher.update(manifest_fingerprint.as_bytes());
    hasher.update(plan.path.to_string_lossy().as_bytes());
    hasher.update(plan.namespace.as_bytes());
    hasher.update(plan.source_fingerprint.as_bytes());
    let mut local_functions = plan.local_functions.iter().collect::<Vec<_>>();
    local_functions.sort();
    for name in local_functions {
        hasher.update(name.as_bytes());
        hasher.update([0]);
    }
    let mut local_mutable_globals = plan.local_mutable_globals.iter().collect::<Vec<_>>();
    local_mutable_globals.sort();
    for name in local_mutable_globals {
        hasher.update(name.as_bytes());
        hasher.update([0xff]);
    }
    hex_encode(hasher.finalize().as_slice())
}

pub(super) fn manifest_fingerprint_for_incremental(
    manifest: &manifest::Manifest,
) -> Result<String> {
    let bytes = serde_json::to_vec(manifest)
        .map_err(|error| anyhow!("failed serializing manifest fingerprint: {error}"))?;
    Ok(hex_encode(Sha256::digest(&bytes).as_slice()))
}

pub(super) fn resolve_native_backend(
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<String> {
    if let Some(explicit) = backend_override {
        let normalized = explicit.trim().to_ascii_lowercase();
        return match normalized.as_str() {
            "llvm" | "cranelift" => Ok(normalized),
            other => Err(anyhow!(
                "unknown backend `{}`; expected `llvm` or `cranelift`",
                other
            )),
        };
    }
    if let Ok(explicit) = std::env::var("FZ_NATIVE_BACKEND") {
        let normalized = explicit.trim().to_ascii_lowercase();
        return match normalized.as_str() {
            "llvm" | "cranelift" => Ok(normalized),
            other => Err(anyhow!(
                "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
                other
            )),
        };
    }
    Ok(match profile {
        BuildProfile::Release => "llvm".to_string(),
        BuildProfile::Dev => "cranelift".to_string(),
        BuildProfile::Verify => "llvm".to_string(),
        BuildProfile::Strict => "llvm".to_string(),
    })
}
