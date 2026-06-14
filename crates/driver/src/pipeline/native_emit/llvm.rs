use super::*;
use super::super::llvm::{lower_llvm_ir, lower_llvm_ir_partitioned};

pub(super) fn emit_native_libraries_llvm(
    fir: &fir::FirModule,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let ll_path = build_dir.join(format!("{artifact_stem}.ll"));
    let obj_path = build_dir.join(format!("{artifact_stem}.ffi.o"));
    let shim_obj_path = build_dir.join(format!("{artifact_stem}.ffi.runtime.o"));
    let static_path = build_dir.join(format!("lib{artifact_stem}.a"));
    let shared_path =
        build_dir.join(format!("lib{artifact_stem}.{}", super::link::shared_lib_extension()));

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
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let llvm_ir = lower_llvm_ir(lowered_fir, enforce_contract_checks)?;
    let cache_marker = native_artifact_cache_marker(&build_dir, artifact_stem, "ffi", "llvm");
    let cache_key = native_artifact_cache_key(
        "ffi",
        "llvm",
        artifact_stem,
        profile,
        lowered_fir,
        manifest,
        &runtime_shim_path,
        &[llvm_ir.as_bytes()],
    )?;
    if native_artifact_cache_hit(&cache_marker, &cache_key, &[&static_path, &shared_path]) {
        return Ok((Some(static_path), Some(shared_path)));
    }
    std::fs::write(&ll_path, llvm_ir)
        .with_context(|| format!("failed writing llvm ir: {}", ll_path.display()))?;

    let candidates = linker_candidates();
    let mut obj_compiled = false;
    let mut shim_compiled = false;
    let mut last_error = None;
    for tool in &candidates {
        let mut obj_cmd = Command::new(tool);
        obj_cmd
            .arg("-x")
            .arg("ir")
            .arg(&ll_path)
            .arg("-c")
            .arg("-fPIC")
            .arg("-o")
            .arg(&obj_path);
        apply_target_link_flags(&mut obj_cmd);
        apply_profile_optimization_flags(&mut obj_cmd, profile, manifest);
        apply_pgo_flags(&mut obj_cmd)?;
        match obj_cmd.output() {
            Ok(output) if output.status.success() => {
                obj_compiled = true;
            }
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed compiling llvm object: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
                continue;
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
                continue;
            }
        }

        let mut shim_cmd = Command::new(tool);
        shim_cmd
            .arg("-x")
            .arg(runtime_shim_language_arg(lowered_fir))
            .arg(&runtime_shim_path)
            .arg("-c")
            .arg("-fPIC")
            .arg("-o")
            .arg(&shim_obj_path);
        apply_target_link_flags(&mut shim_cmd);
        apply_profile_optimization_flags(&mut shim_cmd, profile, manifest);
        apply_pgo_flags(&mut shim_cmd)?;
        match shim_cmd.output() {
            Ok(output) if output.status.success() => {
                shim_compiled = true;
                break;
            }
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed compiling runtime shim object: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    if !obj_compiled || !shim_compiled {
        return Err(anyhow!(
            "failed compiling ffi library objects: {}",
            last_error.unwrap_or_else(|| "unknown compiler error".to_string())
        ));
    }

    super::link::create_static_archive(
        &static_path,
        &[obj_path.as_path(), shim_obj_path.as_path()],
    )?;
    let allow_undefined = !collect_extern_c_imports(lowered_fir).is_empty();
    super::link::link_shared_library(
        &shared_path,
        &[obj_path.as_path(), shim_obj_path.as_path()],
        lowered_fir,
        manifest,
        allow_undefined,
    )?;
    write_native_artifact_cache_key(&cache_marker, &cache_key)?;
    Ok((Some(static_path), Some(shared_path)))
}

pub(super) fn emit_incremental_module_object_llvm(
    fir: &fir::FirModule,
    object_path: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    local_functions: &HashSet<String>,
    local_mutable_globals: &HashSet<String>,
) -> Result<()> {
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let llvm_ir = lower_llvm_ir_partitioned(
        fir,
        enforce_contract_checks,
        Some(local_functions),
        Some(local_mutable_globals),
    )?;
    let ll_path = object_path.with_extension("ll");
    std::fs::write(&ll_path, llvm_ir)
        .with_context(|| format!("failed writing llvm ir: {}", ll_path.display()))?;
    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("-x")
            .arg("ir")
            .arg(&ll_path)
            .arg("-c")
            .arg("-fPIC")
            .arg("-o")
            .arg(object_path);
        apply_target_link_flags(&mut cmd);
        apply_profile_optimization_flags(&mut cmd, profile, manifest);
        apply_pgo_flags(&mut cmd)?;
        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed compiling incremental llvm object: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    Err(anyhow!(
        "failed compiling incremental llvm object {}: {}",
        object_path.display(),
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}

pub(super) fn emit_native_artifact_llvm(
    fir: &fir::FirModule,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<PathBuf> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let ll_path = build_dir.join(format!("{artifact_stem}.ll"));
    let bin_path = build_dir.join(artifact_stem);
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
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let llvm_ir = lower_llvm_ir(lowered_fir, enforce_contract_checks)?;
    let cache_marker = native_artifact_cache_marker(&build_dir, artifact_stem, "bin", "llvm");
    let cache_key = native_artifact_cache_key(
        "bin",
        "llvm",
        artifact_stem,
        profile,
        lowered_fir,
        manifest,
        &runtime_shim_path,
        &[llvm_ir.as_bytes()],
    )?;
    if native_artifact_cache_hit(&cache_marker, &cache_key, &[&bin_path]) {
        return Ok(bin_path);
    }
    std::fs::write(&ll_path, llvm_ir)
        .with_context(|| format!("failed writing llvm ir: {}", ll_path.display()))?;

    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("-x")
            .arg("ir")
            .arg(&ll_path)
            .arg("-x")
            .arg(runtime_shim_language_arg(lowered_fir))
            .arg(&runtime_shim_path)
            .arg("-o")
            .arg(&bin_path);
        apply_target_link_flags(&mut cmd);
        apply_gpu_backend_link_args(&mut cmd, lowered_fir);
        apply_manifest_link_args(&mut cmd, manifest);
        apply_profile_optimization_flags(&mut cmd, profile, manifest);
        apply_extra_linker_args(&mut cmd);
        apply_pgo_flags(&mut cmd)?;

        match cmd.output() {
            Ok(output) if output.status.success() => {
                write_native_artifact_cache_key(&cache_marker, &cache_key)?;
                return Ok(bin_path);
            }
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }

    Err(anyhow!(
        "failed to compile llvm native artifact: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}
