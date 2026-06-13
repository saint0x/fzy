fn emit_native_artifact(
    fir: &fir::FirModule,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
) -> Result<PathBuf> {
    let backend = resolve_native_backend(profile, backend_override)?;
    match backend.as_str() {
        "llvm" => emit_native_artifact_llvm(fir, project_root, artifact_stem, profile, manifest),
        "cranelift" => {
            emit_native_artifact_cranelift(fir, project_root, artifact_stem, profile, manifest)
        }
        other => Err(anyhow!(
            "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
            other
        )),
    }
}

fn emit_native_libraries(
    fir: &fir::FirModule,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let backend = resolve_native_backend(profile, backend_override)?;
    match backend.as_str() {
        "llvm" => emit_native_libraries_llvm(fir, project_root, artifact_stem, profile, manifest),
        "cranelift" => {
            emit_native_libraries_cranelift(fir, project_root, artifact_stem, profile, manifest)
        }
        other => Err(anyhow!(
            "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
            other
        )),
    }
}

fn emit_native_libraries_llvm(
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
    let shared_path = build_dir.join(format!("lib{artifact_stem}.{}", shared_lib_extension()));

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

    create_static_archive(&static_path, &[obj_path.as_path(), shim_obj_path.as_path()])?;
    let allow_undefined = !collect_extern_c_imports(lowered_fir).is_empty();
    link_shared_library(
        &shared_path,
        &[obj_path.as_path(), shim_obj_path.as_path()],
        lowered_fir,
        manifest,
        allow_undefined,
    )?;
    write_native_artifact_cache_key(&cache_marker, &cache_key)?;
    Ok((Some(static_path), Some(shared_path)))
}

fn emit_native_libraries_cranelift(
    fir: &fir::FirModule,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;
    let object_path = build_dir.join(format!("{artifact_stem}.ffi.o"));
    let shim_obj_path = build_dir.join(format!("{artifact_stem}.ffi.runtime.o"));
    let static_path = build_dir.join(format!("lib{artifact_stem}.a"));
    let shared_path = build_dir.join(format!("lib{artifact_stem}.{}", shared_lib_extension()));

    let shim_plan = build_native_runtime_shim_plan(fir)?;
    let lowered_fir = &shim_plan.lowered_fir;
    let string_literals = collect_native_string_literals_with_gpu(lowered_fir);
    let spawn_task_symbols = collect_spawn_task_symbols(lowered_fir)
        .into_iter()
        .filter(|symbol| symbol != "main")
        .collect::<Vec<_>>();
    let plan =
        build_native_canonical_plan_with_task_symbols(lowered_fir, true, &spawn_task_symbols);
    let gpu_kernel_launch_descriptors = metal_kernel_launch_descriptors(lowered_fir)?;
    let task_symbol_set = spawn_task_symbols.iter().cloned().collect::<HashSet<_>>();
    let mut flags_builder = settings::builder();
    let optimize_override = manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.optimize);
    let opt_level = match (profile, optimize_override) {
        (_, Some(true)) => "speed",
        (_, Some(false)) => "none",
        (BuildProfile::Dev, None) => "none",
        (BuildProfile::Release, None) => "speed",
        (BuildProfile::Verify, None) => "speed",
        (BuildProfile::Strict, None) => "speed",
    };
    flags_builder
        .set("opt_level", opt_level)
        .map_err(|error| anyhow!("failed setting cranelift opt_level={opt_level}: {error}"))?;
    flags_builder
        .set("is_pic", "true")
        .map_err(|error| anyhow!("failed enabling cranelift PIC codegen: {error}"))?;
    let flags = settings::Flags::new(flags_builder);
    let isa_builder = cranelift_native::builder()
        .map_err(|error| anyhow!("failed constructing cranelift native isa: {error}"))?;
    let isa = isa_builder
        .finish(flags)
        .map_err(|error| anyhow!("failed finalizing cranelift isa: {error}"))?;
    let object_builder = ObjectBuilder::new(isa, lowered_fir.name.clone(), default_libcall_names())
        .map_err(|error| anyhow!("failed creating cranelift object builder: {error}"))?;
    let mut module = ObjectModule::new(object_builder);

    let (mut function_ids, mut function_signatures) = declare_clif_functions(
        &mut module,
        lowered_fir,
        |function| {
            if is_extern_c_import_decl(function) {
                Linkage::Import
            } else if task_symbol_set.contains(&function.name) {
                Linkage::Export
            } else if is_extern_c_abi_function(function) && !function.body.is_empty() {
                Linkage::Export
            } else {
                Linkage::Local
            }
        },
        "cranelift ffi symbol",
    )?;
    let mut mutable_global_data_ids = HashMap::<String, cranelift_module::DataId>::new();
    let mut mutable_globals_sorted = plan
        .mutable_static_i32
        .iter()
        .map(|(name, value)| (name.clone(), *value))
        .collect::<Vec<_>>();
    mutable_globals_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in mutable_globals_sorted {
        let symbol = llvm_static_symbol_name(&name);
        let data_id = module
            .declare_data(&symbol, Linkage::Local, true, false)
            .map_err(|error| anyhow!("failed declaring mutable static `{name}` data: {error}"))?;
        let mut data = DataDescription::new();
        data.define((value as i32).to_le_bytes().to_vec().into_boxed_slice());
        module
            .define_data(data_id, &data)
            .map_err(|error| anyhow!("failed defining mutable static `{name}` data: {error}"))?;
        mutable_global_data_ids.insert(name, data_id);
    }
    declare_native_runtime_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    declare_native_data_plane_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    for function in &lowered_fir.typed_functions {
        if matches!(
            function.execution_space,
            ast::ExecutionSpace::Kernel | ast::ExecutionSpace::Device
        ) {
            continue;
        }
        if is_extern_c_import_decl(function) {
            continue;
        }
        let Some(function_id) = function_ids.get(&function.name).copied() else {
            continue;
        };
        let mut context = module.make_context();
        context.func.signature.params.clear();
        context.func.signature.returns.clear();
        let signature = function_signatures
            .get(&function.name)
            .ok_or_else(|| anyhow!("missing signature for `{}`", function.name))?;
        for param_ty in &signature.params {
            context.func.signature.params.push(AbiParam::new(*param_ty));
        }
        if let Some(ret_ty) = signature.ret {
            context.func.signature.returns.push(AbiParam::new(ret_ty));
        }

        let mut function_builder_context = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);

        let mut locals = HashMap::<String, LocalBinding>::new();
        let mut next_var = 0usize;
        let mut current_return_ptr = None;
        let mut param_offset = 0usize;
        if signature.sret.is_some() {
            let var = Variable::from_u32(next_var as u32);
            next_var += 1;
            builder.declare_var(var, pointer_sized_clif_type());
            let value = builder.block_params(entry)[0];
            builder.def_var(var, value);
            current_return_ptr = Some(LocalBinding {
                var,
                ty: pointer_sized_clif_type(),
            });
            param_offset = 1;
        }
        for (index, param) in function.params.iter().enumerate() {
            let var = Variable::from_u32(next_var as u32);
            next_var += 1;
            let sig_index = index + param_offset;
            let param_ty = signature.params.get(sig_index).copied().ok_or_else(|| {
                anyhow!("missing param {} type for `{}`", sig_index, function.name)
            })?;
            builder.declare_var(var, param_ty);
            let value = builder.block_params(entry)[sig_index];
            builder.def_var(var, value);
            locals.insert(param.name.clone(), LocalBinding { var, ty: param_ty });
        }
        let cfg = match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => cfg,
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        };
        clif_emit_function_cfg(
            &mut builder,
            &mut module,
            &function_ids,
            &function_signatures,
            &plan.string_literal_ids,
            &plan.task_ref_ids,
            &plan.global_const_i32,
            &plan.variant_tags,
            &mutable_global_data_ids,
            &function.local_types,
            &gpu_kernel_launch_descriptors,
            &lowered_fir.struct_defs,
            &lowered_fir.enum_defs,
            signature.ret,
            signature.sret,
            current_return_ptr,
            &function.name,
            cfg,
            entry,
            &mut locals,
            &mut next_var,
            None,
        )?;
        builder.finalize();
        module
            .define_function(function_id, &mut context)
            .map_err(|error| {
                anyhow!(
                    "failed defining cranelift ffi function `{}`: {error}",
                    function.name
                )
            })?;
        module.clear_context(&mut context);
    }
    let object_product = module.finish();
    let object_bytes = object_product
        .emit()
        .map_err(|error| anyhow!("failed emitting cranelift object bytes: {error}"))?;
    std::fs::write(&object_path, &object_bytes).with_context(|| {
        format!(
            "failed writing cranelift ffi object: {}",
            object_path.display()
        )
    })?;

    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &shim_plan.async_exports,
        &shim_plan.sync_exports,
    )?;
    compile_runtime_shim_object(
        &runtime_shim_path,
        &shim_obj_path,
        profile,
        manifest,
        native_runtime_shim_uses_objc(lowered_fir),
    )?;
    let cache_marker = native_artifact_cache_marker(&build_dir, artifact_stem, "ffi", "cranelift");
    let cache_key = native_artifact_cache_key(
        "ffi",
        "cranelift",
        artifact_stem,
        profile,
        lowered_fir,
        manifest,
        &runtime_shim_path,
        &[&object_bytes],
    )?;
    if native_artifact_cache_hit(&cache_marker, &cache_key, &[&static_path, &shared_path]) {
        return Ok((Some(static_path), Some(shared_path)));
    }
    create_static_archive(
        &static_path,
        &[object_path.as_path(), shim_obj_path.as_path()],
    )?;
    let allow_undefined = !collect_extern_c_imports(lowered_fir).is_empty();
    link_shared_library(
        &shared_path,
        &[object_path.as_path(), shim_obj_path.as_path()],
        lowered_fir,
        manifest,
        allow_undefined,
    )?;
    write_native_artifact_cache_key(&cache_marker, &cache_key)?;
    Ok((Some(static_path), Some(shared_path)))
}

fn create_static_archive(output: &Path, objects: &[&Path]) -> Result<()> {
    let candidates = archiver_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("rcs").arg(output);
        for object in objects {
            cmd.arg(object);
        }
        match cmd.output() {
            Ok(output_result) if output_result.status.success() => return Ok(()),
            Ok(output_result) => {
                last_error = Some(format!(
                    "{} failed creating static archive: {}",
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
        "failed to create static archive {}: {}",
        output.display(),
        last_error.unwrap_or_else(|| "unknown archiver error".to_string())
    ))
}

fn link_shared_library(
    output: &Path,
    objects: &[&Path],
    fir: &fir::FirModule,
    manifest: Option<&manifest::Manifest>,
    allow_undefined: bool,
) -> Result<()> {
    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        if cfg!(target_vendor = "apple") {
            cmd.arg("-dynamiclib");
            if allow_undefined {
                cmd.arg("-Wl,-undefined,dynamic_lookup");
            }
        } else {
            cmd.arg("-shared");
            if allow_undefined {
                cmd.arg("-Wl,--allow-shlib-undefined");
            }
        }
        for object in objects {
            cmd.arg(object);
        }
        cmd.arg("-o").arg(output);
        apply_target_link_flags(&mut cmd);
        apply_gpu_backend_link_args(&mut cmd, fir);
        apply_manifest_link_args(&mut cmd, manifest);
        apply_extra_linker_args(&mut cmd);
        apply_pgo_flags(&mut cmd)?;
        match cmd.output() {
            Ok(output_result) if output_result.status.success() => return Ok(()),
            Ok(output_result) => {
                last_error = Some(format!(
                    "{} failed linking shared library: {}",
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
        "failed to link shared library {}: {}",
        output.display(),
        last_error.unwrap_or_else(|| "unknown linker error".to_string())
    ))
}

fn shared_lib_extension() -> &'static str {
    if cfg!(target_vendor = "apple") {
        "dylib"
    } else if cfg!(target_os = "windows") {
        "dll"
    } else {
        "so"
    }
}

fn resolve_native_backend(profile: BuildProfile, backend_override: Option<&str>) -> Result<String> {
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

fn emit_native_artifact_llvm(
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

fn emit_native_artifact_cranelift(
    fir: &fir::FirModule,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<PathBuf> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let object_path = build_dir.join(format!("{artifact_stem}.o"));
    let bin_path = build_dir.join(artifact_stem);
    let shim_plan = build_native_runtime_shim_plan(fir)?;
    let lowered_fir = &shim_plan.lowered_fir;
    let string_literals = collect_native_string_literals_with_gpu(lowered_fir);
    let mut flags_builder = settings::builder();
    let optimize_override = manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.optimize);
    let opt_level = match (profile, optimize_override) {
        (_, Some(true)) => "speed",
        (_, Some(false)) => "none",
        (BuildProfile::Dev, None) => "none",
        (BuildProfile::Release, None) => "speed",
        (BuildProfile::Verify, None) => "speed",
        (BuildProfile::Strict, None) => "speed",
    };
    flags_builder
        .set("opt_level", opt_level)
        .map_err(|error| anyhow!("failed setting cranelift opt_level={opt_level}: {error}"))?;
    flags_builder
        .set("is_pic", "true")
        .map_err(|error| anyhow!("failed enabling cranelift PIC codegen: {error}"))?;
    let flags = settings::Flags::new(flags_builder);
    let isa_builder = cranelift_native::builder()
        .map_err(|error| anyhow!("failed constructing cranelift native isa: {error}"))?;
    let isa = isa_builder
        .finish(flags)
        .map_err(|error| anyhow!("failed finalizing cranelift isa: {error}"))?;

    let object_builder = ObjectBuilder::new(isa, lowered_fir.name.clone(), default_libcall_names())
        .map_err(|error| anyhow!("failed creating cranelift object builder: {error}"))?;
    let mut module = ObjectModule::new(object_builder);
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let plan = build_native_canonical_plan(lowered_fir, enforce_contract_checks);
    let gpu_kernel_launch_descriptors = metal_kernel_launch_descriptors(lowered_fir)?;

    let (mut function_ids, mut function_signatures) = declare_clif_functions(
        &mut module,
        lowered_fir,
        |function| {
            if is_extern_c_import_decl(function) {
                Linkage::Import
            } else {
                Linkage::Export
            }
        },
        "cranelift symbol",
    )?;
    let mut mutable_global_data_ids = HashMap::<String, cranelift_module::DataId>::new();
    let mut mutable_globals_sorted = plan
        .mutable_static_i32
        .iter()
        .map(|(name, value)| (name.clone(), *value))
        .collect::<Vec<_>>();
    mutable_globals_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in mutable_globals_sorted {
        let symbol = llvm_static_symbol_name(&name);
        let data_id = module
            .declare_data(&symbol, Linkage::Local, true, false)
            .map_err(|error| anyhow!("failed declaring mutable static `{name}` data: {error}"))?;
        let mut data = DataDescription::new();
        data.define((value as i32).to_le_bytes().to_vec().into_boxed_slice());
        module
            .define_data(data_id, &data)
            .map_err(|error| anyhow!("failed defining mutable static `{name}` data: {error}"))?;
        mutable_global_data_ids.insert(name, data_id);
    }
    declare_native_runtime_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    declare_native_data_plane_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    let spawn_task_symbols = collect_spawn_task_symbols(lowered_fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &shim_plan.async_exports,
        &shim_plan.sync_exports,
    )?;

    for function in &lowered_fir.typed_functions {
        if matches!(
            function.execution_space,
            ast::ExecutionSpace::Kernel | ast::ExecutionSpace::Device
        ) {
            continue;
        }
        if is_extern_c_import_decl(function) {
            continue;
        }
        let Some(function_id) = function_ids.get(&function.name).copied() else {
            continue;
        };
        let mut context = module.make_context();
        context.func.signature.params.clear();
        context.func.signature.returns.clear();
        let signature = function_signatures
            .get(&function.name)
            .ok_or_else(|| anyhow!("missing signature for `{}`", function.name))?;
        for param_ty in &signature.params {
            context.func.signature.params.push(AbiParam::new(*param_ty));
        }
        if let Some(ret_ty) = signature.ret {
            context.func.signature.returns.push(AbiParam::new(ret_ty));
        }

        let mut function_builder_context = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);

        let mut locals = HashMap::<String, LocalBinding>::new();
        let mut next_var = 0usize;
        let mut current_return_ptr = None;
        let mut param_offset = 0usize;
        if signature.sret.is_some() {
            let var = Variable::from_u32(next_var as u32);
            next_var += 1;
            builder.declare_var(var, pointer_sized_clif_type());
            let value = builder.block_params(entry)[0];
            builder.def_var(var, value);
            current_return_ptr = Some(LocalBinding {
                var,
                ty: pointer_sized_clif_type(),
            });
            param_offset = 1;
        }
        for (index, param) in function.params.iter().enumerate() {
            let var = Variable::from_u32(next_var as u32);
            next_var += 1;
            let sig_index = index + param_offset;
            let param_ty = signature.params.get(sig_index).copied().ok_or_else(|| {
                anyhow!("missing param {} type for `{}`", sig_index, function.name)
            })?;
            builder.declare_var(var, param_ty);
            let value = builder.block_params(entry)[sig_index];
            builder.def_var(var, value);
            locals.insert(param.name.clone(), LocalBinding { var, ty: param_ty });
        }
        let cfg = match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => cfg,
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        };
        clif_emit_function_cfg(
            &mut builder,
            &mut module,
            &function_ids,
            &function_signatures,
            &plan.string_literal_ids,
            &plan.task_ref_ids,
            &plan.global_const_i32,
            &plan.variant_tags,
            &mutable_global_data_ids,
            &function.local_types,
            &gpu_kernel_launch_descriptors,
            &lowered_fir.struct_defs,
            &lowered_fir.enum_defs,
            signature.ret,
            signature.sret,
            current_return_ptr,
            &function.name,
            cfg,
            entry,
            &mut locals,
            &mut next_var,
            if function.name == "main" && signature.ret == Some(types::I32) {
                Some(
                    plan.forced_main_return
                        .or(lowered_fir.entry_return_const_i32)
                        .unwrap_or(0),
                )
            } else {
                None
            },
        )?;
        builder.finalize();

        module
            .define_function(function_id, &mut context)
            .map_err(|error| {
                anyhow!(
                    "failed defining cranelift function `{}`: {error:?}",
                    function.name
                )
            })?;
        module.clear_context(&mut context);
    }
    let object_product = module.finish();
    let object_bytes = object_product
        .emit()
        .map_err(|error| anyhow!("failed emitting cranelift object bytes: {error}"))?;
    std::fs::write(&object_path, &object_bytes)
        .with_context(|| format!("failed writing cranelift object: {}", object_path.display()))?;
    let cache_marker = native_artifact_cache_marker(&build_dir, artifact_stem, "bin", "cranelift");
    let cache_key = native_artifact_cache_key(
        "bin",
        "cranelift",
        artifact_stem,
        profile,
        lowered_fir,
        manifest,
        &runtime_shim_path,
        &[&object_bytes],
    )?;
    if native_artifact_cache_hit(&cache_marker, &cache_key, &[&bin_path]) {
        return Ok(bin_path);
    }

    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg(&object_path)
            .arg("-x")
            .arg(runtime_shim_language_arg(lowered_fir))
            .arg(&runtime_shim_path)
            .arg("-o")
            .arg(&bin_path)
            .arg("-lpthread");
        apply_target_link_flags(&mut cmd);
        apply_gpu_backend_link_args(&mut cmd, lowered_fir);
        apply_manifest_link_args(&mut cmd, manifest);
        // Object code is already generated at selected Cranelift optimization level.
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
        "failed to link cranelift native artifact: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}

