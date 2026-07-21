use super::*;

pub(crate) fn build_native_cfg_map(
    fir: &fir::FirModule,
    variant_tags: &HashMap<String, i32>,
) -> HashMap<String, Result<ControlFlowCfg, String>> {
    let pattern_source_functions =
        collect_pattern_source_function_map_from_typed(&fir.typed_functions);
    fir.typed_functions
        .par_iter()
        .filter(|function| !is_extern_c_import_decl(function))
        .map(|function| {
            let cfg =
                build_control_flow_cfg(&function.body, variant_tags, &pattern_source_functions)
                    .and_then(|cfg| {
                        verify_control_flow_cfg(&cfg)?;
                        Ok(cfg)
                    });
            (
                function.name.clone(),
                cfg.map_err(|error| error.to_string()),
            )
        })
        .collect()
}

pub(crate) fn build_native_canonical_plan(
    fir: &fir::FirModule,
    enforce_contract_checks: bool,
) -> NativeCanonicalPlan {
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    build_native_canonical_plan_with_task_symbols(fir, enforce_contract_checks, &spawn_task_symbols)
}

pub(crate) fn build_native_canonical_plan_with_task_symbols(
    fir: &fir::FirModule,
    enforce_contract_checks: bool,
    spawn_task_symbols: &[String],
) -> NativeCanonicalPlan {
    ensure_codegen_pool_configured();
    let variant_tags = build_variant_tag_map(fir);
    let cfg_by_function = build_native_cfg_map(fir, &variant_tags);
    let mut task_ref_ids = HashMap::<String, i32>::new();
    for (index, symbol) in spawn_task_symbols.iter().enumerate() {
        task_ref_ids.insert(symbol.clone(), (index + 1) as i32);
    }
    let gpu_backend = resolve_gpu_backend(fir_module_uses_gpu(fir), None)
        .ok()
        .flatten()
        .map(|adapter| adapter.kind);
    let string_literals = collect_native_string_literals_with_gpu(fir, gpu_backend);
    NativeCanonicalPlan {
        forced_main_return: compute_forced_main_return(fir, enforce_contract_checks),
        string_literal_ids: build_string_literal_ids(&string_literals),
        global_const_i32: build_global_const_i32_map(fir),
        mutable_static_i32: build_mutable_static_i32_map(fir),
        variant_tags,
        task_ref_ids,
        cfg_by_function,
        data_ops_by_function: fir
            .typed_functions
            .par_iter()
            .filter(|function| !is_extern_c_import_decl(function))
            .map(|function| {
                (
                    function.name.clone(),
                    collect_native_data_ops_for_function(function),
                )
            })
            .collect(),
    }
}

pub(crate) fn collect_native_string_literals_with_gpu(
    fir: &fir::FirModule,
    backend: Option<super::super::gpu_backend::GpuBackendKind>,
) -> Vec<String> {
    let mut string_literals = collect_native_string_literals(fir);
    if let Some(backend) = backend {
        let Ok(extra_gpu_strings) = gpu_kernel_descriptor_strings(fir, backend) else {
            return string_literals;
        };
        let mut merged = string_literals.into_iter().collect::<HashSet<_>>();
        for value in extra_gpu_strings {
            merged.insert(value);
        }
        string_literals = merged.into_iter().collect();
        string_literals.sort();
    }
    string_literals
}

pub(crate) fn native_mangle_symbol(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}
