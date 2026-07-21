use super::*;

pub(crate) fn lower_llvm_ir(fir: &fir::FirModule, enforce_contract_checks: bool) -> Result<String> {
    lower_llvm_ir_partitioned(fir, enforce_contract_checks, None, None)
}

pub(crate) fn lower_llvm_ir_partitioned(
    fir: &fir::FirModule,
    enforce_contract_checks: bool,
    local_functions: Option<&HashSet<String>>,
    local_mutable_globals: Option<&HashSet<String>>,
) -> Result<String> {
    let plan = build_native_canonical_plan(fir, enforce_contract_checks);
    let gpu_backend = resolve_gpu_backend(fir_module_uses_gpu(fir), None)?
        .map(|adapter| adapter.kind)
        .unwrap_or(super::super::gpu_backend::GpuBackendKind::Metal);
    let gpu_kernel_launch_descriptors = gpu_kernel_launch_descriptors(fir, gpu_backend)?;
    if fir.typed_functions.is_empty() {
        let ret = plan
            .forced_main_return
            .or(fir.entry_return_const_i32)
            .unwrap_or(0);
        return Ok(format!(
            "; ModuleID = '{name}'\ndefine i32 @main() {{\nentry:\n  ret i32 {ret}\n}}\n",
            name = fir.name
        ));
    }

    let mut out = String::new();
    let _ = writeln!(&mut out, "; ModuleID = '{}'", fir.name);
    let _ = writeln!(&mut out, "declare void @llvm.trap()");
    let used_imports = collect_used_native_runtime_imports(fir);
    for import in &used_imports {
        match import.callee {
            "alloc" => {
                let _ = writeln!(
                    &mut out,
                    "declare {} @{}({})",
                    llvm_pointer_int_type(),
                    import.symbol,
                    llvm_pointer_int_type()
                );
            }
            "free" => {
                let _ = writeln!(
                    &mut out,
                    "declare void @{}({})",
                    import.symbol,
                    llvm_pointer_int_type()
                );
            }
            "gpu.device_memory_bytes" => {
                let _ = writeln!(&mut out, "declare i64 @{}(i32)", import.symbol);
            }
            "gpu.upload_f32" | "gpu.upload_i32" | "gpu.upload_u32" => {
                let _ = writeln!(
                    &mut out,
                    "declare i32 @{}(i32, {}, i32)",
                    import.symbol,
                    llvm_pointer_int_type()
                );
            }
            "gpu.download_f32" | "gpu.download_i32" | "gpu.download_u32" => {
                let _ = writeln!(
                    &mut out,
                    "declare {} @{}(i32)",
                    llvm_pointer_int_type(),
                    import.symbol
                );
            }
            "gpu.slice" => {
                let _ = writeln!(
                    &mut out,
                    "declare {} @{}(i32, i32, i32)",
                    llvm_pointer_int_type(),
                    import.symbol
                );
            }
            "gpu.launch0" => {
                let _ = writeln!(
                    &mut out,
                    "declare i32 @{}(i32, i32, i32, i32, i32)",
                    import.symbol
                );
            }
            "gpu.launch1" => {
                let _ = writeln!(
                    &mut out,
                    "declare i32 @{}(i32, i32, i32, i32, i32, {})",
                    import.symbol,
                    llvm_pointer_int_type()
                );
            }
            "gpu.launch2" => {
                let _ = writeln!(
                    &mut out,
                    "declare i32 @{}(i32, i32, i32, i32, i32, {}, {})",
                    import.symbol,
                    llvm_pointer_int_type(),
                    llvm_pointer_int_type()
                );
            }
            "gpu.launch3" => {
                let _ = writeln!(
                    &mut out,
                    "declare i32 @{}(i32, i32, i32, i32, i32, {}, {}, {})",
                    import.symbol,
                    llvm_pointer_int_type(),
                    llvm_pointer_int_type(),
                    llvm_pointer_int_type()
                );
            }
            "gpu.launch4" => {
                let _ = writeln!(
                    &mut out,
                    "declare i32 @{}(i32, i32, i32, i32, i32, {}, {}, {}, {})",
                    import.symbol,
                    llvm_pointer_int_type(),
                    llvm_pointer_int_type(),
                    llvm_pointer_int_type(),
                    llvm_pointer_int_type()
                );
            }
            _ => {
                let mut params = String::new();
                for index in 0..import.arity {
                    if index > 0 {
                        params.push_str(", ");
                    }
                    params.push_str("i32");
                }
                let _ = writeln!(&mut out, "declare i32 @{}({})", import.symbol, params);
            }
        }
    }
    let used_data_plane_imports = collect_used_native_data_plane_imports(fir);
    for import in &used_data_plane_imports {
        let mut params = String::new();
        for index in 0..import.arity {
            if index > 0 {
                params.push_str(", ");
            }
            params.push_str("i32");
        }
        let _ = writeln!(&mut out, "declare i32 @{}({})", import.symbol, params);
    }
    let _ = writeln!(&mut out, "declare i64 @{}(i32, i32)", NATIVE_AGG_NEW_SYMBOL);
    let _ = writeln!(
        &mut out,
        "declare i32 @{}(i64, i32, i64)",
        NATIVE_AGG_SET_I64_SYMBOL
    );
    let _ = writeln!(
        &mut out,
        "declare i64 @{}(i64, i32)",
        NATIVE_AGG_GET_I64_SYMBOL
    );
    let _ = writeln!(&mut out, "declare i32 @{}(i64)", NATIVE_AGG_TAG_SYMBOL);
    let _ = writeln!(
        &mut out,
        "declare {} @{}(i32)",
        llvm_pointer_int_type(),
        NATIVE_STR_PTR_SYMBOL
    );
    let _ = writeln!(
        &mut out,
        "declare i32 @{}({})",
        NATIVE_VEC_LEN_SYMBOL,
        llvm_pointer_int_type()
    );
    let _ = writeln!(
        &mut out,
        "declare i32 @{}({}, i32)",
        NATIVE_VEC_GET_I32_SYMBOL,
        llvm_pointer_int_type()
    );
    let _ = writeln!(
        &mut out,
        "declare i32 @{}({}, i32)",
        NATIVE_VEC_GET_U32_SYMBOL,
        llvm_pointer_int_type()
    );
    let _ = writeln!(
        &mut out,
        "declare float @{}({}, i32)",
        NATIVE_VEC_GET_F32_SYMBOL,
        llvm_pointer_int_type()
    );
    let extern_imports = collect_extern_c_imports(fir);
    let mut extern_link_symbols = fir
        .typed_functions
        .iter()
        .filter(|function| is_extern_c_abi_function(function))
        .map(|function| {
            (
                function.name.clone(),
                function
                    .link_name
                    .clone()
                    .unwrap_or_else(|| function.name.clone()),
            )
        })
        .collect::<HashMap<_, _>>();
    extern_link_symbols.insert(
        NATIVE_AGG_NEW.to_string(),
        NATIVE_AGG_NEW_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_AGG_SET_I64.to_string(),
        NATIVE_AGG_SET_I64_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_AGG_GET_I64.to_string(),
        NATIVE_AGG_GET_I64_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_AGG_TAG.to_string(),
        NATIVE_AGG_TAG_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_STR_PTR.to_string(),
        NATIVE_STR_PTR_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_VEC_LEN.to_string(),
        NATIVE_VEC_LEN_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_VEC_GET_I32.to_string(),
        NATIVE_VEC_GET_I32_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_VEC_GET_U32.to_string(),
        NATIVE_VEC_GET_U32_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_VEC_GET_F32.to_string(),
        NATIVE_VEC_GET_F32_SYMBOL.to_string(),
    );
    let mut function_sigs = HashMap::<String, LlvmFunctionSig>::new();
    for function in &fir.typed_functions {
        function_sigs.insert(
            function.name.clone(),
            LlvmFunctionSig {
                params: function
                    .params
                    .iter()
                    .map(|param| llvm_ir_type_for_ast_type(&param.ty))
                    .collect(),
                ret: (!matches!(function.return_type, ast::Type::Void | ast::Type::Never))
                    .then(|| llvm_ir_type_for_ast_type(&function.return_type)),
                param_names: function
                    .params
                    .iter()
                    .map(|param| param.name.clone())
                    .collect(),
                is_extern_c_import: is_extern_c_import_decl(function),
            },
        );
    }
    function_sigs.insert(
        NATIVE_AGG_NEW.to_string(),
        LlvmFunctionSig {
            params: vec!["i32".to_string(), "i32".to_string()],
            ret: Some("i64".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_AGG_SET_I64.to_string(),
        LlvmFunctionSig {
            params: vec!["i64".to_string(), "i32".to_string(), "i64".to_string()],
            ret: Some("i32".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_AGG_GET_I64.to_string(),
        LlvmFunctionSig {
            params: vec!["i64".to_string(), "i32".to_string()],
            ret: Some("i64".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_AGG_TAG.to_string(),
        LlvmFunctionSig {
            params: vec!["i64".to_string()],
            ret: Some("i32".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        "alloc".to_string(),
        LlvmFunctionSig {
            params: vec![llvm_pointer_int_type().to_string()],
            ret: Some(llvm_pointer_int_type().to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        "free".to_string(),
        LlvmFunctionSig {
            params: vec![llvm_pointer_int_type().to_string()],
            ret: None,
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_STR_PTR.to_string(),
        LlvmFunctionSig {
            params: vec!["i32".to_string()],
            ret: Some(llvm_pointer_int_type().to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_VEC_LEN.to_string(),
        LlvmFunctionSig {
            params: vec![llvm_pointer_int_type().to_string()],
            ret: Some("i32".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_VEC_GET_I32.to_string(),
        LlvmFunctionSig {
            params: vec![llvm_pointer_int_type().to_string(), "i32".to_string()],
            ret: Some("i32".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_VEC_GET_U32.to_string(),
        LlvmFunctionSig {
            params: vec![llvm_pointer_int_type().to_string(), "i32".to_string()],
            ret: Some("i32".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_VEC_GET_F32.to_string(),
        LlvmFunctionSig {
            params: vec![llvm_pointer_int_type().to_string(), "i32".to_string()],
            ret: Some("float".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    for import in &extern_imports {
        let params = import
            .params
            .iter()
            .map(|param| llvm_ir_type_for_ast_type(&param.ty))
            .collect::<Vec<_>>()
            .join(", ");
        let symbol = import.link_name.as_deref().unwrap_or(import.name.as_str());
        let symbol = native_mangle_symbol(symbol);
        let ret = llvm_ir_type_for_ast_type(&import.return_type);
        let _ = writeln!(&mut out, "declare {ret} @{}({})", symbol, params);
    }
    if let Some(local_functions) = local_functions {
        for function in &fir.typed_functions {
            if matches!(
                function.execution_space,
                ast::ExecutionSpace::Kernel | ast::ExecutionSpace::Device
            ) || is_extern_c_import_decl(function)
                || local_functions.contains(&function.name)
            {
                continue;
            }
            let params = function
                .params
                .iter()
                .map(|param| llvm_ir_type_for_ast_type(&param.ty))
                .collect::<Vec<_>>()
                .join(", ");
            let ret = llvm_ir_type_for_ast_type(&function.return_type);
            let _ = writeln!(
                &mut out,
                "declare {ret} @{}({params})",
                native_link_symbol_for_function(function),
            );
        }
    }
    if !used_imports.is_empty() || !used_data_plane_imports.is_empty() || !extern_imports.is_empty()
    {
        out.push('\n');
    }
    let mut mutable_global_symbols = HashMap::<String, String>::new();
    let mut mutable_globals_sorted = plan
        .mutable_static_i32
        .iter()
        .map(|(name, value)| (name.clone(), *value))
        .collect::<Vec<_>>();
    mutable_globals_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in &mutable_globals_sorted {
        let symbol = llvm_static_symbol_name(name);
        let local = local_mutable_globals.is_none_or(|set| set.contains(name));
        if local {
            let _ = writeln!(&mut out, "@{symbol} = global i32 {value}");
        } else {
            let _ = writeln!(&mut out, "@{symbol} = external global i32");
        }
        mutable_global_symbols.insert(name.clone(), symbol);
    }
    if !mutable_global_symbols.is_empty() {
        out.push('\n');
    }
    for function in &fir.typed_functions {
        if matches!(
            function.execution_space,
            ast::ExecutionSpace::Kernel | ast::ExecutionSpace::Device
        ) {
            continue;
        }
        if is_extern_c_import_decl(function)
            || local_functions.is_some_and(|set| !set.contains(&function.name))
        {
            continue;
        }
        if let Some(data_ops) = plan.data_ops_by_function.get(&function.name) {
            for op in data_ops {
                let _ = writeln!(&mut out, "; canonical.dataop {}", render_native_data_op(op));
            }
        }
        let lowered = match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => llvm_emit_function(
                function,
                plan.forced_main_return.filter(|_| function.name == "main"),
                &plan.global_const_i32,
                &plan.variant_tags,
                &mutable_global_symbols,
                &fir.struct_defs,
                &fir.enum_defs,
                &plan.string_literal_ids,
                &plan.task_ref_ids,
                &extern_link_symbols,
                &function_sigs,
                &gpu_kernel_launch_descriptors,
                cfg,
            )
            .map_err(|error| {
                anyhow!(
                    "llvm backend failed lowering canonical cfg for `{}`: {}",
                    function.name,
                    error
                )
            })?,
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
        let _ = writeln!(&mut out, "{lowered}");
    }
    Ok(out)
}

pub(crate) fn llvm_emit_function(
    function: &hir::TypedFunction,
    forced_return: Option<i32>,
    globals: &HashMap<String, i32>,
    variant_tags: &HashMap<String, i32>,
    mutable_globals: &HashMap<String, String>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
    extern_link_symbols: &HashMap<String, String>,
    function_sigs: &HashMap<String, LlvmFunctionSig>,
    gpu_kernel_launch_descriptors: &HashMap<String, GpuKernelLaunchDescriptor>,
    cfg: &ControlFlowCfg,
) -> Result<String> {
    let params = function
        .params
        .iter()
        .enumerate()
        .map(|(i, param)| format!("{} %arg{i}", llvm_ir_type_for_ast_type(&param.ty)))
        .collect::<Vec<_>>()
        .join(", ");
    let return_ty = llvm_ir_type_for_ast_type(&function.return_type);
    let wrapped_indices = collect_wrapped_index_candidates(&function.body);
    let mut ctx = LlvmFuncCtx::new(
        &function.name,
        globals.clone(),
        variant_tags.clone(),
        mutable_globals.clone(),
        function.local_types.clone(),
        struct_defs.clone(),
        enum_defs.clone(),
        gpu_kernel_launch_descriptors.clone(),
        return_ty.clone(),
        wrapped_indices,
        extern_link_symbols.clone(),
        function_sigs.clone(),
    );
    let mut out = String::new();
    let _ = writeln!(
        &mut out,
        "define {return_ty} @{}({params}) {{",
        native_link_symbol_for_function(function),
    );
    let _ = writeln!(&mut out, "entry:");
    for (index, param) in function.params.iter().enumerate() {
        let slot = format!("%slot_{}", param.name);
        let param_ty = llvm_ir_type_for_ast_type(&param.ty);
        ctx.declare_alloca(&slot, &param_ty);
        ctx.emit(format_args!("  store {param_ty} %arg{index}, ptr {slot}\n"));
        ctx.slots.insert(param.name.clone(), slot.clone());
        ctx.slot_tys.insert(param.name.clone(), param_ty);
        if let Some(binding) = llvm_array_binding_from_type(&slot, &param.ty) {
            ctx.array_slots.insert(param.name.clone(), binding);
        }
    }
    let labels = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(id, _)| (id, format!("bb{id}")))
        .collect::<HashMap<_, _>>();
    let entry = labels
        .get(&cfg.entry)
        .ok_or_else(|| anyhow!("missing llvm label for cfg entry block {}", cfg.entry))?;
    if cfg.entry != 0 {
        ctx.emit(format_args!("  br label %{entry}\n"));
    }
    for (block_id, block) in cfg.blocks.iter().enumerate() {
        ctx.direct_values.clear();
        let label = labels
            .get(&block_id)
            .ok_or_else(|| anyhow!("missing llvm label for cfg block {}", block_id))?;
        if !(block_id == cfg.entry && cfg.entry == 0) {
            ctx.emit(format_args!("{label}:\n"));
        }
        let linear_terminated =
            llvm_emit_linear_stmts(&block.stmts, &mut ctx, string_literal_ids, task_ref_ids)?;
        if linear_terminated {
            continue;
        }
        match &block.terminator {
            ControlFlowTerminator::Return(Some(expr)) => {
                let value = llvm_emit_expr(expr, &mut ctx, string_literal_ids, task_ref_ids)?;
                let value = llvm_cast_value(&mut ctx, value, &return_ty)?;
                ctx.emit(format_args!("  ret {} {}\n", value.ty, value.value));
            }
            ControlFlowTerminator::Return(None) => {
                let fallback = forced_return.unwrap_or(0);
                if return_ty == "void" {
                    ctx.code.push_str("  ret void\n");
                } else {
                    let fallback = llvm_zero_literal(&return_ty, fallback);
                    ctx.emit(format_args!("  ret {return_ty} {fallback}\n"));
                }
            }
            ControlFlowTerminator::Jump { target, .. } => {
                let target_label = labels
                    .get(target)
                    .ok_or_else(|| anyhow!("missing llvm label for cfg jump target {target}"))?;
                ctx.emit(format_args!("  br label %{target_label}\n"));
            }
            ControlFlowTerminator::Branch {
                condition,
                then_target,
                else_target,
            } => {
                let pred = llvm_emit_condition_value(
                    condition,
                    &mut ctx,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                let then_label = labels.get(then_target).ok_or_else(|| {
                    anyhow!("missing llvm label for cfg branch target {}", then_target)
                })?;
                let else_label = labels.get(else_target).ok_or_else(|| {
                    anyhow!("missing llvm label for cfg branch target {}", else_target)
                })?;
                ctx.emit(format_args!(
                    "  br i1 {pred}, label %{then_label}, label %{else_label}\n"
                ));
            }
            ControlFlowTerminator::Switch {
                scrutinee,
                cases,
                default_target,
            } => {
                let mut value =
                    llvm_emit_expr(scrutinee, &mut ctx, string_literal_ids, task_ref_ids)?;
                let aggregate_switch = match scrutinee {
                    ast::Expr::Ident(name) => {
                        ctx.aggregate_bindings.contains_key(name)
                            || llvm_local_is_aggregate(name, &ctx)
                    }
                    ast::Expr::EnumInit { .. }
                    | ast::Expr::StructInit { .. }
                    | ast::Expr::Tuple(_) => true,
                    _ => false,
                };
                if aggregate_switch && value.ty == "i64" {
                    let tag_value = ctx.value();
                    ctx.emit(format_args!(
                        "  {tag_value} = call i32 @{}(i64 {})\n",
                        NATIVE_AGG_TAG_SYMBOL, value.value
                    ));
                    value = LlvmValue {
                        value: tag_value,
                        ty: "i32".to_string(),
                    };
                }
                let default_label = labels.get(default_target).ok_or_else(|| {
                    anyhow!(
                        "missing llvm label for cfg switch default target {}",
                        default_target
                    )
                })?;
                ctx.emit(format_args!(
                    "  switch {} {}, label %{default_label} [\n",
                    value.ty, value.value
                ));
                for (case_value, target) in cases {
                    let target_label = labels.get(target).ok_or_else(|| {
                        anyhow!("missing llvm label for cfg switch target {}", target)
                    })?;
                    ctx.emit(format_args!(
                        "    {} {case_value}, label %{target_label}\n",
                        value.ty
                    ));
                }
                ctx.emit(format_args!("  ]\n"));
            }
            ControlFlowTerminator::Unreachable => {
                ctx.emit(format_args!("  unreachable\n"));
            }
        }
    }
    out.push_str(&ctx.alloca_prologue);
    out.push_str(&ctx.code);
    let _ = writeln!(&mut out, "}}");
    Ok(out)
}

pub(crate) fn llvm_emit_expr_as(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
    target_ty: &str,
) -> Result<LlvmValue> {
    let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
    llvm_cast_value(ctx, value, target_ty)
}
