use super::*;

pub(crate) fn llvm_emit_complex_expr(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Option<Result<LlvmValue>> {
    match expr {
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => Some((|| {
            let pred = llvm_emit_condition_value(condition, ctx, string_literal_ids, task_ref_ids)?;
            let then_label = ctx.label("if.then");
            let else_label = ctx.label("if.else");
            let merge_label = ctx.label("if.merge");
            ctx.code.push_str(&format!(
                "  br i1 {pred}, label %{then_label}, label %{else_label}\n"
            ));

            ctx.code.push_str(&format!("{then_label}:\n"));
            let then_value = llvm_emit_expr(then_expr, ctx, string_literal_ids, task_ref_ids)?;
            ctx.code.push_str(&format!("  br label %{merge_label}\n"));

            ctx.code.push_str(&format!("{else_label}:\n"));
            let else_value = llvm_emit_expr(else_expr, ctx, string_literal_ids, task_ref_ids)?;
            let else_value = llvm_cast_value(ctx, else_value, &then_value.ty)?;
            ctx.code.push_str(&format!("  br label %{merge_label}\n"));

            ctx.code.push_str(&format!("{merge_label}:\n"));
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = phi {} [ {}, %{then_label} ], [ {}, %{else_label} ]\n",
                then_value.ty, then_value.value, else_value.value
            ));
            Ok(LlvmValue {
                value: out,
                ty: then_value.ty,
            })
        })()),
        ast::Expr::ObjectLiteral(fields) => Some((|| {
            let map_symbol = native_mangle_symbol(
                native_runtime_import_for_callee("map.new")
                    .expect("map.new runtime import must exist")
                    .symbol,
            );
            let set_symbol = native_mangle_symbol(
                native_runtime_import_for_callee("map.set")
                    .expect("map.set runtime import must exist")
                    .symbol,
            );
            let map_handle = ctx.value();
            ctx.code
                .push_str(&format!("  {map_handle} = call i32 @{map_symbol}()\n"));
            for (key, value) in fields {
                let key_id = string_literal_ids.get(key).copied().unwrap_or(0);
                let rendered = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                let rendered = llvm_cast_value(ctx, rendered, "i32")?;
                let status = ctx.value();
                ctx.code.push_str(&format!(
                    "  {status} = call i32 @{set_symbol}(i32 {map_handle}, i32 {key_id}, i32 {})\n",
                    rendered.value
                ));
            }
            Ok(LlvmValue {
                value: map_handle,
                ty: "i32".to_string(),
            })
        })()),
        ast::Expr::Index { base, index } => Some((|| {
            let index_value = if let Some((base_name, offset)) =
                canonicalize_array_index_window(index)
            {
                if let Some(slot) = ctx.slots.get(&base_name).cloned() {
                    let base_loaded = ctx.value();
                    ctx.code
                        .push_str(&format!("  {base_loaded} = load i32, ptr {slot}\n"));
                    if offset == 0 {
                        base_loaded
                    } else {
                        let adjusted = ctx.value();
                        let op = if offset >= 0 { "add" } else { "sub" };
                        let rhs = offset.unsigned_abs();
                        ctx.code
                            .push_str(&format!("  {adjusted} = {op} i32 {base_loaded}, {rhs}\n"));
                        adjusted
                    }
                } else {
                    llvm_emit_expr_as(index, ctx, string_literal_ids, task_ref_ids, "i32")?.value
                }
            } else {
                llvm_emit_expr_as(index, ctx, string_literal_ids, task_ref_ids, "i32")?.value
            };
            if let Some(kind) = llvm_vec_element_type(base, ctx) {
                let base_handle = llvm_emit_expr_as(
                    base,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                    llvm_pointer_int_type(),
                )?;
                let (helper, ret_ty) = match kind {
                    "f32" => (NATIVE_VEC_GET_F32_SYMBOL, "float"),
                    "i32" => (NATIVE_VEC_GET_I32_SYMBOL, "i32"),
                    "u32" => (NATIVE_VEC_GET_U32_SYMBOL, "i32"),
                    _ => unreachable!("unsupported native vec element kind"),
                };
                let val = ctx.value();
                let helper = native_mangle_symbol(helper);
                ctx.code.push_str(&format!(
                    "  {val} = call {ret_ty} @{helper}({} {}, i32 {index_value})\n",
                    base_handle.ty, base_handle.value
                ));
                return Ok(LlvmValue {
                    value: val,
                    ty: ret_ty.to_string(),
                });
            }
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(binding) = ctx.array_slots.get(name).cloned() {
                    return llvm_emit_array_index_from_binding(binding, index, &index_value, ctx);
                }
            }
            if let Some(element_ty) = llvm_ptr_element_type(base, ctx) {
                let base_ptr = llvm_emit_expr_as(
                    base,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                    llvm_pointer_int_type(),
                )?;
                let base_ptr = if base_ptr.ty == "ptr" {
                    base_ptr.value
                } else {
                    let ptr = ctx.value();
                    ctx.code.push_str(&format!(
                        "  {ptr} = inttoptr {} {} to ptr\n",
                        base_ptr.ty, base_ptr.value
                    ));
                    ptr
                };
                let index_ptr = if llvm_pointer_int_type() == "i32" {
                    index_value.clone()
                } else {
                    let widened = ctx.value();
                    ctx.code.push_str(&format!(
                        "  {widened} = sext i32 {index_value} to {}\n",
                        llvm_pointer_int_type()
                    ));
                    widened
                };
                let element_ptr = ctx.value();
                let loaded = ctx.value();
                ctx.code.push_str(&format!(
                    "  {element_ptr} = getelementptr inbounds {element_ty}, ptr {base_ptr}, {} {index_ptr}\n  {loaded} = load {element_ty}, ptr {element_ptr}\n",
                    llvm_pointer_int_type()
                ));
                return Ok(LlvmValue {
                    value: loaded,
                    ty: element_ty,
                });
            }
            let base_value = llvm_emit_expr(base, ctx, string_literal_ids, task_ref_ids)?;
            let temp_array_slot = format!("%slot_array_index_{}", ctx.next_value);
            ctx.next_value += 1;
            if let Some(binding) = llvm_array_binding_from_ir_type(&temp_array_slot, &base_value.ty)
            {
                ctx.declare_alloca(&binding.storage, &base_value.ty);
                ctx.code.push_str(&format!(
                    "  store {} {}, ptr {}\n",
                    base_value.ty, base_value.value, binding.storage
                ));
                return llvm_emit_array_index_from_binding(binding, index, &index_value, ctx);
            }
            Ok(base_value)
        })()),
        ast::Expr::Call { callee, args } => Some((|| {
            if let Some(value) = eval_const_i32_call(callee, args, &ctx.const_strings) {
                return Ok(LlvmValue {
                    value: value.to_string(),
                    ty: "i32".to_string(),
                });
            }
            if let Some(value) = eval_const_string_call(callee, args, &ctx.const_strings) {
                if let Some(id) = string_literal_ids.get(&value).copied() {
                    return Ok(LlvmValue {
                        value: id.to_string(),
                        ty: "i32".to_string(),
                    });
                }
            }
            if let Some(value) =
                llvm_emit_simd_intrinsic_call(callee, args, ctx, string_literal_ids, task_ref_ids)?
            {
                return Ok(value);
            }
            if callee == "str.concat" && args.len() >= 2 {
                let mut acc = llvm_emit_expr(&args[0], ctx, string_literal_ids, task_ref_ids)?;
                for arg in args.iter().skip(1) {
                    let rhs =
                        llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, &acc.ty)?;
                    let symbol = ctx
                        .extern_link_symbols
                        .get("str.concat")
                        .map(|value| value.as_str())
                        .unwrap_or("fz_native_str_concat2");
                    let symbol = native_mangle_symbol(symbol);
                    let val = ctx.value();
                    ctx.code.push_str(&format!(
                        "  {val} = call {} @{symbol}({} {}, {} {})\n",
                        acc.ty, acc.ty, acc.value, rhs.ty, rhs.value
                    ));
                    acc = LlvmValue {
                        value: val,
                        ty: acc.ty.clone(),
                    };
                }
                return llvm_assert_finite(ctx, acc);
            }
            if let Some(binding) = ctx.closures.get(callee).cloned() {
                return llvm_emit_inlined_closure_call(
                    binding,
                    args,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
            }
            if matches!(
                callee.as_str(),
                "gpu.upload_f32" | "gpu.upload_i32" | "gpu.upload_u32"
            ) {
                if args.len() != 2 {
                    bail!("llvm backend lowering expected 2 source args for `{callee}`");
                }
                let device =
                    llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, "i32")?;
                let Some((host_ptr, host_len)) = llvm_emit_array_argument_parts(
                    &args[1],
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                )?
                else {
                    bail!(
                        "llvm backend lowering for `{callee}` currently requires a host array literal or local array binding until general slice ABI lowering lands"
                    );
                };
                let symbol = native_mangle_symbol(
                    native_runtime_import_for_callee(callee)
                        .expect("gpu upload runtime import should exist")
                        .symbol,
                );
                let host_ptr_value = if host_ptr.ty == "ptr" {
                    let cast = ctx.value();
                    ctx.code.push_str(&format!(
                        "  {cast} = ptrtoint ptr {} to {}\n",
                        host_ptr.value,
                        llvm_pointer_int_type()
                    ));
                    cast
                } else {
                    host_ptr.value.clone()
                };
                let val = ctx.value();
                ctx.code.push_str(&format!(
                    "  {val} = call i32 @{symbol}(i32 {}, {} {}, i32 {})\n",
                    device.value,
                    llvm_pointer_int_type(),
                    host_ptr_value,
                    host_len.value
                ));
                return Ok(LlvmValue {
                    value: val,
                    ty: "i32".to_string(),
                });
            }
            if matches!(
                callee.as_str(),
                "gpu.launch0" | "gpu.launch1" | "gpu.launch2" | "gpu.launch3" | "gpu.launch4"
            ) {
                if args.len() < 3 {
                    bail!("llvm backend lowering expected kernel/grid/block args for `{callee}`");
                }
                let ast::Expr::Ident(kernel_name) = &args[0] else {
                    bail!("llvm backend lowering for `{callee}` requires a direct kernel function name");
                };
                let descriptor = ctx
                    .gpu_kernel_launch_descriptors
                    .get(kernel_name)
                    .ok_or_else(|| {
                        anyhow!("missing Metal kernel launch descriptor for `{kernel_name}`")
                    })?
                    .clone();
                let symbol = native_mangle_symbol(
                    native_runtime_import_for_callee(callee)
                        .expect("gpu launch runtime import should exist")
                        .symbol,
                );
                let kernel_id = string_literal_ids
                    .get(&descriptor.kernel_name)
                    .copied()
                    .ok_or_else(|| {
                        anyhow!("missing native string literal id for kernel `{kernel_name}`")
                    })?;
                let source_id = string_literal_ids
                    .get(&descriptor.source)
                    .copied()
                    .ok_or_else(|| {
                        anyhow!("missing native string literal id for Metal source `{kernel_name}`")
                    })?;
                let layout_id = string_literal_ids
                    .get(&descriptor.param_layout)
                    .copied()
                    .ok_or_else(|| anyhow!("missing native string literal id for Metal launch layout `{kernel_name}`"))?;
                let grid =
                    llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, "i32")?;
                let block =
                    llvm_emit_expr_as(&args[2], ctx, string_literal_ids, task_ref_ids, "i32")?;
                let mut lowered_args = Vec::new();
                let layouts = descriptor
                    .param_layout
                    .split(',')
                    .map(str::trim)
                    .collect::<Vec<_>>();
                for (index, arg) in args.iter().skip(3).enumerate() {
                    let lowered = llvm_encode_gpu_launch_arg(
                        arg,
                        layouts.get(index).copied().unwrap_or("unknown"),
                        ctx,
                        string_literal_ids,
                        task_ref_ids,
                    )?;
                    lowered_args.push(format!("{} {}", lowered.ty, lowered.value));
                }
                let val = ctx.value();
                let mut rendered = vec![
                    format!("i32 {kernel_id}"),
                    format!("i32 {source_id}"),
                    format!("i32 {layout_id}"),
                    format!("i32 {}", grid.value),
                    format!("i32 {}", block.value),
                ];
                rendered.extend(lowered_args);
                ctx.code.push_str(&format!(
                    "  {val} = call i32 @{symbol}({})\n",
                    rendered.join(", ")
                ));
                return Ok(LlvmValue {
                    value: val,
                    ty: "i32".to_string(),
                });
            }
            let signature = ctx.function_sigs.get(callee).cloned();
            let mut rendered_args = Vec::with_capacity(args.len());
            for (index, arg) in args.iter().enumerate() {
                let value = if signature
                    .as_ref()
                    .is_some_and(|sig| llvm_is_extern_c_borrowed_ptr_param(sig, index))
                    && llvm_expr_is_fzy_str(arg, ctx)
                {
                    llvm_emit_borrowed_str_ptr_arg(arg, ctx, string_literal_ids, task_ref_ids)?
                } else {
                    llvm_emit_expr(arg, ctx, string_literal_ids, task_ref_ids)?
                };
                let value = if let Some(sig) = &signature {
                    if let Some(target_ty) = sig.params.get(index) {
                        llvm_cast_value(ctx, value, target_ty)?
                    } else {
                        value
                    }
                } else {
                    llvm_cast_value(ctx, value, "i32")?
                };
                rendered_args.push(format!("{} {}", value.ty, value.value));
            }
            let args = rendered_args.join(", ");
            let symbol = native_runtime_import_for_callee(callee)
                .or_else(|| native_data_plane_import_for_callee(callee))
                .map(|import| import.symbol)
                .unwrap_or(callee.as_str());
            let symbol = ctx
                .extern_link_symbols
                .get(callee)
                .map(|value| value.as_str())
                .unwrap_or(symbol);
            let symbol = native_mangle_symbol(symbol);
            let return_ty = signature
                .and_then(|sig| sig.ret)
                .unwrap_or_else(|| "i32".to_string());
            if return_ty == "void" {
                ctx.code
                    .push_str(&format!("  call void @{symbol}({args})\n"));
                Ok(LlvmValue {
                    value: "0".to_string(),
                    ty: "i32".to_string(),
                })
            } else {
                let val = ctx.value();
                ctx.code
                    .push_str(&format!("  {val} = call {return_ty} @{symbol}({args})\n"));
                llvm_assert_finite(
                    ctx,
                    LlvmValue {
                        value: val,
                        ty: return_ty,
                    },
                )
            }
        })()),
        ast::Expr::UnsafeBlock { body, .. } => Some((|| {
            let terminated = llvm_emit_linear_stmts(body, ctx, string_literal_ids, task_ref_ids)?;
            if terminated {
                let continuation = ctx.label("unsafe.cont");
                ctx.code.push_str(&format!("{continuation}:\n"));
            }
            Ok(LlvmValue {
                value: "0".to_string(),
                ty: "i32".to_string(),
            })
        })()),
        _ => None,
    }
}
