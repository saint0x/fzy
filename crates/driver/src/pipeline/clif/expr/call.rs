use super::*;

pub(super) fn clif_emit_call_expr(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    callee: &str,
    args: &[ast::Expr],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    if let Some(value) = eval_const_i32_call(callee, args, &ctx.const_strings) {
        return Ok(ClifValue {
            value: builder.ins().iconst(default_int_clif_type(), value as i64),
            ty: default_int_clif_type(),
        });
    }
    if let Some(value) = eval_const_string_call(callee, args, &ctx.const_strings) {
        if let Some(id) = ctx.string_literal_ids.get(&value).copied() {
            return Ok(ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), id as i64),
                ty: default_int_clif_type(),
            });
        }
    }
    if let Some((kind, op)) = clif_parse_simd_intrinsic(callee) {
        return clif_emit_simd_intrinsic(builder, ctx, kind, op, args, locals, next_var);
    }
    if callee == "str.concat" && args.len() >= 2 {
        let function_id = ctx
            .function_ids
            .get("str.concat")
            .copied()
            .or_else(|| ctx.function_ids.get("str.concat2").copied())
            .ok_or_else(|| {
                anyhow!("missing native function signature metadata for `str.concat`")
            })?;
        let signature = ctx
            .function_signatures
            .get("str.concat")
            .or_else(|| ctx.function_signatures.get("str.concat2"))
            .ok_or_else(|| {
                anyhow!("missing native function signature metadata for `str.concat`")
            })?;
        let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
        let mut acc = clif_emit_expr(builder, ctx, &args[0], locals, next_var)?;
        if let Some(target) = signature.params.first().copied() {
            acc = cast_clif_value(builder, acc, target)?;
        }
        for arg in args.iter().skip(1) {
            let mut rhs = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
            if let Some(target) = signature.params.get(1).copied() {
                rhs = cast_clif_value(builder, rhs, target)?;
            }
            let call = builder.ins().call(func_ref, &[acc.value, rhs.value]);
            let value = builder.inst_results(call)[0];
            acc = clif_assert_finite(
                builder,
                ClifValue {
                    value,
                    ty: signature.ret.unwrap_or(default_int_clif_type()),
                },
            );
        }
        return Ok(acc);
    }
    if let Some(binding) = ctx.closures.get(callee).cloned() {
        return clif_emit_inlined_closure_call(builder, ctx, binding, args, locals, next_var);
    }

    let mut values = Vec::with_capacity(args.len());
    if let Some(function_id) = ctx.function_ids.get(callee).copied() {
        let signature = ctx
            .function_signatures
            .get(callee)
            .ok_or_else(|| anyhow!("missing native function signature metadata for `{callee}`"))?;
        if matches!(
            callee,
            "gpu.upload_f32" | "gpu.upload_i32" | "gpu.upload_u32"
        ) {
            if args.len() != 2 {
                bail!("native backend lowering expected 2 source args for `{callee}`");
            }
            let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
            let mut device = clif_emit_expr(builder, ctx, &args[0], locals, next_var)?;
            device = cast_clif_value(builder, device, types::I32)?;
            let Some((host_ptr, host_len)) =
                clif_emit_array_argument_parts(builder, ctx, &args[1], locals, next_var)?
            else {
                bail!(
                    "native backend lowering for `{callee}` currently requires a host array literal or local array binding until general slice ABI lowering lands"
                );
            };
            let call = builder
                .ins()
                .call(func_ref, &[device.value, host_ptr.value, host_len.value]);
            let value = builder.inst_results(call)[0];
            return Ok(ClifValue {
                value,
                ty: types::I32,
            });
        }
        if matches!(
            callee,
            "gpu.launch0" | "gpu.launch1" | "gpu.launch2" | "gpu.launch3" | "gpu.launch4"
        ) {
            if args.len() < 3 {
                bail!("native backend lowering expected kernel/grid/block args for `{callee}`");
            }
            let ast::Expr::Ident(kernel_name) = &args[0] else {
                bail!(
                    "native backend lowering for `{callee}` requires a direct kernel function name"
                );
            };
            let descriptor = ctx
                .gpu_kernel_launch_descriptors
                .get(kernel_name)
                .ok_or_else(|| {
                    anyhow!("missing GPU kernel launch descriptor for `{kernel_name}`")
                })?;
            let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
            let kernel_id = ctx
                .string_literal_ids
                .get(&descriptor.kernel_name)
                .copied()
                .ok_or_else(|| {
                    anyhow!("missing native string literal id for kernel `{kernel_name}`")
                })?;
            let source_id = ctx
                .string_literal_ids
                .get(&descriptor.source)
                .copied()
                .ok_or_else(|| {
                    anyhow!("missing native string literal id for GPU source `{kernel_name}`")
                })?;
            let layout_id = ctx
                .string_literal_ids
                .get(&descriptor.param_layout)
                .copied()
                .ok_or_else(|| {
                    anyhow!(
                        "missing native string literal id for GPU launch layout `{kernel_name}`"
                    )
                })?;
            let mut grid = clif_emit_expr(builder, ctx, &args[1], locals, next_var)?;
            grid = cast_clif_value(builder, grid, types::I32)?;
            let mut block = clif_emit_expr(builder, ctx, &args[2], locals, next_var)?;
            block = cast_clif_value(builder, block, types::I32)?;
            let mut values = vec![
                builder.ins().iconst(types::I32, i64::from(kernel_id)),
                builder.ins().iconst(types::I32, i64::from(source_id)),
                builder.ins().iconst(types::I32, i64::from(layout_id)),
                grid.value,
                block.value,
            ];
            let layouts = descriptor
                .param_layout
                .split(',')
                .map(str::trim)
                .collect::<Vec<_>>();
            for (index, arg) in args.iter().skip(3).enumerate() {
                let lowered = clif_encode_gpu_launch_arg(
                    builder,
                    ctx,
                    arg,
                    layouts.get(index).copied().unwrap_or("unknown"),
                    locals,
                    next_var,
                )?;
                values.push(lowered.value);
            }
            let call = builder.ins().call(func_ref, &values);
            let value = builder.inst_results(call)[0];
            return Ok(ClifValue {
                value,
                ty: types::I32,
            });
        }
        if let Some(sret) = signature.sret {
            let stack_slot = clif_create_stack_slot_for_array_abi(builder, sret);
            let result_ptr = builder
                .ins()
                .stack_addr(pointer_sized_clif_type(), stack_slot, 0);
            values.push(result_ptr);
            for (index, arg) in args.iter().enumerate() {
                let target = signature.params.get(index + 1).copied();
                let mut lowered = if clif_is_extern_c_borrowed_ptr_param(signature, index)
                    && clif_expr_is_fzy_str(arg, ctx)
                {
                    clif_emit_borrowed_str_ptr_arg(builder, ctx, arg, locals, next_var)?
                } else if target == Some(pointer_sized_clif_type()) {
                    if let Some(array_ptr) =
                        clif_emit_array_argument_pointer(builder, ctx, arg, locals, next_var)?
                    {
                        array_ptr
                    } else {
                        clif_emit_expr(builder, ctx, arg, locals, next_var)?
                    }
                } else {
                    clif_emit_expr(builder, ctx, arg, locals, next_var)?
                };
                if let Some(target) = target {
                    lowered = cast_clif_value(builder, lowered, target)?;
                }
                values.push(lowered.value);
            }
            let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
            let _ = builder.ins().call(func_ref, &values);
            return Ok(ClifValue {
                value: result_ptr,
                ty: pointer_sized_clif_type(),
            });
        }
        for (index, arg) in args.iter().enumerate() {
            let target = signature.params.get(index).copied();
            let mut lowered = if clif_is_extern_c_borrowed_ptr_param(signature, index)
                && clif_expr_is_fzy_str(arg, ctx)
            {
                clif_emit_borrowed_str_ptr_arg(builder, ctx, arg, locals, next_var)?
            } else if target == Some(pointer_sized_clif_type()) {
                if let Some(array_ptr) =
                    clif_emit_array_argument_pointer(builder, ctx, arg, locals, next_var)?
                {
                    array_ptr
                } else {
                    clif_emit_expr(builder, ctx, arg, locals, next_var)?
                }
            } else {
                clif_emit_expr(builder, ctx, arg, locals, next_var)?
            };
            if let Some(target) = target {
                lowered = cast_clif_value(builder, lowered, target)?;
            }
            values.push(lowered.value);
        }
        let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
        let call = builder.ins().call(func_ref, &values);
        if let Some(value) = builder.inst_results(call).first().copied() {
            Ok(clif_assert_finite(
                builder,
                ClifValue {
                    value,
                    ty: signature.ret.unwrap_or(default_int_clif_type()),
                },
            ))
        } else {
            Ok(ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            })
        }
    } else {
        for arg in args {
            let _ = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
        }
        Err(anyhow!(
            "native backend cannot lower unresolved call target `{}`",
            callee
        ))
    }
}
