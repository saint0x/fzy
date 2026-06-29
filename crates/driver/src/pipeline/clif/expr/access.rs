use super::*;

pub(super) fn clif_emit_field_expr(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    expr: &ast::Expr,
    base: &ast::Expr,
    field: &str,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    if let Some(value) =
        resolve_native_global_const_i32_expr(expr, ctx.current_namespace, ctx.globals)
    {
        return Ok(ClifValue {
            value: builder.ins().iconst(default_int_clif_type(), value as i64),
            ty: default_int_clif_type(),
        });
    }
    if let Some(field_expr) = resolve_field_expr(base, field) {
        return clif_emit_expr(builder, ctx, &field_expr, locals, next_var);
    }
    if let Some(task_ref_name) = expr_task_ref_name(expr) {
        if let Some(task_ref) = ctx.task_ref_ids.get(&task_ref_name).copied() {
            return Ok(ClifValue {
                value: builder
                    .ins()
                    .iconst(default_int_clif_type(), task_ref as i64),
                ty: default_int_clif_type(),
            });
        }
    }
    Ok(if let ast::Expr::Ident(name) = base {
        if let Some(binding) = locals.get(&format!("{name}.{field}")).copied() {
            ClifValue {
                value: builder.use_var(binding.var),
                ty: binding.ty,
            }
        } else if let Some(binding) = ctx.aggregate_bindings.get(name).cloned() {
            if let Some(item) = binding.items.get(field) {
                let handle = clif_emit_expr(builder, ctx, base, locals, next_var)?;
                return clif_emit_aggregate_get(builder, ctx, handle, item.index, item.ty);
            } else {
                clif_emit_expr(builder, ctx, base, locals, next_var)?
            }
        } else if let Some(item) = clif_struct_field_binding_for_local(name, field, ctx) {
            let handle = clif_emit_expr(builder, ctx, base, locals, next_var)?;
            return clif_emit_aggregate_get(builder, ctx, handle, item.index, item.ty);
        } else {
            clif_emit_expr(builder, ctx, base, locals, next_var)?
        }
    } else {
        clif_emit_expr(builder, ctx, base, locals, next_var)?
    })
}

pub(super) fn clif_emit_index_expr(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    base: &ast::Expr,
    index: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let index_value = if let Some((base_name, offset)) = canonicalize_array_index_window(index) {
        if let Some(binding) = locals.get(&base_name).copied() {
            let base_raw = builder.use_var(binding.var);
            let base = cast_clif_value(
                builder,
                ClifValue {
                    value: base_raw,
                    ty: binding.ty,
                },
                default_int_clif_type(),
            )?
            .value;
            let value = if offset == 0 {
                base
            } else {
                builder.ins().iadd_imm(base, i64::from(offset))
            };
            ClifValue {
                value,
                ty: default_int_clif_type(),
            }
        } else {
            let value = clif_emit_expr(builder, ctx, index, locals, next_var)?;
            cast_clif_value(builder, value, default_int_clif_type())?
        }
    } else {
        let value = clif_emit_expr(builder, ctx, index, locals, next_var)?;
        cast_clif_value(builder, value, default_int_clif_type())?
    };
    if let Some(kind) = clif_vec_element_type(base, ctx) {
        let helper_name = match kind {
            "f32" => NATIVE_VEC_GET_F32,
            "i32" => NATIVE_VEC_GET_I32,
            "u32" => NATIVE_VEC_GET_U32,
            _ => unreachable!("unsupported native vec element kind"),
        };
        let helper_id = ctx.function_ids.get(helper_name).copied().ok_or_else(|| {
            anyhow!("missing native helper signature metadata for `{helper_name}`")
        })?;
        let helper_sig = ctx.function_signatures.get(helper_name).ok_or_else(|| {
            anyhow!("missing native helper signature metadata for `{helper_name}`")
        })?;
        let base_handle = clif_emit_expr(builder, ctx, base, locals, next_var)?;
        let base_handle = cast_clif_value(builder, base_handle, pointer_sized_clif_type())?;
        let func_ref = ctx.module.declare_func_in_func(helper_id, builder.func);
        let call = builder
            .ins()
            .call(func_ref, &[base_handle.value, index_value.value]);
        let value = builder.inst_results(call)[0];
        return Ok(ClifValue {
            value,
            ty: helper_sig.ret.unwrap_or(default_int_clif_type()),
        });
    }
    if let Some(element_ty) = clif_ptr_element_type(base, ctx) {
        let base_ptr = clif_emit_expr(builder, ctx, base, locals, next_var)?;
        let base_ptr = cast_clif_value(builder, base_ptr, pointer_sized_clif_type())?;
        let idx_ptr = if pointer_sized_clif_type() == index_value.ty {
            index_value.value
        } else {
            builder
                .ins()
                .uextend(pointer_sized_clif_type(), index_value.value)
        };
        let bytes = u32::from(element_ty.bytes());
        let addr = if bytes == 1 {
            builder.ins().iadd(base_ptr.value, idx_ptr)
        } else {
            let byte_offset = builder.ins().imul_imm(idx_ptr, i64::from(bytes));
            builder.ins().iadd(base_ptr.value, byte_offset)
        };
        let loaded = builder.ins().load(element_ty, MemFlags::new(), addr, 0);
        return Ok(ClifValue {
            value: loaded,
            ty: element_ty,
        });
    }
    if let ast::Expr::Ident(name) = base {
        if let Some(binding) = ctx.array_bindings.get(name) {
            if binding.len == 0 {
                return Ok(ClifValue {
                    value: builder.ins().iconst(binding.element_ty, 0),
                    ty: binding.element_ty,
                });
            }
            if let Some(const_idx) = eval_const_i32_expr(index, &ctx.const_strings) {
                if const_idx >= 0 && (const_idx as usize) < binding.len {
                    let ptr = builder.ins().stack_addr(
                        pointer_sized_clif_type(),
                        binding.stack_slot,
                        const_idx * i32::from(binding.element_stride),
                    );
                    let loaded = builder
                        .ins()
                        .load(binding.element_ty, MemFlags::new(), ptr, 0);
                    return Ok(ClifValue {
                        value: loaded,
                        ty: binding.element_ty,
                    });
                }
            }
            let in_block = builder.create_block();
            let out_block = builder.create_block();
            let merge_block = builder.create_block();
            builder.append_block_param(merge_block, binding.element_ty);

            let zero = builder.ins().iconst(default_int_clif_type(), 0);
            let len_const = builder
                .ins()
                .iconst(default_int_clif_type(), binding.len as i64);
            let nonneg =
                builder
                    .ins()
                    .icmp(IntCC::SignedGreaterThanOrEqual, index_value.value, zero);
            let below_len = builder
                .ins()
                .icmp(IntCC::SignedLessThan, index_value.value, len_const);
            let in_range = builder.ins().band(nonneg, below_len);
            builder.ins().brif(in_range, in_block, &[], out_block, &[]);

            builder.switch_to_block(in_block);
            let base_ptr =
                builder
                    .ins()
                    .stack_addr(pointer_sized_clif_type(), binding.stack_slot, 0);
            let idx_ptr = if pointer_sized_clif_type() == default_int_clif_type() {
                index_value.value
            } else {
                builder
                    .ins()
                    .uextend(pointer_sized_clif_type(), index_value.value)
            };
            let byte_offset = builder
                .ins()
                .imul_imm(idx_ptr, i64::from(binding.element_stride));
            let addr = builder.ins().iadd(base_ptr, byte_offset);
            let loaded = builder
                .ins()
                .load(binding.element_ty, MemFlags::new(), addr, 0);
            builder.ins().jump(merge_block, &[loaded]);

            builder.switch_to_block(out_block);
            let zero_default = zero_for_type(builder, binding.element_ty);
            builder.ins().jump(merge_block, &[zero_default]);

            builder.seal_block(in_block);
            builder.seal_block(out_block);
            builder.switch_to_block(merge_block);
            builder.seal_block(merge_block);
            let selected = builder.block_params(merge_block)[0];
            let _ = (
                binding.element_bits,
                binding.element_align,
                binding.element_stride,
            );
            return Ok(ClifValue {
                value: selected,
                ty: binding.element_ty,
            });
        }
        if let Some(ast::Type::Array { elem, len }) = clif_local_type(ctx, name) {
            if let Some(ptr_binding) = locals.get(name).copied() {
                let element_ty = ast_signature_type_to_clif_type(elem.as_ref())
                    .ok_or_else(|| anyhow!("unsupported array element type for `{name}`"))?;
                let element_stride = if element_ty == types::I8 {
                    1
                } else if element_ty == types::I16 {
                    2
                } else if element_ty == types::I64 || element_ty == types::F64 {
                    8
                } else {
                    4
                };
                if *len == 0 {
                    return Ok(ClifValue {
                        value: builder.ins().iconst(element_ty, 0),
                        ty: element_ty,
                    });
                }
                if let Some(const_idx) = eval_const_i32_expr(index, &ctx.const_strings) {
                    if const_idx >= 0 && (const_idx as usize) < *len {
                        let base_ptr = builder.use_var(ptr_binding.var);
                        let addr = if const_idx == 0 {
                            base_ptr
                        } else {
                            builder.ins().iadd_imm(
                                base_ptr,
                                i64::from(const_idx * i32::from(element_stride)),
                            )
                        };
                        let loaded = builder.ins().load(element_ty, MemFlags::new(), addr, 0);
                        return Ok(ClifValue {
                            value: loaded,
                            ty: element_ty,
                        });
                    }
                }
                let in_block = builder.create_block();
                let out_block = builder.create_block();
                let merge_block = builder.create_block();
                builder.append_block_param(merge_block, element_ty);

                let zero = builder.ins().iconst(default_int_clif_type(), 0);
                let len_const = builder.ins().iconst(default_int_clif_type(), *len as i64);
                let nonneg =
                    builder
                        .ins()
                        .icmp(IntCC::SignedGreaterThanOrEqual, index_value.value, zero);
                let below_len =
                    builder
                        .ins()
                        .icmp(IntCC::SignedLessThan, index_value.value, len_const);
                let in_range = builder.ins().band(nonneg, below_len);
                builder.ins().brif(in_range, in_block, &[], out_block, &[]);

                builder.switch_to_block(in_block);
                let base_ptr = builder.use_var(ptr_binding.var);
                let idx_ptr = if pointer_sized_clif_type() == default_int_clif_type() {
                    index_value.value
                } else {
                    builder
                        .ins()
                        .uextend(pointer_sized_clif_type(), index_value.value)
                };
                let byte_offset = builder.ins().imul_imm(idx_ptr, i64::from(element_stride));
                let addr = builder.ins().iadd(base_ptr, byte_offset);
                let loaded = builder.ins().load(element_ty, MemFlags::new(), addr, 0);
                builder.ins().jump(merge_block, &[loaded]);

                builder.switch_to_block(out_block);
                let zero_default = zero_for_type(builder, element_ty);
                builder.ins().jump(merge_block, &[zero_default]);

                builder.seal_block(in_block);
                builder.seal_block(out_block);
                builder.switch_to_block(merge_block);
                builder.seal_block(merge_block);
                return Ok(ClifValue {
                    value: builder.block_params(merge_block)[0],
                    ty: element_ty,
                });
            }
        }
    }
    clif_emit_expr(builder, ctx, base, locals, next_var)
}
