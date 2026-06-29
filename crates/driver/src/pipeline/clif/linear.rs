use super::*;

pub(crate) fn clif_emit_linear_stmts(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    body: &[ast::Stmt],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<bool> {
    let mut deferred = Vec::<ast::Expr>::new();
    for stmt in body {
        match stmt {
            ast::Stmt::Let {
                name, value, ty, ..
            } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(name.clone(), const_value);
                    ctx.array_bindings.remove(name);
                    ctx.aggregate_bindings.remove(name);
                }
                if let ast::Expr::Call { callee, args } = value {
                    if let Some(kind) = clif_parse_simd_store_wrapper(callee) {
                        if let Some(vector_expr) = args.first() {
                            clif_materialize_simd_store_binding(
                                builder,
                                ctx,
                                name,
                                kind,
                                vector_expr,
                                locals,
                                next_var,
                            )?;
                            continue;
                        }
                    }
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let mut lowered_items = Vec::with_capacity(items.len());
                    for item in items {
                        lowered_items.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
                    }
                    let (element_ty, element_bits, element_align, element_stride) =
                        clif_array_layout_from_values(&lowered_items);
                    let slot_size = (lowered_items.len() as u32) * u32::from(element_stride);
                    let align_shift = element_align.trailing_zeros() as u8;
                    let stack_slot =
                        builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                            cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                            slot_size,
                            align_shift,
                        ));
                    for (idx, mut item_val) in lowered_items.into_iter().enumerate() {
                        item_val = cast_clif_value(builder, item_val, element_ty)?;
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            stack_slot,
                            (idx as i32) * i32::from(element_stride),
                        );
                        builder.ins().store(MemFlags::new(), item_val.value, ptr, 0);
                    }
                    ctx.array_bindings.insert(
                        name.clone(),
                        ClifArrayBinding {
                            stack_slot,
                            len: items.len(),
                            element_ty,
                            element_bits,
                            element_align,
                            element_stride,
                        },
                    );
                    let ptr = builder
                        .ins()
                        .stack_addr(pointer_sized_clif_type(), stack_slot, 0);
                    clif_bind_local(
                        builder,
                        locals,
                        next_var,
                        name,
                        pointer_sized_clif_type(),
                        ptr,
                    );
                    ctx.aggregate_bindings.remove(name);
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_ty) = clif_local_type(ctx, source).cloned() {
                        ctx.derived_local_types.insert(name.clone(), source_ty);
                    }
                    if let Some(binding) = ctx.aggregate_bindings.get(source).cloned() {
                        ctx.aggregate_bindings.insert(name.clone(), binding);
                    }
                    if let Some(source_bindings) = ctx.array_bindings.get(source).cloned() {
                        ctx.array_bindings.insert(name.clone(), source_bindings);
                        if let Some(binding) = locals.get(source).copied() {
                            locals.insert(name.clone(), binding);
                        }
                        continue;
                    }
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    ctx.closures.insert(
                        name.clone(),
                        ClifClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures: clif_snapshot_closure_captures(builder, locals, next_var),
                        },
                    );
                    ctx.aggregate_bindings.remove(name);
                    continue;
                }
                let mut val = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                let target_ty = ty
                    .as_ref()
                    .and_then(ast_signature_type_to_clif_type)
                    .unwrap_or(val.ty);
                val = cast_clif_value(builder, val, target_ty)?;
                let binding = if let Some(existing) = locals.get(name).copied() {
                    existing
                } else {
                    let var = Variable::from_u32(*next_var as u32);
                    *next_var += 1;
                    builder.declare_var(var, target_ty);
                    let binding = LocalBinding { var, ty: target_ty };
                    locals.insert(name.clone(), binding);
                    binding
                };
                let val = cast_clif_value(builder, val, binding.ty)?;
                builder.def_var(binding.var, val.value);
                clif_record_aggregate_binding(builder, ctx, name, value, locals, next_var)?;
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_val = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, field_val.ty);
                        builder.def_var(field_var, field_val.value);
                        locals.insert(
                            format!("{name}.{field}"),
                            LocalBinding {
                                var: field_var,
                                ty: field_val.ty,
                            },
                        );
                    }
                }
                if let ast::Expr::Tuple(items) = value {
                    for (index, item_expr) in items.iter().enumerate() {
                        let item_val = clif_emit_expr(builder, ctx, item_expr, locals, next_var)?;
                        let item_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(item_var, item_val.ty);
                        builder.def_var(item_var, item_val.value);
                        locals.insert(
                            format!("{name}.__tuple{index}"),
                            LocalBinding {
                                var: item_var,
                                ty: item_val.ty,
                            },
                        );
                    }
                }
                if let ast::Expr::EnumInit {
                    enum_name: _,
                    variant: _,
                    payload,
                    named_payload,
                } = value
                {
                    for (index, payload_expr) in payload.iter().enumerate() {
                        let payload_val =
                            clif_emit_expr(builder, ctx, payload_expr, locals, next_var)?;
                        let payload_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(payload_var, payload_val.ty);
                        builder.def_var(payload_var, payload_val.value);
                        locals.insert(
                            format!("{name}.__payload{index}"),
                            LocalBinding {
                                var: payload_var,
                                ty: payload_val.ty,
                            },
                        );
                    }
                    for (field, field_expr) in named_payload {
                        let field_val = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, field_val.ty);
                        builder.def_var(field_var, field_val.value);
                        locals.insert(
                            format!("{name}.{field}"),
                            LocalBinding {
                                var: field_var,
                                ty: field_val.ty,
                            },
                        );
                    }
                }
                if let ast::Expr::Range {
                    start,
                    end,
                    inclusive,
                } = value
                {
                    let start_val = clif_emit_expr(builder, ctx, start, locals, next_var)?;
                    let end_val = clif_emit_expr(builder, ctx, end, locals, next_var)?;
                    let inclusive_val = ClifValue {
                        value: builder
                            .ins()
                            .iconst(default_int_clif_type(), i64::from(*inclusive)),
                        ty: default_int_clif_type(),
                    };
                    for (field, field_val) in [
                        ("start", start_val),
                        ("end", end_val),
                        ("inclusive", inclusive_val),
                    ] {
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, field_val.ty);
                        builder.def_var(field_var, field_val.value);
                        locals.insert(
                            format!("{name}.{field}"),
                            LocalBinding {
                                var: field_var,
                                ty: field_val.ty,
                            },
                        );
                    }
                }
                ctx.array_bindings.remove(name);
                ctx.const_strings.remove(name);
                ctx.closures.remove(name);
            }
            ast::Stmt::LetPattern { pattern, value, .. } => {
                clif_emit_let_pattern(builder, ctx, pattern, value, locals, next_var)?;
            }
            ast::Stmt::Assign { target, value } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(target.clone(), const_value);
                    ctx.array_bindings.remove(target);
                    ctx.aggregate_bindings.remove(target);
                }
                if let ast::Expr::Call { callee, args } = value {
                    if let Some(kind) = clif_parse_simd_store_wrapper(callee) {
                        if let Some(vector_expr) = args.first() {
                            clif_materialize_simd_store_binding(
                                builder,
                                ctx,
                                target,
                                kind,
                                vector_expr,
                                locals,
                                next_var,
                            )?;
                            continue;
                        }
                    }
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    ctx.closures.insert(
                        target.clone(),
                        ClifClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures: clif_snapshot_closure_captures(builder, locals, next_var),
                        },
                    );
                    ctx.aggregate_bindings.remove(target);
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let mut lowered_items = Vec::with_capacity(items.len());
                    for item in items {
                        lowered_items.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
                    }
                    let (element_ty, element_bits, element_align, element_stride) =
                        clif_array_layout_from_values(&lowered_items);
                    let slot_size = (lowered_items.len() as u32) * u32::from(element_stride);
                    let align_shift = element_align.trailing_zeros() as u8;
                    let stack_slot =
                        builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                            cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                            slot_size,
                            align_shift,
                        ));
                    for (idx, mut item_val) in lowered_items.into_iter().enumerate() {
                        item_val = cast_clif_value(builder, item_val, element_ty)?;
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            stack_slot,
                            (idx as i32) * i32::from(element_stride),
                        );
                        builder.ins().store(MemFlags::new(), item_val.value, ptr, 0);
                    }
                    ctx.array_bindings.insert(
                        target.clone(),
                        ClifArrayBinding {
                            stack_slot,
                            len: items.len(),
                            element_ty,
                            element_bits,
                            element_align,
                            element_stride,
                        },
                    );
                    let ptr = builder
                        .ins()
                        .stack_addr(pointer_sized_clif_type(), stack_slot, 0);
                    clif_bind_local(
                        builder,
                        locals,
                        next_var,
                        target,
                        pointer_sized_clif_type(),
                        ptr,
                    );
                    ctx.aggregate_bindings.remove(target);
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_ty) = clif_local_type(ctx, source).cloned() {
                        ctx.derived_local_types.insert(target.clone(), source_ty);
                    }
                    if let Some(binding) = ctx.aggregate_bindings.get(source).cloned() {
                        ctx.aggregate_bindings.insert(target.clone(), binding);
                    }
                    if let Some(source_bindings) = ctx.array_bindings.get(source).cloned() {
                        ctx.array_bindings.insert(target.clone(), source_bindings);
                        if let Some(binding) = locals.get(source).copied() {
                            locals.insert(target.clone(), binding);
                        }
                        continue;
                    }
                }
                let val = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                if let Some(data_id) = ctx.mutable_globals.get(target).copied() {
                    let val = cast_clif_value(builder, val, types::I32)?;
                    let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                    let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                    builder.ins().store(MemFlags::new(), val.value, ptr, 0);
                } else {
                    let binding = if let Some(existing) = locals.get(target).copied() {
                        existing
                    } else {
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, val.ty);
                        let binding = LocalBinding { var, ty: val.ty };
                        locals.insert(target.clone(), binding);
                        binding
                    };
                    let val = cast_clif_value(builder, val, binding.ty)?;
                    builder.def_var(binding.var, val.value);
                    clif_record_aggregate_binding(builder, ctx, target, value, locals, next_var)?;
                    if let ast::Expr::StructInit { fields, .. } = value {
                        for (field, field_expr) in fields {
                            let field_val =
                                clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                            let field_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(field_var, field_val.ty);
                            builder.def_var(field_var, field_val.value);
                            locals.insert(
                                format!("{target}.{field}"),
                                LocalBinding {
                                    var: field_var,
                                    ty: field_val.ty,
                                },
                            );
                        }
                    }
                    if let ast::Expr::Tuple(items) = value {
                        for (index, item_expr) in items.iter().enumerate() {
                            let item_val =
                                clif_emit_expr(builder, ctx, item_expr, locals, next_var)?;
                            let item_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(item_var, item_val.ty);
                            builder.def_var(item_var, item_val.value);
                            locals.insert(
                                format!("{target}.__tuple{index}"),
                                LocalBinding {
                                    var: item_var,
                                    ty: item_val.ty,
                                },
                            );
                        }
                    }
                    if let ast::Expr::EnumInit {
                        enum_name: _,
                        variant: _,
                        payload,
                        named_payload,
                    } = value
                    {
                        for (index, payload_expr) in payload.iter().enumerate() {
                            let payload_val =
                                clif_emit_expr(builder, ctx, payload_expr, locals, next_var)?;
                            let payload_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(payload_var, payload_val.ty);
                            builder.def_var(payload_var, payload_val.value);
                            locals.insert(
                                format!("{target}.__payload{index}"),
                                LocalBinding {
                                    var: payload_var,
                                    ty: payload_val.ty,
                                },
                            );
                        }
                        for (field, field_expr) in named_payload {
                            let field_val =
                                clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                            let field_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(field_var, field_val.ty);
                            builder.def_var(field_var, field_val.value);
                            locals.insert(
                                format!("{target}.{field}"),
                                LocalBinding {
                                    var: field_var,
                                    ty: field_val.ty,
                                },
                            );
                        }
                    }
                    if let ast::Expr::Range {
                        start,
                        end,
                        inclusive,
                    } = value
                    {
                        let start_val = clif_emit_expr(builder, ctx, start, locals, next_var)?;
                        let end_val = clif_emit_expr(builder, ctx, end, locals, next_var)?;
                        let inclusive_val = ClifValue {
                            value: builder
                                .ins()
                                .iconst(default_int_clif_type(), i64::from(*inclusive)),
                            ty: default_int_clif_type(),
                        };
                        for (field, field_val) in [
                            ("start", start_val),
                            ("end", end_val),
                            ("inclusive", inclusive_val),
                        ] {
                            let field_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(field_var, field_val.ty);
                            builder.def_var(field_var, field_val.value);
                            locals.insert(
                                format!("{target}.{field}"),
                                LocalBinding {
                                    var: field_var,
                                    ty: field_val.ty,
                                },
                            );
                        }
                    }
                }
                ctx.array_bindings.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::CompoundAssign { target, op, value } => {
                let combined_expr = ast::Expr::Binary {
                    op: *op,
                    left: Box::new(ast::Expr::Ident(target.clone())),
                    right: Box::new(value.clone()),
                };
                let val = clif_emit_expr(builder, ctx, &combined_expr, locals, next_var)?;
                if let Some(data_id) = ctx.mutable_globals.get(target).copied() {
                    let val = cast_clif_value(builder, val, types::I32)?;
                    let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                    let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                    builder.ins().store(MemFlags::new(), val.value, ptr, 0);
                } else {
                    let binding = if let Some(existing) = locals.get(target).copied() {
                        existing
                    } else {
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, val.ty);
                        let binding = LocalBinding { var, ty: val.ty };
                        locals.insert(target.clone(), binding);
                        binding
                    };
                    let val = cast_clif_value(builder, val, binding.ty)?;
                    builder.def_var(binding.var, val.value);
                }
                ctx.array_bindings.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
                ctx.aggregate_bindings.remove(target);
            }
            ast::Stmt::Defer(expr) => {
                deferred.push(expr.clone());
            }
            ast::Stmt::Expr(expr) | ast::Stmt::Requires(expr) | ast::Stmt::Ensures(expr) => {
                if let ast::Expr::Call { callee, args } = expr {
                    if callee == "__index_assign" && args.len() == 3 {
                        clif_emit_index_assign(
                            builder, ctx, &args[0], &args[1], &args[2], locals, next_var,
                        )?;
                        continue;
                    }
                }
                let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
            }
            ast::Stmt::Return(value) => {
                match (value, ctx.current_return_ty) {
                    (Some(expr), _) if ctx.current_return_array.is_some() => {
                        let return_array = ctx.current_return_array.unwrap();
                        let return_ptr = ctx
                            .current_return_ptr
                            .ok_or_else(|| anyhow!("missing cranelift array return pointer"))?;
                        let dest_ptr = builder.use_var(return_ptr.var);
                        clif_emit_array_expr_to_ptr(
                            builder,
                            ctx,
                            expr,
                            dest_ptr,
                            return_array,
                            locals,
                            next_var,
                        )?;
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        builder.ins().return_(&[]);
                    }
                    (Some(expr), Some(ret_ty)) => {
                        let lowered = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        let lowered = cast_clif_value(builder, lowered, ret_ty)?;
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        builder.ins().return_(&[lowered.value]);
                    }
                    (Some(expr), None) => {
                        let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        builder.ins().return_(&[]);
                    }
                    (None, _) if ctx.current_return_array.is_some() => {
                        let return_array = ctx.current_return_array.unwrap();
                        let return_ptr = ctx
                            .current_return_ptr
                            .ok_or_else(|| anyhow!("missing cranelift array return pointer"))?;
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        let dest_ptr = builder.use_var(return_ptr.var);
                        clif_zero_fill_array_memory(builder, dest_ptr, return_array);
                        builder.ins().return_(&[]);
                    }
                    (None, Some(ret_ty)) => {
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        let fallback = zero_for_type(builder, ret_ty);
                        builder.ins().return_(&[fallback]);
                    }
                    (None, None) => {
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        builder.ins().return_(&[]);
                    }
                }
                return Ok(true);
            }
            ast::Stmt::If { .. }
            | ast::Stmt::While { .. }
            | ast::Stmt::For { .. }
            | ast::Stmt::ForIn { .. }
            | ast::Stmt::Loop { .. }
            | ast::Stmt::Break(_)
            | ast::Stmt::Continue
            | ast::Stmt::Match { .. } => {
                bail!("cranelift linear emission received non-linear control-flow statement");
            }
        }
    }
    for expr in deferred.iter().rev() {
        let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
    }
    Ok(false)
}
