use super::*;

pub(crate) fn llvm_emit_linear_stmts(
    body: &[ast::Stmt],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<bool> {
    let mut deferred = Vec::<ast::Expr>::new();
    for stmt in body {
        match stmt {
            ast::Stmt::Let {
                name,
                value,
                mutable,
                ..
            } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(name.clone(), const_value);
                    ctx.array_slots.remove(name);
                    ctx.direct_values.remove(name);
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let storage = format!("%slot_{}_arr_{}", name, ctx.next_value);
                    let len = items.len();
                    let lowered_items = items
                        .iter()
                        .map(|item| llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids))
                        .collect::<Result<Vec<_>>>()?;
                    let element_ty = lowered_items
                        .first()
                        .map(|value| value.ty.clone())
                        .unwrap_or_else(|| "i32".to_string());
                    ctx.declare_alloca(&storage, &format!("[{len} x {element_ty}]"));
                    for (idx, item) in items.iter().enumerate() {
                        let item_value = llvm_emit_expr_as(
                            item,
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                            &element_ty,
                        )?;
                        let element_ptr = ctx.value();
                        ctx.code.push_str(&format!(
                            "  {element_ptr} = getelementptr inbounds [{len} x {element_ty}], ptr {storage}, i32 0, i64 {idx}\n  store {element_ty} {}, ptr {element_ptr}\n",
                            item_value.value
                        ));
                    }
                    ctx.array_slots.insert(
                        name.clone(),
                        LlvmArrayBinding {
                            storage: storage.clone(),
                            len,
                            element_ty: element_ty.clone(),
                            element_bits: 32,
                            element_align: 4,
                            element_stride: 4,
                        },
                    );
                    ctx.slots.insert(name.clone(), storage);
                    ctx.slot_tys
                        .insert(name.clone(), format!("[{len} x {element_ty}]"));
                    ctx.direct_values.remove(name);
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_ty) = ctx.local_types.get(source).cloned() {
                        ctx.local_types.insert(name.clone(), source_ty);
                    }
                    if let Some(binding) = ctx.aggregate_bindings.get(source).cloned() {
                        ctx.aggregate_bindings.insert(name.clone(), binding);
                    }
                    if let Some(source_binding) = ctx.array_slots.get(source).cloned() {
                        ctx.array_slots.insert(name.clone(), source_binding);
                        ctx.direct_values.remove(name);
                        continue;
                    }
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    let captures = llvm_snapshot_closure_captures(ctx);
                    ctx.closures.insert(
                        name.clone(),
                        LlvmClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures,
                        },
                    );
                    ctx.direct_values.remove(name);
                    continue;
                }
                let rendered = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                let slot = format!("%slot_{}_{}", name, ctx.next_value);
                ctx.declare_alloca(&slot, &rendered.ty);
                ctx.code.push_str(&format!(
                    "  store {} {}, ptr {slot}\n",
                    rendered.ty, rendered.value
                ));
                ctx.slots.insert(name.clone(), slot.clone());
                ctx.slot_tys.insert(name.clone(), rendered.ty.clone());
                if !*mutable {
                    ctx.direct_values.insert(name.clone(), rendered.clone());
                } else {
                    ctx.direct_values.remove(name);
                }
                if let Some(local_ty) = ctx.local_types.get(name) {
                    if let Some(binding) = llvm_array_binding_from_type(&slot, local_ty) {
                        ctx.array_slots.insert(name.clone(), binding);
                    }
                }
                let _ = llvm_record_aggregate_binding(
                    name,
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let field_slot = format!("%slot_{}_{}_{}", name, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &field_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            field_value.ty, field_value.value
                        ));
                        ctx.slots.insert(format!("{name}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{name}.{field}"), field_value.ty.clone());
                    }
                }
                if let ast::Expr::Tuple(items) = value {
                    for (index, item_expr) in items.iter().enumerate() {
                        let item_value =
                            llvm_emit_expr(item_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let item_slot =
                            format!("%slot_{}_tuple_{}_{}", name, index, ctx.next_value);
                        ctx.declare_alloca(&item_slot, &item_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {item_slot}\n",
                            item_value.ty, item_value.value
                        ));
                        ctx.slots
                            .insert(format!("{name}.__tuple{index}"), item_slot);
                        ctx.slot_tys
                            .insert(format!("{name}.__tuple{index}"), item_value.ty.clone());
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
                        let payload_value =
                            llvm_emit_expr(payload_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let payload_slot =
                            format!("%slot_{}_payload_{}_{}", name, index, ctx.next_value);
                        ctx.declare_alloca(&payload_slot, &payload_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {payload_slot}\n",
                            payload_value.ty, payload_value.value
                        ));
                        ctx.slots
                            .insert(format!("{name}.__payload{index}"), payload_slot);
                        ctx.slot_tys
                            .insert(format!("{name}.__payload{index}"), payload_value.ty.clone());
                    }
                    for (field, field_expr) in named_payload {
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let field_slot = format!("%slot_{}_{}_{}", name, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &field_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            field_value.ty, field_value.value
                        ));
                        ctx.slots.insert(format!("{name}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{name}.{field}"), field_value.ty.clone());
                    }
                }
                if let ast::Expr::Range {
                    start,
                    end,
                    inclusive,
                } = value
                {
                    let start_value = llvm_emit_expr(start, ctx, string_literal_ids, task_ref_ids)?;
                    let end_value = llvm_emit_expr(end, ctx, string_literal_ids, task_ref_ids)?;
                    let inclusive_value = LlvmValue {
                        value: if *inclusive {
                            "1".to_string()
                        } else {
                            "0".to_string()
                        },
                        ty: "i8".to_string(),
                    };
                    for (field, rendered) in [
                        ("start", start_value),
                        ("end", end_value),
                        ("inclusive", inclusive_value),
                    ] {
                        let field_slot = format!("%slot_{}_{}_{}", name, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &rendered.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            rendered.ty, rendered.value
                        ));
                        ctx.slots.insert(format!("{name}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{name}.{field}"), rendered.ty.clone());
                    }
                }
                if !matches!(ctx.local_types.get(name), Some(ast::Type::Array { .. })) {
                    ctx.array_slots.remove(name);
                }
                ctx.const_strings.remove(name);
            }
            ast::Stmt::LetPattern { pattern, value, .. } => {
                llvm_emit_let_pattern(pattern, value, ctx, string_literal_ids, task_ref_ids)?;
            }
            ast::Stmt::Assign { target, value } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(target.clone(), const_value);
                    ctx.array_slots.remove(target);
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let storage = format!("%slot_{}_arr_{}", target, ctx.next_value);
                    let len = items.len();
                    let lowered_items = items
                        .iter()
                        .map(|item| llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids))
                        .collect::<Result<Vec<_>>>()?;
                    let element_ty = lowered_items
                        .first()
                        .map(|value| value.ty.clone())
                        .unwrap_or_else(|| "i32".to_string());
                    ctx.declare_alloca(&storage, &format!("[{len} x {element_ty}]"));
                    for (idx, item) in items.iter().enumerate() {
                        let item_value = llvm_emit_expr_as(
                            item,
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                            &element_ty,
                        )?;
                        let element_ptr = ctx.value();
                        ctx.code.push_str(&format!(
                            "  {element_ptr} = getelementptr inbounds [{len} x {element_ty}], ptr {storage}, i32 0, i64 {idx}\n  store {element_ty} {}, ptr {element_ptr}\n",
                            item_value.value
                        ));
                    }
                    ctx.array_slots.insert(
                        target.clone(),
                        LlvmArrayBinding {
                            storage: storage.clone(),
                            len,
                            element_ty: element_ty.clone(),
                            element_bits: 32,
                            element_align: 4,
                            element_stride: 4,
                        },
                    );
                    ctx.slots.insert(target.clone(), storage);
                    ctx.slot_tys
                        .insert(target.clone(), format!("[{len} x {element_ty}]"));
                    ctx.direct_values.remove(target);
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_ty) = ctx.local_types.get(source).cloned() {
                        ctx.local_types.insert(target.clone(), source_ty);
                    }
                    if let Some(binding) = ctx.aggregate_bindings.get(source).cloned() {
                        ctx.aggregate_bindings.insert(target.clone(), binding);
                    }
                    if let Some(source_binding) = ctx.array_slots.get(source).cloned() {
                        ctx.array_slots.insert(target.clone(), source_binding);
                        continue;
                    }
                }
                let rendered_value = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    let captures = llvm_snapshot_closure_captures(ctx);
                    ctx.closures.insert(
                        target.clone(),
                        LlvmClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures,
                        },
                    );
                    continue;
                }
                if let Some(symbol) = ctx.mutable_globals.get(target).cloned() {
                    let stored = llvm_cast_value(ctx, rendered_value.clone(), "i32")?;
                    ctx.code
                        .push_str(&format!("  store i32 {}, ptr @{symbol}\n", stored.value));
                    ctx.direct_values.remove(target);
                    continue;
                }
                let slot = ctx
                    .slots
                    .entry(target.clone())
                    .or_insert_with(|| format!("%slot_{}_{}", target, ctx.next_value))
                    .clone();
                ctx.declare_alloca(&slot, &rendered_value.ty);
                ctx.code.push_str(&format!(
                    "  store {} {}, ptr {slot}\n",
                    rendered_value.ty, rendered_value.value
                ));
                ctx.slot_tys
                    .insert(target.clone(), rendered_value.ty.clone());
                if let Some(local_ty) = ctx.local_types.get(target) {
                    if let Some(binding) = llvm_array_binding_from_type(&slot, local_ty) {
                        ctx.array_slots.insert(target.clone(), binding);
                    }
                }
                ctx.direct_values.remove(target);
                let _ = llvm_record_aggregate_binding(
                    target,
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let field_slot = format!("%slot_{}_{}_{}", target, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &field_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            field_value.ty, field_value.value
                        ));
                        ctx.slots.insert(format!("{target}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{target}.{field}"), field_value.ty.clone());
                    }
                }
                if let ast::Expr::Tuple(items) = value {
                    for (index, item_expr) in items.iter().enumerate() {
                        let item_value =
                            llvm_emit_expr(item_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let item_slot =
                            format!("%slot_{}_tuple_{}_{}", target, index, ctx.next_value);
                        ctx.declare_alloca(&item_slot, &item_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {item_slot}\n",
                            item_value.ty, item_value.value
                        ));
                        ctx.slots
                            .insert(format!("{target}.__tuple{index}"), item_slot);
                        ctx.slot_tys
                            .insert(format!("{target}.__tuple{index}"), item_value.ty.clone());
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
                        let payload_value =
                            llvm_emit_expr(payload_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let payload_slot =
                            format!("%slot_{}_payload_{}_{}", target, index, ctx.next_value);
                        ctx.declare_alloca(&payload_slot, &payload_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {payload_slot}\n",
                            payload_value.ty, payload_value.value
                        ));
                        ctx.slots
                            .insert(format!("{target}.__payload{index}"), payload_slot);
                        ctx.slot_tys.insert(
                            format!("{target}.__payload{index}"),
                            payload_value.ty.clone(),
                        );
                    }
                    for (field, field_expr) in named_payload {
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let field_slot = format!("%slot_{}_{}_{}", target, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &field_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            field_value.ty, field_value.value
                        ));
                        ctx.slots.insert(format!("{target}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{target}.{field}"), field_value.ty.clone());
                    }
                }
                if let ast::Expr::Range {
                    start,
                    end,
                    inclusive,
                } = value
                {
                    let start_value =
                        llvm_emit_expr(start.as_ref(), ctx, string_literal_ids, task_ref_ids)?;
                    let end_value =
                        llvm_emit_expr(end.as_ref(), ctx, string_literal_ids, task_ref_ids)?;
                    let inclusive_value = LlvmValue {
                        value: if *inclusive {
                            "1".to_string()
                        } else {
                            "0".to_string()
                        },
                        ty: "i8".to_string(),
                    };
                    for (field, rendered) in [
                        ("start", start_value),
                        ("end", end_value),
                        ("inclusive", inclusive_value),
                    ] {
                        let field_slot = format!("%slot_{}_{}_{}", target, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &rendered.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            rendered.ty, rendered.value
                        ));
                        ctx.slots.insert(format!("{target}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{target}.{field}"), rendered.ty.clone());
                    }
                }
                ctx.array_slots.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::CompoundAssign { target, op, value } => {
                let combined_expr = ast::Expr::Binary {
                    op: *op,
                    left: Box::new(ast::Expr::Ident(target.clone())),
                    right: Box::new(value.clone()),
                };
                let value = llvm_emit_expr(&combined_expr, ctx, string_literal_ids, task_ref_ids)?;
                if let Some(symbol) = ctx.mutable_globals.get(target).cloned() {
                    let stored = llvm_cast_value(ctx, value.clone(), "i32")?;
                    ctx.code
                        .push_str(&format!("  store i32 {}, ptr @{symbol}\n", stored.value));
                    ctx.direct_values.remove(target);
                    continue;
                }
                let slot = ctx
                    .slots
                    .entry(target.clone())
                    .or_insert_with(|| format!("%slot_{}_{}", target, ctx.next_value))
                    .clone();
                ctx.declare_alloca(&slot, &value.ty);
                ctx.code.push_str(&format!(
                    "  store {} {}, ptr {slot}\n",
                    value.ty, value.value
                ));
                ctx.slot_tys.insert(target.clone(), value.ty.clone());
                ctx.direct_values.remove(target);
                ctx.array_slots.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::Defer(expr) => {
                deferred.push(expr.clone());
            }
            ast::Stmt::Expr(expr) | ast::Stmt::Requires(expr) | ast::Stmt::Ensures(expr) => {
                if let ast::Expr::Call { callee, args } = expr {
                    if callee == "__index_assign" && args.len() == 3 {
                        llvm_emit_index_assign(
                            &args[0],
                            &args[1],
                            &args[2],
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                        )?;
                        continue;
                    }
                }
                let _ = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids);
            }
            ast::Stmt::Return(value) => {
                match value {
                    Some(expr) => {
                        let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
                        let function_return_ty = ctx.function_return_ty.clone();
                        let value = llvm_cast_value(ctx, value, &function_return_ty)?;
                        for expr in deferred.iter().rev() {
                            let _ = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids);
                        }
                        ctx.code
                            .push_str(&format!("  ret {} {}\n", value.ty, value.value));
                    }
                    None => {
                        for expr in deferred.iter().rev() {
                            let _ = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids);
                        }
                        if ctx.function_return_ty == "void" {
                            ctx.code.push_str("  ret void\n");
                        } else {
                            let fallback = llvm_zero_literal(&ctx.function_return_ty, 0);
                            ctx.code.push_str(&format!(
                                "  ret {} {}\n",
                                ctx.function_return_ty, fallback
                            ));
                        }
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
                bail!("llvm linear emission received non-linear control-flow statement");
            }
        }
    }
    for expr in deferred.iter().rev() {
        let _ = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids);
    }
    Ok(false)
}

