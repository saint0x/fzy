use super::*;

pub(crate) fn llvm_emit_simple_expr(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Option<Result<LlvmValue>> {
    match expr {
        ast::Expr::Ident(name) => Some(Ok(if let Some(direct) = ctx.direct_values.get(name) {
            direct.clone()
        } else if let Some(value) = ctx.const_strings.get(name).cloned() {
            LlvmValue {
                value: string_literal_ids
                    .get(&value)
                    .copied()
                    .unwrap_or(0)
                    .to_string(),
                ty: "i32".to_string(),
            }
        } else if let Some(value) =
            resolve_native_global_const_i32_expr(expr, &ctx.current_namespace, &ctx.globals)
        {
            LlvmValue {
                value: value.to_string(),
                ty: "i32".to_string(),
            }
        } else if let Some(slot) = ctx.slots.get(name).cloned() {
            let ty = ctx
                .slot_tys
                .get(name)
                .cloned()
                .unwrap_or_else(|| "i32".to_string());
            let val = ctx.value();
            ctx.code
                .push_str(&format!("  {val} = load {ty}, ptr {slot}\n"));
            LlvmValue { value: val, ty }
        } else if let Some(symbol) = ctx.mutable_globals.get(name).cloned() {
            let val = ctx.value();
            ctx.code
                .push_str(&format!("  {val} = load i32, ptr @{symbol}\n"));
            LlvmValue {
                value: val,
                ty: "i32".to_string(),
            }
        } else if let Some(value) = ctx.globals.get(name).copied() {
            LlvmValue {
                value: value.to_string(),
                ty: "i32".to_string(),
            }
        } else if let Some(task_ref) = task_ref_ids.get(name).copied() {
            LlvmValue {
                value: task_ref.to_string(),
                ty: "i32".to_string(),
            }
        } else {
            LlvmValue {
                value: "0".to_string(),
                ty: "i32".to_string(),
            }
        })),
        ast::Expr::Discard(inner) => Some((|| {
            let _ = llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids)?;
            Ok(LlvmValue {
                value: "0".to_string(),
                ty: "i32".to_string(),
            })
        })()),
        ast::Expr::Closure {
            params,
            return_type,
            body,
        } => Some(Ok({
            let captures = llvm_snapshot_closure_captures(ctx);
            let name = format!("__closure_{}", ctx.next_value);
            ctx.closures.insert(
                name,
                LlvmClosureBinding {
                    params: params.clone(),
                    return_type: return_type.clone(),
                    body: (**body).clone(),
                    captures,
                },
            );
            LlvmValue {
                value: "0".to_string(),
                ty: "i32".to_string(),
            }
        })),
        ast::Expr::Unary { op, expr } => Some((|| {
            let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
            Ok(match op {
                ast::UnaryOp::Plus => value,
                ast::UnaryOp::Neg => {
                    let out = ctx.value();
                    if llvm_is_float_ty(&value.ty) {
                        ctx.code.push_str(&format!(
                            "  {out} = fsub {} 0.0, {}\n",
                            value.ty, value.value
                        ));
                        llvm_assert_finite(
                            ctx,
                            LlvmValue {
                                value: out,
                                ty: value.ty,
                            },
                        )?
                    } else {
                        ctx.code
                            .push_str(&format!("  {out} = sub {} 0, {}\n", value.ty, value.value));
                        LlvmValue {
                            value: out,
                            ty: value.ty,
                        }
                    }
                }
                ast::UnaryOp::BitNot => {
                    let out = ctx.value();
                    ctx.code
                        .push_str(&format!("  {out} = xor {} {}, -1\n", value.ty, value.value));
                    LlvmValue {
                        value: out,
                        ty: value.ty,
                    }
                }
                ast::UnaryOp::Not => {
                    let pred = llvm_emit_truthy_pred(ctx, &value);
                    let out = ctx.value();
                    ctx.code
                        .push_str(&format!("  {out} = xor i1 {pred}, true\n"));
                    llvm_bool_from_pred(ctx, &out)
                }
            })
        })()),
        ast::Expr::FieldAccess { base, field } => Some((|| {
            if let Some(value) =
                resolve_native_global_const_i32_expr(expr, &ctx.current_namespace, &ctx.globals)
            {
                return Ok(LlvmValue {
                    value: value.to_string(),
                    ty: "i32".to_string(),
                });
            }
            if let Some(field_expr) = resolve_field_expr(base, field) {
                return llvm_emit_expr(&field_expr, ctx, string_literal_ids, task_ref_ids);
            }
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(slot) = ctx.slots.get(&format!("{name}.{field}")).cloned() {
                    let ty = ctx
                        .slot_tys
                        .get(&format!("{name}.{field}"))
                        .cloned()
                        .unwrap_or_else(|| "i32".to_string());
                    let val = ctx.value();
                    ctx.code
                        .push_str(&format!("  {val} = load {ty}, ptr {slot}\n"));
                    return Ok(LlvmValue { value: val, ty });
                }
                if let Some(binding) = ctx.aggregate_bindings.get(name).cloned() {
                    if let Some(item) = binding.items.get(field) {
                        let handle = llvm_emit_expr(base, ctx, string_literal_ids, task_ref_ids)?;
                        return Ok(llvm_emit_aggregate_get(ctx, &handle, item.index, &item.ty));
                    }
                }
                if let Some(item) = llvm_struct_field_binding_for_local(name, field, ctx) {
                    let handle = llvm_emit_expr(base, ctx, string_literal_ids, task_ref_ids)?;
                    return Ok(llvm_emit_aggregate_get(ctx, &handle, item.index, &item.ty));
                }
            }
            if let Some(task_ref_name) = expr_task_ref_name(expr) {
                if let Some(task_ref) = task_ref_ids.get(&task_ref_name).copied() {
                    return Ok(LlvmValue {
                        value: task_ref.to_string(),
                        ty: "i32".to_string(),
                    });
                }
            }
            let base_value = llvm_emit_expr(base, ctx, string_literal_ids, task_ref_ids)?;
            if base_value.ty == "i64" {
                let tag_value = ctx.value();
                ctx.code.push_str(&format!(
                    "  {tag_value} = call i32 @{}(i64 {})\n",
                    NATIVE_AGG_TAG_SYMBOL, base_value.value
                ));
                let _ = tag_value;
            }
            Ok(base_value)
        })()),
        ast::Expr::Tuple(items) => Some((|| {
            let mut rendered = Vec::with_capacity(items.len());
            for item in items {
                rendered.push(llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids)?);
            }
            Ok(llvm_emit_aggregate_handle(0, &rendered, ctx))
        })()),
        ast::Expr::ArrayLiteral(items) => Some(llvm_emit_array_literal_value(
            items,
            ctx,
            string_literal_ids,
            task_ref_ids,
        )),
        ast::Expr::StructInit { fields, .. } => Some((|| {
            let mut rendered = Vec::with_capacity(fields.len());
            for (_, value) in fields {
                rendered.push(llvm_emit_expr(
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                )?);
            }
            Ok(llvm_emit_aggregate_handle(0, &rendered, ctx))
        })()),
        ast::Expr::EnumInit {
            enum_name,
            variant,
            payload,
            named_payload,
        } => Some((|| {
            let key = format!("{enum_name}::{variant}");
            let tag = variant_tag_for_key(&key, &ctx.variant_tags);
            let mut rendered = Vec::with_capacity(payload.len() + named_payload.len());
            for value in payload {
                rendered.push(llvm_emit_expr(
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                )?);
            }
            for (_, value) in named_payload {
                rendered.push(llvm_emit_expr(
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                )?);
            }
            Ok(llvm_emit_aggregate_handle(tag, &rendered, ctx))
        })()),
        _ => None,
    }
}
