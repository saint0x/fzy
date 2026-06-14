use super::*;

pub(crate) fn clif_emit_aggregate_handle(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    tag: i32,
    items: &[ClifValue],
) -> Result<ClifValue> {
    let agg_new_id = ctx
        .function_ids
        .get(NATIVE_AGG_NEW)
        .copied()
        .ok_or_else(|| anyhow!("missing runtime import lowering for `{NATIVE_AGG_NEW}`"))?;
    let agg_set_id = ctx
        .function_ids
        .get(NATIVE_AGG_SET_I64)
        .copied()
        .ok_or_else(|| anyhow!("missing runtime import lowering for `{NATIVE_AGG_SET_I64}`"))?;
    let new_ref = ctx.module.declare_func_in_func(agg_new_id, builder.func);
    let tag_value = builder.ins().iconst(types::I32, i64::from(tag));
    let count_value = builder.ins().iconst(types::I32, items.len() as i64);
    let handle_call = builder.ins().call(new_ref, &[tag_value, count_value]);
    let handle = builder.inst_results(handle_call)[0];
    let set_ref = ctx.module.declare_func_in_func(agg_set_id, builder.func);
    for (index, item) in items.iter().cloned().enumerate() {
        let raw = clif_cast_scalar_to_i64(builder, item)?;
        let index_value = builder.ins().iconst(types::I32, index as i64);
        let _ = builder
            .ins()
            .call(set_ref, &[handle, index_value, raw.value]);
    }
    Ok(ClifValue {
        value: handle,
        ty: types::I64,
    })
}

pub(crate) fn clif_emit_aggregate_get(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    handle: ClifValue,
    index: usize,
    target_ty: ClifType,
) -> Result<ClifValue> {
    let agg_get_id = ctx
        .function_ids
        .get(NATIVE_AGG_GET_I64)
        .copied()
        .ok_or_else(|| anyhow!("missing runtime import lowering for `{NATIVE_AGG_GET_I64}`"))?;
    let agg_get_ref = ctx.module.declare_func_in_func(agg_get_id, builder.func);
    let index_value = builder.ins().iconst(types::I32, index as i64);
    let raw_call = builder
        .ins()
        .call(agg_get_ref, &[handle.value, index_value]);
    let raw = builder.inst_results(raw_call)[0];
    clif_cast_i64_to_ty(builder, raw, target_ty)
}

pub(crate) fn clif_record_aggregate_binding(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    name: &str,
    value: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<()> {
    let mut binding = ClifAggregateBinding::default();
    match value {
        ast::Expr::StructInit { fields, .. } => {
            for (index, (field, field_expr)) in fields.iter().enumerate() {
                let field_value = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                binding.items.insert(
                    field.clone(),
                    ClifAggregateItemBinding {
                        index,
                        ty: field_value.ty,
                    },
                );
            }
        }
        ast::Expr::Tuple(items) => {
            for (index, item_expr) in items.iter().enumerate() {
                let item_value = clif_emit_expr(builder, ctx, item_expr, locals, next_var)?;
                binding.items.insert(
                    format!("__tuple{index}"),
                    ClifAggregateItemBinding {
                        index,
                        ty: item_value.ty,
                    },
                );
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for (index, payload_expr) in payload.iter().enumerate() {
                let payload_value = clif_emit_expr(builder, ctx, payload_expr, locals, next_var)?;
                binding.items.insert(
                    format!("__payload{index}"),
                    ClifAggregateItemBinding {
                        index,
                        ty: payload_value.ty,
                    },
                );
            }
            for (offset, (field, field_expr)) in named_payload.iter().enumerate() {
                let field_value = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                binding.items.insert(
                    field.clone(),
                    ClifAggregateItemBinding {
                        index: payload.len() + offset,
                        ty: field_value.ty,
                    },
                );
            }
        }
        _ => {
            ctx.aggregate_bindings.remove(name);
            return Ok(());
        }
    }
    ctx.aggregate_bindings.insert(name.to_string(), binding);
    Ok(())
}

pub(crate) fn clif_tuple_item_binding_for_local(
    name: &str,
    index: usize,
    ctx: &ClifLoweringCtx<'_>,
) -> Option<ClifAggregateItemBinding> {
    let ast::Type::Tuple(items) = clif_local_type(ctx, name)? else {
        return None;
    };
    let item_ty = items.get(index)?;
    Some(ClifAggregateItemBinding {
        index,
        ty: ast_signature_type_to_clif_type(item_ty)?,
    })
}

pub(crate) fn clif_struct_field_binding_for_local(
    name: &str,
    field: &str,
    ctx: &ClifLoweringCtx<'_>,
) -> Option<ClifAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = clif_local_type(ctx, name)? else {
        return None;
    };
    let struct_def = ctx.struct_defs.get(ty_name.as_str())?;
    let (index, struct_field) = struct_def
        .fields
        .iter()
        .enumerate()
        .find(|(_, item)| item.name == field)?;
    Some(ClifAggregateItemBinding {
        index,
        ty: ast_signature_type_to_clif_type(&struct_field.ty)?,
    })
}

pub(crate) fn clif_enum_payload_binding_for_local(
    name: &str,
    enum_name: &str,
    variant: &str,
    index: usize,
    ctx: &ClifLoweringCtx<'_>,
) -> Option<ClifAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = clif_local_type(ctx, name)? else {
        return None;
    };
    if ty_name != enum_name {
        return None;
    }
    let enum_def = ctx.enum_defs.get(enum_name)?;
    let variant_def = enum_def.variants.iter().find(|item| item.name == variant)?;
    let payload_ty = variant_def.payload.get(index)?;
    Some(ClifAggregateItemBinding {
        index,
        ty: ast_signature_type_to_clif_type(payload_ty)?,
    })
}

pub(crate) fn clif_enum_named_binding_for_local(
    name: &str,
    enum_name: &str,
    variant: &str,
    field: &str,
    ctx: &ClifLoweringCtx<'_>,
) -> Option<ClifAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = clif_local_type(ctx, name)? else {
        return None;
    };
    if ty_name != enum_name {
        return None;
    }
    let enum_def = ctx.enum_defs.get(enum_name)?;
    let variant_def = enum_def.variants.iter().find(|item| item.name == variant)?;
    let (offset, named_field) = variant_def
        .named_payload
        .iter()
        .enumerate()
        .find(|(_, item)| item.name == field)?;
    Some(ClifAggregateItemBinding {
        index: variant_def.payload.len() + offset,
        ty: ast_signature_type_to_clif_type(&named_field.ty)?,
    })
}

pub(crate) fn clif_local_is_aggregate(name: &str, ctx: &ClifLoweringCtx<'_>) -> bool {
    matches!(
        clif_local_type(ctx, name),
        Some(ast::Type::Tuple(_)) | Some(ast::Type::Named { .. })
    )
}

