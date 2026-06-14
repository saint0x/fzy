use super::*;

pub(crate) fn clif_emit_inlined_closure_call(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    binding: ClifClosureBinding,
    args: &[ast::Expr],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let mut cast_args = Vec::with_capacity(binding.params.len());
    for (index, param) in binding.params.iter().enumerate() {
        let arg = args.get(index).cloned().unwrap_or(ast::Expr::Int(0));
        let mut lowered = clif_emit_expr(builder, ctx, &arg, locals, next_var)?;
        if let Some(target_ty) = ast_signature_type_to_clif_type(&param.ty) {
            lowered = cast_clif_value(builder, lowered, target_ty)?;
        }
        cast_args.push(lowered);
    }

    let mut saved = HashMap::<String, Option<LocalBinding>>::new();
    let mut inserted = HashSet::<String>::new();
    for (name, capture) in &binding.captures {
        if !saved.contains_key(name) {
            saved.insert(name.clone(), locals.get(name).copied());
        }
        locals.insert(name.clone(), *capture);
        inserted.insert(name.clone());
    }

    for (index, param) in binding.params.iter().enumerate() {
        if !saved.contains_key(&param.name) {
            saved.insert(param.name.clone(), locals.get(&param.name).copied());
        }
        let target_ty = ast_signature_type_to_clif_type(&param.ty).unwrap_or(cast_args[index].ty);
        let var = Variable::from_u32(*next_var as u32);
        *next_var += 1;
        builder.declare_var(var, target_ty);
        let value = cast_clif_value(builder, cast_args[index], target_ty)?;
        builder.def_var(var, value.value);
        locals.insert(param.name.clone(), LocalBinding { var, ty: target_ty });
        inserted.insert(param.name.clone());
    }

    let mut result = clif_emit_expr(builder, ctx, &binding.body, locals, next_var)?;
    if let Some(return_ty) = &binding.return_type {
        if let Some(target_ty) = ast_signature_type_to_clif_type(return_ty) {
            result = cast_clif_value(builder, result, target_ty)?;
        }
    }
    clif_restore_shadowed_locals(locals, saved, inserted);
    Ok(result)
}

pub(crate) fn clif_emit_let_pattern(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    pattern: &ast::Pattern,
    value: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<()> {
    let lowered = clif_emit_expr(builder, ctx, value, locals, next_var)?;
    match pattern {
        ast::Pattern::Wildcard => {}
        ast::Pattern::Ident(name) => {
            let var = Variable::from_u32(*next_var as u32);
            *next_var += 1;
            builder.declare_var(var, lowered.ty);
            builder.def_var(var, lowered.value);
            locals.insert(
                name.clone(),
                LocalBinding {
                    var,
                    ty: lowered.ty,
                },
            );
        }
        ast::Pattern::Tuple(items) => {
            if let ast::Expr::Tuple(values) = value {
                if items.len() != values.len() {
                    bail!("native backend requires tuple pattern arity to match tuple initializer arity");
                }
                for (item, value) in items.iter().zip(values.iter()) {
                    clif_emit_let_pattern(builder, ctx, item, value, locals, next_var)?;
                }
            } else if let ast::Expr::Ident(name) = value {
                for (index, item) in items.iter().enumerate() {
                    let synthetic = format!("{name}.__tuple{index}");
                    if locals.contains_key(&synthetic) {
                        clif_emit_let_pattern(
                            builder,
                            ctx,
                            item,
                            &ast::Expr::Ident(synthetic),
                            locals,
                            next_var,
                        )?;
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(&format!("__tuple{index}")).cloned())
                            .or_else(|| clif_tuple_item_binding_for_local(name, index, ctx))
                            .ok_or_else(|| anyhow!("native backend requires tuple-bound aggregate metadata for `let` tuple destructuring"))?;
                        let handle = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                        let extracted = clif_emit_aggregate_get(
                            builder,
                            ctx,
                            handle,
                            item_binding.index,
                            item_binding.ty,
                        )?;
                        let temp_name = format!("__agg_tuple_extract_{}_{}", name, index);
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, extracted.ty);
                        builder.def_var(var, extracted.value);
                        locals.insert(
                            temp_name.clone(),
                            LocalBinding {
                                var,
                                ty: extracted.ty,
                            },
                        );
                        clif_emit_let_pattern(
                            builder,
                            ctx,
                            item,
                            &ast::Expr::Ident(temp_name),
                            locals,
                            next_var,
                        )?;
                    }
                }
            } else {
                bail!("native backend requires tuple initializer or tuple-bound local for `let` tuple destructuring");
            }
        }
        ast::Pattern::Int(expected) => {
            let expected_value = builder.ins().iconst(lowered.ty, *expected as i64);
            let _ = builder
                .ins()
                .icmp(IntCC::Equal, lowered.value, expected_value);
        }
        ast::Pattern::Bool(expected) => {
            let expected_value = builder.ins().iconst(lowered.ty, i64::from(*expected));
            let _ = builder
                .ins()
                .icmp(IntCC::Equal, lowered.value, expected_value);
        }
        ast::Pattern::Struct { name, fields } => {
            if let ast::Expr::StructInit {
                name: value_name,
                fields: value_fields,
            } = value
            {
                if value_name != name {
                    bail!(
                        "native backend requires exact literal struct type match for `let` struct destructuring"
                    );
                }
                for (field_name, binding_name) in fields {
                    if binding_name == "_" {
                        continue;
                    }
                    let Some((_, field_expr)) =
                        value_fields.iter().find(|(field, _)| field == field_name)
                    else {
                        bail!("native backend requires struct literal fields to cover every bound pattern field");
                    };
                    let payload_val = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                    let var = Variable::from_u32(*next_var as u32);
                    *next_var += 1;
                    builder.declare_var(var, payload_val.ty);
                    builder.def_var(var, payload_val.value);
                    locals.insert(
                        binding_name.clone(),
                        LocalBinding {
                            var,
                            ty: payload_val.ty,
                        },
                    );
                }
            } else if let ast::Expr::Ident(name) = value {
                for (field_name, binding_name) in fields {
                    if binding_name == "_" {
                        continue;
                    }
                    if let Some(binding) = locals.get(&format!("{name}.{field_name}")).copied() {
                        locals.insert(binding_name.clone(), binding);
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(field_name).cloned())
                            .or_else(|| clif_struct_field_binding_for_local(name, field_name, ctx))
                            .ok_or_else(|| anyhow!("native backend requires struct-bound aggregate metadata for `let` struct destructuring"))?;
                        let handle = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                        let extracted = clif_emit_aggregate_get(
                            builder,
                            ctx,
                            handle,
                            item_binding.index,
                            item_binding.ty,
                        )?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, extracted.ty);
                        builder.def_var(var, extracted.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: extracted.ty,
                            },
                        );
                    }
                }
            } else {
                bail!("native backend requires struct initializer or struct-bound local for `let` struct destructuring");
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            named_bindings,
        } => {
            let key = format!("{enum_name}::{variant}");
            let (cmp_ty, cmp_value) = if lowered.ty == types::I64 {
                let agg_tag_id =
                    ctx.function_ids
                        .get(NATIVE_AGG_TAG)
                        .copied()
                        .ok_or_else(|| {
                            anyhow!("missing runtime import lowering for `{NATIVE_AGG_TAG}`")
                        })?;
                let agg_tag_ref = ctx.module.declare_func_in_func(agg_tag_id, builder.func);
                let tag_call = builder.ins().call(agg_tag_ref, &[lowered.value]);
                (types::I32, builder.inst_results(tag_call)[0])
            } else {
                (lowered.ty, lowered.value)
            };
            let expected_tag = builder
                .ins()
                .iconst(cmp_ty, variant_tag_for_key(&key, ctx.variant_tags) as i64);
            let _ = builder.ins().icmp(IntCC::Equal, cmp_value, expected_tag);
            if let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                payload,
                named_payload,
                ..
            } = value
            {
                if value_enum == enum_name
                    && value_variant == variant
                    && payload.len() == bindings.len()
                {
                    for (binding_name, payload_expr) in bindings.iter().zip(payload.iter()) {
                        let payload_val =
                            clif_emit_expr(builder, ctx, payload_expr, locals, next_var)?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, payload_val.ty);
                        builder.def_var(var, payload_val.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: payload_val.ty,
                            },
                        );
                    }
                    for (field_name, binding_name) in named_bindings {
                        if binding_name == "_" {
                            continue;
                        }
                        let Some((_, field_expr)) =
                            named_payload.iter().find(|(field, _)| field == field_name)
                        else {
                            bail!("native backend requires enum literal named payload fields to cover every bound pattern field");
                        };
                        let payload_val =
                            clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, payload_val.ty);
                        builder.def_var(var, payload_val.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: payload_val.ty,
                            },
                        );
                    }
                }
            } else if let ast::Expr::Ident(name) = value {
                for (index, binding_name) in bindings.iter().enumerate() {
                    let key = format!("{name}.__payload{index}");
                    if let Some(binding) = locals.get(&key).copied() {
                        locals.insert(binding_name.clone(), binding);
                    } else {
                        let payload_key = format!("__payload{index}");
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(&payload_key).cloned())
                            .or_else(|| {
                                clif_enum_payload_binding_for_local(
                                    name,
                                    enum_name,
                                    variant,
                                    index,
                                    ctx,
                                )
                            })
                            .ok_or_else(|| anyhow!("native backend requires enum-bound local payloads for `let` variant destructuring"))?;
                        let handle = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                        let extracted = clif_emit_aggregate_get(
                            builder,
                            ctx,
                            handle,
                            item_binding.index,
                            item_binding.ty,
                        )?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, extracted.ty);
                        builder.def_var(var, extracted.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: extracted.ty,
                            },
                        );
                    }
                }
                for (field_name, binding_name) in named_bindings {
                    if binding_name == "_" {
                        continue;
                    }
                    if let Some(binding) = locals.get(&format!("{name}.{field_name}")).copied() {
                        locals.insert(binding_name.clone(), binding);
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(field_name).cloned())
                            .or_else(|| {
                                clif_enum_named_binding_for_local(
                                    name,
                                    enum_name,
                                    variant,
                                    field_name,
                                    ctx,
                                )
                            })
                            .ok_or_else(|| anyhow!("native backend requires enum-bound local named payloads for `let` variant destructuring"))?;
                        let handle = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                        let extracted = clif_emit_aggregate_get(
                            builder,
                            ctx,
                            handle,
                            item_binding.index,
                            item_binding.ty,
                        )?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, extracted.ty);
                        builder.def_var(var, extracted.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: extracted.ty,
                            },
                        );
                    }
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns.iter().find(|pattern| {
                pattern_matches_resolved_scrutinee(pattern, value, ctx.variant_tags)
            }) {
                return clif_emit_let_pattern(builder, ctx, matched, value, locals, next_var);
            }
            if patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
            {
                bail!(
                    "native backend requires resolvable initializer for payload or struct-field bindings in `let` or-patterns"
                );
            }
        }
    }
    Ok(())
}

