use super::super::clif::variant_tag_for_key;
use super::*;

pub(crate) fn llvm_cast_i64_to_ty(
    ctx: &mut LlvmFuncCtx,
    raw_value: String,
    target_ty: &str,
) -> LlvmValue {
    match target_ty {
        "i64" => LlvmValue {
            value: raw_value,
            ty: "i64".to_string(),
        },
        "i32" | "i8" | "i1" => {
            let out = ctx.value();
            ctx.code
                .push_str(&format!("  {out} = trunc i64 {raw_value} to {target_ty}\n"));
            LlvmValue {
                value: out,
                ty: target_ty.to_string(),
            }
        }
        _ => LlvmValue {
            value: raw_value,
            ty: "i64".to_string(),
        },
    }
}

fn llvm_aggregate_width_for_ir_type(target_ty: &str) -> usize {
    if let Some((len, element_ty)) = llvm_parse_array_ir_type_local(target_ty) {
        return len * llvm_aggregate_width_for_ir_type(&element_ty);
    }
    1
}

fn llvm_parse_array_ir_type_local(ty: &str) -> Option<(usize, String)> {
    let ty = ty.trim();
    let inner = ty.strip_prefix('[')?.strip_suffix(']')?;
    let (len, element_ty) = inner.split_once(" x ")?;
    let len = len.parse::<usize>().ok()?;
    Some((len, element_ty.trim().to_string()))
}

fn llvm_aggregate_width_for_ast_type(target_ty: &ast::Type) -> usize {
    llvm_aggregate_width_for_ir_type(&llvm_ir_type_for_ast_type(target_ty))
}

fn llvm_scalar_to_i64(ctx: &mut LlvmFuncCtx, value: LlvmValue) -> Result<LlvmValue> {
    match value.ty.as_str() {
        "i64" => Ok(value),
        "i32" | "i8" | "i1" => {
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = zext {} {} to i64\n",
                value.ty, value.value
            ));
            Ok(LlvmValue {
                value: out,
                ty: "i64".to_string(),
            })
        }
        "float" => {
            let bits = ctx.value();
            let widened = ctx.value();
            ctx.code.push_str(&format!(
                "  {bits} = bitcast float {} to i32\n  {widened} = zext i32 {bits} to i64\n",
                value.value
            ));
            Ok(LlvmValue {
                value: widened,
                ty: "i64".to_string(),
            })
        }
        "double" => {
            let bits = ctx.value();
            ctx.code.push_str(&format!(
                "  {bits} = bitcast double {} to i64\n",
                value.value
            ));
            Ok(LlvmValue {
                value: bits,
                ty: "i64".to_string(),
            })
        }
        _ => Err(anyhow!(
            "unsupported llvm aggregate scalar storage type `{}`",
            value.ty
        )),
    }
}

fn llvm_flatten_aggregate_value(ctx: &mut LlvmFuncCtx, value: LlvmValue) -> Result<Vec<LlvmValue>> {
    if let Some((len, element_ty)) = llvm_parse_array_ir_type_local(&value.ty) {
        let mut out = Vec::with_capacity(len * llvm_aggregate_width_for_ir_type(&element_ty));
        for index in 0..len {
            let extracted = ctx.value();
            ctx.code.push_str(&format!(
                "  {extracted} = extractvalue {} {}, {index}\n",
                value.ty, value.value
            ));
            out.extend(llvm_flatten_aggregate_value(
                ctx,
                LlvmValue {
                    value: extracted,
                    ty: element_ty.clone(),
                },
            )?);
        }
        return Ok(out);
    }
    Ok(vec![llvm_scalar_to_i64(ctx, value)?])
}

fn llvm_emit_aggregate_get_scalar(
    ctx: &mut LlvmFuncCtx,
    handle: &LlvmValue,
    index: usize,
    target_ty: &str,
) -> LlvmValue {
    let raw = ctx.value();
    ctx.code.push_str(&format!(
        "  {raw} = call i64 @{}(i64 {}, i32 {index})\n",
        NATIVE_AGG_GET_I64_SYMBOL, handle.value
    ));
    llvm_cast_i64_to_ty(ctx, raw, target_ty)
}

pub(crate) fn llvm_emit_aggregate_get(
    ctx: &mut LlvmFuncCtx,
    handle: &LlvmValue,
    index: usize,
    target_ty: &str,
) -> Result<LlvmValue> {
    if let Some((len, element_ty)) = llvm_parse_array_ir_type_local(target_ty) {
        let mut current = "undef".to_string();
        let mut scalar_index = index;
        for lane in 0..len {
            let element = llvm_emit_aggregate_get(ctx, handle, scalar_index, &element_ty)?;
            scalar_index += llvm_aggregate_width_for_ir_type(&element_ty);
            let next = ctx.value();
            ctx.code.push_str(&format!(
                "  {next} = insertvalue {target_ty} {current}, {} {}, {lane}\n",
                element.ty, element.value
            ));
            current = next;
        }
        return Ok(LlvmValue {
            value: current,
            ty: target_ty.to_string(),
        });
    }
    Ok(llvm_emit_aggregate_get_scalar(
        ctx, handle, index, target_ty,
    ))
}

pub(crate) fn llvm_record_aggregate_binding(
    name: &str,
    value: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<()> {
    let mut binding = LlvmAggregateBinding::default();
    match value {
        ast::Expr::StructInit { fields, .. } => {
            let mut index = 0;
            for (field, field_expr) in fields {
                let field_value =
                    llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                let field_ty = field_value.ty.clone();
                binding.items.insert(
                    field.clone(),
                    LlvmAggregateItemBinding {
                        index,
                        ty: field_ty.clone(),
                    },
                );
                index += llvm_aggregate_width_for_ir_type(&field_ty);
            }
        }
        ast::Expr::Tuple(items) => {
            let mut index = 0;
            for (ordinal, item_expr) in items.iter().enumerate() {
                let item_value = llvm_emit_expr(item_expr, ctx, string_literal_ids, task_ref_ids)?;
                let item_ty = item_value.ty.clone();
                binding.items.insert(
                    format!("__tuple{ordinal}"),
                    LlvmAggregateItemBinding {
                        index,
                        ty: item_ty.clone(),
                    },
                );
                index += llvm_aggregate_width_for_ir_type(&item_ty);
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            let mut index = 0;
            for (ordinal, payload_expr) in payload.iter().enumerate() {
                let payload_value =
                    llvm_emit_expr(payload_expr, ctx, string_literal_ids, task_ref_ids)?;
                let payload_ty = payload_value.ty.clone();
                binding.items.insert(
                    format!("__payload{ordinal}"),
                    LlvmAggregateItemBinding {
                        index,
                        ty: payload_ty.clone(),
                    },
                );
                index += llvm_aggregate_width_for_ir_type(&payload_ty);
            }
            for (field, field_expr) in named_payload {
                let field_value =
                    llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                let field_ty = field_value.ty.clone();
                binding.items.insert(
                    field.clone(),
                    LlvmAggregateItemBinding {
                        index,
                        ty: field_ty.clone(),
                    },
                );
                index += llvm_aggregate_width_for_ir_type(&field_ty);
            }
        }
        _ => return Ok(()),
    }
    ctx.aggregate_bindings.insert(name.to_string(), binding);
    Ok(())
}

pub(crate) fn llvm_tuple_item_binding_for_local(
    name: &str,
    index: usize,
    ctx: &LlvmFuncCtx,
) -> Option<LlvmAggregateItemBinding> {
    let ast::Type::Tuple(items) = ctx.local_types.get(name)? else {
        return None;
    };
    let item_ty = items.get(index)?;
    let item_index = items
        .iter()
        .take(index)
        .map(llvm_aggregate_width_for_ast_type)
        .sum();
    Some(LlvmAggregateItemBinding {
        index: item_index,
        ty: llvm_ir_type_for_ast_type(item_ty),
    })
}

pub(crate) fn llvm_struct_field_binding_for_local(
    name: &str,
    field: &str,
    ctx: &LlvmFuncCtx,
) -> Option<LlvmAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = ctx.local_types.get(name)? else {
        return None;
    };
    let struct_def = ctx.struct_defs.get(ty_name.as_str())?;
    let (index, struct_field) = struct_def
        .fields
        .iter()
        .enumerate()
        .find(|(_, item)| item.name == field)?;
    let item_index = struct_def
        .fields
        .iter()
        .take(index)
        .map(|item| llvm_aggregate_width_for_ast_type(&item.ty))
        .sum();
    Some(LlvmAggregateItemBinding {
        index: item_index,
        ty: llvm_ir_type_for_ast_type(&struct_field.ty),
    })
}

pub(crate) fn llvm_enum_payload_binding_for_local(
    name: &str,
    enum_name: &str,
    variant: &str,
    index: usize,
    ctx: &LlvmFuncCtx,
) -> Option<LlvmAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = ctx.local_types.get(name)? else {
        return None;
    };
    if ty_name != enum_name {
        return None;
    }
    let enum_def = ctx.enum_defs.get(enum_name)?;
    let variant_def = enum_def.variants.iter().find(|item| item.name == variant)?;
    let payload_ty = variant_def.payload.get(index)?;
    let item_index = variant_def
        .payload
        .iter()
        .take(index)
        .map(llvm_aggregate_width_for_ast_type)
        .sum();
    Some(LlvmAggregateItemBinding {
        index: item_index,
        ty: llvm_ir_type_for_ast_type(payload_ty),
    })
}

pub(crate) fn llvm_enum_named_binding_for_local(
    name: &str,
    enum_name: &str,
    variant: &str,
    field: &str,
    ctx: &LlvmFuncCtx,
) -> Option<LlvmAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = ctx.local_types.get(name)? else {
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
    let item_index = variant_def
        .payload
        .iter()
        .map(llvm_aggregate_width_for_ast_type)
        .sum::<usize>()
        + variant_def
            .named_payload
            .iter()
            .take(offset)
            .map(|item| llvm_aggregate_width_for_ast_type(&item.ty))
            .sum::<usize>();
    Some(LlvmAggregateItemBinding {
        index: item_index,
        ty: llvm_ir_type_for_ast_type(&named_field.ty),
    })
}

pub(crate) fn llvm_local_is_aggregate(name: &str, ctx: &LlvmFuncCtx) -> bool {
    matches!(
        ctx.local_types.get(name),
        Some(ast::Type::Tuple(_)) | Some(ast::Type::Named { .. })
    )
}

pub(crate) fn llvm_emit_aggregate_handle(
    tag: i32,
    items: &[LlvmValue],
    ctx: &mut LlvmFuncCtx,
) -> Result<LlvmValue> {
    let flattened = items
        .iter()
        .cloned()
        .map(|item| llvm_flatten_aggregate_value(ctx, item))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let handle = ctx.value();
    ctx.code.push_str(&format!(
        "  {handle} = call i64 @{}(i32 {tag}, i32 {})\n",
        NATIVE_AGG_NEW_SYMBOL,
        flattened.len()
    ));
    for (index, item) in flattened.into_iter().enumerate() {
        let status = ctx.value();
        ctx.code.push_str(&format!(
            "  {status} = call i32 @{}(i64 {handle}, i32 {index}, i64 {})\n",
            NATIVE_AGG_SET_I64_SYMBOL, item.value
        ));
    }
    Ok(LlvmValue {
        value: handle,
        ty: "i64".to_string(),
    })
}

pub(crate) fn collect_wrapped_index_candidates(
    body: &[ast::Stmt],
) -> HashMap<String, HashSet<usize>> {
    let mut out = HashMap::new();
    collect_wrapped_index_candidates_stmt(body, &mut out);
    out
}

pub(crate) fn collect_wrapped_index_candidates_stmt(
    stmts: &[ast::Stmt],
    out: &mut HashMap<String, HashSet<usize>>,
) {
    for stmt in stmts {
        match stmt {
            ast::Stmt::While { body, .. }
            | ast::Stmt::Loop { body }
            | ast::Stmt::ForIn { body, .. } => {
                collect_wrapped_index_candidates_stmt(body, out);
            }
            ast::Stmt::For {
                init,
                condition: _,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_wrapped_index_candidates_stmt(std::slice::from_ref(init.as_ref()), out);
                }
                if let Some(step) = step {
                    collect_wrapped_index_candidates_stmt(std::slice::from_ref(step.as_ref()), out);
                }
                collect_wrapped_index_candidates_stmt(body, out);
            }
            ast::Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_wrapped_index_candidates_stmt(then_body, out);
                collect_wrapped_index_candidates_stmt(else_body, out);
            }
            _ => {}
        }
    }

    for pair in stmts.windows(2) {
        let first = &pair[0];
        let second = &pair[1];
        let (target, limit) = match first {
            ast::Stmt::CompoundAssign {
                target,
                op: ast::BinaryOp::Add,
                value: ast::Expr::Int(1),
            } => match second {
                ast::Stmt::If {
                    condition:
                        ast::Expr::Binary {
                            op: ast::BinaryOp::Eq,
                            left,
                            right,
                        },
                    then_body,
                    else_body,
                } if else_body.is_empty()
                    && then_body.len() == 1
                    && matches!(
                        then_body.first(),
                        Some(ast::Stmt::Assign {
                            target: assign_target,
                            value: ast::Expr::Int(0),
                        }) if assign_target == target
                    ) =>
                {
                    let cond_target = match left.as_ref() {
                        ast::Expr::Ident(name) => Some(name),
                        _ => None,
                    };
                    let cond_limit = match right.as_ref() {
                        ast::Expr::Int(v) if *v > 0 => Some(*v as usize),
                        _ => None,
                    };
                    if cond_target == Some(target) {
                        if let Some(limit) = cond_limit {
                            (target.clone(), limit)
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                _ => continue,
            },
            _ => continue,
        };
        out.entry(target).or_default().insert(limit);
    }
}

pub(crate) fn llvm_snapshot_closure_captures(
    ctx: &mut LlvmFuncCtx,
) -> HashMap<String, LlvmCaptureBinding> {
    let visible = ctx.slots.clone();
    let mut captures = HashMap::new();
    for (name, slot) in visible {
        let ty = ctx
            .slot_tys
            .get(&name)
            .cloned()
            .unwrap_or_else(|| "i32".to_string());
        let loaded = ctx.value();
        ctx.code
            .push_str(&format!("  {loaded} = load {ty}, ptr {slot}\n"));
        let capture_slot = format!(
            "%slot_cap_{}_{}",
            native_mangle_symbol(&name),
            ctx.next_value
        );
        ctx.code.push_str(&format!(
            "  {capture_slot} = alloca {ty}\n  store {ty} {loaded}, ptr {capture_slot}\n"
        ));
        captures.insert(
            name,
            LlvmCaptureBinding {
                slot: capture_slot,
                ty,
            },
        );
    }
    captures
}

pub(crate) fn llvm_restore_shadowed_slots(
    ctx: &mut LlvmFuncCtx,
    saved: HashMap<String, Option<String>>,
    inserted_names: HashSet<String>,
) {
    for (name, prior) in saved {
        if let Some(slot) = prior {
            ctx.slots.insert(name, slot);
        } else if inserted_names.contains(&name) {
            ctx.slots.remove(&name);
        }
    }
}

pub(crate) fn llvm_emit_inlined_closure_call(
    binding: LlvmClosureBinding,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let mut saved = HashMap::<String, Option<String>>::new();
    let mut inserted = HashSet::<String>::new();
    for (name, capture) in &binding.captures {
        if !saved.contains_key(name) {
            saved.insert(name.clone(), ctx.slots.get(name).cloned());
        }
        ctx.slots.insert(name.clone(), capture.slot.clone());
        ctx.slot_tys.insert(name.clone(), capture.ty.clone());
        inserted.insert(name.clone());
    }
    for (param, arg) in binding.params.iter().zip(args.iter()) {
        let value = llvm_emit_expr(arg, ctx, string_literal_ids, task_ref_ids)?;
        let target_ty = llvm_ir_type_for_ast_type(&param.ty);
        let value = llvm_cast_value(ctx, value, &target_ty)?;
        if !saved.contains_key(&param.name) {
            saved.insert(param.name.clone(), ctx.slots.get(&param.name).cloned());
        }
        let slot = format!("%slot_{}_{}", param.name, ctx.next_value);
        ctx.declare_alloca(&slot, &target_ty);
        ctx.code.push_str(&format!(
            "  store {} {}, ptr {slot}\n",
            value.ty, value.value
        ));
        ctx.slots.insert(param.name.clone(), slot);
        ctx.slot_tys.insert(param.name.clone(), target_ty);
        inserted.insert(param.name.clone());
    }
    let result = llvm_emit_expr(&binding.body, ctx, string_literal_ids, task_ref_ids)?;
    if let Some(return_type) = &binding.return_type {
        let target_ty = llvm_ir_type_for_ast_type(return_type);
        let result = llvm_cast_value(ctx, result, &target_ty)?;
        llvm_restore_shadowed_slots(ctx, saved, inserted);
        Ok(result)
    } else {
        llvm_restore_shadowed_slots(ctx, saved, inserted);
        Ok(result)
    }
}

pub(crate) fn llvm_emit_let_pattern(
    pattern: &ast::Pattern,
    value: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<()> {
    let rendered = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
    match pattern {
        ast::Pattern::Wildcard => {}
        ast::Pattern::Ident(name) => {
            let slot = format!("%slot_{}_{}", native_mangle_symbol(name), ctx.next_value);
            ctx.declare_alloca(&slot, &rendered.ty);
            ctx.code.push_str(&format!(
                "  store {} {}, ptr {slot}\n",
                rendered.ty, rendered.value
            ));
            ctx.slots.insert(name.clone(), slot);
            ctx.slot_tys.insert(name.clone(), rendered.ty.clone());
        }
        ast::Pattern::Tuple(items) => {
            if let ast::Expr::Tuple(values) = value {
                if items.len() != values.len() {
                    bail!("native backend requires tuple pattern arity to match tuple initializer arity");
                }
                for (item, value) in items.iter().zip(values.iter()) {
                    llvm_emit_let_pattern(item, value, ctx, string_literal_ids, task_ref_ids)?;
                }
            } else if let ast::Expr::Ident(name) = value {
                for (index, item) in items.iter().enumerate() {
                    let synthetic = format!("{name}.__tuple{index}");
                    if ctx.slots.contains_key(&synthetic) {
                        llvm_emit_let_pattern(
                            item,
                            &ast::Expr::Ident(synthetic),
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                        )?;
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(&format!("__tuple{index}")).cloned())
                            .or_else(|| llvm_tuple_item_binding_for_local(name, index, ctx))
                            .ok_or_else(|| anyhow!("native backend requires tuple-bound aggregate metadata for `let` tuple destructuring"))?;
                        let handle = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                        let extracted = llvm_emit_aggregate_get(
                            ctx,
                            &handle,
                            item_binding.index,
                            &item_binding.ty,
                        )?;
                        let temp_name = format!("__agg_tuple_extract_{}_{}", name, index);
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(&temp_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &extracted.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            extracted.ty, extracted.value
                        ));
                        ctx.slots.insert(temp_name.clone(), slot);
                        ctx.slot_tys.insert(temp_name.clone(), extracted.ty.clone());
                        llvm_emit_let_pattern(
                            item,
                            &ast::Expr::Ident(temp_name),
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                        )?;
                    }
                }
            } else {
                bail!("native backend requires tuple initializer or tuple-bound local for `let` tuple destructuring");
            }
        }
        ast::Pattern::Int(expected) => {
            let cmp = ctx.value();
            ctx.code.push_str(&format!(
                "  {cmp} = icmp eq {} {}, {expected}\n",
                rendered.ty, rendered.value
            ));
        }
        ast::Pattern::Bool(expected) => {
            let cmp = ctx.value();
            let expected_i32 = if *expected { 1 } else { 0 };
            ctx.code.push_str(&format!(
                "  {cmp} = icmp eq {} {}, {expected_i32}\n",
                rendered.ty, rendered.value
            ));
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
                    let field_value =
                        llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                    let slot = format!(
                        "%slot_{}_{}",
                        native_mangle_symbol(binding_name),
                        ctx.next_value
                    );
                    ctx.declare_alloca(&slot, &field_value.ty);
                    ctx.code.push_str(&format!(
                        "  store {} {}, ptr {slot}\n",
                        field_value.ty, field_value.value
                    ));
                    ctx.slots.insert(binding_name.clone(), slot);
                    ctx.slot_tys
                        .insert(binding_name.clone(), field_value.ty.clone());
                }
            } else if let ast::Expr::Ident(name) = value {
                for (field_name, binding_name) in fields {
                    if binding_name == "_" {
                        continue;
                    }
                    if let Some(slot) = ctx.slots.get(&format!("{name}.{field_name}")).cloned() {
                        let ty = ctx
                            .slot_tys
                            .get(&format!("{name}.{field_name}"))
                            .cloned()
                            .unwrap_or_else(|| "i32".to_string());
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), ty);
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(field_name).cloned())
                            .or_else(|| llvm_struct_field_binding_for_local(name, field_name, ctx))
                            .ok_or_else(|| anyhow!("native backend requires struct-bound aggregate metadata for `let` struct destructuring"))?;
                        let handle = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                        let extracted = llvm_emit_aggregate_get(
                            ctx,
                            &handle,
                            item_binding.index,
                            &item_binding.ty,
                        )?;
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &extracted.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            extracted.ty, extracted.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), extracted.ty);
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
            let tag = variant_tag_for_key(&key, &ctx.variant_tags);
            let (cmp_ty, cmp_value) = if rendered.ty == "i64" {
                let tag_value = ctx.value();
                ctx.code.push_str(&format!(
                    "  {tag_value} = call i32 @{}(i64 {})\n",
                    NATIVE_AGG_TAG_SYMBOL, rendered.value
                ));
                ("i32".to_string(), tag_value)
            } else {
                (rendered.ty.clone(), rendered.value.clone())
            };
            let cmp = ctx.value();
            ctx.code
                .push_str(&format!("  {cmp} = icmp eq {cmp_ty} {cmp_value}, {tag}\n"));
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
                        let payload_value =
                            llvm_emit_expr(payload_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &payload_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            payload_value.ty, payload_value.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys
                            .insert(binding_name.clone(), payload_value.ty.clone());
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
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &field_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            field_value.ty, field_value.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys
                            .insert(binding_name.clone(), field_value.ty.clone());
                    }
                }
            } else if let ast::Expr::Ident(name) = value {
                for (index, binding_name) in bindings.iter().enumerate() {
                    let key = format!("{name}.__payload{index}");
                    if let Some(slot) = ctx.slots.get(&key).cloned() {
                        let ty = ctx
                            .slot_tys
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| "i32".to_string());
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), ty);
                    } else {
                        let payload_key = format!("__payload{index}");
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(&payload_key).cloned())
                            .or_else(|| {
                                llvm_enum_payload_binding_for_local(
                                    name,
                                    enum_name,
                                    variant,
                                    index,
                                    ctx,
                                )
                            })
                            .ok_or_else(|| anyhow!("native backend requires enum-bound local payloads for `let` variant destructuring"))?;
                        let handle = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                        let extracted = llvm_emit_aggregate_get(
                            ctx,
                            &handle,
                            item_binding.index,
                            &item_binding.ty,
                        )?;
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &extracted.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            extracted.ty, extracted.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), extracted.ty);
                    }
                }
                for (field_name, binding_name) in named_bindings {
                    if binding_name == "_" {
                        continue;
                    }
                    let key = format!("{name}.{field_name}");
                    if let Some(slot) = ctx.slots.get(&key).cloned() {
                        let ty = ctx
                            .slot_tys
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| "i32".to_string());
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), ty);
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(field_name).cloned())
                            .or_else(|| {
                                llvm_enum_named_binding_for_local(
                                    name,
                                    enum_name,
                                    variant,
                                    field_name,
                                    ctx,
                                )
                            })
                            .ok_or_else(|| anyhow!("native backend requires enum-bound local named payloads for `let` variant destructuring"))?;
                        let handle = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                        let extracted = llvm_emit_aggregate_get(
                            ctx,
                            &handle,
                            item_binding.index,
                            &item_binding.ty,
                        )?;
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &extracted.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            extracted.ty, extracted.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), extracted.ty);
                    }
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns.iter().find(|pattern| {
                pattern_matches_resolved_scrutinee(pattern, value, &ctx.variant_tags)
            }) {
                return llvm_emit_let_pattern(
                    matched,
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
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
