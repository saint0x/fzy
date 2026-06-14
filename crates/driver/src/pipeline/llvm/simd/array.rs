use super::*;

pub(crate) fn llvm_emit_array_argument_parts(
    arg: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<Option<(LlvmValue, LlvmValue)>> {
    fn pointer_element_stride(ty: &ast::Type) -> Option<u8> {
        let ast::Type::Ptr { to, .. } = ty else {
            return None;
        };
        let element_ty = llvm_ir_type_for_ast_type(to.as_ref());
        let (_bits, _align, stride) = llvm_array_layout_for_element_ty(&element_ty);
        Some(if stride == 0 { 1 } else { stride })
    }
    fn sibling_len_binding_name(name: &str) -> Option<String> {
        for suffix in ["_borrowed", "_owned", "_out", "_inout"] {
            if let Some(stem) = name.strip_suffix(suffix) {
                return Some(format!("{stem}_len"));
            }
        }
        if let Some(stem) = name.strip_suffix("_ptr") {
            return Some(format!("{stem}_len"));
        }
        Some(format!("{name}_len"))
    }
    match arg {
        ast::Expr::Ident(name) => {
            if let Some(binding) = ctx.array_slots.get(name).cloned() {
                let ptr = ctx.value();
                ctx.code.push_str(&format!(
                    "  {ptr} = getelementptr inbounds [{} x {}], ptr {}, i32 0, i64 0\n",
                    binding.len, binding.element_ty, binding.storage
                ));
                return Ok(Some((
                    LlvmValue {
                        value: ptr,
                        ty: "ptr".to_string(),
                    },
                    LlvmValue {
                        value: binding.len.to_string(),
                        ty: "i32".to_string(),
                    },
                )));
            }
            if let Some(ptr_ty) = ctx.local_types.get(name) {
                if !matches!(ptr_ty, ast::Type::Ptr { .. }) {
                    return Ok(None);
                }
                let element_stride = pointer_element_stride(ptr_ty);
                if let Some(len_name) = sibling_len_binding_name(name) {
                    if ctx.local_types.contains_key(&len_name) {
                        let ptr = llvm_emit_expr_as(
                            arg,
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                            llvm_pointer_int_type(),
                        )?;
                        let len = llvm_emit_expr_as(
                            &ast::Expr::Ident(len_name),
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                            "i32",
                        )?;
                        let len = if let Some(element_stride) = element_stride {
                            if element_stride > 1 {
                                let count = ctx.value();
                                ctx.code.push_str(&format!(
                                    "  {count} = udiv i32 {}, {}\n",
                                    len.value, element_stride
                                ));
                                LlvmValue {
                                    value: count,
                                    ty: "i32".to_string(),
                                }
                            } else {
                                len
                            }
                        } else {
                            len
                        };
                        return Ok(Some((ptr, len)));
                    }
                }
            }
            Ok(None)
        }
        ast::Expr::ArrayLiteral(items) => {
            let storage = format!("%slot_upload_arr_{}", ctx.next_value);
            ctx.next_value += 1;
            let lowered_items = items
                .iter()
                .map(|item| llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids))
                .collect::<Result<Vec<_>>>()?;
            let element_ty = lowered_items
                .first()
                .map(|value| value.ty.clone())
                .unwrap_or_else(|| "i32".to_string());
            let len = items.len();
            ctx.declare_alloca(&storage, &format!("[{len} x {element_ty}]"));
            for (idx, item) in items.iter().enumerate() {
                let item_value =
                    llvm_emit_expr_as(item, ctx, string_literal_ids, task_ref_ids, &element_ty)?;
                let element_ptr = ctx.value();
                ctx.code.push_str(&format!(
                    "  {element_ptr} = getelementptr inbounds [{len} x {element_ty}], ptr {storage}, i32 0, i64 {idx}\n  store {element_ty} {}, ptr {element_ptr}\n",
                    item_value.value
                ));
            }
            let ptr = ctx.value();
            ctx.code.push_str(&format!(
                "  {ptr} = getelementptr inbounds [{len} x {element_ty}], ptr {storage}, i32 0, i64 0\n"
            ));
            Ok(Some((
                LlvmValue {
                    value: ptr,
                    ty: "ptr".to_string(),
                },
                LlvmValue {
                    value: len.to_string(),
                    ty: "i32".to_string(),
                },
            )))
        }
        _ => Ok(None),
    }
}

pub(crate) fn llvm_array_layout_for_element_ty(element_ty: &str) -> (u16, u8, u8) {
    match element_ty {
        "i8" => (8, 1, 1),
        "i32" | "float" => (32, 4, 4),
        "i64" | "double" => (64, 8, 8),
        _ => (32, 4, 4),
    }
}

pub(crate) fn llvm_array_binding_from_type(slot: &str, ty: &ast::Type) -> Option<LlvmArrayBinding> {
    let ast::Type::Array { elem, len } = ty else {
        return None;
    };
    let element_ty = llvm_ir_type_for_ast_type(elem);
    let (element_bits, element_align, element_stride) =
        llvm_array_layout_for_element_ty(&element_ty);
    Some(LlvmArrayBinding {
        storage: slot.to_string(),
        len: *len,
        element_ty,
        element_bits,
        element_align,
        element_stride,
    })
}

pub(crate) fn llvm_parse_array_ir_type(ty: &str) -> Option<(usize, String)> {
    let ty = ty.trim();
    let inner = ty.strip_prefix('[')?.strip_suffix(']')?;
    let (len, element_ty) = inner.split_once(" x ")?;
    let len = len.parse::<usize>().ok()?;
    Some((len, element_ty.trim().to_string()))
}

pub(crate) fn llvm_array_binding_from_ir_type(slot: &str, ty: &str) -> Option<LlvmArrayBinding> {
    let (len, element_ty) = llvm_parse_array_ir_type(ty)?;
    let (element_bits, element_align, element_stride) =
        llvm_array_layout_for_element_ty(&element_ty);
    Some(LlvmArrayBinding {
        storage: slot.to_string(),
        len,
        element_ty,
        element_bits,
        element_align,
        element_stride,
    })
}

pub(crate) fn llvm_emit_array_literal_value(
    items: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let len = items.len();
    let lowered_items = items
        .iter()
        .map(|item| llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids))
        .collect::<Result<Vec<_>>>()?;
    let element_ty = lowered_items
        .first()
        .map(|value| value.ty.clone())
        .unwrap_or_else(|| "i32".to_string());
    let array_ty = format!("[{len} x {element_ty}]");
    let storage = format!("%slot_array_literal_{}", ctx.next_value);
    ctx.declare_alloca(&storage, &array_ty);
    for (idx, item) in items.iter().enumerate() {
        let item_value =
            llvm_emit_expr_as(item, ctx, string_literal_ids, task_ref_ids, &element_ty)?;
        let element_ptr = ctx.value();
        ctx.code.push_str(&format!(
            "  {element_ptr} = getelementptr inbounds {array_ty}, ptr {storage}, i32 0, i64 {idx}\n  store {element_ty} {}, ptr {element_ptr}\n",
            item_value.value
        ));
    }
    let loaded = ctx.value();
    ctx.code
        .push_str(&format!("  {loaded} = load {array_ty}, ptr {storage}\n"));
    Ok(LlvmValue {
        value: loaded,
        ty: array_ty,
    })
}

pub(crate) fn llvm_emit_array_index_from_binding(
    binding: LlvmArrayBinding,
    index: &ast::Expr,
    index_value: &str,
    ctx: &mut LlvmFuncCtx,
) -> Result<LlvmValue> {
    if binding.len == 0 {
        return Ok(LlvmValue {
            value: llvm_zero_literal(&binding.element_ty, 0),
            ty: binding.element_ty,
        });
    }
    if let ast::Expr::Ident(index_name) = index {
        if ctx
            .wrapped_indices
            .get(index_name)
            .map(|limits| limits.contains(&binding.len))
            .unwrap_or(false)
        {
            let idx64 = ctx.value();
            let elem_ptr = ctx.value();
            let loaded = ctx.value();
            ctx.code
                .push_str(&format!("  {idx64} = sext i32 {index_value} to i64\n"));
            ctx.code.push_str(&format!(
                "  {elem_ptr} = getelementptr inbounds [{} x {}], ptr {}, i32 0, i64 {idx64}\n",
                binding.len, binding.element_ty, binding.storage
            ));
            ctx.code.push_str(&format!(
                "  {loaded} = load {}, ptr {elem_ptr}\n",
                binding.element_ty
            ));
            return Ok(LlvmValue {
                value: loaded,
                ty: binding.element_ty,
            });
        }
    }
    if let Some(const_idx) = eval_const_i32_expr(index, &ctx.const_strings) {
        if const_idx >= 0 && (const_idx as usize) < binding.len {
            let elem_ptr = ctx.value();
            let loaded = ctx.value();
            ctx.code.push_str(&format!(
                "  {elem_ptr} = getelementptr inbounds [{} x {}], ptr {}, i32 0, i64 {}\n",
                binding.len, binding.element_ty, binding.storage, const_idx
            ));
            ctx.code.push_str(&format!(
                "  {loaded} = load {}, ptr {elem_ptr}\n",
                binding.element_ty
            ));
            return Ok(LlvmValue {
                value: loaded,
                ty: binding.element_ty,
            });
        }
    }
    let in_label = ctx.label("idx.in");
    let out_label = ctx.label("idx.oob");
    let merge_label = ctx.label("idx.merge");
    let ok = ctx.value();
    ctx.code.push_str(&format!(
        "  {ok} = icmp ult i32 {index_value}, {}\n",
        binding.len
    ));
    ctx.code.push_str(&format!(
        "  br i1 {ok}, label %{in_label}, label %{out_label}\n"
    ));
    ctx.code.push_str(&format!("{in_label}:\n"));
    let idx64 = ctx.value();
    let elem_ptr = ctx.value();
    let loaded = ctx.value();
    ctx.code
        .push_str(&format!("  {idx64} = sext i32 {index_value} to i64\n"));
    ctx.code.push_str(&format!(
        "  {elem_ptr} = getelementptr inbounds [{} x {}], ptr {}, i32 0, i64 {idx64}\n",
        binding.len, binding.element_ty, binding.storage
    ));
    ctx.code.push_str(&format!(
        "  {loaded} = load {}, ptr {elem_ptr}\n",
        binding.element_ty
    ));
    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
    ctx.code.push_str(&format!("{out_label}:\n"));
    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
    ctx.code.push_str(&format!("{merge_label}:\n"));
    let selected = ctx.value();
    ctx.code.push_str(&format!(
        "  {selected} = phi {} [ {loaded}, %{in_label} ], [ {}, %{out_label} ]\n",
        binding.element_ty,
        llvm_zero_literal(&binding.element_ty, 0)
    ));
    let _ = (
        binding.element_bits,
        binding.element_align,
        binding.element_stride,
    );
    Ok(LlvmValue {
        value: selected,
        ty: binding.element_ty,
    })
}

pub(crate) fn llvm_emit_index_assign(
    base: &ast::Expr,
    index: &ast::Expr,
    value: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<()> {
    if let ast::Expr::Ident(name) = base {
        if let Some(binding) = ctx.array_slots.get(name).cloned() {
            let index_value =
                llvm_emit_expr_as(index, ctx, string_literal_ids, task_ref_ids, "i32")?;
            let stored_value = llvm_emit_expr_as(
                value,
                ctx,
                string_literal_ids,
                task_ref_ids,
                &binding.element_ty,
            )?;
            let idx64 = ctx.value();
            let elem_ptr = ctx.value();
            ctx.code.push_str(&format!(
                "  {idx64} = sext i32 {} to i64\n",
                index_value.value
            ));
            ctx.code.push_str(&format!(
                "  {elem_ptr} = getelementptr inbounds [{} x {}], ptr {}, i32 0, i64 {idx64}\n",
                binding.len, binding.element_ty, binding.storage
            ));
            ctx.code.push_str(&format!(
                "  store {} {}, ptr {elem_ptr}\n",
                binding.element_ty, stored_value.value
            ));
            return Ok(());
        }
    }
    if let Some(element_ty) = llvm_ptr_element_type(base, ctx) {
        let index_value =
            llvm_emit_expr_as(index, ctx, string_literal_ids, task_ref_ids, "i32")?.value;
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
        let stored_value =
            llvm_emit_expr_as(value, ctx, string_literal_ids, task_ref_ids, &element_ty)?;
        let index_ptr = if llvm_pointer_int_type() == "i32" {
            index_value
        } else {
            let widened = ctx.value();
            ctx.code.push_str(&format!(
                "  {widened} = sext i32 {index_value} to {}\n",
                llvm_pointer_int_type()
            ));
            widened
        };
        let element_ptr = ctx.value();
        ctx.code.push_str(&format!(
            "  {element_ptr} = getelementptr inbounds {element_ty}, ptr {base_ptr}, {} {index_ptr}\n",
            llvm_pointer_int_type()
        ));
        ctx.code.push_str(&format!(
            "  store {element_ty} {}, ptr {element_ptr}\n",
            stored_value.value
        ));
        return Ok(());
    }
    bail!("native backend cannot lower indexed assignment target")
}
