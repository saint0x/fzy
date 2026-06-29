use super::*;

pub(crate) fn llvm_emit_binary_expr(
    op: ast::BinaryOp,
    left: &ast::Expr,
    right: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let lhs = llvm_emit_expr(left, ctx, string_literal_ids, task_ref_ids)?;
    Ok(match op {
        ast::BinaryOp::Add => {
            let rhs_raw = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids)?;
            let result_ty = if llvm_is_float_ty(&lhs.ty) {
                lhs.ty.clone()
            } else if llvm_is_float_ty(&rhs_raw.ty) {
                rhs_raw.ty.clone()
            } else {
                lhs.ty.clone()
            };
            let lhs = llvm_cast_value(ctx, lhs, &result_ty)?;
            let rhs = llvm_cast_value(ctx, rhs_raw, &result_ty)?;
            let out = ctx.value();
            let op = if llvm_is_float_ty(&result_ty) {
                "fadd"
            } else {
                "add"
            };
            ctx.code.push_str(&format!(
                "  {out} = {op} {} {}, {}\n",
                result_ty, lhs.value, rhs.value
            ));
            llvm_assert_finite(
                ctx,
                LlvmValue {
                    value: out,
                    ty: result_ty,
                },
            )?
        }
        ast::BinaryOp::Sub => {
            let rhs_raw = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids)?;
            let result_ty = if llvm_is_float_ty(&lhs.ty) {
                lhs.ty.clone()
            } else if llvm_is_float_ty(&rhs_raw.ty) {
                rhs_raw.ty.clone()
            } else {
                lhs.ty.clone()
            };
            let lhs = llvm_cast_value(ctx, lhs, &result_ty)?;
            let rhs = llvm_cast_value(ctx, rhs_raw, &result_ty)?;
            let out = ctx.value();
            let op = if llvm_is_float_ty(&result_ty) {
                "fsub"
            } else {
                "sub"
            };
            ctx.code.push_str(&format!(
                "  {out} = {op} {} {}, {}\n",
                result_ty, lhs.value, rhs.value
            ));
            llvm_assert_finite(
                ctx,
                LlvmValue {
                    value: out,
                    ty: result_ty,
                },
            )?
        }
        ast::BinaryOp::Mul => {
            let rhs_raw = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids)?;
            let result_ty = if llvm_is_float_ty(&lhs.ty) {
                lhs.ty.clone()
            } else if llvm_is_float_ty(&rhs_raw.ty) {
                rhs_raw.ty.clone()
            } else {
                lhs.ty.clone()
            };
            let lhs = llvm_cast_value(ctx, lhs, &result_ty)?;
            let rhs = llvm_cast_value(ctx, rhs_raw, &result_ty)?;
            let out = ctx.value();
            let op = if llvm_is_float_ty(&result_ty) {
                "fmul"
            } else {
                "mul"
            };
            ctx.code.push_str(&format!(
                "  {out} = {op} {} {}, {}\n",
                result_ty, lhs.value, rhs.value
            ));
            llvm_assert_finite(
                ctx,
                LlvmValue {
                    value: out,
                    ty: result_ty,
                },
            )?
        }
        ast::BinaryOp::Div => {
            let rhs_raw = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids)?;
            let result_ty = if llvm_is_float_ty(&lhs.ty) {
                lhs.ty.clone()
            } else if llvm_is_float_ty(&rhs_raw.ty) {
                rhs_raw.ty.clone()
            } else {
                lhs.ty.clone()
            };
            let lhs = llvm_cast_value(ctx, lhs, &result_ty)?;
            let rhs = llvm_cast_value(ctx, rhs_raw, &result_ty)?;
            let out = ctx.value();
            let op = if llvm_is_float_ty(&result_ty) {
                "fdiv"
            } else {
                "sdiv"
            };
            ctx.code.push_str(&format!(
                "  {out} = {op} {} {}, {}\n",
                result_ty, lhs.value, rhs.value
            ));
            llvm_assert_finite(
                ctx,
                LlvmValue {
                    value: out,
                    ty: result_ty,
                },
            )?
        }
        ast::BinaryOp::Mod => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = srem {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::BitAnd => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = and {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::BitOr => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = or {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::BitXor => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = xor {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::Shl => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = shl {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::Shr => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = ashr {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::And | ast::BinaryOp::Or => {
            let lhs_pred = llvm_emit_truthy_pred(ctx, &lhs);
            let rhs_label = ctx.label("logical.rhs");
            let short_label = ctx.label("logical.short");
            let merge_label = ctx.label("logical.merge");
            let result_slot = format!("%slot_logical_{}", ctx.next_value);
            ctx.next_value += 1;
            ctx.code.push_str(&format!("  {result_slot} = alloca i8\n"));
            match op {
                ast::BinaryOp::And => {
                    ctx.code.push_str(&format!(
                        "  br i1 {lhs_pred}, label %{rhs_label}, label %{short_label}\n"
                    ));
                    ctx.code.push_str(&format!("{short_label}:\n"));
                    ctx.code
                        .push_str(&format!("  store i8 0, ptr {result_slot}\n"));
                    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
                }
                ast::BinaryOp::Or => {
                    ctx.code.push_str(&format!(
                        "  br i1 {lhs_pred}, label %{short_label}, label %{rhs_label}\n"
                    ));
                    ctx.code.push_str(&format!("{short_label}:\n"));
                    ctx.code
                        .push_str(&format!("  store i8 1, ptr {result_slot}\n"));
                    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
                }
                _ => unreachable!(),
            }
            ctx.code.push_str(&format!("{rhs_label}:\n"));
            let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids)?;
            let rhs_pred = llvm_emit_truthy_pred(ctx, &rhs);
            let rhs_i8 = ctx.value();
            ctx.code
                .push_str(&format!("  {rhs_i8} = zext i1 {rhs_pred} to i8\n"));
            ctx.code
                .push_str(&format!("  store i8 {rhs_i8}, ptr {result_slot}\n"));
            ctx.code.push_str(&format!("  br label %{merge_label}\n"));
            ctx.code.push_str(&format!("{merge_label}:\n"));
            let out = ctx.value();
            ctx.code
                .push_str(&format!("  {out} = load i8, ptr {result_slot}\n"));
            LlvmValue {
                value: out,
                ty: "i8".to_string(),
            }
        }
        ast::BinaryOp::Eq
        | ast::BinaryOp::Neq
        | ast::BinaryOp::Lt
        | ast::BinaryOp::Lte
        | ast::BinaryOp::Gt
        | ast::BinaryOp::Gte => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let pred = ctx.value();
            if llvm_is_float_ty(&lhs.ty) {
                let cmp = match op {
                    ast::BinaryOp::Eq => "oeq",
                    ast::BinaryOp::Neq => "une",
                    ast::BinaryOp::Lt => "olt",
                    ast::BinaryOp::Lte => "ole",
                    ast::BinaryOp::Gt => "ogt",
                    ast::BinaryOp::Gte => "oge",
                    _ => unreachable!(),
                };
                ctx.code.push_str(&format!(
                    "  {pred} = fcmp {cmp} {} {}, {}\n",
                    lhs.ty, lhs.value, rhs.value
                ));
            } else {
                let cmp = match op {
                    ast::BinaryOp::Eq => "eq",
                    ast::BinaryOp::Neq => "ne",
                    ast::BinaryOp::Lt => "slt",
                    ast::BinaryOp::Lte => "sle",
                    ast::BinaryOp::Gt => "sgt",
                    ast::BinaryOp::Gte => "sge",
                    _ => unreachable!(),
                };
                ctx.code.push_str(&format!(
                    "  {pred} = icmp {cmp} {} {}, {}\n",
                    lhs.ty, lhs.value, rhs.value
                ));
            }
            llvm_bool_from_pred(ctx, &pred)
        }
    })
}
