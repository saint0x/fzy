use super::*;

pub(super) fn clif_emit_binary_expr(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    op: ast::BinaryOp,
    left: &ast::Expr,
    right: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let lhs = clif_emit_expr(builder, ctx, left, locals, next_var)?;
    Ok(match op {
        ast::BinaryOp::Add => {
            let rhs_raw = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let result_ty = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                lhs.ty
            } else if rhs_raw.ty == types::F32 || rhs_raw.ty == types::F64 {
                rhs_raw.ty
            } else {
                lhs.ty
            };
            let lhs = cast_clif_value(builder, lhs, result_ty)?;
            let rhs = cast_clif_value(builder, rhs_raw, result_ty)?;
            if result_ty == types::F32 || result_ty == types::F64 {
                let lowered = builder.ins().fadd(lhs.value, rhs.value);
                clif_assert_finite(
                    builder,
                    ClifValue {
                        value: lowered,
                        ty: result_ty,
                    },
                )
            } else {
                ClifValue {
                    value: builder.ins().iadd(lhs.value, rhs.value),
                    ty: result_ty,
                }
            }
        }
        ast::BinaryOp::Sub => {
            let rhs_raw = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let result_ty = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                lhs.ty
            } else if rhs_raw.ty == types::F32 || rhs_raw.ty == types::F64 {
                rhs_raw.ty
            } else {
                lhs.ty
            };
            let lhs = cast_clif_value(builder, lhs, result_ty)?;
            let rhs = cast_clif_value(builder, rhs_raw, result_ty)?;
            if result_ty == types::F32 || result_ty == types::F64 {
                let lowered = builder.ins().fsub(lhs.value, rhs.value);
                clif_assert_finite(
                    builder,
                    ClifValue {
                        value: lowered,
                        ty: result_ty,
                    },
                )
            } else {
                ClifValue {
                    value: builder.ins().isub(lhs.value, rhs.value),
                    ty: result_ty,
                }
            }
        }
        ast::BinaryOp::Mul => {
            let rhs_raw = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let result_ty = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                lhs.ty
            } else if rhs_raw.ty == types::F32 || rhs_raw.ty == types::F64 {
                rhs_raw.ty
            } else {
                lhs.ty
            };
            let lhs = cast_clif_value(builder, lhs, result_ty)?;
            let rhs = cast_clif_value(builder, rhs_raw, result_ty)?;
            if result_ty == types::F32 || result_ty == types::F64 {
                let lowered = builder.ins().fmul(lhs.value, rhs.value);
                clif_assert_finite(
                    builder,
                    ClifValue {
                        value: lowered,
                        ty: result_ty,
                    },
                )
            } else {
                ClifValue {
                    value: builder.ins().imul(lhs.value, rhs.value),
                    ty: result_ty,
                }
            }
        }
        ast::BinaryOp::Div => {
            let rhs_raw = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let result_ty = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                lhs.ty
            } else if rhs_raw.ty == types::F32 || rhs_raw.ty == types::F64 {
                rhs_raw.ty
            } else {
                lhs.ty
            };
            let lhs = cast_clif_value(builder, lhs, result_ty)?;
            let rhs = cast_clif_value(builder, rhs_raw, result_ty)?;
            if result_ty == types::F32 || result_ty == types::F64 {
                let lowered = builder.ins().fdiv(lhs.value, rhs.value);
                clif_assert_finite(
                    builder,
                    ClifValue {
                        value: lowered,
                        ty: result_ty,
                    },
                )
            } else {
                ClifValue {
                    value: builder.ins().sdiv(lhs.value, rhs.value),
                    ty: result_ty,
                }
            }
        }
        ast::BinaryOp::Mod => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            ClifValue {
                value: builder.ins().srem(lhs.value, rhs.value),
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::BitAnd => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            ClifValue {
                value: builder.ins().band(lhs.value, rhs.value),
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::BitOr => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            ClifValue {
                value: builder.ins().bor(lhs.value, rhs.value),
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::BitXor => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            ClifValue {
                value: builder.ins().bxor(lhs.value, rhs.value),
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::Shl => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            ClifValue {
                value: builder.ins().ishl(lhs.value, rhs.value),
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::Shr => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            ClifValue {
                value: builder.ins().sshr(lhs.value, rhs.value),
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::And => {
            let lhs_pred = clif_truthy_pred(builder, lhs);
            let rhs_block = builder.create_block();
            let short_block = builder.create_block();
            let merge_block = builder.create_block();
            builder.append_block_param(merge_block, types::I8);
            builder
                .ins()
                .brif(lhs_pred, rhs_block, &[], short_block, &[]);

            builder.switch_to_block(short_block);
            let false_val = builder.ins().iconst(types::I8, 0);
            builder.ins().jump(merge_block, &[false_val]);

            builder.switch_to_block(rhs_block);
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs_pred = clif_truthy_pred(builder, rhs);
            let rhs_bool = bool_to_i8(builder, rhs_pred);
            builder.ins().jump(merge_block, &[rhs_bool.value]);

            builder.seal_block(short_block);
            builder.seal_block(rhs_block);
            builder.switch_to_block(merge_block);
            builder.seal_block(merge_block);
            ClifValue {
                value: builder.block_params(merge_block)[0],
                ty: types::I8,
            }
        }
        ast::BinaryOp::Or => {
            let lhs_pred = clif_truthy_pred(builder, lhs);
            let rhs_block = builder.create_block();
            let short_block = builder.create_block();
            let merge_block = builder.create_block();
            builder.append_block_param(merge_block, types::I8);
            builder
                .ins()
                .brif(lhs_pred, short_block, &[], rhs_block, &[]);

            builder.switch_to_block(short_block);
            let true_val = builder.ins().iconst(types::I8, 1);
            builder.ins().jump(merge_block, &[true_val]);

            builder.switch_to_block(rhs_block);
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs_pred = clif_truthy_pred(builder, rhs);
            let rhs_bool = bool_to_i8(builder, rhs_pred);
            builder.ins().jump(merge_block, &[rhs_bool.value]);

            builder.seal_block(short_block);
            builder.seal_block(rhs_block);
            builder.switch_to_block(merge_block);
            builder.seal_block(merge_block);
            ClifValue {
                value: builder.block_params(merge_block)[0],
                ty: types::I8,
            }
        }
        ast::BinaryOp::Eq => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                builder.ins().fcmp(FloatCC::Equal, lhs.value, rhs.value)
            } else {
                builder.ins().icmp(IntCC::Equal, lhs.value, rhs.value)
            };
            bool_to_i8(builder, pred)
        }
        ast::BinaryOp::Neq => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                builder.ins().fcmp(FloatCC::NotEqual, lhs.value, rhs.value)
            } else {
                builder.ins().icmp(IntCC::NotEqual, lhs.value, rhs.value)
            };
            bool_to_i8(builder, pred)
        }
        ast::BinaryOp::Lt => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                builder.ins().fcmp(FloatCC::LessThan, lhs.value, rhs.value)
            } else {
                builder
                    .ins()
                    .icmp(IntCC::SignedLessThan, lhs.value, rhs.value)
            };
            bool_to_i8(builder, pred)
        }
        ast::BinaryOp::Lte => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                builder
                    .ins()
                    .fcmp(FloatCC::LessThanOrEqual, lhs.value, rhs.value)
            } else {
                builder
                    .ins()
                    .icmp(IntCC::SignedLessThanOrEqual, lhs.value, rhs.value)
            };
            bool_to_i8(builder, pred)
        }
        ast::BinaryOp::Gt => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                builder
                    .ins()
                    .fcmp(FloatCC::GreaterThan, lhs.value, rhs.value)
            } else {
                builder
                    .ins()
                    .icmp(IntCC::SignedGreaterThan, lhs.value, rhs.value)
            };
            bool_to_i8(builder, pred)
        }
        ast::BinaryOp::Gte => {
            let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
            let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
            let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                builder
                    .ins()
                    .fcmp(FloatCC::GreaterThanOrEqual, lhs.value, rhs.value)
            } else {
                builder
                    .ins()
                    .icmp(IntCC::SignedGreaterThanOrEqual, lhs.value, rhs.value)
            };
            bool_to_i8(builder, pred)
        }
    })
}
