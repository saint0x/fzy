use super::*;

pub(crate) fn llvm_emit_condition_value(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<String> {
    match expr {
        ast::Expr::Group(inner) | ast::Expr::Await(inner) => {
            llvm_emit_condition_value(inner, ctx, string_literal_ids, task_ref_ids)
        }
        ast::Expr::Binary { op, left, right } => {
            let lhs = llvm_emit_expr(left, ctx, string_literal_ids, task_ref_ids)?;
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let pred = ctx.value();
            let cc = match op {
                ast::BinaryOp::Eq => Some(("eq", "oeq")),
                ast::BinaryOp::Neq => Some(("ne", "une")),
                ast::BinaryOp::Lt => Some(("slt", "olt")),
                ast::BinaryOp::Lte => Some(("sle", "ole")),
                ast::BinaryOp::Gt => Some(("sgt", "ogt")),
                ast::BinaryOp::Gte => Some(("sge", "oge")),
                _ => None,
            };
            if let Some(cc) = cc {
                if llvm_is_float_ty(&lhs.ty) {
                    ctx.code.push_str(&format!(
                        "  {pred} = fcmp {} {} {}, {}\n",
                        cc.1, lhs.ty, lhs.value, rhs.value
                    ));
                } else {
                    ctx.code.push_str(&format!(
                        "  {pred} = icmp {} {} {}, {}\n",
                        cc.0, lhs.ty, lhs.value, rhs.value
                    ));
                }
                return Ok(pred);
            }
            let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
            Ok(llvm_emit_truthy_pred(ctx, &value))
        }
        _ => {
            let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
            Ok(llvm_emit_truthy_pred(ctx, &value))
        }
    }
}
