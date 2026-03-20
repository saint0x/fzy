use super::*;

#[derive(Clone)]
pub(super) struct LlvmClosureBinding {
    pub(super) params: Vec<ast::Param>,
    pub(super) return_type: Option<ast::Type>,
    pub(super) body: ast::Expr,
    pub(super) captures: HashMap<String, LlvmCaptureBinding>,
}

#[derive(Clone)]
pub(super) struct LlvmCaptureBinding {
    pub(super) slot: String,
    pub(super) ty: String,
}

#[derive(Clone)]
pub(super) struct LlvmValue {
    pub(super) value: String,
    pub(super) ty: String,
}

#[derive(Clone)]
pub(super) struct LlvmArrayBinding {
    pub(super) storage: String,
    pub(super) len: usize,
    pub(super) element_ty: String,
    pub(super) element_bits: u16,
    pub(super) element_align: u8,
    pub(super) element_stride: u8,
}

#[derive(Clone)]
pub(super) struct LlvmFunctionSig {
    pub(super) params: Vec<String>,
    pub(super) ret: Option<String>,
}

pub(super) fn llvm_ir_type_for_ast_type(ty: &ast::Type) -> String {
    match ty {
        ast::Type::Void | ast::Type::Never => "void".to_string(),
        ast::Type::Bool => "i8".to_string(),
        ast::Type::ISize | ast::Type::USize => {
            if std::mem::size_of::<usize>() == 8 {
                "i64".to_string()
            } else {
                "i32".to_string()
            }
        }
        ast::Type::Int { bits, .. } => format!("i{bits}"),
        ast::Type::Float { bits: 32 } => "float".to_string(),
        ast::Type::Float { bits: 64 } => "double".to_string(),
        ast::Type::Char => "i32".to_string(),
        _ => "i32".to_string(),
    }
}

pub(super) fn llvm_is_float_ty(ty: &str) -> bool {
    ty == "float" || ty == "double"
}

pub(super) fn llvm_float_literal(value: f64) -> String {
    let mut rendered = value.to_string();
    if !rendered.contains('.') && !rendered.contains('e') && !rendered.contains('E') {
        rendered.push_str(".0");
    }
    rendered
}

pub(super) fn llvm_zero_literal(ty: &str, int_fallback: i32) -> String {
    if llvm_is_float_ty(ty) {
        "0.0".to_string()
    } else {
        int_fallback.to_string()
    }
}

pub(super) fn llvm_emit_truthy_pred(ctx: &mut LlvmFuncCtx, value: &LlvmValue) -> String {
    let pred = ctx.value();
    if llvm_is_float_ty(&value.ty) {
        ctx.code.push_str(&format!(
            "  {pred} = fcmp une {} {}, 0.0\n",
            value.ty, value.value
        ));
    } else {
        ctx.code.push_str(&format!(
            "  {pred} = icmp ne {} {}, 0\n",
            value.ty, value.value
        ));
    }
    pred
}

pub(super) fn llvm_bool_from_pred(ctx: &mut LlvmFuncCtx, pred: &str) -> LlvmValue {
    let out = ctx.value();
    ctx.code
        .push_str(&format!("  {out} = zext i1 {pred} to i8\n"));
    LlvmValue {
        value: out,
        ty: "i8".to_string(),
    }
}

pub(super) fn llvm_cast_value(
    ctx: &mut LlvmFuncCtx,
    value: LlvmValue,
    target_ty: &str,
) -> Result<LlvmValue> {
    if value.ty == target_ty {
        return Ok(value);
    }
    let out = ctx.value();
    match (value.ty.as_str(), target_ty) {
        ("i8", "i32") | ("i8", "i64") | ("i32", "i64") => {
            ctx.code.push_str(&format!(
                "  {out} = sext {} {} to {target_ty}\n",
                value.ty, value.value
            ));
        }
        ("i64", "i32") | ("i32", "i8") | ("i64", "i8") => {
            ctx.code.push_str(&format!(
                "  {out} = trunc {} {} to {target_ty}\n",
                value.ty, value.value
            ));
        }
        ("i8", "float") | ("i32", "float") | ("i64", "float") => {
            ctx.code.push_str(&format!(
                "  {out} = sitofp {} {} to float\n",
                value.ty, value.value
            ));
        }
        ("i8", "double") | ("i32", "double") | ("i64", "double") => {
            ctx.code.push_str(&format!(
                "  {out} = sitofp {} {} to double\n",
                value.ty, value.value
            ));
        }
        ("float", "i32") | ("float", "i64") | ("double", "i32") | ("double", "i64") => {
            ctx.code.push_str(&format!(
                "  {out} = fptosi {} {} to {target_ty}\n",
                value.ty, value.value
            ));
        }
        ("float", "double") => {
            ctx.code.push_str(&format!(
                "  {out} = fpext float {} to double\n",
                value.value
            ));
        }
        ("double", "float") => {
            ctx.code.push_str(&format!(
                "  {out} = fptrunc double {} to float\n",
                value.value
            ));
        }
        _ => {
            return Err(anyhow!(
                "unsupported llvm cast from `{}` to `{target_ty}`",
                value.ty
            ));
        }
    }
    Ok(LlvmValue {
        value: out,
        ty: target_ty.to_string(),
    })
}

pub(super) fn llvm_emit_expr_as(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
    target_ty: &str,
) -> Result<LlvmValue> {
    let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
    llvm_cast_value(ctx, value, target_ty)
}
