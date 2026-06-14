use super::*;

pub(crate) fn llvm_parse_simd_intrinsic(callee: &str) -> Option<(&str, &str)> {
    let body = callee.strip_prefix("simd.__")?;
    for kind in ["i32x4", "u32x4", "f32x4", "mask32x4"] {
        if let Some(op) = body.strip_prefix(kind) {
            return Some((kind, op));
        }
    }
    None
}

pub(crate) fn llvm_simd_vector_type(kind: &str) -> &'static str {
    match kind {
        "i32x4" | "u32x4" => "<4 x i32>",
        "f32x4" => "<4 x float>",
        "mask32x4" => "<4 x i1>",
        _ => "i32",
    }
}

pub(crate) fn llvm_simd_scalar_type(kind: &str) -> &'static str {
    match kind {
        "f32x4" => "float",
        "mask32x4" => "i1",
        _ => "i32",
    }
}

pub(crate) fn llvm_pointer_int_type() -> &'static str {
    if std::mem::size_of::<usize>() == 8 {
        "i64"
    } else {
        "i32"
    }
}

pub(crate) fn llvm_expr_is_fzy_str(expr: &ast::Expr, ctx: &LlvmFuncCtx) -> bool {
    match expr {
        ast::Expr::Str(_) => true,
        ast::Expr::Ident(name) => matches!(ctx.local_types.get(name), Some(ast::Type::Str)),
        ast::Expr::Group(inner) | ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            llvm_expr_is_fzy_str(inner, ctx)
        }
        _ => false,
    }
}

pub(crate) fn llvm_is_extern_c_borrowed_ptr_param(sig: &LlvmFunctionSig, index: usize) -> bool {
    sig.is_extern_c_import
        && sig
            .param_names
            .get(index)
            .is_some_and(|name| name.contains("_borrowed"))
        && sig
            .params
            .get(index)
            .is_some_and(|ty| ty == llvm_pointer_int_type())
}

pub(crate) fn llvm_emit_borrowed_str_ptr_arg(
    arg: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let string_id = llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, "i32")?;
    let ptr = ctx.value();
    let symbol = native_mangle_symbol(NATIVE_STR_PTR_SYMBOL);
    ctx.code.push_str(&format!(
        "  {ptr} = call {} @{symbol}(i32 {})\n",
        llvm_pointer_int_type(),
        string_id.value
    ));
    Ok(LlvmValue {
        value: ptr,
        ty: llvm_pointer_int_type().to_string(),
    })
}

pub(crate) fn llvm_vec_element_type(expr: &ast::Expr, ctx: &LlvmFuncCtx) -> Option<&'static str> {
    match expr {
        ast::Expr::Ident(name) => match ctx.local_types.get(name) {
            Some(ast::Type::Vec(inner)) => match inner.as_ref() {
                ast::Type::Float { bits: 32 } => Some("f32"),
                ast::Type::Int {
                    signed: true,
                    bits: 32,
                } => Some("i32"),
                ast::Type::Int {
                    signed: false,
                    bits: 32,
                } => Some("u32"),
                _ => None,
            },
            _ => None,
        },
        ast::Expr::Group(inner) | ast::Expr::Discard(inner) => llvm_vec_element_type(inner, ctx),
        ast::Expr::Call { callee, .. } => match callee.as_str() {
            "gpu.download_f32" => Some("f32"),
            "gpu.download_i32" => Some("i32"),
            "gpu.download_u32" => Some("u32"),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn llvm_ptr_element_type(expr: &ast::Expr, ctx: &LlvmFuncCtx) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => match ctx.local_types.get(name) {
            Some(ast::Type::Ptr { to, .. }) => Some(llvm_ir_type_for_ast_type(to)),
            _ => None,
        },
        ast::Expr::Group(inner) | ast::Expr::Discard(inner) => llvm_ptr_element_type(inner, ctx),
        _ => None,
    }
}

pub(crate) fn llvm_simd_bool_splat_literal() -> &'static str {
    "<i1 true, i1 true, i1 true, i1 true>"
}

pub(crate) fn llvm_simd_i32_all_ones_literal() -> &'static str {
    "<i32 -1, i32 -1, i32 -1, i32 -1>"
}
