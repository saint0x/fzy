use super::*;

pub(crate) fn llvm_ir_type_for_ast_type(ty: &ast::Type) -> String {
    let pointer_ty = if std::mem::size_of::<usize>() == 8 {
        "i64".to_string()
    } else {
        "i32".to_string()
    };
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
        ast::Type::Array { elem, len } => {
            format!("[{len} x {}]", llvm_ir_type_for_ast_type(elem))
        }
        ast::Type::Ptr { .. } | ast::Type::Ref { .. } | ast::Type::Slice(_) => pointer_ty,
        ast::Type::SimdVector(shape) => match shape.element {
            ast::SimdElement::I32 | ast::SimdElement::U32 => format!("<{} x i32>", shape.lanes),
            ast::SimdElement::F32 => format!("<{} x float>", shape.lanes),
        },
        ast::Type::SimdMask(shape) => format!("<{} x i1>", shape.lanes),
        ast::Type::Char => "i32".to_string(),
        ast::Type::Tuple(_) | ast::Type::Named { .. } => pointer_ty,
        _ => "i32".to_string(),
    }
}

pub(crate) fn llvm_is_float_ty(ty: &str) -> bool {
    ty == "float" || ty == "double"
}

pub(crate) fn llvm_float_literal(value: f64) -> String {
    let mut rendered = value.to_string();
    if !rendered.contains('.') && !rendered.contains('e') && !rendered.contains('E') {
        rendered.push_str(".0");
    }
    rendered
}

pub(crate) fn llvm_zero_literal(ty: &str, int_fallback: i32) -> String {
    if llvm_is_float_ty(ty) {
        "0.0".to_string()
    } else {
        int_fallback.to_string()
    }
}

pub(crate) fn llvm_emit_truthy_pred(ctx: &mut LlvmFuncCtx, value: &LlvmValue) -> String {
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

pub(crate) fn llvm_bool_from_pred(ctx: &mut LlvmFuncCtx, pred: &str) -> LlvmValue {
    let out = ctx.value();
    ctx.code
        .push_str(&format!("  {out} = zext i1 {pred} to i8\n"));
    LlvmValue {
        value: out,
        ty: "i8".to_string(),
    }
}

pub(crate) fn llvm_cast_value(
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
            let value = llvm_assert_finite(ctx, value)?;
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

pub(crate) fn llvm_encode_gpu_launch_arg(
    arg: &ast::Expr,
    layout: &str,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    match layout {
        "i32" => {
            let value = llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, "i32")?;
            llvm_cast_value(ctx, value, llvm_pointer_int_type())
        }
        "u32" => {
            let value = llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, "i32")?;
            if llvm_pointer_int_type() == "i32" {
                return Ok(LlvmValue {
                    value: value.value,
                    ty: "i32".to_string(),
                });
            }
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = zext i32 {} to {}\n",
                value.value,
                llvm_pointer_int_type()
            ));
            Ok(LlvmValue {
                value: out,
                ty: llvm_pointer_int_type().to_string(),
            })
        }
        "f32" => {
            let value = llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, "float")?;
            let bits = ctx.value();
            ctx.code.push_str(&format!(
                "  {bits} = bitcast float {} to i32\n",
                value.value
            ));
            if llvm_pointer_int_type() == "i32" {
                return Ok(LlvmValue {
                    value: bits,
                    ty: "i32".to_string(),
                });
            }
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = zext i32 {bits} to {}\n",
                llvm_pointer_int_type()
            ));
            Ok(LlvmValue {
                value: out,
                ty: llvm_pointer_int_type().to_string(),
            })
        }
        layout if layout.starts_with("slice_") => {
            let value = llvm_emit_expr(arg, ctx, string_literal_ids, task_ref_ids)?;
            llvm_cast_value(ctx, value, llvm_pointer_int_type())
        }
        _ => {
            let value = llvm_emit_expr(arg, ctx, string_literal_ids, task_ref_ids)?;
            llvm_cast_value(ctx, value, llvm_pointer_int_type())
        }
    }
}

pub(crate) fn llvm_assert_finite(ctx: &mut LlvmFuncCtx, value: LlvmValue) -> Result<LlvmValue> {
    if !llvm_is_float_ty(&value.ty) {
        return Ok(value);
    }
    let neg_limit = if value.ty == "float" {
        "-3.4028234663852886e+38"
    } else {
        "-1.7976931348623157e+308"
    };
    let pos_limit = if value.ty == "float" {
        "3.4028234663852886e+38"
    } else {
        "1.7976931348623157e+308"
    };
    let lower = ctx.value();
    let upper = ctx.value();
    let finite = ctx.value();
    let ok_label = ctx.label("float.finite");
    let trap_label = ctx.label("float.trap");
    ctx.code.push_str(&format!(
        "  {lower} = fcmp oge {} {}, {neg_limit}\n",
        value.ty, value.value
    ));
    ctx.code.push_str(&format!(
        "  {upper} = fcmp ole {} {}, {pos_limit}\n",
        value.ty, value.value
    ));
    ctx.code
        .push_str(&format!("  {finite} = and i1 {lower}, {upper}\n"));
    ctx.code.push_str(&format!(
        "  br i1 {finite}, label %{ok_label}, label %{trap_label}\n"
    ));
    ctx.code.push_str(&format!("{trap_label}:\n"));
    ctx.code
        .push_str("  call void @llvm.trap()\n  unreachable\n");
    ctx.code.push_str(&format!("{ok_label}:\n"));
    Ok(value)
}

