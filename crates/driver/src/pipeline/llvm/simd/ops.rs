use super::*;

pub(crate) fn llvm_emit_simd_ptr_alignment_check(
    kind: &str,
    op: &str,
    ptr_int_value: &str,
    ptr_int_ty: &str,
    ctx: &mut LlvmFuncCtx,
) {
    if !op.contains("_aligned_") {
        return;
    }
    let align = if kind == "mask32x4" { 4 } else { 16 };
    let masked = ctx.value();
    let aligned = ctx.value();
    let ok_label = ctx.label("simd_ptr_align_ok");
    let trap_label = ctx.label("simd_ptr_align_trap");
    ctx.code.push_str(&format!(
        "  {masked} = and {ptr_int_ty} {ptr_int_value}, {}\n  {aligned} = icmp eq {ptr_int_ty} {masked}, 0\n  br i1 {aligned}, label %{ok_label}, label %{trap_label}\n",
        align - 1
    ));
    ctx.code.push_str(&format!("{trap_label}:\n"));
    ctx.code
        .push_str("  call void @llvm.trap()\n  unreachable\n");
    ctx.code.push_str(&format!("{ok_label}:\n"));
}

pub(crate) fn llvm_emit_simd_ptr_memory(
    kind: &str,
    op: &str,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let lowered_ptr = llvm_emit_expr_as(
        &args[0],
        ctx,
        string_literal_ids,
        task_ref_ids,
        llvm_pointer_int_type(),
    )?;
    llvm_emit_simd_ptr_alignment_check(kind, op, &lowered_ptr.value, &lowered_ptr.ty, ctx);
    let base_ptr = {
        let ptr = ctx.value();
        ctx.code.push_str(&format!(
            "  {ptr} = inttoptr {} {} to ptr\n",
            lowered_ptr.ty, lowered_ptr.value
        ));
        ptr
    };
    let is_aligned = op.contains("_aligned_");
    let align = if is_aligned {
        if kind == "mask32x4" { 4 } else { 16 }
    } else {
        1
    };
    let vec_ty = llvm_simd_vector_type(kind).to_string();
    if op.starts_with("_load_") {
        if kind == "mask32x4" {
            let mut lanes = Vec::with_capacity(4);
            for index in 0..4 {
                let lane_ptr = if index == 0 {
                    base_ptr.clone()
                } else {
                    let next = ctx.value();
                    ctx.code.push_str(&format!(
                        "  {next} = getelementptr inbounds i8, ptr {base_ptr}, i64 {index}\n"
                    ));
                    next
                };
                let loaded = ctx.value();
                let pred = ctx.value();
                ctx.code.push_str(&format!(
                    "  {loaded} = load i8, ptr {lane_ptr}, align 1\n  {pred} = icmp ne i8 {loaded}, 0\n"
                ));
                lanes.push(pred);
            }
            let mut current = "undef".to_string();
            for (index, lane) in lanes.iter().enumerate() {
                let next = ctx.value();
                ctx.code.push_str(&format!(
                    "  {next} = insertelement {vec_ty} {current}, i1 {lane}, i32 {index}\n"
                ));
                current = next;
            }
            return Ok(LlvmValue {
                value: current,
                ty: vec_ty,
            });
        }
        let out = ctx.value();
        ctx.code.push_str(&format!(
            "  {out} = load {vec_ty}, ptr {base_ptr}, align {align}\n"
        ));
        return Ok(LlvmValue {
            value: out,
            ty: vec_ty,
        });
    }

    let value = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
    if kind == "mask32x4" {
        for index in 0..4 {
            let lane = ctx.value();
            let widened = ctx.value();
            let lane_ptr = if index == 0 {
                base_ptr.clone()
            } else {
                let next = ctx.value();
                ctx.code.push_str(&format!(
                    "  {next} = getelementptr inbounds i8, ptr {base_ptr}, i64 {index}\n"
                ));
                next
            };
            ctx.code.push_str(&format!(
                "  {lane} = extractelement {vec_ty} {}, i32 {index}\n  {widened} = zext i1 {lane} to i8\n  store i8 {widened}, ptr {lane_ptr}, align 1\n",
                value.value
            ));
        }
    } else {
        ctx.code.push_str(&format!(
            "  store {vec_ty} {}, ptr {base_ptr}, align {align}\n",
            value.value
        ));
    }
    Ok(LlvmValue {
        value: "0".to_string(),
        ty: "i32".to_string(),
    })
}

pub(crate) fn llvm_emit_simd_lane_value(
    arg: &ast::Expr,
    kind: &str,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<String> {
    if kind == "mask32x4" {
        let value = llvm_emit_expr(arg, ctx, string_literal_ids, task_ref_ids)?;
        Ok(llvm_emit_truthy_pred(ctx, &value))
    } else {
        Ok(llvm_emit_expr_as(
            arg,
            ctx,
            string_literal_ids,
            task_ref_ids,
            llvm_simd_scalar_type(kind),
        )?
        .value)
    }
}

pub(crate) fn llvm_emit_simd_ctor_from_lanes(
    kind: &str,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let vec_ty = llvm_simd_vector_type(kind).to_string();
    let lane_ty = llvm_simd_scalar_type(kind);
    let mut current = "undef".to_string();
    for (index, arg) in args.iter().enumerate() {
        let lane = llvm_emit_simd_lane_value(arg, kind, ctx, string_literal_ids, task_ref_ids)?;
        let next = ctx.value();
        ctx.code.push_str(&format!(
            "  {next} = insertelement {vec_ty} {current}, {lane_ty} {lane}, i32 {index}\n"
        ));
        current = next;
    }
    Ok(LlvmValue {
        value: current,
        ty: vec_ty,
    })
}

pub(crate) fn llvm_emit_simd_splat(
    kind: &str,
    arg: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let vec_ty = llvm_simd_vector_type(kind).to_string();
    let lane_ty = llvm_simd_scalar_type(kind);
    let lane = llvm_emit_simd_lane_value(arg, kind, ctx, string_literal_ids, task_ref_ids)?;
    let mut current = "undef".to_string();
    for index in 0..4 {
        let next = ctx.value();
        ctx.code.push_str(&format!(
            "  {next} = insertelement {vec_ty} {current}, {lane_ty} {lane}, i32 {index}\n"
        ));
        current = next;
    }
    Ok(LlvmValue {
        value: current,
        ty: vec_ty,
    })
}

pub(crate) fn llvm_emit_simd_load_from_array(
    kind: &str,
    arg: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let vec_ty = llvm_simd_vector_type(kind).to_string();
    let lane_ty = llvm_simd_scalar_type(kind);
    let mut current = "undef".to_string();
    for index in 0..4 {
        let lane_expr = ast::Expr::Index {
            base: Box::new(arg.clone()),
            index: Box::new(ast::Expr::Int(index as i128)),
        };
        let lane =
            llvm_emit_simd_lane_value(&lane_expr, kind, ctx, string_literal_ids, task_ref_ids)?;
        let next = ctx.value();
        ctx.code.push_str(&format!(
            "  {next} = insertelement {vec_ty} {current}, {lane_ty} {lane}, i32 {index}\n"
        ));
        current = next;
    }
    Ok(LlvmValue {
        value: current,
        ty: vec_ty,
    })
}

pub(crate) fn llvm_emit_simd_saturating_int_binop(
    kind: &str,
    op: &str,
    vec_ty: &str,
    scalar_ty: &str,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, vec_ty)?;
    let rhs = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, vec_ty)?;
    let mut current = "undef".to_string();
    for index in 0..4 {
        let lhs_lane = ctx.value();
        let rhs_lane = ctx.value();
        ctx.code.push_str(&format!(
            "  {lhs_lane} = extractelement {vec_ty} {}, i32 {index}\n",
            lhs.value
        ));
        ctx.code.push_str(&format!(
            "  {rhs_lane} = extractelement {vec_ty} {}, i32 {index}\n",
            rhs.value
        ));
        let clamped_lane = if kind == "i32x4" {
            let lhs_i64 = ctx.value();
            let rhs_i64 = ctx.value();
            let wide = ctx.value();
            let below = ctx.value();
            let above = ctx.value();
            let lower_sel = ctx.value();
            let upper_sel = ctx.value();
            let clamped = ctx.value();
            ctx.code
                .push_str(&format!("  {lhs_i64} = sext i32 {lhs_lane} to i64\n"));
            ctx.code
                .push_str(&format!("  {rhs_i64} = sext i32 {rhs_lane} to i64\n"));
            let wide_op = if op == "_saturating_add" { "add" } else { "sub" };
            ctx.code
                .push_str(&format!("  {wide} = {wide_op} i64 {lhs_i64}, {rhs_i64}\n"));
            ctx.code
                .push_str(&format!("  {below} = icmp slt i64 {wide}, -2147483648\n"));
            ctx.code
                .push_str(&format!("  {above} = icmp sgt i64 {wide}, 2147483647\n"));
            ctx.code.push_str(&format!(
                "  {lower_sel} = select i1 {below}, i64 -2147483648, i64 {wide}\n"
            ));
            ctx.code.push_str(&format!(
                "  {upper_sel} = select i1 {above}, i64 2147483647, i64 {lower_sel}\n"
            ));
            ctx.code
                .push_str(&format!("  {clamped} = trunc i64 {upper_sel} to i32\n"));
            clamped
        } else {
            let lhs_i64 = ctx.value();
            let rhs_i64 = ctx.value();
            ctx.code
                .push_str(&format!("  {lhs_i64} = zext i32 {lhs_lane} to i64\n"));
            ctx.code
                .push_str(&format!("  {rhs_i64} = zext i32 {rhs_lane} to i64\n"));
            if op == "_saturating_add" {
                let wide = ctx.value();
                let overflow = ctx.value();
                let clamped_i64 = ctx.value();
                let clamped = ctx.value();
                ctx.code
                    .push_str(&format!("  {wide} = add i64 {lhs_i64}, {rhs_i64}\n"));
                ctx.code
                    .push_str(&format!("  {overflow} = icmp ugt i64 {wide}, 4294967295\n"));
                ctx.code.push_str(&format!(
                    "  {clamped_i64} = select i1 {overflow}, i64 4294967295, i64 {wide}\n"
                ));
                ctx.code
                    .push_str(&format!("  {clamped} = trunc i64 {clamped_i64} to i32\n"));
                clamped
            } else {
                let underflow = ctx.value();
                let wide = ctx.value();
                let clamped_i64 = ctx.value();
                let clamped = ctx.value();
                ctx.code.push_str(&format!(
                    "  {underflow} = icmp ult i64 {lhs_i64}, {rhs_i64}\n"
                ));
                ctx.code
                    .push_str(&format!("  {wide} = sub i64 {lhs_i64}, {rhs_i64}\n"));
                ctx.code.push_str(&format!(
                    "  {clamped_i64} = select i1 {underflow}, i64 0, i64 {wide}\n"
                ));
                ctx.code
                    .push_str(&format!("  {clamped} = trunc i64 {clamped_i64} to i32\n"));
                clamped
            }
        };
        let next = ctx.value();
        ctx.code.push_str(&format!(
            "  {next} = insertelement {vec_ty} {current}, {scalar_ty} {clamped_lane}, i32 {index}\n"
        ));
        current = next;
    }
    Ok(LlvmValue {
        value: current,
        ty: vec_ty.to_string(),
    })
}

pub(crate) fn llvm_emit_simd_reduce_scalar(
    kind: &str,
    op: &str,
    vec_ty: &str,
    scalar_ty: &str,
    arg: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let input = llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, vec_ty)?;
    let mut lanes = Vec::with_capacity(4);
    for index in 0..4 {
        let lane = ctx.value();
        ctx.code.push_str(&format!(
            "  {lane} = extractelement {vec_ty} {}, i32 {index}\n",
            input.value
        ));
        lanes.push(lane);
    }
    let fold_name = match op {
        "_reduce_add" if kind == "f32x4" => "fadd",
        "_reduce_add" => "add",
        _ => "",
    };
    if !fold_name.is_empty() {
        let fold0 = ctx.value();
        let fold1 = ctx.value();
        let fold2 = ctx.value();
        ctx.code.push_str(&format!(
            "  {fold0} = {fold_name} {scalar_ty} {}, {}\n",
            lanes[0], lanes[1]
        ));
        ctx.code.push_str(&format!(
            "  {fold1} = {fold_name} {scalar_ty} {fold0}, {}\n",
            lanes[2]
        ));
        ctx.code.push_str(&format!(
            "  {fold2} = {fold_name} {scalar_ty} {fold1}, {}\n",
            lanes[3]
        ));
        return Ok(LlvmValue {
            value: fold2,
            ty: scalar_ty.to_string(),
        });
    }
    let cmp = match (kind, op) {
        ("f32x4", "_reduce_min") => "olt",
        ("f32x4", "_reduce_max") => "ogt",
        ("u32x4", "_reduce_min") => "ult",
        ("u32x4", "_reduce_max") => "ugt",
        (_, "_reduce_min") => "slt",
        (_, "_reduce_max") => "sgt",
        _ => unreachable!(),
    };
    let mut current = lanes[0].clone();
    for lane in lanes.iter().skip(1) {
        let pred = ctx.value();
        let selected = ctx.value();
        let cmp_op = if kind == "f32x4" { "fcmp" } else { "icmp" };
        ctx.code.push_str(&format!(
            "  {pred} = {cmp_op} {cmp} {scalar_ty} {lane}, {current}\n"
        ));
        ctx.code.push_str(&format!(
            "  {selected} = select i1 {pred}, {scalar_ty} {lane}, {scalar_ty} {current}\n"
        ));
        current = selected;
    }
    Ok(LlvmValue {
        value: current,
        ty: scalar_ty.to_string(),
    })
}

pub(crate) fn llvm_emit_simd_intrinsic_call(
    callee: &str,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<Option<LlvmValue>> {
    let Some((kind, op)) = llvm_parse_simd_intrinsic(callee) else {
        return Ok(None);
    };
    let vec_ty = llvm_simd_vector_type(kind).to_string();
    let scalar_ty = llvm_simd_scalar_type(kind);
    let mask_ty = llvm_simd_vector_type("mask32x4").to_string();
    let value = match op {
        "" => llvm_emit_simd_ctor_from_lanes(kind, args, ctx, string_literal_ids, task_ref_ids)?,
        "_splat" => llvm_emit_simd_splat(kind, &args[0], ctx, string_literal_ids, task_ref_ids)?,
        "_load" => {
            llvm_emit_simd_load_from_array(kind, &args[0], ctx, string_literal_ids, task_ref_ids)?
        }
        "_load_aligned_ptr"
        | "_load_unaligned_ptr"
        | "_store_aligned_ptr"
        | "_store_unaligned_ptr" => {
            llvm_emit_simd_ptr_memory(kind, op, args, ctx, string_literal_ids, task_ref_ids)?
        }
        "_saturating_add" | "_saturating_sub" => llvm_emit_simd_saturating_int_binop(
            kind,
            op,
            &vec_ty,
            scalar_ty,
            args,
            ctx,
            string_literal_ids,
            task_ref_ids,
        )?,
        "_add" | "_sub" | "_mul" | "_and" | "_or" | "_xor" => {
            let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let rhs = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let op_name = match op {
                "_add" if kind == "f32x4" => "fadd",
                "_sub" if kind == "f32x4" => "fsub",
                "_mul" if kind == "f32x4" => "fmul",
                "_add" => "add",
                "_sub" => "sub",
                "_mul" => "mul",
                "_and" => "and",
                "_or" => "or",
                "_xor" => "xor",
                _ => unreachable!(),
            };
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = {op_name} {vec_ty} {}, {}\n",
                lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: vec_ty,
            }
        }
        "_shl" | "_shr" => {
            let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let rhs =
                llvm_emit_simd_splat("i32x4", &args[1], ctx, string_literal_ids, task_ref_ids)?;
            let out = ctx.value();
            let op_name = match (kind, op) {
                ("u32x4", "_shr") => "lshr",
                (_, "_shr") => "ashr",
                _ => "shl",
            };
            ctx.code.push_str(&format!(
                "  {out} = {op_name} {vec_ty} {}, {}\n",
                lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: vec_ty,
            }
        }
        "_min" | "_max" => {
            let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let rhs = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let pred = ctx.value();
            if kind == "f32x4" {
                let cc = if op == "_min" { "olt" } else { "ogt" };
                ctx.code.push_str(&format!(
                    "  {pred} = fcmp {cc} {vec_ty} {}, {}\n",
                    lhs.value, rhs.value
                ));
            } else {
                let cc = match (kind, op) {
                    ("u32x4", "_min") => "ult",
                    ("u32x4", "_max") => "ugt",
                    (_, "_min") => "slt",
                    _ => "sgt",
                };
                ctx.code.push_str(&format!(
                    "  {pred} = icmp {cc} {vec_ty} {}, {}\n",
                    lhs.value, rhs.value
                ));
            }
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = select {mask_ty} {pred}, {vec_ty} {}, {vec_ty} {}\n",
                lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: vec_ty,
            }
        }
        "_not" => {
            let input =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let out = ctx.value();
            let literal = if kind == "mask32x4" {
                llvm_simd_bool_splat_literal()
            } else {
                llvm_simd_i32_all_ones_literal()
            };
            ctx.code.push_str(&format!(
                "  {out} = xor {vec_ty} {}, {literal}\n",
                input.value
            ));
            LlvmValue {
                value: out,
                ty: vec_ty,
            }
        }
        "_eq" | "_ne" | "_lt" | "_le" | "_gt" | "_ge" => {
            let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let rhs = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let out = ctx.value();
            if kind == "f32x4" {
                let cc = match op {
                    "_eq" => "oeq",
                    "_ne" => "une",
                    "_lt" => "olt",
                    "_le" => "ole",
                    "_gt" => "ogt",
                    "_ge" => "oge",
                    _ => unreachable!(),
                };
                ctx.code.push_str(&format!(
                    "  {out} = fcmp {cc} {vec_ty} {}, {}\n",
                    lhs.value, rhs.value
                ));
            } else {
                let cc = match op {
                    "_eq" => "eq",
                    "_ne" => "ne",
                    "_lt" if kind == "u32x4" => "ult",
                    "_le" if kind == "u32x4" => "ule",
                    "_gt" if kind == "u32x4" => "ugt",
                    "_ge" if kind == "u32x4" => "uge",
                    "_lt" => "slt",
                    "_le" => "sle",
                    "_gt" => "sgt",
                    "_ge" => "sge",
                    _ => unreachable!(),
                };
                ctx.code.push_str(&format!(
                    "  {out} = icmp {cc} {vec_ty} {}, {}\n",
                    lhs.value, rhs.value
                ));
            }
            LlvmValue {
                value: out,
                ty: mask_ty,
            }
        }
        "_select" => {
            let mask =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &mask_ty)?;
            let then_vec =
                llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let else_vec =
                llvm_emit_expr_as(&args[2], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = select {mask_ty} {}, {vec_ty} {}, {vec_ty} {}\n",
                mask.value, then_vec.value, else_vec.value
            ));
            LlvmValue {
                value: out,
                ty: vec_ty,
            }
        }
        "_shuffle" => {
            let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let rhs = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let mut current = "undef".to_string();
            for (lane_index, arg) in args[2..].iter().enumerate() {
                let selector =
                    llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, "i32")?;
                let ge_zero = ctx.value();
                let lt_eight = ctx.value();
                let in_range = ctx.value();
                let ok_label = ctx.label("simd_shuffle_ok");
                let trap_label = ctx.label("simd_shuffle_trap");
                ctx.code.push_str(&format!(
                    "  {ge_zero} = icmp sge i32 {}, 0\n",
                    selector.value
                ));
                ctx.code.push_str(&format!(
                    "  {lt_eight} = icmp slt i32 {}, 8\n",
                    selector.value
                ));
                ctx.code
                    .push_str(&format!("  {in_range} = and i1 {ge_zero}, {lt_eight}\n"));
                ctx.code.push_str(&format!(
                    "  br i1 {in_range}, label %{ok_label}, label %{trap_label}\n"
                ));
                ctx.code.push_str(&format!("{trap_label}:\n"));
                ctx.code
                    .push_str("  call void @llvm.trap()\n  unreachable\n");
                ctx.code.push_str(&format!("{ok_label}:\n"));

                let use_left = ctx.value();
                let right_index = ctx.value();
                let left_lane = ctx.value();
                let right_lane = ctx.value();
                let picked_lane = ctx.value();
                let next = ctx.value();
                ctx.code.push_str(&format!(
                    "  {use_left} = icmp slt i32 {}, 4\n",
                    selector.value
                ));
                ctx.code.push_str(&format!(
                    "  {right_index} = sub i32 {}, 4\n",
                    selector.value
                ));
                ctx.code.push_str(&format!(
                    "  {left_lane} = extractelement {vec_ty} {}, i32 {}\n",
                    lhs.value, selector.value
                ));
                ctx.code.push_str(&format!(
                    "  {right_lane} = extractelement {vec_ty} {}, i32 {right_index}\n",
                    rhs.value
                ));
                ctx.code.push_str(&format!(
                    "  {picked_lane} = select i1 {use_left}, {scalar_ty} {left_lane}, {scalar_ty} {right_lane}\n"
                ));
                ctx.code.push_str(&format!(
                    "  {next} = insertelement {vec_ty} {current}, {scalar_ty} {picked_lane}, i32 {lane_index}\n"
                ));
                current = next;
            }
            LlvmValue {
                value: current,
                ty: vec_ty,
            }
        }
        "_as_u32x4" | "_as_i32x4" | "_bitcast_f32x4" | "_bitcast_i32x4" | "_bitcast_u32x4" => {
            let (source_ty, target_ty) = match op {
                "_as_u32x4" => ("<4 x i32>", "<4 x i32>"),
                "_as_i32x4" => ("<4 x i32>", "<4 x i32>"),
                "_bitcast_f32x4" => ("<4 x i32>", "<4 x float>"),
                "_bitcast_i32x4" => ("<4 x float>", "<4 x i32>"),
                "_bitcast_u32x4" => ("<4 x float>", "<4 x i32>"),
                _ => unreachable!(),
            };
            let input =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, source_ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = bitcast {source_ty} {} to {target_ty}\n",
                input.value
            ));
            LlvmValue {
                value: out,
                ty: target_ty.to_string(),
            }
        }
        "_reduce_add" | "_reduce_min" | "_reduce_max" => llvm_emit_simd_reduce_scalar(
            kind,
            op,
            &vec_ty,
            scalar_ty,
            &args[0],
            ctx,
            string_literal_ids,
            task_ref_ids,
        )?,
        "_any" | "_all" | "_none" => {
            let input =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &mask_ty)?;
            let mut lanes = Vec::with_capacity(4);
            for index in 0..4 {
                let lane = ctx.value();
                ctx.code.push_str(&format!(
                    "  {lane} = extractelement {mask_ty} {}, i32 {index}\n",
                    input.value
                ));
                lanes.push(lane);
            }
            let fold0 = ctx.value();
            let fold1 = ctx.value();
            let fold2 = ctx.value();
            let bit_op = if op == "_all" { "and" } else { "or" };
            ctx.code.push_str(&format!(
                "  {fold0} = {bit_op} i1 {}, {}\n",
                lanes[0], lanes[1]
            ));
            ctx.code
                .push_str(&format!("  {fold1} = {bit_op} i1 {fold0}, {}\n", lanes[2]));
            ctx.code
                .push_str(&format!("  {fold2} = {bit_op} i1 {fold1}, {}\n", lanes[3]));
            let pred = if op == "_none" {
                let inverted = ctx.value();
                ctx.code
                    .push_str(&format!("  {inverted} = xor i1 {fold2}, true\n"));
                inverted
            } else {
                fold2
            };
            llvm_bool_from_pred(ctx, &pred)
        }
        "_bitmask" => {
            let input =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &mask_ty)?;
            let mut acc = "0".to_string();
            for index in 0..4 {
                let lane = ctx.value();
                ctx.code.push_str(&format!(
                    "  {lane} = extractelement {mask_ty} {}, i32 {index}\n",
                    input.value
                ));
                let lane_i32 = ctx.value();
                ctx.code
                    .push_str(&format!("  {lane_i32} = zext i1 {lane} to i32\n"));
                let shifted = ctx.value();
                ctx.code
                    .push_str(&format!("  {shifted} = shl i32 {lane_i32}, {index}\n"));
                let next = ctx.value();
                ctx.code
                    .push_str(&format!("  {next} = or i32 {acc}, {shifted}\n"));
                acc = next;
            }
            LlvmValue {
                value: acc,
                ty: "i32".to_string(),
            }
        }
        "_lane0" | "_lane1" | "_lane2" | "_lane3" => {
            let index = match op {
                "_lane0" => 0,
                "_lane1" => 1,
                "_lane2" => 2,
                "_lane3" => 3,
                _ => unreachable!(),
            };
            let input =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let lane = ctx.value();
            ctx.code.push_str(&format!(
                "  {lane} = extractelement {vec_ty} {}, i32 {index}\n",
                input.value
            ));
            if kind == "mask32x4" {
                llvm_bool_from_pred(ctx, &lane)
            } else {
                LlvmValue {
                    value: lane,
                    ty: scalar_ty.to_string(),
                }
            }
        }
        _ => {
            return Err(anyhow!(
                "unsupported llvm SIMD intrinsic lowering for `{callee}`"
            ))
        }
    };
    Ok(Some(value))
}
