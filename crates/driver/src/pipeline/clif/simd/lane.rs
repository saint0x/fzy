use super::*;

pub(crate) fn clif_simd_true_lane(builder: &mut FunctionBuilder) -> cranelift_codegen::ir::Value {
    builder.ins().iconst(types::I32, -1)
}

pub(crate) fn clif_simd_false_lane(builder: &mut FunctionBuilder) -> cranelift_codegen::ir::Value {
    builder.ins().iconst(types::I32, 0)
}

pub(crate) fn clif_emit_simd_lane_from_expr(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    arg: &ast::Expr,
    kind: &str,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    if kind == "mask32x4" {
        let lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
        let pred = clif_truthy_pred(builder, lowered);
        let true_lane = clif_simd_true_lane(builder);
        let false_lane = clif_simd_false_lane(builder);
        return Ok(ClifValue {
            value: builder.ins().select(pred, true_lane, false_lane),
            ty: types::I32,
        });
    }
    let lane_ty = clif_simd_lane_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd lane type for `{kind}`"))?;
    let lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
    cast_clif_value(builder, lowered, lane_ty)
}

pub(crate) fn clif_emit_simd_vector_from_lanes(
    builder: &mut FunctionBuilder,
    kind: &str,
    lanes: &[ClifValue],
) -> Result<ClifValue> {
    let vec_ty = clif_simd_vector_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd vector type for `{kind}`"))?;
    let lane_ty = clif_simd_lane_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd lane type for `{kind}`"))?;
    if lanes.len() != 4 {
        bail!(
            "expected exactly 4 SIMD lanes for `{kind}`, found {}",
            lanes.len()
        );
    }
    let first = if lanes[0].ty == lane_ty {
        lanes[0].value
    } else {
        bail!("lane type mismatch while building `{kind}`");
    };
    let mut current = builder.ins().scalar_to_vector(vec_ty, first);
    for (index, lane) in lanes.iter().enumerate().skip(1) {
        if lane.ty != lane_ty {
            bail!("lane type mismatch while building `{kind}`");
        }
        current = builder.ins().insertlane(current, lane.value, index as u8);
    }
    Ok(ClifValue {
        value: current,
        ty: vec_ty,
    })
}

pub(crate) fn clif_emit_simd_lanes(
    builder: &mut FunctionBuilder,
    value: ClifValue,
    kind: &str,
) -> Result<Vec<ClifValue>> {
    let mut lanes = Vec::with_capacity(4);
    for lane in 0..4 {
        lanes.push(clif_emit_simd_extract_lane(builder, value, kind, lane)?);
    }
    Ok(lanes)
}

pub(crate) fn clif_emit_simd_ctor_from_args(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    kind: &str,
    args: &[ast::Expr],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let mut lanes = Vec::with_capacity(args.len());
    for arg in args {
        lanes.push(clif_emit_simd_lane_from_expr(
            builder, ctx, arg, kind, locals, next_var,
        )?);
    }
    clif_emit_simd_vector_from_lanes(builder, kind, &lanes)
}

pub(crate) fn clif_emit_simd_extract_lane(
    builder: &mut FunctionBuilder,
    value: ClifValue,
    kind: &str,
    lane: u8,
) -> Result<ClifValue> {
    let lane_ty = clif_simd_lane_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd lane type for `{kind}`"))?;
    Ok(ClifValue {
        value: builder.ins().extractlane(value.value, lane),
        ty: lane_ty,
    })
}

pub(crate) fn clif_emit_simd_mask_pred(
    builder: &mut FunctionBuilder,
    lane: ClifValue,
) -> cranelift_codegen::ir::Value {
    let zero = builder.ins().iconst(types::I32, 0);
    builder.ins().icmp(IntCC::NotEqual, lane.value, zero)
}

pub(crate) fn clif_emit_simd_shuffle_lane(
    builder: &mut FunctionBuilder,
    selector: ClifValue,
    candidates: &[ClifValue],
) -> Result<ClifValue> {
    if candidates.len() != 8 {
        bail!(
            "cranelift simd shuffle expected 8 lane candidates, found {}",
            candidates.len()
        );
    }
    let selector = cast_clif_value(builder, selector, types::I32)?;
    let zero = builder.ins().iconst(types::I32, 0);
    let eight = builder.ins().iconst(types::I32, 8);
    let non_negative = builder
        .ins()
        .icmp(IntCC::SignedGreaterThanOrEqual, selector.value, zero);
    let below_upper = builder
        .ins()
        .icmp(IntCC::SignedLessThan, selector.value, eight);
    let valid = builder.ins().band(non_negative, below_upper);
    builder.ins().trapz(valid, TrapCode::unwrap_user(1));

    let mut current = candidates[0].clone();
    for (index, candidate) in candidates.iter().enumerate().skip(1) {
        let lane_index = builder.ins().iconst(types::I32, index as i64);
        let pick = builder.ins().icmp(IntCC::Equal, selector.value, lane_index);
        current = ClifValue {
            value: builder.ins().select(pick, candidate.value, current.value),
            ty: current.ty,
        };
    }
    Ok(current)
}

pub(crate) fn clif_emit_simd_compare_lane(
    builder: &mut FunctionBuilder,
    kind: &str,
    op: &str,
    left: ClifValue,
    right: ClifValue,
) -> Result<ClifValue> {
    let pred = match kind {
        "f32x4" => {
            let cc = match op {
                "_eq" => FloatCC::Equal,
                "_ne" => FloatCC::NotEqual,
                "_lt" => FloatCC::LessThan,
                "_le" => FloatCC::LessThanOrEqual,
                "_gt" => FloatCC::GreaterThan,
                "_ge" => FloatCC::GreaterThanOrEqual,
                _ => bail!("unsupported cranelift simd comparison `{kind}{op}`"),
            };
            builder.ins().fcmp(cc, left.value, right.value)
        }
        "u32x4" => {
            let cc = match op {
                "_eq" => IntCC::Equal,
                "_ne" => IntCC::NotEqual,
                "_lt" => IntCC::UnsignedLessThan,
                "_le" => IntCC::UnsignedLessThanOrEqual,
                "_gt" => IntCC::UnsignedGreaterThan,
                "_ge" => IntCC::UnsignedGreaterThanOrEqual,
                _ => bail!("unsupported cranelift simd comparison `{kind}{op}`"),
            };
            builder.ins().icmp(cc, left.value, right.value)
        }
        _ => {
            let cc = match op {
                "_eq" => IntCC::Equal,
                "_ne" => IntCC::NotEqual,
                "_lt" => IntCC::SignedLessThan,
                "_le" => IntCC::SignedLessThanOrEqual,
                "_gt" => IntCC::SignedGreaterThan,
                "_ge" => IntCC::SignedGreaterThanOrEqual,
                _ => bail!("unsupported cranelift simd comparison `{kind}{op}`"),
            };
            builder.ins().icmp(cc, left.value, right.value)
        }
    };
    Ok(ClifValue {
        value: {
            let true_lane = clif_simd_true_lane(builder);
            let false_lane = clif_simd_false_lane(builder);
            builder.ins().select(pred, true_lane, false_lane)
        },
        ty: types::I32,
    })
}

pub(crate) fn clif_emit_simd_saturating_lane(
    builder: &mut FunctionBuilder,
    kind: &str,
    op: &str,
    left: ClifValue,
    right: ClifValue,
) -> Result<ClifValue> {
    let lane_ty = types::I32;
    match kind {
        "i32x4" => {
            let wide_left = builder.ins().sextend(types::I64, left.value);
            let wide_right = builder.ins().sextend(types::I64, right.value);
            let wide = if op == "_saturating_add" {
                builder.ins().iadd(wide_left, wide_right)
            } else {
                builder.ins().isub(wide_left, wide_right)
            };
            let min_val = builder.ins().iconst(types::I64, i64::from(i32::MIN));
            let max_val = builder.ins().iconst(types::I64, i64::from(i32::MAX));
            let below = builder.ins().icmp(IntCC::SignedLessThan, wide, min_val);
            let above = builder.ins().icmp(IntCC::SignedGreaterThan, wide, max_val);
            let bounded_low = builder.ins().select(below, min_val, wide);
            let bounded = builder.ins().select(above, max_val, bounded_low);
            Ok(ClifValue {
                value: builder.ins().ireduce(lane_ty, bounded),
                ty: lane_ty,
            })
        }
        "u32x4" => {
            let wide_left = builder.ins().uextend(types::I64, left.value);
            let wide_right = builder.ins().uextend(types::I64, right.value);
            let max_val = builder.ins().iconst(types::I64, u32::MAX as i64);
            let wide = if op == "_saturating_add" {
                let sum = builder.ins().iadd(wide_left, wide_right);
                let above = builder.ins().icmp(IntCC::UnsignedGreaterThan, sum, max_val);
                builder.ins().select(above, max_val, sum)
            } else {
                let underflow = builder
                    .ins()
                    .icmp(IntCC::UnsignedLessThan, wide_left, wide_right);
                let diff = builder.ins().isub(wide_left, wide_right);
                let zero = builder.ins().iconst(types::I64, 0);
                builder.ins().select(underflow, zero, diff)
            };
            Ok(ClifValue {
                value: builder.ins().ireduce(lane_ty, wide),
                ty: lane_ty,
            })
        }
        _ => bail!("unsupported cranelift simd saturating op `{kind}{op}`"),
    }
}

pub(crate) fn clif_emit_simd_reduce_lanes(
    builder: &mut FunctionBuilder,
    kind: &str,
    op: &str,
    lanes: &[ClifValue],
) -> Result<ClifValue> {
    if lanes.is_empty() {
        bail!("cannot reduce empty SIMD lane set for `{kind}{op}`");
    }
    let mut current = lanes[0].clone();
    for lane in lanes.iter().skip(1) {
        current = match (kind, op) {
            ("f32x4", "_reduce_add") => ClifValue {
                value: builder.ins().fadd(current.value, lane.value),
                ty: types::F32,
            },
            ("f32x4", "_reduce_min") => ClifValue {
                value: builder.ins().fmin(current.value, lane.value),
                ty: types::F32,
            },
            ("f32x4", "_reduce_max") => ClifValue {
                value: builder.ins().fmax(current.value, lane.value),
                ty: types::F32,
            },
            ("u32x4", "_reduce_add") => ClifValue {
                value: builder.ins().iadd(current.value, lane.value),
                ty: types::I32,
            },
            ("u32x4", "_reduce_min") => ClifValue {
                value: builder.ins().umin(current.value, lane.value),
                ty: types::I32,
            },
            ("u32x4", "_reduce_max") => ClifValue {
                value: builder.ins().umax(current.value, lane.value),
                ty: types::I32,
            },
            (_, "_reduce_add") => ClifValue {
                value: builder.ins().iadd(current.value, lane.value),
                ty: types::I32,
            },
            (_, "_reduce_min") => ClifValue {
                value: builder.ins().smin(current.value, lane.value),
                ty: types::I32,
            },
            (_, "_reduce_max") => ClifValue {
                value: builder.ins().smax(current.value, lane.value),
                ty: types::I32,
            },
            _ => bail!("unsupported cranelift simd reduction `{kind}{op}`"),
        };
    }
    Ok(current)
}
