use super::*;

pub(crate) fn clif_emit_simd_intrinsic(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    kind: &str,
    op: &str,
    args: &[ast::Expr],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let vec_ty = clif_simd_vector_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd type family `{kind}`"))?;
    let lane_ty = clif_simd_lane_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd lane family `{kind}`"))?;
    match op {
        "" => return clif_emit_simd_ctor_from_args(builder, ctx, kind, args, locals, next_var),
        "_splat" => {
            let lane =
                clif_emit_simd_lane_from_expr(builder, ctx, &args[0], kind, locals, next_var)?;
            return Ok(ClifValue {
                value: builder.ins().splat(vec_ty, lane.value),
                ty: vec_ty,
            });
        }
        "_load" => {
            if let ast::Expr::ArrayLiteral(items) = &args[0] {
                return clif_emit_simd_ctor_from_args(builder, ctx, kind, items, locals, next_var);
            }
            if let ast::Expr::Ident(name) = &args[0] {
                if let Some(binding) = ctx.array_bindings.get(name).cloned() {
                    let mut lanes = Vec::with_capacity(binding.len.min(4));
                    for index in 0..binding.len.min(4) {
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            binding.stack_slot,
                            (index as i32) * i32::from(binding.element_stride),
                        );
                        let loaded =
                            builder
                                .ins()
                                .load(binding.element_ty, MemFlags::new(), ptr, 0);
                        let lane = if kind == "mask32x4" {
                            let zero = builder.ins().iconst(binding.element_ty, 0);
                            let pred = builder.ins().icmp(IntCC::NotEqual, loaded, zero);
                            let true_lane = clif_simd_true_lane(builder);
                            let false_lane = clif_simd_false_lane(builder);
                            ClifValue {
                                value: builder.ins().select(pred, true_lane, false_lane),
                                ty: types::I32,
                            }
                        } else {
                            cast_clif_value(
                                builder,
                                ClifValue {
                                    value: loaded,
                                    ty: binding.element_ty,
                                },
                                lane_ty,
                            )?
                        };
                        lanes.push(lane);
                    }
                    return clif_emit_simd_vector_from_lanes(builder, kind, &lanes);
                }
                if let Some(ast::Type::Array { elem, len }) = clif_local_type(ctx, name) {
                    if *len == 4 {
                        if let Some(ptr_binding) = locals.get(name).copied() {
                            let element_ty = ast_signature_type_to_clif_type(elem.as_ref())
                                .ok_or_else(|| {
                                    anyhow!("unsupported array element type for `{name}`")
                                })?;
                            let element_stride = if element_ty == types::I8 {
                                1
                            } else if element_ty == types::I16 {
                                2
                            } else {
                                4
                            };
                            let base_ptr = builder.use_var(ptr_binding.var);
                            let mut lanes = Vec::with_capacity(4);
                            for index in 0..4 {
                                let addr = if index == 0 {
                                    base_ptr
                                } else {
                                    builder.ins().iadd_imm(
                                        base_ptr,
                                        (index as i64) * i64::from(element_stride),
                                    )
                                };
                                let loaded =
                                    builder.ins().load(element_ty, MemFlags::new(), addr, 0);
                                let lane = if kind == "mask32x4" {
                                    let zero = builder.ins().iconst(element_ty, 0);
                                    let pred = builder.ins().icmp(IntCC::NotEqual, loaded, zero);
                                    let true_lane = clif_simd_true_lane(builder);
                                    let false_lane = clif_simd_false_lane(builder);
                                    ClifValue {
                                        value: builder.ins().select(pred, true_lane, false_lane),
                                        ty: types::I32,
                                    }
                                } else {
                                    cast_clif_value(
                                        builder,
                                        ClifValue {
                                            value: loaded,
                                            ty: element_ty,
                                        },
                                        lane_ty,
                                    )?
                                };
                                lanes.push(lane);
                            }
                            return clif_emit_simd_vector_from_lanes(builder, kind, &lanes);
                        }
                    }
                }
            }
            bail!("cranelift simd load currently requires fixed-array-backed values")
        }
        "_load_aligned_ptr"
        | "_load_unaligned_ptr"
        | "_store_aligned_ptr"
        | "_store_unaligned_ptr" => {
            return clif_emit_simd_ptr_memory(builder, ctx, kind, op, args, locals, next_var);
        }
        _ => {}
    }

    let vector_args = match op {
        "_add" | "_sub" | "_mul" | "_min" | "_max" | "_and" | "_or" | "_xor"
        | "_saturating_add" | "_saturating_sub" | "_eq" | "_ne" | "_lt" | "_le" | "_gt" | "_ge" => {
            2
        }
        "_select" => 3,
        "_shuffle" => 2,
        "_shl" | "_shr" | "_not" | "_as_u32x4" | "_as_i32x4" | "_bitcast_f32x4"
        | "_bitcast_i32x4" | "_bitcast_u32x4" | "_reduce_add" | "_reduce_min" | "_reduce_max"
        | "_any" | "_all" | "_none" | "_bitmask" | "_lane0" | "_lane1" | "_lane2" | "_lane3" => 1,
        _ => args.len(),
    };
    let mut lowered = Vec::with_capacity(vector_args);
    for arg in args.iter().take(vector_args) {
        lowered.push(clif_emit_expr(builder, ctx, arg, locals, next_var)?);
    }

    match op {
        "_add" | "_sub" | "_mul" | "_min" | "_max" | "_and" | "_or" | "_xor" | "_not" | "_shl"
        | "_shr" | "_eq" | "_ne" | "_lt" | "_le" | "_gt" | "_ge" | "_select" | "_shuffle"
        | "_saturating_add" | "_saturating_sub" | "_reduce_add" | "_reduce_min" | "_reduce_max"
        | "_any" | "_all" | "_none" | "_bitmask" | "_lane0" | "_lane1" | "_lane2" | "_lane3" => {}
        "_as_u32x4" | "_as_i32x4" => {
            return Ok(ClifValue {
                value: lowered[0].value,
                ty: vec_ty,
            });
        }
        "_bitcast_f32x4" | "_bitcast_i32x4" | "_bitcast_u32x4" => {
            return Ok(ClifValue {
                value: builder
                    .ins()
                    .bitcast(vec_ty, MemFlags::new(), lowered[0].value),
                ty: vec_ty,
            });
        }
        _ => {
            bail!("cranelift lowering does not support `simd.__{kind}{op}` yet");
        }
    }

    if matches!(
        op,
        "_reduce_add"
            | "_reduce_min"
            | "_reduce_max"
            | "_any"
            | "_all"
            | "_none"
            | "_bitmask"
            | "_lane0"
            | "_lane1"
            | "_lane2"
            | "_lane3"
    ) {
        let lanes = clif_emit_simd_lanes(builder, lowered[0], kind)?;
        return match op {
            "_reduce_add" | "_reduce_min" | "_reduce_max" => {
                clif_emit_simd_reduce_lanes(builder, kind, op, &lanes)
            }
            "_any" => {
                let mut pred = clif_emit_simd_mask_pred(builder, lanes[0].clone());
                for lane in lanes.iter().skip(1) {
                    let lane_pred = clif_emit_simd_mask_pred(builder, lane.clone());
                    pred = builder.ins().bor(pred, lane_pred);
                }
                Ok(bool_to_i8(builder, pred))
            }
            "_all" => {
                let mut pred = clif_emit_simd_mask_pred(builder, lanes[0].clone());
                for lane in lanes.iter().skip(1) {
                    let lane_pred = clif_emit_simd_mask_pred(builder, lane.clone());
                    pred = builder.ins().band(pred, lane_pred);
                }
                Ok(bool_to_i8(builder, pred))
            }
            "_none" => {
                let mut pred = clif_emit_simd_mask_pred(builder, lanes[0].clone());
                for lane in lanes.iter().skip(1) {
                    let lane_pred = clif_emit_simd_mask_pred(builder, lane.clone());
                    pred = builder.ins().bor(pred, lane_pred);
                }
                let zero = builder.ins().iconst(types::I8, 0);
                let not_pred = builder.ins().icmp(IntCC::Equal, pred, zero);
                Ok(bool_to_i8(builder, not_pred))
            }
            "_bitmask" => {
                let mut mask = builder.ins().iconst(types::I32, 0);
                for (index, lane) in lanes.iter().enumerate() {
                    let lane_pred = clif_emit_simd_mask_pred(builder, lane.clone());
                    let bit = bool_to_i8(builder, lane_pred);
                    let wide = builder.ins().uextend(types::I32, bit.value);
                    let shifted = if index == 0 {
                        wide
                    } else {
                        builder.ins().ishl_imm(wide, index as i64)
                    };
                    mask = builder.ins().bor(mask, shifted);
                }
                Ok(ClifValue {
                    value: mask,
                    ty: types::I32,
                })
            }
            "_lane0" | "_lane1" | "_lane2" | "_lane3" => {
                let index = match op {
                    "_lane0" => 0,
                    "_lane1" => 1,
                    "_lane2" => 2,
                    _ => 3,
                };
                if kind == "mask32x4" {
                    let pred = clif_emit_simd_mask_pred(builder, lanes[index].clone());
                    Ok(bool_to_i8(builder, pred))
                } else {
                    Ok(lanes[index].clone())
                }
            }
            _ => unreachable!(),
        };
    }

    if op == "_select" {
        let mask_vec = cast_clif_value(
            builder,
            lowered[0],
            clif_simd_vector_type("mask32x4").unwrap_or(types::I32X4),
        )?;
        let then_bits = cast_clif_value(builder, lowered[1], types::I32X4)?;
        let else_bits = cast_clif_value(builder, lowered[2], types::I32X4)?;
        let inverted_mask = builder.ins().bnot(mask_vec.value);
        let masked_then = builder.ins().band(mask_vec.value, then_bits.value);
        let masked_else = builder.ins().band(inverted_mask, else_bits.value);
        let blended_bits = builder.ins().bor(masked_then, masked_else);
        return if kind == "f32x4" {
            Ok(ClifValue {
                value: builder.ins().bitcast(vec_ty, MemFlags::new(), blended_bits),
                ty: vec_ty,
            })
        } else {
            Ok(ClifValue {
                value: blended_bits,
                ty: vec_ty,
            })
        };
    }

    let lhs_lanes = clif_emit_simd_lanes(builder, lowered[0], kind)?;
    let rhs_lanes = if lowered.len() > 1 {
        Some(clif_emit_simd_lanes(builder, lowered[1], kind)?)
    } else {
        None
    };
    let shift_amount = if matches!(op, "_shl" | "_shr") {
        let shift_expr = clif_emit_expr(builder, ctx, &args[1], locals, next_var)?;
        Some(cast_clif_value(builder, shift_expr, types::I32)?)
    } else {
        None
    };
    let shuffle_selectors = if op == "_shuffle" {
        let mut selectors = Vec::with_capacity(4);
        for lane_index in 0..4 {
            let selector_expr =
                clif_emit_expr(builder, ctx, &args[lane_index + 2], locals, next_var)?;
            selectors.push(cast_clif_value(builder, selector_expr, types::I32)?);
        }
        Some(selectors)
    } else {
        None
    };
    let mut out_lanes = Vec::with_capacity(4);
    for lane_index in 0..4 {
        let lhs_lane = lhs_lanes[lane_index].clone();
        let lane = match op {
            "_add" => match kind {
                "f32x4" => ClifValue {
                    value: builder.ins().fadd(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                _ => ClifValue {
                    value: builder.ins().iadd(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
            },
            "_sub" => match kind {
                "f32x4" => ClifValue {
                    value: builder.ins().fsub(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                _ => ClifValue {
                    value: builder.ins().isub(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
            },
            "_mul" => match kind {
                "f32x4" => ClifValue {
                    value: builder.ins().fmul(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                _ => ClifValue {
                    value: builder.ins().imul(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
            },
            "_min" => match kind {
                "f32x4" => ClifValue {
                    value: builder.ins().fmin(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                "u32x4" => ClifValue {
                    value: builder.ins().umin(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                _ => ClifValue {
                    value: builder.ins().smin(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
            },
            "_max" => match kind {
                "f32x4" => ClifValue {
                    value: builder.ins().fmax(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                "u32x4" => ClifValue {
                    value: builder.ins().umax(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                _ => ClifValue {
                    value: builder.ins().smax(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
            },
            "_and" => ClifValue {
                value: builder.ins().band(
                    lhs_lane.value,
                    rhs_lanes.as_ref().unwrap()[lane_index].value,
                ),
                ty: lane_ty,
            },
            "_or" => ClifValue {
                value: builder.ins().bor(
                    lhs_lane.value,
                    rhs_lanes.as_ref().unwrap()[lane_index].value,
                ),
                ty: lane_ty,
            },
            "_xor" => ClifValue {
                value: builder.ins().bxor(
                    lhs_lane.value,
                    rhs_lanes.as_ref().unwrap()[lane_index].value,
                ),
                ty: lane_ty,
            },
            "_not" => ClifValue {
                value: builder.ins().bnot(lhs_lane.value),
                ty: lane_ty,
            },
            "_shl" => {
                let amount = shift_amount
                    .clone()
                    .ok_or_else(|| anyhow!("missing cranelift simd shift amount"))?;
                ClifValue {
                    value: builder.ins().ishl(lhs_lane.value, amount.value),
                    ty: lane_ty,
                }
            }
            "_shr" => {
                let amount = shift_amount
                    .clone()
                    .ok_or_else(|| anyhow!("missing cranelift simd shift amount"))?;
                let value = if kind == "u32x4" {
                    builder.ins().ushr(lhs_lane.value, amount.value)
                } else {
                    builder.ins().sshr(lhs_lane.value, amount.value)
                };
                ClifValue { value, ty: lane_ty }
            }
            "_eq" | "_ne" | "_lt" | "_le" | "_gt" | "_ge" => clif_emit_simd_compare_lane(
                builder,
                kind,
                op,
                lhs_lane,
                rhs_lanes.as_ref().unwrap()[lane_index].clone(),
            )?,
            "_select" => {
                bail!("cranelift lane-wise simd select should have been handled earlier")
            }
            "_shuffle" => {
                let selector = shuffle_selectors
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing cranelift simd shuffle selectors"))?
                    [lane_index]
                    .clone();
                let mut candidates = lhs_lanes.clone();
                candidates.extend(rhs_lanes.as_ref().unwrap().iter().cloned());
                clif_emit_simd_shuffle_lane(builder, selector, &candidates)?
            }
            "_saturating_add" | "_saturating_sub" => clif_emit_simd_saturating_lane(
                builder,
                kind,
                op,
                lhs_lane,
                rhs_lanes.as_ref().unwrap()[lane_index].clone(),
            )?,
            _ => bail!("unsupported cranelift simd op `{kind}{op}`"),
        };
        out_lanes.push(lane);
    }
    let result_kind = if matches!(op, "_eq" | "_ne" | "_lt" | "_le" | "_gt" | "_ge") {
        "mask32x4"
    } else {
        kind
    };
    clif_emit_simd_vector_from_lanes(builder, result_kind, &out_lanes)
}
