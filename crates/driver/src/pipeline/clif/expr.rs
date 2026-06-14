use super::*;

#[path = "expr/access.rs"]
mod access;
#[path = "expr/binary.rs"]
mod binary;
#[path = "expr/call.rs"]
mod call;

use self::access::{clif_emit_field_expr, clif_emit_index_expr};
use self::binary::clif_emit_binary_expr;
use self::call::clif_emit_call_expr;

pub(crate) fn clif_emit_expr(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    expr: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    Ok(match expr {
        ast::Expr::Int(v) => {
            let ty = if i32::try_from(*v).is_ok() {
                types::I32
            } else {
                types::I64
            };
            ClifValue {
                value: builder.ins().iconst(ty, *v as i64),
                ty,
            }
        }
        ast::Expr::Float { value, bits } => {
            if bits.unwrap_or(64) == 32 {
                ClifValue {
                    value: builder.ins().f32const(*value as f32),
                    ty: types::F32,
                }
            } else {
                ClifValue {
                    value: builder.ins().f64const(*value),
                    ty: types::F64,
                }
            }
        }
        ast::Expr::Char(v) => ClifValue {
            value: builder.ins().iconst(types::I32, *v as i64),
            ty: types::I32,
        },
        ast::Expr::Bool(v) => ClifValue {
            value: builder.ins().iconst(types::I8, if *v { 1 } else { 0 }),
            ty: types::I8,
        },
        ast::Expr::Str(value) => ClifValue {
            value: builder.ins().iconst(
                pointer_sized_clif_type(),
                ctx.string_literal_ids.get(value).copied().unwrap_or(0) as i64,
            ),
            ty: pointer_sized_clif_type(),
        },
        ast::Expr::Ident(name) => {
            if let Some(binding) = locals.get(name).copied() {
                ClifValue {
                    value: builder.use_var(binding.var),
                    ty: binding.ty,
                }
            } else if let Some(value) = ctx.const_strings.get(name).cloned() {
                ClifValue {
                    value: builder.ins().iconst(
                        default_int_clif_type(),
                        ctx.string_literal_ids.get(&value).copied().unwrap_or(0) as i64,
                    ),
                    ty: default_int_clif_type(),
                }
            } else if let Some(value) =
                resolve_native_global_const_i32_expr(expr, ctx.current_namespace, ctx.globals)
            {
                ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), value as i64),
                    ty: default_int_clif_type(),
                }
            } else if let Some(data_id) = ctx.mutable_globals.get(name).copied() {
                let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                ClifValue {
                    value: builder.ins().load(types::I32, MemFlags::new(), ptr, 0),
                    ty: types::I32,
                }
            } else if let Some(value) = ctx.globals.get(name).copied() {
                ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), value as i64),
                    ty: default_int_clif_type(),
                }
            } else if let Some(task_ref) = ctx.task_ref_ids.get(name).copied() {
                ClifValue {
                    value: builder
                        .ins()
                        .iconst(default_int_clif_type(), task_ref as i64),
                    ty: default_int_clif_type(),
                }
            } else {
                ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), 0),
                    ty: default_int_clif_type(),
                }
            }
        }
        ast::Expr::Group(inner) => clif_emit_expr(builder, ctx, inner, locals, next_var)?,
        ast::Expr::Await(inner) => clif_emit_expr(builder, ctx, inner, locals, next_var)?,
        ast::Expr::Discard(inner) => {
            let _ = clif_emit_expr(builder, ctx, inner, locals, next_var)?;
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::Closure {
            params,
            return_type,
            body,
        } => {
            let captures = clif_snapshot_closure_captures(builder, locals, next_var);
            let name = format!("__closure_{}", *next_var);
            ctx.closures.insert(
                name,
                ClifClosureBinding {
                    params: params.clone(),
                    return_type: return_type.clone(),
                    body: (**body).clone(),
                    captures,
                },
            );
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::Unary { op, expr } => {
            let value = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
            match op {
                ast::UnaryOp::Plus => value,
                ast::UnaryOp::Neg => {
                    if value.ty == types::F32 || value.ty == types::F64 {
                        let zero = if value.ty == types::F32 {
                            builder.ins().f32const(0.0)
                        } else {
                            builder.ins().f64const(0.0)
                        };
                        let lowered = builder.ins().fsub(zero, value.value);
                        clif_assert_finite(
                            builder,
                            ClifValue {
                                value: lowered,
                                ty: value.ty,
                            },
                        )
                    } else {
                        let zero = builder.ins().iconst(value.ty, 0);
                        ClifValue {
                            value: builder.ins().isub(zero, value.value),
                            ty: value.ty,
                        }
                    }
                }
                ast::UnaryOp::Not => {
                    let pred = clif_truthy_pred(builder, value);
                    let pred = builder.ins().bnot(pred);
                    bool_to_i8(builder, pred)
                }
                ast::UnaryOp::BitNot => {
                    if !value.ty.is_int() {
                        bail!("native backend bitwise not requires integer operand");
                    }
                    let all_ones = builder.ins().iconst(value.ty, -1);
                    ClifValue {
                        value: builder.ins().bxor(value.value, all_ones),
                        ty: value.ty,
                    }
                }
            }
        }
        ast::Expr::FieldAccess { base, field } => {
            clif_emit_field_expr(builder, ctx, expr, base, field, locals, next_var)?
        }
        ast::Expr::Tuple(items) => {
            let mut rendered = Vec::with_capacity(items.len());
            for item in items {
                rendered.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
            }
            clif_emit_aggregate_handle(builder, ctx, 0, &rendered)?
        }
        ast::Expr::StructInit { fields, .. } => {
            let mut rendered = Vec::with_capacity(fields.len());
            for (_, value) in fields {
                rendered.push(clif_emit_expr(builder, ctx, value, locals, next_var)?);
            }
            clif_emit_aggregate_handle(builder, ctx, 0, &rendered)?
        }
        ast::Expr::EnumInit {
            enum_name,
            variant,
            payload,
            named_payload,
        } => {
            let mut rendered = Vec::with_capacity(payload.len() + named_payload.len());
            for value in payload {
                rendered.push(clif_emit_expr(builder, ctx, value, locals, next_var)?);
            }
            for (_, value) in named_payload {
                rendered.push(clif_emit_expr(builder, ctx, value, locals, next_var)?);
            }
            let key = format!("{enum_name}::{variant}");
            clif_emit_aggregate_handle(
                builder,
                ctx,
                variant_tag_for_key(&key, ctx.variant_tags),
                &rendered,
            )?
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr: _,
        } => clif_emit_expr(builder, ctx, try_expr, locals, next_var)?,
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let cond = clif_emit_expr(builder, ctx, condition, locals, next_var)?;
            let cond_pred = clif_truthy_pred(builder, cond);

            let then_block = builder.create_block();
            let else_block = builder.create_block();
            let merge_block = builder.create_block();
            builder
                .ins()
                .brif(cond_pred, then_block, &[], else_block, &[]);

            builder.switch_to_block(then_block);
            let then_value = clif_emit_expr(builder, ctx, then_expr, locals, next_var)?;
            builder.append_block_param(merge_block, then_value.ty);
            builder.ins().jump(merge_block, &[then_value.value]);

            builder.switch_to_block(else_block);
            let else_value = clif_emit_expr(builder, ctx, else_expr, locals, next_var)?;
            let else_value = cast_clif_value(builder, else_value, then_value.ty)?;
            builder.ins().jump(merge_block, &[else_value.value]);

            builder.seal_block(then_block);
            builder.seal_block(else_block);
            builder.switch_to_block(merge_block);
            builder.seal_block(merge_block);
            ClifValue {
                value: builder.block_params(merge_block)[0],
                ty: then_value.ty,
            }
        }
        ast::Expr::Range { start, .. } => clif_emit_expr(builder, ctx, start, locals, next_var)?,
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                let _ = clif_emit_expr(builder, ctx, item, locals, next_var)?;
            }
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::ObjectLiteral(fields) => {
            let map_new = ctx
                .function_ids
                .get("map.new")
                .copied()
                .ok_or_else(|| anyhow!("missing runtime import lowering for `map.new`"))?;
            let map_set = ctx
                .function_ids
                .get("map.set")
                .copied()
                .ok_or_else(|| anyhow!("missing runtime import lowering for `map.set`"))?;
            let map_ref = ctx.module.declare_func_in_func(map_new, builder.func);
            let map_call = builder.ins().call(map_ref, &[]);
            let map_handle = builder.inst_results(map_call)[0];
            let set_ref = ctx.module.declare_func_in_func(map_set, builder.func);
            for (key, value) in fields {
                let key_id = i64::from(ctx.string_literal_ids.get(key).copied().unwrap_or(0));
                let key_value = builder.ins().iconst(default_int_clif_type(), key_id);
                let lowered = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                let lowered = cast_clif_value(builder, lowered, default_int_clif_type())?;
                let _ = builder
                    .ins()
                    .call(set_ref, &[map_handle, key_value, lowered.value]);
            }
            ClifValue {
                value: map_handle,
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::Index { base, index } => {
            clif_emit_index_expr(builder, ctx, base, index, locals, next_var)?
        }
        ast::Expr::Binary { op, left, right } => {
            clif_emit_binary_expr(builder, ctx, *op, left, right, locals, next_var)?
        }
        ast::Expr::Call { callee, args } => {
            clif_emit_call_expr(builder, ctx, callee, args, locals, next_var)?
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            let linear_terminated = clif_emit_linear_stmts(builder, ctx, body, locals, next_var)?;
            if linear_terminated {
                let continuation = builder.create_block();
                builder.switch_to_block(continuation);
                builder.seal_block(continuation);
            }
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        _ => ClifValue {
            value: builder.ins().iconst(default_int_clif_type(), 0),
            ty: default_int_clif_type(),
        },
    })
}
