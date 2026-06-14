use super::*;

pub(crate) fn render_native_data_op(op: &NativeDataOp) -> String {
    match &op.kind {
        NativeDataOpKind::ArrayLiteral {
            binding,
            len,
            element_bits,
            element_align,
            element_stride,
            memory,
            alias,
        } => format!(
            "array.literal binding={binding} len={len} bits={element_bits} align={element_align} stride={element_stride} memory={memory:?} alias={alias:?} boundary={:?}",
            op.effect_boundary
        ),
        NativeDataOpKind::ArrayIndexLoad {
            binding,
            index,
            bounds,
        } => format!(
            "array.index.load binding={binding} index={index} bounds={bounds:?} boundary={:?}",
            op.effect_boundary
        ),
        NativeDataOpKind::StringViewCall {
            callee,
            foldable,
            alias,
        } => format!(
            "string.view.call callee={callee} foldable={foldable} alias={alias:?} boundary={:?}",
            op.effect_boundary
        ),
        NativeDataOpKind::RuntimeBoundaryCall { callee, arity } => format!(
            "runtime.boundary.call callee={callee} arity={arity} boundary={:?}",
            op.effect_boundary
        ),
    }
}

pub(crate) fn index_expr_shape(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::Int(value) => value.to_string(),
        ast::Expr::Ident(name) => name.clone(),
        ast::Expr::Group(inner) => index_expr_shape(inner),
        _ => "<expr>".to_string(),
    }
}

pub(crate) fn infer_array_element_layout(items: &[ast::Expr]) -> (u16, u8, u8) {
    let mut bits = 32u16;
    for item in items {
        if let ast::Expr::Int(value) = item {
            if *value < i128::from(i32::MIN) || *value > i128::from(i32::MAX) {
                bits = bits.max(64);
            }
        }
    }
    let stride = if bits <= 8 {
        1
    } else if bits <= 16 {
        2
    } else if bits <= 32 {
        4
    } else {
        8
    };
    (bits, stride, stride)
}

pub(crate) fn collect_native_data_ops_from_expr(
    expr: &ast::Expr,
    array_lengths: &HashMap<String, usize>,
    const_strings: &HashMap<String, String>,
    out: &mut Vec<NativeDataOp>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if let Some(import) = native_runtime_import_for_callee(callee) {
                out.push(NativeDataOp {
                    kind: NativeDataOpKind::RuntimeBoundaryCall {
                        callee: callee.clone(),
                        arity: import.arity,
                    },
                    effect_boundary: NativeEffectBoundary::CapabilityRuntimeImport,
                });
            } else if is_native_data_plane_string_call(callee) {
                let foldable = eval_const_i32_call(callee, args, const_strings).is_some()
                    || eval_const_string_call(callee, args, const_strings).is_some();
                out.push(NativeDataOp {
                    kind: NativeDataOpKind::StringViewCall {
                        callee: callee.clone(),
                        foldable,
                        alias: NativeAliasClass::LocalNoEscape,
                    },
                    effect_boundary: NativeEffectBoundary::Local,
                });
            }
            for arg in args {
                collect_native_data_ops_from_expr(arg, array_lengths, const_strings, out);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            let mut nested_array_lengths = array_lengths.clone();
            let mut nested_const_strings = const_strings.clone();
            for stmt in body {
                collect_native_data_ops_from_stmt(
                    stmt,
                    &mut nested_array_lengths,
                    &mut nested_const_strings,
                    out,
                );
            }
        }
        ast::Expr::Index { base, index } => {
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(len) = array_lengths.get(name) {
                    let bounds = match index.as_ref() {
                        ast::Expr::Int(value) => usize::try_from(*value)
                            .ok()
                            .filter(|idx| idx < len)
                            .map(|_| NativeBoundsPolicy::ProvenInRange)
                            .unwrap_or(NativeBoundsPolicy::Checked),
                        _ => NativeBoundsPolicy::Checked,
                    };
                    out.push(NativeDataOp {
                        kind: NativeDataOpKind::ArrayIndexLoad {
                            binding: name.clone(),
                            index: index_expr_shape(index),
                            bounds,
                        },
                        effect_boundary: NativeEffectBoundary::Local,
                    });
                }
            }
            collect_native_data_ops_from_expr(base, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(index, array_lengths, const_strings, out);
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_native_data_ops_from_expr(base, array_lengths, const_strings, out)
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
            }
        }
        ast::Expr::EnumInit { payload, .. } | ast::Expr::ArrayLiteral(payload) => {
            for value in payload {
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
            }
        }
        ast::Expr::Closure { body, .. }
        | ast::Expr::Group(body)
        | ast::Expr::Await(body)
        | ast::Expr::Discard(body) => {
            collect_native_data_ops_from_expr(body, array_lengths, const_strings, out)
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_native_data_ops_from_expr(try_expr, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(catch_expr, array_lengths, const_strings, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(then_expr, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(else_expr, array_lengths, const_strings, out);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_native_data_ops_from_expr(expr, array_lengths, const_strings, out)
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_native_data_ops_from_expr(left, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(right, array_lengths, const_strings, out);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_native_data_ops_from_expr(start, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(end, array_lengths, const_strings, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

pub(crate) fn collect_native_data_ops_from_stmt(
    stmt: &ast::Stmt,
    array_lengths: &mut HashMap<String, usize>,
    const_strings: &mut HashMap<String, String>,
    out: &mut Vec<NativeDataOp>,
) {
    match stmt {
        ast::Stmt::Let {
            name,
            value,
            mutable: _,
            ..
        } => {
            match value {
                ast::Expr::ArrayLiteral(items) => {
                    let (bits, align, stride) = infer_array_element_layout(items);
                    array_lengths.insert(name.clone(), items.len());
                    out.push(NativeDataOp {
                        kind: NativeDataOpKind::ArrayLiteral {
                            binding: name.clone(),
                            len: items.len(),
                            element_bits: bits,
                            element_align: align,
                            element_stride: stride,
                            memory: NativeMemoryClass::Stack,
                            alias: NativeAliasClass::LocalNoEscape,
                        },
                        effect_boundary: NativeEffectBoundary::Local,
                    });
                }
                ast::Expr::Str(value) => {
                    const_strings.insert(name.clone(), value.clone());
                }
                _ => {
                    const_strings.remove(name);
                }
            }
            collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
        }
        ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => {
            collect_native_data_ops_from_expr(value, array_lengths, const_strings, out)
        }
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
            for stmt in then_body {
                collect_native_data_ops_from_stmt(stmt, array_lengths, const_strings, out);
            }
            for stmt in else_body {
                collect_native_data_ops_from_stmt(stmt, array_lengths, const_strings, out);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
            for stmt in body {
                collect_native_data_ops_from_stmt(stmt, array_lengths, const_strings, out);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_native_data_ops_from_stmt(init, array_lengths, const_strings, out);
            }
            if let Some(condition) = condition {
                collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
            }
            if let Some(step) = step {
                collect_native_data_ops_from_stmt(step, array_lengths, const_strings, out);
            }
            for stmt in body {
                collect_native_data_ops_from_stmt(stmt, array_lengths, const_strings, out);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_native_data_ops_from_expr(iterable, array_lengths, const_strings, out);
            for stmt in body {
                collect_native_data_ops_from_stmt(stmt, array_lengths, const_strings, out);
            }
        }
        ast::Stmt::Loop { body } => {
            for stmt in body {
                collect_native_data_ops_from_stmt(stmt, array_lengths, const_strings, out);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_native_data_ops_from_expr(scrutinee, array_lengths, const_strings, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_native_data_ops_from_expr(guard, array_lengths, const_strings, out);
                }
                collect_native_data_ops_from_expr(&arm.value, array_lengths, const_strings, out);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

pub(crate) fn collect_native_data_ops_for_function(function: &hir::TypedFunction) -> Vec<NativeDataOp> {
    let mut out = Vec::new();
    let mut array_lengths = HashMap::<String, usize>::new();
    let mut const_strings = HashMap::<String, String>::new();

    for stmt in &function.body {
        collect_native_data_ops_from_stmt(stmt, &mut array_lengths, &mut const_strings, &mut out);
    }
    out
}

