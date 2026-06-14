use super::*;

pub(crate) fn resolve_field_expr(base: &ast::Expr, field: &str) -> Option<ast::Expr> {
    match base {
        ast::Expr::StructInit { fields, .. } => fields.iter().find_map(|(name, value)| {
            if name == field {
                Some(value.clone())
            } else {
                None
            }
        }),
        ast::Expr::Range {
            start,
            end,
            inclusive,
        } => match field {
            "start" => Some((**start).clone()),
            "end" => Some((**end).clone()),
            "inclusive" => Some(ast::Expr::Bool(*inclusive)),
            _ => None,
        },
        ast::Expr::FieldAccess { base, field: lhs } => {
            let resolved_base = resolve_field_expr(base, lhs)?;
            resolve_field_expr(&resolved_base, field)
        }
        ast::Expr::Group(inner) => resolve_field_expr(inner, field),
        _ => None,
    }
}

pub(crate) fn expr_symbol_name(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => Some(name.clone()),
        ast::Expr::FieldAccess { base, field } => {
            Some(format!("{}.{}", expr_symbol_name(base)?, field))
        }
        ast::Expr::Group(inner) => expr_symbol_name(inner),
        _ => None,
    }
}

pub(crate) fn native_current_namespace(function_name: &str) -> &str {
    function_name
        .rsplit_once('.')
        .map(|(namespace, _)| namespace)
        .unwrap_or("")
}

pub(crate) fn resolve_native_global_const_i32_expr(
    expr: &ast::Expr,
    current_namespace: &str,
    globals: &HashMap<String, i32>,
) -> Option<i32> {
    let symbol = expr_symbol_name(expr)?;
    globals.get(&symbol).copied().or_else(|| {
        if symbol.contains('.') || current_namespace.is_empty() {
            None
        } else {
            globals
                .get(&qualify_name(current_namespace, &symbol))
                .copied()
        }
    })
}

pub(crate) fn bindings_for_match_arm_pattern(
    pattern: &ast::Pattern,
    scrutinee: &ast::Expr,
    variant_tags: &HashMap<String, i32>,
) -> Result<Vec<ast::Stmt>> {
    match pattern {
        ast::Pattern::Tuple(items) => {
            if !pattern_has_tuple_bindings(items) {
                Ok(Vec::new())
            } else {
                Ok(vec![ast::Stmt::LetPattern {
                    pattern: pattern.clone(),
                    mutable: false,
                    ty: None,
                    value: scrutinee.clone(),
                }])
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            named_bindings,
        } => {
            if bindings.is_empty() && named_bindings.is_empty() {
                return Ok(Vec::new());
            }
            let _ = (enum_name, variant);
            Ok(vec![ast::Stmt::LetPattern {
                pattern: pattern.clone(),
                mutable: false,
                ty: None,
                value: scrutinee.clone(),
            }])
        }
        ast::Pattern::Struct { name, fields } => {
            let binding_fields = fields
                .iter()
                .filter(|(_, binding)| binding != "_")
                .collect::<Vec<_>>();
            if binding_fields.is_empty() {
                return Ok(Vec::new());
            }
            let _ = name;
            Ok(vec![ast::Stmt::LetPattern {
                pattern: pattern.clone(),
                mutable: false,
                ty: None,
                value: scrutinee.clone(),
            }])
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns.iter().find(|pattern| {
                pattern_matches_resolved_scrutinee(pattern, scrutinee, variant_tags)
            }) {
                return bindings_for_match_arm_pattern(matched, scrutinee, variant_tags);
            }
            if patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
            {
                bail!(
                    "native backend requires resolvable scrutinee for payload or struct-field bindings within or-pattern match arms"
                );
            }
            Ok(Vec::new())
        }
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Ident(_) => Ok(Vec::new()),
    }
}

pub(crate) fn verify_control_flow_cfg(cfg: &ControlFlowCfg) -> Result<()> {
    if cfg.blocks.is_empty() {
        bail!("control-flow cfg must include at least one block");
    }
    if cfg.entry >= cfg.blocks.len() {
        bail!(
            "control-flow cfg entry {} out of range (blocks={})",
            cfg.entry,
            cfg.blocks.len()
        );
    }
    let loop_map = cfg
        .loops
        .iter()
        .map(|loop_cfg| (loop_cfg.id, loop_cfg))
        .collect::<HashMap<_, _>>();
    let mut reachable = vec![false; cfg.blocks.len()];
    let mut stack = vec![cfg.entry];
    while let Some(block_id) = stack.pop() {
        if reachable[block_id] {
            continue;
        }
        reachable[block_id] = true;
        match &cfg.blocks[block_id].terminator {
            ControlFlowTerminator::Return(_) | ControlFlowTerminator::Unreachable => {}
            ControlFlowTerminator::Jump { target, edge } => {
                if *target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} jumps to invalid target {}",
                        block_id,
                        target
                    );
                }
                match edge {
                    ControlFlowEdge::Break { loop_id } => {
                        let loop_cfg = loop_map.get(loop_id).ok_or_else(|| {
                            anyhow!(
                                "control-flow cfg block {} references unknown break loop id {}",
                                block_id,
                                loop_id
                            )
                        })?;
                        if loop_cfg.break_target != *target {
                            bail!(
                                "control-flow cfg block {} break edge target {} does not match loop {} break target {}",
                                block_id,
                                target,
                                loop_id,
                                loop_cfg.break_target
                            );
                        }
                    }
                    ControlFlowEdge::Continue { loop_id } => {
                        let loop_cfg = loop_map.get(loop_id).ok_or_else(|| {
                            anyhow!(
                                "control-flow cfg block {} references unknown continue loop id {}",
                                block_id,
                                loop_id
                            )
                        })?;
                        if loop_cfg.continue_target != *target {
                            bail!(
                                "control-flow cfg block {} continue edge target {} does not match loop {} continue target {}",
                                block_id,
                                target,
                                loop_id,
                                loop_cfg.continue_target
                            );
                        }
                    }
                    ControlFlowEdge::Normal | ControlFlowEdge::LoopBack { .. } => {}
                }
                stack.push(*target);
            }
            ControlFlowTerminator::Branch {
                then_target,
                else_target,
                ..
            } => {
                if *then_target >= cfg.blocks.len() || *else_target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} has invalid branch targets ({}, {})",
                        block_id,
                        then_target,
                        else_target
                    );
                }
                stack.push(*then_target);
                stack.push(*else_target);
            }
            ControlFlowTerminator::Switch {
                cases,
                default_target,
                ..
            } => {
                if *default_target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} has invalid switch default target {}",
                        block_id,
                        default_target
                    );
                }
                for (_, target) in cases {
                    if *target >= cfg.blocks.len() {
                        bail!(
                            "control-flow cfg block {} has invalid switch case target {}",
                            block_id,
                            target
                        );
                    }
                }
                stack.push(*default_target);
                for (_, target) in cases {
                    stack.push(*target);
                }
            }
        }
    }
    for (index, is_reachable) in reachable.iter().enumerate() {
        if !is_reachable {
            bail!(
                "control-flow cfg contains unreachable declared block {}",
                index
            );
        }
    }
    Ok(())
}
