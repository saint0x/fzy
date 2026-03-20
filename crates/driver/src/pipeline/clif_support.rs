use super::*;
use anyhow::{bail, Result};
use std::collections::HashMap;

use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::{types, InstBuilder, TrapCode, Type as ClifType};
use cranelift_frontend::FunctionBuilder;

use super::ClifValue;

fn variant_tag(variant: &str) -> i32 {
    (variant.bytes().fold(0u32, |acc, byte| {
        acc.wrapping_mul(33).wrapping_add(byte as u32)
    }) & 0x7fff_ffff) as i32
}

pub(super) fn variant_tag_for_key(key: &str, variant_tags: &HashMap<String, i32>) -> i32 {
    variant_tags
        .get(key)
        .copied()
        .unwrap_or_else(|| variant_tag(key))
}

pub(super) struct ClifLoweringCtx<'a> {
    pub(super) module: &'a mut ObjectModule,
    pub(super) function_ids: &'a HashMap<String, cranelift_module::FuncId>,
    pub(super) function_signatures: &'a HashMap<String, ClifFunctionSignature>,
    pub(super) string_literal_ids: &'a HashMap<String, i32>,
    pub(super) task_ref_ids: &'a HashMap<String, i32>,
    pub(super) globals: &'a HashMap<String, i32>,
    pub(super) variant_tags: &'a HashMap<String, i32>,
    pub(super) mutable_globals: &'a HashMap<String, cranelift_module::DataId>,
    pub(super) current_return_ty: Option<ClifType>,
    pub(super) closures: HashMap<String, ClifClosureBinding>,
    pub(super) array_bindings: HashMap<String, ClifArrayBinding>,
    pub(super) const_strings: HashMap<String, String>,
}

pub(super) fn lower_cranelift_ir(
    fir: &fir::FirModule,
    enforce_contract_checks: bool,
) -> Result<String> {
    let plan = build_native_canonical_plan(fir, enforce_contract_checks);
    let mut out = String::new();
    for function in &fir.typed_functions {
        if is_extern_c_import_decl(function) {
            continue;
        }
        if let Some(data_ops) = plan.data_ops_by_function.get(&function.name) {
            for op in data_ops {
                let _ = writeln!(&mut out, "; canonical.dataop {}", render_native_data_op(op));
            }
        }
        let _ = writeln!(
            &mut out,
            "function %{}() -> i32 {{",
            native_mangle_symbol(&function.name)
        );
        match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => {
                for (block_id, block) in cfg.blocks.iter().enumerate() {
                    let _ = writeln!(&mut out, "block{block_id}:");
                    for stmt in &block.stmts {
                        let _ = writeln!(&mut out, "  ; {:?}", stmt);
                    }
                    match &block.terminator {
                        ControlFlowTerminator::Return(Some(expr)) => {
                            let _ = writeln!(&mut out, "  return {:?}", expr);
                        }
                        ControlFlowTerminator::Return(None) => {
                            if function.name == "main" {
                                let fallback = plan
                                    .forced_main_return
                                    .or(fir.entry_return_const_i32)
                                    .unwrap_or(0);
                                let _ = writeln!(&mut out, "  return {}", fallback);
                            } else {
                                let _ = writeln!(&mut out, "  return 0");
                            }
                        }
                        ControlFlowTerminator::Jump { target, edge } => {
                            let _ = writeln!(&mut out, "  jump block{} ; {:?}", target, edge);
                        }
                        ControlFlowTerminator::Branch {
                            condition,
                            then_target,
                            else_target,
                        } => {
                            let _ = writeln!(
                                &mut out,
                                "  br {:?}, block{}, block{}",
                                condition, then_target, else_target
                            );
                        }
                        ControlFlowTerminator::Switch {
                            scrutinee,
                            cases,
                            default_target,
                        } => {
                            let rendered_cases = cases
                                .iter()
                                .map(|(value, target)| format!("{value}->block{target}"))
                                .collect::<Vec<_>>()
                                .join(", ");
                            let _ = writeln!(
                                &mut out,
                                "  switch {:?}, [{}], default=block{}",
                                scrutinee, rendered_cases, default_target
                            );
                        }
                        ControlFlowTerminator::Unreachable => {
                            let _ = writeln!(&mut out, "  trap");
                        }
                    }
                }
            }
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        }
        out.push_str("}\n\n");
    }
    if out.is_empty() {
        let fallback = plan
            .forced_main_return
            .or(fir.entry_return_const_i32)
            .unwrap_or(0);
        return Ok(format!(
            "function %main() -> i32 {{\nblock0:\n  return {fallback}\n}}\n"
        ));
    }
    Ok(out)
}

pub(super) fn clif_emit_function_cfg(
    builder: &mut FunctionBuilder,
    module: &mut ObjectModule,
    function_ids: &HashMap<String, cranelift_module::FuncId>,
    function_signatures: &HashMap<String, ClifFunctionSignature>,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
    globals: &HashMap<String, i32>,
    variant_tags: &HashMap<String, i32>,
    mutable_globals: &HashMap<String, cranelift_module::DataId>,
    current_return_ty: Option<ClifType>,
    cfg: &ControlFlowCfg,
    entry_block: cranelift_codegen::ir::Block,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
    forced_return_i32: Option<i32>,
) -> Result<()> {
    let mut ctx = ClifLoweringCtx {
        module,
        function_ids,
        function_signatures,
        string_literal_ids,
        task_ref_ids,
        globals,
        variant_tags,
        mutable_globals,
        current_return_ty,
        closures: HashMap::new(),
        array_bindings: HashMap::new(),
        const_strings: HashMap::new(),
    };
    clif_emit_cfg(
        builder,
        &mut ctx,
        cfg,
        entry_block,
        locals,
        current_return_ty,
        next_var,
        forced_return_i32,
    )
}

fn clif_emit_cfg(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    cfg: &ControlFlowCfg,
    entry_block: cranelift_codegen::ir::Block,
    locals: &mut HashMap<String, LocalBinding>,
    return_ty: Option<ClifType>,
    next_var: &mut usize,
    forced_return_i32: Option<i32>,
) -> Result<()> {
    let mut clif_blocks = Vec::with_capacity(cfg.blocks.len());
    for block_id in 0..cfg.blocks.len() {
        if block_id == cfg.entry {
            clif_blocks.push(entry_block);
        } else {
            clif_blocks.push(builder.create_block());
        }
    }

    let mut predecessor_count = vec![0usize; cfg.blocks.len()];
    for block in &cfg.blocks {
        match &block.terminator {
            ControlFlowTerminator::Return(_) | ControlFlowTerminator::Unreachable => {}
            ControlFlowTerminator::Jump { target, .. } => {
                predecessor_count[*target] += 1;
            }
            ControlFlowTerminator::Branch {
                then_target,
                else_target,
                ..
            } => {
                predecessor_count[*then_target] += 1;
                predecessor_count[*else_target] += 1;
            }
            ControlFlowTerminator::Switch {
                cases,
                default_target,
                ..
            } => {
                predecessor_count[*default_target] += 1;
                for (_, target) in cases {
                    predecessor_count[*target] += 1;
                }
            }
        }
    }

    let mut observed_predecessors = vec![0usize; cfg.blocks.len()];
    let mut sealed = vec![false; cfg.blocks.len()];
    if predecessor_count[cfg.entry] == 0 {
        builder.seal_block(clif_blocks[cfg.entry]);
        sealed[cfg.entry] = true;
    }

    let mut emitted = vec![false; cfg.blocks.len()];
    let mut queue = vec![cfg.entry];
    while let Some(block_id) = queue.pop() {
        if emitted[block_id] {
            continue;
        }
        emitted[block_id] = true;
        builder.switch_to_block(clif_blocks[block_id]);
        let linear_terminated =
            clif_emit_linear_stmts(builder, ctx, &cfg.blocks[block_id].stmts, locals, next_var)?;
        if linear_terminated {
            emitted[block_id] = true;
            continue;
        }
        match &cfg.blocks[block_id].terminator {
            ControlFlowTerminator::Return(Some(expr)) => {
                if let Some(return_ty) = return_ty {
                    let value = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                    let value = cast_clif_value(builder, value, return_ty)?;
                    builder.ins().return_(&[value.value]);
                } else {
                    builder.ins().return_(&[]);
                }
            }
            ControlFlowTerminator::Return(None) => {
                if let Some(return_ty) = return_ty {
                    let ret = if return_ty == types::I32 {
                        builder
                            .ins()
                            .iconst(types::I32, forced_return_i32.unwrap_or(0) as i64)
                    } else {
                        zero_for_type(builder, return_ty)
                    };
                    builder.ins().return_(&[ret]);
                } else {
                    builder.ins().return_(&[]);
                }
            }
            ControlFlowTerminator::Jump { target, .. } => {
                builder.ins().jump(clif_blocks[*target], &[]);
                observed_predecessors[*target] += 1;
                if !sealed[*target] && observed_predecessors[*target] >= predecessor_count[*target]
                {
                    builder.seal_block(clif_blocks[*target]);
                    sealed[*target] = true;
                }
                queue.push(*target);
            }
            ControlFlowTerminator::Branch {
                condition,
                then_target,
                else_target,
            } => {
                let cond_val = clif_emit_expr(builder, ctx, condition, locals, next_var)?;
                let cond = clif_truthy_pred(builder, cond_val);
                builder.ins().brif(
                    cond,
                    clif_blocks[*then_target],
                    &[],
                    clif_blocks[*else_target],
                    &[],
                );
                observed_predecessors[*then_target] += 1;
                observed_predecessors[*else_target] += 1;
                if !sealed[*then_target]
                    && observed_predecessors[*then_target] >= predecessor_count[*then_target]
                {
                    builder.seal_block(clif_blocks[*then_target]);
                    sealed[*then_target] = true;
                }
                if !sealed[*else_target]
                    && observed_predecessors[*else_target] >= predecessor_count[*else_target]
                {
                    builder.seal_block(clif_blocks[*else_target]);
                    sealed[*else_target] = true;
                }
                queue.push(*else_target);
                queue.push(*then_target);
            }
            ControlFlowTerminator::Switch {
                scrutinee,
                cases,
                default_target,
            } => {
                let cond_val = clif_emit_expr(builder, ctx, scrutinee, locals, next_var)?;
                let cond_val = cast_clif_value(builder, cond_val, default_int_clif_type())?;
                let mut switch = Switch::new();
                for (value, target) in cases {
                    switch.set_entry(*value as u128, clif_blocks[*target]);
                }
                switch.emit(builder, cond_val.value, clif_blocks[*default_target]);
                for (_, target) in cases {
                    observed_predecessors[*target] += 1;
                    if !sealed[*target]
                        && observed_predecessors[*target] >= predecessor_count[*target]
                    {
                        builder.seal_block(clif_blocks[*target]);
                        sealed[*target] = true;
                    }
                    queue.push(*target);
                }
                observed_predecessors[*default_target] += 1;
                if !sealed[*default_target]
                    && observed_predecessors[*default_target] >= predecessor_count[*default_target]
                {
                    builder.seal_block(clif_blocks[*default_target]);
                    sealed[*default_target] = true;
                }
                queue.push(*default_target);
            }
            ControlFlowTerminator::Unreachable => {
                if let Some(return_ty) = return_ty {
                    let ret = zero_for_type(builder, return_ty);
                    builder.ins().return_(&[ret]);
                } else {
                    builder.ins().return_(&[]);
                }
            }
        }
    }

    if emitted.iter().any(|done| !*done) {
        bail!("cranelift cfg emission left one or more reachable blocks un-emitted");
    }
    for (index, block) in clif_blocks.iter().enumerate() {
        if !sealed[index] {
            builder.seal_block(*block);
        }
    }
    Ok(())
}

pub(super) fn clif_snapshot_closure_captures(
    builder: &mut FunctionBuilder,
    locals: &HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> HashMap<String, LocalBinding> {
    let mut captures = HashMap::new();
    for (name, binding) in locals {
        let captured_var = Variable::from_u32(*next_var as u32);
        *next_var += 1;
        builder.declare_var(captured_var, binding.ty);
        let current = builder.use_var(binding.var);
        builder.def_var(captured_var, current);
        captures.insert(
            name.clone(),
            LocalBinding {
                var: captured_var,
                ty: binding.ty,
            },
        );
    }
    captures
}

fn clif_restore_shadowed_locals(
    locals: &mut HashMap<String, LocalBinding>,
    saved: HashMap<String, Option<LocalBinding>>,
    inserted: HashSet<String>,
) {
    for (name, prior) in saved {
        if let Some(binding) = prior {
            locals.insert(name, binding);
        } else if inserted.contains(&name) {
            locals.remove(&name);
        }
    }
}

pub(super) fn clif_emit_inlined_closure_call(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    binding: ClifClosureBinding,
    args: &[ast::Expr],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let mut cast_args = Vec::with_capacity(binding.params.len());
    for (index, param) in binding.params.iter().enumerate() {
        let arg = args.get(index).cloned().unwrap_or(ast::Expr::Int(0));
        let mut lowered = clif_emit_expr(builder, ctx, &arg, locals, next_var)?;
        if let Some(target_ty) = ast_signature_type_to_clif_type(&param.ty) {
            lowered = cast_clif_value(builder, lowered, target_ty)?;
        }
        cast_args.push(lowered);
    }

    let mut saved = HashMap::<String, Option<LocalBinding>>::new();
    let mut inserted = HashSet::<String>::new();
    for (name, capture) in &binding.captures {
        if !saved.contains_key(name) {
            saved.insert(name.clone(), locals.get(name).copied());
        }
        locals.insert(name.clone(), *capture);
        inserted.insert(name.clone());
    }

    for (index, param) in binding.params.iter().enumerate() {
        if !saved.contains_key(&param.name) {
            saved.insert(param.name.clone(), locals.get(&param.name).copied());
        }
        let target_ty = ast_signature_type_to_clif_type(&param.ty).unwrap_or(cast_args[index].ty);
        let var = Variable::from_u32(*next_var as u32);
        *next_var += 1;
        builder.declare_var(var, target_ty);
        let value = cast_clif_value(builder, cast_args[index], target_ty)?;
        builder.def_var(var, value.value);
        locals.insert(param.name.clone(), LocalBinding { var, ty: target_ty });
        inserted.insert(param.name.clone());
    }

    let mut result = clif_emit_expr(builder, ctx, &binding.body, locals, next_var)?;
    if let Some(return_ty) = &binding.return_type {
        if let Some(target_ty) = ast_signature_type_to_clif_type(return_ty) {
            result = cast_clif_value(builder, result, target_ty)?;
        }
    }
    clif_restore_shadowed_locals(locals, saved, inserted);
    Ok(result)
}

pub(super) fn clif_emit_let_pattern(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    pattern: &ast::Pattern,
    value: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<()> {
    let lowered = clif_emit_expr(builder, ctx, value, locals, next_var)?;
    match pattern {
        ast::Pattern::Wildcard => {}
        ast::Pattern::Ident(name) => {
            let var = Variable::from_u32(*next_var as u32);
            *next_var += 1;
            builder.declare_var(var, lowered.ty);
            builder.def_var(var, lowered.value);
            locals.insert(
                name.clone(),
                LocalBinding {
                    var,
                    ty: lowered.ty,
                },
            );
        }
        ast::Pattern::Int(expected) => {
            let expected_value = builder.ins().iconst(lowered.ty, *expected as i64);
            let _ = builder
                .ins()
                .icmp(IntCC::Equal, lowered.value, expected_value);
        }
        ast::Pattern::Bool(expected) => {
            let expected_value = builder.ins().iconst(lowered.ty, i64::from(*expected));
            let _ = builder
                .ins()
                .icmp(IntCC::Equal, lowered.value, expected_value);
        }
        ast::Pattern::Struct { name, fields } => {
            let ast::Expr::StructInit {
                name: value_name,
                fields: value_fields,
            } = value
            else {
                bail!("native backend requires literal struct initializer for `let` struct destructuring");
            };
            if value_name != name {
                bail!(
                    "native backend requires exact literal struct type match for `let` struct destructuring"
                );
            }
            for (field_name, binding_name) in fields {
                if binding_name == "_" {
                    continue;
                }
                let Some((_, field_expr)) =
                    value_fields.iter().find(|(field, _)| field == field_name)
                else {
                    bail!("native backend requires struct literal fields to cover every bound pattern field");
                };
                let payload_val = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                let var = Variable::from_u32(*next_var as u32);
                *next_var += 1;
                builder.declare_var(var, payload_val.ty);
                builder.def_var(var, payload_val.value);
                locals.insert(
                    binding_name.clone(),
                    LocalBinding {
                        var,
                        ty: payload_val.ty,
                    },
                );
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            ..
        } => {
            let key = format!("{enum_name}::{variant}");
            let expected_tag = builder.ins().iconst(
                lowered.ty,
                variant_tag_for_key(&key, ctx.variant_tags) as i64,
            );
            let _ = builder
                .ins()
                .icmp(IntCC::Equal, lowered.value, expected_tag);
            if let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                payload,
                ..
            } = value
            {
                if value_enum == enum_name
                    && value_variant == variant
                    && payload.len() == bindings.len()
                {
                    for (binding_name, payload_expr) in bindings.iter().zip(payload.iter()) {
                        let payload_val =
                            clif_emit_expr(builder, ctx, payload_expr, locals, next_var)?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, payload_val.ty);
                        builder.def_var(var, payload_val.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: payload_val.ty,
                            },
                        );
                    }
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns.iter().find(|pattern| {
                pattern_matches_resolved_scrutinee(pattern, value, ctx.variant_tags)
            }) {
                return clif_emit_let_pattern(builder, ctx, matched, value, locals, next_var);
            }
            if patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
            {
                bail!(
                    "native backend requires resolvable initializer for payload or struct-field bindings in `let` or-patterns"
                );
            }
        }
    }
    Ok(())
}

pub(super) fn clif_emit_linear_stmts(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    body: &[ast::Stmt],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<bool> {
    for stmt in body {
        match stmt {
            ast::Stmt::Let {
                name, value, ty, ..
            } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(name.clone(), const_value);
                    ctx.array_bindings.remove(name);
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let mut lowered_items = Vec::with_capacity(items.len());
                    for item in items {
                        lowered_items.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
                    }
                    let (element_ty, element_bits, element_align, element_stride) =
                        clif_array_layout_from_values(&lowered_items);
                    let slot_size = (lowered_items.len() as u32) * u32::from(element_stride);
                    let align_shift = element_align.trailing_zeros() as u8;
                    let stack_slot =
                        builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                            cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                            slot_size,
                            align_shift,
                        ));
                    for (idx, mut item_val) in lowered_items.into_iter().enumerate() {
                        item_val = cast_clif_value(builder, item_val, element_ty)?;
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            stack_slot,
                            (idx as i32) * i32::from(element_stride),
                        );
                        builder.ins().store(MemFlags::new(), item_val.value, ptr, 0);
                    }
                    ctx.array_bindings.insert(
                        name.clone(),
                        ClifArrayBinding {
                            stack_slot,
                            len: items.len(),
                            element_ty,
                            element_bits,
                            element_align,
                            element_stride,
                        },
                    );
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_bindings) = ctx.array_bindings.get(source).cloned() {
                        ctx.array_bindings.insert(name.clone(), source_bindings);
                        continue;
                    }
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    ctx.closures.insert(
                        name.clone(),
                        ClifClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures: clif_snapshot_closure_captures(builder, locals, next_var),
                        },
                    );
                    continue;
                }
                let mut val = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                let target_ty = ty
                    .as_ref()
                    .and_then(ast_signature_type_to_clif_type)
                    .unwrap_or(val.ty);
                val = cast_clif_value(builder, val, target_ty)?;
                let binding = if let Some(existing) = locals.get(name).copied() {
                    existing
                } else {
                    let var = Variable::from_u32(*next_var as u32);
                    *next_var += 1;
                    builder.declare_var(var, target_ty);
                    let binding = LocalBinding { var, ty: target_ty };
                    locals.insert(name.clone(), binding);
                    binding
                };
                let val = cast_clif_value(builder, val, binding.ty)?;
                builder.def_var(binding.var, val.value);
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_val = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, field_val.ty);
                        builder.def_var(field_var, field_val.value);
                        locals.insert(
                            format!("{name}.{field}"),
                            LocalBinding {
                                var: field_var,
                                ty: field_val.ty,
                            },
                        );
                    }
                }
                if let ast::Expr::Range {
                    start,
                    end,
                    inclusive,
                } = value
                {
                    let start_val = clif_emit_expr(builder, ctx, start, locals, next_var)?;
                    let end_val = clif_emit_expr(builder, ctx, end, locals, next_var)?;
                    let inclusive_val = ClifValue {
                        value: builder
                            .ins()
                            .iconst(default_int_clif_type(), i64::from(*inclusive)),
                        ty: default_int_clif_type(),
                    };
                    for (field, field_val) in [
                        ("start", start_val),
                        ("end", end_val),
                        ("inclusive", inclusive_val),
                    ] {
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, field_val.ty);
                        builder.def_var(field_var, field_val.value);
                        locals.insert(
                            format!("{name}.{field}"),
                            LocalBinding {
                                var: field_var,
                                ty: field_val.ty,
                            },
                        );
                    }
                }
                ctx.array_bindings.remove(name);
                ctx.const_strings.remove(name);
            }
            ast::Stmt::LetPattern { pattern, value, .. } => {
                clif_emit_let_pattern(builder, ctx, pattern, value, locals, next_var)?;
            }
            ast::Stmt::Assign { target, value } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(target.clone(), const_value);
                    ctx.array_bindings.remove(target);
                    continue;
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    ctx.closures.insert(
                        target.clone(),
                        ClifClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures: clif_snapshot_closure_captures(builder, locals, next_var),
                        },
                    );
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let mut lowered_items = Vec::with_capacity(items.len());
                    for item in items {
                        lowered_items.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
                    }
                    let (element_ty, element_bits, element_align, element_stride) =
                        clif_array_layout_from_values(&lowered_items);
                    let slot_size = (lowered_items.len() as u32) * u32::from(element_stride);
                    let align_shift = element_align.trailing_zeros() as u8;
                    let stack_slot =
                        builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                            cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                            slot_size,
                            align_shift,
                        ));
                    for (idx, mut item_val) in lowered_items.into_iter().enumerate() {
                        item_val = cast_clif_value(builder, item_val, element_ty)?;
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            stack_slot,
                            (idx as i32) * i32::from(element_stride),
                        );
                        builder.ins().store(MemFlags::new(), item_val.value, ptr, 0);
                    }
                    ctx.array_bindings.insert(
                        target.clone(),
                        ClifArrayBinding {
                            stack_slot,
                            len: items.len(),
                            element_ty,
                            element_bits,
                            element_align,
                            element_stride,
                        },
                    );
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_bindings) = ctx.array_bindings.get(source).cloned() {
                        ctx.array_bindings.insert(target.clone(), source_bindings);
                        continue;
                    }
                }
                let val = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                if let Some(data_id) = ctx.mutable_globals.get(target).copied() {
                    let val = cast_clif_value(builder, val, types::I32)?;
                    let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                    let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                    builder.ins().store(MemFlags::new(), val.value, ptr, 0);
                } else {
                    let binding = if let Some(existing) = locals.get(target).copied() {
                        existing
                    } else {
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, val.ty);
                        let binding = LocalBinding { var, ty: val.ty };
                        locals.insert(target.clone(), binding);
                        binding
                    };
                    let val = cast_clif_value(builder, val, binding.ty)?;
                    builder.def_var(binding.var, val.value);
                    if let ast::Expr::StructInit { fields, .. } = value {
                        for (field, field_expr) in fields {
                            let field_val =
                                clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                            let field_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(field_var, field_val.ty);
                            builder.def_var(field_var, field_val.value);
                            locals.insert(
                                format!("{target}.{field}"),
                                LocalBinding {
                                    var: field_var,
                                    ty: field_val.ty,
                                },
                            );
                        }
                    }
                    if let ast::Expr::Range {
                        start,
                        end,
                        inclusive,
                    } = value
                    {
                        let start_val = clif_emit_expr(builder, ctx, start, locals, next_var)?;
                        let end_val = clif_emit_expr(builder, ctx, end, locals, next_var)?;
                        let inclusive_val = ClifValue {
                            value: builder
                                .ins()
                                .iconst(default_int_clif_type(), i64::from(*inclusive)),
                            ty: default_int_clif_type(),
                        };
                        for (field, field_val) in [
                            ("start", start_val),
                            ("end", end_val),
                            ("inclusive", inclusive_val),
                        ] {
                            let field_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(field_var, field_val.ty);
                            builder.def_var(field_var, field_val.value);
                            locals.insert(
                                format!("{target}.{field}"),
                                LocalBinding {
                                    var: field_var,
                                    ty: field_val.ty,
                                },
                            );
                        }
                    }
                }
                ctx.array_bindings.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::CompoundAssign { target, op, value } => {
                let combined_expr = ast::Expr::Binary {
                    op: *op,
                    left: Box::new(ast::Expr::Ident(target.clone())),
                    right: Box::new(value.clone()),
                };
                let val = clif_emit_expr(builder, ctx, &combined_expr, locals, next_var)?;
                if let Some(data_id) = ctx.mutable_globals.get(target).copied() {
                    let val = cast_clif_value(builder, val, types::I32)?;
                    let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                    let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                    builder.ins().store(MemFlags::new(), val.value, ptr, 0);
                } else {
                    let binding = if let Some(existing) = locals.get(target).copied() {
                        existing
                    } else {
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, val.ty);
                        let binding = LocalBinding { var, ty: val.ty };
                        locals.insert(target.clone(), binding);
                        binding
                    };
                    let val = cast_clif_value(builder, val, binding.ty)?;
                    builder.def_var(binding.var, val.value);
                }
                ctx.array_bindings.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::Expr(expr)
            | ast::Stmt::Requires(expr)
            | ast::Stmt::Ensures(expr)
            | ast::Stmt::Defer(expr) => {
                let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
            }
            ast::Stmt::Return(value) => {
                match (value, ctx.current_return_ty) {
                    (Some(expr), Some(ret_ty)) => {
                        let lowered = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        let lowered = cast_clif_value(builder, lowered, ret_ty)?;
                        builder.ins().return_(&[lowered.value]);
                    }
                    (Some(expr), None) => {
                        let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        builder.ins().return_(&[]);
                    }
                    (None, Some(ret_ty)) => {
                        let fallback = zero_for_type(builder, ret_ty);
                        builder.ins().return_(&[fallback]);
                    }
                    (None, None) => {
                        builder.ins().return_(&[]);
                    }
                }
                return Ok(true);
            }
            ast::Stmt::If { .. }
            | ast::Stmt::While { .. }
            | ast::Stmt::For { .. }
            | ast::Stmt::ForIn { .. }
            | ast::Stmt::Loop { .. }
            | ast::Stmt::Break(_)
            | ast::Stmt::Continue
            | ast::Stmt::Match { .. } => {
                bail!("cranelift linear emission received non-linear control-flow statement");
            }
        }
    }
    Ok(false)
}

pub(super) fn clif_emit_expr(
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
            if let Some(field_expr) = resolve_field_expr(base, field) {
                return clif_emit_expr(builder, ctx, &field_expr, locals, next_var);
            }
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(binding) = locals.get(&format!("{name}.{field}")).copied() {
                    ClifValue {
                        value: builder.use_var(binding.var),
                        ty: binding.ty,
                    }
                } else if let Some(task_ref_name) = expr_task_ref_name(expr) {
                    if let Some(task_ref) = ctx.task_ref_ids.get(&task_ref_name).copied() {
                        ClifValue {
                            value: builder
                                .ins()
                                .iconst(default_int_clif_type(), task_ref as i64),
                            ty: default_int_clif_type(),
                        }
                    } else {
                        clif_emit_expr(builder, ctx, base, locals, next_var)?
                    }
                } else {
                    clif_emit_expr(builder, ctx, base, locals, next_var)?
                }
            } else {
                clif_emit_expr(builder, ctx, base, locals, next_var)?
            }
        }
        ast::Expr::StructInit { fields, .. } => {
            let mut first = None;
            for (_, value) in fields {
                let out = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                if first.is_none() {
                    first = Some(out);
                }
            }
            first.unwrap_or_else(|| ClifValue {
                value: builder.ins().iconst(pointer_sized_clif_type(), 0),
                ty: pointer_sized_clif_type(),
            })
        }
        ast::Expr::EnumInit {
            enum_name,
            variant,
            payload,
            named_payload,
        } => {
            for value in payload {
                let _ = clif_emit_expr(builder, ctx, value, locals, next_var)?;
            }
            for (_, value) in named_payload {
                let _ = clif_emit_expr(builder, ctx, value, locals, next_var)?;
            }
            let key = format!("{enum_name}::{variant}");
            ClifValue {
                value: builder.ins().iconst(
                    default_int_clif_type(),
                    variant_tag_for_key(&key, ctx.variant_tags) as i64,
                ),
                ty: default_int_clif_type(),
            }
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
            let index_value =
                if let Some((base_name, offset)) = canonicalize_array_index_window(index) {
                    if let Some(binding) = locals.get(&base_name).copied() {
                        let base_raw = builder.use_var(binding.var);
                        let base = cast_clif_value(
                            builder,
                            ClifValue {
                                value: base_raw,
                                ty: binding.ty,
                            },
                            default_int_clif_type(),
                        )?
                        .value;
                        let value = if offset == 0 {
                            base
                        } else {
                            builder.ins().iadd_imm(base, i64::from(offset))
                        };
                        ClifValue {
                            value,
                            ty: default_int_clif_type(),
                        }
                    } else {
                        let value = clif_emit_expr(builder, ctx, index, locals, next_var)?;
                        cast_clif_value(builder, value, default_int_clif_type())?
                    }
                } else {
                    let value = clif_emit_expr(builder, ctx, index, locals, next_var)?;
                    cast_clif_value(builder, value, default_int_clif_type())?
                };
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(binding) = ctx.array_bindings.get(name) {
                    if binding.len == 0 {
                        return Ok(ClifValue {
                            value: builder.ins().iconst(binding.element_ty, 0),
                            ty: binding.element_ty,
                        });
                    }
                    if let Some(const_idx) = eval_const_i32_expr(index, &ctx.const_strings) {
                        if const_idx >= 0 && (const_idx as usize) < binding.len {
                            let ptr = builder.ins().stack_addr(
                                pointer_sized_clif_type(),
                                binding.stack_slot,
                                const_idx * i32::from(binding.element_stride),
                            );
                            let loaded =
                                builder
                                    .ins()
                                    .load(binding.element_ty, MemFlags::new(), ptr, 0);
                            return Ok(ClifValue {
                                value: loaded,
                                ty: binding.element_ty,
                            });
                        }
                    }
                    let in_block = builder.create_block();
                    let out_block = builder.create_block();
                    let merge_block = builder.create_block();
                    builder.append_block_param(merge_block, binding.element_ty);

                    let zero = builder.ins().iconst(default_int_clif_type(), 0);
                    let len_const = builder
                        .ins()
                        .iconst(default_int_clif_type(), binding.len as i64);
                    let nonneg = builder.ins().icmp(
                        IntCC::SignedGreaterThanOrEqual,
                        index_value.value,
                        zero,
                    );
                    let below_len =
                        builder
                            .ins()
                            .icmp(IntCC::SignedLessThan, index_value.value, len_const);
                    let in_range = builder.ins().band(nonneg, below_len);
                    builder.ins().brif(in_range, in_block, &[], out_block, &[]);

                    builder.switch_to_block(in_block);
                    let base_ptr =
                        builder
                            .ins()
                            .stack_addr(pointer_sized_clif_type(), binding.stack_slot, 0);
                    let idx_ptr = if pointer_sized_clif_type() == default_int_clif_type() {
                        index_value.value
                    } else {
                        builder
                            .ins()
                            .uextend(pointer_sized_clif_type(), index_value.value)
                    };
                    let byte_offset = builder
                        .ins()
                        .imul_imm(idx_ptr, i64::from(binding.element_stride));
                    let addr = builder.ins().iadd(base_ptr, byte_offset);
                    let loaded = builder
                        .ins()
                        .load(binding.element_ty, MemFlags::new(), addr, 0);
                    builder.ins().jump(merge_block, &[loaded]);

                    builder.switch_to_block(out_block);
                    let zero_default = builder.ins().iconst(binding.element_ty, 0);
                    builder.ins().jump(merge_block, &[zero_default]);

                    builder.seal_block(in_block);
                    builder.seal_block(out_block);
                    builder.switch_to_block(merge_block);
                    builder.seal_block(merge_block);
                    let selected = builder.block_params(merge_block)[0];
                    let _ = (
                        binding.element_bits,
                        binding.element_align,
                        binding.element_stride,
                    );
                    return Ok(ClifValue {
                        value: selected,
                        ty: binding.element_ty,
                    });
                }
            }
            clif_emit_expr(builder, ctx, base, locals, next_var)?
        }
        ast::Expr::Binary { op, left, right } => {
            let lhs = clif_emit_expr(builder, ctx, left, locals, next_var)?;
            match op {
                ast::BinaryOp::Add => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        let lowered = builder.ins().fadd(lhs.value, rhs.value);
                        clif_assert_finite(
                            builder,
                            ClifValue {
                                value: lowered,
                                ty: lhs.ty,
                            },
                        )
                    } else {
                        ClifValue {
                            value: builder.ins().iadd(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Sub => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        let lowered = builder.ins().fsub(lhs.value, rhs.value);
                        clif_assert_finite(
                            builder,
                            ClifValue {
                                value: lowered,
                                ty: lhs.ty,
                            },
                        )
                    } else {
                        ClifValue {
                            value: builder.ins().isub(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Mul => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        let lowered = builder.ins().fmul(lhs.value, rhs.value);
                        clif_assert_finite(
                            builder,
                            ClifValue {
                                value: lowered,
                                ty: lhs.ty,
                            },
                        )
                    } else {
                        ClifValue {
                            value: builder.ins().imul(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Div => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        let lowered = builder.ins().fdiv(lhs.value, rhs.value);
                        clif_assert_finite(
                            builder,
                            ClifValue {
                                value: lowered,
                                ty: lhs.ty,
                            },
                        )
                    } else {
                        ClifValue {
                            value: builder.ins().sdiv(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Mod => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().srem(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::BitAnd => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().band(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::BitOr => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().bor(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::BitXor => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().bxor(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::Shl => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().ishl(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::Shr => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().sshr(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::And => {
                    let lhs_pred = clif_truthy_pred(builder, lhs);
                    let rhs_block = builder.create_block();
                    let short_block = builder.create_block();
                    let merge_block = builder.create_block();
                    builder.append_block_param(merge_block, types::I8);
                    builder
                        .ins()
                        .brif(lhs_pred, rhs_block, &[], short_block, &[]);

                    builder.switch_to_block(short_block);
                    let false_val = builder.ins().iconst(types::I8, 0);
                    builder.ins().jump(merge_block, &[false_val]);

                    builder.switch_to_block(rhs_block);
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs_pred = clif_truthy_pred(builder, rhs);
                    let rhs_bool = bool_to_i8(builder, rhs_pred);
                    builder.ins().jump(merge_block, &[rhs_bool.value]);

                    builder.seal_block(short_block);
                    builder.seal_block(rhs_block);
                    builder.switch_to_block(merge_block);
                    builder.seal_block(merge_block);
                    ClifValue {
                        value: builder.block_params(merge_block)[0],
                        ty: types::I8,
                    }
                }
                ast::BinaryOp::Or => {
                    let lhs_pred = clif_truthy_pred(builder, lhs);
                    let rhs_block = builder.create_block();
                    let short_block = builder.create_block();
                    let merge_block = builder.create_block();
                    builder.append_block_param(merge_block, types::I8);
                    builder
                        .ins()
                        .brif(lhs_pred, short_block, &[], rhs_block, &[]);

                    builder.switch_to_block(short_block);
                    let true_val = builder.ins().iconst(types::I8, 1);
                    builder.ins().jump(merge_block, &[true_val]);

                    builder.switch_to_block(rhs_block);
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs_pred = clif_truthy_pred(builder, rhs);
                    let rhs_bool = bool_to_i8(builder, rhs_pred);
                    builder.ins().jump(merge_block, &[rhs_bool.value]);

                    builder.seal_block(short_block);
                    builder.seal_block(rhs_block);
                    builder.switch_to_block(merge_block);
                    builder.seal_block(merge_block);
                    ClifValue {
                        value: builder.block_params(merge_block)[0],
                        ty: types::I8,
                    }
                }
                ast::BinaryOp::Eq => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder.ins().fcmp(FloatCC::Equal, lhs.value, rhs.value)
                    } else {
                        builder.ins().icmp(IntCC::Equal, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Neq => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder.ins().fcmp(FloatCC::NotEqual, lhs.value, rhs.value)
                    } else {
                        builder.ins().icmp(IntCC::NotEqual, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Lt => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder.ins().fcmp(FloatCC::LessThan, lhs.value, rhs.value)
                    } else {
                        builder
                            .ins()
                            .icmp(IntCC::SignedLessThan, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Lte => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder
                            .ins()
                            .fcmp(FloatCC::LessThanOrEqual, lhs.value, rhs.value)
                    } else {
                        builder
                            .ins()
                            .icmp(IntCC::SignedLessThanOrEqual, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Gt => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder
                            .ins()
                            .fcmp(FloatCC::GreaterThan, lhs.value, rhs.value)
                    } else {
                        builder
                            .ins()
                            .icmp(IntCC::SignedGreaterThan, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Gte => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder
                            .ins()
                            .fcmp(FloatCC::GreaterThanOrEqual, lhs.value, rhs.value)
                    } else {
                        builder
                            .ins()
                            .icmp(IntCC::SignedGreaterThanOrEqual, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
            }
        }
        ast::Expr::Call { callee, args } => {
            if let Some(value) = eval_const_i32_call(callee, args, &ctx.const_strings) {
                return Ok(ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), value as i64),
                    ty: default_int_clif_type(),
                });
            }
            if let Some(value) = eval_const_string_call(callee, args, &ctx.const_strings) {
                if let Some(id) = ctx.string_literal_ids.get(&value).copied() {
                    return Ok(ClifValue {
                        value: builder.ins().iconst(default_int_clif_type(), id as i64),
                        ty: default_int_clif_type(),
                    });
                }
            }
            if let Some(binding) = ctx.closures.get(callee).cloned() {
                return clif_emit_inlined_closure_call(
                    builder, ctx, binding, args, locals, next_var,
                );
            }
            let mut values = Vec::with_capacity(args.len());
            if let Some(function_id) = ctx.function_ids.get(callee).copied() {
                let signature = ctx.function_signatures.get(callee).ok_or_else(|| {
                    anyhow!("missing native function signature metadata for `{callee}`")
                })?;
                for (index, arg) in args.iter().enumerate() {
                    let mut lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
                    if let Some(target) = signature.params.get(index).copied() {
                        lowered = cast_clif_value(builder, lowered, target)?;
                    }
                    values.push(lowered.value);
                }
                let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
                let call = builder.ins().call(func_ref, &values);
                if let Some(value) = builder.inst_results(call).first().copied() {
                    clif_assert_finite(
                        builder,
                        ClifValue {
                        value,
                        ty: signature.ret.unwrap_or(default_int_clif_type()),
                        },
                    )
                } else {
                    ClifValue {
                        value: builder.ins().iconst(default_int_clif_type(), 0),
                        ty: default_int_clif_type(),
                    }
                }
            } else {
                for arg in args {
                    let _ = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
                }
                return Err(anyhow!(
                    "native backend cannot lower unresolved call target `{}`",
                    callee
                ));
            }
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

pub(super) fn ast_signature_type_to_clif_type(ty: &ast::Type) -> Option<ClifType> {
    match ty {
        ast::Type::Void | ast::Type::Never => None,
        ast::Type::Bool => Some(types::I8),
        ast::Type::ISize | ast::Type::USize => Some(pointer_sized_clif_type()),
        ast::Type::Int { bits, .. } => match bits {
            8 => Some(types::I8),
            16 => Some(types::I16),
            32 => Some(types::I32),
            64 => Some(types::I64),
            128 => Some(types::I128),
            _ => None,
        },
        ast::Type::BigInt | ast::Type::BigUint | ast::Type::Decimal128 => {
            Some(pointer_sized_clif_type())
        }
        ast::Type::Float { bits } => match bits {
            32 => Some(types::F32),
            64 => Some(types::F64),
            _ => None,
        },
        ast::Type::Char
        | ast::Type::Str
        | ast::Type::Bytes
        | ast::Type::Uuid
        | ast::Type::DynTrait(_)
        | ast::Type::Map { .. }
        | ast::Type::Set(_)
        | ast::Type::Deque(_)
        | ast::Type::Ring(_)
        | ast::Type::Ptr { .. }
        | ast::Type::Ref { .. }
        | ast::Type::Slice(_)
        | ast::Type::Array { .. }
        | ast::Type::Result { .. }
        | ast::Type::Option(_)
        | ast::Type::Vec(_)
        | ast::Type::Future(_)
        | ast::Type::Path
        | ast::Type::PathBuf
        | ast::Type::Url
        | ast::Type::SocketAddr
        | ast::Type::Duration
        | ast::Type::Instant
        | ast::Type::Decimal
        | ast::Type::DateTimeTz
        | ast::Type::ExitStatus
        | ast::Type::Tuple(_)
        | ast::Type::Function { .. }
        | ast::Type::Named { .. }
        | ast::Type::TypeVar(_) => Some(pointer_sized_clif_type()),
    }
}

pub(super) fn pointer_sized_clif_type() -> ClifType {
    if std::mem::size_of::<usize>() == 8 {
        types::I64
    } else {
        types::I32
    }
}

pub(super) fn default_int_clif_type() -> ClifType {
    types::I32
}

pub(super) fn clif_array_layout_from_values(values: &[ClifValue]) -> (ClifType, u16, u8, u8) {
    let element_ty = if values.iter().any(|value| value.ty == types::F64) {
        types::F64
    } else if values.iter().any(|value| value.ty == types::F32) {
        types::F32
    } else if values.iter().any(|value| value.ty == types::I64) {
        types::I64
    } else {
        types::I32
    };
    let element_bits = element_ty.bits() as u16;
    let element_stride = (element_bits / 8) as u8;
    let element_align = element_stride;
    (element_ty, element_bits, element_align, element_stride)
}

pub(super) fn zero_for_type(
    builder: &mut FunctionBuilder,
    ty: ClifType,
) -> cranelift_codegen::ir::Value {
    if ty.is_int() {
        builder.ins().iconst(ty, 0)
    } else if ty == types::F32 {
        builder.ins().f32const(0.0)
    } else if ty == types::F64 {
        builder.ins().f64const(0.0)
    } else {
        builder.ins().iconst(default_int_clif_type(), 0)
    }
}

pub(super) fn clif_truthy_pred(
    builder: &mut FunctionBuilder,
    value: ClifValue,
) -> cranelift_codegen::ir::Value {
    if value.ty == types::F32 {
        let zero = builder.ins().f32const(0.0);
        builder.ins().fcmp(FloatCC::NotEqual, value.value, zero)
    } else if value.ty == types::F64 {
        let zero = builder.ins().f64const(0.0);
        builder.ins().fcmp(FloatCC::NotEqual, value.value, zero)
    } else {
        let zero = zero_for_type(builder, value.ty);
        builder.ins().icmp(IntCC::NotEqual, value.value, zero)
    }
}

pub(super) fn clif_assert_finite(builder: &mut FunctionBuilder, value: ClifValue) -> ClifValue {
    if value.ty != types::F32 && value.ty != types::F64 {
        return value;
    }
    let (neg_limit, pos_limit) = if value.ty == types::F32 {
        (
            builder.ins().f32const(-f32::MAX),
            builder.ins().f32const(f32::MAX),
        )
    } else {
        (
            builder.ins().f64const(-f64::MAX),
            builder.ins().f64const(f64::MAX),
        )
    };
    let lower = builder
        .ins()
        .fcmp(FloatCC::GreaterThanOrEqual, value.value, neg_limit);
    let upper = builder
        .ins()
        .fcmp(FloatCC::LessThanOrEqual, value.value, pos_limit);
    let ok = builder.ins().band(lower, upper);
    let continue_block = builder.create_block();
    let trap_block = builder.create_block();
    builder
        .ins()
        .brif(ok, continue_block, &[], trap_block, &[]);
    builder.switch_to_block(trap_block);
    builder.ins().trap(TrapCode::unwrap_user(1));
    builder.seal_block(trap_block);
    builder.switch_to_block(continue_block);
    builder.seal_block(continue_block);
    value
}

pub(super) fn bool_to_i8(
    builder: &mut FunctionBuilder,
    pred: cranelift_codegen::ir::Value,
) -> ClifValue {
    let one = builder.ins().iconst(types::I8, 1);
    let zero = builder.ins().iconst(types::I8, 0);
    ClifValue {
        value: builder.ins().select(pred, one, zero),
        ty: types::I8,
    }
}

pub(super) fn cast_clif_value(
    builder: &mut FunctionBuilder,
    value: ClifValue,
    target: ClifType,
) -> Result<ClifValue> {
    if value.ty == target {
        return Ok(value);
    }
    if value.ty.is_int() && target.is_int() {
        if value.ty.bits() < target.bits() {
            return Ok(ClifValue {
                value: builder.ins().sextend(target, value.value),
                ty: target,
            });
        }
        if value.ty.bits() > target.bits() {
            return Ok(ClifValue {
                value: builder.ins().ireduce(target, value.value),
                ty: target,
            });
        }
    }
    if value.ty.is_int() && (target == types::F32 || target == types::F64) {
        let out = if target == types::F32 {
            builder.ins().fcvt_from_sint(types::F32, value.value)
        } else {
            builder.ins().fcvt_from_sint(types::F64, value.value)
        };
        return Ok(ClifValue {
            value: out,
            ty: target,
        });
    }
    if (value.ty == types::F32 || value.ty == types::F64) && target.is_int() {
        let value = clif_assert_finite(builder, value);
        return Ok(ClifValue {
            value: builder.ins().fcvt_to_sint(target, value.value),
            ty: target,
        });
    }
    if value.ty == types::F32 && target == types::F64 {
        return Ok(ClifValue {
            value: builder.ins().fpromote(types::F64, value.value),
            ty: types::F64,
        });
    }
    if value.ty == types::F64 && target == types::F32 {
        return Ok(ClifValue {
            value: builder.ins().fdemote(types::F32, value.value),
            ty: types::F32,
        });
    }
    bail!(
        "unsupported native cast from `{}` to `{}`",
        value.ty,
        target
    );
}
