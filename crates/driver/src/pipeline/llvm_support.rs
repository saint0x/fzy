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

pub(super) struct LlvmFuncCtx {
    pub(super) next_value: usize,
    pub(super) next_label: usize,
    pub(super) slots: HashMap<String, String>,
    pub(super) slot_tys: HashMap<String, String>,
    pub(super) array_slots: HashMap<String, LlvmArrayBinding>,
    pub(super) const_strings: HashMap<String, String>,
    pub(super) direct_values: HashMap<String, LlvmValue>,
    pub(super) wrapped_indices: HashMap<String, HashSet<usize>>,
    pub(super) extern_link_symbols: HashMap<String, String>,
    pub(super) closures: HashMap<String, LlvmClosureBinding>,
    pub(super) function_sigs: HashMap<String, LlvmFunctionSig>,
    pub(super) globals: HashMap<String, i32>,
    pub(super) variant_tags: HashMap<String, i32>,
    pub(super) mutable_globals: HashMap<String, String>,
    pub(super) alloca_prologue: String,
    pub(super) declared_allocas: HashSet<String>,
    pub(super) code: String,
}

impl LlvmFuncCtx {
    pub(super) fn new(
        globals: HashMap<String, i32>,
        variant_tags: HashMap<String, i32>,
        mutable_globals: HashMap<String, String>,
        wrapped_indices: HashMap<String, HashSet<usize>>,
        extern_link_symbols: HashMap<String, String>,
        function_sigs: HashMap<String, LlvmFunctionSig>,
    ) -> Self {
        Self {
            next_value: 0,
            next_label: 0,
            slots: HashMap::new(),
            slot_tys: HashMap::new(),
            array_slots: HashMap::new(),
            const_strings: HashMap::new(),
            direct_values: HashMap::new(),
            wrapped_indices,
            extern_link_symbols,
            closures: HashMap::new(),
            function_sigs,
            globals,
            variant_tags,
            mutable_globals,
            alloca_prologue: String::new(),
            declared_allocas: HashSet::new(),
            code: String::new(),
        }
    }

    pub(super) fn value(&mut self) -> String {
        let id = self.next_value;
        self.next_value += 1;
        format!("%v{id}")
    }

    pub(super) fn label(&mut self, prefix: &str) -> String {
        let id = self.next_label;
        self.next_label += 1;
        format!("{prefix}.{id}")
    }

    pub(super) fn declare_alloca(&mut self, slot: &str, ty: &str) {
        if self.declared_allocas.insert(slot.to_string()) {
            self.alloca_prologue
                .push_str(&format!("  {slot} = alloca {ty}\n"));
        }
    }
}

pub(super) fn collect_wrapped_index_candidates(
    body: &[ast::Stmt],
) -> HashMap<String, HashSet<usize>> {
    let mut out = HashMap::new();
    collect_wrapped_index_candidates_stmt(body, &mut out);
    out
}

fn collect_wrapped_index_candidates_stmt(
    stmts: &[ast::Stmt],
    out: &mut HashMap<String, HashSet<usize>>,
) {
    for stmt in stmts {
        match stmt {
            ast::Stmt::While { body, .. }
            | ast::Stmt::Loop { body }
            | ast::Stmt::ForIn { body, .. } => {
                collect_wrapped_index_candidates_stmt(body, out);
            }
            ast::Stmt::For {
                init,
                condition: _,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_wrapped_index_candidates_stmt(std::slice::from_ref(init.as_ref()), out);
                }
                if let Some(step) = step {
                    collect_wrapped_index_candidates_stmt(std::slice::from_ref(step.as_ref()), out);
                }
                collect_wrapped_index_candidates_stmt(body, out);
            }
            ast::Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_wrapped_index_candidates_stmt(then_body, out);
                collect_wrapped_index_candidates_stmt(else_body, out);
            }
            _ => {}
        }
    }

    for pair in stmts.windows(2) {
        let first = &pair[0];
        let second = &pair[1];
        let (target, limit) = match first {
            ast::Stmt::CompoundAssign {
                target,
                op: ast::BinaryOp::Add,
                value: ast::Expr::Int(1),
            } => match second {
                ast::Stmt::If {
                    condition:
                        ast::Expr::Binary {
                            op: ast::BinaryOp::Eq,
                            left,
                            right,
                        },
                    then_body,
                    else_body,
                } if else_body.is_empty()
                    && then_body.len() == 1
                    && matches!(
                        then_body.first(),
                        Some(ast::Stmt::Assign {
                            target: assign_target,
                            value: ast::Expr::Int(0),
                        }) if assign_target == target
                    ) =>
                {
                    let cond_target = match left.as_ref() {
                        ast::Expr::Ident(name) => Some(name),
                        _ => None,
                    };
                    let cond_limit = match right.as_ref() {
                        ast::Expr::Int(v) if *v > 0 => Some(*v as usize),
                        _ => None,
                    };
                    if cond_target == Some(target) {
                        if let Some(limit) = cond_limit {
                            (target.clone(), limit)
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                _ => continue,
            },
            _ => continue,
        };
        out.entry(target).or_default().insert(limit);
    }
}

pub(super) fn llvm_snapshot_closure_captures(
    ctx: &mut LlvmFuncCtx,
) -> HashMap<String, LlvmCaptureBinding> {
    let visible = ctx.slots.clone();
    let mut captures = HashMap::new();
    for (name, slot) in visible {
        let ty = ctx
            .slot_tys
            .get(&name)
            .cloned()
            .unwrap_or_else(|| "i32".to_string());
        let loaded = ctx.value();
        ctx.code
            .push_str(&format!("  {loaded} = load {ty}, ptr {slot}\n"));
        let capture_slot = format!(
            "%slot_cap_{}_{}",
            native_mangle_symbol(&name),
            ctx.next_value
        );
        ctx.code.push_str(&format!(
            "  {capture_slot} = alloca {ty}\n  store {ty} {loaded}, ptr {capture_slot}\n"
        ));
        captures.insert(
            name,
            LlvmCaptureBinding {
                slot: capture_slot,
                ty,
            },
        );
    }
    captures
}

pub(super) fn llvm_restore_shadowed_slots(
    ctx: &mut LlvmFuncCtx,
    saved: HashMap<String, Option<String>>,
    inserted_names: HashSet<String>,
) {
    for (name, prior) in saved {
        if let Some(slot) = prior {
            ctx.slots.insert(name, slot);
        } else if inserted_names.contains(&name) {
            ctx.slots.remove(&name);
        }
    }
}

pub(super) fn llvm_emit_inlined_closure_call(
    binding: LlvmClosureBinding,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let mut saved = HashMap::<String, Option<String>>::new();
    let mut inserted = HashSet::<String>::new();
    for (name, capture) in &binding.captures {
        if !saved.contains_key(name) {
            saved.insert(name.clone(), ctx.slots.get(name).cloned());
        }
        ctx.slots.insert(name.clone(), capture.slot.clone());
        ctx.slot_tys.insert(name.clone(), capture.ty.clone());
        inserted.insert(name.clone());
    }
    for (param, arg) in binding.params.iter().zip(args.iter()) {
        let value = llvm_emit_expr(arg, ctx, string_literal_ids, task_ref_ids)?;
        let target_ty = llvm_ir_type_for_ast_type(&param.ty);
        let value = llvm_cast_value(ctx, value, &target_ty)?;
        if !saved.contains_key(&param.name) {
            saved.insert(param.name.clone(), ctx.slots.get(&param.name).cloned());
        }
        let slot = format!("%slot_{}_{}", param.name, ctx.next_value);
        ctx.declare_alloca(&slot, &target_ty);
        ctx.code.push_str(&format!(
            "  store {} {}, ptr {slot}\n",
            value.ty, value.value
        ));
        ctx.slots.insert(param.name.clone(), slot);
        ctx.slot_tys.insert(param.name.clone(), target_ty);
        inserted.insert(param.name.clone());
    }
    let result = llvm_emit_expr(&binding.body, ctx, string_literal_ids, task_ref_ids)?;
    if let Some(return_type) = &binding.return_type {
        let target_ty = llvm_ir_type_for_ast_type(return_type);
        let result = llvm_cast_value(ctx, result, &target_ty)?;
        llvm_restore_shadowed_slots(ctx, saved, inserted);
        Ok(result)
    } else {
        llvm_restore_shadowed_slots(ctx, saved, inserted);
        Ok(result)
    }
}

pub(super) fn llvm_emit_let_pattern(
    pattern: &ast::Pattern,
    value: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<()> {
    let rendered = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
    match pattern {
        ast::Pattern::Wildcard => {}
        ast::Pattern::Ident(name) => {
            let slot = format!("%slot_{}_{}", native_mangle_symbol(name), ctx.next_value);
            ctx.declare_alloca(&slot, &rendered.ty);
            ctx.code.push_str(&format!(
                "  store {} {}, ptr {slot}\n",
                rendered.ty, rendered.value
            ));
            ctx.slots.insert(name.clone(), slot);
            ctx.slot_tys.insert(name.clone(), rendered.ty.clone());
        }
        ast::Pattern::Int(expected) => {
            let cmp = ctx.value();
            ctx.code.push_str(&format!(
                "  {cmp} = icmp eq {} {}, {expected}\n",
                rendered.ty, rendered.value
            ));
        }
        ast::Pattern::Bool(expected) => {
            let cmp = ctx.value();
            let expected_i32 = if *expected { 1 } else { 0 };
            ctx.code.push_str(&format!(
                "  {cmp} = icmp eq {} {}, {expected_i32}\n",
                rendered.ty, rendered.value
            ));
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
                let field_value =
                    llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                let slot = format!(
                    "%slot_{}_{}",
                    native_mangle_symbol(binding_name),
                    ctx.next_value
                );
                ctx.declare_alloca(&slot, &field_value.ty);
                ctx.code.push_str(&format!(
                    "  store {} {}, ptr {slot}\n",
                    field_value.ty, field_value.value
                ));
                ctx.slots.insert(binding_name.clone(), slot);
                ctx.slot_tys
                    .insert(binding_name.clone(), field_value.ty.clone());
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            ..
        } => {
            let key = format!("{enum_name}::{variant}");
            let tag = variant_tag_for_key(&key, &ctx.variant_tags);
            let cmp = ctx.value();
            ctx.code.push_str(&format!(
                "  {cmp} = icmp eq {} {}, {tag}\n",
                rendered.ty, rendered.value
            ));
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
                        let payload_value =
                            llvm_emit_expr(payload_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &payload_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            payload_value.ty, payload_value.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys
                            .insert(binding_name.clone(), payload_value.ty.clone());
                    }
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns.iter().find(|pattern| {
                pattern_matches_resolved_scrutinee(pattern, value, &ctx.variant_tags)
            }) {
                return llvm_emit_let_pattern(
                    matched,
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
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

pub(super) fn llvm_assert_finite(ctx: &mut LlvmFuncCtx, value: LlvmValue) -> Result<LlvmValue> {
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
    ctx.code.push_str("  call void @llvm.trap()\n  unreachable\n");
    ctx.code.push_str(&format!("{ok_label}:\n"));
    Ok(value)
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
