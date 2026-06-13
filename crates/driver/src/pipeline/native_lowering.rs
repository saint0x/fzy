fn lower_backend_ir(fir: &fir::FirModule, backend: BackendKind) -> Result<String> {
    let plan = build_native_canonical_plan(fir, true);
    drop(plan);
    match backend {
        BackendKind::Llvm => lower_llvm_ir(fir, true),
        BackendKind::Cranelift => lower_cranelift_ir(fir, true),
    }
}

#[derive(Clone)]
struct NativeCanonicalPlan {
    forced_main_return: Option<i32>,
    string_literal_ids: HashMap<String, i32>,
    global_const_i32: HashMap<String, i32>,
    variant_tags: HashMap<String, i32>,
    mutable_static_i32: HashMap<String, i32>,
    task_ref_ids: HashMap<String, i32>,
    cfg_by_function: HashMap<String, Result<ControlFlowCfg, String>>,
    data_ops_by_function: HashMap<String, Vec<NativeDataOp>>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum NativeMemoryClass {
    Stack,
    Static,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum NativeAliasClass {
    LocalNoEscape,
    Escapes,
}

#[derive(Debug, Clone, Copy)]
enum NativeBoundsPolicy {
    Checked,
    ProvenInRange,
}

#[derive(Debug, Clone, Copy)]
enum NativeEffectBoundary {
    Local,
    CapabilityRuntimeImport,
}

#[derive(Debug, Clone)]
enum NativeDataOpKind {
    ArrayLiteral {
        binding: String,
        len: usize,
        element_bits: u16,
        element_align: u8,
        element_stride: u8,
        memory: NativeMemoryClass,
        alias: NativeAliasClass,
    },
    ArrayIndexLoad {
        binding: String,
        index: String,
        bounds: NativeBoundsPolicy,
    },
    StringViewCall {
        callee: String,
        foldable: bool,
        alias: NativeAliasClass,
    },
    RuntimeBoundaryCall {
        callee: String,
        arity: usize,
    },
}

#[derive(Debug, Clone)]
struct NativeDataOp {
    kind: NativeDataOpKind,
    effect_boundary: NativeEffectBoundary,
}

fn render_native_data_op(op: &NativeDataOp) -> String {
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

fn index_expr_shape(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::Int(value) => value.to_string(),
        ast::Expr::Ident(name) => name.clone(),
        ast::Expr::Group(inner) => index_expr_shape(inner),
        _ => "<expr>".to_string(),
    }
}

fn infer_array_element_layout(items: &[ast::Expr]) -> (u16, u8, u8) {
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

fn collect_native_data_ops_from_expr(
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

fn collect_native_data_ops_from_stmt(
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

fn collect_native_data_ops_for_function(function: &hir::TypedFunction) -> Vec<NativeDataOp> {
    let mut out = Vec::new();
    let mut array_lengths = HashMap::<String, usize>::new();
    let mut const_strings = HashMap::<String, String>::new();

    for stmt in &function.body {
        collect_native_data_ops_from_stmt(stmt, &mut array_lengths, &mut const_strings, &mut out);
    }
    out
}

fn compute_forced_main_return(fir: &fir::FirModule, enforce_contract_checks: bool) -> Option<i32> {
    if !enforce_contract_checks {
        return None;
    }
    let (fallback_requires, fallback_ensures) =
        collect_main_contract_conditions(&fir.typed_functions);
    let requires = merge_contract_conditions(&fir.entry_requires, &fallback_requires);
    let ensures = merge_contract_conditions(&fir.entry_ensures, &fallback_ensures);
    if requires
        .iter()
        .any(|condition| matches!(condition, Some(false)))
    {
        Some(120)
    } else if ensures
        .iter()
        .any(|condition| matches!(condition, Some(false)))
    {
        Some(121)
    } else {
        None
    }
}

fn merge_contract_conditions(
    primary: &[Option<bool>],
    fallback: &[Option<bool>],
) -> Vec<Option<bool>> {
    let len = primary.len().max(fallback.len());
    (0..len)
        .map(|index| {
            primary
                .get(index)
                .copied()
                .flatten()
                .map(Some)
                .unwrap_or_else(|| {
                    fallback
                        .get(index)
                        .copied()
                        .flatten()
                        .map(Some)
                        .unwrap_or(None)
                })
        })
        .collect()
}

fn compile_time_contract_diagnostics(
    module: &ast::Module,
    fir: &fir::FirModule,
    enforce_contract_checks: bool,
    profile: BuildProfile,
) -> Vec<diagnostics::Diagnostic> {
    let mut diagnostics = match compute_forced_main_return(fir, enforce_contract_checks) {
        Some(120) => vec![diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            "entry `requires` contract is statically false",
            Some(
                "Make the `requires` condition provably true, or remove the contradictory contract."
                    .to_string(),
            ),
        )],
        Some(121) => vec![diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            "entry `ensures` contract is statically false",
            Some(
                "Make the `ensures` condition provably true, or remove the contradictory contract."
                    .to_string(),
            ),
        )],
        Some(code) => vec![diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            format!("entry contract forcing would terminate with status {code}"),
            None,
        )],
        None => Vec::new(),
    };

    if matches!(profile, BuildProfile::Strict) {
        diagnostics.extend(strict_async_contract_diagnostics(fir));
        diagnostics.extend(strict_memory_phase_contract_diagnostics(fir));
        diagnostics.extend(strict_rpc_contract_diagnostics(module, fir));
        diagnostics.extend(strict_stdlib_capability_policy_diagnostics(module));
    }

    diagnostics
}

fn strict_async_contract_diagnostics(fir: &fir::FirModule) -> Vec<diagnostics::Diagnostic> {
    let task_group_terminal_param_summaries = fir
        .typed_functions
        .iter()
        .filter_map(summarize_task_group_terminal_params)
        .collect::<BTreeMap<_, _>>();
    let task_handle_terminal_param_summaries = fir
        .typed_functions
        .iter()
        .filter_map(summarize_task_handle_terminal_params)
        .collect::<BTreeMap<_, _>>();
    let gpu_event_terminal_param_summaries = fir
        .typed_functions
        .iter()
        .filter_map(summarize_gpu_event_terminal_params)
        .collect::<BTreeMap<_, _>>();
    let mut diagnostics = fir
        .typed_functions
        .iter()
        .flat_map(|function| {
            collect_task_handle_findings(function, &task_handle_terminal_param_summaries)
        })
        .map(|finding| {
            diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                finding.message,
                Some(finding.help),
            )
        })
        .collect::<Vec<_>>();
    diagnostics.extend(
        fir.typed_functions
            .iter()
            .flat_map(|function| {
                collect_task_group_findings(function, &task_group_terminal_param_summaries)
            })
            .map(|finding| {
                diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    finding.message,
                    Some(finding.help),
                )
            }),
    );
    diagnostics.extend(
        fir.typed_functions
            .iter()
            .flat_map(collect_async_runtime_wait_findings)
            .map(|finding| {
                diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    finding.message,
                    Some(finding.help),
                )
            }),
    );
    diagnostics.extend(
        fir.typed_functions
            .iter()
            .flat_map(|function| {
                collect_gpu_event_findings(function, &gpu_event_terminal_param_summaries)
            })
            .map(|finding| {
                diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    finding.message,
                    Some(finding.help),
                )
            }),
    );
    diagnostics
}

fn strict_memory_phase_contract_diagnostics(fir: &fir::FirModule) -> Vec<diagnostics::Diagnostic> {
    let summaries = build_freeze_phase_summaries(fir);
    collect_freeze_phase_findings(fir, &summaries)
        .into_iter()
        .map(|finding| {
            diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                finding.message,
                Some(finding.help),
            )
            .with_code("E-DRV-MEM-FREEZE-PHASE")
        })
        .collect()
}

fn strict_rpc_contract_diagnostics(
    module: &ast::Module,
    fir: &fir::FirModule,
) -> Vec<diagnostics::Diagnostic> {
    let rpc_functions = fir
        .typed_functions
        .iter()
        .filter(|function| {
            function.is_extern
                && function
                    .abi
                    .as_deref()
                    .is_some_and(|abi| abi.eq_ignore_ascii_case("rpc"))
        })
        .collect::<Vec<_>>();
    if rpc_functions.is_empty() {
        return Vec::new();
    }

    let rpc_methods = rpc_functions
        .iter()
        .map(|function| serde_json::json!({ "name": function.name }))
        .collect::<Vec<_>>();
    let policy_evidence = collect_rpc_policy_evidence(module, &rpc_methods);
    let mut diagnostics = Vec::new();
    for function in rpc_functions {
        let method = function.name.as_str();
        let evidence = policy_evidence
            .get(method)
            .cloned()
            .unwrap_or_else(RpcPolicyEvidence::default);
        if let Some(param) = function
            .params
            .iter()
            .find(|param| !param.ty.is_rpc_payload_supported())
        {
            diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!(
                    "RPC method `{method}` parameter `{}` must use an owned/value payload type at the boundary",
                    param.name
                ),
                Some(
                    "Replace borrowed, pointer-like, async, or function payloads with `str`, bytes, JSON, or a typed owned request struct/enum."
                        .to_string(),
                ),
            ));
        }
        if !function.return_type.is_rpc_payload_supported() {
            diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!(
                    "RPC method `{method}` return type `{}` must be an owned/value payload at the boundary",
                    function.return_type
                ),
                Some(
                    "Return an owned response payload, `Result<T, E>`, or an explicit status type instead of borrowed, pointer-like, async, or function values."
                        .to_string(),
                ),
            ));
        }
        if evidence.calls == 0 {
            continue;
        }
        if evidence.deadline_protected_calls < evidence.calls {
            diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!(
                    "RPC method `{method}` is called without an explicit timeout/deadline on every call path"
                ),
                Some(
                    "Add `timeout(...)` or `deadline(...)` before the RPC call or immediately after it so strict mode can prove the request is bounded."
                        .to_string(),
                ),
            ));
        }
        if evidence.cleanup_observed_calls() < evidence.calls {
            diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!(
                    "RPC method `{method}` is called without an explicit recv()/cancel() cleanup policy on every call path"
                ),
                Some(
                    "Handle every RPC call with `recv()` or `cancel()` so strict mode can prove the request is cleaned up on success, deadline, and cancellation paths."
                        .to_string(),
                ),
            ));
        }
    }
    diagnostics
}

fn strict_stdlib_capability_policy_diagnostics(
    module: &ast::Module,
) -> Vec<diagnostics::Diagnostic> {
    struct HazardVisitor {
        diagnostics: Vec<diagnostics::Diagnostic>,
    }

    impl HazardVisitor {
        fn warn(&mut self, message: impl Into<String>, help: impl Into<String>) {
            self.diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Warning,
                message.into(),
                Some(help.into()),
            ));
        }
    }

    impl ast::AstVisitor for HazardVisitor {
        fn visit_expr(&mut self, expr: &ast::Expr) {
            match expr {
                ast::Expr::Call { callee, args } => {
                    match callee.as_str() {
                        "json.raw" => {
                            if let Some(arg) = args.first() {
                                match arg {
                                    ast::Expr::Str(value) => {
                                        let trimmed = value.trim_start();
                                        if trimmed.starts_with('{')
                                            || trimmed.starts_with('[')
                                            || trimmed.starts_with('"')
                                        {
                                            self.warn(
                                                "strict stdlib policy: `json.raw(...)` embeds a composite or quoted JSON literal",
                                                "Use `json.object(...)`, `json.array(...)`, or `json.str(...)` so the compiler can preserve typed JSON boundaries and avoid raw injection drift.",
                                            );
                                        }
                                    }
                                    ast::Expr::Int(_)
                                    | ast::Expr::Float { .. }
                                    | ast::Expr::Bool(_) => {}
                                    _ => self.warn(
                                        "strict stdlib policy: `json.raw(...)` is fed by a dynamic expression",
                                        "Keep JSON typed inside the program and reserve `json.raw(...)` for audited primitive boundary escapes; prefer `json.str(...)`, `json.object(...)`, or `json.array(...)`.",
                                    ),
                                }
                            }
                        }
                        "fs.read_file" | "fs.write_file" | "fs.open" | "fs.atomic_write"
                        | "io.remove" | "storage.kv_open" => {
                            if let Some(ast::Expr::Str(path)) = args.first() {
                                if path.contains("../") || path.contains("..\\") {
                                    self.warn(
                                        format!(
                                            "strict stdlib policy: `{callee}` uses traversal-prone literal path `{path}`"
                                        ),
                                        "Reject `..` path traversal in production code; normalize the path first or route it through a safe-join helper before calling filesystem APIs.",
                                    );
                                }
                                if callee == "fs.write_file"
                                    && (path.starts_with("/tmp/") || path.starts_with("/var/tmp/"))
                                {
                                    self.warn(
                                        format!(
                                            "strict stdlib policy: `{callee}` writes directly to temp path `{path}`"
                                        ),
                                        "Prefer `fs.atomic_write(...)` for temp-backed or replace-in-place output so crash recovery and durability stay explicit.",
                                    );
                                }
                            }
                        }
                        "proc.spawn_cmd" | "proc.run_cmd" => {
                            if let Some(ast::Expr::Str(program)) = args.first() {
                                if matches!(
                                    program.as_str(),
                                    "sh" | "/bin/sh" | "bash" | "/bin/bash" | "zsh" | "/bin/zsh"
                                ) {
                                    self.warn(
                                        format!(
                                            "strict stdlib policy: `{callee}` shells out through `{program}`"
                                        ),
                                        "Prefer direct argv builders for the real program instead of shell dispatch; shell-based process construction is flagged in production strict mode.",
                                    );
                                }
                            }
                        }
                        "proc.argv_push" => {
                            if let Some(ast::Expr::Str(flag)) = args.get(1) {
                                if flag == "-c" || flag == "/c" {
                                    self.warn(
                                        "strict stdlib policy: process argv uses shell command-string flag",
                                        "Avoid `-c`/`/c` shell command strings in production strict mode; build a direct argv vector for the target process instead.",
                                    );
                                }
                            }
                        }
                        "http.header_set" => {
                            if let Some(ast::Expr::Str(name)) = args.first() {
                                let normalized = name.chars().all(|ch| {
                                    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'
                                });
                                if !normalized {
                                    self.warn(
                                        format!(
                                            "strict stdlib policy: HTTP header `{name}` is not normalized"
                                        ),
                                        "Use lowercase header tokens with `-` separators before calling `http.header_set(...)` so production header behavior stays normalized.",
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                    ast::walk_expr(self, expr);
                }
                ast::Expr::Binary {
                    op: ast::BinaryOp::Eq | ast::BinaryOp::Neq,
                    left,
                    right,
                } => {
                    if is_secret_bearing_crypto_expr(left) || is_secret_bearing_crypto_expr(right) {
                        self.warn(
                            "strict stdlib policy: secret-bearing values are compared with `==`/`!=`",
                            "Use `crypto.constant_time_eq(...)` for MAC, digest, or signature comparisons so timing behavior stays production-safe.",
                        );
                    }
                    ast::walk_expr(self, expr);
                }
                _ => ast::walk_expr(self, expr),
            }
        }
    }

    let mut visitor = HazardVisitor {
        diagnostics: Vec::new(),
    };
    for item in &module.items {
        match item {
            ast::Item::Function(function) => {
                for stmt in &function.body {
                    visitor.visit_stmt(stmt);
                }
            }
            ast::Item::Impl(imp) => {
                for function in &imp.methods {
                    for stmt in &function.body {
                        visitor.visit_stmt(stmt);
                    }
                }
            }
            ast::Item::Const(item) => visitor.visit_expr(&item.value),
            ast::Item::Static(item) => visitor.visit_expr(&item.value),
            ast::Item::Test(test) => {
                for stmt in &test.body {
                    visitor.visit_stmt(stmt);
                }
            }
            ast::Item::TypeAlias(_)
            | ast::Item::NewType(_)
            | ast::Item::Struct(_)
            | ast::Item::Enum(_)
            | ast::Item::Trait(_) => {}
        }
    }
    visitor.diagnostics
}

fn is_secret_bearing_crypto_expr(expr: &ast::Expr) -> bool {
    match expr {
        ast::Expr::Call { callee, .. } => matches!(
            callee.as_str(),
            "crypto.hmac_sha256" | "security.sign" | "security.sign_value"
        ),
        ast::Expr::Group(inner) => is_secret_bearing_crypto_expr(inner),
        _ => false,
    }
}

fn collect_main_contract_conditions(
    functions: &[hir::TypedFunction],
) -> (Vec<Option<bool>>, Vec<Option<bool>>) {
    let mut requires = Vec::new();
    let mut ensures = Vec::new();
    for function in functions {
        if function.name != "main"
            && function
                .name
                .rsplit('.')
                .next()
                .is_none_or(|segment| segment != "main")
        {
            continue;
        }
        for statement in &function.body {
            match statement {
                ast::Stmt::Requires(expr) => requires.push(eval_contract_const_bool(expr)),
                ast::Stmt::Ensures(expr) => ensures.push(eval_contract_const_bool(expr)),
                _ => {}
            }
        }
    }
    (requires, ensures)
}

fn eval_contract_const_bool(expr: &ast::Expr) -> Option<bool> {
    let empty_const_strings = HashMap::new();
    match expr {
        ast::Expr::Bool(value) => Some(*value),
        ast::Expr::Int(value) => Some(*value != 0),
        ast::Expr::Str(value) => Some(!value.is_empty()),
        ast::Expr::Group(inner) => eval_contract_const_bool(inner),
        ast::Expr::Unary { op, expr } => match op {
            ast::UnaryOp::Not => eval_contract_const_bool(expr).map(|value| !value),
            ast::UnaryOp::Plus => {
                eval_const_i32_expr(expr, &empty_const_strings).map(|value| value != 0)
            }
            ast::UnaryOp::Neg => {
                eval_const_i32_expr(expr, &empty_const_strings).map(|value| -value != 0)
            }
            ast::UnaryOp::BitNot => {
                eval_const_i32_expr(expr, &empty_const_strings).map(|value| !value != 0)
            }
        },
        ast::Expr::Binary { op, left, right } => match op {
            ast::BinaryOp::And => {
                Some(eval_contract_const_bool(left)? && eval_contract_const_bool(right)?)
            }
            ast::BinaryOp::Or => {
                Some(eval_contract_const_bool(left)? || eval_contract_const_bool(right)?)
            }
            ast::BinaryOp::Eq => Some(
                eval_const_i32_expr(left, &empty_const_strings)?
                    == eval_const_i32_expr(right, &empty_const_strings)?,
            ),
            ast::BinaryOp::Neq => Some(
                eval_const_i32_expr(left, &empty_const_strings)?
                    != eval_const_i32_expr(right, &empty_const_strings)?,
            ),
            ast::BinaryOp::Lt => Some(
                eval_const_i32_expr(left, &empty_const_strings)?
                    < eval_const_i32_expr(right, &empty_const_strings)?,
            ),
            ast::BinaryOp::Lte => Some(
                eval_const_i32_expr(left, &empty_const_strings)?
                    <= eval_const_i32_expr(right, &empty_const_strings)?,
            ),
            ast::BinaryOp::Gt => Some(
                eval_const_i32_expr(left, &empty_const_strings)?
                    > eval_const_i32_expr(right, &empty_const_strings)?,
            ),
            ast::BinaryOp::Gte => Some(
                eval_const_i32_expr(left, &empty_const_strings)?
                    >= eval_const_i32_expr(right, &empty_const_strings)?,
            ),
            _ => eval_const_i32_expr(expr, &empty_const_strings).map(|value| value != 0),
        },
        _ => eval_const_i32_expr(expr, &empty_const_strings).map(|value| value != 0),
    }
}

fn build_native_cfg_map(
    fir: &fir::FirModule,
    variant_tags: &HashMap<String, i32>,
) -> HashMap<String, Result<ControlFlowCfg, String>> {
    let pattern_source_functions =
        collect_pattern_source_function_map_from_typed(&fir.typed_functions);
    fir.typed_functions
        .par_iter()
        .filter(|function| !is_extern_c_import_decl(function))
        .map(|function| {
            let cfg =
                build_control_flow_cfg(&function.body, variant_tags, &pattern_source_functions)
                    .and_then(|cfg| {
                        verify_control_flow_cfg(&cfg)?;
                        Ok(cfg)
                    });
            (
                function.name.clone(),
                cfg.map_err(|error| error.to_string()),
            )
        })
        .collect()
}

fn build_native_canonical_plan(
    fir: &fir::FirModule,
    enforce_contract_checks: bool,
) -> NativeCanonicalPlan {
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    build_native_canonical_plan_with_task_symbols(fir, enforce_contract_checks, &spawn_task_symbols)
}

fn build_native_canonical_plan_with_task_symbols(
    fir: &fir::FirModule,
    enforce_contract_checks: bool,
    spawn_task_symbols: &[String],
) -> NativeCanonicalPlan {
    ensure_codegen_pool_configured();
    let variant_tags = build_variant_tag_map(fir);
    let cfg_by_function = build_native_cfg_map(fir, &variant_tags);
    let mut task_ref_ids = HashMap::<String, i32>::new();
    for (index, symbol) in spawn_task_symbols.iter().enumerate() {
        task_ref_ids.insert(symbol.clone(), (index + 1) as i32);
    }
    let string_literals = collect_native_string_literals_with_gpu(fir);
    NativeCanonicalPlan {
        forced_main_return: compute_forced_main_return(fir, enforce_contract_checks),
        string_literal_ids: build_string_literal_ids(&string_literals),
        global_const_i32: build_global_const_i32_map(fir),
        mutable_static_i32: build_mutable_static_i32_map(fir),
        variant_tags,
        task_ref_ids,
        cfg_by_function,
        data_ops_by_function: fir
            .typed_functions
            .par_iter()
            .filter(|function| !is_extern_c_import_decl(function))
            .map(|function| {
                (
                    function.name.clone(),
                    collect_native_data_ops_for_function(function),
                )
            })
            .collect(),
    }
}

fn collect_native_string_literals_with_gpu(fir: &fir::FirModule) -> Vec<String> {
    let mut string_literals = collect_native_string_literals(fir);
    if let Ok(extra_gpu_strings) = metal_kernel_descriptor_strings(fir) {
        let mut merged = string_literals.into_iter().collect::<HashSet<_>>();
        for value in extra_gpu_strings {
            merged.insert(value);
        }
        string_literals = merged.into_iter().collect();
        string_literals.sort();
    }
    string_literals
}

fn native_mangle_symbol(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn llvm_emit_expr(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    if let Some(result) = llvm_emit_complex_expr(expr, ctx, string_literal_ids, task_ref_ids) {
        return result;
    }
    if let Some(result) = llvm_emit_simple_expr(expr, ctx, string_literal_ids, task_ref_ids) {
        return result;
    }
    Ok(match expr {
        ast::Expr::Int(v) => {
            let ty = if i32::try_from(*v).is_ok() {
                "i32"
            } else {
                "i64"
            };
            LlvmValue {
                value: v.to_string(),
                ty: ty.to_string(),
            }
        }
        ast::Expr::Float { value, bits } => LlvmValue {
            value: llvm_float_literal(*value),
            ty: if bits.unwrap_or(64) == 32 {
                "float".to_string()
            } else {
                "double".to_string()
            },
        },
        ast::Expr::Char(value) => LlvmValue {
            value: (*value as i32).to_string(),
            ty: "i32".to_string(),
        },
        ast::Expr::Bool(v) => LlvmValue {
            value: if *v { "1".to_string() } else { "0".to_string() },
            ty: "i8".to_string(),
        },
        ast::Expr::Str(value) => LlvmValue {
            value: string_literal_ids
                .get(value)
                .copied()
                .unwrap_or(0)
                .to_string(),
            ty: "i32".to_string(),
        },
        ast::Expr::Ident(_) => unreachable!("simple expressions are handled above"),
        ast::Expr::Group(inner) => llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids)?,
        ast::Expr::Await(inner) => llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids)?,
        ast::Expr::Discard(_) => unreachable!("simple expressions are handled above"),
        ast::Expr::Closure { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::Unary { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::FieldAccess { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::StructInit { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::EnumInit { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::TryCatch { try_expr, .. } => {
            llvm_emit_expr(try_expr, ctx, string_literal_ids, task_ref_ids)?
        }
        ast::Expr::If { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::Range { start, .. } => {
            llvm_emit_expr(start, ctx, string_literal_ids, task_ref_ids)?
        }
        ast::Expr::ArrayLiteral(items) => {
            llvm_emit_array_literal_value(items, ctx, string_literal_ids, task_ref_ids)?
        }
        ast::Expr::ObjectLiteral(_) => unreachable!("complex expressions are handled above"),
        ast::Expr::Index { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::Call { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::UnsafeBlock { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::Binary { op, left, right } => {
            llvm_emit_binary_expr(*op, left, right, ctx, string_literal_ids, task_ref_ids)?
        }
        _ => LlvmValue {
            value: "0".to_string(),
            ty: "i32".to_string(),
        },
    })
}

fn expr_task_ref_name(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => Some(name.clone()),
        ast::Expr::FieldAccess { base, field } => {
            let mut name = expr_task_ref_name(base)?;
            name.push('.');
            name.push_str(field);
            Some(name)
        }
        ast::Expr::Group(inner) => expr_task_ref_name(inner),
        ast::Expr::Unary { expr, .. } => expr_task_ref_name(expr),
        _ => None,
    }
}

fn eval_const_string_expr(
    expr: &ast::Expr,
    const_strings: &HashMap<String, String>,
) -> Option<String> {
    match expr {
        ast::Expr::Str(value) => Some(value.clone()),
        ast::Expr::Ident(name) => const_strings.get(name).cloned(),
        ast::Expr::Group(inner) => eval_const_string_expr(inner, const_strings),
        ast::Expr::Call { callee, args } => eval_const_string_call(callee, args, const_strings),
        _ => None,
    }
}

fn eval_const_string_call(
    callee: &str,
    args: &[ast::Expr],
    const_strings: &HashMap<String, String>,
) -> Option<String> {
    match callee {
        "str.concat2" if args.len() == 2 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            Some(format!("{a}{b}"))
        }
        "str.concat3" if args.len() == 3 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            let c = eval_const_string_expr(&args[2], const_strings)?;
            Some(format!("{a}{b}{c}"))
        }
        "str.concat4" if args.len() == 4 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            let c = eval_const_string_expr(&args[2], const_strings)?;
            let d = eval_const_string_expr(&args[3], const_strings)?;
            Some(format!("{a}{b}{c}{d}"))
        }
        "str.concat" if !args.is_empty() => {
            let mut out = String::new();
            for arg in args {
                out.push_str(&eval_const_string_expr(arg, const_strings)?);
            }
            Some(out)
        }
        "str.trim" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            Some(value.trim().to_string())
        }
        "str.replace" if args.len() == 3 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let from = eval_const_string_expr(&args[1], const_strings)?;
            let to = eval_const_string_expr(&args[2], const_strings)?;
            Some(value.replace(&from, &to))
        }
        "str.slice" if args.len() == 3 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let start = eval_const_i32_expr(&args[1], const_strings)
                .unwrap_or(0)
                .max(0) as usize;
            let end = eval_const_i32_expr(&args[2], const_strings)
                .unwrap_or(0)
                .max(0) as usize;
            let len = value.len();
            let s = start.min(len);
            let e = end.min(len);
            if value.is_char_boundary(s) && value.is_char_boundary(e) {
                if e >= s {
                    Some(value[s..e].to_string())
                } else {
                    Some(String::new())
                }
            } else {
                None
            }
        }
        "str.upper_ascii" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            Some(value.to_ascii_uppercase())
        }
        "str.lower_ascii" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            Some(value.to_ascii_lowercase())
        }
        _ => None,
    }
}

fn eval_const_i32_expr(expr: &ast::Expr, const_strings: &HashMap<String, String>) -> Option<i32> {
    match expr {
        ast::Expr::Int(value) => i32::try_from(*value).ok(),
        ast::Expr::Bool(value) => Some(if *value { 1 } else { 0 }),
        ast::Expr::Group(inner) => eval_const_i32_expr(inner, const_strings),
        ast::Expr::Call { callee, args } => eval_const_i32_call(callee, args, const_strings),
        _ => None,
    }
}

fn eval_const_i32_call(
    callee: &str,
    args: &[ast::Expr],
    const_strings: &HashMap<String, String>,
) -> Option<i32> {
    match callee {
        "str.contains" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let needle = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.contains(&needle) { 1 } else { 0 })
        }
        "str.starts_with" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let prefix = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.starts_with(&prefix) { 1 } else { 0 })
        }
        "str.ends_with" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let suffix = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.ends_with(&suffix) { 1 } else { 0 })
        }
        "str.len" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            i32::try_from(value.len()).ok()
        }
        _ => None,
    }
}

fn is_native_data_plane_string_call(callee: &str) -> bool {
    matches!(callee, "str.concat")
        || native_data_plane_import_for_callee(callee)
            .is_some_and(|import| import.callee.starts_with("str."))
}

fn canonicalize_array_index_window(expr: &ast::Expr) -> Option<(String, i32)> {
    match expr {
        ast::Expr::Ident(name) => Some((name.clone(), 0)),
        ast::Expr::Group(inner) => canonicalize_array_index_window(inner),
        ast::Expr::Binary { op, left, right } => match op {
            ast::BinaryOp::Add => match (left.as_ref(), right.as_ref()) {
                (ast::Expr::Ident(name), ast::Expr::Int(offset)) => {
                    i32::try_from(*offset).ok().map(|off| (name.clone(), off))
                }
                (ast::Expr::Int(offset), ast::Expr::Ident(name)) => {
                    i32::try_from(*offset).ok().map(|off| (name.clone(), off))
                }
                _ => None,
            },
            ast::BinaryOp::Sub => match (left.as_ref(), right.as_ref()) {
                (ast::Expr::Ident(name), ast::Expr::Int(offset)) => i32::try_from(*offset)
                    .ok()
                    .and_then(|off| off.checked_neg())
                    .map(|off| (name.clone(), off)),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn collect_used_runtime_imports_from_stmt(
    stmt: &ast::Stmt,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_used_runtime_imports_from_expr(value, seen, used),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            for nested in then_body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
            for nested in else_body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_used_runtime_imports_from_stmt(init, seen, used);
            }
            if let Some(condition) = condition {
                collect_used_runtime_imports_from_expr(condition, seen, used);
            }
            if let Some(step) = step {
                collect_used_runtime_imports_from_stmt(step, seen, used);
            }
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_used_runtime_imports_from_expr(iterable, seen, used);
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_used_runtime_imports_from_expr(scrutinee, seen, used);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_used_runtime_imports_from_expr(guard, seen, used);
                }
                collect_used_runtime_imports_from_expr(&arm.value, seen, used);
            }
        }
    }
}

fn collect_used_runtime_imports_from_expr(
    expr: &ast::Expr,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            let empty_const_strings = HashMap::<String, String>::new();
            let folded_const = eval_const_string_call(callee, args, &empty_const_strings).is_some()
                || eval_const_i32_call(callee, args, &empty_const_strings).is_some();
            if !folded_const {
                if let Some(import) = native_runtime_import_for_callee(callee) {
                    if seen.insert(import.symbol) {
                        used.push(import);
                    }
                }
            }
            for arg in args {
                collect_used_runtime_imports_from_expr(arg, seen, used);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_used_runtime_imports_from_stmt(stmt, seen, used);
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_used_runtime_imports_from_expr(base, seen, used);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::ObjectLiteral(fields) => {
            if let Some(import) = native_runtime_import_for_callee("map.new") {
                if seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            if let Some(import) = native_runtime_import_for_callee("map.set") {
                if seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            for (_, value) in fields {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_used_runtime_imports_from_expr(body, seen, used);
        }
        ast::Expr::Group(inner) => {
            collect_used_runtime_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_used_runtime_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_used_runtime_imports_from_expr(expr, seen, used);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_used_runtime_imports_from_expr(try_expr, seen, used);
            collect_used_runtime_imports_from_expr(catch_expr, seen, used);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            collect_used_runtime_imports_from_expr(then_expr, seen, used);
            collect_used_runtime_imports_from_expr(else_expr, seen, used);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_used_runtime_imports_from_expr(left, seen, used);
            collect_used_runtime_imports_from_expr(right, seen, used);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_used_runtime_imports_from_expr(start, seen, used);
            collect_used_runtime_imports_from_expr(end, seen, used);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_used_runtime_imports_from_expr(item, seen, used);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_used_runtime_imports_from_expr(base, seen, used);
            collect_used_runtime_imports_from_expr(index, seen, used);
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

fn collect_used_data_plane_imports_from_stmt(
    stmt: &ast::Stmt,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_used_data_plane_imports_from_expr(value, seen, used),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            for nested in then_body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
            for nested in else_body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_used_data_plane_imports_from_stmt(init, seen, used);
            }
            if let Some(condition) = condition {
                collect_used_data_plane_imports_from_expr(condition, seen, used);
            }
            if let Some(step) = step {
                collect_used_data_plane_imports_from_stmt(step, seen, used);
            }
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_used_data_plane_imports_from_expr(iterable, seen, used);
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_used_data_plane_imports_from_expr(scrutinee, seen, used);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_used_data_plane_imports_from_expr(guard, seen, used);
                }
                collect_used_data_plane_imports_from_expr(&arm.value, seen, used);
            }
        }
    }
}

fn collect_used_data_plane_imports_from_expr(
    expr: &ast::Expr,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if let Some(import) = native_data_plane_import_for_callee(callee) {
                let empty_const_strings = HashMap::<String, String>::new();
                let folded_const = eval_const_string_call(callee, args, &empty_const_strings)
                    .is_some()
                    || eval_const_i32_call(callee, args, &empty_const_strings).is_some();
                let can_skip = folded_const && callee.starts_with("str.");
                if !can_skip && seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            for arg in args {
                collect_used_data_plane_imports_from_expr(arg, seen, used);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_used_data_plane_imports_from_stmt(stmt, seen, used);
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_used_data_plane_imports_from_expr(base, seen, used);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_used_data_plane_imports_from_expr(body, seen, used);
        }
        ast::Expr::Group(inner) => {
            collect_used_data_plane_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_used_data_plane_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_used_data_plane_imports_from_expr(expr, seen, used);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_used_data_plane_imports_from_expr(try_expr, seen, used);
            collect_used_data_plane_imports_from_expr(catch_expr, seen, used);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            collect_used_data_plane_imports_from_expr(then_expr, seen, used);
            collect_used_data_plane_imports_from_expr(else_expr, seen, used);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_used_data_plane_imports_from_expr(left, seen, used);
            collect_used_data_plane_imports_from_expr(right, seen, used);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_used_data_plane_imports_from_expr(start, seen, used);
            collect_used_data_plane_imports_from_expr(end, seen, used);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_used_data_plane_imports_from_expr(item, seen, used);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_used_data_plane_imports_from_expr(base, seen, used);
            collect_used_data_plane_imports_from_expr(index, seen, used);
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
