use super::*;

pub(crate) fn compute_forced_main_return(fir: &fir::FirModule, enforce_contract_checks: bool) -> Option<i32> {
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

pub(crate) fn merge_contract_conditions(
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

pub(crate) fn compile_time_contract_diagnostics(
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

pub(crate) fn strict_async_contract_diagnostics(fir: &fir::FirModule) -> Vec<diagnostics::Diagnostic> {
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

pub(crate) fn strict_memory_phase_contract_diagnostics(fir: &fir::FirModule) -> Vec<diagnostics::Diagnostic> {
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

pub(crate) fn strict_rpc_contract_diagnostics(
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

pub(crate) fn strict_stdlib_capability_policy_diagnostics(
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

pub(crate) fn is_secret_bearing_crypto_expr(expr: &ast::Expr) -> bool {
    match expr {
        ast::Expr::Call { callee, .. } => matches!(
            callee.as_str(),
            "crypto.hmac_sha256" | "security.sign" | "security.sign_value"
        ),
        ast::Expr::Group(inner) => is_secret_bearing_crypto_expr(inner),
        _ => false,
    }
}

pub(crate) fn collect_main_contract_conditions(
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

pub(crate) fn eval_contract_const_bool(expr: &ast::Expr) -> Option<bool> {
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

