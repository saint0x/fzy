fn build_rpc_safety_json(module: &ast::Module, fir: &fir::FirModule) -> serde_json::Value {
    let rpc_methods = fir
        .typed_functions
        .iter()
        .filter(|function| {
            function.is_extern
                && function
                    .abi
                    .as_deref()
                    .is_some_and(|abi| abi.eq_ignore_ascii_case("rpc"))
        })
        .map(|function| {
            let params = function
                .params
                .iter()
                .map(|param| {
                    serde_json::json!({
                        "name": param.name,
                        "type": param.ty.to_string(),
                        "ownership": param.ty.rpc_boundary_ownership(),
                        "payloadSupported": param.ty.is_rpc_payload_supported(),
                    })
                })
                .collect::<Vec<_>>();
            let request_explicit = params.iter().all(|param| {
                param["ownership"]
                    .as_str()
                    .is_some_and(|ownership| ownership == "value" || ownership == "owned")
                    && param["payloadSupported"].as_bool() == Some(true)
            });
            let response_ownership = function.return_type.rpc_boundary_ownership();
            let response_payload_supported = function.return_type.is_rpc_payload_supported();
            serde_json::json!({
                "name": function.name,
                "canonicalName": function.link_name.clone().unwrap_or_else(|| function.name.clone()),
                "methodNameStable": function.link_name.as_deref().is_none_or(|link_name| link_name == function.name),
                "params": params,
                "returnType": function.return_type.to_string(),
                "requestOwnershipExplicit": request_explicit,
                "responseOwnership": response_ownership,
                "responseOwnershipExplicit": matches!(response_ownership, "value" | "owned" | "status") && response_payload_supported,
                "payloadTypesSupported": request_explicit && response_payload_supported,
                "errorNormalization": rpc_error_normalization_kind(&function.return_type),
            })
        })
        .collect::<Vec<_>>();
    let policy_evidence = collect_rpc_policy_evidence(module, &rpc_methods);
    let deadline_policies = rpc_methods
        .iter()
        .map(|method| {
            let name = method["name"].as_str().unwrap_or_default();
            let evidence = policy_evidence
                .get(name)
                .cloned()
                .unwrap_or_else(RpcPolicyEvidence::default);
            serde_json::json!({
                "method": name,
                "policy": evidence.deadline_policy(),
                "calls": evidence.calls,
                "protectedCalls": evidence.deadline_protected_calls,
                "strictReady": evidence.calls > 0 && evidence.deadline_protected_calls == evidence.calls,
            })
        })
        .collect::<Vec<_>>();
    let cancel_policies = rpc_methods
        .iter()
        .map(|method| {
            let name = method["name"].as_str().unwrap_or_default();
            let evidence = policy_evidence
                .get(name)
                .cloned()
                .unwrap_or_else(RpcPolicyEvidence::default);
            serde_json::json!({
                "method": name,
                "policy": evidence.cancel_policy(),
                "calls": evidence.calls,
                "cancelObservedCalls": evidence.cancel_observed_calls,
                "recvObservedCalls": evidence.recv_observed_calls,
                "cleanupObservedCalls": evidence.cleanup_observed_calls(),
                "cleanupPolicy": evidence.cleanup_policy(),
                "handlerCleanupStatus": evidence.cleanup_policy(),
                "strictReady": evidence.calls > 0 && evidence.cleanup_observed_calls() == evidence.calls,
            })
        })
        .collect::<Vec<_>>();

    let payload_contracts = rpc_methods
        .iter()
        .map(|method| {
            serde_json::json!({
                "method": method["name"].as_str().unwrap_or_default(),
                "requestOwnershipExplicit": method["requestOwnershipExplicit"],
                "responseOwnershipExplicit": method["responseOwnershipExplicit"],
                "payloadTypesSupported": method["payloadTypesSupported"],
                "methodNameStable": method["methodNameStable"],
                "errorNormalization": method["errorNormalization"],
                "strictReady": method["requestOwnershipExplicit"].as_bool() == Some(true)
                    && method["responseOwnershipExplicit"].as_bool() == Some(true)
                    && method["payloadTypesSupported"].as_bool() == Some(true)
                    && method["methodNameStable"].as_bool() == Some(true),
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "schemaVersion": "fozzylang.rpc_safety.v1",
        "versions": compatibility_versions_json(),
        "rpc_methods": rpc_methods,
        "strictRequirements": {
            "deadlinePerCall": true,
            "handlerCancelCleanup": "required",
            "frameTraceability": true,
            "requestOwnershipExplicit": true,
            "responseOwnershipExplicit": true,
            "payloadTypesSupported": true,
            "methodNameStable": true,
        },
        "deadline_policies": deadline_policies,
        "cancel_policies": cancel_policies,
        "payload_contracts": payload_contracts,
        "resource_cleanup": [],
        "rpc_frames": [
            "rpc_send",
            "rpc_recv",
            "rpc_deadline",
            "rpc_cancel",
            "rpc_resource_open",
            "rpc_resource_close",
            "rpc_resource_leak_rejected"
        ],
    })
}

#[derive(Debug, Clone, Default)]
struct RpcPolicyEvidence {
    calls: usize,
    deadline_protected_calls: usize,
    cancel_observed_calls: usize,
    recv_observed_calls: usize,
}

impl RpcPolicyEvidence {
    fn deadline_policy(&self) -> &'static str {
        if self.calls == 0 {
            "not_observed"
        } else if self.deadline_protected_calls == self.calls {
            "explicit"
        } else if self.deadline_protected_calls > 0 {
            "partial"
        } else {
            "missing"
        }
    }

    fn cancel_policy(&self) -> &'static str {
        if self.calls == 0 {
            "not_observed"
        } else if self.cancel_observed_calls == self.calls {
            "cancel"
        } else if self.recv_observed_calls == self.calls {
            "recv"
        } else if self.cleanup_observed_calls() == self.calls {
            "mixed"
        } else if self.cancel_observed_calls > 0 {
            "cancel_partial"
        } else if self.recv_observed_calls > 0 {
            "recv_partial"
        } else {
            "missing"
        }
    }

    fn cleanup_observed_calls(&self) -> usize {
        self.cancel_observed_calls.max(self.recv_observed_calls)
    }

    fn cleanup_policy(&self) -> &'static str {
        if self.calls == 0 {
            "not_observed"
        } else if self.cleanup_observed_calls() == self.calls {
            "explicit"
        } else if self.cleanup_observed_calls() > 0 {
            "partial"
        } else {
            "missing"
        }
    }
}

fn rpc_error_normalization_kind(return_type: &ast::Type) -> &'static str {
    match return_type {
        ast::Type::Void => "status_only",
        ast::Type::Result { .. } => "result",
        ast::Type::Int {
            signed: true,
            bits: 32,
        }
        | ast::Type::ExitStatus => "status_code",
        _ => "typed_payload",
    }
}

#[derive(Debug, Clone, Default)]
struct PendingRpcCall {
    method: String,
    deadline_seen: bool,
    cancel_seen: bool,
    recv_seen: bool,
}

fn collect_rpc_policy_evidence(
    module: &ast::Module,
    rpc_methods: &[serde_json::Value],
) -> HashMap<String, RpcPolicyEvidence> {
    let rpc_method_names = rpc_methods
        .iter()
        .filter_map(|method| method["name"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let call_sequence = collect_pipeline_call_sequence(module);
    let mut evidence = rpc_method_names
        .iter()
        .map(|method| ((*method).to_string(), RpcPolicyEvidence::default()))
        .collect::<HashMap<_, _>>();
    let mut pending = Vec::<PendingRpcCall>::new();
    let mut next_rpc_has_deadline = false;

    for call in call_sequence {
        if rpc_method_names.contains(call.as_str()) {
            let entry = evidence.entry(call.clone()).or_default();
            entry.calls += 1;
            pending.push(PendingRpcCall {
                method: call,
                deadline_seen: next_rpc_has_deadline,
                cancel_seen: false,
                recv_seen: false,
            });
            next_rpc_has_deadline = false;
            continue;
        }

        match call.as_str() {
            "timeout" | "deadline" => {
                if let Some(last) = pending
                    .iter_mut()
                    .rev()
                    .find(|rpc| !rpc.cancel_seen && !rpc.recv_seen)
                {
                    last.deadline_seen = true;
                } else {
                    next_rpc_has_deadline = true;
                }
            }
            "cancel" => {
                if let Some(last) = pending
                    .iter_mut()
                    .rev()
                    .find(|rpc| !rpc.cancel_seen && !rpc.recv_seen)
                {
                    last.cancel_seen = true;
                }
            }
            "recv" => {
                if let Some(last) = pending
                    .iter_mut()
                    .rev()
                    .find(|rpc| !rpc.recv_seen && !rpc.cancel_seen)
                {
                    last.recv_seen = true;
                }
            }
            _ => {}
        }
    }

    for rpc in pending {
        let entry = evidence.entry(rpc.method).or_default();
        if rpc.deadline_seen {
            entry.deadline_protected_calls += 1;
        }
        if rpc.cancel_seen {
            entry.cancel_observed_calls += 1;
        }
        if rpc.recv_seen {
            entry.recv_observed_calls += 1;
        }
    }

    evidence
}

fn collect_pipeline_call_sequence(module: &ast::Module) -> Vec<String> {
    let mut call_sequence = Vec::new();
    for item in &module.items {
        if let ast::Item::Function(function) = item {
            for statement in &function.body {
                collect_pipeline_call_names_from_stmt(statement, &mut call_sequence);
            }
        }
    }
    call_sequence
}

fn collect_pipeline_call_names_from_stmt(statement: &ast::Stmt, out: &mut Vec<String>) {
    match statement {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_pipeline_call_names_from_expr(value, out),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_pipeline_call_names_from_expr(value, out);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_pipeline_call_names_from_expr(condition, out);
            for stmt in then_body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
            for stmt in else_body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_pipeline_call_names_from_expr(condition, out);
            for stmt in body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_pipeline_call_names_from_stmt(init, out);
            }
            if let Some(condition) = condition {
                collect_pipeline_call_names_from_expr(condition, out);
            }
            if let Some(step) = step {
                collect_pipeline_call_names_from_stmt(step, out);
            }
            for stmt in body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_pipeline_call_names_from_expr(iterable, out);
            for stmt in body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::Loop { body } => {
            for stmt in body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_pipeline_call_names_from_expr(scrutinee, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_pipeline_call_names_from_expr(guard, out);
                }
                collect_pipeline_call_names_from_expr(&arm.value, out);
            }
        }
        ast::Stmt::Break(value) => {
            if let Some(value) = value {
                collect_pipeline_call_names_from_expr(value, out);
            }
        }
        ast::Stmt::Continue => {}
    }
}

fn collect_pipeline_call_names_from_expr(expr: &ast::Expr, out: &mut Vec<String>) {
    match expr {
        ast::Expr::Call { callee, args } => {
            for arg in args {
                collect_pipeline_call_names_from_expr(arg, out);
            }
            out.push(callee.clone());
        }
        ast::Expr::Await(inner)
        | ast::Expr::Group(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::FieldAccess { base: inner, .. }
        | ast::Expr::Unary { expr: inner, .. } => collect_pipeline_call_names_from_expr(inner, out),
        ast::Expr::Index { base, index } => {
            collect_pipeline_call_names_from_expr(base, out);
            collect_pipeline_call_names_from_expr(index, out);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_pipeline_call_names_from_expr(left, out);
            collect_pipeline_call_names_from_expr(right, out);
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_pipeline_call_names_from_expr(value, out);
            }
        }
        ast::Expr::EnumInit { payload, .. }
        | ast::Expr::Tuple(payload)
        | ast::Expr::ArrayLiteral(payload) => {
            for value in payload {
                collect_pipeline_call_names_from_expr(value, out);
            }
        }
        ast::Expr::Closure { body, .. } => collect_pipeline_call_names_from_expr(body, out),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_pipeline_call_names_from_expr(try_expr, out);
            collect_pipeline_call_names_from_expr(catch_expr, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_pipeline_call_names_from_expr(condition, out);
            collect_pipeline_call_names_from_expr(then_expr, out);
            collect_pipeline_call_names_from_expr(else_expr, out);
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_pipeline_call_names_from_expr(scrutinee, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_pipeline_call_names_from_expr(guard, out);
                }
                collect_pipeline_call_names_from_expr(&arm.value, out);
            }
        }
        ast::Expr::While { condition, body } => {
            collect_pipeline_call_names_from_expr(condition, out);
            for stmt in body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_pipeline_call_names_from_stmt(init, out);
            }
            if let Some(condition) = condition {
                collect_pipeline_call_names_from_expr(condition, out);
            }
            if let Some(step) = step {
                collect_pipeline_call_names_from_stmt(step, out);
            }
            for stmt in body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_pipeline_call_names_from_expr(iterable, out);
            for stmt in body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
        }
        ast::Expr::Loop { body } => {
            for stmt in body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_pipeline_call_names_from_expr(value, out);
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_pipeline_call_names_from_expr(start, out);
            collect_pipeline_call_names_from_expr(end, out);
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_pipeline_call_names_from_stmt(stmt, out);
            }
        }
        ast::Expr::Ident(_)
        | ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Char(_)
        | ast::Expr::Continue => {}
    }
}

fn build_ffi_report_json(fir: &fir::FirModule) -> serde_json::Value {
    let repr_c_names = collect_repr_c_names_for_ffi(fir);
    let imports = collect_extern_c_imports(fir)
        .into_iter()
        .map(|function| {
            let params = function
                .params
                .iter()
                .map(|param| {
                    serde_json::json!({
                        "name": param.name,
                        "type": param.ty.to_string(),
                        "pointerLike": param.ty.is_pointer_like(),
                        "ownershipTag": ffi_pointer_ownership_tag(&param.name),
                        "hasLenPair": ffi_has_len_pair(function, &param.name),
                        "isContextAnchor": ffi_is_context_anchor_name(&param.name),
                        "isCallback": ffi_is_callback_param(&param.ty),
                    })
                })
                .collect::<Vec<_>>();
            let pointer_contract_violation = ffi_pointer_param_missing_contract(function);
            let callback_anchor_violation = ffi_callback_param_missing_anchor(function);
            let unstable_types = ffi_unstable_types(function, &repr_c_names);
            serde_json::json!({
                "name": function.name,
                "unsafe": function.is_unsafe,
                "async": function.is_async,
                "linkName": function.link_name,
                "params": params,
                "returnType": function.return_type.to_string(),
                "panicBoundary": function.ffi_panic,
                "hasPointerLikeSurface": function.return_type.is_pointer_like()
                    || function.params.iter().any(|param| param.ty.is_pointer_like()),
                "pointerContractOk": pointer_contract_violation.is_none(),
                "pointerContractViolation": pointer_contract_violation,
                "callbackContextAnchorOk": callback_anchor_violation.is_none(),
                "callbackContextAnchorViolation": callback_anchor_violation,
                "ffiStableOk": unstable_types.is_empty(),
                "unstableTypes": unstable_types,
                "asyncImportForbidden": function.is_async,
            })
        })
        .collect::<Vec<_>>();
    let exports = fir
        .typed_functions
        .iter()
        .filter(|function| is_extern_c_abi_function(function) && !function.body.is_empty())
        .map(|function| {
            let params = function
                .params
                .iter()
                .map(|param| {
                    serde_json::json!({
                        "name": param.name,
                        "type": param.ty.to_string(),
                        "pointerLike": param.ty.is_pointer_like(),
                        "ownershipTag": ffi_pointer_ownership_tag(&param.name),
                        "hasLenPair": ffi_has_len_pair(function, &param.name),
                        "isContextAnchor": ffi_is_context_anchor_name(&param.name),
                        "isCallback": ffi_is_callback_param(&param.ty),
                    })
                })
                .collect::<Vec<_>>();
            let unstable_types = ffi_unstable_types(function, &repr_c_names);
            serde_json::json!({
                "name": function.name,
                "async": function.is_async,
                "linkName": function.link_name,
                "params": params,
                "returnType": function.return_type.to_string(),
                "panicBoundary": function.ffi_panic,
                "panicBoundaryDeclared": function.ffi_panic.is_some(),
                "ffiStableOk": unstable_types.is_empty(),
                "unstableTypes": unstable_types,
            })
        })
        .collect::<Vec<_>>();
    let pointer_contract_violation_count = imports
        .iter()
        .filter(|item| !item["pointerContractOk"].as_bool().unwrap_or(false))
        .count();
    let callback_context_anchor_violation_count = imports
        .iter()
        .filter(|item| !item["callbackContextAnchorOk"].as_bool().unwrap_or(false))
        .count();
    let async_import_violation_count = imports
        .iter()
        .filter(|item| item["asyncImportForbidden"].as_bool().unwrap_or(false))
        .count();
    let ffi_stable_type_violation_count = imports
        .iter()
        .chain(exports.iter())
        .filter(|item| !item["ffiStableOk"].as_bool().unwrap_or(false))
        .count();
    let missing_panic_boundary_count = exports
        .iter()
        .filter(|item| !item["panicBoundaryDeclared"].as_bool().unwrap_or(false))
        .count();
    serde_json::json!({
        "schemaVersion": "fozzylang.ffi_report.v2",
        "versions": compatibility_versions_json(),
        "pointerContractViolationCount": pointer_contract_violation_count,
        "callbackContextAnchorViolationCount": callback_context_anchor_violation_count,
        "ffiStableTypeViolationCount": ffi_stable_type_violation_count,
        "asyncImportViolationCount": async_import_violation_count,
        "missingPanicBoundaryCount": missing_panic_boundary_count,
        "imports": imports,
        "exports": exports,
        "asyncExports": collect_async_c_exports(fir).iter().map(|export| {
            serde_json::json!({
                "name": export.name,
                "symbol": export.mangled_symbol,
                "params": export.params.iter().map(|(ty, name)| {
                    serde_json::json!({
                        "name": name,
                        "cType": ty,
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    })
}

fn render_ffi_report_markdown(value: &serde_json::Value) -> String {
    let mut out = String::from("# FFI Report\n\n");
    let import_count = value["imports"]
        .as_array()
        .map(|items| items.len())
        .unwrap_or(0);
    let export_count = value["exports"]
        .as_array()
        .map(|items| items.len())
        .unwrap_or(0);
    out.push_str(&format!(
        "- Imports: {import_count}\n- Exports: {export_count}\n- Pointer contract violations: {}\n- Callback anchor violations: {}\n- FFI-stable type violations: {}\n- Async import violations: {}\n- Missing panic boundary declarations: {}\n\n",
        value["pointerContractViolationCount"].as_u64().unwrap_or(0),
        value["callbackContextAnchorViolationCount"].as_u64().unwrap_or(0),
        value["ffiStableTypeViolationCount"].as_u64().unwrap_or(0),
        value["asyncImportViolationCount"].as_u64().unwrap_or(0),
        value["missingPanicBoundaryCount"].as_u64().unwrap_or(0),
    ));
    out.push_str("## Imports\n\n");
    if let Some(imports) = value["imports"].as_array() {
        for import in imports {
            out.push_str(&format!(
                "- `{}` -> `{}` | pointer_contract_ok={} | callback_anchor_ok={} | ffi_stable_ok={} | async_forbidden={}\n",
                import["name"].as_str().unwrap_or("?"),
                import["returnType"].as_str().unwrap_or("?"),
                import["pointerContractOk"].as_bool().unwrap_or(false),
                import["callbackContextAnchorOk"].as_bool().unwrap_or(false),
                import["ffiStableOk"].as_bool().unwrap_or(false),
                import["asyncImportForbidden"].as_bool().unwrap_or(false),
            ));
        }
    }
    out.push_str("\n## Exports\n\n");
    if let Some(exports) = value["exports"].as_array() {
        for export in exports {
            out.push_str(&format!(
                "- `{}` -> `{}` | panic_boundary_declared={} | ffi_stable_ok={}\n",
                export["name"].as_str().unwrap_or("?"),
                export["returnType"].as_str().unwrap_or("?"),
                export["panicBoundaryDeclared"].as_bool().unwrap_or(false),
                export["ffiStableOk"].as_bool().unwrap_or(false),
            ));
        }
    }
    out
}

fn collect_repr_c_names_for_ffi(fir: &fir::FirModule) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (name, item) in &fir.struct_defs {
        if item
            .repr
            .as_deref()
            .is_some_and(|repr| repr.to_ascii_lowercase().contains('c'))
        {
            names.insert(name.clone());
        }
    }
    for (name, item) in &fir.enum_defs {
        if item
            .repr
            .as_deref()
            .is_some_and(|repr| repr.to_ascii_lowercase().contains('c'))
        {
            names.insert(name.clone());
        }
    }
    names
}

fn ffi_pointer_ownership_tag(name: &str) -> Option<&'static str> {
    ["_owned", "_borrowed", "_out", "_inout"]
        .into_iter()
        .find_map(|suffix| name.ends_with(suffix).then_some(&suffix[1..]))
}

fn ffi_pointer_base_name(name: &str) -> String {
    for suffix in ["_borrowed", "_owned", "_out", "_inout"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    name.to_string()
}

fn ffi_has_len_pair(function: &hir::TypedFunction, pointer_param_name: &str) -> bool {
    let base = ffi_pointer_base_name(pointer_param_name);
    let expected = format!("{base}_len");
    function.params.iter().any(|candidate| {
        matches!(candidate.ty, ast::Type::USize)
            && (candidate.name == "len"
                || candidate.name == expected
                || candidate.name == format!("{base}_bytes"))
    })
}

fn ffi_is_context_anchor_name(name: &str) -> bool {
    name.ends_with("_ctx") || name.ends_with("_context")
}

fn ffi_is_callback_param(ty: &ast::Type) -> bool {
    matches!(ty, ast::Type::Function { .. })
}

fn ffi_pointer_param_missing_contract(function: &hir::TypedFunction) -> Option<String> {
    if !(function.is_extern && function.abi.as_deref() == Some("c") && function.body.is_empty()) {
        return None;
    }
    for param in &function.params {
        if !matches!(param.ty, ast::Type::Ptr { .. }) {
            continue;
        }
        let tagged = ffi_pointer_ownership_tag(&param.name).is_some();
        let ctx_param = ffi_is_context_anchor_name(&param.name);
        if (!tagged && !ctx_param) || (!ctx_param && !ffi_has_len_pair(function, &param.name)) {
            return Some(param.name.clone());
        }
    }
    None
}

fn ffi_callback_param_missing_anchor(function: &hir::TypedFunction) -> Option<String> {
    if !(function.is_extern && function.abi.as_deref() == Some("c") && function.body.is_empty()) {
        return None;
    }
    for (index, param) in function.params.iter().enumerate() {
        if !ffi_is_callback_param(&param.ty) {
            continue;
        }
        let prev_is_anchor = if index > 0 {
            function
                .params
                .get(index - 1)
                .is_some_and(|neighbor| ffi_is_context_anchor_name(&neighbor.name))
        } else {
            false
        };
        let next_is_anchor = function
            .params
            .get(index + 1)
            .is_some_and(|neighbor| ffi_is_context_anchor_name(&neighbor.name));
        if !(prev_is_anchor || next_is_anchor) {
            return Some(param.name.clone());
        }
    }
    None
}

fn ffi_stable_type(ty: &ast::Type, repr_c_names: &BTreeSet<String>) -> bool {
    match ty {
        ast::Type::Never
        | ast::Type::Void
        | ast::Type::Bool
        | ast::Type::Char
        | ast::Type::Float { .. }
        | ast::Type::ISize
        | ast::Type::USize
        | ast::Type::Int { .. } => true,
        ast::Type::Ptr { to, .. } => ffi_stable_type(to, repr_c_names),
        ast::Type::Named { name, args } => args.is_empty() && repr_c_names.contains(name),
        ast::Type::Function { params, ret } => {
            params
                .iter()
                .all(|param| ffi_stable_type(param, repr_c_names))
                && ffi_stable_type(ret, repr_c_names)
        }
        _ => false,
    }
}

fn ffi_unstable_types(
    function: &hir::TypedFunction,
    repr_c_names: &BTreeSet<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    if !ffi_stable_type(&function.return_type, repr_c_names) {
        out.push(format!("return: {}", function.return_type));
    }
    for param in &function.params {
        if !ffi_stable_type(&param.ty, repr_c_names) {
            out.push(format!("param {}: {}", param.name, param.ty));
        }
    }
    out
}

fn build_native_runtime_contracts_json() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": "fozzylang.native_runtime_contracts.v1",
        "versions": compatibility_versions_json(),
        "imports": native_runtime_contracts().into_iter().map(|contract| {
            serde_json::json!({
                "callee": contract.callee,
                "symbol": contract.symbol,
                "arity": contract.arity,
                "argOwnership": contract.arg_ownership,
                "returnOwnership": contract.return_ownership,
                "requiredCapability": contract.required_capability,
                "linearity": contract.linearity,
                "errorBehavior": contract.error_behavior,
                "traceBehavior": contract.trace_behavior,
                "blockingBehavior": contract.blocking_behavior,
            })
        }).collect::<Vec<_>>(),
    })
}

fn render_native_runtime_contracts_markdown(value: &serde_json::Value) -> String {
    let mut out = String::from("# Native Runtime Contracts\n\n");
    let import_count = value["imports"]
        .as_array()
        .map(|items| items.len())
        .unwrap_or(0);
    out.push_str(&format!(
        "- Imports: {import_count}\n- Schema: `{}`\n\n",
        value["schemaVersion"].as_str().unwrap_or("unknown")
    ));
    out.push_str(
        "| Callee | Symbol | Arity | Arg Ownership | Return Ownership | Capability | Linearity | Error | Trace | Blocking |\n|---|---|---:|---|---|---|---|---|---|---|\n",
    );
    if let Some(imports) = value["imports"].as_array() {
        for import in imports {
            out.push_str(&format!(
                "| `{}` | `{}` | {} | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |\n",
                import["callee"].as_str().unwrap_or("?"),
                import["symbol"].as_str().unwrap_or("?"),
                import["arity"].as_u64().unwrap_or(0),
                import["argOwnership"].as_str().unwrap_or("?"),
                import["returnOwnership"].as_str().unwrap_or("?"),
                import["requiredCapability"].as_str().unwrap_or("?"),
                import["linearity"].as_str().unwrap_or("?"),
                import["errorBehavior"].as_str().unwrap_or("?"),
                import["traceBehavior"].as_str().unwrap_or("?"),
                import["blockingBehavior"].as_str().unwrap_or("?"),
            ));
        }
    }
    out
}

fn build_handle_contracts_json() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": "fozzylang.handle_contracts.v1",
        "versions": compatibility_versions_json(),
        "handles": hir::runtime_handle_contracts().iter().map(|contract| {
            serde_json::json!({
                "name": contract.name,
                "copy": contract.copy,
                "owned": contract.owned,
                "linear": contract.linear,
                "closable": contract.closable,
                "sendSafe": contract.send_safe,
                "asyncStable": contract.async_stable,
                "producerIntrinsics": contract.producer_intrinsics,
                "consumerIntrinsics": contract.consumer_intrinsics,
                "observerIntrinsics": contract.observer_intrinsics,
            })
        }).collect::<Vec<_>>(),
    })
}

fn collect_function_owner_artifacts(
    function: &hir::TypedFunction,
    out: &mut Vec<MemoryOwnerArtifact>,
) {
    fn create_owner(
        function_name: &str,
        binding: &str,
        created_at: String,
        next_owner_id: &mut usize,
        owners: &mut BTreeMap<String, usize>,
        rows: &mut Vec<MemoryOwnerArtifact>,
    ) {
        let owner_id = *next_owner_id;
        *next_owner_id += 1;
        owners.insert(binding.to_string(), rows.len());
        rows.push(MemoryOwnerArtifact {
            function: function_name.to_string(),
            name: binding.to_string(),
            owner_id,
            created_at,
            terminal_state: "Owned".to_string(),
            terminal_at: None,
            transfer_edges: Vec::new(),
        });
    }

    fn mark_terminal(
        binding: &str,
        owners: &mut BTreeMap<String, usize>,
        rows: &mut [MemoryOwnerArtifact],
        state: &str,
        at: String,
    ) {
        if let Some(index) = owners.remove(binding) {
            rows[index].terminal_state = state.to_string();
            rows[index].terminal_at = Some(at);
        }
    }

    fn scan_expr(
        function: &hir::TypedFunction,
        expr: &ast::Expr,
        next_owner_id: &mut usize,
        owners: &mut BTreeMap<String, usize>,
        rows: &mut Vec<MemoryOwnerArtifact>,
    ) {
        match expr {
            ast::Expr::UnsafeBlock { body, .. } => {
                scan_stmts(function, body, next_owner_id, owners, rows);
            }
            ast::Expr::If {
                then_expr,
                else_expr,
                ..
            } => {
                scan_expr(function, then_expr, next_owner_id, owners, rows);
                scan_expr(function, else_expr, next_owner_id, owners, rows);
            }
            ast::Expr::Match { arms, .. } => {
                for arm in arms {
                    scan_expr(function, &arm.value, next_owner_id, owners, rows);
                }
            }
            ast::Expr::While { body, .. }
            | ast::Expr::ForIn { body, .. }
            | ast::Expr::Loop { body } => {
                scan_stmts(function, body, next_owner_id, owners, rows);
            }
            ast::Expr::For { body, .. } => {
                scan_stmts(function, body, next_owner_id, owners, rows);
            }
            _ => {}
        }
    }

    fn scan_stmts(
        function: &hir::TypedFunction,
        body: &[ast::Stmt],
        next_owner_id: &mut usize,
        owners: &mut BTreeMap<String, usize>,
        rows: &mut Vec<MemoryOwnerArtifact>,
    ) {
        for stmt in body {
            match stmt {
                ast::Stmt::Let {
                    name, value, ty, ..
                } => {
                    if let ast::Expr::Ident(from) = value {
                        if let Some(index) = owners.remove(from) {
                            rows[index]
                                .transfer_edges
                                .push(format!("let {name} = {from}"));
                            rows[index].name = name.clone();
                            owners.insert(name.clone(), index);
                            continue;
                        }
                    }
                    let binding_ty = ty.as_ref().or_else(|| function.local_types.get(name));
                    if binding_ty.is_some_and(memory_report_is_linear_type)
                        || memory_report_is_alloc_like(value)
                    {
                        create_owner(
                            &function.name,
                            name,
                            memory_report_expr_origin(value),
                            next_owner_id,
                            owners,
                            rows,
                        );
                    }
                    scan_expr(function, value, next_owner_id, owners, rows);
                }
                ast::Stmt::Assign { target, value } => {
                    if let ast::Expr::Ident(from) = value {
                        if let Some(index) = owners.remove(from) {
                            rows[index]
                                .transfer_edges
                                .push(format!("{target} = {from}"));
                            rows[index].name = target.clone();
                            owners.insert(target.clone(), index);
                        }
                    }
                    scan_expr(function, value, next_owner_id, owners, rows);
                }
                ast::Stmt::Defer(expr) => {
                    if let Some((binding, at)) = memory_report_terminal_call(expr) {
                        mark_terminal(&binding, owners, rows, "Deferred", at);
                    }
                    scan_expr(function, expr, next_owner_id, owners, rows);
                }
                ast::Stmt::Return(Some(ast::Expr::Ident(name))) => {
                    mark_terminal(name, owners, rows, "Returned", "return".to_string());
                }
                ast::Stmt::Return(Some(expr)) => {
                    scan_expr(function, expr, next_owner_id, owners, rows);
                }
                ast::Stmt::Expr(expr) => {
                    if let Some((binding, at)) = memory_report_terminal_call(expr) {
                        let state = if at.starts_with("task.group_") {
                            "Consumed"
                        } else {
                            "Consumed"
                        };
                        mark_terminal(&binding, owners, rows, state, at);
                    }
                    scan_expr(function, expr, next_owner_id, owners, rows);
                }
                ast::Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    scan_stmts(function, then_body, next_owner_id, owners, rows);
                    scan_stmts(function, else_body, next_owner_id, owners, rows);
                }
                ast::Stmt::While { body, .. }
                | ast::Stmt::ForIn { body, .. }
                | ast::Stmt::Loop { body } => {
                    scan_stmts(function, body, next_owner_id, owners, rows);
                }
                ast::Stmt::For { body, .. } => {
                    scan_stmts(function, body, next_owner_id, owners, rows);
                }
                ast::Stmt::Match { arms, .. } => {
                    for arm in arms {
                        scan_expr(function, &arm.value, next_owner_id, owners, rows);
                    }
                }
                ast::Stmt::LetPattern { value, .. }
                | ast::Stmt::CompoundAssign { value, .. }
                | ast::Stmt::Requires(value)
                | ast::Stmt::Ensures(value) => {
                    scan_expr(function, value, next_owner_id, owners, rows);
                }
                ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
            }
        }
    }

    let mut next_owner_id = 1usize;
    let mut active = BTreeMap::<String, usize>::new();
    let start = out.len();
    scan_stmts(
        function,
        &function.body,
        &mut next_owner_id,
        &mut active,
        out,
    );
    for index in active.into_values() {
        if out[index].terminal_state == "Owned" {
            out[index].terminal_at = Some("function_exit".to_string());
        }
    }
    for row in &mut out[start..] {
        if row.terminal_state == "Owned"
            && row.transfer_edges.iter().any(|edge| edge.contains(" = "))
        {
            row.terminal_state = "TransferredToCaller".to_string();
        }
    }
}

fn memory_report_is_alloc_like(expr: &ast::Expr) -> bool {
    matches!(expr, ast::Expr::Call { callee, .. } if is_memory_phase_alloc_like_callee(callee) || callee == "task.group_begin")
}

fn memory_report_expr_origin(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::Call { callee, .. } => callee.clone(),
        ast::Expr::Ident(name) => name.clone(),
        _ => "<expr>".to_string(),
    }
}

fn memory_report_is_linear_type(ty: &ast::Type) -> bool {
    match ty {
        ast::Type::Ptr { .. } => true,
        ast::Type::Named { name, .. } => {
            hir::runtime_handle_contract(name).is_some_and(|contract| contract.linear)
                || matches!(name.as_str(), "Linear" | "Resource" | "Ptr")
        }
        _ => false,
    }
}

fn memory_report_is_owned_handle_type(ty: &ast::Type) -> bool {
    match ty {
        ast::Type::Named { name, .. } => hir::runtime_handle_contract(name)
            .is_some_and(|contract| contract.owned && !contract.linear),
        _ => false,
    }
}

fn memory_report_terminal_call(expr: &ast::Expr) -> Option<(String, String)> {
    let ast::Expr::Call { callee, args } = expr else {
        return None;
    };
    let binding = match args.first() {
        Some(ast::Expr::Ident(name)) => name.clone(),
        Some(ast::Expr::Group(inner)) => match inner.as_ref() {
            ast::Expr::Ident(name) => name.clone(),
            _ => return None,
        },
        _ => return None,
    };
    let terminal = match callee.as_str() {
        "free"
        | "close"
        | "join"
        | "detach"
        | "cancel_task"
        | "http.stream_close"
        | "task.group_join"
        | "task.group_join_all"
        | "task.group_cancel" => Some(callee.clone()),
        _ if callee.ends_with(".free")
            || callee.ends_with(".close")
            || callee.ends_with("_close") =>
        {
            Some(callee.clone())
        }
        _ => None,
    }?;
    Some((binding, terminal))
}

fn count_awaits_in_stmts(body: &[ast::Stmt]) -> usize {
    body.iter().map(count_awaits_in_stmt).sum()
}

fn count_awaits_in_stmt(stmt: &ast::Stmt) -> usize {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Return(Some(value))
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => count_awaits_in_expr(value),
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            count_awaits_in_expr(condition)
                + count_awaits_in_stmts(then_body)
                + count_awaits_in_stmts(else_body)
        }
        ast::Stmt::While { condition, body } => {
            count_awaits_in_expr(condition) + count_awaits_in_stmts(body)
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref().map(count_awaits_in_stmt).unwrap_or(0)
                + condition.as_ref().map(count_awaits_in_expr).unwrap_or(0)
                + step.as_deref().map(count_awaits_in_stmt).unwrap_or(0)
                + count_awaits_in_stmts(body)
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            count_awaits_in_expr(iterable) + count_awaits_in_stmts(body)
        }
        ast::Stmt::Loop { body } => count_awaits_in_stmts(body),
        ast::Stmt::Match { scrutinee, arms } => {
            count_awaits_in_expr(scrutinee)
                + arms
                    .iter()
                    .map(|arm| {
                        arm.guard.as_ref().map(count_awaits_in_expr).unwrap_or(0)
                            + count_awaits_in_expr(&arm.value)
                    })
                    .sum::<usize>()
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => 0,
    }
}

fn count_awaits_in_expr(expr: &ast::Expr) -> usize {
    match expr {
        ast::Expr::Await(inner) => 1 + count_awaits_in_expr(inner),
        ast::Expr::Call { args, .. } => args.iter().map(count_awaits_in_expr).sum(),
        ast::Expr::UnsafeBlock { body, .. } => count_awaits_in_stmts(body),
        ast::Expr::FieldAccess { base, .. }
        | ast::Expr::Group(base)
        | ast::Expr::Discard(base)
        | ast::Expr::Unary { expr: base, .. } => count_awaits_in_expr(base),
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => fields
            .iter()
            .map(|(_, value)| count_awaits_in_expr(value))
            .sum(),
        ast::Expr::EnumInit { payload, .. }
        | ast::Expr::Tuple(payload)
        | ast::Expr::ArrayLiteral(payload) => payload.iter().map(count_awaits_in_expr).sum(),
        ast::Expr::Closure { body, .. } => count_awaits_in_expr(body),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => count_awaits_in_expr(try_expr) + count_awaits_in_expr(catch_expr),
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            count_awaits_in_expr(condition)
                + count_awaits_in_expr(then_expr)
                + count_awaits_in_expr(else_expr)
        }
        ast::Expr::Match { scrutinee, arms } => {
            count_awaits_in_expr(scrutinee)
                + arms
                    .iter()
                    .map(|arm| {
                        arm.guard.as_ref().map(count_awaits_in_expr).unwrap_or(0)
                            + count_awaits_in_expr(&arm.value)
                    })
                    .sum::<usize>()
        }
        ast::Expr::While { condition, body } => {
            count_awaits_in_expr(condition) + count_awaits_in_stmts(body)
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref().map(count_awaits_in_stmt).unwrap_or(0)
                + condition.as_deref().map(count_awaits_in_expr).unwrap_or(0)
                + step.as_deref().map(count_awaits_in_stmt).unwrap_or(0)
                + count_awaits_in_stmts(body)
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            count_awaits_in_expr(iterable) + count_awaits_in_stmts(body)
        }
        ast::Expr::Loop { body } => count_awaits_in_stmts(body),
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            value.as_deref().map(count_awaits_in_expr).unwrap_or(0)
        }
        ast::Expr::Binary { left, right, .. } => {
            count_awaits_in_expr(left) + count_awaits_in_expr(right)
        }
        ast::Expr::Range { start, end, .. } => {
            count_awaits_in_expr(start) + count_awaits_in_expr(end)
        }
        ast::Expr::Index { base, index } => {
            count_awaits_in_expr(base) + count_awaits_in_expr(index)
        }
        ast::Expr::Continue
        | ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => 0,
    }
}

fn collect_task_transfer_events(function: &hir::TypedFunction) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    collect_task_transfer_events_from_stmts(&function.name, &function.body, &mut out);
    out
}

fn collect_task_transfer_events_from_stmts(
    function_name: &str,
    body: &[ast::Stmt],
    out: &mut Vec<serde_json::Value>,
) {
    for stmt in body {
        match stmt {
            ast::Stmt::Let { value, .. }
            | ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::Assign { value, .. }
            | ast::Stmt::CompoundAssign { value, .. }
            | ast::Stmt::Return(Some(value))
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value)
            | ast::Stmt::Expr(value) => {
                collect_task_transfer_events_from_expr(function_name, value, out)
            }
            ast::Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_task_transfer_events_from_stmts(function_name, then_body, out);
                collect_task_transfer_events_from_stmts(function_name, else_body, out);
            }
            ast::Stmt::While { body, .. }
            | ast::Stmt::ForIn { body, .. }
            | ast::Stmt::Loop { body } => {
                collect_task_transfer_events_from_stmts(function_name, body, out)
            }
            ast::Stmt::For { body, .. } => {
                collect_task_transfer_events_from_stmts(function_name, body, out)
            }
            ast::Stmt::Match { arms, .. } => {
                for arm in arms {
                    collect_task_transfer_events_from_expr(function_name, &arm.value, out);
                }
            }
            ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }
}

fn collect_task_transfer_events_from_expr(
    function_name: &str,
    expr: &ast::Expr,
    out: &mut Vec<serde_json::Value>,
) {
    match expr {
        ast::Expr::Call { callee, args }
            if matches!(
                callee.as_str(),
                "spawn"
                    | "thread.spawn"
                    | "spawn_ctx"
                    | "thread.spawn_ctx"
                    | "task.group_spawn"
                    | "task.group_spawn_n"
                    | "task.parallel_map"
            ) =>
        {
            out.push(serde_json::json!({
                "function": function_name,
                "callee": callee,
                "args": args.iter().map(memory_report_expr_origin).collect::<Vec<_>>(),
                "result": "accepted",
            }));
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            collect_task_transfer_events_from_stmts(function_name, body, out);
        }
        ast::Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            collect_task_transfer_events_from_expr(function_name, then_expr, out);
            collect_task_transfer_events_from_expr(function_name, else_expr, out);
        }
        ast::Expr::Match { arms, .. } => {
            for arm in arms {
                collect_task_transfer_events_from_expr(function_name, &arm.value, out);
            }
        }
        _ => {}
    }
}

fn summarize_task_handle_terminal_params(
    function: &hir::TypedFunction,
) -> Option<(String, BTreeMap<usize, String>)> {
    let mut terminal_params = BTreeMap::<usize, String>::new();
    for stmt in &function.body {
        collect_task_handle_terminal_param_stmt(stmt, function, &mut terminal_params);
    }
    (!terminal_params.is_empty()).then_some((function.name.clone(), terminal_params))
}

fn collect_task_handle_terminal_param_stmt(
    stmt: &ast::Stmt,
    function: &hir::TypedFunction,
    terminal_params: &mut BTreeMap<usize, String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value)
        | ast::Stmt::Return(Some(value)) => {
            collect_task_handle_terminal_param_expr(value, function, terminal_params);
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_task_handle_terminal_param_expr(condition, function, terminal_params);
            for nested in then_body {
                collect_task_handle_terminal_param_stmt(nested, function, terminal_params);
            }
            for nested in else_body {
                collect_task_handle_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_task_handle_terminal_param_expr(condition, function, terminal_params);
            for nested in body {
                collect_task_handle_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_task_handle_terminal_param_stmt(init, function, terminal_params);
            }
            if let Some(condition) = condition {
                collect_task_handle_terminal_param_expr(condition, function, terminal_params);
            }
            if let Some(step) = step {
                collect_task_handle_terminal_param_stmt(step, function, terminal_params);
            }
            for nested in body {
                collect_task_handle_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_task_handle_terminal_param_expr(iterable, function, terminal_params);
            for nested in body {
                collect_task_handle_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_task_handle_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_task_handle_terminal_param_expr(scrutinee, function, terminal_params);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_task_handle_terminal_param_expr(guard, function, terminal_params);
                }
                collect_task_handle_terminal_param_expr(&arm.value, function, terminal_params);
            }
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

fn collect_task_handle_terminal_param_expr(
    expr: &ast::Expr,
    function: &hir::TypedFunction,
    terminal_params: &mut BTreeMap<usize, String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if matches!(callee.as_str(), "join" | "detach" | "cancel_task") {
                if let Some(ast::Expr::Ident(name)) = args.first() {
                    if let Some((index, _)) =
                        function.params.iter().enumerate().find(|(_, param)| {
                            param.name == *name && param.ty.to_string() == "TaskHandle"
                        })
                    {
                        terminal_params
                            .entry(index)
                            .or_insert_with(|| callee.clone());
                    }
                }
            }
            for arg in args {
                collect_task_handle_terminal_param_expr(arg, function, terminal_params);
            }
        }
        ast::Expr::Await(inner)
        | ast::Expr::Group(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::FieldAccess { base: inner, .. }
        | ast::Expr::Unary { expr: inner, .. } => {
            collect_task_handle_terminal_param_expr(inner, function, terminal_params);
        }
        ast::Expr::Index { base, index } => {
            collect_task_handle_terminal_param_expr(base, function, terminal_params);
            collect_task_handle_terminal_param_expr(index, function, terminal_params);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_task_handle_terminal_param_expr(left, function, terminal_params);
            collect_task_handle_terminal_param_expr(right, function, terminal_params);
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_task_handle_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for value in payload {
                collect_task_handle_terminal_param_expr(value, function, terminal_params);
            }
            for (_, value) in named_payload {
                collect_task_handle_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Tuple(values) | ast::Expr::ArrayLiteral(values) => {
            for value in values {
                collect_task_handle_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_task_handle_terminal_param_expr(body, function, terminal_params);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_task_handle_terminal_param_expr(try_expr, function, terminal_params);
            collect_task_handle_terminal_param_expr(catch_expr, function, terminal_params);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_task_handle_terminal_param_expr(condition, function, terminal_params);
            collect_task_handle_terminal_param_expr(then_expr, function, terminal_params);
            collect_task_handle_terminal_param_expr(else_expr, function, terminal_params);
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_task_handle_terminal_param_expr(scrutinee, function, terminal_params);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_task_handle_terminal_param_expr(guard, function, terminal_params);
                }
                collect_task_handle_terminal_param_expr(&arm.value, function, terminal_params);
            }
        }
        ast::Expr::While { condition, body } => {
            collect_task_handle_terminal_param_expr(condition, function, terminal_params);
            for stmt in body {
                collect_task_handle_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_task_handle_terminal_param_stmt(init, function, terminal_params);
            }
            if let Some(condition) = condition {
                collect_task_handle_terminal_param_expr(condition, function, terminal_params);
            }
            if let Some(step) = step {
                collect_task_handle_terminal_param_stmt(step, function, terminal_params);
            }
            for stmt in body {
                collect_task_handle_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_task_handle_terminal_param_expr(iterable, function, terminal_params);
            for stmt in body {
                collect_task_handle_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::Loop { body } | ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_task_handle_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_task_handle_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_task_handle_terminal_param_expr(start, function, terminal_params);
            collect_task_handle_terminal_param_expr(end, function, terminal_params);
        }
        ast::Expr::Continue
        | ast::Expr::Ident(_)
        | ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_) => {}
    }
}

fn summarize_task_group_terminal_params(
    function: &hir::TypedFunction,
) -> Option<(String, BTreeMap<usize, String>)> {
    let mut terminal_params = BTreeMap::<usize, String>::new();
    for stmt in &function.body {
        collect_task_group_terminal_param_stmt(stmt, function, &mut terminal_params);
    }
    (!terminal_params.is_empty()).then_some((function.name.clone(), terminal_params))
}

fn summarize_gpu_event_terminal_params(
    function: &hir::TypedFunction,
) -> Option<(String, BTreeMap<usize, String>)> {
    let mut terminal_params = BTreeMap::<usize, String>::new();
    for stmt in &function.body {
        collect_gpu_event_terminal_param_stmt(stmt, function, &mut terminal_params);
    }
    (!terminal_params.is_empty()).then_some((function.name.clone(), terminal_params))
}

fn collect_gpu_event_terminal_param_stmt(
    stmt: &ast::Stmt,
    function: &hir::TypedFunction,
    terminal_params: &mut BTreeMap<usize, String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value)
        | ast::Stmt::Return(Some(value)) => {
            collect_gpu_event_terminal_param_expr(value, function, terminal_params);
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            for nested in then_body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
            for nested in else_body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            for nested in body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_gpu_event_terminal_param_stmt(init, function, terminal_params);
            }
            if let Some(condition) = condition {
                collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            }
            if let Some(step) = step {
                collect_gpu_event_terminal_param_stmt(step, function, terminal_params);
            }
            for nested in body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_gpu_event_terminal_param_expr(iterable, function, terminal_params);
            for nested in body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_gpu_event_terminal_param_expr(scrutinee, function, terminal_params);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_gpu_event_terminal_param_expr(guard, function, terminal_params);
                }
                collect_gpu_event_terminal_param_expr(&arm.value, function, terminal_params);
            }
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

fn collect_gpu_event_terminal_param_expr(
    expr: &ast::Expr,
    function: &hir::TypedFunction,
    terminal_params: &mut BTreeMap<usize, String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if matches!(callee.as_str(), "gpu.wait" | "gpu.wait_async") {
                if let Some(ast::Expr::Ident(name)) = args.first() {
                    if let Some((index, _)) =
                        function.params.iter().enumerate().find(|(_, param)| {
                            param.name == *name && param.ty.to_string() == "GpuEvent"
                        })
                    {
                        terminal_params
                            .entry(index)
                            .or_insert_with(|| callee.clone());
                    }
                }
            }
            for arg in args {
                collect_gpu_event_terminal_param_expr(arg, function, terminal_params);
            }
        }
        ast::Expr::Await(inner)
        | ast::Expr::Group(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::FieldAccess { base: inner, .. }
        | ast::Expr::Unary { expr: inner, .. } => {
            collect_gpu_event_terminal_param_expr(inner, function, terminal_params);
        }
        ast::Expr::Index { base, index } => {
            collect_gpu_event_terminal_param_expr(base, function, terminal_params);
            collect_gpu_event_terminal_param_expr(index, function, terminal_params);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_gpu_event_terminal_param_expr(left, function, terminal_params);
            collect_gpu_event_terminal_param_expr(right, function, terminal_params);
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_gpu_event_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for value in payload {
                collect_gpu_event_terminal_param_expr(value, function, terminal_params);
            }
            for (_, value) in named_payload {
                collect_gpu_event_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Tuple(values) | ast::Expr::ArrayLiteral(values) => {
            for value in values {
                collect_gpu_event_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_gpu_event_terminal_param_expr(body, function, terminal_params);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_gpu_event_terminal_param_expr(try_expr, function, terminal_params);
            collect_gpu_event_terminal_param_expr(catch_expr, function, terminal_params);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            collect_gpu_event_terminal_param_expr(then_expr, function, terminal_params);
            collect_gpu_event_terminal_param_expr(else_expr, function, terminal_params);
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_gpu_event_terminal_param_expr(scrutinee, function, terminal_params);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_gpu_event_terminal_param_expr(guard, function, terminal_params);
                }
                collect_gpu_event_terminal_param_expr(&arm.value, function, terminal_params);
            }
        }
        ast::Expr::While { condition, body } => {
            collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            for stmt in body {
                collect_gpu_event_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_gpu_event_terminal_param_stmt(init, function, terminal_params);
            }
            if let Some(condition) = condition {
                collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            }
            if let Some(step) = step {
                collect_gpu_event_terminal_param_stmt(step, function, terminal_params);
            }
            for stmt in body {
                collect_gpu_event_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_gpu_event_terminal_param_expr(iterable, function, terminal_params);
            for stmt in body {
                collect_gpu_event_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::Loop { body } | ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_gpu_event_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_gpu_event_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_gpu_event_terminal_param_expr(start, function, terminal_params);
            collect_gpu_event_terminal_param_expr(end, function, terminal_params);
        }
        ast::Expr::Continue
        | ast::Expr::Ident(_)
        | ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_) => {}
    }
}

fn collect_task_group_terminal_param_stmt(
    stmt: &ast::Stmt,
    function: &hir::TypedFunction,
    terminal_params: &mut BTreeMap<usize, String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value)
        | ast::Stmt::Return(Some(value)) => {
            collect_task_group_terminal_param_expr(value, function, terminal_params);
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_task_group_terminal_param_expr(condition, function, terminal_params);
            for nested in then_body {
                collect_task_group_terminal_param_stmt(nested, function, terminal_params);
            }
            for nested in else_body {
                collect_task_group_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_task_group_terminal_param_expr(condition, function, terminal_params);
            for nested in body {
                collect_task_group_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_task_group_terminal_param_stmt(init, function, terminal_params);
            }
            if let Some(condition) = condition {
                collect_task_group_terminal_param_expr(condition, function, terminal_params);
            }
            if let Some(step) = step {
                collect_task_group_terminal_param_stmt(step, function, terminal_params);
            }
            for nested in body {
                collect_task_group_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_task_group_terminal_param_expr(iterable, function, terminal_params);
            for nested in body {
                collect_task_group_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_task_group_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_task_group_terminal_param_expr(scrutinee, function, terminal_params);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_task_group_terminal_param_expr(guard, function, terminal_params);
                }
                collect_task_group_terminal_param_expr(&arm.value, function, terminal_params);
            }
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

fn collect_task_group_terminal_param_expr(
    expr: &ast::Expr,
    function: &hir::TypedFunction,
    terminal_params: &mut BTreeMap<usize, String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if matches!(
                callee.as_str(),
                "task.group_join" | "task.group_join_all" | "task.group_cancel"
            ) {
                if let Some(ast::Expr::Ident(name)) = args.first() {
                    if let Some((index, _)) =
                        function.params.iter().enumerate().find(|(_, param)| {
                            param.name == *name && param.ty.to_string() == "TaskGroupHandle"
                        })
                    {
                        terminal_params
                            .entry(index)
                            .or_insert_with(|| callee.clone());
                    }
                }
            }
            for arg in args {
                collect_task_group_terminal_param_expr(arg, function, terminal_params);
            }
        }
        ast::Expr::Await(inner)
        | ast::Expr::Group(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::FieldAccess { base: inner, .. }
        | ast::Expr::Unary { expr: inner, .. } => {
            collect_task_group_terminal_param_expr(inner, function, terminal_params);
        }
        ast::Expr::Index { base, index } => {
            collect_task_group_terminal_param_expr(base, function, terminal_params);
            collect_task_group_terminal_param_expr(index, function, terminal_params);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_task_group_terminal_param_expr(left, function, terminal_params);
            collect_task_group_terminal_param_expr(right, function, terminal_params);
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_task_group_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for value in payload {
                collect_task_group_terminal_param_expr(value, function, terminal_params);
            }
            for (_, value) in named_payload {
                collect_task_group_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Tuple(values) | ast::Expr::ArrayLiteral(values) => {
            for value in values {
                collect_task_group_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_task_group_terminal_param_expr(body, function, terminal_params);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_task_group_terminal_param_expr(try_expr, function, terminal_params);
            collect_task_group_terminal_param_expr(catch_expr, function, terminal_params);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_task_group_terminal_param_expr(condition, function, terminal_params);
            collect_task_group_terminal_param_expr(then_expr, function, terminal_params);
            collect_task_group_terminal_param_expr(else_expr, function, terminal_params);
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_task_group_terminal_param_expr(scrutinee, function, terminal_params);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_task_group_terminal_param_expr(guard, function, terminal_params);
                }
                collect_task_group_terminal_param_expr(&arm.value, function, terminal_params);
            }
        }
        ast::Expr::While { condition, body } => {
            collect_task_group_terminal_param_expr(condition, function, terminal_params);
            for stmt in body {
                collect_task_group_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_task_group_terminal_param_stmt(init, function, terminal_params);
            }
            if let Some(condition) = condition {
                collect_task_group_terminal_param_expr(condition, function, terminal_params);
            }
            if let Some(step) = step {
                collect_task_group_terminal_param_stmt(step, function, terminal_params);
            }
            for stmt in body {
                collect_task_group_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_task_group_terminal_param_expr(iterable, function, terminal_params);
            for stmt in body {
                collect_task_group_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::Loop { body } | ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_task_group_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_task_group_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_task_group_terminal_param_expr(start, function, terminal_params);
            collect_task_group_terminal_param_expr(end, function, terminal_params);
        }
        ast::Expr::Continue
        | ast::Expr::Ident(_)
        | ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_) => {}
    }
}

