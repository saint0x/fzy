use super::*;

pub(crate) fn build_rpc_safety_json(
    module: &ast::Module,
    fir: &fir::FirModule,
) -> serde_json::Value {
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
pub(crate) struct RpcPolicyEvidence {
    pub(crate) calls: usize,
    pub(crate) deadline_protected_calls: usize,
    pub(crate) cancel_observed_calls: usize,
    pub(crate) recv_observed_calls: usize,
}

impl RpcPolicyEvidence {
    pub(crate) fn deadline_policy(&self) -> &'static str {
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

    pub(crate) fn cancel_policy(&self) -> &'static str {
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

    pub(crate) fn cleanup_observed_calls(&self) -> usize {
        self.cancel_observed_calls.max(self.recv_observed_calls)
    }

    pub(crate) fn cleanup_policy(&self) -> &'static str {
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

pub(crate) fn rpc_error_normalization_kind(return_type: &ast::Type) -> &'static str {
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
pub(crate) struct PendingRpcCall {
    pub(crate) method: String,
    pub(crate) deadline_seen: bool,
    pub(crate) cancel_seen: bool,
    pub(crate) recv_seen: bool,
}

pub(crate) fn collect_rpc_policy_evidence(
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

pub(crate) fn collect_pipeline_call_sequence(module: &ast::Module) -> Vec<String> {
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

pub(crate) fn collect_pipeline_call_names_from_stmt(statement: &ast::Stmt, out: &mut Vec<String>) {
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

pub(crate) fn collect_pipeline_call_names_from_expr(expr: &ast::Expr, out: &mut Vec<String>) {
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
