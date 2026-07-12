use super::*;

#[derive(Debug, Clone, serde::Serialize)]
struct RpcCompatibilityVersions {
    #[serde(rename = "languageVersion")]
    language_version: String,
    #[serde(rename = "traceSchemaVersion")]
    trace_schema_version: String,
    #[serde(rename = "manifestSchemaVersion")]
    manifest_schema_version: String,
    #[serde(rename = "runtimeAbiVersion")]
    runtime_abi_version: String,
    #[serde(rename = "nativeImportTableVersion")]
    native_import_table_version: String,
    #[serde(rename = "diagnosticCatalogVersion")]
    diagnostic_catalog_version: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RpcParamSafety {
    name: String,
    #[serde(rename = "type")]
    ty: String,
    ownership: &'static str,
    #[serde(rename = "payloadSupported")]
    payload_supported: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RpcMethodSafety {
    name: String,
    #[serde(rename = "canonicalName")]
    canonical_name: String,
    #[serde(rename = "methodNameStable")]
    method_name_stable: bool,
    params: Vec<RpcParamSafety>,
    #[serde(rename = "returnType")]
    return_type: String,
    #[serde(rename = "requestOwnershipExplicit")]
    request_ownership_explicit: bool,
    #[serde(rename = "responseOwnership")]
    response_ownership: &'static str,
    #[serde(rename = "responseOwnershipExplicit")]
    response_ownership_explicit: bool,
    #[serde(rename = "payloadTypesSupported")]
    payload_types_supported: bool,
    #[serde(rename = "errorNormalization")]
    error_normalization: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RpcDeadlinePolicyRecord {
    method: String,
    policy: &'static str,
    calls: usize,
    #[serde(rename = "protectedCalls")]
    protected_calls: usize,
    #[serde(rename = "strictReady")]
    strict_ready: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RpcCancelPolicyRecord {
    method: String,
    policy: &'static str,
    calls: usize,
    #[serde(rename = "cancelObservedCalls")]
    cancel_observed_calls: usize,
    #[serde(rename = "recvObservedCalls")]
    recv_observed_calls: usize,
    #[serde(rename = "cleanupObservedCalls")]
    cleanup_observed_calls: usize,
    #[serde(rename = "cleanupPolicy")]
    cleanup_policy: &'static str,
    #[serde(rename = "handlerCleanupStatus")]
    handler_cleanup_status: &'static str,
    #[serde(rename = "strictReady")]
    strict_ready: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RpcPayloadContractRecord {
    method: String,
    #[serde(rename = "requestOwnershipExplicit")]
    request_ownership_explicit: bool,
    #[serde(rename = "responseOwnershipExplicit")]
    response_ownership_explicit: bool,
    #[serde(rename = "payloadTypesSupported")]
    payload_types_supported: bool,
    #[serde(rename = "methodNameStable")]
    method_name_stable: bool,
    #[serde(rename = "errorNormalization")]
    error_normalization: &'static str,
    #[serde(rename = "strictReady")]
    strict_ready: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RpcStrictRequirements {
    #[serde(rename = "deadlinePerCall")]
    deadline_per_call: bool,
    #[serde(rename = "handlerCancelCleanup")]
    handler_cancel_cleanup: &'static str,
    #[serde(rename = "frameTraceability")]
    frame_traceability: bool,
    #[serde(rename = "requestOwnershipExplicit")]
    request_ownership_explicit: bool,
    #[serde(rename = "responseOwnershipExplicit")]
    response_ownership_explicit: bool,
    #[serde(rename = "payloadTypesSupported")]
    payload_types_supported: bool,
    #[serde(rename = "methodNameStable")]
    method_name_stable: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RpcSafetyReport {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    versions: RpcCompatibilityVersions,
    rpc_methods: Vec<RpcMethodSafety>,
    #[serde(rename = "strictRequirements")]
    strict_requirements: RpcStrictRequirements,
    deadline_policies: Vec<RpcDeadlinePolicyRecord>,
    cancel_policies: Vec<RpcCancelPolicyRecord>,
    payload_contracts: Vec<RpcPayloadContractRecord>,
    resource_cleanup: Vec<RpcResourceCleanupRecord>,
    rpc_frames: Vec<&'static str>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RpcResourceCleanupRecord {}

fn rpc_compatibility_versions() -> RpcCompatibilityVersions {
    let compatibility = fzscenario::compatibility_info();
    RpcCompatibilityVersions {
        language_version: compatibility.language_version,
        trace_schema_version: compatibility.trace_schema_version,
        manifest_schema_version: compatibility.manifest_schema_version,
        runtime_abi_version: compatibility.runtime_abi_version,
        native_import_table_version: compatibility.native_import_table_version,
        diagnostic_catalog_version: compatibility.diagnostic_catalog_version,
    }
}

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
                .map(|param| RpcParamSafety {
                    name: param.name.clone(),
                    ty: param.ty.to_string(),
                    ownership: param.ty.rpc_boundary_ownership(),
                    payload_supported: param.ty.is_rpc_payload_supported(),
                })
                .collect::<Vec<_>>();
            let request_explicit = params.iter().all(|param| {
                matches!(param.ownership, "value" | "owned") && param.payload_supported
            });
            let response_ownership = function.return_type.rpc_boundary_ownership();
            let response_payload_supported = function.return_type.is_rpc_payload_supported();
            RpcMethodSafety {
                name: function.name.clone(),
                canonical_name: function
                    .link_name
                    .clone()
                    .unwrap_or_else(|| function.name.clone()),
                method_name_stable: function
                    .link_name
                    .as_deref()
                    .is_none_or(|link_name| link_name == function.name),
                params,
                return_type: function.return_type.to_string(),
                request_ownership_explicit: request_explicit,
                response_ownership,
                response_ownership_explicit: matches!(
                    response_ownership,
                    "value" | "owned" | "status"
                ) && response_payload_supported,
                payload_types_supported: request_explicit && response_payload_supported,
                error_normalization: rpc_error_normalization_kind(&function.return_type),
            }
        })
        .collect::<Vec<_>>();
    let policy_evidence = collect_rpc_policy_evidence_from_names(
        module,
        rpc_methods.iter().map(|method| method.name.as_str()),
    );
    let deadline_policies = rpc_methods
        .iter()
        .map(|method| {
            let evidence = policy_evidence
                .get(method.name.as_str())
                .cloned()
                .unwrap_or_else(RpcPolicyEvidence::default);
            RpcDeadlinePolicyRecord {
                method: method.name.clone(),
                policy: evidence.deadline_policy(),
                calls: evidence.calls,
                protected_calls: evidence.deadline_protected_calls,
                strict_ready: evidence.calls > 0
                    && evidence.deadline_protected_calls == evidence.calls,
            }
        })
        .collect::<Vec<_>>();
    let cancel_policies = rpc_methods
        .iter()
        .map(|method| {
            let evidence = policy_evidence
                .get(method.name.as_str())
                .cloned()
                .unwrap_or_else(RpcPolicyEvidence::default);
            RpcCancelPolicyRecord {
                method: method.name.clone(),
                policy: evidence.cancel_policy(),
                calls: evidence.calls,
                cancel_observed_calls: evidence.cancel_observed_calls,
                recv_observed_calls: evidence.recv_observed_calls,
                cleanup_observed_calls: evidence.cleanup_observed_calls(),
                cleanup_policy: evidence.cleanup_policy(),
                handler_cleanup_status: evidence.cleanup_policy(),
                strict_ready: evidence.calls > 0
                    && evidence.cleanup_observed_calls() == evidence.calls,
            }
        })
        .collect::<Vec<_>>();

    let payload_contracts = rpc_methods
        .iter()
        .map(|method| RpcPayloadContractRecord {
            method: method.name.clone(),
            request_ownership_explicit: method.request_ownership_explicit,
            response_ownership_explicit: method.response_ownership_explicit,
            payload_types_supported: method.payload_types_supported,
            method_name_stable: method.method_name_stable,
            error_normalization: method.error_normalization,
            strict_ready: method.request_ownership_explicit
                && method.response_ownership_explicit
                && method.payload_types_supported
                && method.method_name_stable,
        })
        .collect::<Vec<_>>();

    serde_json::to_value(RpcSafetyReport {
        schema_version: "fozzylang.rpc_safety.v1",
        versions: rpc_compatibility_versions(),
        rpc_methods,
        strict_requirements: RpcStrictRequirements {
            deadline_per_call: true,
            handler_cancel_cleanup: "required",
            frame_traceability: true,
            request_ownership_explicit: true,
            response_ownership_explicit: true,
            payload_types_supported: true,
            method_name_stable: true,
        },
        deadline_policies,
        cancel_policies,
        payload_contracts,
        resource_cleanup: Vec::new(),
        rpc_frames: vec![
            "rpc_send",
            "rpc_recv",
            "rpc_deadline",
            "rpc_cancel",
            "rpc_resource_open",
            "rpc_resource_close",
            "rpc_resource_leak_rejected",
        ],
    })
    .expect("rpc safety report should serialize")
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
    rpc_method_names: &[String],
) -> HashMap<String, RpcPolicyEvidence> {
    collect_rpc_policy_evidence_from_names(module, rpc_method_names.iter().map(String::as_str))
}

fn collect_rpc_policy_evidence_from_names<'a>(
    module: &ast::Module,
    rpc_method_names: impl IntoIterator<Item = &'a str>,
) -> HashMap<String, RpcPolicyEvidence> {
    let rpc_method_names = rpc_method_names
        .into_iter()
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
