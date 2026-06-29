use super::*;

pub(crate) fn build_ffi_report_json(fir: &fir::FirModule) -> serde_json::Value {
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

pub(crate) fn render_ffi_report_markdown(value: &serde_json::Value) -> String {
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

pub(crate) fn collect_repr_c_names_for_ffi(fir: &fir::FirModule) -> BTreeSet<String> {
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

pub(crate) fn ffi_pointer_ownership_tag(name: &str) -> Option<&'static str> {
    ["_owned", "_borrowed", "_out", "_inout"]
        .into_iter()
        .find_map(|suffix| name.ends_with(suffix).then_some(&suffix[1..]))
}

pub(crate) fn ffi_pointer_base_name(name: &str) -> String {
    for suffix in ["_borrowed", "_owned", "_out", "_inout"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    name.to_string()
}

pub(crate) fn ffi_has_len_pair(function: &hir::TypedFunction, pointer_param_name: &str) -> bool {
    let base = ffi_pointer_base_name(pointer_param_name);
    let expected = format!("{base}_len");
    function.params.iter().any(|candidate| {
        matches!(candidate.ty, ast::Type::USize)
            && (candidate.name == "len"
                || candidate.name == expected
                || candidate.name == format!("{base}_bytes"))
    })
}

pub(crate) fn ffi_is_context_anchor_name(name: &str) -> bool {
    name.ends_with("_ctx") || name.ends_with("_context")
}

pub(crate) fn ffi_is_callback_param(ty: &ast::Type) -> bool {
    matches!(ty, ast::Type::Function { .. })
}

pub(crate) fn ffi_pointer_param_missing_contract(function: &hir::TypedFunction) -> Option<String> {
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

pub(crate) fn ffi_callback_param_missing_anchor(function: &hir::TypedFunction) -> Option<String> {
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

pub(crate) fn ffi_stable_type(ty: &ast::Type, repr_c_names: &BTreeSet<String>) -> bool {
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

pub(crate) fn ffi_unstable_types(
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

pub(crate) fn build_native_runtime_contracts_json() -> serde_json::Value {
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

pub(crate) fn render_native_runtime_contracts_markdown(value: &serde_json::Value) -> String {
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
