use super::*;

#[derive(Debug, Clone, serde::Serialize)]
struct FfiParamRecord {
    name: String,
    #[serde(rename = "type")]
    ty: String,
    #[serde(rename = "pointerLike")]
    pointer_like: bool,
    #[serde(rename = "ownershipTag")]
    ownership_tag: Option<String>,
    #[serde(rename = "hasLenPair")]
    has_len_pair: bool,
    #[serde(rename = "isContextAnchor")]
    is_context_anchor: bool,
    #[serde(rename = "isCallback")]
    is_callback: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FfiImportRecord {
    name: String,
    #[serde(rename = "unsafe")]
    is_unsafe: bool,
    #[serde(rename = "async")]
    is_async: bool,
    #[serde(rename = "linkName")]
    link_name: Option<String>,
    params: Vec<FfiParamRecord>,
    #[serde(rename = "returnType")]
    return_type: String,
    #[serde(rename = "panicBoundary")]
    panic_boundary: Option<String>,
    #[serde(rename = "hasPointerLikeSurface")]
    has_pointer_like_surface: bool,
    #[serde(rename = "pointerContractOk")]
    pointer_contract_ok: bool,
    #[serde(rename = "pointerContractViolation")]
    pointer_contract_violation: Option<String>,
    #[serde(rename = "callbackContextAnchorOk")]
    callback_context_anchor_ok: bool,
    #[serde(rename = "callbackContextAnchorViolation")]
    callback_context_anchor_violation: Option<String>,
    #[serde(rename = "ffiStableOk")]
    ffi_stable_ok: bool,
    #[serde(rename = "unstableTypes")]
    unstable_types: Vec<String>,
    #[serde(rename = "asyncImportForbidden")]
    async_import_forbidden: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FfiExportRecord {
    name: String,
    #[serde(rename = "async")]
    is_async: bool,
    #[serde(rename = "linkName")]
    link_name: Option<String>,
    params: Vec<FfiParamRecord>,
    #[serde(rename = "returnType")]
    return_type: String,
    #[serde(rename = "panicBoundary")]
    panic_boundary: Option<String>,
    #[serde(rename = "panicBoundaryDeclared")]
    panic_boundary_declared: bool,
    #[serde(rename = "ffiStableOk")]
    ffi_stable_ok: bool,
    #[serde(rename = "unstableTypes")]
    unstable_types: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FfiAsyncExportParamRecord {
    name: String,
    #[serde(rename = "cType")]
    c_type: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FfiAsyncExportRecord {
    name: String,
    symbol: String,
    params: Vec<FfiAsyncExportParamRecord>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FfiCompatibilityVersions {
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
pub(crate) struct FfiReport {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    versions: FfiCompatibilityVersions,
    #[serde(rename = "pointerContractViolationCount")]
    pointer_contract_violation_count: usize,
    #[serde(rename = "callbackContextAnchorViolationCount")]
    callback_context_anchor_violation_count: usize,
    #[serde(rename = "ffiStableTypeViolationCount")]
    ffi_stable_type_violation_count: usize,
    #[serde(rename = "asyncImportViolationCount")]
    async_import_violation_count: usize,
    #[serde(rename = "missingPanicBoundaryCount")]
    missing_panic_boundary_count: usize,
    imports: Vec<FfiImportRecord>,
    exports: Vec<FfiExportRecord>,
    #[serde(rename = "asyncExports")]
    async_exports: Vec<FfiAsyncExportRecord>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct NativeRuntimeContractImportRecord {
    callee: &'static str,
    symbol: &'static str,
    arity: usize,
    #[serde(rename = "argOwnership")]
    arg_ownership: &'static str,
    #[serde(rename = "returnOwnership")]
    return_ownership: &'static str,
    #[serde(rename = "requiredCapability")]
    required_capability: &'static str,
    linearity: &'static str,
    #[serde(rename = "errorBehavior")]
    error_behavior: &'static str,
    #[serde(rename = "traceBehavior")]
    trace_behavior: &'static str,
    #[serde(rename = "blockingBehavior")]
    blocking_behavior: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct NativeRuntimeContractsReport {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    versions: FfiCompatibilityVersions,
    imports: Vec<NativeRuntimeContractImportRecord>,
}

fn ffi_compatibility_versions() -> FfiCompatibilityVersions {
    let compatibility = fzscenario::compatibility_info();
    FfiCompatibilityVersions {
        language_version: compatibility.language_version,
        trace_schema_version: compatibility.trace_schema_version,
        manifest_schema_version: compatibility.manifest_schema_version,
        runtime_abi_version: compatibility.runtime_abi_version,
        native_import_table_version: compatibility.native_import_table_version,
        diagnostic_catalog_version: compatibility.diagnostic_catalog_version,
    }
}

fn build_ffi_param_record(function: &hir::TypedFunction, param: &ast::Param) -> FfiParamRecord {
    FfiParamRecord {
        name: param.name.clone(),
        ty: param.ty.to_string(),
        pointer_like: param.ty.is_pointer_like(),
        ownership_tag: ffi_pointer_ownership_tag(&param.name).map(str::to_string),
        has_len_pair: ffi_has_len_pair(function, &param.name),
        is_context_anchor: ffi_is_context_anchor_name(&param.name),
        is_callback: ffi_is_callback_param(&param.ty),
    }
}

pub(crate) fn build_ffi_report(fir: &fir::FirModule) -> FfiReport {
    let repr_c_names = collect_repr_c_names_for_ffi(fir);
    let imports = collect_extern_c_imports(fir)
        .into_iter()
        .map(|function| {
            let params = function
                .params
                .iter()
                .map(|param| build_ffi_param_record(function, param))
                .collect::<Vec<_>>();
            let pointer_contract_violation = ffi_pointer_param_missing_contract(function);
            let callback_anchor_violation = ffi_callback_param_missing_anchor(function);
            let unstable_types = ffi_unstable_types(function, &repr_c_names);
            FfiImportRecord {
                name: function.name.clone(),
                is_unsafe: function.is_unsafe,
                is_async: function.is_async,
                link_name: function.link_name.clone(),
                params,
                return_type: function.return_type.to_string(),
                panic_boundary: function.ffi_panic.clone(),
                has_pointer_like_surface: function.return_type.is_pointer_like()
                    || function
                        .params
                        .iter()
                        .any(|param| param.ty.is_pointer_like()),
                pointer_contract_ok: pointer_contract_violation.is_none(),
                pointer_contract_violation,
                callback_context_anchor_ok: callback_anchor_violation.is_none(),
                callback_context_anchor_violation: callback_anchor_violation,
                ffi_stable_ok: unstable_types.is_empty(),
                unstable_types,
                async_import_forbidden: function.is_async,
            }
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
                .map(|param| build_ffi_param_record(function, param))
                .collect::<Vec<_>>();
            let unstable_types = ffi_unstable_types(function, &repr_c_names);
            FfiExportRecord {
                name: function.name.clone(),
                is_async: function.is_async,
                link_name: function.link_name.clone(),
                params,
                return_type: function.return_type.to_string(),
                panic_boundary: function.ffi_panic.clone(),
                panic_boundary_declared: function.ffi_panic.is_some(),
                ffi_stable_ok: unstable_types.is_empty(),
                unstable_types,
            }
        })
        .collect::<Vec<_>>();
    let pointer_contract_violation_count = imports
        .iter()
        .filter(|item| !item.pointer_contract_ok)
        .count();
    let callback_context_anchor_violation_count = imports
        .iter()
        .filter(|item| !item.callback_context_anchor_ok)
        .count();
    let async_import_violation_count = imports
        .iter()
        .filter(|item| item.async_import_forbidden)
        .count();
    let ffi_stable_type_violation_count = imports.iter().filter(|item| !item.ffi_stable_ok).count()
        + exports.iter().filter(|item| !item.ffi_stable_ok).count();
    let missing_panic_boundary_count = exports
        .iter()
        .filter(|item| !item.panic_boundary_declared)
        .count();
    FfiReport {
        schema_version: "fozzylang.ffi_report.v2".to_string(),
        versions: ffi_compatibility_versions(),
        pointer_contract_violation_count,
        callback_context_anchor_violation_count,
        ffi_stable_type_violation_count,
        async_import_violation_count,
        missing_panic_boundary_count,
        imports,
        exports,
        async_exports: collect_async_c_exports(fir)
            .iter()
            .map(|export| FfiAsyncExportRecord {
                name: export.name.clone(),
                symbol: export.mangled_symbol.clone(),
                params: export
                    .params
                    .iter()
                    .map(|(ty, name)| FfiAsyncExportParamRecord {
                        name: name.clone(),
                        c_type: ty.clone(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

pub(crate) fn render_ffi_report_markdown(report: &FfiReport) -> String {
    let mut out = String::from("# FFI Report\n\n");
    let import_count = report.imports.len();
    let export_count = report.exports.len();
    out.push_str(&format!(
        "- Imports: {import_count}\n- Exports: {export_count}\n- Pointer contract violations: {}\n- Callback anchor violations: {}\n- FFI-stable type violations: {}\n- Async import violations: {}\n- Missing panic boundary declarations: {}\n\n",
        report.pointer_contract_violation_count,
        report.callback_context_anchor_violation_count,
        report.ffi_stable_type_violation_count,
        report.async_import_violation_count,
        report.missing_panic_boundary_count,
    ));
    out.push_str("## Imports\n\n");
    for import in &report.imports {
        out.push_str(&format!(
            "- `{}` -> `{}` | pointer_contract_ok={} | callback_anchor_ok={} | ffi_stable_ok={} | async_forbidden={}\n",
            import.name,
            import.return_type,
            import.pointer_contract_ok,
            import.callback_context_anchor_ok,
            import.ffi_stable_ok,
            import.async_import_forbidden,
        ));
    }
    out.push_str("\n## Exports\n\n");
    for export in &report.exports {
        out.push_str(&format!(
            "- `{}` -> `{}` | panic_boundary_declared={} | ffi_stable_ok={}\n",
            export.name, export.return_type, export.panic_boundary_declared, export.ffi_stable_ok,
        ));
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

pub(crate) fn build_native_runtime_contracts_report() -> NativeRuntimeContractsReport {
    NativeRuntimeContractsReport {
        schema_version: "fozzylang.native_runtime_contracts.v1",
        versions: ffi_compatibility_versions(),
        imports: native_runtime_contracts()
            .into_iter()
            .map(|contract| NativeRuntimeContractImportRecord {
                callee: contract.callee,
                symbol: contract.symbol,
                arity: contract.arity,
                arg_ownership: contract.arg_ownership,
                return_ownership: contract.return_ownership,
                required_capability: contract.required_capability,
                linearity: contract.linearity,
                error_behavior: contract.error_behavior,
                trace_behavior: contract.trace_behavior,
                blocking_behavior: contract.blocking_behavior,
            })
            .collect(),
    }
}

pub(crate) fn render_native_runtime_contracts_markdown(
    report: &NativeRuntimeContractsReport,
) -> String {
    let mut out = String::from("# Native Runtime Contracts\n\n");
    out.push_str(&format!(
        "- Imports: {import_count}\n- Schema: `{}`\n\n",
        report.schema_version,
        import_count = report.imports.len()
    ));
    out.push_str(
        "| Callee | Symbol | Arity | Arg Ownership | Return Ownership | Capability | Linearity | Error | Trace | Blocking |\n|---|---|---:|---|---|---|---|---|---|---|\n",
    );
    for import in &report.imports {
        out.push_str(&format!(
            "| `{}` | `{}` | {} | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |\n",
            import.callee,
            import.symbol,
            import.arity,
            import.arg_ownership,
            import.return_ownership,
            import.required_capability,
            import.linearity,
            import.error_behavior,
            import.trace_behavior,
            import.blocking_behavior,
        ));
    }
    out
}
