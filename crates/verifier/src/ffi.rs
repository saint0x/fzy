use fir::VerifierFunction;
use std::collections::BTreeSet;

pub(crate) fn extern_c_import_requires_unsafe(function: VerifierFunction<'_>) -> bool {
    is_extern_c_import(function)
        && !function.is_unsafe
        && (function.return_type.is_pointer_like()
            || function
                .params
                .iter()
                .any(|param| param.ty.is_pointer_like()))
}

pub(crate) fn extern_c_import_pointer_param_missing_contract(
    function: VerifierFunction<'_>,
) -> Option<&str> {
    if !is_extern_c_import(function) {
        return None;
    }
    for param in function.params {
        if !matches!(param.ty, ast::Type::Ptr { .. }) {
            continue;
        }
        let tagged = param.name.ends_with("_owned")
            || param.name.ends_with("_borrowed")
            || param.name.ends_with("_out")
            || param.name.ends_with("_inout");
        let ctx_param = param.name.ends_with("_ctx") || param.name.ends_with("_context");
        if (!tagged && !ctx_param) || (!ctx_param && !has_len_pair(function, &param.name)) {
            return Some(param.name.as_str());
        }
    }
    None
}

pub(crate) fn callback_param_missing_adjacent_context_anchor(
    function: VerifierFunction<'_>,
) -> Option<&str> {
    if !is_extern_c_import(function) {
        return None;
    }
    for (index, param) in function.params.iter().enumerate() {
        if !is_callback_param(&param.ty) {
            continue;
        }
        let prev_is_anchor = if index > 0 {
            function
                .params
                .get(index - 1)
                .is_some_and(|neighbor| is_context_anchor_name(&neighbor.name))
        } else {
            false
        };
        let next_is_anchor = function
            .params
            .get(index + 1)
            .is_some_and(|neighbor| is_context_anchor_name(&neighbor.name));
        let has_adjacent_anchor = prev_is_anchor || next_is_anchor;
        if !has_adjacent_anchor {
            return Some(param.name.as_str());
        }
    }
    None
}

fn is_callback_param(ty: &ast::Type) -> bool {
    matches!(ty, ast::Type::Function { .. })
}

pub(crate) fn collect_repr_c_names(module: &fir::FirModule) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (name, item) in &module.struct_defs {
        if item
            .repr
            .as_deref()
            .is_some_and(|repr| repr.to_ascii_lowercase().contains('c'))
        {
            names.insert(name.clone());
        }
    }
    for (name, item) in &module.enum_defs {
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

pub(crate) fn extern_c_import_unstable_ffi_type(
    function: VerifierFunction<'_>,
    repr_c_names: &BTreeSet<String>,
) -> Option<String> {
    if !is_extern_c_import(function) {
        return None;
    }
    if !ffi_stable_type(&function.return_type, repr_c_names) {
        return Some(format!(
            "extern C import `{}` uses unstable return type `{}`",
            function.name, function.return_type
        ));
    }
    for param in function.params {
        if !ffi_stable_type(&param.ty, repr_c_names) {
            return Some(format!(
                "extern C import `{}` parameter `{}` uses unstable type `{}`",
                function.name, param.name, param.ty
            ));
        }
    }
    None
}

fn is_extern_c_import(function: VerifierFunction<'_>) -> bool {
    function.is_extern && function.abi.as_deref() == Some("c") && !function.has_body
}

fn is_rpc_import(function: VerifierFunction<'_>) -> bool {
    function.is_extern && function.abi.as_deref() == Some("rpc") && !function.has_body
}

pub(crate) fn rpc_param_payload_violation(
    function: VerifierFunction<'_>,
) -> Option<(&str, &ast::Type)> {
    if !is_rpc_import(function) {
        return None;
    }
    function
        .params
        .iter()
        .find(|param| !param.ty.is_rpc_payload_supported())
        .map(|param| (param.name.as_str(), &param.ty))
}

pub(crate) fn rpc_return_payload_violation(function: VerifierFunction<'_>) -> Option<&ast::Type> {
    if !is_rpc_import(function) {
        return None;
    }
    (!function.return_type.is_rpc_payload_supported()).then_some(&function.return_type)
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

fn pointer_base_name(name: &str) -> String {
    for suffix in ["_borrowed", "_owned", "_out", "_inout"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    name.to_string()
}

fn has_len_pair(function: VerifierFunction<'_>, pointer_param_name: &str) -> bool {
    let base = pointer_base_name(pointer_param_name);
    let expected = format!("{base}_len");
    function.params.iter().any(|candidate| {
        matches!(candidate.ty, ast::Type::USize)
            && (candidate.name == "len"
                || candidate.name == expected
                || candidate.name == format!("{base}_bytes"))
    })
}

fn is_context_anchor_name(name: &str) -> bool {
    name.ends_with("_ctx") || name.ends_with("_context")
}
