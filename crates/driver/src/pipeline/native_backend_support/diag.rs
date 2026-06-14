use super::*;

pub(crate) fn native_lowerability_diagnostics(
    module: &ast::Module,
) -> Vec<diagnostics::Diagnostic> {
    let mut diagnostics = Vec::new();
    let pattern_source_functions = collect_pattern_source_function_map_from_module(module);
    let mut variant_keys = BTreeSet::<String>::new();
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        for stmt in &function.body {
            collect_variant_keys_from_stmt(stmt, &mut variant_keys);
        }
    }
    let variant_tags = variant_keys
        .into_iter()
        .enumerate()
        .map(|(idx, key)| (key, idx as i32 + 1))
        .collect::<HashMap<_, _>>();
    diagnostics.extend(native_runtime_import_contract_errors().into_iter().map(|message| {
        diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            message,
            Some(
                "runtime shim imports are reserved for capability/host-effect boundaries; local data-plane paths must lower directly"
                    .to_string(),
            ),
        )
    }));
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        for param in &function.params {
            if !native_backend_supports_signature_type(&param.ty) {
                diagnostics.push(diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    format!(
                        "native backend does not support parameter type `{}` in function `{}`",
                        param.ty, function.name
                    ),
                    Some(
                        "native backend signatures support scalar widths, pointer-sized integers, floats, and pointer-like/aggregate handles"
                            .to_string(),
                    ),
                ));
            }
        }
        if !native_backend_supports_signature_type(&function.return_type) {
            diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!(
                    "native backend does not support return type `{}` in function `{}`",
                    function.return_type, function.name
                ),
                Some(
                    "native backend signatures support scalar widths, pointer-sized integers, floats, and pointer-like/aggregate handles"
                        .to_string(),
                ),
            ));
        }
        if let Err(error) =
            build_control_flow_cfg(&function.body, &variant_tags, &pattern_source_functions)
        {
            diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!(
                    "native backend cannot lower pattern/control-flow semantics in function `{}`: {}",
                    function.name, error
                ),
                Some(
                    "rewrite unsupported pattern guard shapes or non-lowerable control-flow forms to explicit statements"
                        .to_string(),
                ),
            ));
        }
    }

    let defined_functions = collect_defined_function_names(module);
    let mut unresolved = HashSet::<String>::new();
    for item in &module.items {
        if let ast::Item::Function(function) = item {
            let mut local_callables = HashSet::<String>::new();
            collect_local_callable_bindings(&function.body, &mut local_callables);
            for stmt in &function.body {
                collect_unresolved_calls_from_stmt(
                    stmt,
                    &defined_functions,
                    &local_callables,
                    &mut unresolved,
                );
            }
        }
    }
    let mut unresolved = unresolved.into_iter().collect::<Vec<_>>();
    unresolved.sort();
    diagnostics.extend(unresolved.into_iter().map(|callee| {
        let mut help =
            "run via Fozzy scenario/host backends or provide a real native implementation for this symbol"
                .to_string();
        if let Some(stripped) = callee.strip_prefix("process.") {
            let migrated = format!("proc.{stripped}");
            if hir::runtime_intrinsic_names().contains(&migrated.as_str()) {
                help.push_str(&format!(
                    "; `process.*` was removed, migrate to `{migrated}`"
                ));
            }
        } else {
            let nearest = hir::runtime_intrinsic_names()
                .iter()
                .map(|candidate| {
                    (
                        *candidate,
                        candidate
                            .chars()
                            .zip(callee.chars())
                            .filter(|(left, right)| left != right)
                            .count()
                            + candidate.len().abs_diff(callee.len()),
                    )
                })
                .min_by_key(|(_, distance)| *distance)
                .and_then(|(candidate, distance)| (distance <= 6).then_some(candidate));
            if let Some(suggested) = nearest {
                help.push_str(&format!("; did you mean `{suggested}`?"));
            }
        }
        diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            format!("native backend cannot execute unresolved call `{callee}`"),
            Some(help),
        )
        .with_catalog_key("native.unresolved_call")
    }));

    diagnostics::assign_stable_codes(
        &mut diagnostics,
        diagnostics::DiagnosticDomain::NativeLowering,
    );
    diagnostics
}

pub(crate) fn experimental_feature_diagnostics(
    _module: &ast::Module,
    manifest: Option<&manifest::Manifest>,
) -> Vec<diagnostics::Diagnostic> {
    let tier = manifest
        .map(|value| value.language.tier.as_str())
        .unwrap_or("core_v1");
    let allow_experimental = manifest
        .map(|value| value.language.allow_experimental)
        .unwrap_or(false);
    if tier == "experimental" && allow_experimental {
        return Vec::new();
    }

    let mut diagnostics = Vec::new();
    diagnostics::assign_stable_codes(&mut diagnostics, diagnostics::DiagnosticDomain::Verifier);
    diagnostics
}

pub(crate) fn backend_capability_diagnostics(
    module: &ast::Module,
    backend: &str,
    for_library: bool,
) -> Vec<diagnostics::Diagnostic> {
    let mut diagnostics = Vec::new();
    let backend = backend.trim().to_ascii_lowercase();
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        let crosses_abi = function.is_pubext || function.is_extern || function.abi.is_some();
        let signature_has_simd = function
            .params
            .iter()
            .any(|param| type_contains_simd(&param.ty))
            || type_contains_simd(&function.return_type);
        if crosses_abi && signature_has_simd {
            diagnostics.push(
                diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    format!(
                        "SIMD type appears across ABI boundary in function `{}`",
                        function.name
                    ),
                    Some(
                        "portable SIMD is not ABI-stable in phase 1; keep SIMD values inside native fzy functions"
                            .to_string(),
                    ),
                )
                .with_catalog_key("native.simd_abi_crossing_unsupported"),
            );
        }
    }
    if backend == "cranelift" {
        for item in &module.items {
            let ast::Item::Function(function) = item else {
                continue;
            };
            if !for_library
                && function.is_pubext
                && function.is_async
                && function
                    .abi
                    .as_deref()
                    .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
            {
                diagnostics.push(
                    diagnostics::Diagnostic::new(
                        diagnostics::Severity::Error,
                        format!(
                            "backend `cranelift` does not support async C export `{}`",
                            function.name
                        ),
                        Some(
                            "compile with `--backend llvm` or remove async C export surface"
                                .to_string(),
                        ),
                    )
                    .with_catalog_key("native.cranelift_async_c_export_unsupported")
                    .with_fix("switch backend: `fz build <path> --backend llvm`"),
                );
            }
            if function.is_async && function.is_unsafe {
                diagnostics.push(
                    diagnostics::Diagnostic::new(
                        diagnostics::Severity::Error,
                        format!(
                            "backend `cranelift` rejects async+unsafe function `{}`",
                            function.name
                        ),
                        Some(
                            "use backend llvm for this code shape or refactor unsafe code outside async path"
                                .to_string(),
                        ),
                    )
                    .with_catalog_key("native.cranelift_async_unsafe_unsupported")
                    .with_fix("switch backend: `fz build <path> --backend llvm`"),
                );
            }
        }
    }
    diagnostics::assign_stable_codes(
        &mut diagnostics,
        diagnostics::DiagnosticDomain::NativeLowering,
    );
    diagnostics
}

fn type_contains_simd(ty: &ast::Type) -> bool {
    match ty {
        ast::Type::SimdVector(_) | ast::Type::SimdMask(_) => true,
        ast::Type::Ptr { to, .. } | ast::Type::Ref { to, .. } => type_contains_simd(to),
        ast::Type::Slice(inner)
        | ast::Type::Set(inner)
        | ast::Type::Deque(inner)
        | ast::Type::Ring(inner)
        | ast::Type::Option(inner)
        | ast::Type::Vec(inner)
        | ast::Type::Future(inner) => type_contains_simd(inner),
        ast::Type::Array { elem, .. } => type_contains_simd(elem),
        ast::Type::Result { ok, err } => type_contains_simd(ok) || type_contains_simd(err),
        ast::Type::Map { key, value } => type_contains_simd(key) || type_contains_simd(value),
        ast::Type::Function { params, ret } => {
            params.iter().any(type_contains_simd) || type_contains_simd(ret)
        }
        ast::Type::Tuple(items) => items.iter().any(type_contains_simd),
        ast::Type::Named { args, .. } => args.iter().any(type_contains_simd),
        ast::Type::Never
        | ast::Type::Void
        | ast::Type::Bool
        | ast::Type::ISize
        | ast::Type::USize
        | ast::Type::Int { .. }
        | ast::Type::BigInt
        | ast::Type::BigUint
        | ast::Type::Float { .. }
        | ast::Type::Decimal128
        | ast::Type::Char
        | ast::Type::Str
        | ast::Type::Bytes
        | ast::Type::Uuid
        | ast::Type::Path
        | ast::Type::PathBuf
        | ast::Type::Url
        | ast::Type::SocketAddr
        | ast::Type::Duration
        | ast::Type::Instant
        | ast::Type::Decimal
        | ast::Type::DateTimeTz
        | ast::Type::ExitStatus
        | ast::Type::DynTrait(_)
        | ast::Type::TypeVar(_) => false,
    }
}

pub(crate) fn native_backend_supports_signature_type(ty: &ast::Type) -> bool {
    ast_signature_type_to_clif_type(ty).is_some()
        || matches!(ty, ast::Type::Void | ast::Type::Never)
}
