use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use super::*;

#[derive(Debug, Clone)]
pub(super) struct NativeAsyncExport {
    pub(super) name: String,
    pub(super) mangled_symbol: String,
    pub(super) params: Vec<(String, String)>,
}

pub(super) fn native_runtime_import_contract_errors() -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = HashSet::<&'static str>::new();
    for import in NATIVE_RUNTIME_IMPORTS {
        if !seen.insert(import.callee) {
            errors.push(format!(
                "duplicate native runtime import callee `{}` in boundary import table",
                import.callee
            ));
        }
    }
    for import in NATIVE_DATA_PLANE_IMPORTS {
        if !seen.insert(import.callee) {
            errors.push(format!(
                "duplicate native runtime import callee `{}` in data-plane import table",
                import.callee
            ));
        }
    }

    let declared_runtime = hir::runtime_intrinsic_names()
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let imported_runtime = NATIVE_RUNTIME_IMPORTS
        .iter()
        .chain(NATIVE_DATA_PLANE_IMPORTS.iter())
        .map(|import| import.callee)
        .collect::<HashSet<_>>();

    let critical = [
        "str.concat",
        "str.concat2",
        "str.concat3",
        "str.concat4",
        "proc.run",
        "proc.spawn",
        "proc.run_cmd",
        "proc.spawn_cmd",
        "proc.exec_timeout",
    ];
    for callee in critical
        .iter()
        .copied()
        .filter(|callee| !declared_runtime.contains(callee))
    {
        errors.push(format!(
            "intrinsic `{}` is required by parity gate but missing from HIR declarations",
            callee
        ));
    }
    for callee in critical
        .iter()
        .copied()
        .filter(|callee| !imported_runtime.contains(callee))
    {
        errors.push(format!(
            "intrinsic `{}` is declared in HIR but missing native import binding",
            callee
        ));
    }
    for callee in imported_runtime
        .iter()
        .filter(|callee| !declared_runtime.contains(**callee))
    {
        errors.push(format!(
            "native import `{}` is not declared as a runtime intrinsic in HIR",
            callee
        ));
    }
    errors
}

pub(super) fn is_extern_c_import_decl(function: &hir::TypedFunction) -> bool {
    function.is_extern
        && function
            .abi
            .as_deref()
            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
        && function.body.is_empty()
}

pub(super) fn collect_extern_c_imports(fir: &fir::FirModule) -> Vec<&hir::TypedFunction> {
    fir.typed_functions
        .iter()
        .filter(|function| is_extern_c_import_decl(function))
        .collect()
}

pub(super) fn is_extern_c_abi_function(function: &hir::TypedFunction) -> bool {
    function.is_extern
        && function
            .abi
            .as_deref()
            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
}

pub(super) fn native_link_symbol_for_function(function: &hir::TypedFunction) -> String {
    let base = if is_extern_c_abi_function(function) {
        function
            .link_name
            .clone()
            .unwrap_or_else(|| function.name.clone())
    } else {
        function.name.clone()
    };
    native_mangle_symbol(&base)
}

pub(super) fn collect_async_c_exports(fir: &fir::FirModule) -> Vec<NativeAsyncExport> {
    fir.typed_functions
        .iter()
        .filter(|function| {
            function.is_async
                && is_extern_c_abi_function(function)
                && !function.body.is_empty()
                && matches!(
                    function.return_type,
                    ast::Type::Int {
                        signed: true,
                        bits: 32
                    }
                )
        })
        .map(|function| NativeAsyncExport {
            name: native_link_symbol_for_function(function),
            mangled_symbol: native_link_symbol_for_function(function),
            params: function
                .params
                .iter()
                .map(|param| {
                    (
                        ffi_signature_type_to_c_type(&param.ty),
                        native_mangle_symbol(&param.name),
                    )
                })
                .collect(),
        })
        .collect()
}

pub(super) fn ensure_native_runtime_shim(
    build_dir: &Path,
    string_literals: &[String],
    task_symbols: &[String],
    async_exports: &[NativeAsyncExport],
) -> Result<PathBuf> {
    let mut hasher = Sha256::new();
    for literal in string_literals {
        hasher.update(literal.as_bytes());
        hasher.update([0u8]);
    }
    for symbol in task_symbols {
        hasher.update(symbol.as_bytes());
        hasher.update([0u8]);
    }
    for export in async_exports {
        hasher.update(export.name.as_bytes());
        hasher.update([0u8]);
        hasher.update(export.mangled_symbol.as_bytes());
        hasher.update([0u8]);
        for (ty, name) in &export.params {
            hasher.update(ty.as_bytes());
            hasher.update([0u8]);
            hasher.update(name.as_bytes());
            hasher.update([0u8]);
        }
    }
    let digest = hasher.finalize();
    let tag = hex_encode(&digest[..8]);
    let runtime_shim_path = build_dir.join(format!("fz_native_runtime_{tag}.c"));
    std::fs::write(
        &runtime_shim_path,
        render_native_runtime_shim(string_literals, task_symbols, async_exports),
    )
    .with_context(|| {
        format!(
            "failed writing native runtime shim source: {}",
            runtime_shim_path.display()
        )
    })?;
    Ok(runtime_shim_path)
}

pub(super) fn compile_runtime_shim_object(
    runtime_shim_path: &Path,
    out_object: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<()> {
    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("-x")
            .arg("c")
            .arg(runtime_shim_path)
            .arg("-c")
            .arg("-fPIC")
            .arg("-o")
            .arg(out_object);
        apply_target_link_flags(&mut cmd);
        apply_profile_optimization_flags(&mut cmd, profile, manifest);
        apply_pgo_flags(&mut cmd)?;
        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed compiling runtime shim object: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    Err(anyhow!(
        "failed to compile runtime shim object: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}

pub(super) fn ffi_signature_type_to_c_type(ty: &ast::Type) -> String {
    match ty {
        ast::Type::Ptr { mutable, to } => {
            if *mutable {
                format!("{}*", ffi_signature_type_to_c_type(to))
            } else {
                format!("const {}*", ffi_signature_type_to_c_type(to))
            }
        }
        ast::Type::Void => "void".to_string(),
        ast::Type::Bool => "bool".to_string(),
        ast::Type::ISize => "ssize_t".to_string(),
        ast::Type::USize => "size_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 8,
        } => "int8_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 16,
        } => "int16_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 32,
        } => "int32_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 64,
        } => "int64_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 128,
        } => "__int128_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 8,
        } => "uint8_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 16,
        } => "uint16_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 32,
        } => "uint32_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 64,
        } => "uint64_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 128,
        } => "__uint128_t".to_string(),
        ast::Type::Float { bits: 32 } => "float".to_string(),
        ast::Type::Float { bits: 64 } => "double".to_string(),
        ast::Type::Char => "uint32_t".to_string(),
        ast::Type::Str => "const char*".to_string(),
        ast::Type::Named { name, .. } => name.clone(),
        _ => "void*".to_string(),
    }
}

pub(super) fn collect_used_native_runtime_imports(
    fir: &fir::FirModule,
) -> Vec<&'static NativeRuntimeImport> {
    let mut seen = HashSet::<&'static str>::new();
    let mut used = Vec::<&'static NativeRuntimeImport>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_used_runtime_imports_from_stmt(stmt, &mut seen, &mut used);
        }
    }
    used
}

pub(super) fn collect_used_native_data_plane_imports(
    fir: &fir::FirModule,
) -> Vec<&'static NativeRuntimeImport> {
    let mut seen = HashSet::<&'static str>::new();
    let mut used = Vec::<&'static NativeRuntimeImport>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_used_data_plane_imports_from_stmt(stmt, &mut seen, &mut used);
        }
    }
    used
}
