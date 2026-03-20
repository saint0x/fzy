use std::collections::HashSet;

use super::super::*;

pub(crate) fn native_runtime_import_contract_errors() -> Vec<String> {
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

pub(crate) fn collect_used_native_runtime_imports(
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

pub(crate) fn collect_used_native_data_plane_imports(
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
