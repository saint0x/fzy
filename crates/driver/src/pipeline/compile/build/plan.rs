use super::*;

pub(crate) fn build_incremental_module_plans(
    parsed: &ParsedProgram,
    fir: &fir::FirModule,
    project_root: &Path,
) -> Vec<IncrementalModuleUnitPlan> {
    let mut plans = parsed
        .qualified_modules()
        .iter()
        .map(|unit| {
            let mut local_functions = HashSet::new();
            let mut local_mutable_globals = HashSet::new();
            for item in &unit.ast.items {
                match item {
                    ast::Item::Function(function) => {
                        local_functions.insert(function.name.clone());
                    }
                    ast::Item::Impl(item) => {
                        let receiver = item.for_type.to_string();
                        for method in &item.methods {
                            local_functions.insert(format!("{receiver}.{}", method.name));
                        }
                    }
                    ast::Item::Static(item) if item.mutable => {
                        local_mutable_globals.insert(item.name.clone());
                    }
                    ast::Item::Const(_)
                    | ast::Item::Static(_)
                    | ast::Item::TypeAlias(_)
                    | ast::Item::NewType(_)
                    | ast::Item::Struct(_)
                    | ast::Item::Enum(_)
                    | ast::Item::Trait(_)
                    | ast::Item::Test(_) => {}
                }
            }
            IncrementalModuleUnitPlan {
                path: unit.path.clone(),
                namespace: unit.namespace.clone(),
                source_fingerprint: unit.source_fingerprint.clone(),
                local_functions,
                local_mutable_globals,
            }
        })
        .collect::<Vec<_>>();
    let mut claimed_functions = plans
        .iter()
        .flat_map(|plan| plan.local_functions.iter().cloned())
        .collect::<HashSet<_>>();
    let mut claimed_globals = plans
        .iter()
        .flat_map(|plan| plan.local_mutable_globals.iter().cloned())
        .collect::<HashSet<_>>();
    let residual_functions = fir
        .typed_functions
        .iter()
        .filter(|function| {
            !matches!(
                function.execution_space,
                ast::ExecutionSpace::Kernel | ast::ExecutionSpace::Device
            ) && !is_extern_c_import_decl(function)
                && !claimed_functions.contains(&function.name)
        })
        .map(|function| function.name.clone())
        .collect::<HashSet<_>>();
    let residual_globals = fir
        .typed_globals
        .iter()
        .filter(|global| global.mutable && !claimed_globals.contains(&global.name))
        .map(|global| global.name.clone())
        .collect::<HashSet<_>>();
    if !residual_functions.is_empty() || !residual_globals.is_empty() {
        claimed_functions.extend(residual_functions.iter().cloned());
        claimed_globals.extend(residual_globals.iter().cloned());
        plans.push(IncrementalModuleUnitPlan {
            path: project_root.join(".fz").join("incremental-stdlib"),
            namespace: "::__synthetic_stdlib".to_string(),
            source_fingerprint: parsed.global_interface_fingerprint.clone(),
            local_functions: residual_functions,
            local_mutable_globals: residual_globals,
        });
    }
    plans
}
