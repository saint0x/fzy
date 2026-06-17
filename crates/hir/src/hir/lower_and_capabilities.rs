use crate::*;

pub fn lower(module: &Module) -> TypedModule {
    let mut fn_sigs = HashMap::<String, (Vec<Type>, Type)>::new();
    let mut fn_async = HashMap::<String, bool>::new();
    let mut fn_generics = HashMap::<String, Vec<ast::GenericParam>>::new();
    let mut pending_functions = Vec::<PendingTypedFunction>::new();
    let mut type_errors = 0usize;
    let mut type_error_details = Vec::new();
    let mut typed_globals = Vec::new();
    let mut global_scope = SymbolScopes::new();
    let mut global_const_values = HashMap::<String, i32>::new();
    let ModuleDeclIndex {
        struct_defs,
        enum_defs,
        trait_defs,
        trait_impls,
        type_aliases,
    } = index_module_declarations(module);
    let mut generic_specializations = BTreeSet::new();
    let mut trait_violations = validate_trait_impls(module, &trait_defs);
    let mut fn_param_names = HashMap::<String, Vec<String>>::new();
    let mut fn_is_extern_unsafe_c = BTreeSet::<String>::new();
    let empty_global_types = HashMap::<String, Type>::new();
    let empty_global_mutability = HashMap::<String, bool>::new();
    let empty_assoc_types = HashMap::<String, Type>::new();

    for item in &module.items {
        match item {
            ast::Item::Const(item) => {
                let declared_ty = resolve_alias_type(&item.ty, &type_aliases, 0);
                let inferred = infer_expr_type(
                    &item.value,
                    &global_scope,
                    &TypeCheckEnv {
                        current_namespace: "",
                        fn_sigs: &fn_sigs,
                        fn_async: &fn_async,
                        fn_generics: &fn_generics,
                        fn_param_names: &fn_param_names,
                        fn_is_extern_unsafe_c: &fn_is_extern_unsafe_c,
                        struct_defs: &struct_defs,
                        enum_defs: &enum_defs,
                        trait_impls: &trait_impls,
                        global_types: &empty_global_types,
                        global_mutability: &empty_global_mutability,
                    },
                    &mut TypeCheckState {
                        errors: &mut type_errors,
                        type_error_details: &mut type_error_details,
                        generic_specializations: &mut generic_specializations,
                        trait_violations: &mut trait_violations,
                    },
                );
                if let Some(actual) = inferred {
                    if !expr_type_compatible(&declared_ty, &actual, &item.value) {
                        record_type_error(
                            &mut type_errors,
                            &mut type_error_details,
                            format!(
                                "const `{}` type mismatch: expected `{}`, got `{}`",
                                item.name, declared_ty, actual
                            ),
                        );
                    }
                }
                let const_i32 = eval_const_i32(&item.value, &global_const_values);
                if const_i32.is_none() {
                    record_type_error(
                        &mut type_errors,
                        &mut type_error_details,
                        format!(
                            "const `{}` must be initialized with an integer/char/bool compile-time expression",
                            item.name
                        ),
                    );
                }
                if let Some(value) = const_i32 {
                    global_const_values.insert(item.name.clone(), value);
                }
                global_scope.insert(item.name.clone(), declared_ty.clone(), false);
                typed_globals.push(TypedGlobal {
                    name: item.name.clone(),
                    ty: declared_ty,
                    is_static: false,
                    mutable: false,
                    is_pub: item.is_pub,
                    const_i32,
                });
            }
            ast::Item::Static(item) => {
                let declared_ty = resolve_alias_type(&item.ty, &type_aliases, 0);
                let inferred = infer_expr_type(
                    &item.value,
                    &global_scope,
                    &TypeCheckEnv {
                        current_namespace: "",
                        fn_sigs: &fn_sigs,
                        fn_async: &fn_async,
                        fn_generics: &fn_generics,
                        fn_param_names: &fn_param_names,
                        fn_is_extern_unsafe_c: &fn_is_extern_unsafe_c,
                        struct_defs: &struct_defs,
                        enum_defs: &enum_defs,
                        trait_impls: &trait_impls,
                        global_types: &empty_global_types,
                        global_mutability: &empty_global_mutability,
                    },
                    &mut TypeCheckState {
                        errors: &mut type_errors,
                        type_error_details: &mut type_error_details,
                        generic_specializations: &mut generic_specializations,
                        trait_violations: &mut trait_violations,
                    },
                );
                if let Some(actual) = inferred {
                    if !expr_type_compatible(&declared_ty, &actual, &item.value) {
                        record_type_error(
                            &mut type_errors,
                            &mut type_error_details,
                            format!(
                                "static `{}` type mismatch: expected `{}`, got `{}`",
                                item.name, declared_ty, actual
                            ),
                        );
                    }
                }
                let const_i32 = eval_const_i32(&item.value, &global_const_values);
                if const_i32.is_none() {
                    record_type_error(
                        &mut type_errors,
                        &mut type_error_details,
                        format!(
                            "static `{}` must be initialized with an integer/char/bool compile-time expression",
                            item.name
                        ),
                    );
                }
                if let Some(value) = const_i32 {
                    global_const_values.insert(item.name.clone(), value);
                }
                global_scope.insert(item.name.clone(), declared_ty.clone(), item.mutable);
                typed_globals.push(TypedGlobal {
                    name: item.name.clone(),
                    ty: declared_ty,
                    is_static: true,
                    mutable: item.mutable,
                    is_pub: item.is_pub,
                    const_i32,
                });
            }
            ast::Item::Function(function) => {
                let params = function
                    .params
                    .iter()
                    .map(|param| ast::Param {
                        name: param.name.clone(),
                        ty: resolve_alias_type(&param.ty, &type_aliases, 0),
                    })
                    .collect::<Vec<_>>();
                let return_type = resolve_alias_type(&function.return_type, &type_aliases, 0);
                for detail in
                    validate_generic_bounds_exist(&function.name, &function.generics, &trait_defs)
                {
                    record_type_error(&mut type_errors, &mut type_error_details, detail.clone());
                    trait_violations.push(detail);
                }
                fn_sigs.insert(
                    function.name.clone(),
                    (
                        params.iter().map(|p| p.ty.clone()).collect(),
                        return_type.clone(),
                    ),
                );
                fn_param_names.insert(
                    function.name.clone(),
                    function
                        .params
                        .iter()
                        .map(|param| param.name.clone())
                        .collect(),
                );
                if function.is_extern && function.is_unsafe && function.abi.as_deref() == Some("c")
                {
                    fn_is_extern_unsafe_c.insert(function.name.clone());
                }
                fn_async.insert(function.name.clone(), function.is_async);
                fn_generics.insert(function.name.clone(), function.generics.clone());
                pending_functions.push(PendingTypedFunction {
                    name: function.name.clone(),
                    link_name: function.link_name.clone(),
                    generics: function.generics.clone(),
                    params,
                    return_type,
                    body: function.body.clone(),
                    is_unsafe: function.is_unsafe,
                    is_async: function.is_async,
                    is_extern: function.is_extern,
                    execution_space: function.execution_space,
                    abi: function.abi.clone(),
                    ffi_panic: function.ffi_panic.clone(),
                    is_test: false,
                });
            }
            ast::Item::Test(test) => {
                let name = format!("test::{}", sanitize_test_name(&test.name));
                fn_sigs.insert(name.clone(), (Vec::new(), Type::Void));
                fn_async.insert(name.clone(), false);
                fn_generics.insert(name.clone(), Vec::new());
                pending_functions.push(PendingTypedFunction {
                    name,
                    link_name: None,
                    generics: Vec::new(),
                    params: Vec::new(),
                    return_type: Type::Void,
                    body: test.body.clone(),
                    is_unsafe: false,
                    is_async: false,
                    is_extern: false,
                    execution_space: ast::ExecutionSpace::Host,
                    abi: None,
                    ffi_panic: None,
                    is_test: true,
                });
            }
            ast::Item::Impl(item) => {
                let for_type = resolve_alias_type(&item.for_type, &type_aliases, 0);
                let receiver = for_type.to_string();
                let impl_associated_types = item
                    .associated_types
                    .iter()
                    .map(|(name, ty)| {
                        let resolved = resolve_alias_type(ty, &type_aliases, 0);
                        let contextual =
                            resolve_impl_context_type(&resolved, &for_type, &empty_assoc_types);
                        (name.clone(), contextual)
                    })
                    .collect::<HashMap<_, _>>();
                for method in &item.methods {
                    let params = method
                        .params
                        .iter()
                        .map(|param| ast::Param {
                            name: param.name.clone(),
                            ty: resolve_impl_context_type(
                                &resolve_alias_type(&param.ty, &type_aliases, 0),
                                &for_type,
                                &impl_associated_types,
                            ),
                        })
                        .collect::<Vec<_>>();
                    let return_type = resolve_impl_context_type(
                        &resolve_alias_type(&method.return_type, &type_aliases, 0),
                        &for_type,
                        &impl_associated_types,
                    );
                    let method_symbol = format!("{receiver}.{}", method.name);
                    for detail in
                        validate_generic_bounds_exist(&method_symbol, &method.generics, &trait_defs)
                    {
                        record_type_error(
                            &mut type_errors,
                            &mut type_error_details,
                            detail.clone(),
                        );
                        trait_violations.push(detail);
                    }
                    if fn_sigs.contains_key(&method_symbol) {
                        record_type_error(
                            &mut type_errors,
                            &mut type_error_details,
                            format!("duplicate impl method symbol `{method_symbol}`"),
                        );
                        continue;
                    }
                    fn_sigs.insert(
                        method_symbol.clone(),
                        (
                            params.iter().map(|p| p.ty.clone()).collect(),
                            return_type.clone(),
                        ),
                    );
                    fn_async.insert(method_symbol.clone(), method.is_async);
                    fn_generics.insert(method_symbol.clone(), method.generics.clone());
                    pending_functions.push(PendingTypedFunction {
                        name: method_symbol,
                        link_name: method.link_name.clone(),
                        generics: method.generics.clone(),
                        params,
                        return_type,
                        body: method.body.clone(),
                        is_unsafe: method.is_unsafe,
                        is_async: method.is_async,
                        is_extern: method.is_extern,
                        execution_space: method.execution_space,
                        abi: method.abi.clone(),
                        ffi_panic: method.ffi_panic.clone(),
                        is_test: false,
                    });
                }
            }
            _ => {}
        }
    }
    let global_types = typed_globals
        .iter()
        .map(|item| (item.name.clone(), item.ty.clone()))
        .collect::<HashMap<_, _>>();
    let global_mutability = typed_globals
        .iter()
        .map(|item| (item.name.clone(), item.mutable))
        .collect::<HashMap<_, _>>();

    let mut typed_functions = Vec::with_capacity(pending_functions.len());
    for pending in pending_functions {
        if pending.body.is_empty() {
            typed_functions.push(TypedFunction {
                name: pending.name,
                link_name: pending.link_name,
                generics: pending.generics,
                params: pending.params,
                local_types: BTreeMap::new(),
                return_type: pending.return_type,
                body: pending.body,
                is_unsafe: pending.is_unsafe,
                is_async: pending.is_async,
                is_extern: pending.is_extern,
                execution_space: pending.execution_space,
                abi: pending.abi,
                ffi_panic: pending.ffi_panic,
                is_test: pending.is_test,
                required_capabilities: Vec::new(),
            });
            continue;
        }
        let mut scopes = SymbolScopes::new();
        let mut local_types = BTreeMap::new();
        let current_namespace = pending
            .name
            .rsplit_once('.')
            .map(|(prefix, _)| prefix)
            .unwrap_or("");
        let env = TypeCheckEnv {
            current_namespace,
            fn_sigs: &fn_sigs,
            fn_async: &fn_async,
            fn_generics: &fn_generics,
            fn_param_names: &fn_param_names,
            fn_is_extern_unsafe_c: &fn_is_extern_unsafe_c,
            struct_defs: &struct_defs,
            enum_defs: &enum_defs,
            trait_impls: &trait_impls,
            global_types: &global_types,
            global_mutability: &global_mutability,
        };
        let mut state = TypeCheckState {
            errors: &mut type_errors,
            type_error_details: &mut type_error_details,
            generic_specializations: &mut generic_specializations,
            trait_violations: &mut trait_violations,
        };
        for param in &pending.params {
            scopes.insert(param.name.clone(), param.ty.clone(), false);
            local_types.insert(param.name.clone(), param.ty.clone());
        }
        for stmt in &pending.body {
            type_check_stmt(
                stmt,
                &mut scopes,
                &mut local_types,
                &env,
                0,
                &pending.return_type,
                &mut state,
            );
        }
        typed_functions.push(TypedFunction {
            name: pending.name,
            link_name: pending.link_name,
            generics: pending.generics,
            params: pending.params,
            local_types,
            return_type: pending.return_type,
            body: pending.body,
            is_unsafe: pending.is_unsafe,
            is_async: pending.is_async,
            is_extern: pending.is_extern,
            execution_space: pending.execution_space,
            abi: pending.abi,
            ffi_panic: pending.ffi_panic,
            is_test: pending.is_test,
            required_capabilities: Vec::new(),
        });
    }
    let function_capability_requirements = compute_function_capabilities(&typed_functions);
    for function in &mut typed_functions {
        if let Some(entry) = function_capability_requirements
            .iter()
            .find(|entry| entry.function == function.name)
        {
            function.required_capabilities = entry.required.clone();
        }
    }
    infer_default_pure_functions(&mut typed_functions, &struct_defs, &enum_defs);
    for detail in analyze_execution_spaces(&typed_functions) {
        record_type_error(&mut type_errors, &mut type_error_details, detail);
    }
    validate_async_semantics(
        &typed_functions,
        &fn_async,
        &mut type_errors,
        &mut type_error_details,
    );
    for detail in analyze_device_safe_types(&typed_functions, &struct_defs, &enum_defs) {
        record_type_error(&mut type_errors, &mut type_error_details, detail);
    }

    let entry_return_type = typed_functions
        .iter()
        .find(|f| f.name == "main")
        .map(|f| f.return_type.clone());
    let entry_return_const_i32 = interpret_entry_i32(&typed_functions);
    let entry_has_return_expr = typed_functions
        .iter()
        .find(|f| f.name == "main")
        .is_some_and(|f| function_has_explicit_return(&f.body));

    let (
        linear_resources,
        deferred_resources,
        matches_without_wildcard,
        match_unreachable_arms,
        match_duplicate_catchall_arms,
    ) = collect_semantic_hints(&typed_functions);
    let (entry_requires, entry_ensures) = collect_entry_contracts(&typed_functions, &fn_sigs);
    let (
        host_syscall_sites,
        _unsafe_sites_markers,
        _unsafe_reasoned_sites_markers,
        reference_sites,
        alloc_sites,
        free_sites,
    ) = collect_effect_markers(&typed_functions);
    let unsafe_contract_sites = collect_unsafe_contract_sites(&typed_functions);
    let unsafe_sites = unsafe_contract_sites
        .iter()
        .filter(|site| site.kind != "unsafe_violation_callsite")
        .count();
    let unsafe_reasoned_sites = unsafe_contract_sites
        .iter()
        .filter(|site| site.kind != "unsafe_violation_callsite")
        .filter(|site| unsafe_contract_counts_as_reasoned(site))
        .count();
    let inferred_capabilities = infer_capabilities(&typed_functions);
    let extern_c_abi_functions = module
        .items
        .iter()
        .filter(|item| {
            matches!(
                item,
                ast::Item::Function(function)
                    if function.is_extern
                        && function
                            .abi
                            .as_deref()
                            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
            )
        })
        .count();
    let repr_c_layout_items = module
        .items
        .iter()
        .filter(|item| {
            matches!(
                item,
                ast::Item::Struct(ast::Struct { repr: Some(repr), .. })
                    | ast::Item::Enum(ast::Enum { repr: Some(repr), .. })
                    if repr.to_ascii_lowercase().contains('c')
            )
        })
        .count();
    let generic_instantiations = collect_generic_instantiations(module);
    let call_graph = build_call_graph(module);
    let ownership_violations =
        analyze_ownership(&typed_functions, &call_graph, &struct_defs, &enum_defs);
    let unsafe_context_violations = analyze_unsafe_context_violations(&typed_functions);
    let capability_token_violations = if capability_token_mode_enabled(&typed_functions) {
        analyze_capability_token_contracts(&typed_functions, &function_capability_requirements)
    } else {
        Vec::new()
    };
    let thread_boundary_violations = analyze_send_sync_contracts(&typed_functions);
    let reference_lifetime_violations = analyze_reference_lifetimes(&typed_functions);
    let linear_type_violations = analyze_linear_types(&typed_functions);
    monomorphize_typed_functions(
        &mut typed_functions,
        &mut generic_specializations,
        &mut type_errors,
        &mut type_error_details,
    );

    TypedModule {
        name: module.name.clone(),
        symbol_count: module.items.len(),
        capabilities: module.capabilities.clone(),
        inferred_capabilities,
        entry_return_type,
        entry_return_const_i32,
        entry_has_return_expr,
        linear_resources,
        deferred_resources,
        matches_without_wildcard,
        match_unreachable_arms,
        match_duplicate_catchall_arms,
        entry_requires,
        entry_ensures,
        host_syscall_sites,
        unsafe_sites,
        unsafe_reasoned_sites,
        unsafe_contract_sites,
        reference_sites,
        alloc_sites,
        free_sites,
        extern_c_abi_functions,
        repr_c_layout_items,
        generic_instantiations,
        generic_specializations: generic_specializations.into_iter().collect(),
        call_graph,
        typed_functions,
        typed_globals,
        struct_defs,
        enum_defs,
        type_errors,
        type_error_details,
        function_capability_requirements,
        ownership_violations,
        unsafe_context_violations,
        capability_token_violations,
        thread_boundary_violations,
        trait_violations,
        reference_lifetime_violations,
        linear_type_violations,
    }
}

pub(crate) fn sanitize_test_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unnamed".to_string()
    } else {
        out
    }
}

pub(crate) fn validate_trait_impls(
    module: &Module,
    trait_defs: &HashMap<String, ast::Trait>,
) -> Vec<String> {
    let mut violations = Vec::new();
    let mut trait_impl_targets = HashMap::<String, Vec<Type>>::new();
    for item in &module.items {
        let ast::Item::Impl(item) = item else {
            continue;
        };
        let Some(trait_name) = &item.trait_name else {
            continue;
        };
        let recorded = trait_impl_targets.entry(trait_name.clone()).or_default();
        for existing in recorded.iter() {
            if type_compatible(existing, &item.for_type)
                || type_compatible(&item.for_type, existing)
            {
                violations.push(format!(
                    "overlapping impls for trait `{}`: `{}` conflicts with `{}`",
                    trait_name, item.for_type, existing
                ));
            }
        }
        recorded.push(item.for_type.clone());
        let Some(trait_def) = trait_defs.get(trait_name) else {
            violations.push(format!("impl references unknown trait `{trait_name}`"));
            continue;
        };
        let self_type = &item.for_type;
        let impl_associated_types = item
            .associated_types
            .iter()
            .map(|(name, ty)| (name.clone(), ty.clone()))
            .collect::<HashMap<_, _>>();
        for (name, _) in &item.associated_types {
            if !trait_def
                .associated_types
                .iter()
                .any(|candidate| candidate == name)
            {
                violations.push(format!(
                    "impl for `{}` defines extra associated type `{}` not declared by trait `{}`",
                    item.for_type, name, trait_name
                ));
            }
        }
        for item_const in &item.associated_consts {
            if trait_def
                .associated_consts
                .iter()
                .all(|candidate| candidate.name != item_const.name)
            {
                violations.push(format!(
                    "impl for `{}` defines extra associated const `{}` not declared by trait `{}`",
                    item.for_type, item_const.name, trait_name
                ));
            }
        }
        for assoc_type in &trait_def.associated_types {
            if item
                .associated_types
                .iter()
                .all(|(name, _)| name != assoc_type)
            {
                violations.push(format!(
                    "impl for `{}` missing associated type `{}` required by trait `{}`",
                    item.for_type, assoc_type, trait_name
                ));
            }
        }
        for assoc_const in &trait_def.associated_consts {
            let Some(found) = item
                .associated_consts
                .iter()
                .find(|candidate| candidate.name == assoc_const.name)
            else {
                violations.push(format!(
                    "impl for `{}` missing associated const `{}` required by trait `{}`",
                    item.for_type, assoc_const.name, trait_name
                ));
                continue;
            };
            let expected_ty =
                resolve_impl_context_type(&assoc_const.ty, self_type, &impl_associated_types);
            let actual_ty = resolve_impl_context_type(&found.ty, self_type, &impl_associated_types);
            if !type_compatible(&actual_ty, &expected_ty) {
                violations.push(format!(
                    "impl associated const `{}` type mismatch for trait `{}`: expected `{}`, got `{}`",
                    assoc_const.name, trait_name, expected_ty, actual_ty
                ));
            }
        }
        for impl_method in &item.methods {
            if trait_def
                .methods
                .iter()
                .all(|candidate| candidate.name != impl_method.name)
            {
                violations.push(format!(
                    "impl for `{}` defines extra method `{}` not declared by trait `{}`",
                    item.for_type, impl_method.name, trait_name
                ));
            }
        }
        for method in &trait_def.methods {
            let Some(found) = item
                .methods
                .iter()
                .find(|candidate| candidate.name == method.name)
            else {
                violations.push(format!(
                    "impl for `{}` missing method `{}` required by trait `{}`",
                    item.for_type, method.name, trait_name
                ));
                continue;
            };
            if found.params.len() != method.params.len() {
                violations.push(format!(
                    "impl method `{}` parameter count mismatch for trait `{}`",
                    method.name, trait_name
                ));
            }
            for (index, (found_param, trait_param)) in
                found.params.iter().zip(method.params.iter()).enumerate()
            {
                let expected_ty =
                    resolve_impl_context_type(&trait_param.ty, self_type, &impl_associated_types);
                let actual_ty =
                    resolve_impl_context_type(&found_param.ty, self_type, &impl_associated_types);
                if !type_compatible(&actual_ty, &expected_ty) {
                    violations.push(format!(
                        "impl method `{}` parameter {} type mismatch for trait `{}`: expected `{}`, got `{}`",
                        method.name, index, trait_name, expected_ty, actual_ty
                    ));
                }
            }
            let expected_return =
                resolve_impl_context_type(&method.return_type, self_type, &impl_associated_types);
            let actual_return =
                resolve_impl_context_type(&found.return_type, self_type, &impl_associated_types);
            if !type_compatible(&actual_return, &expected_return) {
                violations.push(format!(
                    "impl method `{}` return type mismatch for trait `{}`: expected `{}`, got `{}`",
                    method.name, trait_name, expected_return, actual_return
                ));
            }
            if !found.generics.is_empty() {
                violations.push(format!(
                    "impl method `{}` in trait `{}` must not declare generic parameters in v1",
                    method.name, trait_name
                ));
            }
            if found.is_async {
                violations.push(format!(
                    "impl method `{}` in trait `{}` must not be async in v1",
                    method.name, trait_name
                ));
            }
            if found.is_unsafe {
                violations.push(format!(
                    "impl method `{}` in trait `{}` must not be unsafe in v1",
                    method.name, trait_name
                ));
            }
        }
    }
    violations
}

pub(crate) fn validate_generic_bounds_exist(
    owner: &str,
    generics: &[ast::GenericParam],
    trait_defs: &HashMap<String, ast::Trait>,
) -> Vec<String> {
    let mut violations = Vec::new();
    for generic in generics {
        for bound in &generic.bounds {
            if !trait_defs.contains_key(bound) {
                violations.push(format!(
                    "{owner} declares generic bound `{}` on `{}` but trait `{}` is not defined",
                    bound, generic.name, bound
                ));
            }
        }
    }
    violations
}

pub(crate) fn analyze_capability_token_contracts(
    functions: &[TypedFunction],
    requirements: &[FunctionCapabilityRequirement],
) -> Vec<String> {
    let mut violations = Vec::new();
    let requirement_map = requirements
        .iter()
        .map(|entry| (entry.function.as_str(), entry))
        .collect::<BTreeMap<_, _>>();

    for function in functions {
        let required = requirement_map
            .get(function.name.as_str())
            .map(|entry| entry.required.clone())
            .unwrap_or_default();
        if required.is_empty() {
            continue;
        }

        let mut available = BTreeSet::<String>::new();
        for param in &function.params {
            if let Some(caps) = capability_set_from_type(&param.ty) {
                available.extend(caps);
            }
        }
        for cap in &required {
            if !available.contains(cap) {
                violations.push(format!(
                    "function `{}` requires capability `{}` but has no capability token parameter proving it",
                    function.name, cap
                ));
            }
        }

        let local_types = function
            .params
            .iter()
            .map(|p| (p.name.clone(), p.ty.clone()))
            .collect::<BTreeMap<_, _>>();
        analyze_call_token_propagation(
            &function.name,
            &function.body,
            &local_types,
            &requirement_map,
            &mut violations,
        );
    }

    violations
}

pub(crate) fn capability_token_mode_enabled(functions: &[TypedFunction]) -> bool {
    for function in functions {
        for param in &function.params {
            if capability_set_from_type(&param.ty).is_some() {
                return true;
            }
        }
        for stmt in &function.body {
            if statement_uses_cap_token_intrinsic(stmt) {
                return true;
            }
        }
    }
    false
}

pub(crate) fn statement_uses_cap_token_intrinsic(stmt: &Stmt) -> bool {
    fn expr_has_cap_intrinsic(expr: &Expr) -> bool {
        match expr {
            Expr::Call { callee, args } => {
                if callee == "revoke_cap"
                    || callee == "delegate_cap"
                    || callee == "compose_cap"
                    || callee == "intersect_cap"
                    || callee == "negate_cap"
                {
                    return true;
                }
                args.iter().any(expr_has_cap_intrinsic)
            }
            Expr::UnsafeBlock { .. } => false,
            Expr::FieldAccess { base, .. } => expr_has_cap_intrinsic(base),
            Expr::StructInit { fields, .. } => fields
                .iter()
                .any(|(_, value)| expr_has_cap_intrinsic(value)),
            Expr::EnumInit { payload, .. } => payload.iter().any(expr_has_cap_intrinsic),
            Expr::Tuple(items) => items.iter().any(expr_has_cap_intrinsic),
            Expr::Closure { body, .. } => expr_has_cap_intrinsic(body),
            Expr::TryCatch {
                try_expr,
                catch_expr,
            } => expr_has_cap_intrinsic(try_expr) || expr_has_cap_intrinsic(catch_expr),
            Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                expr_has_cap_intrinsic(condition)
                    || expr_has_cap_intrinsic(then_expr)
                    || expr_has_cap_intrinsic(else_expr)
            }
            Expr::Match { scrutinee, arms } => {
                expr_has_cap_intrinsic(scrutinee)
                    || arms.iter().any(|arm| {
                        arm.guard.as_ref().is_some_and(expr_has_cap_intrinsic)
                            || expr_has_cap_intrinsic(&arm.value)
                    })
            }
            Expr::While { condition, body } => {
                expr_has_cap_intrinsic(condition)
                    || body.iter().any(statement_uses_cap_token_intrinsic)
            }
            Expr::For {
                init,
                condition,
                step,
                body,
            } => {
                init.as_ref()
                    .is_some_and(|stmt| statement_uses_cap_token_intrinsic(stmt))
                    || condition
                        .as_ref()
                        .is_some_and(|expr| expr_has_cap_intrinsic(expr))
                    || step
                        .as_ref()
                        .is_some_and(|stmt| statement_uses_cap_token_intrinsic(stmt))
                    || body.iter().any(statement_uses_cap_token_intrinsic)
            }
            Expr::ForIn { iterable, body, .. } => {
                expr_has_cap_intrinsic(iterable)
                    || body.iter().any(statement_uses_cap_token_intrinsic)
            }
            Expr::Loop { body } => body.iter().any(statement_uses_cap_token_intrinsic),
            Expr::Return(value) | Expr::Break(value) => value
                .as_ref()
                .is_some_and(|expr| expr_has_cap_intrinsic(expr)),
            Expr::Continue => false,
            Expr::Binary { left, right, .. } => {
                expr_has_cap_intrinsic(left) || expr_has_cap_intrinsic(right)
            }
            Expr::Range { start, end, .. } => {
                expr_has_cap_intrinsic(start) || expr_has_cap_intrinsic(end)
            }
            Expr::ArrayLiteral(items) => items.iter().any(expr_has_cap_intrinsic),
            Expr::ObjectLiteral(fields) => fields
                .iter()
                .any(|(_, value)| expr_has_cap_intrinsic(value)),
            Expr::Index { base, index } => {
                expr_has_cap_intrinsic(base) || expr_has_cap_intrinsic(index)
            }
            Expr::Group(inner) => expr_has_cap_intrinsic(inner),
            Expr::Await(inner) => expr_has_cap_intrinsic(inner),
            Expr::Discard(inner) => expr_has_cap_intrinsic(inner),
            Expr::Unary { expr, .. } => expr_has_cap_intrinsic(expr),
            Expr::Int(_)
            | Expr::Float { .. }
            | Expr::Char(_)
            | Expr::Bool(_)
            | Expr::Str(_)
            | Expr::Ident(_) => false,
        }
    }

    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => expr_has_cap_intrinsic(value),
        Stmt::Return(None) => false,
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            expr_has_cap_intrinsic(condition)
                || then_body.iter().any(statement_uses_cap_token_intrinsic)
                || else_body.iter().any(statement_uses_cap_token_intrinsic)
        }
        Stmt::While { condition, body } => {
            expr_has_cap_intrinsic(condition) || body.iter().any(statement_uses_cap_token_intrinsic)
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref()
                .is_some_and(statement_uses_cap_token_intrinsic)
                || condition.as_ref().is_some_and(expr_has_cap_intrinsic)
                || step
                    .as_deref()
                    .is_some_and(statement_uses_cap_token_intrinsic)
                || body.iter().any(statement_uses_cap_token_intrinsic)
        }
        Stmt::ForIn { iterable, body, .. } => {
            expr_has_cap_intrinsic(iterable) || body.iter().any(statement_uses_cap_token_intrinsic)
        }
        Stmt::Loop { body } => body.iter().any(statement_uses_cap_token_intrinsic),
        Stmt::Break(_) | Stmt::Continue => false,
        Stmt::Match { scrutinee, arms } => {
            expr_has_cap_intrinsic(scrutinee)
                || arms.iter().any(|arm| {
                    arm.guard.as_ref().is_some_and(expr_has_cap_intrinsic)
                        || expr_has_cap_intrinsic(&arm.value)
                })
        }
    }
}

pub(crate) fn analyze_call_token_propagation(
    function_name: &str,
    body: &[Stmt],
    local_types: &BTreeMap<String, Type>,
    requirement_map: &BTreeMap<&str, &FunctionCapabilityRequirement>,
    violations: &mut Vec<String>,
) {
    for stmt in body {
        match stmt {
            Stmt::Let { .. }
            | Stmt::LetPattern { .. }
            | Stmt::Assign { .. }
            | Stmt::CompoundAssign { .. }
            | Stmt::Return(_)
            | Stmt::Defer(_)
            | Stmt::Requires(_)
            | Stmt::Ensures(_)
            | Stmt::Expr(_) => {
                analyze_expr_call_tokens(
                    function_name,
                    stmt_expr(stmt),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                analyze_expr_call_tokens(
                    function_name,
                    Some(condition),
                    local_types,
                    requirement_map,
                    violations,
                );
                analyze_call_token_propagation(
                    function_name,
                    then_body,
                    local_types,
                    requirement_map,
                    violations,
                );
                analyze_call_token_propagation(
                    function_name,
                    else_body,
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            Stmt::While { condition, body } => {
                analyze_expr_call_tokens(
                    function_name,
                    Some(condition),
                    local_types,
                    requirement_map,
                    violations,
                );
                analyze_call_token_propagation(
                    function_name,
                    body,
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    analyze_call_token_propagation(
                        function_name,
                        std::slice::from_ref(init.as_ref()),
                        local_types,
                        requirement_map,
                        violations,
                    );
                }
                analyze_expr_call_tokens(
                    function_name,
                    condition.as_ref(),
                    local_types,
                    requirement_map,
                    violations,
                );
                if let Some(step) = step {
                    analyze_call_token_propagation(
                        function_name,
                        std::slice::from_ref(step.as_ref()),
                        local_types,
                        requirement_map,
                        violations,
                    );
                }
                analyze_call_token_propagation(
                    function_name,
                    body,
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            Stmt::ForIn { iterable, body, .. } => {
                analyze_expr_call_tokens(
                    function_name,
                    Some(iterable),
                    local_types,
                    requirement_map,
                    violations,
                );
                analyze_call_token_propagation(
                    function_name,
                    body,
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            Stmt::Loop { body } => {
                analyze_call_token_propagation(
                    function_name,
                    body,
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            Stmt::Break(_) | Stmt::Continue => {}
            Stmt::Match { scrutinee, arms } => {
                analyze_expr_call_tokens(
                    function_name,
                    Some(scrutinee),
                    local_types,
                    requirement_map,
                    violations,
                );
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        analyze_expr_call_tokens(
                            function_name,
                            Some(guard),
                            local_types,
                            requirement_map,
                            violations,
                        );
                    }
                    analyze_expr_call_tokens(
                        function_name,
                        Some(&arm.value),
                        local_types,
                        requirement_map,
                        violations,
                    );
                }
            }
        }
    }
}

pub(crate) fn stmt_expr(stmt: &Stmt) -> Option<&Expr> {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value)
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. } => Some(value),
        Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::For { .. }
        | Stmt::ForIn { .. }
        | Stmt::Loop { .. }
        | Stmt::Break(_)
        | Stmt::Continue
        | Stmt::Match { .. }
        | Stmt::Return(None) => None,
    }
}

pub(crate) fn analyze_expr_call_tokens(
    function_name: &str,
    expr: Option<&Expr>,
    local_types: &BTreeMap<String, Type>,
    requirement_map: &BTreeMap<&str, &FunctionCapabilityRequirement>,
    violations: &mut Vec<String>,
) {
    let Some(expr) = expr else {
        return;
    };
    match expr {
        Expr::Call { callee, args } => {
            if let Some(requirement) = requirement_map.get(callee.as_str()) {
                let mut provided = BTreeSet::<String>::new();
                for arg in args {
                    if let Expr::Ident(name) = arg {
                        if let Some(ty) = local_types.get(name) {
                            if let Some(caps) = capability_set_from_type(ty) {
                                provided.extend(caps);
                            }
                        }
                    }
                }
                for cap in &requirement.required {
                    if !provided.contains(cap) {
                        violations.push(format!(
                            "function `{}` calls `{}` without passing capability token for `{}`",
                            function_name, callee, cap
                        ));
                    }
                }
            }

            if (callee == "revoke_cap" || callee == "delegate_cap") && args.is_empty() {
                violations.push(format!(
                    "function `{}` uses `{}` without token argument",
                    function_name, callee
                ));
            }

            for arg in args {
                analyze_expr_call_tokens(
                    function_name,
                    Some(arg),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            analyze_call_token_propagation(
                function_name,
                body,
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::FieldAccess { base, .. } => analyze_expr_call_tokens(
            function_name,
            Some(base),
            local_types,
            requirement_map,
            violations,
        ),
        Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                analyze_expr_call_tokens(
                    function_name,
                    Some(value),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::EnumInit { payload, .. } => {
            for value in payload {
                analyze_expr_call_tokens(
                    function_name,
                    Some(value),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::Tuple(items) => {
            for item in items {
                analyze_expr_call_tokens(
                    function_name,
                    Some(item),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::Closure { body, .. } => analyze_expr_call_tokens(
            function_name,
            Some(body),
            local_types,
            requirement_map,
            violations,
        ),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            analyze_expr_call_tokens(
                function_name,
                Some(try_expr),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(catch_expr),
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            analyze_expr_call_tokens(
                function_name,
                Some(condition),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(then_expr),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(else_expr),
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::Match { scrutinee, arms } => {
            analyze_expr_call_tokens(
                function_name,
                Some(scrutinee),
                local_types,
                requirement_map,
                violations,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    analyze_expr_call_tokens(
                        function_name,
                        Some(guard),
                        local_types,
                        requirement_map,
                        violations,
                    );
                }
                analyze_expr_call_tokens(
                    function_name,
                    Some(&arm.value),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::While { condition, body } => {
            analyze_expr_call_tokens(
                function_name,
                Some(condition),
                local_types,
                requirement_map,
                violations,
            );
            analyze_call_token_propagation(
                function_name,
                body,
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                analyze_call_token_propagation(
                    function_name,
                    std::slice::from_ref(init.as_ref()),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            if let Some(condition) = condition {
                analyze_expr_call_tokens(
                    function_name,
                    Some(condition),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            if let Some(step) = step {
                analyze_call_token_propagation(
                    function_name,
                    std::slice::from_ref(step.as_ref()),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            analyze_call_token_propagation(
                function_name,
                body,
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::ForIn { iterable, body, .. } => {
            analyze_expr_call_tokens(
                function_name,
                Some(iterable),
                local_types,
                requirement_map,
                violations,
            );
            analyze_call_token_propagation(
                function_name,
                body,
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::Loop { body } => analyze_call_token_propagation(
            function_name,
            body,
            local_types,
            requirement_map,
            violations,
        ),
        Expr::Return(value) | Expr::Break(value) => {
            if let Some(value) = value {
                analyze_expr_call_tokens(
                    function_name,
                    Some(value),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::Continue => {}
        Expr::Binary { left, right, .. } => {
            analyze_expr_call_tokens(
                function_name,
                Some(left),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(right),
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::Range { start, end, .. } => {
            analyze_expr_call_tokens(
                function_name,
                Some(start),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(end),
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::ArrayLiteral(items) => {
            for item in items {
                analyze_expr_call_tokens(
                    function_name,
                    Some(item),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                analyze_expr_call_tokens(
                    function_name,
                    Some(value),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::Index { base, index } => {
            analyze_expr_call_tokens(
                function_name,
                Some(base),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(index),
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::Group(inner) => analyze_expr_call_tokens(
            function_name,
            Some(inner),
            local_types,
            requirement_map,
            violations,
        ),
        Expr::Await(inner) => analyze_expr_call_tokens(
            function_name,
            Some(inner),
            local_types,
            requirement_map,
            violations,
        ),
        Expr::Discard(inner) => analyze_expr_call_tokens(
            function_name,
            Some(inner),
            local_types,
            requirement_map,
            violations,
        ),
        Expr::Unary { expr, .. } => analyze_expr_call_tokens(
            function_name,
            Some(expr),
            local_types,
            requirement_map,
            violations,
        ),
        Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Char(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::Ident(_) => {}
    }
}

pub(crate) fn capability_set_from_type(ty: &Type) -> Option<BTreeSet<String>> {
    match ty {
        Type::Named { name, args } if name == "Cap" && args.len() == 1 => {
            let mut set = BTreeSet::new();
            if let Some(cap_name) = capability_name_from_type(&args[0]) {
                set.insert(cap_name);
                return Some(set);
            }
            None
        }
        Type::Named { name, args } if name == "CapSet" => {
            let mut set = BTreeSet::new();
            for arg in args {
                if let Some(cap_name) = capability_name_from_type(arg) {
                    set.insert(cap_name);
                }
            }
            if set.is_empty() {
                None
            } else {
                Some(set)
            }
        }
        _ => None,
    }
}

pub(crate) fn capability_name_from_type(ty: &Type) -> Option<String> {
    match ty {
        Type::Named { name, args } if args.is_empty() => {
            core::Capability::parse(name).map(|cap| cap.as_str().to_string())
        }
        Type::TypeVar(name) => core::Capability::parse(name).map(|cap| cap.as_str().to_string()),
        _ => None,
    }
}

pub(crate) fn analyze_reference_lifetimes(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    let signatures = functions
        .iter()
        .map(|function| (function.name.as_str(), function))
        .collect::<FunctionSignatures<'_>>();
    for function in functions {
        let has_await = function_body_has_await(&function.body);
        let mut ref_bindings = CowBindings::<(Option<String>, bool)>::default();
        for param in &function.params {
            if let Type::Ref {
                lifetime, mutable, ..
            } = &param.ty
            {
                if lifetime.is_none() {
                    violations.push(format!(
                        "function `{}` parameter `{}` is a reference missing explicit lifetime annotation",
                        function.name, param.name
                    ));
                }
                ref_bindings.insert(param.name.clone(), (lifetime.clone(), *mutable));
                if function.is_async
                    && has_await
                    && ref_used_after_await(&function.body, &param.name, *mutable)
                {
                    violations.push(format!(
                        "function `{}` cannot use {} reference `{}` across await suspension points",
                        function.name,
                        if *mutable { "mutable" } else { "borrowed" },
                        param.name
                    ));
                }
            }
            if function.is_async
                && has_await
                && function_param_handle_is_not_async_stable(param)
                && ref_used_after_await(&function.body, &param.name, false)
            {
                let Type::Named { name, .. } = &param.ty else {
                    continue;
                };
                violations.push(format!(
                    "function `{}` cannot use non-async-stable handle `{}` ({}) across await suspension points",
                    function.name, param.name, name
                ));
            }
        }
        for (name, ty) in &function.local_types {
            if let Type::Ref {
                lifetime, mutable, ..
            } = ty
            {
                ref_bindings.insert(name.clone(), (lifetime.clone(), *mutable));
                if lifetime.is_none() {
                    violations.push(format!(
                        "function `{}` local reference `{}` is missing explicit lifetime annotation",
                        function.name, name
                    ));
                }
                if function.is_async
                    && has_await
                    && ref_used_after_await(&function.body, name, *mutable)
                {
                    violations.push(format!(
                        "function `{}` cannot use {} local reference `{}` across await suspension points",
                        function.name,
                        if *mutable { "mutable" } else { "borrowed" },
                        name
                    ));
                }
            }
            if function.is_async
                && has_await
                && runtime_handle_contract_is_not_async_stable(ty)
                && ref_used_after_await(&function.body, name, false)
            {
                let Type::Named {
                    name: handle_name, ..
                } = ty
                else {
                    continue;
                };
                violations.push(format!(
                    "function `{}` cannot use non-async-stable handle `{}` ({}) across await suspension points",
                    function.name, name, handle_name
                ));
            }
        }
        let return_lifetime = match &function.return_type {
            Type::Ref { lifetime, .. } => {
                if lifetime.is_none() {
                    violations.push(format!(
                        "function `{}` return reference is missing explicit lifetime annotation",
                        function.name
                    ));
                }
                lifetime.clone()
            }
            _ => None,
        };
        if return_lifetime.is_some() {
            let mut current_bindings = ref_bindings.clone();
            validate_reference_returns(
                &function.body,
                function,
                &mut current_bindings,
                &signatures,
                &return_lifetime,
                &mut violations,
            );
        }
    }
    violations
}

pub(crate) fn function_param_handle_is_not_async_stable(param: &ast::Param) -> bool {
    runtime_handle_contract_is_not_async_stable(&param.ty)
}

pub(crate) fn runtime_handle_contract_is_not_async_stable(ty: &Type) -> bool {
    matches!(ty, Type::Named { name, .. } if runtime_handle_contract(name).is_some_and(|contract| !contract.async_stable))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BorrowBinding {
    pub(crate) owner: String,
    pub(crate) mutable: bool,
}

pub(crate) type FunctionSignatures<'a> = BTreeMap<&'a str, &'a TypedFunction>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GpuSliceAccessMode {
    Observe,
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

impl GpuSliceAccessMode {
    pub(crate) fn with_read(self) -> Self {
        match self {
            Self::Observe => Self::ReadOnly,
            Self::ReadOnly => Self::ReadOnly,
            Self::WriteOnly => Self::ReadWrite,
            Self::ReadWrite => Self::ReadWrite,
        }
    }

    pub(crate) fn with_write(self) -> Self {
        match self {
            Self::Observe => Self::WriteOnly,
            Self::ReadOnly => Self::ReadWrite,
            Self::WriteOnly => Self::WriteOnly,
            Self::ReadWrite => Self::ReadWrite,
        }
    }

    pub(crate) fn is_read_only_like(self) -> bool {
        matches!(self, Self::Observe | Self::ReadOnly)
    }
}
