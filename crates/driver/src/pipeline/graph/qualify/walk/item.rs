use super::*;

pub(crate) fn qualify_module_symbols(
    module: &mut ast::Module,
    namespace: &str,
    root_module_aliases: &HashMap<String, String>,
) {
    let local_functions = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) => Some(function.name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let local_types = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::TypeAlias(item) => Some(item.name.clone()),
            ast::Item::NewType(item) => Some(item.name.clone()),
            ast::Item::Struct(item) => Some(item.name.clone()),
            ast::Item::Enum(item) => Some(item.name.clone()),
            ast::Item::Trait(item) => Some(item.name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut module_aliases = root_module_aliases.clone();
    for module_name in &module.modules {
        module_aliases.insert(
            module_name.clone(),
            super::super::text::qualify_name(namespace, module_name.as_str()),
        );
    }
    for (alias, target) in super::super::alias::import_aliases(module, &module_aliases) {
        module_aliases.insert(alias, target);
    }

    for item in &mut module.items {
        match item {
            ast::Item::Function(function) => {
                qualify_function(
                    function,
                    namespace,
                    &local_functions,
                    &local_types,
                    &module_aliases,
                );
            }
            ast::Item::Const(item) => {
                item.name = super::super::text::qualify_name(namespace, &item.name);
                qualify_type(&mut item.ty, namespace, &local_types, &module_aliases);
                qualify_expr(
                    &mut item.value,
                    namespace,
                    &local_functions,
                    &local_types,
                    &module_aliases,
                );
            }
            ast::Item::Static(item) => {
                item.name = super::super::text::qualify_name(namespace, &item.name);
                qualify_type(&mut item.ty, namespace, &local_types, &module_aliases);
                qualify_expr(
                    &mut item.value,
                    namespace,
                    &local_functions,
                    &local_types,
                    &module_aliases,
                );
            }
            ast::Item::Test(test) => {
                for stmt in &mut test.body {
                    qualify_stmt(
                        stmt,
                        namespace,
                        &local_functions,
                        &local_types,
                        &module_aliases,
                    );
                }
            }
            ast::Item::TypeAlias(item) => {
                item.name = super::super::text::qualify_name(namespace, &item.name);
                qualify_type(&mut item.ty, namespace, &local_types, &module_aliases);
            }
            ast::Item::NewType(item) => {
                item.name = super::super::text::qualify_name(namespace, &item.name);
                qualify_type(&mut item.inner, namespace, &local_types, &module_aliases);
            }
            ast::Item::Struct(item) => {
                item.name = super::super::text::qualify_name(namespace, &item.name);
                for field in &mut item.fields {
                    qualify_type(&mut field.ty, namespace, &local_types, &module_aliases);
                }
            }
            ast::Item::Enum(item) => {
                item.name = super::super::text::qualify_name(namespace, &item.name);
                for variant in &mut item.variants {
                    for payload in &mut variant.payload {
                        qualify_type(payload, namespace, &local_types, &module_aliases);
                    }
                    for field in &mut variant.named_payload {
                        qualify_type(&mut field.ty, namespace, &local_types, &module_aliases);
                    }
                }
            }
            ast::Item::Trait(item) => {
                item.name = super::super::text::qualify_name(namespace, &item.name);
                qualify_generic_params(
                    &mut item.generics,
                    namespace,
                    &local_types,
                    &module_aliases,
                );
                for assoc in &mut item.associated_consts {
                    qualify_type(&mut assoc.ty, namespace, &local_types, &module_aliases);
                }
                for method in &mut item.methods {
                    for param in &mut method.params {
                        qualify_type(&mut param.ty, namespace, &local_types, &module_aliases);
                    }
                    qualify_type(
                        &mut method.return_type,
                        namespace,
                        &local_types,
                        &module_aliases,
                    );
                }
            }
            ast::Item::Impl(item) => {
                qualify_generic_params(
                    &mut item.generics,
                    namespace,
                    &local_types,
                    &module_aliases,
                );
                if let Some(trait_name) = &mut item.trait_name {
                    *trait_name = super::super::text::qualify_type_name(
                        trait_name,
                        namespace,
                        &local_types,
                        &module_aliases,
                    );
                }
                qualify_type(&mut item.for_type, namespace, &local_types, &module_aliases);
                for (_, ty) in &mut item.associated_types {
                    qualify_type(ty, namespace, &local_types, &module_aliases);
                }
                for assoc in &mut item.associated_consts {
                    qualify_type(&mut assoc.ty, namespace, &local_types, &module_aliases);
                    qualify_expr(
                        &mut assoc.value,
                        namespace,
                        &local_functions,
                        &local_types,
                        &module_aliases,
                    );
                }
                for method in &mut item.methods {
                    qualify_method(
                        method,
                        namespace,
                        &local_functions,
                        &local_types,
                        &module_aliases,
                    );
                }
            }
        }
    }

    super::super::alias::qualify_imports_for_cross_module_resolution(
        module,
        namespace,
        &module_aliases,
    );
}

pub(crate) fn qualify_function(
    function: &mut ast::Function,
    namespace: &str,
    local_functions: &HashSet<String>,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    function.name = super::super::text::qualify_name(namespace, &function.name);
    qualify_function_signature(function, namespace, local_types, module_aliases);
    for stmt in &mut function.body {
        qualify_stmt(
            stmt,
            namespace,
            local_functions,
            local_types,
            module_aliases,
        );
    }
}

pub(crate) fn qualify_method(
    function: &mut ast::Function,
    namespace: &str,
    local_functions: &HashSet<String>,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    qualify_function_signature(function, namespace, local_types, module_aliases);
    for stmt in &mut function.body {
        qualify_stmt(
            stmt,
            namespace,
            local_functions,
            local_types,
            module_aliases,
        );
    }
}

pub(crate) fn qualify_function_signature(
    function: &mut ast::Function,
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    qualify_generic_params(
        &mut function.generics,
        namespace,
        local_types,
        module_aliases,
    );
    for param in &mut function.params {
        qualify_type(&mut param.ty, namespace, local_types, module_aliases);
    }
    qualify_type(
        &mut function.return_type,
        namespace,
        local_types,
        module_aliases,
    );
}
