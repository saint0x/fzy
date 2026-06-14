use super::*;

pub(crate) fn visible_root_module_aliases(
    root_namespace_prefix: &str,
    discovered: &HashMap<PathBuf, DiscoveredModule>,
) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    for discovered_module in discovered.values() {
        let namespace = discovered_module.namespace.as_str();
        if namespace.is_empty() {
            continue;
        }
        if root_namespace_prefix.is_empty() {
            if namespace.contains('.') {
                continue;
            }
            aliases.insert(namespace.to_string(), namespace.to_string());
            continue;
        }
        let Some(suffix) = namespace.strip_prefix(root_namespace_prefix) else {
            continue;
        };
        let Some(name) = suffix.strip_prefix('.') else {
            continue;
        };
        if name.is_empty() || name.contains('.') {
            continue;
        }
        aliases.insert(name.to_string(), namespace.to_string());
    }
    aliases
}

pub(crate) fn import_aliases(
    module: &ast::Module,
    module_aliases: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    for import in &module.imports {
        if import.wildcard || import.path.is_empty() {
            continue;
        }
        let Some(leaf) = import.path.last().cloned() else {
            continue;
        };
        let canonical = canonicalize_import_path(&import.path, module_aliases);
        let alias = import.alias.clone().unwrap_or(leaf);
        aliases.insert(alias, canonical);
    }
    aliases
}

pub(crate) fn canonicalize_import_path(
    path: &[String],
    module_aliases: &HashMap<String, String>,
) -> String {
    let mut segments = path.to_vec();
    if let Some(head) = segments.first_mut() {
        if let Some(replacement) = module_aliases.get(head) {
            *head = replacement.clone();
        }
    }
    segments.join(".")
}

pub(crate) fn expand_wildcard_imports(
    module: &mut ast::Module,
    namespace: &str,
    root_module_aliases: &HashMap<String, String>,
    discovered: &HashMap<PathBuf, DiscoveredModule>,
) -> Result<()> {
    let mut module_aliases = root_module_aliases.clone();
    for module_name in &module.modules {
        module_aliases.insert(
            module_name.clone(),
            super::text::qualify_name(namespace, module_name.as_str()),
        );
    }
    for (alias, target) in import_aliases(module, &module_aliases) {
        module_aliases.insert(alias, target);
    }

    let mut namespace_to_path = HashMap::<String, PathBuf>::new();
    for (path, discovered_module) in discovered {
        namespace_to_path.insert(discovered_module.namespace.clone(), path.clone());
    }

    let mut expanded = Vec::<ast::Import>::new();
    for import in &module.imports {
        if !import.wildcard || import.path.is_empty() {
            continue;
        }
        let canonical = canonicalize_import_path(&import.path, &module_aliases);
        let Some(target_path) = namespace_to_path.get(&canonical) else {
            continue;
        };
        let Some(target_module) = discovered.get(target_path) else {
            continue;
        };
        let target_ast = &target_module.ast;
        let mut seen = HashSet::<String>::new();
        for item in &target_ast.items {
            let Some(name) = (match item {
                ast::Item::Function(function) => Some(function.name.as_str()),
                ast::Item::TypeAlias(item) => Some(item.name.as_str()),
                ast::Item::NewType(item) => Some(item.name.as_str()),
                ast::Item::Struct(item) => Some(item.name.as_str()),
                ast::Item::Enum(item) => Some(item.name.as_str()),
                ast::Item::Trait(item) => Some(item.name.as_str()),
                ast::Item::Const(item) => Some(item.name.as_str()),
                ast::Item::Static(item) => Some(item.name.as_str()),
                _ => None,
            }) else {
                continue;
            };
            if seen.insert(name.to_string()) {
                let mut path = canonical
                    .split('.')
                    .map(|segment| segment.to_string())
                    .collect::<Vec<_>>();
                path.push(name.to_string());
                expanded.push(ast::Import {
                    path,
                    alias: None,
                    wildcard: false,
                    is_pub: import.is_pub,
                });
            }
        }
        for reexport in &target_ast.imports {
            if !reexport.is_pub || reexport.wildcard || reexport.path.is_empty() {
                continue;
            }
            let exposed_name = reexport
                .alias
                .clone()
                .or_else(|| reexport.path.last().cloned())
                .unwrap_or_default();
            if !seen.insert(exposed_name.clone()) {
                continue;
            }
            let mut path = canonical
                .split('.')
                .map(|segment| segment.to_string())
                .collect::<Vec<_>>();
            path.push(exposed_name);
            expanded.push(ast::Import {
                path,
                alias: None,
                wildcard: false,
                is_pub: import.is_pub,
            });
        }
    }

    module.imports.extend(expanded);
    Ok(())
}

pub(crate) fn qualify_imports_for_cross_module_resolution(
    module: &mut ast::Module,
    namespace: &str,
    module_aliases: &HashMap<String, String>,
) {
    for import in &mut module.imports {
        if import.path.is_empty() || import.wildcard {
            continue;
        }
        let exposed_name = import
            .alias
            .clone()
            .or_else(|| import.path.last().cloned())
            .unwrap_or_default();
        let canonical = canonicalize_import_path(&import.path, module_aliases);
        import.path = canonical
            .split('.')
            .map(|segment| segment.to_string())
            .collect();
        if import.is_pub {
            import.alias = Some(super::text::qualify_name(namespace, &exposed_name));
        }
    }
}
