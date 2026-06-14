use super::*;

pub(crate) fn parse_and_qualify_module(
    module_path: &Path,
    discovered: &HashMap<PathBuf, DiscoveredModule>,
) -> Result<(PathBuf, LoadedModule)> {
    let discovered_module = discovered.get(module_path).ok_or_else(|| {
        anyhow!(
            "internal discovered module cache miss for {}",
            module_path.display()
        )
    })?;
    let mut ast = discovered_module.ast.clone();
    let root_module_aliases =
        super::alias::visible_root_module_aliases(&discovered_module.root_namespace_prefix, discovered);
    super::alias::expand_wildcard_imports(
        &mut ast,
        &discovered_module.namespace,
        &root_module_aliases,
        discovered,
    )?;
    super::walk::qualify_module_symbols(&mut ast, &discovered_module.namespace, &root_module_aliases);
    ast.modules.clear();
    Ok((
        module_path.to_path_buf(),
        LoadedModule {
            source_fingerprint: sha256_hex(discovered_module.source.as_bytes()),
            namespace: discovered_module.namespace.clone(),
            ast,
            source: discovered_module.source.clone(),
        },
    ))
}

pub(crate) fn module_interface_fingerprint(module: &ast::Module) -> Result<String> {
    let mut summary = module.clone();
    for item in &mut summary.items {
        match item {
            ast::Item::Function(function) => function.body.clear(),
            ast::Item::Impl(item) => {
                for method in &mut item.methods {
                    method.body.clear();
                }
            }
            ast::Item::Const(_) | ast::Item::Static(_) => {}
            ast::Item::Test(test) => test.body.clear(),
            ast::Item::TypeAlias(_)
            | ast::Item::NewType(_)
            | ast::Item::Struct(_)
            | ast::Item::Enum(_)
            | ast::Item::Trait(_) => {}
        }
    }
    Ok(sha256_hex(format!("{summary:#?}").as_bytes()))
}

pub(crate) fn module_namespace_with_prefix(
    root_source: &Path,
    module_path: &Path,
    namespace_prefix: &str,
) -> Result<String> {
    if module_path == root_source {
        return Ok(namespace_prefix.to_string());
    }
    let root_dir = root_source.parent().ok_or_else(|| {
        anyhow!(
            "root source has no parent directory: {}",
            root_source.display()
        )
    })?;
    let relative = module_path
        .strip_prefix(root_dir)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| module_path.to_path_buf());
    let mut components = relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .map(|component| component.to_string())
        .collect::<Vec<_>>();
    if components.is_empty() {
        return Ok(String::new());
    }
    let tail = components.pop().unwrap_or_default();
    let stem = Path::new(&tail)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !stem.is_empty() && stem != "mod" {
        components.push(stem.to_string());
    }
    let suffix = components.join(".");
    if namespace_prefix.is_empty() {
        return Ok(suffix);
    }
    if suffix.is_empty() {
        return Ok(namespace_prefix.to_string());
    }
    Ok(format!("{namespace_prefix}.{suffix}"))
}
