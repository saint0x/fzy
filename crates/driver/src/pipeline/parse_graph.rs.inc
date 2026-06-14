fn parse_program_uncached_with_root_source(
    canonical: &Path,
    root_source_override: Option<&str>,
    parse_context: Option<&ParseProjectContext>,
) -> Result<ParsedProgram> {
    let mut state = ModuleLoadState::default();
    let mut cache_paths = Vec::<PathBuf>::new();
    if let Some(context) = parse_context {
        for root in &context.roots {
            discover_module_graph_recursive(
                &root.source_path,
                &root.source_path,
                if root.source_path == canonical {
                    root_source_override
                } else {
                    None
                },
                &root.namespace_prefix,
                &mut state,
            )?;
        }
        cache_paths.extend(context.extra_stamp_paths.iter().cloned());
    } else {
        discover_module_graph_recursive(
            canonical,
            canonical,
            root_source_override,
            "",
            &mut state,
        )?;
    }

    let loaded_modules = state
        .load_order
        .par_iter()
        .map(|path| parse_and_qualify_module(path, &state.discovered))
        .collect::<Result<Vec<_>>>()?;
    state.loaded = loaded_modules.into_iter().collect();

    let mut fingerprint = Sha256::new();
    let mut interface_fingerprints = Vec::with_capacity(state.load_order.len());
    let mut input_bytes = 0usize;
    let mut module_sources = Vec::with_capacity(state.load_order.len());
    let mut qualified_modules = Vec::with_capacity(state.load_order.len());
    for path in &state.load_order {
        let loaded = state
            .loaded
            .get(path)
            .ok_or_else(|| anyhow!("internal module cache miss for {}", path.display()))?;
        fingerprint.update(path.to_string_lossy().as_bytes());
        fingerprint.update([0]);
        fingerprint.update(loaded.source.as_bytes());
        fingerprint.update([0xff]);
        input_bytes += "// module: ".len() + path.display().to_string().len() + 1;
        input_bytes += loaded.source.len();
        if !loaded.source.ends_with('\n') {
            input_bytes += 1;
        }
        module_sources.push(ModuleSourceText {
            path: path.clone(),
            source: Arc::<str>::from(loaded.source.as_str()),
        });
        interface_fingerprints.push(module_interface_fingerprint(&loaded.ast)?);
        qualified_modules.push(QualifiedModuleUnit {
            path: path.clone(),
            namespace: loaded.namespace.clone(),
            ast: loaded.ast.clone(),
            source_fingerprint: loaded.source_fingerprint.clone(),
        });
    }
    interface_fingerprints.sort();
    let global_interface_fingerprint =
        sha256_hex(interface_fingerprints.join("\n").as_bytes());
    let mut merged = state
        .loaded
        .remove(canonical)
        .map(|module| module.ast)
        .ok_or_else(|| anyhow!("failed to load root module {}", canonical.display()))?;
    for path in &state.load_order {
        if path == canonical {
            continue;
        }
        let loaded = state
            .loaded
            .remove(path)
            .ok_or_else(|| anyhow!("internal module cache miss for {}", path.display()))?;
        merge_module_owned(&mut merged, loaded.ast);
    }
    merge_imported_core_stdlib_modules(&mut merged)?;
    canonicalize_call_targets(&mut merged);
    cache_paths.extend(state.load_order.iter().cloned());
    cache_paths.sort();
    cache_paths.dedup();
    Ok(ParsedProgram {
        module: merged,
        module_paths: state.load_order,
        cache_paths: Arc::new(cache_paths),
        module_fingerprint: format!("{:x}", fingerprint.finalize()),
        global_interface_fingerprint,
        input_bytes,
        module_sources: Arc::new(module_sources),
        qualified_modules: Arc::new(qualified_modules),
        combined_source: OnceLock::new(),
    })
}

fn read_module_source(
    canonical: &Path,
    root_path: &Path,
    root_source_override: Option<&str>,
) -> Result<String> {
    if canonical == root_path {
        if let Some(source_override) = root_source_override {
            return Ok(source_override.to_string());
        }
    }
    std::fs::read_to_string(canonical)
        .with_context(|| format!("failed reading source file: {}", canonical.display()))
}

fn module_stamp(path: &Path) -> Option<ModuleStamp> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let modified_ns = modified.duration_since(UNIX_EPOCH).ok()?.as_nanos();
    Some(ModuleStamp {
        path: path.to_path_buf(),
        bytes: meta.len(),
        modified_ns,
    })
}

fn cached_parsed_program(canonical: &Path) -> Option<Arc<ParsedProgram>> {
    let cache = PARSED_PROGRAM_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    let entry = {
        let guard = cache.read().ok()?;
        guard.get(canonical).cloned()?
    };
    if entry.stamps.par_iter().all(module_stamp_matches) {
        return Some(Arc::clone(&entry.parsed));
    }
    None
}

fn module_stamp_matches(stamp: &ModuleStamp) -> bool {
    module_stamp(&stamp.path).is_some_and(|current| {
        current.bytes == stamp.bytes && current.modified_ns == stamp.modified_ns
    })
}

fn store_parsed_program_cache(canonical: &Path, parsed: Arc<ParsedProgram>) {
    let stamps = parsed
        .cache_paths
        .iter()
        .filter_map(|path| module_stamp(path))
        .collect::<Vec<_>>();
    let cache = PARSED_PROGRAM_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(mut guard) = cache.write() {
        guard.insert(
            canonical.to_path_buf(),
            ParsedProgramCacheEntry { parsed, stamps },
        );
    }
}

#[derive(Debug, Clone)]
struct LoadedModule {
    ast: ast::Module,
    source: String,
    namespace: String,
    source_fingerprint: String,
}

#[derive(Debug, Clone)]
struct ParseRoot {
    source_path: PathBuf,
    namespace_prefix: String,
}

#[derive(Debug, Clone)]
struct ParseProjectContext {
    roots: Vec<ParseRoot>,
    extra_stamp_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct DiscoveredModule {
    source: String,
    ast: ast::Module,
    namespace: String,
    root_namespace_prefix: String,
}

#[derive(Debug, Default)]
struct ModuleLoadState {
    discovered: HashMap<PathBuf, DiscoveredModule>,
    loaded: HashMap<PathBuf, LoadedModule>,
    load_order: Vec<PathBuf>,
    visiting: Vec<PathBuf>,
    visiting_set: HashSet<PathBuf>,
}

fn parse_project_context_for_source(source_path: &Path) -> Result<Option<ParseProjectContext>> {
    let Some(project_root) = find_project_root_for_source(source_path) else {
        return Ok(None);
    };
    let manifest = load_manifest_for_parse(&project_root)?;
    let mut roots = vec![ParseRoot {
        source_path: source_path.to_path_buf(),
        namespace_prefix: String::new(),
    }];
    let mut extra_stamp_paths = vec![project_root.join("fozzy.toml")];
    for (alias, dependency) in &manifest.deps {
        let manifest::Dependency::Path { path } = dependency else {
            continue;
        };
        let dep_root = project_root.join(path).canonicalize().with_context(|| {
            format!(
                "failed resolving path dependency `{}` from {}",
                alias,
                project_root.display()
            )
        })?;
        let dep_manifest = load_manifest_for_parse(&dep_root)?;
        let Some(lib_target) = dep_manifest.target.lib.as_ref() else {
            continue;
        };
        roots.push(ParseRoot {
            source_path: dep_root
                .join(&lib_target.path)
                .canonicalize()
                .with_context(|| {
                    format!(
                        "failed resolving library target for path dependency `{}` at {}",
                        alias,
                        dep_root.display()
                    )
                })?,
            namespace_prefix: alias.clone(),
        });
        extra_stamp_paths.push(dep_root.join("fozzy.toml"));
    }
    Ok(Some(ParseProjectContext {
        roots,
        extra_stamp_paths,
    }))
}

fn find_project_root_for_source(source_path: &Path) -> Option<PathBuf> {
    let mut cursor = source_path.parent().map(Path::to_path_buf);
    while let Some(current) = cursor {
        if load_manifest_for_parse(&current).is_ok() {
            return Some(current);
        }
        cursor = current.parent().map(Path::to_path_buf);
    }
    None
}

fn load_manifest_for_parse(dir: &Path) -> Result<manifest::Manifest> {
    let primary = dir.join("fozzy.toml");
    let contents = std::fs::read_to_string(&primary)
        .with_context(|| format!("no valid compiler manifest found at {}", primary.display()))?;
    let mut parsed = manifest::load(&contents).context("failed parsing fozzy.toml")?;
    apply_workspace_policy(dir, &mut parsed)?;
    parsed.infer_default_targets(dir);
    parsed
        .validate()
        .map_err(|err| anyhow!("invalid fozzy.toml: {err}"))?;
    validate_dependency_paths(dir, &parsed)?;
    Ok(parsed)
}

fn discover_module_graph_recursive(
    path: &Path,
    root_path: &Path,
    root_source_override: Option<&str>,
    namespace_prefix: &str,
    state: &mut ModuleLoadState,
) -> Result<()> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed resolving module path: {}", path.display()))?;
    if state.discovered.contains_key(&canonical) {
        return Ok(());
    }
    if state.visiting_set.contains(&canonical) {
        let cycle = format_module_cycle(&state.visiting, &canonical);
        return Err(anyhow!("cyclic module declaration detected: {}", cycle));
    }

    state.visiting_set.insert(canonical.clone());
    state.visiting.push(canonical.clone());

    let source = read_module_source(&canonical, root_path, root_source_override)?;
    let module_name = canonical
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", canonical.display()))?;
    let ast = parser::parse(&source, module_name)
        .map_err(|diagnostics| anyhow!(render_parse_failure(&canonical, &diagnostics)))?;

    let base_dir = canonical
        .parent()
        .ok_or_else(|| anyhow!("module has no parent directory: {}", canonical.display()))?;
    for module_decl in &ast.modules {
        let module_path = resolve_declared_module(base_dir, module_decl).with_context(|| {
            format!(
                "while resolving module `{}` from {}",
                module_decl,
                canonical.display()
            )
        })?;
        discover_module_graph_recursive(
            &module_path,
            root_path,
            root_source_override,
            namespace_prefix,
            state,
        )?;
    }

    state.visiting.pop();
    state.visiting_set.remove(&canonical);
    state.load_order.push(canonical.clone());
    let namespace = module_namespace_with_prefix(root_path, &canonical, namespace_prefix)?;
    state.discovered.insert(
        canonical,
        DiscoveredModule {
            source,
            namespace,
            root_namespace_prefix: namespace_prefix.to_string(),
            ast,
        },
    );
    Ok(())
}

fn parse_and_qualify_module(
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
        visible_root_module_aliases(&discovered_module.root_namespace_prefix, discovered);
    expand_wildcard_imports(
        &mut ast,
        &discovered_module.namespace,
        &root_module_aliases,
        discovered,
    )?;
    qualify_module_symbols(&mut ast, &discovered_module.namespace, &root_module_aliases);
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

fn module_interface_fingerprint(module: &ast::Module) -> Result<String> {
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

fn module_namespace_with_prefix(
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

fn expand_wildcard_imports(
    module: &mut ast::Module,
    namespace: &str,
    root_module_aliases: &HashMap<String, String>,
    discovered: &HashMap<PathBuf, DiscoveredModule>,
) -> Result<()> {
    let mut module_aliases = root_module_aliases.clone();
    for module_name in &module.modules {
        module_aliases.insert(
            module_name.clone(),
            qualify_name(namespace, module_name.as_str()),
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

fn qualify_module_symbols(
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
            qualify_name(namespace, module_name.as_str()),
        );
    }
    for (alias, target) in import_aliases(module, &module_aliases) {
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
                item.name = qualify_name(namespace, &item.name);
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
                item.name = qualify_name(namespace, &item.name);
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
                item.name = qualify_name(namespace, &item.name);
                qualify_type(&mut item.ty, namespace, &local_types, &module_aliases);
            }
            ast::Item::NewType(item) => {
                item.name = qualify_name(namespace, &item.name);
                qualify_type(&mut item.inner, namespace, &local_types, &module_aliases);
            }
            ast::Item::Struct(item) => {
                item.name = qualify_name(namespace, &item.name);
                for field in &mut item.fields {
                    qualify_type(&mut field.ty, namespace, &local_types, &module_aliases);
                }
            }
            ast::Item::Enum(item) => {
                item.name = qualify_name(namespace, &item.name);
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
                item.name = qualify_name(namespace, &item.name);
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
                    *trait_name =
                        qualify_type_name(trait_name, namespace, &local_types, &module_aliases);
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

    qualify_imports_for_cross_module_resolution(module, namespace, &module_aliases);
}

fn visible_root_module_aliases(
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

fn import_aliases(
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

fn canonicalize_import_path(path: &[String], module_aliases: &HashMap<String, String>) -> String {
    let mut segments = path.to_vec();
    if let Some(head) = segments.first_mut() {
        if let Some(replacement) = module_aliases.get(head) {
            *head = replacement.clone();
        }
    }
    segments.join(".")
}

fn qualify_imports_for_cross_module_resolution(
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
            import.alias = Some(qualify_name(namespace, &exposed_name));
        }
    }
}

fn qualify_function(
    function: &mut ast::Function,
    namespace: &str,
    local_functions: &HashSet<String>,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    function.name = qualify_name(namespace, &function.name);
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

fn qualify_method(
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

fn qualify_function_signature(
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

fn qualify_stmt(
    stmt: &mut ast::Stmt,
    namespace: &str,
    local_functions: &HashSet<String>,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match stmt {
        ast::Stmt::Let { ty, value, .. } => {
            if let Some(ty) = ty {
                qualify_type(ty, namespace, local_types, module_aliases);
            }
            qualify_expr(
                value,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            )
        }
        ast::Stmt::LetPattern {
            pattern, ty, value, ..
        } => {
            qualify_pattern(pattern, namespace, local_types, module_aliases);
            if let Some(ty) = ty {
                qualify_type(ty, namespace, local_types, module_aliases);
            }
            qualify_expr(
                value,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            )
        }
        ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => qualify_expr(
            value,
            namespace,
            local_functions,
            local_types,
            module_aliases,
        ),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                qualify_expr(
                    value,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            qualify_expr(
                condition,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for nested in then_body {
                qualify_stmt(
                    nested,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
            for nested in else_body {
                qualify_stmt(
                    nested,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            qualify_expr(
                condition,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for nested in body {
                qualify_stmt(
                    nested,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                qualify_stmt(
                    init,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
            if let Some(condition) = condition {
                qualify_expr(
                    condition,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
            if let Some(step) = step {
                qualify_stmt(
                    step,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
            for nested in body {
                qualify_stmt(
                    nested,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            qualify_expr(
                iterable,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for nested in body {
                qualify_stmt(
                    nested,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                qualify_stmt(
                    nested,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            qualify_expr(
                scrutinee,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for arm in arms {
                qualify_pattern(&mut arm.pattern, namespace, local_types, module_aliases);
                if let Some(guard) = &mut arm.guard {
                    qualify_expr(
                        guard,
                        namespace,
                        local_functions,
                        local_types,
                        module_aliases,
                    );
                }
                qualify_expr(
                    &mut arm.value,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
    }
}

fn qualify_expr(
    expr: &mut ast::Expr,
    namespace: &str,
    local_functions: &HashSet<String>,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            *callee = qualify_callee(
                callee,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for arg in args {
                qualify_expr(arg, namespace, local_functions, local_types, module_aliases);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            qualify_expr(
                base,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::StructInit { name, fields } => {
            *name = qualify_type_name(name, namespace, local_types, module_aliases);
            for (_, value) in fields {
                qualify_expr(
                    value,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::EnumInit {
            enum_name,
            payload,
            named_payload,
            ..
        } => {
            *enum_name = qualify_type_name(enum_name, namespace, local_types, module_aliases);
            for value in payload {
                qualify_expr(
                    value,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
            for (_, value) in named_payload {
                qualify_expr(
                    value,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            qualify_expr(
                body,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::Group(inner) => {
            qualify_expr(
                inner,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::Tuple(items) => {
            for item in items {
                qualify_expr(
                    item,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            qualify_expr(
                inner,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            qualify_expr(
                try_expr,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            qualify_expr(
                catch_expr,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            qualify_expr(
                condition,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            qualify_expr(
                then_expr,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            qualify_expr(
                else_expr,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::Match { scrutinee, arms } => {
            qualify_expr(
                scrutinee,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for arm in arms {
                qualify_pattern(&mut arm.pattern, namespace, local_types, module_aliases);
                if let Some(guard) = &mut arm.guard {
                    qualify_expr(
                        guard,
                        namespace,
                        local_functions,
                        local_types,
                        module_aliases,
                    );
                }
                qualify_expr(
                    &mut arm.value,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::While { condition, body } => {
            qualify_expr(
                condition,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for stmt in body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                qualify_stmt(
                    init,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
            if let Some(condition) = condition {
                qualify_expr(
                    condition,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
            if let Some(step) = step {
                qualify_stmt(
                    step,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
            for stmt in body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            qualify_expr(
                iterable,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for stmt in body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::Loop { body } => {
            for stmt in body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::Break(value) | ast::Expr::Return(value) => {
            if let Some(value) = value {
                qualify_expr(
                    value,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::Continue => {}
        ast::Expr::Range { start, end, .. } => {
            qualify_expr(
                start,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            qualify_expr(end, namespace, local_functions, local_types, module_aliases);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                qualify_expr(
                    item,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                qualify_expr(
                    value,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::Index { base, index } => {
            qualify_expr(
                base,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            qualify_expr(
                index,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::Unary { expr, .. } => {
            qualify_expr(
                expr,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            qualify_expr(
                left,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            qualify_expr(
                right,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
    }
}

fn qualify_pattern(
    pattern: &mut ast::Pattern,
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match pattern {
        ast::Pattern::Tuple(items) | ast::Pattern::Or(items) => {
            for item in items {
                qualify_pattern(item, namespace, local_types, module_aliases);
            }
        }
        ast::Pattern::Struct { name, .. } => {
            *name = qualify_type_name(name, namespace, local_types, module_aliases);
        }
        ast::Pattern::Variant { enum_name, .. } => {
            *enum_name = qualify_type_name(enum_name, namespace, local_types, module_aliases);
        }
        ast::Pattern::Wildcard
        | ast::Pattern::Ident(_)
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_) => {}
    }
}

fn qualify_generic_params(
    generics: &mut [ast::GenericParam],
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    for generic in generics {
        for bound in &mut generic.bounds {
            *bound = qualify_type_name(bound, namespace, local_types, module_aliases);
        }
    }
}

fn qualify_type(
    ty: &mut ast::Type,
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match ty {
        ast::Type::Ptr { to, .. } | ast::Type::Ref { to, .. } => {
            qualify_type(to, namespace, local_types, module_aliases)
        }
        ast::Type::Slice(inner)
        | ast::Type::Set(inner)
        | ast::Type::Deque(inner)
        | ast::Type::Ring(inner)
        | ast::Type::Option(inner)
        | ast::Type::Vec(inner)
        | ast::Type::Future(inner) => qualify_type(inner, namespace, local_types, module_aliases),
        ast::Type::Array { elem, .. } => qualify_type(elem, namespace, local_types, module_aliases),
        ast::Type::Result { ok, err } => {
            qualify_type(ok, namespace, local_types, module_aliases);
            qualify_type(err, namespace, local_types, module_aliases);
        }
        ast::Type::Map { key, value } => {
            qualify_type(key, namespace, local_types, module_aliases);
            qualify_type(value, namespace, local_types, module_aliases);
        }
        ast::Type::Function { params, ret } => {
            for param in params {
                qualify_type(param, namespace, local_types, module_aliases);
            }
            qualify_type(ret, namespace, local_types, module_aliases);
        }
        ast::Type::DynTrait(name) => {
            *name = qualify_type_name(name, namespace, local_types, module_aliases);
        }
        ast::Type::Tuple(items) => {
            for item in items {
                qualify_type(item, namespace, local_types, module_aliases);
            }
        }
        ast::Type::Named { name, args } => {
            *name = qualify_type_name(name, namespace, local_types, module_aliases);
            for arg in args {
                qualify_type(arg, namespace, local_types, module_aliases);
            }
        }
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
        | ast::Type::SimdVector(_)
        | ast::Type::SimdMask(_)
        | ast::Type::TypeVar(_) => {}
    }
}

fn qualify_type_name(
    name: &str,
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) -> String {
    if let Some(exact_alias) = module_aliases.get(name) {
        exact_alias.clone()
    } else if let Some((head, tail)) = name.split_once('.') {
        if let Some(qualified_head) = module_aliases.get(head) {
            format!("{qualified_head}.{tail}")
        } else {
            name.to_string()
        }
    } else if local_types.contains(name) {
        qualify_name(namespace, name)
    } else {
        name.to_string()
    }
}

fn qualify_callee(
    callee: &str,
    namespace: &str,
    local_functions: &HashSet<String>,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) -> String {
    let (base, generic_suffix) = split_generic_suffix(callee);
    let qualified_base = if let Some(exact_alias) = module_aliases.get(base) {
        exact_alias.clone()
    } else if let Some((head, tail)) = base.split_once('.') {
        if let Some(qualified_head) = module_aliases.get(head) {
            format!("{qualified_head}.{tail}")
        } else if local_types.contains(head) {
            format!("{}.{tail}", qualify_name(namespace, head))
        } else {
            base.to_string()
        }
    } else if local_functions.contains(base) {
        qualify_name(namespace, base)
    } else {
        base.to_string()
    };
    let qualified_suffix =
        qualify_generic_suffix(generic_suffix, namespace, local_types, module_aliases);
    format!("{qualified_base}{qualified_suffix}")
}

fn split_generic_suffix(callee: &str) -> (&str, &str) {
    if let Some(index) = callee.find('<') {
        (&callee[..index], &callee[index..])
    } else {
        (callee, "")
    }
}

fn qualify_generic_suffix(
    suffix: &str,
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) -> String {
    if suffix.is_empty() {
        return String::new();
    }
    let Some(inner) = suffix
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
    else {
        return suffix.to_string();
    };
    let Some(parts) = split_top_level_segments(inner) else {
        return suffix.to_string();
    };
    let qualified = parts
        .into_iter()
        .map(|part| qualify_type_expr_text(part, namespace, local_types, module_aliases))
        .collect::<Vec<_>>()
        .join(", ");
    format!("<{qualified}>")
}

fn qualify_type_expr_text(
    text: &str,
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) -> String {
    let text = text.trim();
    if text.is_empty() {
        return text.to_string();
    }
    if let Some(stripped) = text.strip_prefix("dyn ") {
        let inner = qualify_type_expr_text(stripped, namespace, local_types, module_aliases);
        return format!("dyn {inner}");
    }
    for prefix in ["*mut ", "*", "&mut ", "&", "[]"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            let inner = qualify_type_expr_text(rest, namespace, local_types, module_aliases);
            return format!("{prefix}{inner}");
        }
    }
    if let Some(inner) = text
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
    {
        if let Some(parts) = split_top_level_segments(inner) {
            let qualified = parts
                .into_iter()
                .map(|part| qualify_type_expr_text(part, namespace, local_types, module_aliases))
                .collect::<Vec<_>>()
                .join(", ");
            return format!("({qualified})");
        }
    }
    if let Some(inner) = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        if let Some((elem, len)) = split_array_type_expr(inner) {
            let elem = qualify_type_expr_text(elem, namespace, local_types, module_aliases);
            return format!("[{elem}; {}]", len.trim());
        }
    }
    if let Some(start) = text.find('<') {
        if text.ends_with('>') {
            let name = text[..start].trim();
            let inner = &text[start + 1..text.len() - 1];
            if let Some(parts) = split_top_level_segments(inner) {
                let qualified_name =
                    qualify_type_name(name, namespace, local_types, module_aliases);
                let qualified_args = parts
                    .into_iter()
                    .map(|part| {
                        qualify_type_expr_text(part, namespace, local_types, module_aliases)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                return format!("{qualified_name}<{qualified_args}>");
            }
        }
    }
    qualify_type_name(text, namespace, local_types, module_aliases)
}

fn split_top_level_segments(input: &str) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    let mut depth_angle = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_paren = 0usize;
    let mut start = 0usize;
    for (idx, ch) in input.char_indices() {
        match ch {
            '<' => depth_angle += 1,
            '>' => {
                if depth_angle == 0 {
                    return None;
                }
                depth_angle -= 1;
            }
            '[' => depth_bracket += 1,
            ']' => {
                if depth_bracket == 0 {
                    return None;
                }
                depth_bracket -= 1;
            }
            '(' => depth_paren += 1,
            ')' => {
                if depth_paren == 0 {
                    return None;
                }
                depth_paren -= 1;
            }
            ',' if depth_angle == 0 && depth_bracket == 0 && depth_paren == 0 => {
                out.push(input[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    if depth_angle != 0 || depth_bracket != 0 || depth_paren != 0 {
        return None;
    }
    out.push(input[start..].trim());
    Some(out)
}

fn split_array_type_expr(input: &str) -> Option<(&str, &str)> {
    let mut depth_angle = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_paren = 0usize;
    for (idx, ch) in input.char_indices() {
        match ch {
            '<' => depth_angle += 1,
            '>' => {
                if depth_angle == 0 {
                    return None;
                }
                depth_angle -= 1;
            }
            '[' => depth_bracket += 1,
            ']' => {
                if depth_bracket == 0 {
                    return None;
                }
                depth_bracket -= 1;
            }
            '(' => depth_paren += 1,
            ')' => {
                if depth_paren == 0 {
                    return None;
                }
                depth_paren -= 1;
            }
            ';' if depth_angle == 0 && depth_bracket == 0 && depth_paren == 0 => {
                return Some((input[..idx].trim(), input[idx + 1..].trim()));
            }
            _ => {}
        }
    }
    None
}

fn qualify_name(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

fn canonicalize_call_targets(module: &mut ast::Module) {
    let known_functions = collect_defined_function_names(module);
    let known_values = collect_defined_value_names(module);
    let reexported_functions = collect_reexported_function_aliases(module);
    for item in &mut module.items {
        if let ast::Item::Function(function) = item {
            let namespace = function
                .name
                .rsplit_once('.')
                .map(|(prefix, _)| prefix)
                .unwrap_or("");
            for stmt in &mut function.body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    &known_functions,
                    &known_values,
                    &reexported_functions,
                );
            }
        }
    }
}

fn collect_defined_function_names(module: &ast::Module) -> HashSet<String> {
    let mut out = HashSet::<String>::new();
    for item in &module.items {
        match item {
            ast::Item::Function(function) => {
                out.insert(function.name.clone());
            }
            ast::Item::Impl(item) => {
                let receiver = item.for_type.to_string();
                for method in &item.methods {
                    out.insert(format!("{receiver}.{}", method.name));
                }
            }
            _ => {}
        }
    }
    out
}

fn collect_reexported_function_aliases(module: &ast::Module) -> HashMap<String, String> {
    let known_functions = collect_defined_function_names(module);
    let mut out = HashMap::new();
    for import in &module.imports {
        if !import.is_pub || import.wildcard || import.path.is_empty() {
            continue;
        }
        let canonical = import.path.join(".");
        if !known_functions.contains(&canonical) {
            continue;
        }
        let alias = import.alias.clone().unwrap_or_else(|| {
            import
                .path
                .last()
                .cloned()
                .unwrap_or_else(|| canonical.clone())
        });
        out.insert(alias, canonical);
    }
    out
}

fn collect_defined_value_names(module: &ast::Module) -> HashSet<String> {
    let mut out = HashSet::<String>::new();
    for item in &module.items {
        match item {
            ast::Item::Const(item) => {
                out.insert(item.name.clone());
            }
            ast::Item::Static(item) => {
                out.insert(item.name.clone());
            }
            _ => {}
        }
    }
    out
}

fn canonicalize_stmt_calls(
    stmt: &mut ast::Stmt,
    namespace: &str,
    known_functions: &HashSet<String>,
    known_values: &HashSet<String>,
    reexported_functions: &HashMap<String, String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => canonicalize_expr_calls(
            value,
            namespace,
            known_functions,
            known_values,
            reexported_functions,
        ),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                canonicalize_expr_calls(
                    value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            canonicalize_expr_calls(
                condition,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for nested in then_body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            for nested in else_body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            canonicalize_expr_calls(
                condition,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for nested in body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                canonicalize_stmt_calls(
                    init,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            if let Some(condition) = condition {
                canonicalize_expr_calls(
                    condition,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            if let Some(step) = step {
                canonicalize_stmt_calls(
                    step,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            for nested in body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            canonicalize_expr_calls(
                iterable,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for nested in body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            canonicalize_expr_calls(
                scrutinee,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for arm in arms {
                if let Some(guard) = &mut arm.guard {
                    canonicalize_expr_calls(
                        guard,
                        namespace,
                        known_functions,
                        known_values,
                        reexported_functions,
                    );
                }
                canonicalize_expr_calls(
                    &mut arm.value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
    }
}

fn canonicalize_expr_calls(
    expr: &mut ast::Expr,
    namespace: &str,
    known_functions: &HashSet<String>,
    known_values: &HashSet<String>,
    reexported_functions: &HashMap<String, String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            *callee = canonicalize_callee(callee, namespace, known_functions, reexported_functions);
            if matches!(
                callee.as_str(),
                "spawn" | "thread.spawn" | "spawn_ctx" | "thread.spawn_ctx" | "task.group_spawn"
            ) {
                if let Some(task_ref) = args.first_mut() {
                    canonicalize_task_ref_expr(
                        task_ref,
                        namespace,
                        known_functions,
                        reexported_functions,
                    );
                }
            }
            for arg in args {
                canonicalize_expr_calls(
                    arg,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            canonicalize_expr_calls(
                base,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            if let Some(value_ref) = expr_path_name(expr) {
                let canonical = canonicalize_value_ref(&value_ref, namespace, known_values);
                if canonical != value_ref {
                    *expr = ast::Expr::Ident(canonical);
                }
            }
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                canonicalize_expr_calls(
                    value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                canonicalize_expr_calls(
                    value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            canonicalize_expr_calls(
                body,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Group(inner) => {
            canonicalize_expr_calls(
                inner,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Tuple(items) => {
            for item in items {
                canonicalize_expr_calls(
                    item,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            canonicalize_expr_calls(
                inner,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            canonicalize_expr_calls(
                try_expr,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                catch_expr,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            canonicalize_expr_calls(
                condition,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                then_expr,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                else_expr,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Match { scrutinee, arms } => {
            canonicalize_expr_calls(
                scrutinee,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for arm in arms {
                if let Some(guard) = &mut arm.guard {
                    canonicalize_expr_calls(
                        guard,
                        namespace,
                        known_functions,
                        known_values,
                        reexported_functions,
                    );
                }
                canonicalize_expr_calls(
                    &mut arm.value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::While { condition, body } => {
            canonicalize_expr_calls(
                condition,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for stmt in body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                canonicalize_stmt_calls(
                    init,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            if let Some(condition) = condition {
                canonicalize_expr_calls(
                    condition,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            if let Some(step) = step {
                canonicalize_stmt_calls(
                    step,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            for stmt in body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            canonicalize_expr_calls(
                iterable,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for stmt in body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Loop { body } => {
            for stmt in body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Break(value) | ast::Expr::Return(value) => {
            if let Some(value) = value {
                canonicalize_expr_calls(
                    value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Continue => {}
        ast::Expr::Range { start, end, .. } => {
            canonicalize_expr_calls(
                start,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                end,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                canonicalize_expr_calls(
                    item,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                canonicalize_expr_calls(
                    value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Index { base, index } => {
            canonicalize_expr_calls(
                base,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                index,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Unary { expr, .. } => {
            canonicalize_expr_calls(
                expr,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            canonicalize_expr_calls(
                left,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                right,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
    }
}

fn expr_path_name(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => Some(name.clone()),
        ast::Expr::Group(inner) => expr_path_name(inner),
        ast::Expr::FieldAccess { base, field } => {
            let mut base_name = expr_path_name(base)?;
            base_name.push('.');
            base_name.push_str(field);
            Some(base_name)
        }
        _ => None,
    }
}

fn canonicalize_value_ref(
    value_ref: &str,
    namespace: &str,
    known_values: &HashSet<String>,
) -> String {
    if known_values.contains(value_ref) {
        return value_ref.to_string();
    }
    if value_ref.contains('.') {
        let mut scope = Some(namespace);
        while let Some(current) = scope {
            if !current.is_empty() {
                let candidate = format!("{current}.{value_ref}");
                if known_values.contains(&candidate) {
                    return candidate;
                }
            }
            scope = current.rsplit_once('.').map(|(parent, _)| parent);
        }
    } else {
        let candidate = qualify_name(namespace, value_ref);
        if known_values.contains(&candidate) {
            return candidate;
        }
    }
    value_ref.to_string()
}

fn canonicalize_callee(
    callee: &str,
    namespace: &str,
    known_functions: &HashSet<String>,
    reexported_functions: &HashMap<String, String>,
) -> String {
    let (base, generic_suffix) = split_generic_suffix(callee);
    if let Some(target) = reexported_functions.get(base) {
        return format!("{target}{generic_suffix}");
    }
    if known_functions.contains(base) {
        return callee.to_string();
    }
    if base.contains('.') {
        let mut scope = Some(namespace);
        while let Some(current) = scope {
            if !current.is_empty() {
                let candidate = format!("{current}.{base}");
                if known_functions.contains(&candidate) {
                    return format!("{candidate}{generic_suffix}");
                }
            }
            scope = current.rsplit_once('.').map(|(parent, _)| parent);
        }
    } else {
        let candidate = qualify_name(namespace, base);
        if known_functions.contains(&candidate) {
            return format!("{candidate}{generic_suffix}");
        }
    }
    callee.to_string()
}

fn canonicalize_task_ref_expr(
    expr: &mut ast::Expr,
    namespace: &str,
    known_functions: &HashSet<String>,
    reexported_functions: &HashMap<String, String>,
) {
    let Some(task_ref) = expr_task_ref_name(expr) else {
        return;
    };
    let canonical =
        canonicalize_callee(&task_ref, namespace, known_functions, reexported_functions);
    if canonical == task_ref {
        return;
    }
    *expr = task_ref_expr_from_name(&canonical);
}

fn task_ref_expr_from_name(name: &str) -> ast::Expr {
    let mut segments = name.split('.');
    let head = segments.next().unwrap_or_default().to_string();
    let mut expr = ast::Expr::Ident(head);
    for segment in segments {
        expr = ast::Expr::FieldAccess {
            base: Box::new(expr),
            field: segment.to_string(),
        };
    }
    expr
}

fn collect_parse_diagnostics_with_root_source(
    source_path: &Path,
    root_source_override: Option<&str>,
) -> Result<Vec<diagnostics::Diagnostic>> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    let mut visited = HashSet::<PathBuf>::new();
    let mut visiting = HashSet::<PathBuf>::new();
    match collect_parse_diagnostics_recursive(
        &canonical,
        &canonical,
        root_source_override,
        &mut visited,
        &mut visiting,
    )? {
        Some((failed_path, import_chain, diagnostics)) => Ok(diagnostics
            .into_iter()
            .map(|diagnostic| annotate_parse_diagnostic(diagnostic, &failed_path, &import_chain))
            .collect()),
        None => Ok(Vec::new()),
    }
}

type ParseDiagnosticsHit = (PathBuf, Vec<PathBuf>, Vec<diagnostics::Diagnostic>);

fn collect_parse_diagnostics_recursive(
    path: &Path,
    root_path: &Path,
    root_source_override: Option<&str>,
    visited: &mut HashSet<PathBuf>,
    visiting: &mut HashSet<PathBuf>,
) -> Result<Option<ParseDiagnosticsHit>> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed resolving module path: {}", path.display()))?;
    if visited.contains(&canonical) || visiting.contains(&canonical) {
        return Ok(None);
    }
    visiting.insert(canonical.clone());
    let source = read_module_source(&canonical, root_path, root_source_override)?;
    let module_name = canonical
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", canonical.display()))?;
    let ast = match parser::parse(&source, module_name) {
        Ok(ast) => ast,
        Err(diagnostics) => {
            return Ok(Some((
                canonical.clone(),
                vec![canonical.clone()],
                diagnostics,
            )))
        }
    };
    visited.insert(canonical.clone());

    let base_dir = canonical
        .parent()
        .ok_or_else(|| anyhow!("module has no parent directory: {}", canonical.display()))?;
    for module_decl in &ast.modules {
        let module_path = resolve_declared_module(base_dir, module_decl).with_context(|| {
            format!(
                "while resolving module `{}` from {}",
                module_decl,
                canonical.display()
            )
        })?;
        if let Some((failed_path, mut import_chain, diagnostics)) =
            collect_parse_diagnostics_recursive(
                &module_path,
                root_path,
                root_source_override,
                visited,
                visiting,
            )?
        {
            import_chain.insert(0, canonical.clone());
            return Ok(Some((failed_path, import_chain, diagnostics)));
        }
    }
    visiting.remove(&canonical);
    Ok(None)
}

fn annotate_parse_diagnostic(
    mut diagnostic: diagnostics::Diagnostic,
    module_path: &Path,
    import_chain: &[PathBuf],
) -> diagnostics::Diagnostic {
    diagnostic.path = Some(module_path.display().to_string());
    diagnostic
        .notes
        .push(format!("source: {}", module_path.display()));
    if import_chain.len() > 1 {
        let chain = import_chain
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(" -> ");
        diagnostic.notes.push(format!("import chain: {chain}"));
    }
    diagnostic
}

fn render_parse_failure(path: &Path, diagnostics: &[diagnostics::Diagnostic]) -> String {
    let mut summary = format!(
        "parse failed for {} with {} diagnostics",
        path.display(),
        diagnostics.len()
    );
    if diagnostics.is_empty() {
        return summary;
    }
    let details = diagnostics
        .iter()
        .map(|diagnostic| {
            if let Some(span) = &diagnostic.span {
                format!(
                    "{}:{}-{}:{} {}",
                    span.start_line,
                    span.start_col,
                    span.end_line,
                    span.end_col,
                    diagnostic.message
                )
            } else {
                diagnostic.message.clone()
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    summary.push_str(": ");
    summary.push_str(&details);
    summary
}

fn enrich_diagnostics_context(diagnostics: &mut [diagnostics::Diagnostic]) {
    let mut source_cache = HashMap::<String, Vec<String>>::new();
    for diagnostic in diagnostics {
        if let Some(path) = &diagnostic.path {
            let lines = if let Some(lines) = source_cache.get(path) {
                lines
            } else if let Ok(source) = std::fs::read_to_string(path) {
                source_cache.insert(
                    path.clone(),
                    source.lines().map(ToString::to_string).collect::<Vec<_>>(),
                );
                source_cache
                    .get(path)
                    .expect("inserted path is retrievable")
            } else {
                continue;
            };
            if let Some(span) = &diagnostic.span {
                if span.start_line > 0
                    && span.start_line <= lines.len()
                    && diagnostic.snippet.is_none()
                {
                    diagnostic.snippet = Some(lines[span.start_line - 1].clone());
                }
                if diagnostic.labels.is_empty() {
                    diagnostic.labels.push(diagnostics::Label {
                        message: diagnostic.message.clone(),
                        primary: true,
                        span: Some(span.clone()),
                    });
                }
            } else if let Some(anchors) =
                derive_context_anchors_from_message(&diagnostic.message, lines)
            {
                if let Some((primary_token, primary_span)) = anchors.first() {
                    diagnostic.span = Some(primary_span.clone());
                    diagnostic.snippet = Some(lines[primary_span.start_line - 1].clone());
                    diagnostic.labels.push(diagnostics::Label {
                        message: format!("while analyzing `{primary_token}`"),
                        primary: true,
                        span: Some(primary_span.clone()),
                    });
                }
                for (token, span) in anchors.iter().skip(1) {
                    diagnostic.labels.push(diagnostics::Label {
                        message: format!("related context `{token}`"),
                        primary: false,
                        span: Some(span.clone()),
                    });
                }
                diagnostic.notes.push(
                    "source anchors derived from diagnostic evidence when explicit semantic spans are unavailable"
                        .to_string(),
                );
            }
        }
    }
}

fn derive_context_anchors_from_message(
    message: &str,
    lines: &[String],
) -> Option<Vec<(String, diagnostics::Span)>> {
    if message.contains("non-exhaustive match for enum `") {
        if let Some(span) = find_token_span(lines, "match") {
            return Some(vec![("match".to_string(), span)]);
        }
    }
    derive_anchors_from_message(message, lines)
}

fn derive_anchors_from_message(
    message: &str,
    lines: &[String],
) -> Option<Vec<(String, diagnostics::Span)>> {
    let quoted = extract_backticked_tokens(message);
    let mut out = Vec::new();
    for token in quoted {
        if token.trim().is_empty() {
            continue;
        }
        if let Some(span) = find_token_span(lines, &token) {
            out.push((token, span));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_backticked_tokens(message: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (idx, ch) in message.char_indices() {
        if ch == '`' {
            if let Some(open) = start.take() {
                if idx > open + 1 {
                    out.push(message[open + 1..idx].to_string());
                }
            } else {
                start = Some(idx);
            }
        }
    }
    out
}

fn find_token_span(lines: &[String], token: &str) -> Option<diagnostics::Span> {
    for (line_idx, line) in lines.iter().enumerate() {
        for (col_idx, _) in line.match_indices(token) {
            if !token_boundary_matches(line, col_idx, token.len()) {
                continue;
            }
            return Some(diagnostics::Span {
                start_line: line_idx + 1,
                start_col: col_idx + 1,
                end_line: line_idx + 1,
                end_col: col_idx + token.len().max(1),
            });
        }
    }
    None
}

fn token_boundary_matches(line: &str, start: usize, len: usize) -> bool {
    let token = &line[start..start.saturating_add(len)];
    if !token.chars().all(is_ident_char) {
        return true;
    }
    let end = start.saturating_add(len);
    let left = line[..start].chars().next_back();
    let right = line[end..].chars().next();
    !(left.is_some_and(is_ident_char) || right.is_some_and(is_ident_char))
}

fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn resolve_declared_module(base_dir: &Path, module_decl: &str) -> Result<PathBuf> {
    let normalized = module_decl.trim().replace("::", "/");
    if normalized.is_empty() {
        return Err(anyhow!("empty module declaration"));
    }
    if normalized
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '/'))
    {
        return Err(anyhow!(
            "invalid module declaration `{}` (allowed: [A-Za-z0-9_::])",
            module_decl
        ));
    }

    let file_candidate = base_dir.join(format!("{normalized}.fzy"));
    if file_candidate.is_file() {
        return Ok(file_candidate);
    }
    let mod_candidate = base_dir.join(&normalized).join("mod.fzy");
    if mod_candidate.is_file() {
        return Ok(mod_candidate);
    }
    Err(anyhow!(
        "module `{}` not found; expected {} or {}",
        module_decl,
        file_candidate.display(),
        mod_candidate.display()
    ))
}

fn merge_module_owned(root: &mut ast::Module, mut module: ast::Module) {
    root.items.append(&mut module.items);
    root.modules.append(&mut module.modules);
    root.imports.append(&mut module.imports);
    root.capabilities.append(&mut module.capabilities);
    root.host_syscall_sites += module.host_syscall_sites;
    root.unsafe_reasoned_sites += module.unsafe_reasoned_sites;
}

fn merge_imported_core_stdlib_modules(root: &mut ast::Module) -> Result<()> {
    let imported = root
        .imports
        .iter()
        .filter_map(|import| {
            if import.path.len() == 1 {
                embedded_core_stdlib_module_source(import.path[0].as_str())
                    .map(|source| (import.path[0].clone(), source))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let mut merged_names = HashSet::<String>::new();
    for (module_name, source) in imported {
        if !merged_names.insert(module_name.clone()) {
            continue;
        }
        let mut module = parser::parse(source, &module_name).map_err(|diagnostics| {
            anyhow!(
                "{}",
                format_embedded_stdlib_parse_failure(&module_name, source, &diagnostics)
            )
        })?;
        if matches!(module_name.as_str(), "log" | "thread" | "http")
            && !module.capabilities.iter().any(|cap| cap == &module_name)
        {
            module.capabilities.push(module_name.clone());
        }
        qualify_module_symbols(&mut module, &module_name, &HashMap::new());
        merge_module_owned(root, module);
    }
    Ok(())
}

fn format_embedded_stdlib_parse_failure(
    module_name: &str,
    source: &str,
    diagnostics: &[diagnostics::Diagnostic],
) -> String {
    let mut lines = vec![format!(
        "failed parsing embedded core stdlib module `{module_name}` during `parse-embedded-stdlib`"
    )];
    if diagnostics.is_empty() {
        lines.push("  error: unknown parse failure".to_string());
        return lines.join("\n");
    }
    let virtual_path = format!("<embedded-core-stdlib:{module_name}>");
    for diagnostic in diagnostics {
        let code = diagnostic.code.as_deref().unwrap_or("E-PAR-UNKNOWN");
        lines.push(format!("  error[{code}]: {}", diagnostic.message));
        if let Some(span) = &diagnostic.span {
            lines.push(format!(
                "    at {virtual_path}:{}:{}",
                span.start_line, span.start_col
            ));
            if let Some(snippet) = embedded_stdlib_snippet(source, span.start_line) {
                lines.push(format!("    snippet: {snippet}"));
            }
        }
        if let Some(help) = &diagnostic.help {
            lines.push(format!("    help: {help}"));
        }
        for note in &diagnostic.notes {
            lines.push(format!("    note: {note}"));
        }
    }
    lines.join("\n")
}

fn embedded_stdlib_snippet(source: &str, line: usize) -> Option<String> {
    source
        .lines()
        .nth(line.saturating_sub(1))
        .map(|snippet| snippet.trim_end().to_string())
}

#[cfg(test)]
mod embedded_stdlib_dx_tests {
    use super::format_embedded_stdlib_parse_failure;

    #[test]
    fn embedded_stdlib_parse_failure_includes_phase_span_and_help() {
        let diagnostics = vec![diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            "unexpected token in expression",
            Some("finish the current expression".to_string()),
        )
        .with_code("E-PAR-12345678")
        .with_span(2, 9, 2, 10)];
        let rendered = format_embedded_stdlib_parse_failure(
            "process",
            "fn ok() -> i32 {\n    let x = )\n}\n",
            &diagnostics,
        );
        assert!(rendered.contains("parse-embedded-stdlib"));
        assert!(rendered.contains("<embedded-core-stdlib:process>:2:9"));
        assert!(rendered.contains("snippet:     let x = )"));
        assert!(rendered.contains("help: finish the current expression"));
    }
}

pub(crate) fn embedded_core_stdlib_module_source(module_name: &str) -> Option<&'static str> {
    match module_name {
        "concurrency" => Some(include_str!("../../../../core/src/concurrency.fzy")),
        "process" => Some(include_str!("../../../../core/src/process.fzy")),
        "term" => Some(include_str!("../../../../core/src/term.fzy")),
        "thread" => Some(include_str!("../../../../core/src/thread.fzy")),
        "log" => Some(include_str!("../../../../core/src/log.fzy")),
        "mem" => Some(include_str!("../../../../core/src/mem.fzy")),
        "security" => Some(include_str!("../../../../core/src/security.fzy")),
        "result" => Some(include_str!("../../../../core/src/result.fzy")),
        "simd" => Some(include_str!("../../../../core/src/simd.fzy")),
        "text" => Some(include_str!("../../../../core/src/text.fzy")),
        "io" => Some(include_str!("../../../../core/src/io.fzy")),
        "http" => Some(include_str!("../../../../core/src/http.fzy")),
        _ => None,
    }
}

fn format_module_cycle(stack: &[PathBuf], repeated: &Path) -> String {
    if let Some(start) = stack.iter().position(|entry| entry == repeated) {
        let mut parts = stack[start..]
            .iter()
            .map(|entry| entry.display().to_string())
            .collect::<Vec<_>>();
        parts.push(repeated.display().to_string());
        return parts.join(" -> ");
    }
    repeated.display().to_string()
}
