use super::*;

pub(crate) fn parse_program_uncached_with_root_source(
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
    let global_interface_fingerprint = sha256_hex(interface_fingerprints.join("\n").as_bytes());
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

pub(crate) fn read_module_source(
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

pub(crate) fn module_stamp(path: &Path) -> Option<ModuleStamp> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let modified_ns = modified.duration_since(UNIX_EPOCH).ok()?.as_nanos();
    Some(ModuleStamp {
        path: path.to_path_buf(),
        bytes: meta.len(),
        modified_ns,
    })
}

pub(crate) fn cached_parsed_program(canonical: &Path) -> Option<Arc<ParsedProgram>> {
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

pub(crate) fn module_stamp_matches(stamp: &ModuleStamp) -> bool {
    module_stamp(&stamp.path).is_some_and(|current| {
        current.bytes == stamp.bytes && current.modified_ns == stamp.modified_ns
    })
}

pub(crate) fn store_parsed_program_cache(canonical: &Path, parsed: Arc<ParsedProgram>) {
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
pub(crate) struct LoadedModule {
    pub(crate) ast: ast::Module,
    pub(crate) source: String,
    pub(crate) namespace: String,
    pub(crate) source_fingerprint: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ParseRoot {
    source_path: PathBuf,
    namespace_prefix: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ParseProjectContext {
    roots: Vec<ParseRoot>,
    extra_stamp_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub(crate) struct DiscoveredModule {
    pub(crate) source: String,
    pub(crate) ast: ast::Module,
    pub(crate) namespace: String,
    pub(crate) root_namespace_prefix: String,
}

#[derive(Debug, Default)]
pub(crate) struct ModuleLoadState {
    discovered: HashMap<PathBuf, DiscoveredModule>,
    loaded: HashMap<PathBuf, LoadedModule>,
    load_order: Vec<PathBuf>,
    visiting: Vec<PathBuf>,
    visiting_set: HashSet<PathBuf>,
}

pub(crate) fn parse_project_context_for_source(
    source_path: &Path,
) -> Result<Option<ParseProjectContext>> {
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
        let resolution = match dependency {
            manifest::Dependency::Framework { .. } | manifest::Dependency::Path { .. } => {
                resolve_local_dependency(&project_root, alias, dependency)?
            }
            manifest::Dependency::Version { .. } | manifest::Dependency::Git { .. } => continue,
        };
        let dep_root = resolution.root;
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
                        "failed resolving library target for dependency `{}` at {}",
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

pub(crate) fn find_project_root_for_source(source_path: &Path) -> Option<PathBuf> {
    let mut cursor = source_path.parent().map(Path::to_path_buf);
    while let Some(current) = cursor {
        if load_manifest_for_parse(&current).is_ok() {
            return Some(current);
        }
        cursor = current.parent().map(Path::to_path_buf);
    }
    None
}

pub(crate) fn load_manifest_for_parse(dir: &Path) -> Result<manifest::Manifest> {
    let primary = dir.join("fozzy.toml");
    let contents = std::fs::read_to_string(&primary)
        .with_context(|| format!("no valid compiler manifest found at {}", primary.display()))?;
    if !manifest::looks_like_compiler_manifest(&contents) {
        bail!("no valid compiler manifest found at {}", primary.display());
    }
    let mut parsed = manifest::load(&contents).context("failed parsing fozzy.toml")?;
    apply_workspace_policy(dir, &mut parsed)?;
    parsed.infer_default_targets(dir);
    parsed
        .validate()
        .map_err(|err| anyhow!("invalid fozzy.toml: {err}"))?;
    validate_dependency_paths(dir, &parsed)?;
    Ok(parsed)
}

pub(crate) fn discover_module_graph_recursive(
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
