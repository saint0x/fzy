struct ResolvedSource {
    source_path: PathBuf,
    project_root: PathBuf,
    manifest: Option<manifest::Manifest>,
    manifest_fingerprint: Option<String>,
    dependency_graph_hash: Option<String>,
    artifact_stem: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WorkspacePolicyFile {
    #[serde(default)]
    policy: WorkspacePolicySection,
    #[serde(default)]
    packages: HashMap<String, WorkspacePolicySection>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WorkspacePolicySection {
    language_tier: Option<String>,
    allow_experimental: Option<bool>,
    unsafe_enforce_verify: Option<bool>,
    unsafe_enforce_release: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockfileMode {
    ValidateOrCreate,
    ForceRewrite,
}

fn resolve_source_path(input: &Path) -> Result<ResolvedSource> {
    resolve_source_path_with_target(input, false)
}

fn resolve_source_path_with_target(
    input: &Path,
    prefer_lib_target: bool,
) -> Result<ResolvedSource> {
    if input.is_file() {
        if !is_supported_source_file(input) {
            bail!(
                "expected a `.fzy` source file or a project directory, got file: {}",
                input.display()
            );
        }
        let root = input
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(ResolvedSource {
            source_path: input.to_path_buf(),
            project_root: root,
            manifest: None,
            manifest_fingerprint: None,
            dependency_graph_hash: None,
            artifact_stem: input
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("main")
                .to_string(),
        });
    }
    if !input.is_dir() {
        return Err(anyhow!(
            "path is neither a source file nor a project directory: {}",
            input.display()
        ));
    }

    let (manifest, manifest_path, dependency_graph_hash) =
        load_manifest(input, LockfileMode::ValidateOrCreate)?;

    let relative = if prefer_lib_target {
        manifest
            .target
            .lib
            .as_ref()
            .map(|lib| lib.path.as_str())
            .or_else(|| manifest.primary_bin_path())
            .ok_or_else(|| {
                anyhow!(
                    "no [target.lib] or [[target.bin]] entry in {}",
                    manifest_path.display()
                )
            })?
    } else {
        manifest
            .primary_bin_path()
            .ok_or_else(|| anyhow!("no [[target.bin]] entry in {}", manifest_path.display()))?
    };
    let artifact_stem = if prefer_lib_target {
        manifest
            .target
            .lib
            .as_ref()
            .map(|lib| lib.name.as_str())
            .or_else(|| manifest.primary_bin_name())
            .unwrap_or("main")
            .to_string()
    } else {
        manifest.primary_bin_name().unwrap_or("main").to_string()
    };
    Ok(ResolvedSource {
        source_path: input.join(relative),
        project_root: input.to_path_buf(),
        manifest_fingerprint: Some(manifest_fingerprint(&manifest)?),
        manifest: Some(manifest),
        dependency_graph_hash: Some(dependency_graph_hash),
        artifact_stem,
    })
}

fn load_manifest(
    dir: &Path,
    lock_mode: LockfileMode,
) -> Result<(manifest::Manifest, std::path::PathBuf, String)> {
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
    let graph_hash = write_lockfile(dir, &parsed, &contents, lock_mode)?;
    Ok((parsed, primary, graph_hash))
}

fn manifest_fingerprint(manifest: &manifest::Manifest) -> Result<String> {
    let bytes = serde_json::to_vec(manifest)
        .map_err(|error| anyhow!("failed serializing manifest fingerprint: {error}"))?;
    Ok(sha256_hex(&bytes))
}

fn apply_workspace_policy(dir: &Path, manifest: &mut manifest::Manifest) -> Result<()> {
    let Some((_, policy)) = load_workspace_policy(dir)? else {
        return Ok(());
    };
    let mut merged = policy.policy.clone();
    if let Some(package_override) = policy.packages.get(&manifest.package.name) {
        if package_override.language_tier.is_some() {
            merged.language_tier = package_override.language_tier.clone();
        }
        if package_override.allow_experimental.is_some() {
            merged.allow_experimental = package_override.allow_experimental;
        }
        if package_override.unsafe_enforce_verify.is_some() {
            merged.unsafe_enforce_verify = package_override.unsafe_enforce_verify;
        }
        if package_override.unsafe_enforce_release.is_some() {
            merged.unsafe_enforce_release = package_override.unsafe_enforce_release;
        }
    }

    if let Some(tier) = merged.language_tier {
        manifest.language.tier = tier;
    }
    if let Some(allow) = merged.allow_experimental {
        manifest.language.allow_experimental = allow;
    }
    if let Some(value) = merged.unsafe_enforce_verify {
        manifest.unsafe_policy.enforce_verify = Some(value);
    }
    if let Some(value) = merged.unsafe_enforce_release {
        manifest.unsafe_policy.enforce_release = Some(value);
    }
    Ok(())
}

fn load_workspace_policy(dir: &Path) -> Result<Option<(PathBuf, WorkspacePolicyFile)>> {
    let mut cursor = Some(dir.to_path_buf());
    while let Some(current) = cursor {
        let candidate = current.join("fozzy.workspace.toml");
        if candidate.exists() {
            let text = std::fs::read_to_string(&candidate)
                .with_context(|| format!("failed reading {}", candidate.display()))?;
            let parsed: WorkspacePolicyFile = toml::from_str(&text)
                .with_context(|| format!("failed parsing {}", candidate.display()))?;
            return Ok(Some((candidate, parsed)));
        }
        cursor = current.parent().map(Path::to_path_buf);
    }
    Ok(None)
}

fn validate_dependency_paths(dir: &Path, manifest: &manifest::Manifest) -> Result<()> {
    for (name, dependency) in &manifest.deps {
        if let manifest::Dependency::Path { path } = dependency {
            let resolved = dir.join(path);
            if !resolved.exists() {
                return Err(anyhow!(
                    "path dependency `{}` not found at {}",
                    name,
                    resolved.display()
                ));
            }
        }
    }
    Ok(())
}

pub fn refresh_lockfile(dir: &Path) -> Result<String> {
    let (_, _, graph_hash) = load_manifest(dir, LockfileMode::ForceRewrite)?;
    Ok(graph_hash)
}

fn write_lockfile(
    dir: &Path,
    manifest: &manifest::Manifest,
    root_manifest_contents: &str,
    mode: LockfileMode,
) -> Result<String> {
    let root_manifest_hash = sha256_hex(root_manifest_contents.as_bytes());
    let graph = build_dependency_graph(dir, manifest, &root_manifest_hash)?;
    let graph_bytes = serde_json::to_vec(&graph)?;
    let graph_hash = sha256_hex(&graph_bytes);
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.lock.v0",
        "dependencyGraphHash": graph_hash,
        "graph": graph,
    });
    let lock_path = dir.join("fozzy.lock");
    let should_write = match mode {
        LockfileMode::ForceRewrite => true,
        LockfileMode::ValidateOrCreate => {
            if !lock_path.exists() {
                true
            } else {
                let existing_text = std::fs::read_to_string(&lock_path)
                    .with_context(|| format!("failed reading lockfile: {}", lock_path.display()))?;
                let existing_json: serde_json::Value = serde_json::from_str(&existing_text)
                    .with_context(|| format!("failed parsing lockfile: {}", lock_path.display()))?;
                let existing_hash = existing_json
                    .get("dependencyGraphHash")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                let existing_graph = existing_json.get("graph").cloned().unwrap_or_default();
                let existing_schema = existing_json
                    .get("schemaVersion")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                if existing_schema == "fozzylang.lock.v0"
                    && existing_hash == graph_hash
                    && existing_graph == graph
                {
                    false
                } else {
                    true
                }
            }
        }
    };
    if should_write {
        std::fs::write(&lock_path, serde_json::to_vec_pretty(&payload)?)
            .with_context(|| format!("failed writing lockfile: {}", lock_path.display()))?;
    }
    Ok(graph_hash)
}

fn build_dependency_graph(
    dir: &Path,
    manifest: &manifest::Manifest,
    root_manifest_hash: &str,
) -> Result<serde_json::Value> {
    let mut dep_entries = Vec::new();
    for (name, dependency) in &manifest.deps {
        match dependency {
            manifest::Dependency::Path { path } => {
                let resolved = dir.join(path);
                let canonical = resolved.canonicalize().with_context(|| {
                    format!(
                        "failed canonicalizing path dependency `{}` at {}",
                        name,
                        resolved.display()
                    )
                })?;
                let dep_state = dependency_source_state(&canonical).with_context(|| {
                    format!(
                        "failed loading cached dependency state for `{}` at {}",
                        name,
                        canonical.display()
                    )
                })?;
                dep_entries.push(serde_json::json!({
                    "name": name,
                    "sourceType": "path",
                    "path": normalize_rel_path(path),
                    "canonicalPath": canonical.display().to_string(),
                    "package": {
                        "name": dep_state.package_name,
                        "version": dep_state.package_version,
                    },
                    "manifestHash": dep_state.manifest_hash,
                    "sourceHash": dep_state.source_hash,
                }));
            }
            manifest::Dependency::Version { version, source } => {
                let source_locator = source
                    .clone()
                    .unwrap_or_else(|| "registry+https://crates.io".to_string());
                let source_hash =
                    sha256_hex(format!("version:{name}:{version}:{source_locator}").as_bytes());
                dep_entries.push(serde_json::json!({
                    "name": name,
                    "sourceType": "version",
                    "version": version,
                    "source": source_locator,
                    "sourceHash": source_hash,
                }));
            }
            manifest::Dependency::Git { git, rev } => {
                let source_hash = sha256_hex(format!("git:{name}:{git}:{rev}").as_bytes());
                dep_entries.push(serde_json::json!({
                    "name": name,
                    "sourceType": "git",
                    "git": git,
                    "rev": rev,
                    "sourceHash": source_hash,
                }));
            }
        }
    }
    Ok(serde_json::json!({
        "package": {
            "name": manifest.package.name,
            "version": manifest.package.version,
            "manifestHash": root_manifest_hash,
        },
        "deps": dep_entries,
    }))
}

fn normalize_rel_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn hash_stamped_files(root: &Path, files: &[ModuleStamp]) -> Result<String> {
    let mut hasher = Sha256::new();
    for stamp in files {
        let rel = stamp.path.strip_prefix(root).with_context(|| {
            format!("failed deriving relative path for {}", stamp.path.display())
        })?;
        let rel = normalize_rel_path(&rel.display().to_string());
        hasher.update(rel.as_bytes());
        let bytes = std::fs::read(&stamp.path).with_context(|| {
            format!(
                "failed reading dependency file for hashing: {}",
                stamp.path.display()
            )
        })?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

fn collect_file_stamps(root: &Path) -> Result<Vec<ModuleStamp>> {
    let mut files = Vec::new();
    collect_files_recursive(root, root, &mut files)?;
    Ok(files)
}

fn collect_files_recursive(root: &Path, current: &Path, out: &mut Vec<ModuleStamp>) -> Result<()> {
    let mut entries = std::fs::read_dir(current)
        .with_context(|| format!("failed reading dependency directory: {}", current.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed iterating dependency directory: {}",
                current.display()
            )
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let full = entry.path();
        let rel = full
            .strip_prefix(root)
            .with_context(|| format!("failed deriving relative path for {}", full.display()))?;
        let rel_str = normalize_rel_path(&rel.display().to_string());
        if should_skip_hash_path(&rel_str) {
            continue;
        }
        if entry
            .file_type()
            .with_context(|| format!("failed reading file type for {}", full.display()))?
            .is_dir()
        {
            collect_files_recursive(root, &full, out)?;
        } else {
            let Some(stamp) = module_stamp(&full) else {
                continue;
            };
            out.push(stamp);
        }
    }
    Ok(())
}

fn dependency_source_state(canonical: &Path) -> Result<DependencySourceCacheEntry> {
    let manifest_path = canonical.join("fozzy.toml");
    let manifest_stamp = module_stamp(&manifest_path).ok_or_else(|| {
        anyhow!(
            "path dependency manifest missing at {}",
            manifest_path.display()
        )
    })?;
    let current_stamps = collect_file_stamps(canonical)?;
    let cache = DEPENDENCY_SOURCE_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(guard) = cache.read() {
        if let Some(cached) = guard.get(canonical) {
            if cached.manifest_stamp == manifest_stamp && cached.source_stamps == current_stamps {
                return Ok(cached.clone());
            }
        }
    }

    let dep_manifest_text = std::fs::read_to_string(&manifest_path).with_context(|| {
        format!(
            "path dependency manifest missing at {}",
            manifest_path.display()
        )
    })?;
    let dep_manifest = manifest::load(&dep_manifest_text).with_context(|| {
        format!(
            "failed parsing dependency manifest at {}",
            manifest_path.display()
        )
    })?;
    dep_manifest.validate().map_err(|err| {
        anyhow!(
            "invalid dependency manifest at {}: {}",
            manifest_path.display(),
            err
        )
    })?;
    let entry = DependencySourceCacheEntry {
        manifest_stamp,
        manifest_hash: sha256_hex(dep_manifest_text.as_bytes()),
        package_name: dep_manifest.package.name,
        package_version: dep_manifest.package.version,
        source_hash: hash_stamped_files(canonical, &current_stamps)?,
        source_stamps: current_stamps,
    };
    if let Ok(mut guard) = cache.write() {
        guard.insert(canonical.to_path_buf(), entry.clone());
    }
    Ok(entry)
}

fn should_skip_hash_path(rel: &str) -> bool {
    rel.starts_with(".git/")
        || rel.starts_with(".fz/")
        || rel.starts_with("vendor/")
        || rel.starts_with("target/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize().as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn native_artifact_cache_marker(
    build_dir: &Path,
    artifact_stem: &str,
    kind: &str,
    backend: &str,
) -> PathBuf {
    build_dir.join(format!("{artifact_stem}.{kind}.{backend}.cachekey"))
}

fn read_native_artifact_cache_key(marker: &Path) -> Option<String> {
    std::fs::read_to_string(marker)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn write_native_artifact_cache_key(marker: &Path, key: &str) -> Result<()> {
    std::fs::write(marker, key).with_context(|| {
        format!(
            "failed writing native artifact cache marker: {}",
            marker.display()
        )
    })
}

fn native_artifact_cache_hit(marker: &Path, key: &str, outputs: &[&Path]) -> bool {
    outputs.iter().all(|output| output.exists())
        && read_native_artifact_cache_key(marker).as_deref() == Some(key)
}

fn native_artifact_cache_key(
    kind: &str,
    backend: &str,
    artifact_stem: &str,
    profile: BuildProfile,
    fir: &fir::FirModule,
    manifest: Option<&manifest::Manifest>,
    runtime_shim_path: &Path,
    extra: &[&[u8]],
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(backend.as_bytes());
    hasher.update(artifact_stem.as_bytes());
    hasher.update(format!("{profile:?}").as_bytes());
    hasher.update(format!("{fir:?}").as_bytes());
    let manifest_bytes = match manifest {
        Some(manifest) => serde_json::to_vec(manifest).map_err(|error| {
            anyhow!("failed serializing manifest for native cache key: {error}")
        })?,
        None => Vec::new(),
    };
    hasher.update(&manifest_bytes);
    let runtime_shim = std::fs::read(runtime_shim_path).with_context(|| {
        format!(
            "failed reading runtime shim for native cache key: {}",
            runtime_shim_path.display()
        )
    })?;
    hasher.update(&runtime_shim);
    for bytes in extra {
        hasher.update(bytes);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

fn successful_build_cache_path(
    build_dir: &Path,
    artifact_stem: &str,
    kind: &str,
    backend: &str,
) -> PathBuf {
    build_dir.join(format!("{artifact_stem}.{kind}.{backend}.buildcache.json"))
}

fn pgo_signature(pgo: &PgoConfig) -> String {
    format!(
        "generate={};use={}",
        pgo.generate_dir
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        pgo.use_profile
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    )
}

fn successful_build_cache_hit(
    entry: &SuccessfulBuildCacheEntry,
    resolved: &ResolvedSource,
    profile: BuildProfile,
    backend: &str,
    pgo: &PgoConfig,
) -> bool {
    entry.schema_version == "fozzylang.buildcache.v1"
        && entry.source_path == resolved.source_path
        && entry.profile == profile.as_str()
        && entry.backend == backend
        && entry.manifest_fingerprint == resolved.manifest_fingerprint
        && entry.dependency_graph_hash == resolved.dependency_graph_hash
        && entry.pgo_signature == pgo_signature(pgo)
        && entry.source_stamps.par_iter().all(module_stamp_matches)
}

fn read_successful_build_cache(path: &Path) -> Option<SuccessfulBuildCacheEntry> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_successful_build_cache(
    path: &Path,
    entry: &SuccessfulBuildCacheEntry,
) -> Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(entry)?)
        .with_context(|| format!("failed writing successful build cache: {}", path.display()))
}

fn runtime_shim_language_arg(fir: &fir::FirModule) -> &'static str {
    if native_runtime_shim_uses_objc(fir) {
        "objective-c"
    } else {
        "c"
    }
}

fn apply_gpu_backend_link_args(cmd: &mut Command, fir: &fir::FirModule) {
    if cfg!(target_vendor = "apple") && fir_module_uses_gpu(fir) {
        cmd.arg("-framework").arg("Metal");
        cmd.arg("-framework").arg("Foundation");
    }
}
