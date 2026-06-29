use super::*;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    bytes: u64,
    modified_ns: u128,
}

#[derive(Debug, Clone)]
struct ManifestCacheEntry {
    stamp: FileStamp,
    manifest: manifest::Manifest,
}

#[derive(Debug, Clone)]
struct ModuleSetCacheEntry {
    root: PathBuf,
    stamps: Vec<(PathBuf, FileStamp)>,
    module_set: ResolvedModuleSet,
}

static MANIFEST_CACHE: OnceLock<RwLock<HashMap<PathBuf, ManifestCacheEntry>>> = OnceLock::new();
static MODULE_SET_CACHE: OnceLock<RwLock<HashMap<PathBuf, ModuleSetCacheEntry>>> = OnceLock::new();

#[derive(Debug, Clone)]
pub(super) struct ResolvedSource {
    pub(super) source_path: PathBuf,
    pub(super) project_root: PathBuf,
    pub(super) manifest: Option<manifest::Manifest>,
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedModuleSource {
    pub(super) path: PathBuf,
    pub(super) module_name: String,
    pub(super) source: String,
    pub(super) ast: ast::Module,
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedModuleSet {
    pub(super) resolved: ResolvedSource,
    pub(super) modules: Vec<ResolvedModuleSource>,
}

pub(super) fn resolve_source(path: &Path) -> Result<ResolvedSource> {
    if path.is_file() {
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(ResolvedSource {
            source_path: path.to_path_buf(),
            project_root: root,
            manifest: None,
        });
    }
    if !path.is_dir() {
        bail!(
            "path is neither a source file nor a project directory: {}",
            path.display()
        );
    }
    let manifest_path = path.join("fozzy.toml");
    let manifest = match load_cached_project_manifest(path) {
        Ok(manifest) => manifest,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|err| err.kind() == std::io::ErrorKind::NotFound) =>
        {
            let suggestions = discover_nested_project_roots(path);
            let guidance = if suggestions.is_empty() {
                format!(
                    "directory `{}` is not a Fozzy project root (missing {}). initialize a project here with `fz init [path]` or run the command against a project directory/file explicitly",
                    path.display(),
                    manifest_path.display()
                )
            } else {
                format!(
                    "directory `{}` is not a Fozzy project root (missing {}). detected nested project(s): {}. run `fz audit unsafe <project-path>` for one of those roots",
                    path.display(),
                    manifest_path.display(),
                    suggestions
                        .iter()
                        .map(|candidate| candidate.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            bail!(guidance);
        }
        Err(error)
            if error
                .to_string()
                .contains("no valid compiler manifest found") =>
        {
            let guidance = format!(
                "directory `{}` is not a Fozzy project root ({} is scenario/runtime config, not a compiler manifest). run the command against a real project root or a `.fzy` file explicitly",
                path.display(),
                manifest_path.display()
            );
            bail!(guidance);
        }
        Err(error) => return Err(error),
    };
    let relative = manifest
        .target
        .lib
        .as_ref()
        .map(|lib| lib.path.as_str())
        .or_else(|| manifest.primary_bin_path())
        .ok_or_else(|| {
            anyhow!(
                "no [target.lib] or [[target.bin]] entry in {} for source resolution",
                manifest_path.display()
            )
        })?;
    Ok(ResolvedSource {
        source_path: path.join(relative),
        project_root: path.to_path_buf(),
        manifest: Some(manifest),
    })
}

fn load_cached_project_manifest(path: &Path) -> Result<manifest::Manifest> {
    let manifest_path = path.join("fozzy.toml");
    let stamp = file_stamp(&manifest_path)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let cache = MANIFEST_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(guard) = cache.read() {
        if let Some(entry) = guard.get(&manifest_path) {
            if entry.stamp == stamp {
                return Ok(entry.manifest.clone());
            }
        }
    }
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed reading manifest: {}", manifest_path.display()))?;
    if !manifest::looks_like_compiler_manifest(&manifest_text) {
        bail!(
            "no valid compiler manifest found at {}",
            manifest_path.display()
        );
    }
    let mut manifest = manifest::load(&manifest_text).context("failed parsing fozzy.toml")?;
    manifest.infer_default_targets(path);
    manifest
        .validate()
        .map_err(|error| anyhow!("invalid fozzy.toml: {error}"))?;
    if let Ok(mut guard) = cache.write() {
        guard.insert(
            manifest_path,
            ManifestCacheEntry {
                stamp,
                manifest: manifest.clone(),
            },
        );
    }
    Ok(manifest)
}

pub(super) fn discover_nested_project_roots(path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(path) else {
        return out;
    };
    for entry in entries.flatten() {
        let candidate = entry.path();
        if !candidate.is_dir() {
            continue;
        }
        if is_valid_project_root(&candidate) {
            out.push(candidate);
        }
    }
    out.sort();
    out
}

pub(super) fn discover_project_roots(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("path `{}` has no parent directory", path.display()))?;
        return discover_project_roots(parent);
    }
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    if !path.is_dir() {
        bail!(
            "workspace unsafe audit expects a directory root: {}",
            path.display()
        );
    }

    let mut out = Vec::<PathBuf>::new();
    if is_valid_project_root(path) {
        out.push(path.to_path_buf());
    }
    let mut queue = VecDeque::from([path.to_path_buf()]);
    while let Some(root) = queue.pop_front() {
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let candidate = entry.path();
            if !candidate.is_dir() {
                continue;
            }
            let name = candidate
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or_default();
            if name.starts_with('.')
                || name == "target"
                || name == "artifacts"
                || name == "vendor"
                || name == "node_modules"
            {
                continue;
            }
            if is_valid_project_root(&candidate) {
                out.push(candidate.clone());
            }
            queue.push_back(candidate);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn is_valid_project_root(path: &Path) -> bool {
    load_cached_project_manifest(path).is_ok()
}

pub(super) fn default_header_path(resolved: &ResolvedSource) -> PathBuf {
    if let Some(manifest) = &resolved.manifest {
        return resolved
            .project_root
            .join("include")
            .join(format!("{}.h", manifest.package.name));
    }
    let stem = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .unwrap_or("module");
    resolved
        .source_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.h"))
}

pub(super) fn load_resolved_module_set(path: &Path) -> Result<ResolvedModuleSet> {
    let cache_key = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if let Some(cached) = cached_module_set(&cache_key)? {
        return Ok(cached);
    }
    if path.is_dir() && !path.join("fozzy.toml").exists() {
        let module_paths = collect_all_fzy_files(path)?;
        if module_paths.is_empty() {
            bail!("no .fzy sources found under {}", path.display());
        }
        let mut modules = Vec::new();
        for module_path in &module_paths {
            let source = std::fs::read_to_string(module_path).with_context(|| {
                format!("failed reading source file: {}", module_path.display())
            })?;
            let module_name = module_path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| anyhow!("invalid module filename: {}", module_path.display()))?
                .to_string();
            let ast = parser::parse(&source, &module_name).map_err(|diagnostics| {
                let detail = diagnostics
                    .first()
                    .map(|diag| diag.message.clone())
                    .unwrap_or_else(|| "unknown parse failure".to_string());
                anyhow!(
                    "failed parsing module source for generation: {} ({detail})",
                    module_path.display()
                )
            })?;
            modules.push(ResolvedModuleSource {
                path: module_path.clone(),
                module_name,
                source,
                ast,
            });
        }
        let module_set = ResolvedModuleSet {
            resolved: ResolvedSource {
                source_path: module_paths[0].clone(),
                project_root: path.to_path_buf(),
                manifest: None,
            },
            modules,
        };
        store_module_set_cache(&cache_key, &module_set, &module_paths)?;
        return Ok(module_set);
    }
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let mut module_paths = parsed.module_paths;
    let source_root = resolved.project_root.join("src");
    if source_root.is_dir() {
        module_paths.extend(collect_all_fzy_files(&source_root)?);
    }
    module_paths.sort();
    module_paths.dedup();
    let mut modules = Vec::new();
    for module_path in module_paths {
        let source = std::fs::read_to_string(&module_path)
            .with_context(|| format!("failed reading source file: {}", module_path.display()))?;
        let module_name = module_path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("invalid module filename: {}", module_path.display()))?
            .to_string();
        let ast = parser::parse(&source, &module_name).map_err(|diagnostics| {
            let detail = diagnostics
                .first()
                .map(|diag| diag.message.clone())
                .unwrap_or_else(|| "unknown parse failure".to_string());
            anyhow!(
                "failed parsing module source for generation: {} ({detail})",
                module_path.display()
            )
        })?;
        modules.push(ResolvedModuleSource {
            path: module_path,
            module_name,
            source,
            ast,
        });
    }
    let module_set = ResolvedModuleSet { resolved, modules };
    let module_paths = module_set
        .modules
        .iter()
        .map(|module| module.path.clone())
        .collect::<Vec<_>>();
    store_module_set_cache(&cache_key, &module_set, &module_paths)?;
    Ok(module_set)
}

fn collect_all_fzy_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut queue = VecDeque::from([root.to_path_buf()]);
    while let Some(dir) = queue.pop_front() {
        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("failed reading directory: {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("failed iterating {}", dir.display()))?;
            let path = entry.path();
            if path.is_dir() {
                queue.push_back(path);
            } else if is_fzy_source_path(&path) {
                let canonical = path.canonicalize().unwrap_or(path);
                files.push(canonical);
            }
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn cached_module_set(cache_key: &Path) -> Result<Option<ResolvedModuleSet>> {
    let cache = MODULE_SET_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    let guard = match cache.read() {
        Ok(guard) => guard,
        Err(_) => return Ok(None),
    };
    let Some(entry) = guard.get(cache_key) else {
        return Ok(None);
    };
    let current_stamps = collect_path_stamps(&entry.root, &entry.module_set.modules)?;
    if current_stamps == entry.stamps {
        return Ok(Some(entry.module_set.clone()));
    }
    Ok(None)
}

fn store_module_set_cache(
    cache_key: &Path,
    module_set: &ResolvedModuleSet,
    module_paths: &[PathBuf],
) -> Result<()> {
    let root = module_set.resolved.project_root.clone();
    let stamps = collect_stamps_for_paths(module_paths)?;
    let cache = MODULE_SET_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(mut guard) = cache.write() {
        guard.insert(
            cache_key.to_path_buf(),
            ModuleSetCacheEntry {
                root,
                stamps,
                module_set: module_set.clone(),
            },
        );
    }
    Ok(())
}

fn collect_path_stamps(
    _root: &Path,
    modules: &[ResolvedModuleSource],
) -> Result<Vec<(PathBuf, FileStamp)>> {
    collect_stamps_for_paths(
        &modules
            .iter()
            .map(|module| module.path.clone())
            .collect::<Vec<_>>(),
    )
}

fn collect_stamps_for_paths(paths: &[PathBuf]) -> Result<Vec<(PathBuf, FileStamp)>> {
    paths
        .iter()
        .map(|path| {
            let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
            let stamp = file_stamp(&canonical)
                .ok_or_else(|| anyhow!("failed reading file metadata: {}", canonical.display()))?;
            Ok((canonical, stamp))
        })
        .collect()
}

fn file_stamp(path: &Path) -> Option<FileStamp> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let modified_ns = modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(FileStamp {
        bytes: meta.len(),
        modified_ns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn resolve_source_refreshes_manifest_cache_after_change() {
        let root = std::env::temp_dir().join(format!(
            "fozzylang-source-manifest-cache-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/alt_main.fzy"),
            "fn main() -> i32 {\n    return 1\n}\n",
        )
        .expect("alternate source should be written");

        let first = resolve_source(&root).expect("initial source resolution should succeed");
        assert_eq!(first.source_path, root.join("src/main.fzy"));

        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/alt_main.fzy\"\n",
        )
        .expect("manifest should be updated");

        let second = resolve_source(&root).expect("updated source resolution should succeed");
        assert_eq!(second.source_path, root.join("src/alt_main.fzy"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn load_resolved_module_set_refreshes_cached_modules_after_change() {
        let root = std::env::temp_dir().join(format!(
            "fozzylang-source-module-set-cache-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("module dir should be created");
        let module_path = root.join("main.fzy");
        std::fs::write(&module_path, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("initial module should be written");

        let first = load_resolved_module_set(&root).expect("first module load should succeed");
        assert_eq!(first.modules.len(), 1);
        assert!(first.modules[0].source.contains("return 0"));

        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(
            &module_path,
            "fn main() -> i32 {\n    return 42\n}\n\nfn helper() -> i32 {\n    return 1\n}\n",
        )
        .expect("module source should mutate");

        let second = load_resolved_module_set(&root).expect("second module load should succeed");
        assert_eq!(second.modules.len(), 1);
        assert!(second.modules[0].source.contains("return 42"));
        assert_ne!(first.modules[0].source, second.modules[0].source);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resolve_source_rejects_scenario_config_directory_as_project_root() {
        let root = std::env::temp_dir().join(format!(
            "fozzylang-source-scenario-config-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "base_dir = \".fozzy\"\nreporter = \"pretty\"\nproc_backend = \"scripted\"\n",
        )
        .expect("scenario config should be written");

        let error = resolve_source(&root).expect_err("scenario config dir must not resolve");
        assert!(error.to_string().contains("is not a Fozzy project root"));

        let _ = std::fs::remove_dir_all(root);
    }
}
