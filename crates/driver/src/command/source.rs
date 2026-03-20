use super::*;

#[derive(Debug, Clone)]
pub(super) struct ResolvedSource {
    pub(super) source_path: PathBuf,
    pub(super) project_root: PathBuf,
    pub(super) manifest: Option<manifest::Manifest>,
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
    let manifest_text = match std::fs::read_to_string(&manifest_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let suggestions = discover_nested_project_roots(path);
            let guidance = if suggestions.is_empty() {
                format!(
                    "directory `{}` is not a Fozzy project root (missing {}). initialize a project here with `fz init <name>` or run the command against a project directory/file explicitly",
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
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed reading manifest: {}", manifest_path.display()));
        }
    };
    let manifest = manifest::load(&manifest_text).context("failed parsing fozzy.toml")?;
    manifest
        .validate()
        .map_err(|error| anyhow!("invalid fozzy.toml: {error}"))?;
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
        if candidate.join("fozzy.toml").exists() {
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
    let manifest_path = path.join("fozzy.toml");
    let text = match std::fs::read_to_string(&manifest_path) {
        Ok(text) => text,
        Err(_) => return false,
    };
    let manifest = match manifest::load(&text) {
        Ok(manifest) => manifest,
        Err(_) => return false,
    };
    manifest.validate().is_ok()
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
