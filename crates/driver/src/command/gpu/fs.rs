use super::*;
use crate::pipeline::{
    normalize_rel_path, refresh_lockfile, resolve_local_dependency, stable_relative_path,
    verify_lockfile, DependencyResolutionKind,
};

pub(crate) fn vendor_command(path: &Path, check: bool, format: Format) -> Result<String> {
    if !path.is_dir() {
        bail!("vendor requires a project directory: {}", path.display());
    }
    let manifest_path = path.join("fozzy.toml");
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("missing manifest: {}", manifest_path.display()))?;
    if !manifest::looks_like_compiler_manifest(&manifest_text) {
        bail!("missing compiler manifest: {}", manifest_path.display());
    }
    let manifest = manifest::load(&manifest_text).context("failed parsing fozzy.toml")?;
    manifest
        .validate()
        .map_err(|error| anyhow!("invalid fozzy.toml: {error}"))?;
    let lock_hash = if check {
        verify_lockfile(path)?
    } else {
        refresh_lockfile(path)?
    };
    let lock_path = path.join("fozzy.lock");
    let lock_text = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("failed reading lockfile: {}", lock_path.display()))?;
    let lock_json: serde_json::Value = serde_json::from_str(&lock_text)
        .with_context(|| format!("failed parsing lockfile: {}", lock_path.display()))?;
    let lock_deps = lock_json
        .get("graph")
        .and_then(|value| value.get("deps"))
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let mut lock_dep_by_name = BTreeMap::new();
    for dep in &lock_deps {
        if let Some(name) = dep.get("name").and_then(|value| value.as_str()) {
            lock_dep_by_name.insert(name.to_string(), dep.clone());
        }
    }
    let vendor_dir = path.join("vendor");
    let vendor_manifest = vendor_dir.join("fozzy-vendor.json");
    let vendor_manifest_exists = vendor_manifest.exists();
    if !check {
        std::fs::create_dir_all(&vendor_dir)
            .with_context(|| format!("failed creating vendor dir: {}", vendor_dir.display()))?;
    }
    let mut copied = Vec::new();
    for (name, dependency) in &manifest.deps {
        let lock_dep = lock_dep_by_name
            .get(name.as_str())
            .ok_or_else(|| anyhow!("lockfile missing dependency entry for `{name}`"))?;
        match dependency {
            manifest::Dependency::Framework { .. } | manifest::Dependency::Path { .. } => {
                let resolution = resolve_local_dependency(path, name, dependency)?;
                let source_dir = resolution.root;
                let target_dir = vendor_dir.join(name);
                let source_hash = lock_dep
                    .get("sourceHash")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string();
                let vendor_hash = if check {
                    if !vendor_manifest_exists {
                        String::new()
                    } else {
                        if !target_dir.exists() {
                            bail!(
                                "vendored dependency directory missing for `{}`: {}",
                                name,
                                target_dir.display()
                            );
                        }
                        hash_directory_tree(&target_dir)?
                    }
                } else {
                    if target_dir.exists() {
                        std::fs::remove_dir_all(&target_dir).with_context(|| {
                            format!(
                                "failed cleaning existing vendor target: {}",
                                target_dir.display()
                            )
                        })?;
                    }
                    copy_dir_recursive(&source_dir, &target_dir)?;
                    hash_directory_tree(&target_dir)?
                };
                if !source_hash.is_empty() && !vendor_hash.is_empty() && source_hash != vendor_hash
                {
                    bail!(
                        "vendor copy hash mismatch for `{}`: lock sourceHash={} vendorHash={}",
                        name,
                        source_hash,
                        vendor_hash
                    );
                }
                let source_type = match resolution.kind {
                    DependencyResolutionKind::Framework => "framework",
                    DependencyResolutionKind::Path => "path",
                };
                let mut record = serde_json::Map::new();
                record.insert("name".to_string(), serde_json::json!(name));
                record.insert("sourceType".to_string(), serde_json::json!(source_type));
                record.insert(
                    "source".to_string(),
                    serde_json::json!(stable_relative_path(path, &source_dir)?),
                );
                record.insert(
                    "target".to_string(),
                    serde_json::json!(normalize_rel_path(
                        &target_dir
                            .strip_prefix(path)
                            .unwrap_or(&target_dir)
                            .display()
                            .to_string()
                    )),
                );
                record.insert("sourceHash".to_string(), serde_json::json!(source_hash));
                if !vendor_hash.is_empty() {
                    record.insert("vendorHash".to_string(), serde_json::json!(vendor_hash));
                }
                record.insert(
                    "package".to_string(),
                    lock_dep
                        .get("package")
                        .cloned()
                        .unwrap_or(serde_json::json!({})),
                );
                copied.push(serde_json::Value::Object(record));
            }
            manifest::Dependency::Version { version, source } => {
                copied.push(serde_json::json!({
                    "name": name,
                    "sourceType": "version",
                    "version": version,
                    "source": source.clone().unwrap_or_else(|| "registry+https://crates.io".to_string()),
                    "sourceHash": lock_dep.get("sourceHash").and_then(|value| value.as_str()).unwrap_or_default(),
                    "vendored": false,
                    "package": lock_dep.get("package").cloned().unwrap_or(serde_json::json!({})),
                }));
            }
            manifest::Dependency::Git { git, rev } => {
                copied.push(serde_json::json!({
                    "name": name,
                    "sourceType": "git",
                    "git": git,
                    "rev": rev,
                    "sourceHash": lock_dep.get("sourceHash").and_then(|value| value.as_str()).unwrap_or_default(),
                    "vendored": false,
                    "package": lock_dep.get("package").cloned().unwrap_or(serde_json::json!({})),
                }));
            }
        }
    }
    let vendor_payload = serde_json::json!({
        "schemaVersion": "fozzylang.vendor.v0",
        "lockHash": lock_hash,
        "lockfile": "fozzy.lock",
        "dependencies": copied,
    });
    let vendor_state = if check {
        if !vendor_manifest_exists {
            "absent".to_string()
        } else {
            let existing_text = std::fs::read_to_string(&vendor_manifest).with_context(|| {
                format!(
                    "failed reading vendor manifest: {}",
                    vendor_manifest.display()
                )
            })?;
            let existing_payload: serde_json::Value = serde_json::from_str(&existing_text)
                .with_context(|| {
                    format!(
                        "failed parsing vendor manifest: {}",
                        vendor_manifest.display()
                    )
                })?;
            if existing_payload != vendor_payload {
                bail!(
                    "vendor manifest drift detected for {} (run `fz vendor {}` to refresh the checked-in vendor snapshot)",
                    vendor_manifest.display(),
                    path.display()
                );
            }
            "ok".to_string()
        }
    } else {
        std::fs::write(
            &vendor_manifest,
            serde_json::to_vec_pretty(&vendor_payload)?,
        )
        .with_context(|| {
            format!(
                "failed writing vendor manifest: {}",
                vendor_manifest.display()
            )
        })?;
        "written".to_string()
    };
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            (
                "mode",
                if check {
                    "vendor-check".to_string()
                } else {
                    "vendor".to_string()
                },
            ),
            ("dependencies", copied.len().to_string()),
            ("dir", vendor_dir.display().to_string()),
            ("lock_hash", lock_hash.clone()),
            ("vendor_state", vendor_state.clone()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "mode": if check { "vendor-check" } else { "vendor" },
            "vendorDir": vendor_dir.display().to_string(),
            "lockHash": lock_hash,
            "lockfile": lock_path.display().to_string(),
            "vendorManifest": vendor_manifest.display().to_string(),
            "vendorState": vendor_state,
            "dependencies": copied,
        })
        .to_string()),
    }
}

pub(crate) fn copy_dir_recursive(source: &Path, target: &Path) -> Result<()> {
    std::fs::create_dir_all(target)
        .with_context(|| format!("failed creating directory: {}", target.display()))?;
    for entry in std::fs::read_dir(source)
        .with_context(|| format!("failed reading directory: {}", source.display()))?
    {
        let entry = entry?;
        let src = entry.path();
        let dst = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst).with_context(|| {
                format!(
                    "failed copying file from {} to {}",
                    src.display(),
                    dst.display()
                )
            })?;
        }
    }
    Ok(())
}

pub(crate) fn hash_directory_tree(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect_files_recursive(root, root, &mut files)?;
    let mut hasher = Sha256::new();
    for (rel, full) in files {
        hasher.update(rel.as_bytes());
        let bytes = std::fs::read(&full)
            .with_context(|| format!("failed reading file for hash: {}", full.display()))?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

pub(crate) fn collect_files_recursive(
    root: &Path,
    current: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let mut entries = std::fs::read_dir(current)
        .with_context(|| format!("failed reading directory: {}", current.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed iterating directory: {}", current.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let full = entry.path();
        let rel = full
            .strip_prefix(root)
            .with_context(|| format!("failed deriving relative path for {}", full.display()))?;
        let rel_str = rel.display().to_string().replace('\\', "/");
        if rel_str.starts_with(".git/")
            || rel_str.starts_with(".fz/")
            || rel_str.starts_with("vendor/")
            || rel_str.starts_with("target/")
        {
            continue;
        }
        if entry
            .file_type()
            .with_context(|| format!("failed reading file type for {}", full.display()))?
            .is_dir()
        {
            collect_files_recursive(root, &full, out)?;
        } else {
            out.push((rel_str, full));
        }
    }
    Ok(())
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

pub(crate) fn ensure_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    Ok(())
}
