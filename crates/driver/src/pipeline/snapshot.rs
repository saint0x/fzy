use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotManifest {
    schema_version: String,
    snapshot_hash: String,
    source_anchor: PathBuf,
    original_project_root: PathBuf,
    snapshot_tree_root: PathBuf,
    snapshot_project_root: PathBuf,
    object_store_root: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct BuildSnapshot {
    pub(crate) source_anchor: PathBuf,
    pub(crate) snapshot_tree_root: PathBuf,
    pub(crate) snapshot_project_root: PathBuf,
    pub(crate) object_store_root: PathBuf,
}

#[derive(Debug, Clone)]
struct SnapshotFileEntry {
    source: PathBuf,
    relative: PathBuf,
}

const SNAPSHOT_SCHEMA_VERSION: &str = "fozzylang.snapshot.v1";

pub(crate) fn prepare_build_snapshot(project_root: &Path) -> Result<BuildSnapshot> {
    if let Some(existing) = load_existing_build_snapshot(project_root)? {
        return Ok(existing);
    }

    let canonical_project_root = project_root
        .canonicalize()
        .with_context(|| format!("failed resolving project root: {}", project_root.display()))?;
    let mut project_roots = Vec::new();
    let mut seen = HashSet::new();
    collect_snapshot_project_roots(&canonical_project_root, &mut seen, &mut project_roots)?;
    project_roots.sort();
    project_roots.dedup();
    let source_anchor = common_ancestor_path(&project_roots)
        .ok_or_else(|| anyhow!("failed deriving common source anchor for snapshot capture"))?;
    let snapshot_files = collect_snapshot_file_entries(&project_roots, &source_anchor)?;
    let snapshot_hash = compute_snapshot_hash(&snapshot_files)?;
    let snapshot_base = canonical_project_root
        .join(".fz")
        .join("snapshots")
        .join(&snapshot_hash);
    let snapshot_tree_root = snapshot_base.join("tree");
    let snapshot_project_root =
        snapshot_tree_root.join(canonical_project_root.strip_prefix(&source_anchor)?);
    let object_store_root = canonical_project_root.join(".fz").join("cache").join("obj");
    let snapshot = BuildSnapshot {
        source_anchor: source_anchor.clone(),
        snapshot_tree_root: snapshot_tree_root.clone(),
        snapshot_project_root: snapshot_project_root.clone(),
        object_store_root: object_store_root.clone(),
    };
    let snapshots_root = canonical_project_root.join(".fz").join("snapshots");
    std::fs::create_dir_all(&snapshots_root).with_context(|| {
        format!(
            "failed creating snapshots directory: {}",
            snapshots_root.display()
        )
    })?;
    let _lock = acquire_snapshot_lock(&snapshots_root)?;
    if let Some(existing) = load_existing_build_snapshot(&snapshot_project_root)? {
        return Ok(existing);
    }

    for entry in &snapshot_files {
        let destination = snapshot_tree_root.join(&entry.relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed creating snapshot directory: {}", parent.display())
            })?;
        }
        std::fs::copy(&entry.source, &destination).with_context(|| {
            format!(
                "failed copying snapshot file {} -> {}",
                entry.source.display(),
                destination.display()
            )
        })?;
    }
    std::fs::create_dir_all(snapshot_project_root.join(".fz")).with_context(|| {
        format!(
            "failed creating snapshot metadata directory: {}",
            snapshot_project_root.join(".fz").display()
        )
    })?;
    let manifest = SnapshotManifest {
        schema_version: SNAPSHOT_SCHEMA_VERSION.to_string(),
        snapshot_hash,
        source_anchor,
        original_project_root: canonical_project_root,
        snapshot_tree_root,
        snapshot_project_root: snapshot_project_root.clone(),
        object_store_root,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let manifest_text = String::from_utf8(manifest_bytes)
        .map_err(|error| anyhow!("failed encoding snapshot manifest as utf-8: {error}"))?;
    write_atomic_text_file(
        &snapshot_manifest_path(&snapshot_project_root),
        &manifest_text,
    )?;
    Ok(snapshot)
}

pub(crate) fn load_existing_build_snapshot(project_root: &Path) -> Result<Option<BuildSnapshot>> {
    let manifest_path = snapshot_manifest_path(project_root);
    if !manifest_path.exists() {
        return Ok(None);
    }
    let manifest: SnapshotManifest = serde_json::from_slice(
        &std::fs::read(&manifest_path)
            .with_context(|| format!("failed reading {}", manifest_path.display()))?,
    )
    .with_context(|| format!("failed parsing {}", manifest_path.display()))?;
    if manifest.schema_version != SNAPSHOT_SCHEMA_VERSION {
        bail!(
            "unsupported snapshot manifest schema `{}` at {}",
            manifest.schema_version,
            manifest_path.display()
        );
    }
    Ok(Some(BuildSnapshot {
        source_anchor: manifest.source_anchor,
        snapshot_tree_root: manifest.snapshot_tree_root,
        snapshot_project_root: manifest.snapshot_project_root,
        object_store_root: manifest.object_store_root,
    }))
}

pub(crate) fn map_path_into_snapshot(snapshot: &BuildSnapshot, path: &Path) -> Result<PathBuf> {
    if path.starts_with(&snapshot.snapshot_tree_root) {
        return Ok(path.to_path_buf());
    }
    let canonical = path.canonicalize().with_context(|| {
        format!(
            "failed resolving path for snapshot mapping: {}",
            path.display()
        )
    })?;
    let relative = canonical
        .strip_prefix(&snapshot.source_anchor)
        .with_context(|| {
            format!(
                "path {} is outside snapshot source anchor {}",
                canonical.display(),
                snapshot.source_anchor.display()
            )
        })?;
    Ok(snapshot.snapshot_tree_root.join(relative))
}

pub(crate) fn map_snapshot_path_to_source(snapshot: &BuildSnapshot, path: &Path) -> PathBuf {
    path.strip_prefix(&snapshot.snapshot_tree_root)
        .map(|relative| snapshot.source_anchor.join(relative))
        .unwrap_or_else(|_| path.to_path_buf())
}

pub(crate) fn remap_snapshot_diagnostic_paths(
    snapshot: &BuildSnapshot,
    diagnostics: &mut [diagnostics::Diagnostic],
) {
    for diagnostic in diagnostics {
        if let Some(path) = diagnostic.path.as_ref() {
            diagnostic.path = Some(remap_snapshot_path_string(snapshot, path));
        }
    }
}

pub(crate) fn remap_snapshot_incremental_report(
    snapshot: &BuildSnapshot,
    report: &mut IncrementalBuildReport,
) {
    for module in &mut report.module_details {
        module.path = remap_snapshot_path_string(snapshot, &module.path);
    }
}

fn remap_snapshot_path_string(snapshot: &BuildSnapshot, raw: &str) -> String {
    let path = Path::new(raw);
    map_snapshot_path_to_source(snapshot, path)
        .display()
        .to_string()
}

fn snapshot_manifest_path(project_root: &Path) -> PathBuf {
    project_root.join(".fz").join("snapshot.json")
}

fn acquire_snapshot_lock(snapshots_root: &Path) -> Result<SnapshotCaptureLock> {
    acquire_lock_file(
        &snapshots_root.join(".capture.lock"),
        "snapshot capture",
        std::time::Duration::from_secs(120),
        std::time::Duration::from_millis(50),
    )
}

#[derive(Debug)]
struct SnapshotCaptureLock {
    path: PathBuf,
}

impl Drop for SnapshotCaptureLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn acquire_lock_file(
    path: &Path,
    label: &str,
    timeout: std::time::Duration,
    retry_delay: std::time::Duration,
) -> Result<SnapshotCaptureLock> {
    let owner = format!(
        "pid={} label={} started_at_unix_nanos={}\n",
        std::process::id(),
        label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let start = std::time::Instant::now();
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut file) => {
                use std::io::Write;
                file.write_all(owner.as_bytes())
                    .with_context(|| format!("failed writing lock file: {}", path.display()))?;
                return Ok(SnapshotCaptureLock {
                    path: path.to_path_buf(),
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if start.elapsed() >= timeout {
                    let holder = std::fs::read_to_string(path)
                        .unwrap_or_else(|_| "<unknown lock holder>".to_string());
                    bail!(
                        "timed out waiting for {} lock {} held by {}",
                        label,
                        path.display(),
                        holder.trim()
                    );
                }
                std::thread::sleep(retry_delay);
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed creating lock file: {}", path.display()));
            }
        }
    }
}

fn collect_snapshot_project_roots(
    root: &Path,
    seen: &mut HashSet<PathBuf>,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    let canonical = root.canonicalize().with_context(|| {
        format!(
            "failed canonicalizing snapshot project root: {}",
            root.display()
        )
    })?;
    if !seen.insert(canonical.clone()) {
        return Ok(());
    }
    out.push(canonical.clone());
    let (manifest, _, _) = load_manifest(&canonical, LockfileMode::ValidateOrCreate)?;
    for (alias, dependency) in &manifest.deps {
        let dep_root = match dependency {
            manifest::Dependency::Framework { .. } | manifest::Dependency::Path { .. } => {
                resolve_local_dependency(&canonical, alias, dependency)?.root
            }
            manifest::Dependency::Version { .. } | manifest::Dependency::Git { .. } => continue,
        };
        collect_snapshot_project_roots(&dep_root, seen, out)?;
    }
    Ok(())
}

fn collect_snapshot_file_entries(
    project_roots: &[PathBuf],
    source_anchor: &Path,
) -> Result<Vec<SnapshotFileEntry>> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for root in project_roots {
        collect_snapshot_files_recursive(root, source_anchor, &mut seen, &mut entries)?;
        collect_snapshot_workspace_policy_files(root, source_anchor, &mut seen, &mut entries)?;
    }
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(entries)
}

fn collect_snapshot_workspace_policy_files(
    project_root: &Path,
    source_anchor: &Path,
    seen: &mut HashSet<PathBuf>,
    entries: &mut Vec<SnapshotFileEntry>,
) -> Result<()> {
    let mut cursor = Some(project_root.to_path_buf());
    while let Some(current) = cursor {
        let candidate = current.join("fozzy.workspace.toml");
        if candidate.exists() {
            let canonical = candidate
                .canonicalize()
                .with_context(|| format!("failed resolving {}", candidate.display()))?;
            if seen.insert(canonical.clone()) {
                entries.push(SnapshotFileEntry {
                    relative: canonical.strip_prefix(source_anchor)?.to_path_buf(),
                    source: canonical,
                });
            }
        }
        if current == source_anchor {
            break;
        }
        cursor = current.parent().map(Path::to_path_buf);
    }
    Ok(())
}

fn collect_snapshot_files_recursive(
    current: &Path,
    source_anchor: &Path,
    seen: &mut HashSet<PathBuf>,
    entries: &mut Vec<SnapshotFileEntry>,
) -> Result<()> {
    let mut children = std::fs::read_dir(current)
        .with_context(|| format!("failed reading snapshot directory: {}", current.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed iterating snapshot directory: {}", current.display()))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let name = child.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), ".fz" | ".git" | "target") {
                continue;
            }
            collect_snapshot_files_recursive(&path, source_anchor, seen, entries)?;
            continue;
        }
        if name.starts_with('.') && name.contains(".tmp-") {
            continue;
        }
        let canonical = path
            .canonicalize()
            .with_context(|| format!("failed resolving snapshot file: {}", path.display()))?;
        if !seen.insert(canonical.clone()) {
            continue;
        }
        entries.push(SnapshotFileEntry {
            relative: canonical.strip_prefix(source_anchor)?.to_path_buf(),
            source: canonical,
        });
    }
    Ok(())
}

fn compute_snapshot_hash(entries: &[SnapshotFileEntry]) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_SCHEMA_VERSION.as_bytes());
    hasher.update([0]);
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    for entry in entries {
        hasher.update(normalize_rel_path(&entry.relative.display().to_string()).as_bytes());
        hasher.update([0]);
        let bytes = std::fs::read(&entry.source)
            .with_context(|| format!("failed reading snapshot file: {}", entry.source.display()))?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        hasher.update([0xff]);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

fn common_ancestor_path(paths: &[PathBuf]) -> Option<PathBuf> {
    let components = paths
        .iter()
        .map(|path| path.components().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let first = components.first()?.clone();
    let mut shared = Vec::new();
    'outer: for (index, component) in first.iter().enumerate() {
        for candidate in &components[1..] {
            if candidate.get(index) != Some(component) {
                break 'outer;
            }
        }
        shared.push(*component);
    }
    let mut out = PathBuf::new();
    for component in shared {
        out.push(component.as_os_str());
    }
    Some(out)
}
