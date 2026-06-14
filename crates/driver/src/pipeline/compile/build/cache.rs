use super::*;

pub(crate) fn cached_compile_file_artifact(
    resolved: &ResolvedSource,
    profile: BuildProfile,
    backend: &str,
    pgo: &PgoConfig,
) -> Option<BuildArtifact> {
    let build_dir = resolved.project_root.join(".fz").join("build");
    let cache_path =
        successful_build_cache_path(&build_dir, &resolved.artifact_stem, "bin", backend);
    let entry = read_successful_build_cache(&cache_path)?;
    if !successful_build_cache_hit(&entry, resolved, profile, backend, pgo) {
        return None;
    }
    let output = entry.output?;
    if !output.exists() {
        return None;
    }
    Some(BuildArtifact {
        module: entry.module_name,
        profile,
        status: "ok",
        diagnostics: 0,
        diagnostic_details: Vec::new(),
        output: Some(output),
        dependency_graph_hash: resolved.dependency_graph_hash.clone(),
        incremental: None,
    })
}

pub(crate) fn cached_compile_library_artifact(
    resolved: &ResolvedSource,
    profile: BuildProfile,
    backend: &str,
    pgo: &PgoConfig,
) -> Option<LibraryArtifact> {
    let build_dir = resolved.project_root.join(".fz").join("build");
    let cache_path =
        successful_build_cache_path(&build_dir, &resolved.artifact_stem, "ffi", backend);
    let entry = read_successful_build_cache(&cache_path)?;
    if !successful_build_cache_hit(&entry, resolved, profile, backend, pgo) {
        return None;
    }
    let static_lib = entry.static_lib.filter(|path| path.exists());
    let shared_lib = entry.shared_lib.filter(|path| path.exists());
    if static_lib.is_none() && shared_lib.is_none() {
        return None;
    }
    Some(LibraryArtifact {
        module: entry.module_name,
        profile,
        status: "ok",
        diagnostics: 0,
        diagnostic_details: Vec::new(),
        static_lib,
        shared_lib,
        dependency_graph_hash: resolved.dependency_graph_hash.clone(),
        incremental: None,
    })
}

pub(crate) fn parsed_program_source_stamps(parsed: &ParsedProgram) -> Vec<ModuleStamp> {
    parsed
        .cache_paths
        .iter()
        .filter_map(|path| module_stamp(path))
        .collect()
}

pub(crate) fn write_successful_compile_file_cache(
    resolved: &ResolvedSource,
    parsed: &ParsedProgram,
    module_name: &str,
    profile: BuildProfile,
    backend: &str,
    pgo: &PgoConfig,
    output: &Path,
) -> Result<()> {
    let build_dir = resolved.project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;
    let cache_path =
        successful_build_cache_path(&build_dir, &resolved.artifact_stem, "bin", backend);
    write_successful_build_cache(
        &cache_path,
        &SuccessfulBuildCacheEntry {
            schema_version: "fozzylang.buildcache.v1".to_string(),
            source_path: resolved.source_path.clone(),
            module_name: module_name.to_string(),
            profile: profile.as_str().to_string(),
            backend: backend.to_string(),
            manifest_fingerprint: resolved.manifest_fingerprint.clone(),
            dependency_graph_hash: resolved.dependency_graph_hash.clone(),
            pgo_signature: pgo_signature(pgo),
            source_stamps: parsed_program_source_stamps(parsed),
            output: Some(output.to_path_buf()),
            static_lib: None,
            shared_lib: None,
        },
    )
}

pub(crate) fn write_successful_compile_library_cache(
    resolved: &ResolvedSource,
    parsed: &ParsedProgram,
    module_name: &str,
    profile: BuildProfile,
    backend: &str,
    pgo: &PgoConfig,
    static_lib: Option<&PathBuf>,
    shared_lib: Option<&PathBuf>,
) -> Result<()> {
    let build_dir = resolved.project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;
    let cache_path =
        successful_build_cache_path(&build_dir, &resolved.artifact_stem, "ffi", backend);
    write_successful_build_cache(
        &cache_path,
        &SuccessfulBuildCacheEntry {
            schema_version: "fozzylang.buildcache.v1".to_string(),
            source_path: resolved.source_path.clone(),
            module_name: module_name.to_string(),
            profile: profile.as_str().to_string(),
            backend: backend.to_string(),
            manifest_fingerprint: resolved.manifest_fingerprint.clone(),
            dependency_graph_hash: resolved.dependency_graph_hash.clone(),
            pgo_signature: pgo_signature(pgo),
            source_stamps: parsed_program_source_stamps(parsed),
            output: None,
            static_lib: static_lib.cloned(),
            shared_lib: shared_lib.cloned(),
        },
    )
}
