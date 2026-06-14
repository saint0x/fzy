fn check_file_with_root_guidance(path: &Path) -> Result<Output> {
    check_file(path).map_err(|error| attach_project_root_guidance(path, error))
}

fn verify_file_with_root_guidance(path: &Path) -> Result<Output> {
    verify_file(path).map_err(|error| attach_project_root_guidance(path, error))
}

fn compile_file_with_backend_with_root_guidance(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<BuildArtifact> {
    compile_file_with_backend(path, profile, backend_override)
        .map_err(|error| attach_project_root_guidance(path, error))
}

fn compile_file_incremental_with_backend_with_root_guidance(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<BuildArtifact> {
    compile_file_incremental_with_backend(path, profile, backend_override)
        .map_err(|error| attach_project_root_guidance(path, error))
}

fn compile_library_with_backend_with_root_guidance(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<LibraryArtifact> {
    compile_library_with_backend(path, profile, backend_override)
        .map_err(|error| attach_project_root_guidance(path, error))
}

fn compile_library_incremental_with_backend_with_root_guidance(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<LibraryArtifact> {
    compile_library_incremental_with_backend(path, profile, backend_override)
        .map_err(|error| attach_project_root_guidance(path, error))
}

fn attach_project_root_guidance(path: &Path, error: anyhow::Error) -> anyhow::Error {
    let text = error.to_string();
    if !(text.contains("no valid compiler manifest found")
        || text.contains("path is neither a source file nor a project directory")
        || text.contains("expected a `.fzy` source file or a project directory"))
    {
        return error;
    }
    if path.is_file() {
        return error;
    }
    let manifest_path = path.join("fozzy.toml");
    if manifest_path.exists() {
        return error;
    }
    let nested = discover_nested_project_roots(path);
    if nested.is_empty() {
        anyhow!(
            "directory `{}` is not a Fozzy project root (missing {}). initialize a project here with `fz init [path]` or run against a project directory/file explicitly",
            path.display(),
            manifest_path.display()
        )
    } else {
        anyhow!(
            "directory `{}` is not a Fozzy project root (missing {}). detected nested project(s): {}. run the command against one of those project roots explicitly",
            path.display(),
            manifest_path.display(),
            nested
                .iter()
                .map(|candidate| candidate.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn maybe_generate_build_interop_artifacts(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<Option<BuildInteropArtifacts>> {
    if !project_has_c_exports(path)? {
        return Ok(None);
    }
    let library = compile_library_with_backend_with_root_guidance(path, profile, backend_override)?;
    let headers = generate_c_headers(path, None)?;
    Ok(Some(finalize_build_interop_artifacts(
        path, &library, headers,
    )?))
}

fn finalize_build_interop_artifacts(
    path: &Path,
    library: &LibraryArtifact,
    headers: HeaderArtifact,
) -> Result<BuildInteropArtifacts> {
    let export_symbols = read_abi_export_symbols(&headers.abi_manifest)?;
    let artifact_manifest =
        write_interop_artifact_manifest(path, library, &headers, &export_symbols)?;
    Ok(BuildInteropArtifacts {
        library: library.clone(),
        headers,
        artifact_manifest,
        export_symbols,
    })
}

fn read_abi_export_symbols(abi_manifest: &Path) -> Result<Vec<String>> {
    let value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(abi_manifest)
            .with_context(|| format!("failed reading {}", abi_manifest.display()))?,
    )
    .with_context(|| format!("failed parsing {}", abi_manifest.display()))?;
    Ok(value
        .get("exports")
        .and_then(|exports| exports.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("name").and_then(|name| name.as_str()))
        .map(ToString::to_string)
        .collect())
}

fn write_interop_artifact_manifest(
    path: &Path,
    library: &LibraryArtifact,
    headers: &HeaderArtifact,
    export_symbols: &[String],
) -> Result<PathBuf> {
    let resolved = resolve_source(path)?;
    let manifest_path = headers.path.with_extension("artifacts.json");
    let manifest_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("artifact manifest path must have a parent directory"))?;
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.interop_artifacts.v1",
        "source": manifest_relative_path(manifest_dir, &resolved.source_path),
        "projectRoot": manifest_relative_path(manifest_dir, &resolved.project_root),
        "module": library.module,
        "profile": library.profile.as_str(),
        "buildMode": "lib",
        "staticLib": library.static_lib.as_ref().map(|path| manifest_relative_path(manifest_dir, path)),
        "sharedLib": library.shared_lib.as_ref().map(|path| manifest_relative_path(manifest_dir, path)),
        "header": manifest_relative_path(manifest_dir, &headers.path),
        "abiManifest": manifest_relative_path(manifest_dir, &headers.abi_manifest),
        "artifactManifest": manifest_relative_path(manifest_dir, &manifest_path),
        "exports": export_symbols,
        "hostLifecycle": {
            "init": "fz_host_init",
            "shutdown": "fz_host_shutdown",
            "cleanup": "fz_host_cleanup",
            "lastErrorCode": "fz_host_last_error_code",
            "lastErrorClass": "fz_host_last_error_class",
            "lastErrorMessage": "fz_host_last_error_message",
            "registerCallbackI32": "fz_host_register_callback_i32",
            "invokeCallbackI32": "fz_host_invoke_callback_i32",
        },
    });
    let bytes = serde_json::to_vec_pretty(&payload)?;
    if std::fs::read(&manifest_path).ok().as_deref() != Some(bytes.as_slice()) {
        std::fs::write(&manifest_path, &bytes)
            .with_context(|| format!("failed writing {}", manifest_path.display()))?;
    }
    Ok(manifest_path)
}

fn manifest_relative_path(base: &Path, path: &Path) -> String {
    relative_path_from(base, path).unwrap_or_else(|| path.to_string_lossy().into_owned())
}

fn relative_path_from(base: &Path, path: &Path) -> Option<String> {
    let base_components = normalized_path_components(base)?;
    let path_components = normalized_path_components(path)?;
    if base_components.first()? != path_components.first()? {
        return None;
    }

    let mut shared = 0usize;
    while shared < base_components.len()
        && shared < path_components.len()
        && base_components[shared] == path_components[shared]
    {
        shared += 1;
    }

    let mut relative = PathBuf::new();
    for _ in shared..base_components.len() {
        relative.push("..");
    }
    for component in &path_components[shared..] {
        relative.push(component);
    }
    if relative.as_os_str().is_empty() {
        relative.push(".");
    }
    Some(relative.to_string_lossy().into_owned())
}

fn normalized_path_components(path: &Path) -> Option<Vec<String>> {
    use std::path::Component;

    let mut out = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                out.push(prefix.as_os_str().to_string_lossy().into_owned())
            }
            Component::RootDir => out.push("/".to_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if out.last().is_some_and(|segment| segment != "/") {
                    out.pop();
                } else {
                    return None;
                }
            }
            Component::Normal(part) => out.push(part.to_string_lossy().into_owned()),
        }
    }
    Some(out)
}

fn project_has_c_exports(path: &Path) -> Result<bool> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    Ok(parsed.module.items.iter().any(|item| match item {
        ast::Item::Function(function) => {
            function.is_pub
                && function.is_extern
                && function
                    .abi
                    .as_deref()
                    .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
        }
        _ => false,
    }))
}

fn maybe_generate_unsafe_docs(path: &Path) -> Option<PathBuf> {
    let resolved = resolve_source(path).ok()?;
    let parsed = parse_program(&resolved.source_path).ok()?;
    if parsed.module.unsafe_sites == 0 {
        return None;
    }
    let docs_path = resolved.project_root.join(".fz/unsafe-docs.md");
    if unsafe_docs_cache_hit(path, &docs_path).ok()? {
        return Some(docs_path);
    }
    if audit_unsafe_command(&resolved.project_root, false, Format::Json).is_ok() {
        let _ = write_unsafe_docs_cache_stamp(path, &docs_path);
        Some(docs_path)
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsafeDocsCacheStamp {
    fingerprint: String,
}

fn unsafe_docs_cache_hit(path: &Path, docs_path: &Path) -> Result<bool> {
    let stamp_path = unsafe_docs_cache_path(docs_path);
    let json_path = docs_path.with_extension("json");
    let html_path = docs_path.with_extension("html");
    if !docs_path.exists() || !json_path.exists() || !html_path.exists() || !stamp_path.exists() {
        return Ok(false);
    }
    let stamp: UnsafeDocsCacheStamp = serde_json::from_slice(
        &std::fs::read(&stamp_path)
            .with_context(|| format!("failed reading {}", stamp_path.display()))?,
    )
    .with_context(|| format!("failed parsing {}", stamp_path.display()))?;
    Ok(stamp.fingerprint == unsafe_docs_fingerprint(path)?)
}

fn write_unsafe_docs_cache_stamp(path: &Path, docs_path: &Path) -> Result<()> {
    let stamp_path = unsafe_docs_cache_path(docs_path);
    let payload = UnsafeDocsCacheStamp {
        fingerprint: unsafe_docs_fingerprint(path)?,
    };
    if let Some(parent) = stamp_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&stamp_path, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("failed writing {}", stamp_path.display()))
}

fn unsafe_docs_cache_path(docs_path: &Path) -> PathBuf {
    docs_path.with_extension("stamp.json")
}

fn unsafe_docs_fingerprint(path: &Path) -> Result<String> {
    let module_set = load_resolved_module_set(path)?;
    let mut hasher = Sha256::new();
    hasher.update(
        module_set
            .resolved
            .project_root
            .to_string_lossy()
            .as_bytes(),
    );
    hasher.update(module_set.resolved.source_path.to_string_lossy().as_bytes());
    if let Some(manifest) = module_set.resolved.manifest.as_ref() {
        hasher.update(manifest.package.name.as_bytes());
        hasher.update(manifest.package.version.as_bytes());
    }
    for module in &module_set.modules {
        hasher.update(module.path.to_string_lossy().as_bytes());
        hasher.update(module.source.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) const DIAGNOSTIC_EXPLAIN_SCHEMA_VERSION: &str = "fozzylang.diagnostic_explain.v1";
pub(crate) const LSP_DIAGNOSTIC_DATA_SCHEMA_VERSION: &str = "fozzylang.lsp_diagnostic_data.v1";

fn explain_command(diag_code: &str, format: Format) -> Result<String> {
    let raw = diag_code.trim();
    let normalized = raw.to_ascii_uppercase();
    if normalized.is_empty() {
        bail!("missing diagnostic code: usage `fz explain <diag-code>`");
    }
    let catalog = diagnostic_catalog();
    if normalized == "CATALOG" || normalized == "--CATALOG" {
        return match format {
            Format::Text => Ok(catalog
                .iter()
                .map(|entry| {
                    format!(
                        "code_prefix: {}\nfamily: {}\nsummary: {}\nexample: {}\nnext_command: {}",
                        entry.code_prefix,
                        entry.family,
                        entry.summary,
                        entry.example,
                        entry.next_command
                    )
                })
                .collect::<Vec<_>>()
                .join("\n\n")),
            Format::Json => Ok(serde_json::json!({
                "schemaVersion": "fozzylang.diagnostic_catalog.v1",
                "entries": catalog,
            })
            .to_string()),
        };
    }
    let resolution = resolve_diagnostic_explain(raw);
    match format {
        Format::Text => {
            let mut fields = vec![
                ("code", resolution.normalized.clone()),
                ("family", resolution.family.clone()),
                ("root_cause", resolution.root_cause.clone()),
                ("likely_fix", resolution.likely_fix.clone()),
                ("verify_with", "fz check <path> --json".to_string()),
                (
                    "diagnostic_identity",
                    "codes are stable within a domain for unchanged message and source anchor"
                        .to_string(),
                ),
                ("explain_command", resolution.explain_command.clone()),
            ];
            if let Some(entry) = resolution.catalog_entry {
                fields.push(("catalog_key", entry.key));
                fields.push(("catalog_summary", entry.summary));
                fields.push(("catalog_example", entry.example));
                fields.push(("common_triggers", entry.common_triggers.join(" | ")));
                fields.push(("production_action", entry.production_action));
                fields.push(("production_risk", entry.production_risk));
                fields.push(("next_command", entry.next_command));
            }
            Ok(render_text_fields(&fields))
        }
        Format::Json => Ok(serde_json::json!({
            "schemaVersion": DIAGNOSTIC_EXPLAIN_SCHEMA_VERSION,
            "code": resolution.normalized,
            "family": resolution.family,
            "rootCause": resolution.root_cause,
            "likelyFix": resolution.likely_fix,
            "verifyWith": "fz check <path> --json",
            "diagnosticIdentity": "codes are stable within a domain for unchanged message and source anchor",
            "catalog": resolution.catalog_entry,
            "catalogKey": resolution.catalog_key,
            "commonTriggers": resolution.common_triggers,
            "productionAction": resolution.production_action,
            "productionRisk": resolution.production_risk,
            "nextCommand": resolution.next_command,
            "explainCommand": resolution.explain_command,
        })
        .to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiagnosticCatalogEntry {
    key: String,
    code_prefix: String,
    family: String,
    summary: String,
    example: String,
    likely_fix: String,
    common_triggers: Vec<String>,
    production_action: String,
    production_risk: String,
    next_command: String,
}

#[derive(Debug, Clone)]
pub(crate) struct DiagnosticExplainResolution {
    pub normalized: String,
    pub family: String,
    pub root_cause: String,
    pub likely_fix: String,
    pub catalog_entry: Option<DiagnosticCatalogEntry>,
    pub catalog_key: Option<String>,
    pub common_triggers: Vec<String>,
    pub production_action: Option<String>,
    pub production_risk: Option<String>,
    pub next_command: String,
    pub explain_command: String,
}

pub(crate) fn resolve_diagnostic_explain(raw: &str) -> DiagnosticExplainResolution {
    let normalized = raw.trim().to_ascii_uppercase();
    let catalog = diagnostic_catalog();
    let catalog_entry = catalog
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case(raw))
        .cloned()
        .or_else(|| {
            catalog
                .iter()
                .find(|entry| normalized.starts_with(&entry.code_prefix))
                .cloned()
        });
    let family = catalog_entry
        .as_ref()
        .map(|entry| entry.family.clone())
        .unwrap_or_else(|| {
            if normalized.starts_with("E-PAR-") || normalized.starts_with("W-PAR-") {
                "parser".to_string()
            } else if normalized.starts_with("E-HIR-") || normalized.starts_with("W-HIR-") {
                "hir".to_string()
            } else if normalized.starts_with("E-VER-") || normalized.starts_with("W-VER-") {
                "verifier".to_string()
            } else if normalized.starts_with("E-NAT-") || normalized.starts_with("W-NAT-") {
                "native-lowering".to_string()
            } else if normalized.starts_with("E-DRV-") || normalized.starts_with("W-DRV-") {
                "driver".to_string()
            } else {
                "unknown".to_string()
            }
        });
    let likely_fix = catalog_entry
        .as_ref()
        .map(|entry| entry.likely_fix.clone())
        .unwrap_or_else(|| match family.as_str() {
            "parser" => "Fix syntax at the primary span, then rerun `fz check <path>`.".to_string(),
            "hir" => "Fix name/type mismatch and rerun `fz check <path>`.".to_string(),
            "verifier" => {
                "Fix policy/type contract violation and rerun `fz verify <path>`.".to_string()
            }
            "native-lowering" => {
                "Adjust unsupported lowering shape or switch backend, then rerun `fz build <path>`."
                    .to_string()
            }
            "driver" => {
                "Fix project/configuration issue and rerun the failing command.".to_string()
            }
            _ => {
                "Run `fz check <path>` to regenerate diagnostics with spans and helps.".to_string()
            }
        });
    let root_cause = catalog_entry
        .as_ref()
        .map(|entry| entry.summary.clone())
        .unwrap_or_else(|| format!("diagnostic family `{family}`"));
    let next_command = catalog_entry
        .as_ref()
        .map(|entry| entry.next_command.clone())
        .unwrap_or_else(|| "fz check <path> --json".to_string());
    let explain_target = catalog_entry
        .as_ref()
        .map(|entry| entry.key.clone())
        .unwrap_or_else(|| normalized.clone());
    DiagnosticExplainResolution {
        normalized,
        family,
        root_cause,
        likely_fix,
        catalog_key: catalog_entry.as_ref().map(|entry| entry.key.clone()),
        common_triggers: catalog_entry
            .as_ref()
            .map(|entry| entry.common_triggers.clone())
            .unwrap_or_default(),
        production_action: catalog_entry
            .as_ref()
            .map(|entry| entry.production_action.clone()),
        production_risk: catalog_entry
            .as_ref()
            .map(|entry| entry.production_risk.clone()),
        next_command,
        explain_command: format!("fz explain {explain_target}"),
        catalog_entry,
    }
}
