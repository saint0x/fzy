use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use cranelift_codegen::ir::{types, AbiParam, InstBuilder};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_module::{default_libcall_names, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildProfile {
    Dev,
    Release,
    Verify,
}

#[derive(Debug, Clone)]
pub struct BuildArtifact {
    pub module: String,
    pub profile: BuildProfile,
    pub status: &'static str,
    pub diagnostics: usize,
    pub output: Option<PathBuf>,
    pub dependency_graph_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Output {
    pub module: String,
    pub nodes: usize,
    pub diagnostics: usize,
    pub diagnostic_details: Vec<diagnostics::Diagnostic>,
    pub backend_ir: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedProgram {
    pub module: ast::Module,
    pub combined_source: String,
    pub module_paths: Vec<PathBuf>,
}

pub fn compile_file(path: &Path, profile: BuildProfile) -> Result<BuildArtifact> {
    compile_file_with_backend(path, profile, None)
}

pub fn compile_file_with_backend(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<BuildArtifact> {
    let resolved = resolve_source_path(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let typed = hir::lower(&parsed.module);
    let fir = fir::build(&typed);
    let report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: matches!(profile, BuildProfile::Verify),
        },
    );

    let checks_enabled = resolved
        .manifest
        .as_ref()
        .and_then(|manifest| profile_config(manifest, profile).and_then(|config| config.checks))
        .unwrap_or(true);
    let has_errors = report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let status = if checks_enabled && has_errors {
        "error"
    } else {
        "ok"
    };
    let output = if status == "ok" {
        Some(emit_native_artifact(
            &fir,
            &resolved.project_root,
            profile,
            resolved.manifest.as_ref(),
            backend_override,
        )?)
    } else {
        None
    };

    Ok(BuildArtifact {
        module: fir.name,
        profile,
        status,
        diagnostics: report.diagnostics.len(),
        output,
        dependency_graph_hash: resolved.dependency_graph_hash,
    })
}

pub fn verify_file(path: &Path) -> Result<Output> {
    let resolved = resolve_source_path(path)?;
    let module_name = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;
    let parsed = match parse_program(&resolved.source_path) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Ok(Output {
                module: module_name.to_string(),
                nodes: 0,
                diagnostics: 1,
                diagnostic_details: vec![diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    error.to_string(),
                    None,
                )],
                backend_ir: None,
            });
        }
    };
    let typed = hir::lower(&parsed.module);
    let fir = fir::build(&typed);
    let report = verifier::verify(&fir);
    let diagnostics = report.diagnostics;

    Ok(Output {
        module: fir.name,
        nodes: fir.nodes,
        diagnostics: diagnostics.len(),
        diagnostic_details: diagnostics,
        backend_ir: None,
    })
}

pub fn emit_ir(path: &Path) -> Result<Output> {
    let resolved = resolve_source_path(path)?;
    let source_path = resolved.source_path;
    let module_name = source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;

    let parsed = match parse_program(&source_path) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Ok(Output {
                module: module_name.to_string(),
                nodes: 0,
                diagnostics: 1,
                diagnostic_details: vec![diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    error.to_string(),
                    None,
                )],
                backend_ir: None,
            });
        }
    };
    let typed = hir::lower(&parsed.module);
    let fir = fir::build(&typed);
    let report = verifier::verify(&fir);
    let diagnostics = report.diagnostics;
    let llvm = lower_backend_ir(&fir, BackendKind::Llvm);
    let cranelift = lower_backend_ir(&fir, BackendKind::Cranelift);

    Ok(Output {
        module: fir.name,
        nodes: fir.nodes,
        diagnostics: diagnostics.len(),
        diagnostic_details: diagnostics,
        backend_ir: Some(format!(
            "; backend=llvm\n{llvm}\n; backend=cranelift\n{cranelift}\n"
        )),
    })
}

pub fn parse_program(source_path: &Path) -> Result<ParsedProgram> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    let mut state = ModuleLoadState::default();
    load_module_recursive(&canonical, &mut state)?;

    let root = state
        .loaded
        .get(&canonical)
        .ok_or_else(|| anyhow!("failed to load root module {}", canonical.display()))?;
    let mut merged = root.ast.clone();
    let mut combined_source = String::new();

    for path in &state.load_order {
        let loaded = state
            .loaded
            .get(path)
            .ok_or_else(|| anyhow!("internal module cache miss for {}", path.display()))?;
        combined_source.push_str("// module: ");
        combined_source.push_str(&loaded.path.display().to_string());
        combined_source.push('\n');
        combined_source.push_str(&loaded.source);
        if !loaded.source.ends_with('\n') {
            combined_source.push('\n');
        }
    }

    for path in state.load_order.iter().filter(|path| **path != canonical) {
        let loaded = state
            .loaded
            .get(path)
            .ok_or_else(|| anyhow!("internal module cache miss for {}", path.display()))?;
        merge_module(&mut merged, &loaded.ast);
    }

    Ok(ParsedProgram {
        module: merged,
        combined_source,
        module_paths: state.load_order,
    })
}

#[derive(Debug, Clone)]
struct LoadedModule {
    ast: ast::Module,
    source: String,
    path: PathBuf,
}

#[derive(Debug, Default)]
struct ModuleLoadState {
    loaded: HashMap<PathBuf, LoadedModule>,
    load_order: Vec<PathBuf>,
    visiting: Vec<PathBuf>,
    visiting_set: HashSet<PathBuf>,
}

fn load_module_recursive(path: &Path, state: &mut ModuleLoadState) -> Result<()> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed resolving module path: {}", path.display()))?;
    if state.loaded.contains_key(&canonical) {
        return Ok(());
    }
    if state.visiting_set.contains(&canonical) {
        let cycle = format_module_cycle(&state.visiting, &canonical);
        return Err(anyhow!("cyclic module declaration detected: {}", cycle));
    }

    state.visiting_set.insert(canonical.clone());
    state.visiting.push(canonical.clone());

    let source = std::fs::read_to_string(&canonical)
        .with_context(|| format!("failed reading source file: {}", canonical.display()))?;
    let module_name = canonical
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", canonical.display()))?;
    let ast = parser::parse(&source, module_name).map_err(|diagnostics| {
        anyhow!(
            "parse failed for {} with {} diagnostics",
            canonical.display(),
            diagnostics.len()
        )
    })?;

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
        load_module_recursive(&module_path, state)?;
    }

    state.visiting.pop();
    state.visiting_set.remove(&canonical);
    state.load_order.push(canonical.clone());
    state.loaded.insert(
        canonical.clone(),
        LoadedModule {
            ast,
            source,
            path: canonical,
        },
    );
    Ok(())
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

fn merge_module(root: &mut ast::Module, module: &ast::Module) {
    root.items.extend(module.items.iter().cloned());
    root.modules.extend(module.modules.iter().cloned());
    root.imports.extend(module.imports.iter().cloned());
    root.capabilities
        .extend(module.capabilities.iter().cloned());
    root.inferred_capabilities
        .extend(module.inferred_capabilities.iter().cloned());
    root.host_syscall_sites += module.host_syscall_sites;
    root.unsafe_reasoned_sites += module.unsafe_reasoned_sites;
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

#[derive(Debug, Clone, Copy)]
enum BackendKind {
    Llvm,
    Cranelift,
}

fn lower_backend_ir(fir: &fir::FirModule, backend: BackendKind) -> String {
    match backend {
        BackendKind::Llvm => lower_llvm_ir(fir, true),
        BackendKind::Cranelift => lower_cranelift_ir(fir, true),
    }
}

fn lower_llvm_ir(fir: &fir::FirModule, enforce_contract_checks: bool) -> String {
    let ret = if enforce_contract_checks {
        if fir
            .entry_requires
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            120
        } else if fir
            .entry_ensures
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            121
        } else {
            fir.entry_return_const_i32.unwrap_or(0)
        }
    } else {
        fir.entry_return_const_i32.unwrap_or(0)
    };
    format!(
        "; ModuleID = '{name}'\ndefine i32 @main() {{\nentry:\n  ret i32 {ret}\n}}\n",
        name = fir.name
    )
}

fn lower_cranelift_ir(fir: &fir::FirModule, enforce_contract_checks: bool) -> String {
    let ret = if enforce_contract_checks {
        if fir
            .entry_requires
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            120
        } else if fir
            .entry_ensures
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            121
        } else {
            fir.entry_return_const_i32.unwrap_or(0)
        }
    } else {
        fir.entry_return_const_i32.unwrap_or(0)
    };
    format!("function %main() -> i32 {{\nblock0:\n  v0 = iconst.i32 {ret}\n  return v0\n}}\n")
}

struct ResolvedSource {
    source_path: PathBuf,
    project_root: PathBuf,
    manifest: Option<manifest::Manifest>,
    dependency_graph_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockfileMode {
    ValidateOrCreate,
    ForceRewrite,
}

fn resolve_source_path(input: &Path) -> Result<ResolvedSource> {
    if input.is_file() {
        let root = input
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(ResolvedSource {
            source_path: input.to_path_buf(),
            project_root: root,
            manifest: None,
            dependency_graph_hash: None,
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

    let relative = manifest
        .primary_bin_path()
        .ok_or_else(|| anyhow!("no [[target.bin]] entry in {}", manifest_path.display()))?;
    Ok(ResolvedSource {
        source_path: input.join(relative),
        project_root: input.to_path_buf(),
        manifest: Some(manifest),
        dependency_graph_hash: Some(dependency_graph_hash),
    })
}

fn load_manifest(
    dir: &Path,
    lock_mode: LockfileMode,
) -> Result<(manifest::Manifest, std::path::PathBuf, String)> {
    let primary = dir.join("fozzy.toml");
    let contents = std::fs::read_to_string(&primary)
        .with_context(|| format!("no valid compiler manifest found at {}", primary.display()))?;
    let parsed = manifest::load(&contents).context("failed parsing fozzy.toml")?;
    parsed
        .validate()
        .map_err(|err| anyhow!("invalid fozzy.toml: {err}"))?;
    validate_dependency_paths(dir, &parsed)?;
    let graph_hash = write_lockfile(dir, &parsed, &contents, lock_mode)?;
    Ok((parsed, primary, graph_hash))
}

fn validate_dependency_paths(dir: &Path, manifest: &manifest::Manifest) -> Result<()> {
    for (name, dependency) in &manifest.deps {
        let manifest::Dependency::Path { path } = dependency;
        let resolved = dir.join(path);
        if !resolved.exists() {
            return Err(anyhow!(
                "path dependency `{}` not found at {}",
                name,
                resolved.display()
            ));
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
                    return Err(anyhow!(
                        "lockfile drift detected at {}: expected dependencyGraphHash={} (run `fozzyc vendor {}` to refresh)",
                        lock_path.display(),
                        graph_hash,
                        dir.display()
                    ));
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
        let manifest::Dependency::Path { path } = dependency;
        let resolved = dir.join(path);
        let canonical = resolved.canonicalize().with_context(|| {
            format!(
                "failed canonicalizing path dependency `{}` at {}",
                name,
                resolved.display()
            )
        })?;
        let dep_manifest_path = canonical.join("fozzy.toml");
        let dep_manifest_text = std::fs::read_to_string(&dep_manifest_path).with_context(|| {
            format!(
                "path dependency `{}` missing manifest at {}",
                name,
                dep_manifest_path.display()
            )
        })?;
        let dep_manifest = manifest::load(&dep_manifest_text).with_context(|| {
            format!(
                "failed parsing dependency manifest for `{}` at {}",
                name,
                dep_manifest_path.display()
            )
        })?;
        dep_manifest.validate().map_err(|err| {
            anyhow!(
                "invalid dependency manifest for `{}` at {}: {}",
                name,
                dep_manifest_path.display(),
                err
            )
        })?;
        let dep_source_hash = hash_directory_tree(&canonical)?;
        dep_entries.push(serde_json::json!({
            "name": name,
            "path": normalize_rel_path(path),
            "canonicalPath": canonical.display().to_string(),
            "package": {
                "name": dep_manifest.package.name,
                "version": dep_manifest.package.version,
            },
            "manifestHash": sha256_hex(dep_manifest_text.as_bytes()),
            "sourceHash": dep_source_hash,
        }));
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

fn hash_directory_tree(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect_files_recursive(root, root, &mut files)?;
    let mut hasher = Sha256::new();
    for (rel, full) in files {
        hasher.update(rel.as_bytes());
        let bytes = std::fs::read(&full).with_context(|| {
            format!(
                "failed reading dependency file for hashing: {}",
                full.display()
            )
        })?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

fn collect_files_recursive(
    root: &Path,
    current: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
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
            out.push((rel_str, full));
        }
    }
    Ok(())
}

fn should_skip_hash_path(rel: &str) -> bool {
    rel.starts_with(".git/")
        || rel.starts_with(".fozzyc/")
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

fn emit_native_artifact(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
) -> Result<PathBuf> {
    let backend = resolve_native_backend(profile, backend_override)?;
    match backend.as_str() {
        "llvm" => emit_native_artifact_llvm(fir, project_root, profile, manifest),
        "cranelift" => emit_native_artifact_cranelift(fir, project_root, profile, manifest),
        other => Err(anyhow!(
            "unknown FOZZYC_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
            other
        )),
    }
}

fn resolve_native_backend(profile: BuildProfile, backend_override: Option<&str>) -> Result<String> {
    if let Some(explicit) = backend_override {
        let normalized = explicit.trim().to_ascii_lowercase();
        return match normalized.as_str() {
            "llvm" | "cranelift" => Ok(normalized),
            other => Err(anyhow!(
                "unknown backend `{}`; expected `llvm` or `cranelift`",
                other
            )),
        };
    }
    if let Ok(explicit) = std::env::var("FOZZYC_NATIVE_BACKEND") {
        let normalized = explicit.trim().to_ascii_lowercase();
        return match normalized.as_str() {
            "llvm" | "cranelift" => Ok(normalized),
            other => Err(anyhow!(
                "unknown FOZZYC_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
                other
            )),
        };
    }
    Ok(match profile {
        BuildProfile::Release => "llvm".to_string(),
        BuildProfile::Dev => "cranelift".to_string(),
        BuildProfile::Verify => "llvm".to_string(),
    })
}

fn emit_native_artifact_llvm(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<PathBuf> {
    let build_dir = project_root.join(".fozzyc").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let ll_path = build_dir.join(format!("{}.ll", fir.name));
    let bin_path = build_dir.join(fir.name.as_str());
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let llvm_ir = lower_llvm_ir(fir, enforce_contract_checks);
    std::fs::write(&ll_path, llvm_ir)
        .with_context(|| format!("failed writing llvm ir: {}", ll_path.display()))?;

    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("-x")
            .arg("ir")
            .arg(&ll_path)
            .arg("-o")
            .arg(&bin_path);
        apply_target_link_flags(&mut cmd);
        let optimize_override = manifest
            .and_then(|manifest| profile_config(manifest, profile))
            .and_then(|config| config.optimize);
        match (profile, optimize_override) {
            (_, Some(true)) => {
                cmd.arg("-O2");
            }
            (_, Some(false)) => {
                cmd.arg("-O0");
            }
            (BuildProfile::Dev, None) => {
                cmd.arg("-O0");
            }
            (BuildProfile::Release, None) => {
                cmd.arg("-O2");
            }
            (BuildProfile::Verify, None) => {
                cmd.arg("-O1").arg("-g");
            }
        }
        apply_extra_linker_args(&mut cmd);

        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(bin_path),
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }

    Err(anyhow!(
        "failed to compile llvm native artifact: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}

fn emit_native_artifact_cranelift(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<PathBuf> {
    let build_dir = project_root.join(".fozzyc").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let object_path = build_dir.join(format!("{}.o", fir.name));
    let bin_path = build_dir.join(fir.name.as_str());
    let mut flags_builder = settings::builder();
    let optimize_override = manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.optimize);
    let opt_level = match (profile, optimize_override) {
        (_, Some(true)) => "speed",
        (_, Some(false)) => "none",
        (BuildProfile::Dev, None) => "none",
        (BuildProfile::Release, None) => "speed",
        (BuildProfile::Verify, None) => "speed",
    };
    flags_builder
        .set("opt_level", opt_level)
        .map_err(|error| anyhow!("failed setting cranelift opt_level={opt_level}: {error}"))?;
    let flags = settings::Flags::new(flags_builder);
    let isa_builder = cranelift_native::builder()
        .map_err(|error| anyhow!("failed constructing cranelift native isa: {error}"))?;
    let isa = isa_builder
        .finish(flags)
        .map_err(|error| anyhow!("failed finalizing cranelift isa: {error}"))?;

    let object_builder = ObjectBuilder::new(isa, fir.name.clone(), default_libcall_names())
        .map_err(|error| anyhow!("failed creating cranelift object builder: {error}"))?;
    let mut module = ObjectModule::new(object_builder);
    let mut context = module.make_context();
    context
        .func
        .signature
        .returns
        .push(AbiParam::new(types::I32));

    let function_id = module
        .declare_function("main", Linkage::Export, &context.func.signature)
        .map_err(|error| anyhow!("failed declaring cranelift main symbol: {error}"))?;
    let mut function_builder_context = FunctionBuilderContext::new();
    let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
    let block = builder.create_block();
    builder.switch_to_block(block);
    builder.seal_block(block);
    let entry_return = computed_entry_return(fir, !matches!(profile, BuildProfile::Release));
    let ret = builder.ins().iconst(types::I32, entry_return as i64);
    builder.ins().return_(&[ret]);
    builder.finalize();

    module
        .define_function(function_id, &mut context)
        .map_err(|error| anyhow!("failed defining cranelift function body: {error}"))?;
    module.clear_context(&mut context);
    let object_product = module.finish();
    let object_bytes = object_product
        .emit()
        .map_err(|error| anyhow!("failed emitting cranelift object bytes: {error}"))?;
    std::fs::write(&object_path, object_bytes)
        .with_context(|| format!("failed writing cranelift object: {}", object_path.display()))?;

    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg(&object_path).arg("-o").arg(&bin_path);
        apply_target_link_flags(&mut cmd);
        // Object code is already generated at selected Cranelift optimization level.
        apply_extra_linker_args(&mut cmd);

        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(bin_path),
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }

    Err(anyhow!(
        "failed to link cranelift native artifact: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}

fn computed_entry_return(fir: &fir::FirModule, enforce_contract_checks: bool) -> i32 {
    if enforce_contract_checks {
        if fir
            .entry_requires
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            return 120;
        }
        if fir
            .entry_ensures
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            return 121;
        }
    }
    fir.entry_return_const_i32.unwrap_or(0)
}

fn linker_candidates() -> Vec<String> {
    if let Ok(explicit) = std::env::var("FOZZYC_CC") {
        if !explicit.trim().is_empty() {
            return vec![explicit];
        }
    }
    let mut candidates = Vec::new();
    let target = std::env::var("TARGET")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if target.contains("apple-darwin") {
        candidates.push("clang".to_string());
        candidates.push("cc".to_string());
        candidates.push("gcc".to_string());
    } else if target.contains("linux") {
        candidates.push("cc".to_string());
        candidates.push("clang".to_string());
        candidates.push("gcc".to_string());
    } else {
        candidates.push("clang".to_string());
        candidates.push("cc".to_string());
        candidates.push("gcc".to_string());
    }
    candidates
}

fn apply_target_link_flags(cmd: &mut Command) {
    if let Ok(target) = std::env::var("TARGET") {
        let target = target.trim();
        if !target.is_empty() {
            cmd.arg("-target").arg(target);
        }
    }
}

fn apply_extra_linker_args(cmd: &mut Command) {
    if let Ok(extra) = std::env::var("FOZZYC_LINKER_ARGS") {
        for arg in extra.split_whitespace() {
            if !arg.trim().is_empty() {
                cmd.arg(arg);
            }
        }
    }
}

fn profile_config(
    manifest: &manifest::Manifest,
    profile: BuildProfile,
) -> Option<&manifest::Profile> {
    match profile {
        BuildProfile::Dev => manifest.profiles.dev.as_ref(),
        BuildProfile::Release => manifest.profiles.release.as_ref(),
        BuildProfile::Verify => manifest.profiles.verify.as_ref(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        compile_file, compile_file_with_backend, emit_ir, parse_program, refresh_lockfile,
        BuildProfile,
    };

    #[test]
    fn compile_file_runs_pipeline() {
        let file_name = format!(
            "fozzylang-pipeline-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "use cap.time;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should compile");
        assert_eq!(artifact.module, path.file_stem().unwrap().to_string_lossy());
        assert_eq!(artifact.status, "ok");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn compile_project_directory_uses_manifest_target() {
        let project_name = format!(
            "fozzylang-project-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use cap.time;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
        assert_eq!(artifact.module, "main");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compile_project_uses_capabilities_from_declared_modules() {
        let project_name = format!(
            "fozzylang-mod-cap-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod infra;\nfn main() -> i32 {\n    let c = net.connect()\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/infra.fzy"), "use cap.net;\n")
            .expect("module source should be written");

        let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
        assert_eq!(artifact.status, "ok");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compile_with_verify_errors_skips_native_output() {
        let file_name = format!(
            "fozzylang-error-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let c = net.connect()\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should run");
        assert_eq!(artifact.status, "error");
        assert!(artifact.output.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn compile_project_fails_for_missing_path_dependency() {
        let project_name = format!(
            "fozzylang-deps-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let error = compile_file(&root, BuildProfile::Dev).expect_err("build should fail");
        assert!(error.to_string().contains("path dependency"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compile_project_fails_when_lockfile_drifts() {
        let project_name = format!(
            "fozzylang-lock-drift-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        let dep_dir = root.join("deps/util");
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::create_dir_all(dep_dir.join("src")).expect("dep src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        std::fs::write(
            dep_dir.join("fozzy.toml"),
            "[package]\nname=\"util\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"util\"\npath=\"src/main.fzy\"\n",
        )
        .expect("dep manifest should be written");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("dep source should be written");

        let first = compile_file(&root, BuildProfile::Dev).expect("first build should succeed");
        assert_eq!(first.status, "ok");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 1\n}\n",
        )
        .expect("dep source should mutate");
        let error = compile_file(&root, BuildProfile::Dev).expect_err("drift should fail build");
        assert!(error.to_string().contains("lockfile drift detected"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn refresh_lockfile_unblocks_drifted_project_build() {
        let project_name = format!(
            "fozzylang-lock-refresh-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        let dep_dir = root.join("deps/util");
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::create_dir_all(dep_dir.join("src")).expect("dep src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        std::fs::write(
            dep_dir.join("fozzy.toml"),
            "[package]\nname=\"util\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"util\"\npath=\"src/main.fzy\"\n",
        )
        .expect("dep manifest should be written");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("dep source should be written");

        compile_file(&root, BuildProfile::Dev).expect("first build should succeed");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 2\n}\n",
        )
        .expect("dep source should mutate");
        refresh_lockfile(&root).expect("refresh lockfile should succeed");
        let artifact = compile_file(&root, BuildProfile::Dev).expect("build should recover");
        assert_eq!(artifact.status, "ok");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn profile_checks_can_be_disabled() {
        let project_name = format!(
            "fozzylang-profile-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[profiles.dev]\nchecks=false\noptimize=false\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    let c = net.connect()\n    return 0\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file(&root, BuildProfile::Dev).expect("build should run");
        assert_eq!(artifact.status, "ok");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_profile_rejects_unsafe_capabilities_even_if_declared() {
        let file_name = format!(
            "fozzylang-safe-profile-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "use cap.net;\nfn main() -> i32 {\n    let c = net.connect()\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Verify).expect("pipeline should run");
        assert_eq!(artifact.status, "error");
        assert!(artifact.output.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn compile_rejects_false_contracts() {
        let file_name = format!(
            "fozzylang-contract-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    requires false\n    ensures false\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should run");
        assert_eq!(artifact.status, "error");
        assert!(artifact.output.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn emit_ir_includes_llvm_and_cranelift_forms() {
        let file_name = format!(
            "fozzylang-ir-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(&path, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("temp source should be written");

        let output = emit_ir(&path).expect("emit ir should run");
        let ir = output.backend_ir.expect("backend ir should be available");
        assert!(ir.contains("backend=llvm"));
        assert!(ir.contains("backend=cranelift"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn backend_override_rejects_removed_c_shim() {
        let file_name = format!(
            "fozzylang-backend-removed-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(&path, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("temp source should be written");

        let error = compile_file_with_backend(&path, BuildProfile::Dev, Some("c_shim"))
            .expect_err("removed backend must fail");
        assert!(error.to_string().contains("unknown backend"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn backend_defaults_dev_cranelift_release_llvm() {
        let project_name = format!(
            "fozzylang-backend-defaults-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
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
        .expect("source should be written");

        let dev = compile_file_with_backend(&root, BuildProfile::Dev, None)
            .expect("dev build should succeed");
        assert_eq!(dev.status, "ok");
        assert!(root.join(".fozzyc/build/main.o").exists());

        let release = compile_file_with_backend(&root, BuildProfile::Release, None)
            .expect("release build should succeed");
        assert_eq!(release.status, "ok");
        assert!(root.join(".fozzyc/build/main.ll").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parse_program_fails_for_missing_declared_module() {
        let root_name = format!(
            "fozzylang-mod-missing-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(root_name);
        std::fs::create_dir_all(&root).expect("temp dir should be created");
        let path = root.join("main.fzy");
        std::fs::write(&path, "mod util;\nfn main() -> i32 {\n    return 0\n}\n")
            .expect("root source should be written");

        let error = parse_program(&path).expect_err("missing module should fail parsing");
        assert!(error.to_string().contains("resolving module `util`"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parse_program_detects_cycle() {
        let root_name = format!(
            "fozzylang-mod-cycle-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(root_name);
        std::fs::create_dir_all(&root).expect("temp dir should be created");
        let main = root.join("main.fzy");
        let a = root.join("a.fzy");
        let b = root.join("b.fzy");
        std::fs::write(&main, "mod a;\nfn main() -> i32 {\n return 0\n}\n")
            .expect("main source should be written");
        std::fs::write(&a, "mod b;\n").expect("module a should be written");
        std::fs::write(&b, "mod a;\n").expect("module b should be written");

        let error = parse_program(&main).expect_err("cycle should fail parsing");
        assert!(error.to_string().contains("cyclic module declaration"));

        let _ = std::fs::remove_dir_all(root);
    }
}
