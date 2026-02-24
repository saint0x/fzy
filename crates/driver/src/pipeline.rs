use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
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
        });
    }
    if !input.is_dir() {
        return Err(anyhow!(
            "path is neither a source file nor a project directory: {}",
            input.display()
        ));
    }

    let (manifest, manifest_path) = load_manifest(input)?;

    let relative = manifest
        .primary_bin_path()
        .ok_or_else(|| anyhow!("no [[target.bin]] entry in {}", manifest_path.display()))?;
    Ok(ResolvedSource {
        source_path: input.join(relative),
        project_root: input.to_path_buf(),
        manifest: Some(manifest),
    })
}

fn load_manifest(dir: &Path) -> Result<(manifest::Manifest, std::path::PathBuf)> {
    let primary = dir.join("fozzy.toml");
    let contents = std::fs::read_to_string(&primary)
        .with_context(|| format!("no valid compiler manifest found at {}", primary.display()))?;
    let parsed = manifest::load(&contents).context("failed parsing fozzy.toml")?;
    parsed
        .validate()
        .map_err(|err| anyhow!("invalid fozzy.toml: {err}"))?;
    validate_dependency_paths(dir, &parsed)?;
    Ok((parsed, primary))
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

fn emit_native_artifact(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<PathBuf> {
    let backend = std::env::var("FOZZYC_NATIVE_BACKEND")
        .unwrap_or_else(|_| "llvm".to_string())
        .to_ascii_lowercase();
    match backend.as_str() {
        "llvm" => emit_native_artifact_llvm(fir, project_root, profile, manifest),
        "c_shim" => emit_native_artifact_c_shim(fir, project_root, profile, manifest),
        other => Err(anyhow!(
            "unknown FOZZYC_NATIVE_BACKEND `{}`; expected `llvm` or `c_shim`",
            other
        )),
    }
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

    let mut candidates = vec!["clang", "cc", "gcc"];
    let mut last_error = None;
    for tool in candidates.drain(..) {
        let mut cmd = Command::new(tool);
        cmd.arg("-x")
            .arg("ir")
            .arg(&ll_path)
            .arg("-o")
            .arg(&bin_path);
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

fn emit_native_artifact_c_shim(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<PathBuf> {
    let build_dir = project_root.join(".fozzyc").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let c_path = build_dir.join(format!("{}.c", fir.name));
    let bin_path = build_dir.join(fir.name.as_str());
    let entry_return = fir.entry_return_const_i32.unwrap_or(0);
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);

    let mut c_source = String::from("#include <stdint.h>\nint main(void) {\n");
    if enforce_contract_checks {
        for condition in &fir.entry_requires {
            let guard = if matches!(condition, Some(false)) {
                "0"
            } else {
                "1"
            };
            c_source.push_str(&format!("  if (!({guard})) {{ return 120; }}\n"));
        }
    }
    c_source.push_str(&format!("  int __fozzy_ret = {entry_return};\n"));
    if enforce_contract_checks {
        for condition in &fir.entry_ensures {
            let guard = if matches!(condition, Some(false)) {
                "0"
            } else {
                "1"
            };
            c_source.push_str(&format!("  if (!({guard})) {{ return 121; }}\n"));
        }
    }
    c_source.push_str("  return __fozzy_ret;\n}\n");
    std::fs::write(&c_path, c_source)
        .with_context(|| format!("failed writing c source: {}", c_path.display()))?;

    let mut candidates = vec!["cc", "clang", "gcc"];
    let mut last_error = None;
    for tool in candidates.drain(..) {
        let mut cmd = Command::new(tool);
        cmd.arg(&c_path).arg("-o").arg(&bin_path);
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
        "failed to compile c_shim native artifact: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
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

    use super::{compile_file, emit_ir, parse_program, BuildProfile};

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
