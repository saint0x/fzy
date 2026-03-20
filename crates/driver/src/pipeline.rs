use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use cranelift_codegen::ir::{types, AbiParam, MemFlags, Type as ClifType};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Switch, Variable};
use cranelift_module::{default_libcall_names, DataDescription, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use rayon::prelude::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Mutex, Once, OnceLock};
use std::time::UNIX_EPOCH;

mod llvm_support;
mod clif_support;
mod native_metadata;
mod native_backend_support;
mod native_runtime_support;
mod native_runtime_tables;
mod linker_support;

use self::clif_support::{
    ast_signature_type_to_clif_type, clif_emit_function_cfg, lower_cranelift_ir,
    variant_tag_for_key,
};
use self::linker_support::{
    apply_extra_linker_args, apply_manifest_link_args, apply_pgo_flags,
    apply_profile_optimization_flags, apply_target_link_flags, archiver_candidates,
    linker_candidates, profile_config, unsafe_contracts_enforced, unsafe_scope_policy,
};
use self::native_backend_support::{
    backend_capability_diagnostics, declare_native_data_plane_imports,
    declare_native_runtime_imports, experimental_feature_diagnostics,
    native_lowerability_diagnostics,
};
use self::llvm_support::{
    llvm_emit_binary_expr, llvm_emit_complex_expr, llvm_emit_simple_expr, lower_llvm_ir,
    llvm_float_literal, LlvmFuncCtx, LlvmValue,
};
use self::native_metadata::{
    build_global_const_i32_map, build_mutable_static_i32_map, build_string_literal_ids,
    build_variant_tag_map, collect_native_string_literals,
    collect_passthrough_function_map_from_module, collect_passthrough_function_map_from_typed,
    collect_spawn_task_symbols, collect_variant_keys_from_stmt, llvm_static_symbol_name,
};
use self::native_runtime_support::{
    collect_async_c_exports, collect_extern_c_imports, collect_used_native_data_plane_imports,
    collect_used_native_runtime_imports, compile_runtime_shim_object,
    ensure_native_runtime_shim, is_extern_c_abi_function, is_extern_c_import_decl,
    native_link_symbol_for_function, native_runtime_import_contract_errors,
};
use self::native_runtime_tables::{
    native_data_plane_import_for_callee, native_runtime_import_for_callee, NativeRuntimeImport,
    NATIVE_DATA_PLANE_IMPORTS, NATIVE_RUNTIME_IMPORTS,
};

#[derive(Clone, Copy)]
struct LocalBinding {
    var: Variable,
    ty: ClifType,
}

#[derive(Clone, Copy)]
struct ClifValue {
    value: cranelift_codegen::ir::Value,
    ty: ClifType,
}

#[derive(Clone)]
struct ClifFunctionSignature {
    params: Vec<ClifType>,
    ret: Option<ClifType>,
}

#[derive(Clone)]
struct ClifClosureBinding {
    params: Vec<ast::Param>,
    return_type: Option<ast::Type>,
    body: ast::Expr,
    captures: HashMap<String, LocalBinding>,
}

#[derive(Clone)]
struct ClifArrayBinding {
    stack_slot: cranelift_codegen::ir::StackSlot,
    len: usize,
    element_ty: ClifType,
    element_bits: u16,
    element_align: u8,
    element_stride: u8,
}

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
    pub diagnostic_details: Vec<diagnostics::Diagnostic>,
    pub output: Option<PathBuf>,
    pub dependency_graph_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LibraryArtifact {
    pub module: String,
    pub profile: BuildProfile,
    pub status: &'static str,
    pub diagnostics: usize,
    pub diagnostic_details: Vec<diagnostics::Diagnostic>,
    pub static_lib: Option<PathBuf>,
    pub shared_lib: Option<PathBuf>,
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

#[derive(Debug, Clone)]
struct ModuleStamp {
    path: PathBuf,
    bytes: u64,
    modified_ns: u128,
}

#[derive(Debug, Clone)]
struct ParsedProgramCacheEntry {
    parsed: ParsedProgram,
    stamps: Vec<ModuleStamp>,
}

#[derive(Debug, Clone)]
struct LowerCacheEntry {
    typed: hir::TypedModule,
    fir: fir::FirModule,
}

static PARSED_PROGRAM_CACHE: OnceLock<Mutex<HashMap<PathBuf, ParsedProgramCacheEntry>>> =
    OnceLock::new();
static LOWER_CACHE: OnceLock<Mutex<HashMap<String, LowerCacheEntry>>> = OnceLock::new();
static CODEGEN_POOL_INIT: Once = Once::new();

#[derive(Debug, Clone)]
struct PgoConfig {
    generate_dir: Option<PathBuf>,
    use_profile: Option<PathBuf>,
}

fn configured_codegen_jobs() -> Option<usize> {
    std::env::var("FZ_CODEGEN_JOBS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn ensure_codegen_pool_configured() {
    CODEGEN_POOL_INIT.call_once(|| {
        let Some(threads) = configured_codegen_jobs() else {
            return;
        };
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global();
    });
}

fn configured_pgo() -> PgoConfig {
    let generate_dir = std::env::var("FZ_PGO_GENERATE")
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty());
    let use_profile = std::env::var("FZ_PGO_USE")
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty());
    PgoConfig {
        generate_dir,
        use_profile,
    }
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
    let experimental_diagnostics =
        experimental_feature_diagnostics(&parsed.module, resolved.manifest.as_ref());
    let backend = resolve_native_backend(profile, backend_override)?;
    let pgo = configured_pgo();
    if (pgo.generate_dir.is_some() || pgo.use_profile.is_some()) && backend != "llvm" {
        bail!(
            "PGO is only supported with backend `llvm`; current backend is `{}`",
            backend
        );
    }
    let native_lowerability_errors = native_lowerability_diagnostics(&parsed.module);
    let backend_risks = backend_capability_diagnostics(&parsed.module, &backend, false);
    let (_typed, fir) = lower_fir_cached(&parsed);
    let strict_unsafe_contracts = unsafe_contracts_enforced(resolved.manifest.as_ref(), profile);
    let (deny_unsafe_in, allow_unsafe_in) = unsafe_scope_policy(resolved.manifest.as_ref());
    let report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: matches!(profile, BuildProfile::Verify),
            production_memory_safety: true,
            strict_unsafe_contracts,
            deny_unsafe_in,
            allow_unsafe_in,
        },
    );

    let checks_enabled = resolved
        .manifest
        .as_ref()
        .and_then(|manifest| profile_config(manifest, profile).and_then(|config| config.checks))
        .unwrap_or(true);
    let has_verifier_errors = report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_experimental_errors = experimental_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_native_lowerability_errors = !native_lowerability_errors.is_empty();
    let has_backend_risks = backend_risks
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let status = if has_experimental_errors
        || has_native_lowerability_errors
        || has_backend_risks
        || (checks_enabled && has_verifier_errors)
    {
        "error"
    } else {
        "ok"
    };
    let mut diagnostic_details = experimental_diagnostics;
    diagnostic_details.extend(native_lowerability_errors);
    diagnostic_details.extend(backend_risks);
    diagnostic_details.extend(report.diagnostics);
    normalize_diagnostics_for_path(&resolved.source_path, &mut diagnostic_details);
    let output = if status == "ok" {
        Some(emit_native_artifact(
            &fir,
            &resolved.project_root,
            profile,
            resolved.manifest.as_ref(),
            Some(backend.as_str()),
        )?)
    } else {
        None
    };

    Ok(BuildArtifact {
        module: fir.name,
        profile,
        status,
        diagnostics: diagnostic_details.len(),
        diagnostic_details,
        output,
        dependency_graph_hash: resolved.dependency_graph_hash,
    })
}

pub fn compile_library_with_backend(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<LibraryArtifact> {
    let resolved = resolve_source_path_with_target(path, true)?;
    let parsed = parse_program(&resolved.source_path)?;
    let experimental_diagnostics =
        experimental_feature_diagnostics(&parsed.module, resolved.manifest.as_ref());
    let requested_backend = resolve_native_backend(profile, backend_override)?;
    let backend = if requested_backend == "llvm" {
        if backend_override.is_some_and(|value| value.trim().eq_ignore_ascii_case("llvm")) {
            bail!(
                "backend `llvm` is not supported for `fz build --lib`; use `--backend cranelift`"
            );
        }
        "cranelift".to_string()
    } else {
        requested_backend
    };
    let pgo = configured_pgo();
    if (pgo.generate_dir.is_some() || pgo.use_profile.is_some()) && backend != "llvm" {
        bail!(
            "PGO is only supported with backend `llvm`; current backend is `{}`",
            backend
        );
    }
    let native_lowerability_errors = native_lowerability_diagnostics(&parsed.module);
    let backend_risks = backend_capability_diagnostics(&parsed.module, &backend, true);
    let (_typed, fir) = lower_fir_cached(&parsed);
    let strict_unsafe_contracts = unsafe_contracts_enforced(resolved.manifest.as_ref(), profile);
    let (deny_unsafe_in, allow_unsafe_in) = unsafe_scope_policy(resolved.manifest.as_ref());
    let report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: matches!(profile, BuildProfile::Verify),
            production_memory_safety: true,
            strict_unsafe_contracts,
            deny_unsafe_in,
            allow_unsafe_in,
        },
    );

    let checks_enabled = resolved
        .manifest
        .as_ref()
        .and_then(|manifest| profile_config(manifest, profile).and_then(|config| config.checks))
        .unwrap_or(true);
    let has_verifier_errors = report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_experimental_errors = experimental_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_native_lowerability_errors = !native_lowerability_errors.is_empty();
    let has_backend_risks = backend_risks
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let status = if has_experimental_errors
        || has_native_lowerability_errors
        || has_backend_risks
        || (checks_enabled && has_verifier_errors)
    {
        "error"
    } else {
        "ok"
    };
    let mut diagnostic_details = experimental_diagnostics;
    diagnostic_details.extend(native_lowerability_errors);
    diagnostic_details.extend(backend_risks);
    diagnostic_details.extend(report.diagnostics);
    normalize_diagnostics_for_path(&resolved.source_path, &mut diagnostic_details);
    let (static_lib, shared_lib) = if status == "ok" {
        emit_native_libraries(
            &fir,
            &resolved.project_root,
            profile,
            resolved.manifest.as_ref(),
            Some(backend.as_str()),
        )?
    } else {
        (None, None)
    };

    Ok(LibraryArtifact {
        module: fir.name,
        profile,
        status,
        diagnostics: diagnostic_details.len(),
        diagnostic_details,
        static_lib,
        shared_lib,
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
            let mut diagnostics =
                collect_parse_diagnostics(&resolved.source_path).unwrap_or_else(|_| {
                    vec![diagnostics::Diagnostic::new(
                        diagnostics::Severity::Error,
                        error.to_string(),
                        None,
                    )]
                });
            for diagnostic in &mut diagnostics {
                if diagnostic.path.is_none() {
                    diagnostic.path = Some(resolved.source_path.display().to_string());
                }
            }
            enrich_diagnostics_context(&mut diagnostics);
            diagnostics::assign_stable_codes(
                &mut diagnostics,
                diagnostics::DiagnosticDomain::Driver,
            );
            return Ok(Output {
                module: module_name.to_string(),
                nodes: 0,
                diagnostics: diagnostics.len(),
                diagnostic_details: diagnostics,
                backend_ir: None,
            });
        }
    };
    let mut diagnostics =
        experimental_feature_diagnostics(&parsed.module, resolved.manifest.as_ref());
    diagnostics.extend(native_lowerability_diagnostics(&parsed.module));
    let (_typed, fir) = lower_fir_cached(&parsed);
    let (deny_unsafe_in, allow_unsafe_in) = unsafe_scope_policy(resolved.manifest.as_ref());
    let report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: false,
            production_memory_safety: true,
            strict_unsafe_contracts: true,
            deny_unsafe_in,
            allow_unsafe_in,
        },
    );
    diagnostics.extend(report.diagnostics);
    for diagnostic in &mut diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(resolved.source_path.display().to_string());
        }
    }
    enrich_diagnostics_context(&mut diagnostics);
    diagnostics::assign_stable_codes(&mut diagnostics, diagnostics::DiagnosticDomain::Driver);

    Ok(Output {
        module: fir.name,
        nodes: fir.nodes,
        diagnostics: diagnostics.len(),
        diagnostic_details: diagnostics,
        backend_ir: None,
    })
}

fn normalize_diagnostics_for_path(path: &Path, diagnostics: &mut [diagnostics::Diagnostic]) {
    for diagnostic in diagnostics.iter_mut() {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(path.display().to_string());
        }
    }
    enrich_diagnostics_context(diagnostics);
    diagnostics::assign_stable_codes(diagnostics, diagnostics::DiagnosticDomain::Driver);
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
            let mut diagnostics = vec![diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                error.to_string(),
                None,
            )];
            for diagnostic in &mut diagnostics {
                if diagnostic.path.is_none() {
                    diagnostic.path = Some(source_path.display().to_string());
                }
            }
            enrich_diagnostics_context(&mut diagnostics);
            diagnostics::assign_stable_codes(
                &mut diagnostics,
                diagnostics::DiagnosticDomain::Driver,
            );
            return Ok(Output {
                module: module_name.to_string(),
                nodes: 0,
                diagnostics: diagnostics.len(),
                diagnostic_details: diagnostics,
                backend_ir: None,
            });
        }
    };
    let mut diagnostics = native_lowerability_diagnostics(&parsed.module);
    let (_typed, fir) = lower_fir_cached(&parsed);
    let report = verifier::verify(&fir);
    diagnostics.extend(report.diagnostics);
    for diagnostic in &mut diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(source_path.display().to_string());
        }
    }
    enrich_diagnostics_context(&mut diagnostics);
    diagnostics::assign_stable_codes(&mut diagnostics, diagnostics::DiagnosticDomain::Driver);
    let llvm = lower_backend_ir(&fir, BackendKind::Llvm)?;
    let cranelift = lower_backend_ir(&fir, BackendKind::Cranelift)?;

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
    if let Some(cached) = cached_parsed_program(&canonical) {
        return Ok(cached);
    }
    let parsed = parse_program_uncached(&canonical)?;
    store_parsed_program_cache(&canonical, &parsed);
    Ok(parsed)
}

pub fn lower_fir_cached(parsed: &ParsedProgram) -> (hir::TypedModule, fir::FirModule) {
    let module_hash = sha256_hex(parsed.combined_source.as_bytes());
    let cache = LOWER_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(cached) = guard.get(&module_hash) {
            return (cached.typed.clone(), cached.fir.clone());
        }
    }
    let typed = hir::lower(&parsed.module);
    let fir_module = fir::build_owned(typed.clone());
    if let Ok(mut guard) = cache.lock() {
        guard.insert(
            module_hash,
            LowerCacheEntry {
                typed: typed.clone(),
                fir: fir_module.clone(),
            },
        );
    }
    (typed, fir_module)
}

fn parse_program_uncached(canonical: &Path) -> Result<ParsedProgram> {
    let mut state = ModuleLoadState::default();
    discover_module_graph_recursive(canonical, &mut state)?;

    let loaded_modules = state
        .load_order
        .par_iter()
        .map(|path| parse_and_qualify_module(path, canonical, &state.discovered))
        .collect::<Result<Vec<_>>>()?;
    state.loaded = loaded_modules.into_iter().collect();

    let mut combined_source = String::new();
    for path in &state.load_order {
        let loaded = state
            .loaded
            .get(path)
            .ok_or_else(|| anyhow!("internal module cache miss for {}", path.display()))?;
        combined_source.push_str("// module: ");
        combined_source.push_str(&path.display().to_string());
        combined_source.push('\n');
        combined_source.push_str(&loaded.source);
        if !loaded.source.ends_with('\n') {
            combined_source.push('\n');
        }
    }
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
    canonicalize_call_targets(&mut merged);
    Ok(ParsedProgram {
        module: merged,
        combined_source,
        module_paths: state.load_order,
    })
}

fn module_stamp(path: &Path) -> Option<ModuleStamp> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let modified_ns = modified.duration_since(UNIX_EPOCH).ok()?.as_nanos();
    Some(ModuleStamp {
        path: path.to_path_buf(),
        bytes: meta.len(),
        modified_ns,
    })
}

fn cached_parsed_program(canonical: &Path) -> Option<ParsedProgram> {
    let cache = PARSED_PROGRAM_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let guard = cache.lock().ok()?;
    let entry = guard.get(canonical)?;
    if entry.stamps.iter().all(|stamp| {
        module_stamp(&stamp.path).is_some_and(|current| {
            current.bytes == stamp.bytes && current.modified_ns == stamp.modified_ns
        })
    }) {
        return Some(entry.parsed.clone());
    }
    None
}

fn store_parsed_program_cache(canonical: &Path, parsed: &ParsedProgram) {
    let stamps = parsed
        .module_paths
        .iter()
        .filter_map(|path| module_stamp(path))
        .collect::<Vec<_>>();
    let cache = PARSED_PROGRAM_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = cache.lock() {
        guard.insert(
            canonical.to_path_buf(),
            ParsedProgramCacheEntry {
                parsed: parsed.clone(),
                stamps,
            },
        );
    }
}

#[derive(Debug, Clone)]
struct LoadedModule {
    ast: ast::Module,
    source: String,
}

#[derive(Debug, Clone)]
struct DiscoveredModule {
    source: String,
    module_decls: Vec<String>,
}

#[derive(Debug, Default)]
struct ModuleLoadState {
    discovered: HashMap<PathBuf, DiscoveredModule>,
    loaded: HashMap<PathBuf, LoadedModule>,
    load_order: Vec<PathBuf>,
    visiting: Vec<PathBuf>,
    visiting_set: HashSet<PathBuf>,
}

fn discover_module_graph_recursive(path: &Path, state: &mut ModuleLoadState) -> Result<()> {
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

    let source = std::fs::read_to_string(&canonical)
        .with_context(|| format!("failed reading source file: {}", canonical.display()))?;
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
        discover_module_graph_recursive(&module_path, state)?;
    }

    state.visiting.pop();
    state.visiting_set.remove(&canonical);
    state.load_order.push(canonical.clone());
    state.discovered.insert(
        canonical,
        DiscoveredModule {
            source,
            module_decls: ast.modules,
        },
    );
    Ok(())
}

fn parse_and_qualify_module(
    module_path: &Path,
    root_source: &Path,
    discovered: &HashMap<PathBuf, DiscoveredModule>,
) -> Result<(PathBuf, LoadedModule)> {
    let discovered_module = discovered.get(module_path).ok_or_else(|| {
        anyhow!(
            "internal discovered module cache miss for {}",
            module_path.display()
        )
    })?;
    let module_name = module_path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", module_path.display()))?;
    let mut ast = parser::parse(&discovered_module.source, module_name)
        .map_err(|diagnostics| anyhow!(render_parse_failure(module_path, &diagnostics)))?;
    let namespace = module_namespace(root_source, module_path)?;
    qualify_module_symbols(&mut ast, &namespace);
    ast.modules = discovered_module.module_decls.clone();
    Ok((
        module_path.to_path_buf(),
        LoadedModule {
            ast,
            source: discovered_module.source.clone(),
        },
    ))
}

fn module_namespace(root_source: &Path, module_path: &Path) -> Result<String> {
    if module_path == root_source {
        return Ok(String::new());
    }
    let root_dir = root_source.parent().ok_or_else(|| {
        anyhow!(
            "root source has no parent directory: {}",
            root_source.display()
        )
    })?;
    let relative = module_path
        .strip_prefix(root_dir)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| module_path.to_path_buf());
    let mut components = relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .map(|component| component.to_string())
        .collect::<Vec<_>>();
    if components.is_empty() {
        return Ok(String::new());
    }
    let tail = components.pop().unwrap_or_default();
    let stem = Path::new(&tail)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !stem.is_empty() && stem != "mod" {
        components.push(stem.to_string());
    }
    Ok(components.join("."))
}

fn qualify_module_symbols(module: &mut ast::Module, namespace: &str) {
    let local_functions = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) => Some(function.name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut module_aliases = module
        .modules
        .iter()
        .map(|module_name| {
            (
                module_name.clone(),
                qualify_name(namespace, module_name.as_str()),
            )
        })
        .collect::<HashMap<_, _>>();
    for (alias, target) in import_aliases(module, &module_aliases) {
        module_aliases.insert(alias, target);
    }

    for item in &mut module.items {
        match item {
            ast::Item::Function(function) => {
                qualify_function(function, namespace, &local_functions, &module_aliases);
            }
            ast::Item::Test(test) => {
                for stmt in &mut test.body {
                    qualify_stmt(stmt, namespace, &local_functions, &module_aliases);
                }
            }
            _ => {}
        }
    }
}

fn import_aliases(
    module: &ast::Module,
    module_aliases: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    for import in &module.imports {
        if import.wildcard || import.path.is_empty() {
            continue;
        }
        let Some(leaf) = import.path.last().cloned() else {
            continue;
        };
        let canonical = canonicalize_import_path(&import.path, module_aliases);
        let alias = import.alias.clone().unwrap_or(leaf);
        aliases.insert(alias, canonical);
    }
    aliases
}

fn canonicalize_import_path(path: &[String], module_aliases: &HashMap<String, String>) -> String {
    let mut segments = path.to_vec();
    if let Some(head) = segments.first_mut() {
        if let Some(replacement) = module_aliases.get(head) {
            *head = replacement.clone();
        }
    }
    segments.join(".")
}

fn qualify_function(
    function: &mut ast::Function,
    namespace: &str,
    local_functions: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    function.name = qualify_name(namespace, &function.name);
    for stmt in &mut function.body {
        qualify_stmt(stmt, namespace, local_functions, module_aliases);
    }
}

fn qualify_stmt(
    stmt: &mut ast::Stmt,
    namespace: &str,
    local_functions: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => qualify_expr(value, namespace, local_functions, module_aliases),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                qualify_expr(value, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            qualify_expr(condition, namespace, local_functions, module_aliases);
            for nested in then_body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
            for nested in else_body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::While { condition, body } => {
            qualify_expr(condition, namespace, local_functions, module_aliases);
            for nested in body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                qualify_stmt(init, namespace, local_functions, module_aliases);
            }
            if let Some(condition) = condition {
                qualify_expr(condition, namespace, local_functions, module_aliases);
            }
            if let Some(step) = step {
                qualify_stmt(step, namespace, local_functions, module_aliases);
            }
            for nested in body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            qualify_expr(iterable, namespace, local_functions, module_aliases);
            for nested in body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            qualify_expr(scrutinee, namespace, local_functions, module_aliases);
            for arm in arms {
                if let Some(guard) = &mut arm.guard {
                    qualify_expr(guard, namespace, local_functions, module_aliases);
                }
                qualify_expr(&mut arm.value, namespace, local_functions, module_aliases);
            }
        }
    }
}

fn qualify_expr(
    expr: &mut ast::Expr,
    namespace: &str,
    local_functions: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            *callee = qualify_callee(callee, namespace, local_functions, module_aliases);
            for arg in args {
                qualify_expr(arg, namespace, local_functions, module_aliases);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                qualify_stmt(stmt, namespace, local_functions, module_aliases);
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            qualify_expr(base, namespace, local_functions, module_aliases);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                qualify_expr(value, namespace, local_functions, module_aliases);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                qualify_expr(value, namespace, local_functions, module_aliases);
            }
        }
        ast::Expr::Closure { body, .. } => {
            qualify_expr(body, namespace, local_functions, module_aliases);
        }
        ast::Expr::Group(inner) => {
            qualify_expr(inner, namespace, local_functions, module_aliases);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            qualify_expr(inner, namespace, local_functions, module_aliases);
        }
        ast::Expr::Unary { expr, .. } => {
            qualify_expr(expr, namespace, local_functions, module_aliases);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            qualify_expr(try_expr, namespace, local_functions, module_aliases);
            qualify_expr(catch_expr, namespace, local_functions, module_aliases);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            qualify_expr(condition, namespace, local_functions, module_aliases);
            qualify_expr(then_expr, namespace, local_functions, module_aliases);
            qualify_expr(else_expr, namespace, local_functions, module_aliases);
        }
        ast::Expr::Binary { left, right, .. } => {
            qualify_expr(left, namespace, local_functions, module_aliases);
            qualify_expr(right, namespace, local_functions, module_aliases);
        }
        ast::Expr::Range { start, end, .. } => {
            qualify_expr(start, namespace, local_functions, module_aliases);
            qualify_expr(end, namespace, local_functions, module_aliases);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                qualify_expr(item, namespace, local_functions, module_aliases);
            }
        }
        ast::Expr::Index { base, index } => {
            qualify_expr(base, namespace, local_functions, module_aliases);
            qualify_expr(index, namespace, local_functions, module_aliases);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn qualify_callee(
    callee: &str,
    namespace: &str,
    local_functions: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) -> String {
    let (base, generic_suffix) = split_generic_suffix(callee);
    let qualified_base = if let Some(exact_alias) = module_aliases.get(base) {
        exact_alias.clone()
    } else if let Some((head, tail)) = base.split_once('.') {
        if let Some(qualified_head) = module_aliases.get(head) {
            format!("{qualified_head}.{tail}")
        } else {
            base.to_string()
        }
    } else if local_functions.contains(base) {
        qualify_name(namespace, base)
    } else {
        base.to_string()
    };
    format!("{qualified_base}{generic_suffix}")
}

fn split_generic_suffix(callee: &str) -> (&str, &str) {
    if let Some(index) = callee.find('<') {
        (&callee[..index], &callee[index..])
    } else {
        (callee, "")
    }
}

fn qualify_name(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

fn canonicalize_call_targets(module: &mut ast::Module) {
    let known_functions = collect_defined_function_names(module);
    for item in &mut module.items {
        if let ast::Item::Function(function) = item {
            let namespace = function
                .name
                .rsplit_once('.')
                .map(|(prefix, _)| prefix)
                .unwrap_or("");
            for stmt in &mut function.body {
                canonicalize_stmt_calls(stmt, namespace, &known_functions);
            }
        }
    }
}

fn collect_defined_function_names(module: &ast::Module) -> HashSet<String> {
    let mut out = HashSet::<String>::new();
    for item in &module.items {
        match item {
            ast::Item::Function(function) => {
                out.insert(function.name.clone());
            }
            ast::Item::Impl(item) => {
                let receiver = item.for_type.to_string();
                for method in &item.methods {
                    out.insert(format!("{receiver}.{}", method.name));
                }
            }
            _ => {}
        }
    }
    out
}

fn canonicalize_stmt_calls(
    stmt: &mut ast::Stmt,
    namespace: &str,
    known_functions: &HashSet<String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => canonicalize_expr_calls(value, namespace, known_functions),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                canonicalize_expr_calls(value, namespace, known_functions);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            canonicalize_expr_calls(condition, namespace, known_functions);
            for nested in then_body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
            for nested in else_body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
        }
        ast::Stmt::While { condition, body } => {
            canonicalize_expr_calls(condition, namespace, known_functions);
            for nested in body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                canonicalize_stmt_calls(init, namespace, known_functions);
            }
            if let Some(condition) = condition {
                canonicalize_expr_calls(condition, namespace, known_functions);
            }
            if let Some(step) = step {
                canonicalize_stmt_calls(step, namespace, known_functions);
            }
            for nested in body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            canonicalize_expr_calls(iterable, namespace, known_functions);
            for nested in body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            canonicalize_expr_calls(scrutinee, namespace, known_functions);
            for arm in arms {
                if let Some(guard) = &mut arm.guard {
                    canonicalize_expr_calls(guard, namespace, known_functions);
                }
                canonicalize_expr_calls(&mut arm.value, namespace, known_functions);
            }
        }
    }
}

fn canonicalize_expr_calls(
    expr: &mut ast::Expr,
    namespace: &str,
    known_functions: &HashSet<String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            *callee = canonicalize_callee(callee, namespace, known_functions);
            if matches!(
                callee.as_str(),
                "spawn" | "spawn_ctx" | "task.group_spawn" | "thread.spawn"
            ) {
                if let Some(task_ref) = args.first_mut() {
                    canonicalize_task_ref_expr(task_ref, namespace, known_functions);
                }
            }
            for arg in args {
                canonicalize_expr_calls(arg, namespace, known_functions);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                canonicalize_stmt_calls(stmt, namespace, known_functions);
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            canonicalize_expr_calls(base, namespace, known_functions);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                canonicalize_expr_calls(value, namespace, known_functions);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                canonicalize_expr_calls(value, namespace, known_functions);
            }
        }
        ast::Expr::Closure { body, .. } => {
            canonicalize_expr_calls(body, namespace, known_functions);
        }
        ast::Expr::Group(inner) => {
            canonicalize_expr_calls(inner, namespace, known_functions);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            canonicalize_expr_calls(inner, namespace, known_functions);
        }
        ast::Expr::Unary { expr, .. } => {
            canonicalize_expr_calls(expr, namespace, known_functions);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            canonicalize_expr_calls(try_expr, namespace, known_functions);
            canonicalize_expr_calls(catch_expr, namespace, known_functions);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            canonicalize_expr_calls(condition, namespace, known_functions);
            canonicalize_expr_calls(then_expr, namespace, known_functions);
            canonicalize_expr_calls(else_expr, namespace, known_functions);
        }
        ast::Expr::Binary { left, right, .. } => {
            canonicalize_expr_calls(left, namespace, known_functions);
            canonicalize_expr_calls(right, namespace, known_functions);
        }
        ast::Expr::Range { start, end, .. } => {
            canonicalize_expr_calls(start, namespace, known_functions);
            canonicalize_expr_calls(end, namespace, known_functions);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                canonicalize_expr_calls(item, namespace, known_functions);
            }
        }
        ast::Expr::Index { base, index } => {
            canonicalize_expr_calls(base, namespace, known_functions);
            canonicalize_expr_calls(index, namespace, known_functions);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn canonicalize_callee(callee: &str, namespace: &str, known_functions: &HashSet<String>) -> String {
    let (base, generic_suffix) = split_generic_suffix(callee);
    if known_functions.contains(base) {
        return callee.to_string();
    }
    if base.contains('.') {
        let mut scope = Some(namespace);
        while let Some(current) = scope {
            if !current.is_empty() {
                let candidate = format!("{current}.{base}");
                if known_functions.contains(&candidate) {
                    return format!("{candidate}{generic_suffix}");
                }
            }
            scope = current.rsplit_once('.').map(|(parent, _)| parent);
        }
    } else {
        let candidate = qualify_name(namespace, base);
        if known_functions.contains(&candidate) {
            return format!("{candidate}{generic_suffix}");
        }
    }
    callee.to_string()
}

fn canonicalize_task_ref_expr(
    expr: &mut ast::Expr,
    namespace: &str,
    known_functions: &HashSet<String>,
) {
    let Some(task_ref) = expr_task_ref_name(expr) else {
        return;
    };
    let canonical = canonicalize_callee(&task_ref, namespace, known_functions);
    if canonical == task_ref {
        return;
    }
    *expr = task_ref_expr_from_name(&canonical);
}

fn task_ref_expr_from_name(name: &str) -> ast::Expr {
    let mut segments = name.split('.');
    let head = segments.next().unwrap_or_default().to_string();
    let mut expr = ast::Expr::Ident(head);
    for segment in segments {
        expr = ast::Expr::FieldAccess {
            base: Box::new(expr),
            field: segment.to_string(),
        };
    }
    expr
}

fn collect_parse_diagnostics(source_path: &Path) -> Result<Vec<diagnostics::Diagnostic>> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    let mut visited = HashSet::<PathBuf>::new();
    let mut visiting = HashSet::<PathBuf>::new();
    match collect_parse_diagnostics_recursive(&canonical, &mut visited, &mut visiting)? {
        Some((failed_path, import_chain, diagnostics)) => Ok(diagnostics
            .into_iter()
            .map(|diagnostic| annotate_parse_diagnostic(diagnostic, &failed_path, &import_chain))
            .collect()),
        None => Ok(Vec::new()),
    }
}

type ParseDiagnosticsHit = (PathBuf, Vec<PathBuf>, Vec<diagnostics::Diagnostic>);

fn collect_parse_diagnostics_recursive(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    visiting: &mut HashSet<PathBuf>,
) -> Result<Option<ParseDiagnosticsHit>> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed resolving module path: {}", path.display()))?;
    if visited.contains(&canonical) || visiting.contains(&canonical) {
        return Ok(None);
    }
    visiting.insert(canonical.clone());
    let source = std::fs::read_to_string(&canonical)
        .with_context(|| format!("failed reading source file: {}", canonical.display()))?;
    let module_name = canonical
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", canonical.display()))?;
    let ast = match parser::parse(&source, module_name) {
        Ok(ast) => ast,
        Err(diagnostics) => {
            return Ok(Some((
                canonical.clone(),
                vec![canonical.clone()],
                diagnostics,
            )))
        }
    };
    visited.insert(canonical.clone());

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
        if let Some((failed_path, mut import_chain, diagnostics)) =
            collect_parse_diagnostics_recursive(&module_path, visited, visiting)?
        {
            import_chain.insert(0, canonical.clone());
            return Ok(Some((failed_path, import_chain, diagnostics)));
        }
    }
    visiting.remove(&canonical);
    Ok(None)
}

fn annotate_parse_diagnostic(
    mut diagnostic: diagnostics::Diagnostic,
    module_path: &Path,
    import_chain: &[PathBuf],
) -> diagnostics::Diagnostic {
    diagnostic.path = Some(module_path.display().to_string());
    let mut help = diagnostic.help.unwrap_or_default();
    if !help.is_empty() {
        help.push(' ');
    }
    help.push_str(&format!("source: {}", module_path.display()));
    if import_chain.len() > 1 {
        let chain = import_chain
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(" -> ");
        if !help.is_empty() {
            help.push(' ');
        }
        help.push_str(&format!("import chain: {chain}"));
        diagnostic.notes.push(format!("import chain: {chain}"));
    }
    diagnostic.help = Some(help);
    diagnostic
}

fn render_parse_failure(path: &Path, diagnostics: &[diagnostics::Diagnostic]) -> String {
    let mut summary = format!(
        "parse failed for {} with {} diagnostics",
        path.display(),
        diagnostics.len()
    );
    if diagnostics.is_empty() {
        return summary;
    }
    let details = diagnostics
        .iter()
        .map(|diagnostic| {
            if let Some(span) = &diagnostic.span {
                format!(
                    "{}:{}-{}:{} {}",
                    span.start_line,
                    span.start_col,
                    span.end_line,
                    span.end_col,
                    diagnostic.message
                )
            } else {
                diagnostic.message.clone()
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    summary.push_str(": ");
    summary.push_str(&details);
    summary
}

fn enrich_diagnostics_context(diagnostics: &mut [diagnostics::Diagnostic]) {
    let mut source_cache = HashMap::<String, Vec<String>>::new();
    for diagnostic in diagnostics {
        if let Some(path) = &diagnostic.path {
            let lines = if let Some(lines) = source_cache.get(path) {
                lines
            } else if let Ok(source) = std::fs::read_to_string(path) {
                source_cache.insert(
                    path.clone(),
                    source.lines().map(ToString::to_string).collect::<Vec<_>>(),
                );
                source_cache
                    .get(path)
                    .expect("inserted path is retrievable")
            } else {
                continue;
            };
            if let Some(span) = &diagnostic.span {
                if span.start_line > 0
                    && span.start_line <= lines.len()
                    && diagnostic.snippet.is_none()
                {
                    diagnostic.snippet = Some(lines[span.start_line - 1].clone());
                }
                if diagnostic.labels.is_empty() {
                    diagnostic.labels.push(diagnostics::Label {
                        message: diagnostic.message.clone(),
                        primary: true,
                        span: Some(span.clone()),
                    });
                }
            } else if let Some(anchors) = derive_anchors_from_message(&diagnostic.message, lines) {
                if let Some((primary_token, primary_span)) = anchors.first() {
                    diagnostic.span = Some(primary_span.clone());
                    diagnostic.snippet = Some(lines[primary_span.start_line - 1].clone());
                    diagnostic.labels.push(diagnostics::Label {
                        message: format!("while analyzing `{primary_token}`"),
                        primary: true,
                        span: Some(primary_span.clone()),
                    });
                }
                for (token, span) in anchors.iter().skip(1) {
                    diagnostic.labels.push(diagnostics::Label {
                        message: format!("related context `{token}`"),
                        primary: false,
                        span: Some(span.clone()),
                    });
                }
                diagnostic.notes.push(
                    "source anchors derived from diagnostic evidence when explicit semantic spans are unavailable"
                        .to_string(),
                );
            }
        }
    }
}

fn derive_anchors_from_message(
    message: &str,
    lines: &[String],
) -> Option<Vec<(String, diagnostics::Span)>> {
    let quoted = extract_backticked_tokens(message);
    let mut out = Vec::new();
    for token in quoted {
        if token.trim().is_empty() {
            continue;
        }
        if let Some(span) = find_token_span(lines, &token) {
            out.push((token, span));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_backticked_tokens(message: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (idx, ch) in message.char_indices() {
        if ch == '`' {
            if let Some(open) = start.take() {
                if idx > open + 1 {
                    out.push(message[open + 1..idx].to_string());
                }
            } else {
                start = Some(idx);
            }
        }
    }
    out
}

fn find_token_span(lines: &[String], token: &str) -> Option<diagnostics::Span> {
    for (line_idx, line) in lines.iter().enumerate() {
        if let Some(col_idx) = line.find(token) {
            return Some(diagnostics::Span {
                start_line: line_idx + 1,
                start_col: col_idx + 1,
                end_line: line_idx + 1,
                end_col: col_idx + token.len().max(1),
            });
        }
    }
    None
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

fn merge_module_owned(root: &mut ast::Module, mut module: ast::Module) {
    root.items.append(&mut module.items);
    root.modules.append(&mut module.modules);
    root.imports.append(&mut module.imports);
    root.capabilities.append(&mut module.capabilities);
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

type CfgBlockId = usize;

#[derive(Debug, Clone)]
struct ControlFlowCfg {
    entry: CfgBlockId,
    blocks: Vec<ControlFlowBlock>,
    loops: Vec<ControlFlowLoop>,
}

#[derive(Debug, Clone)]
struct ControlFlowLoop {
    id: usize,
    break_target: CfgBlockId,
    continue_target: CfgBlockId,
}

#[derive(Debug, Clone)]
struct ControlFlowBlock {
    stmts: Vec<ast::Stmt>,
    terminator: ControlFlowTerminator,
}

#[derive(Debug, Clone)]
enum ControlFlowTerminator {
    Return(Option<ast::Expr>),
    Jump {
        target: CfgBlockId,
        edge: ControlFlowEdge,
    },
    Branch {
        condition: ast::Expr,
        then_target: CfgBlockId,
        else_target: CfgBlockId,
    },
    Switch {
        scrutinee: ast::Expr,
        cases: Vec<(i32, CfgBlockId)>,
        default_target: CfgBlockId,
    },
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlFlowEdge {
    Normal,
    LoopBack { loop_id: usize },
    Break { loop_id: usize },
    Continue { loop_id: usize },
}

#[derive(Clone, Copy)]
struct ActiveLoop {
    id: usize,
    break_target: CfgBlockId,
    continue_target: CfgBlockId,
}

#[derive(Clone)]
struct CfgBuildBlock {
    stmts: Vec<ast::Stmt>,
    terminator: Option<ControlFlowTerminator>,
}

struct ControlFlowBuilder {
    blocks: Vec<CfgBuildBlock>,
    loops: Vec<ControlFlowLoop>,
    active_loops: Vec<ActiveLoop>,
    next_loop_id: usize,
    next_temp: usize,
    variant_tags: HashMap<String, i32>,
    passthrough_functions: HashMap<String, usize>,
    known_pattern_values: HashMap<String, ast::Expr>,
}

impl ControlFlowBuilder {
    fn new(
        variant_tags: HashMap<String, i32>,
        passthrough_functions: HashMap<String, usize>,
    ) -> Self {
        Self {
            blocks: vec![CfgBuildBlock {
                stmts: Vec::new(),
                terminator: None,
            }],
            loops: Vec::new(),
            active_loops: Vec::new(),
            next_loop_id: 0,
            next_temp: 0,
            variant_tags,
            passthrough_functions,
            known_pattern_values: HashMap::new(),
        }
    }

    fn new_block(&mut self) -> CfgBlockId {
        let id = self.blocks.len();
        self.blocks.push(CfgBuildBlock {
            stmts: Vec::new(),
            terminator: None,
        });
        id
    }

    fn append_stmt(&mut self, block: CfgBlockId, stmt: ast::Stmt) -> Result<()> {
        let current = self
            .blocks
            .get_mut(block)
            .ok_or_else(|| anyhow!("control-flow builder referenced missing block {}", block))?;
        if current.terminator.is_some() {
            bail!("control-flow builder attempted to append into terminated block {block}");
        }
        current.stmts.push(stmt);
        Ok(())
    }

    fn terminate(&mut self, block: CfgBlockId, terminator: ControlFlowTerminator) -> Result<()> {
        let current = self
            .blocks
            .get_mut(block)
            .ok_or_else(|| anyhow!("control-flow builder referenced missing block {}", block))?;
        if current.terminator.is_some() {
            bail!("control-flow builder attempted to re-terminate block {block}");
        }
        current.terminator = Some(terminator);
        Ok(())
    }

    fn next_temp_name(&mut self, prefix: &str) -> String {
        let name = format!("__cfg_{prefix}_{}", self.next_temp);
        self.next_temp += 1;
        name
    }

    fn lower_stmt_seq(
        &mut self,
        mut current: CfgBlockId,
        body: &[ast::Stmt],
    ) -> Result<Option<CfgBlockId>> {
        for stmt in body {
            match stmt {
                ast::Stmt::Let {
                    name,
                    mutable,
                    ty,
                    value,
                } => {
                    if let Some(resolved) = resolve_pattern_source_expr(
                        value,
                        &self.known_pattern_values,
                        &self.passthrough_functions,
                    ) {
                        self.known_pattern_values.insert(name.clone(), resolved);
                    } else {
                        self.known_pattern_values.remove(name);
                    }
                    self.append_stmt(
                        current,
                        ast::Stmt::Let {
                            name: name.clone(),
                            mutable: *mutable,
                            ty: ty.clone(),
                            value: value.clone(),
                        },
                    )?;
                }
                ast::Stmt::LetPattern {
                    pattern,
                    value,
                    mutable,
                    ty,
                } => {
                    let resolved = resolve_pattern_source_expr(
                        value,
                        &self.known_pattern_values,
                        &self.passthrough_functions,
                    )
                    .unwrap_or_else(|| value.clone());
                    self.append_stmt(
                        current,
                        ast::Stmt::LetPattern {
                            pattern: pattern.clone(),
                            value: resolved,
                            mutable: *mutable,
                            ty: ty.clone(),
                        },
                    )?;
                }
                ast::Stmt::Assign { target, value } => {
                    if let Some(resolved) = resolve_pattern_source_expr(
                        value,
                        &self.known_pattern_values,
                        &self.passthrough_functions,
                    ) {
                        self.known_pattern_values.insert(target.clone(), resolved);
                    } else {
                        self.known_pattern_values.remove(target);
                    }
                    self.append_stmt(
                        current,
                        ast::Stmt::Assign {
                            target: target.clone(),
                            value: value.clone(),
                        },
                    )?;
                }
                ast::Stmt::CompoundAssign { target, op, value } => {
                    self.known_pattern_values.remove(target);
                    self.append_stmt(
                        current,
                        ast::Stmt::CompoundAssign {
                            target: target.clone(),
                            op: *op,
                            value: value.clone(),
                        },
                    )?;
                }
                ast::Stmt::Defer(_)
                | ast::Stmt::Requires(_)
                | ast::Stmt::Ensures(_)
                | ast::Stmt::Expr(_) => {
                    self.append_stmt(current, stmt.clone())?;
                }
                ast::Stmt::Return(expr) => {
                    self.terminate(current, ControlFlowTerminator::Return(expr.clone()))?;
                    return Ok(None);
                }
                ast::Stmt::Break(_) => {
                    let active = self.active_loops.last().copied().ok_or_else(|| {
                        anyhow!("control-flow lowering encountered `break` outside loop scope")
                    })?;
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: active.break_target,
                            edge: ControlFlowEdge::Break { loop_id: active.id },
                        },
                    )?;
                    return Ok(None);
                }
                ast::Stmt::Continue => {
                    let active = self.active_loops.last().copied().ok_or_else(|| {
                        anyhow!("control-flow lowering encountered `continue` outside loop scope")
                    })?;
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: active.continue_target,
                            edge: ControlFlowEdge::Continue { loop_id: active.id },
                        },
                    )?;
                    return Ok(None);
                }
                ast::Stmt::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    self.known_pattern_values.clear();
                    let then_block = self.new_block();
                    let else_block = self.new_block();
                    self.terminate(
                        current,
                        ControlFlowTerminator::Branch {
                            condition: condition.clone(),
                            then_target: then_block,
                            else_target: else_block,
                        },
                    )?;
                    let then_tail = self.lower_stmt_seq(then_block, then_body)?;
                    let else_tail = self.lower_stmt_seq(else_block, else_body)?;
                    match (then_tail, else_tail) {
                        (None, None) => return Ok(None),
                        (then_tail, else_tail) => {
                            let cont = self.new_block();
                            if let Some(tail) = then_tail {
                                self.terminate(
                                    tail,
                                    ControlFlowTerminator::Jump {
                                        target: cont,
                                        edge: ControlFlowEdge::Normal,
                                    },
                                )?;
                            }
                            if let Some(tail) = else_tail {
                                self.terminate(
                                    tail,
                                    ControlFlowTerminator::Jump {
                                        target: cont,
                                        edge: ControlFlowEdge::Normal,
                                    },
                                )?;
                            }
                            current = cont;
                        }
                    }
                }
                ast::Stmt::While { condition, body } => {
                    self.known_pattern_values.clear();
                    let head = self.new_block();
                    let loop_body = self.new_block();
                    let exit = self.new_block();
                    let loop_id = self.next_loop_id;
                    self.next_loop_id += 1;
                    self.loops.push(ControlFlowLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: head,
                    });
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: head,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                    self.terminate(
                        head,
                        ControlFlowTerminator::Branch {
                            condition: condition.clone(),
                            then_target: loop_body,
                            else_target: exit,
                        },
                    )?;
                    self.active_loops.push(ActiveLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: head,
                    });
                    let body_tail = self.lower_stmt_seq(loop_body, body)?;
                    let _ = self.active_loops.pop();
                    if let Some(tail) = body_tail {
                        self.terminate(
                            tail,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    current = exit;
                }
                ast::Stmt::For {
                    init,
                    condition,
                    step,
                    body,
                } => {
                    self.known_pattern_values.clear();
                    if let Some(init) = init {
                        let Some(next) =
                            self.lower_stmt_seq(current, std::slice::from_ref(init.as_ref()))?
                        else {
                            return Ok(None);
                        };
                        current = next;
                    }
                    let head = self.new_block();
                    let loop_body = self.new_block();
                    let step_block = self.new_block();
                    let exit = self.new_block();
                    let loop_id = self.next_loop_id;
                    self.next_loop_id += 1;
                    self.loops.push(ControlFlowLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: step_block,
                    });
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: head,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                    if let Some(condition) = condition {
                        self.terminate(
                            head,
                            ControlFlowTerminator::Branch {
                                condition: condition.clone(),
                                then_target: loop_body,
                                else_target: exit,
                            },
                        )?;
                    } else {
                        self.terminate(
                            head,
                            ControlFlowTerminator::Jump {
                                target: loop_body,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    self.active_loops.push(ActiveLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: step_block,
                    });
                    let body_tail = self.lower_stmt_seq(loop_body, body)?;
                    let _ = self.active_loops.pop();
                    if let Some(tail) = body_tail {
                        self.terminate(
                            tail,
                            ControlFlowTerminator::Jump {
                                target: step_block,
                                edge: ControlFlowEdge::Normal,
                            },
                        )?;
                    }
                    if let Some(step) = step {
                        if let Some(step_tail) =
                            self.lower_stmt_seq(step_block, std::slice::from_ref(step.as_ref()))?
                        {
                            self.terminate(
                                step_tail,
                                ControlFlowTerminator::Jump {
                                    target: head,
                                    edge: ControlFlowEdge::LoopBack { loop_id },
                                },
                            )?;
                        }
                    } else {
                        self.terminate(
                            step_block,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    current = exit;
                }
                ast::Stmt::ForIn {
                    binding,
                    iterable,
                    body,
                } => {
                    self.known_pattern_values.clear();
                    if let ast::Expr::Range {
                        start,
                        end,
                        inclusive,
                    } = iterable
                    {
                        self.append_stmt(
                            current,
                            ast::Stmt::Let {
                                name: binding.clone(),
                                mutable: true,
                                ty: Some(ast::Type::Int {
                                    signed: true,
                                    bits: 32,
                                }),
                                value: *start.clone(),
                            },
                        )?;
                        let head = self.new_block();
                        let loop_body = self.new_block();
                        let step_block = self.new_block();
                        let exit = self.new_block();
                        let loop_id = self.next_loop_id;
                        self.next_loop_id += 1;
                        self.loops.push(ControlFlowLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: step_block,
                        });
                        self.terminate(
                            current,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::Normal,
                            },
                        )?;
                        let cond_expr = ast::Expr::Binary {
                            op: if *inclusive {
                                ast::BinaryOp::Lte
                            } else {
                                ast::BinaryOp::Lt
                            },
                            left: Box::new(ast::Expr::Ident(binding.clone())),
                            right: Box::new(*end.clone()),
                        };
                        self.terminate(
                            head,
                            ControlFlowTerminator::Branch {
                                condition: cond_expr,
                                then_target: loop_body,
                                else_target: exit,
                            },
                        )?;
                        self.active_loops.push(ActiveLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: step_block,
                        });
                        let body_tail = self.lower_stmt_seq(loop_body, body)?;
                        let _ = self.active_loops.pop();
                        if let Some(tail) = body_tail {
                            self.terminate(
                                tail,
                                ControlFlowTerminator::Jump {
                                    target: step_block,
                                    edge: ControlFlowEdge::Normal,
                                },
                            )?;
                        }
                        let step_stmt = ast::Stmt::CompoundAssign {
                            target: binding.clone(),
                            op: ast::BinaryOp::Add,
                            value: ast::Expr::Int(1),
                        };
                        self.append_stmt(step_block, step_stmt)?;
                        self.terminate(
                            step_block,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                        current = exit;
                    } else {
                        let body_block = self.new_block();
                        let exit = self.new_block();
                        let loop_id = self.next_loop_id;
                        self.next_loop_id += 1;
                        self.loops.push(ControlFlowLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: exit,
                        });
                        self.terminate(
                            current,
                            ControlFlowTerminator::Jump {
                                target: body_block,
                                edge: ControlFlowEdge::Normal,
                            },
                        )?;
                        self.active_loops.push(ActiveLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: exit,
                        });
                        let body_tail = self.lower_stmt_seq(body_block, body)?;
                        let _ = self.active_loops.pop();
                        if let Some(tail) = body_tail {
                            self.terminate(
                                tail,
                                ControlFlowTerminator::Jump {
                                    target: exit,
                                    edge: ControlFlowEdge::Normal,
                                },
                            )?;
                        }
                        current = exit;
                    }
                }
                ast::Stmt::Loop { body } => {
                    self.known_pattern_values.clear();
                    let head = self.new_block();
                    let has_loop_break = body_contains_break_at_depth(body, 0);
                    let exit = if has_loop_break {
                        Some(self.new_block())
                    } else {
                        None
                    };
                    let loop_id = self.next_loop_id;
                    self.next_loop_id += 1;
                    self.loops.push(ControlFlowLoop {
                        id: loop_id,
                        break_target: exit.unwrap_or(head),
                        continue_target: head,
                    });
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: head,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                    self.active_loops.push(ActiveLoop {
                        id: loop_id,
                        break_target: exit.unwrap_or(head),
                        continue_target: head,
                    });
                    let body_tail = self.lower_stmt_seq(head, body)?;
                    let _ = self.active_loops.pop();
                    if let Some(tail) = body_tail {
                        self.terminate(
                            tail,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    if let Some(exit) = exit {
                        current = exit;
                    } else {
                        return Ok(None);
                    }
                }
                ast::Stmt::Match { scrutinee, arms } => {
                    let resolved_scrutinee = resolve_pattern_source_expr(
                        scrutinee,
                        &self.known_pattern_values,
                        &self.passthrough_functions,
                    )
                    .unwrap_or_else(|| scrutinee.clone());
                    if arms.is_empty() {
                        self.terminate(current, ControlFlowTerminator::Unreachable)?;
                        return Ok(None);
                    }
                    let scrutinee_name = self.next_temp_name("match");
                    self.append_stmt(
                        current,
                        ast::Stmt::Let {
                            name: scrutinee_name.clone(),
                            mutable: false,
                            ty: None,
                            value: resolved_scrutinee.clone(),
                        },
                    )?;
                    let all_returning = arms.iter().all(|arm| arm.returns);
                    let end_block = if all_returning {
                        None
                    } else {
                        Some(self.new_block())
                    };
                    let has_terminal_catchall = arms.last().is_some_and(|arm| {
                        arm.guard.is_none() && pattern_is_catchall(&arm.pattern)
                    });
                    let mut fallback_block = if let Some(end_block) = end_block {
                        end_block
                    } else if has_terminal_catchall {
                        usize::MAX
                    } else {
                        let unreachable_block = self.new_block();
                        self.terminate(unreachable_block, ControlFlowTerminator::Unreachable)?;
                        unreachable_block
                    };
                    let mut switch_cases = Vec::<(i32, CfgBlockId)>::new();
                    let mut switch_default = fallback_block;
                    let mut switch_seen = HashSet::<i32>::new();
                    let mut switch_viable = true;
                    let mut arm_blocks = Vec::<CfgBlockId>::with_capacity(arms.len());
                    for (index, arm) in arms.iter().enumerate() {
                        let arm_block = self.new_block();
                        arm_blocks.push(arm_block);
                        if arm.guard.is_some() {
                            switch_viable = false;
                        } else if pattern_is_catchall(&arm.pattern) {
                            if index + 1 != arms.len() || switch_default != fallback_block {
                                switch_viable = false;
                            } else {
                                switch_default = arm_block;
                            }
                        } else if let Some(values) =
                            pattern_switch_values(&arm.pattern, &self.variant_tags)
                        {
                            for value in values {
                                if !switch_seen.insert(value) {
                                    switch_viable = false;
                                    break;
                                }
                                switch_cases.push((value, arm_block));
                            }
                        } else {
                            switch_viable = false;
                        }
                    }

                    if switch_viable && !switch_cases.is_empty() {
                        if switch_default == usize::MAX {
                            let unreachable_block = self.new_block();
                            self.terminate(unreachable_block, ControlFlowTerminator::Unreachable)?;
                            switch_default = unreachable_block;
                        }
                        self.terminate(
                            current,
                            ControlFlowTerminator::Switch {
                                scrutinee: ast::Expr::Ident(scrutinee_name.clone()),
                                cases: switch_cases,
                                default_target: switch_default,
                            },
                        )?;
                        for (arm, arm_block) in arms.iter().zip(arm_blocks.iter().copied()) {
                            let binding_stmts = bindings_for_match_arm_pattern(
                                &arm.pattern,
                                &resolved_scrutinee,
                                &self.variant_tags,
                            )?;
                            for stmt in binding_stmts {
                                self.append_stmt(arm_block, stmt)?;
                            }
                            if arm.returns {
                                self.terminate(
                                    arm_block,
                                    ControlFlowTerminator::Return(Some(arm.value.clone())),
                                )?;
                            } else {
                                let end_block =
                                    end_block.expect("non-returning match must have end block");
                                self.append_stmt(arm_block, ast::Stmt::Expr(arm.value.clone()))?;
                                self.terminate(
                                    arm_block,
                                    ControlFlowTerminator::Jump {
                                        target: end_block,
                                        edge: ControlFlowEdge::Normal,
                                    },
                                )?;
                            }
                        }
                        if let Some(end_block) = end_block {
                            current = end_block;
                        } else {
                            return Ok(None);
                        }
                    } else {
                        if fallback_block == usize::MAX {
                            let unreachable_block = self.new_block();
                            self.terminate(unreachable_block, ControlFlowTerminator::Unreachable)?;
                            fallback_block = unreachable_block;
                        }
                        let mut dispatch = current;
                        for (index, arm) in arms.iter().enumerate() {
                            let arm_block = arm_blocks[index];
                            let is_last = index + 1 == arms.len();
                            let else_block = if is_last {
                                fallback_block
                            } else {
                                self.new_block()
                            };
                            self.terminate(
                                dispatch,
                                ControlFlowTerminator::Branch {
                                    condition: pattern_to_expr(
                                        &scrutinee_name,
                                        &arm.pattern,
                                        &self.variant_tags,
                                    ),
                                    then_target: arm_block,
                                    else_target: else_block,
                                },
                            )?;
                            let binding_stmts = bindings_for_match_arm_pattern(
                                &arm.pattern,
                                &resolved_scrutinee,
                                &self.variant_tags,
                            )?;
                            for stmt in binding_stmts {
                                self.append_stmt(arm_block, stmt)?;
                            }
                            let value_block = if let Some(guard) = &arm.guard {
                                let guarded_value_block = self.new_block();
                                self.terminate(
                                    arm_block,
                                    ControlFlowTerminator::Branch {
                                        condition: guard.clone(),
                                        then_target: guarded_value_block,
                                        else_target: else_block,
                                    },
                                )?;
                                guarded_value_block
                            } else {
                                arm_block
                            };
                            if arm.returns {
                                self.terminate(
                                    value_block,
                                    ControlFlowTerminator::Return(Some(arm.value.clone())),
                                )?;
                            } else {
                                let end_block =
                                    end_block.expect("non-returning match must have end block");
                                self.append_stmt(value_block, ast::Stmt::Expr(arm.value.clone()))?;
                                self.terminate(
                                    value_block,
                                    ControlFlowTerminator::Jump {
                                        target: end_block,
                                        edge: ControlFlowEdge::Normal,
                                    },
                                )?;
                            }
                            dispatch = else_block;
                        }
                        if let Some(end_block) = end_block {
                            current = end_block;
                            self.known_pattern_values.clear();
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }
        }
        Ok(Some(current))
    }

    fn finish(mut self, body: &[ast::Stmt]) -> Result<ControlFlowCfg> {
        if let Some(tail) = self.lower_stmt_seq(0, body)? {
            self.terminate(tail, ControlFlowTerminator::Return(None))?;
        }
        let blocks = self
            .blocks
            .into_iter()
            .enumerate()
            .map(|(id, block)| {
                let terminator = block.terminator.ok_or_else(|| {
                    anyhow!("control-flow builder emitted block {id} without terminator")
                })?;
                Ok(ControlFlowBlock {
                    stmts: block.stmts,
                    terminator,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ControlFlowCfg {
            entry: 0,
            blocks,
            loops: self.loops,
        })
    }
}

fn build_control_flow_cfg(
    body: &[ast::Stmt],
    variant_tags: &HashMap<String, i32>,
    passthrough_functions: &HashMap<String, usize>,
) -> Result<ControlFlowCfg> {
    ControlFlowBuilder::new(variant_tags.clone(), passthrough_functions.clone()).finish(body)
}

fn body_contains_break_at_depth(body: &[ast::Stmt], depth: usize) -> bool {
    body.iter()
        .any(|stmt| stmt_contains_break_at_depth(stmt, depth))
}

fn stmt_contains_break_at_depth(stmt: &ast::Stmt, depth: usize) -> bool {
    match stmt {
        ast::Stmt::Break(_) => depth == 0,
        ast::Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            body_contains_break_at_depth(then_body, depth)
                || body_contains_break_at_depth(else_body, depth)
        }
        ast::Stmt::While { body, .. }
        | ast::Stmt::For { body, .. }
        | ast::Stmt::ForIn { body, .. }
        | ast::Stmt::Loop { body } => body_contains_break_at_depth(body, depth + 1),
        ast::Stmt::Match { .. }
        | ast::Stmt::Continue
        | ast::Stmt::Return(_)
        | ast::Stmt::Defer(_)
        | ast::Stmt::Requires(_)
        | ast::Stmt::Ensures(_)
        | ast::Stmt::Expr(_)
        | ast::Stmt::Let { .. }
        | ast::Stmt::LetPattern { .. }
        | ast::Stmt::Assign { .. }
        | ast::Stmt::CompoundAssign { .. } => false,
    }
}

fn pattern_to_expr(
    scrutinee_name: &str,
    pattern: &ast::Pattern,
    variant_tags: &HashMap<String, i32>,
) -> ast::Expr {
    match pattern {
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) => ast::Expr::Bool(true),
        ast::Pattern::Int(value) => ast::Expr::Binary {
            op: ast::BinaryOp::Eq,
            left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
            right: Box::new(ast::Expr::Int(*value)),
        },
        ast::Pattern::Bool(value) => ast::Expr::Binary {
            op: ast::BinaryOp::Eq,
            left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
            right: Box::new(ast::Expr::Bool(*value)),
        },
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            let key = format!("{enum_name}::{variant}");
            ast::Expr::Binary {
                op: ast::BinaryOp::Eq,
                left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
                right: Box::new(ast::Expr::Int(
                    variant_tag_for_key(&key, variant_tags) as i128
                )),
            }
        }
        ast::Pattern::Struct { .. } => ast::Expr::Bool(true),
        ast::Pattern::Or(patterns) => {
            let mut iter = patterns.iter();
            let first = iter
                .next()
                .map(|pattern| pattern_to_expr(scrutinee_name, pattern, variant_tags))
                .unwrap_or(ast::Expr::Bool(true));
            iter.fold(first, |acc, pattern| ast::Expr::Binary {
                op: ast::BinaryOp::Or,
                left: Box::new(acc),
                right: Box::new(pattern_to_expr(scrutinee_name, pattern, variant_tags)),
            })
        }
    }
}

fn pattern_is_catchall(pattern: &ast::Pattern) -> bool {
    matches!(pattern, ast::Pattern::Wildcard | ast::Pattern::Ident(_))
}

fn pattern_switch_values(
    pattern: &ast::Pattern,
    variant_tags: &HashMap<String, i32>,
) -> Option<Vec<i32>> {
    match pattern {
        ast::Pattern::Int(value) => i32::try_from(*value).ok().map(|v| vec![v]),
        ast::Pattern::Bool(value) => Some(vec![if *value { 1 } else { 0 }]),
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            let key = format!("{enum_name}::{variant}");
            Some(vec![variant_tag_for_key(&key, variant_tags)])
        }
        ast::Pattern::Or(patterns) => {
            let mut out = Vec::new();
            for pattern in patterns {
                let mut values = pattern_switch_values(pattern, variant_tags)?;
                out.append(&mut values);
            }
            Some(out)
        }
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) | ast::Pattern::Struct { .. } => None,
    }
}

fn pattern_has_variant_payload_bindings(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Variant { bindings, .. } => !bindings.is_empty(),
        ast::Pattern::Or(patterns) => patterns.iter().any(pattern_has_variant_payload_bindings),
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Struct { .. }
        | ast::Pattern::Ident(_) => false,
    }
}

fn pattern_has_struct_field_bindings(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Struct { fields, .. } => fields.iter().any(|(_, binding)| binding != "_"),
        ast::Pattern::Or(patterns) => patterns.iter().any(pattern_has_struct_field_bindings),
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Ident(_)
        | ast::Pattern::Variant { .. } => false,
    }
}

fn pattern_matches_resolved_scrutinee(
    pattern: &ast::Pattern,
    scrutinee: &ast::Expr,
    variant_tags: &HashMap<String, i32>,
) -> bool {
    match pattern {
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) => true,
        ast::Pattern::Int(expected) => {
            matches!(scrutinee, ast::Expr::Int(actual) if actual == expected)
        }
        ast::Pattern::Bool(expected) => {
            matches!(scrutinee, ast::Expr::Bool(actual) if actual == expected)
        }
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            if let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                ..
            } = scrutinee
            {
                value_enum == enum_name && value_variant == variant
            } else if let ast::Expr::Int(value) = scrutinee {
                i32::try_from(*value).ok().is_some_and(|actual| {
                    let key = format!("{enum_name}::{variant}");
                    actual == variant_tag_for_key(&key, variant_tags)
                })
            } else {
                false
            }
        }
        ast::Pattern::Struct { name, .. } => matches!(
            scrutinee,
            ast::Expr::StructInit {
                name: value_name,
                ..
            } if value_name == name
        ),
        ast::Pattern::Or(patterns) => patterns
            .iter()
            .any(|pattern| pattern_matches_resolved_scrutinee(pattern, scrutinee, variant_tags)),
    }
}

fn resolve_pattern_source_expr(
    expr: &ast::Expr,
    known_values: &HashMap<String, ast::Expr>,
    passthrough_functions: &HashMap<String, usize>,
) -> Option<ast::Expr> {
    fn resolve_inner(
        expr: &ast::Expr,
        known_values: &HashMap<String, ast::Expr>,
        passthrough_functions: &HashMap<String, usize>,
        depth: usize,
    ) -> Option<ast::Expr> {
        if depth > 32 {
            return None;
        }
        match expr {
            ast::Expr::EnumInit { .. } | ast::Expr::StructInit { .. } => Some(expr.clone()),
            ast::Expr::Group(inner) => {
                resolve_inner(inner, known_values, passthrough_functions, depth + 1)
            }
            ast::Expr::Ident(name) => known_values.get(name).and_then(|value| {
                resolve_inner(value, known_values, passthrough_functions, depth + 1)
            }),
            ast::Expr::Call { callee, args } => {
                if let Some(index) = passthrough_functions.get(callee).copied() {
                    let arg = args.get(index)?;
                    resolve_inner(arg, known_values, passthrough_functions, depth + 1)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    resolve_inner(expr, known_values, passthrough_functions, 0)
}

fn resolve_field_expr(base: &ast::Expr, field: &str) -> Option<ast::Expr> {
    match base {
        ast::Expr::StructInit { fields, .. } => fields.iter().find_map(|(name, value)| {
            if name == field {
                Some(value.clone())
            } else {
                None
            }
        }),
        ast::Expr::Range {
            start,
            end,
            inclusive,
        } => match field {
            "start" => Some((**start).clone()),
            "end" => Some((**end).clone()),
            "inclusive" => Some(ast::Expr::Bool(*inclusive)),
            _ => None,
        },
        ast::Expr::FieldAccess { base, field: lhs } => {
            let resolved_base = resolve_field_expr(base, lhs)?;
            resolve_field_expr(&resolved_base, field)
        }
        ast::Expr::Group(inner) => resolve_field_expr(inner, field),
        _ => None,
    }
}

fn bindings_for_match_arm_pattern(
    pattern: &ast::Pattern,
    scrutinee: &ast::Expr,
    variant_tags: &HashMap<String, i32>,
) -> Result<Vec<ast::Stmt>> {
    match pattern {
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            ..
        } => {
            if bindings.is_empty() {
                return Ok(Vec::new());
            }
            let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                payload,
                ..
            } = scrutinee
            else {
                bail!(
                    "native backend requires literal enum scrutinee for match-arm payload bindings"
                );
            };
            if value_enum != enum_name
                || value_variant != variant
                || payload.len() != bindings.len()
            {
                bail!(
                    "native backend requires exact literal enum variant match for payload bindings"
                );
            }
            let mut stmts = Vec::with_capacity(bindings.len());
            for (name, value) in bindings.iter().zip(payload.iter()) {
                stmts.push(ast::Stmt::Let {
                    name: name.clone(),
                    mutable: false,
                    ty: None,
                    value: value.clone(),
                });
            }
            Ok(stmts)
        }
        ast::Pattern::Struct { name, fields } => {
            let binding_fields = fields
                .iter()
                .filter(|(_, binding)| binding != "_")
                .collect::<Vec<_>>();
            if binding_fields.is_empty() {
                return Ok(Vec::new());
            }
            let ast::Expr::StructInit {
                name: value_name,
                fields: value_fields,
            } = scrutinee
            else {
                bail!(
                    "native backend requires literal struct scrutinee for match-arm struct bindings"
                );
            };
            if value_name != name {
                bail!(
                    "native backend requires exact literal struct type match for struct bindings"
                );
            }
            let mut stmts = Vec::with_capacity(binding_fields.len());
            for (field_name, binding_name) in binding_fields {
                let Some((_, field_expr)) =
                    value_fields.iter().find(|(field, _)| field == field_name)
                else {
                    bail!("native backend requires struct literal fields to cover every bound pattern field");
                };
                stmts.push(ast::Stmt::Let {
                    name: binding_name.clone(),
                    mutable: false,
                    ty: None,
                    value: field_expr.clone(),
                });
            }
            Ok(stmts)
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns.iter().find(|pattern| {
                pattern_matches_resolved_scrutinee(pattern, scrutinee, variant_tags)
            }) {
                return bindings_for_match_arm_pattern(matched, scrutinee, variant_tags);
            }
            if patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
            {
                bail!(
                    "native backend requires resolvable scrutinee for payload or struct-field bindings within or-pattern match arms"
                );
            }
            Ok(Vec::new())
        }
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Ident(_) => Ok(Vec::new()),
    }
}

fn verify_control_flow_cfg(cfg: &ControlFlowCfg) -> Result<()> {
    if cfg.blocks.is_empty() {
        bail!("control-flow cfg must include at least one block");
    }
    if cfg.entry >= cfg.blocks.len() {
        bail!(
            "control-flow cfg entry {} out of range (blocks={})",
            cfg.entry,
            cfg.blocks.len()
        );
    }
    let loop_map = cfg
        .loops
        .iter()
        .map(|loop_cfg| (loop_cfg.id, loop_cfg))
        .collect::<HashMap<_, _>>();
    let mut reachable = vec![false; cfg.blocks.len()];
    let mut stack = vec![cfg.entry];
    while let Some(block_id) = stack.pop() {
        if reachable[block_id] {
            continue;
        }
        reachable[block_id] = true;
        match &cfg.blocks[block_id].terminator {
            ControlFlowTerminator::Return(_) | ControlFlowTerminator::Unreachable => {}
            ControlFlowTerminator::Jump { target, edge } => {
                if *target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} jumps to invalid target {}",
                        block_id,
                        target
                    );
                }
                match edge {
                    ControlFlowEdge::Break { loop_id } => {
                        let loop_cfg = loop_map.get(loop_id).ok_or_else(|| {
                            anyhow!(
                                "control-flow cfg block {} references unknown break loop id {}",
                                block_id,
                                loop_id
                            )
                        })?;
                        if loop_cfg.break_target != *target {
                            bail!(
                                "control-flow cfg block {} break edge target {} does not match loop {} break target {}",
                                block_id,
                                target,
                                loop_id,
                                loop_cfg.break_target
                            );
                        }
                    }
                    ControlFlowEdge::Continue { loop_id } => {
                        let loop_cfg = loop_map.get(loop_id).ok_or_else(|| {
                            anyhow!(
                                "control-flow cfg block {} references unknown continue loop id {}",
                                block_id,
                                loop_id
                            )
                        })?;
                        if loop_cfg.continue_target != *target {
                            bail!(
                                "control-flow cfg block {} continue edge target {} does not match loop {} continue target {}",
                                block_id,
                                target,
                                loop_id,
                                loop_cfg.continue_target
                            );
                        }
                    }
                    ControlFlowEdge::Normal | ControlFlowEdge::LoopBack { .. } => {}
                }
                stack.push(*target);
            }
            ControlFlowTerminator::Branch {
                then_target,
                else_target,
                ..
            } => {
                if *then_target >= cfg.blocks.len() || *else_target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} has invalid branch targets ({}, {})",
                        block_id,
                        then_target,
                        else_target
                    );
                }
                stack.push(*then_target);
                stack.push(*else_target);
            }
            ControlFlowTerminator::Switch {
                cases,
                default_target,
                ..
            } => {
                if *default_target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} has invalid switch default target {}",
                        block_id,
                        default_target
                    );
                }
                for (_, target) in cases {
                    if *target >= cfg.blocks.len() {
                        bail!(
                            "control-flow cfg block {} has invalid switch case target {}",
                            block_id,
                            target
                        );
                    }
                }
                stack.push(*default_target);
                for (_, target) in cases {
                    stack.push(*target);
                }
            }
        }
    }
    for (index, is_reachable) in reachable.iter().enumerate() {
        if !is_reachable {
            bail!(
                "control-flow cfg contains unreachable declared block {}",
                index
            );
        }
    }
    Ok(())
}

fn lower_backend_ir(fir: &fir::FirModule, backend: BackendKind) -> Result<String> {
    match backend {
        BackendKind::Llvm => lower_llvm_ir(fir, true),
        BackendKind::Cranelift => lower_cranelift_ir(fir, true),
    }
}

#[derive(Clone)]
struct NativeCanonicalPlan {
    forced_main_return: Option<i32>,
    string_literal_ids: HashMap<String, i32>,
    global_const_i32: HashMap<String, i32>,
    variant_tags: HashMap<String, i32>,
    mutable_static_i32: HashMap<String, i32>,
    task_ref_ids: HashMap<String, i32>,
    cfg_by_function: HashMap<String, Result<ControlFlowCfg, String>>,
    data_ops_by_function: HashMap<String, Vec<NativeDataOp>>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum NativeMemoryClass {
    Stack,
    Static,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum NativeAliasClass {
    LocalNoEscape,
    Escapes,
}

#[derive(Debug, Clone, Copy)]
enum NativeBoundsPolicy {
    Checked,
    ProvenInRange,
}

#[derive(Debug, Clone, Copy)]
enum NativeEffectBoundary {
    Local,
    CapabilityRuntimeImport,
}

#[derive(Debug, Clone)]
enum NativeDataOpKind {
    ArrayLiteral {
        binding: String,
        len: usize,
        element_bits: u16,
        element_align: u8,
        element_stride: u8,
        memory: NativeMemoryClass,
        alias: NativeAliasClass,
    },
    ArrayIndexLoad {
        binding: String,
        index: String,
        bounds: NativeBoundsPolicy,
    },
    StringViewCall {
        callee: String,
        foldable: bool,
        alias: NativeAliasClass,
    },
    RuntimeBoundaryCall {
        callee: String,
        arity: usize,
    },
}

#[derive(Debug, Clone)]
struct NativeDataOp {
    kind: NativeDataOpKind,
    effect_boundary: NativeEffectBoundary,
}

fn render_native_data_op(op: &NativeDataOp) -> String {
    match &op.kind {
        NativeDataOpKind::ArrayLiteral {
            binding,
            len,
            element_bits,
            element_align,
            element_stride,
            memory,
            alias,
        } => format!(
            "array.literal binding={binding} len={len} bits={element_bits} align={element_align} stride={element_stride} memory={memory:?} alias={alias:?} boundary={:?}",
            op.effect_boundary
        ),
        NativeDataOpKind::ArrayIndexLoad {
            binding,
            index,
            bounds,
        } => format!(
            "array.index.load binding={binding} index={index} bounds={bounds:?} boundary={:?}",
            op.effect_boundary
        ),
        NativeDataOpKind::StringViewCall {
            callee,
            foldable,
            alias,
        } => format!(
            "string.view.call callee={callee} foldable={foldable} alias={alias:?} boundary={:?}",
            op.effect_boundary
        ),
        NativeDataOpKind::RuntimeBoundaryCall { callee, arity } => format!(
            "runtime.boundary.call callee={callee} arity={arity} boundary={:?}",
            op.effect_boundary
        ),
    }
}

fn index_expr_shape(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::Int(value) => value.to_string(),
        ast::Expr::Ident(name) => name.clone(),
        ast::Expr::Group(inner) => index_expr_shape(inner),
        _ => "<expr>".to_string(),
    }
}

fn infer_array_element_layout(items: &[ast::Expr]) -> (u16, u8, u8) {
    let mut bits = 32u16;
    for item in items {
        if let ast::Expr::Int(value) = item {
            if *value < i128::from(i32::MIN) || *value > i128::from(i32::MAX) {
                bits = bits.max(64);
            }
        }
    }
    let stride = if bits <= 8 {
        1
    } else if bits <= 16 {
        2
    } else if bits <= 32 {
        4
    } else {
        8
    };
    (bits, stride, stride)
}

fn collect_native_data_ops_from_expr(
    expr: &ast::Expr,
    array_lengths: &HashMap<String, usize>,
    const_strings: &HashMap<String, String>,
    out: &mut Vec<NativeDataOp>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if let Some(import) = native_runtime_import_for_callee(callee) {
                out.push(NativeDataOp {
                    kind: NativeDataOpKind::RuntimeBoundaryCall {
                        callee: callee.clone(),
                        arity: import.arity,
                    },
                    effect_boundary: NativeEffectBoundary::CapabilityRuntimeImport,
                });
            } else if is_native_data_plane_string_call(callee) {
                let foldable = eval_const_i32_call(callee, args, const_strings).is_some()
                    || eval_const_string_call(callee, args, const_strings).is_some();
                out.push(NativeDataOp {
                    kind: NativeDataOpKind::StringViewCall {
                        callee: callee.clone(),
                        foldable,
                        alias: NativeAliasClass::LocalNoEscape,
                    },
                    effect_boundary: NativeEffectBoundary::Local,
                });
            }
            for arg in args {
                collect_native_data_ops_from_expr(arg, array_lengths, const_strings, out);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::Index { base, index } => {
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(len) = array_lengths.get(name) {
                    let bounds = match index.as_ref() {
                        ast::Expr::Int(value) => usize::try_from(*value)
                            .ok()
                            .filter(|idx| idx < len)
                            .map(|_| NativeBoundsPolicy::ProvenInRange)
                            .unwrap_or(NativeBoundsPolicy::Checked),
                        _ => NativeBoundsPolicy::Checked,
                    };
                    out.push(NativeDataOp {
                        kind: NativeDataOpKind::ArrayIndexLoad {
                            binding: name.clone(),
                            index: index_expr_shape(index),
                            bounds,
                        },
                        effect_boundary: NativeEffectBoundary::Local,
                    });
                }
            }
            collect_native_data_ops_from_expr(base, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(index, array_lengths, const_strings, out);
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_native_data_ops_from_expr(base, array_lengths, const_strings, out)
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
            }
        }
        ast::Expr::EnumInit { payload, .. } | ast::Expr::ArrayLiteral(payload) => {
            for value in payload {
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
            }
        }
        ast::Expr::Closure { body, .. }
        | ast::Expr::Group(body)
        | ast::Expr::Await(body)
        | ast::Expr::Discard(body) => {
            collect_native_data_ops_from_expr(body, array_lengths, const_strings, out)
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_native_data_ops_from_expr(try_expr, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(catch_expr, array_lengths, const_strings, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(then_expr, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(else_expr, array_lengths, const_strings, out);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_native_data_ops_from_expr(expr, array_lengths, const_strings, out)
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_native_data_ops_from_expr(left, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(right, array_lengths, const_strings, out);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_native_data_ops_from_expr(start, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(end, array_lengths, const_strings, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn collect_native_data_ops_for_function(function: &hir::TypedFunction) -> Vec<NativeDataOp> {
    let mut out = Vec::new();
    let mut array_lengths = HashMap::<String, usize>::new();
    let mut const_strings = HashMap::<String, String>::new();

    fn walk_stmt(
        stmt: &ast::Stmt,
        array_lengths: &mut HashMap<String, usize>,
        const_strings: &mut HashMap<String, String>,
        out: &mut Vec<NativeDataOp>,
    ) {
        match stmt {
            ast::Stmt::Let {
                name,
                value,
                mutable: _,
                ..
            } => {
                match value {
                    ast::Expr::ArrayLiteral(items) => {
                        let (bits, align, stride) = infer_array_element_layout(items);
                        array_lengths.insert(name.clone(), items.len());
                        out.push(NativeDataOp {
                            kind: NativeDataOpKind::ArrayLiteral {
                                binding: name.clone(),
                                len: items.len(),
                                element_bits: bits,
                                element_align: align,
                                element_stride: stride,
                                memory: NativeMemoryClass::Stack,
                                alias: NativeAliasClass::LocalNoEscape,
                            },
                            effect_boundary: NativeEffectBoundary::Local,
                        });
                    }
                    ast::Expr::Str(value) => {
                        const_strings.insert(name.clone(), value.clone());
                    }
                    _ => {
                        const_strings.remove(name);
                    }
                }
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
            }
            ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::Assign { value, .. }
            | ast::Stmt::CompoundAssign { value, .. }
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value)
            | ast::Stmt::Expr(value) => {
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out)
            }
            ast::Stmt::Return(value) => {
                if let Some(value) = value {
                    collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
                for stmt in then_body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
                for stmt in else_body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::While { condition, body } => {
                collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
                for stmt in body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    walk_stmt(init, array_lengths, const_strings, out);
                }
                if let Some(condition) = condition {
                    collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
                }
                if let Some(step) = step {
                    walk_stmt(step, array_lengths, const_strings, out);
                }
                for stmt in body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                collect_native_data_ops_from_expr(iterable, array_lengths, const_strings, out);
                for stmt in body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::Loop { body } => {
                for stmt in body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::Match { scrutinee, arms } => {
                collect_native_data_ops_from_expr(scrutinee, array_lengths, const_strings, out);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        collect_native_data_ops_from_expr(guard, array_lengths, const_strings, out);
                    }
                    collect_native_data_ops_from_expr(
                        &arm.value,
                        array_lengths,
                        const_strings,
                        out,
                    );
                }
            }
            ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }

    for stmt in &function.body {
        walk_stmt(stmt, &mut array_lengths, &mut const_strings, &mut out);
    }
    out
}

fn compute_forced_main_return(fir: &fir::FirModule, enforce_contract_checks: bool) -> Option<i32> {
    if !enforce_contract_checks {
        return None;
    }
    if fir
        .entry_requires
        .iter()
        .any(|condition| matches!(condition, Some(false)))
    {
        Some(120)
    } else if fir
        .entry_ensures
        .iter()
        .any(|condition| matches!(condition, Some(false)))
    {
        Some(121)
    } else {
        None
    }
}

fn build_native_cfg_map(
    fir: &fir::FirModule,
    variant_tags: &HashMap<String, i32>,
) -> HashMap<String, Result<ControlFlowCfg, String>> {
    let passthrough_functions = collect_passthrough_function_map_from_typed(&fir.typed_functions);
    fir.typed_functions
        .par_iter()
        .filter(|function| !is_extern_c_import_decl(function))
        .map(|function| {
            let cfg = build_control_flow_cfg(&function.body, variant_tags, &passthrough_functions)
                .and_then(|cfg| {
                    verify_control_flow_cfg(&cfg)?;
                    Ok(cfg)
                });
            (
                function.name.clone(),
                cfg.map_err(|error| error.to_string()),
            )
        })
        .collect()
}

fn build_native_canonical_plan(
    fir: &fir::FirModule,
    enforce_contract_checks: bool,
) -> NativeCanonicalPlan {
    ensure_codegen_pool_configured();
    let variant_tags = build_variant_tag_map(fir);
    let cfg_by_function = build_native_cfg_map(fir, &variant_tags);
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    let mut task_ref_ids = HashMap::<String, i32>::new();
    for (index, symbol) in spawn_task_symbols.iter().enumerate() {
        task_ref_ids.insert(symbol.clone(), (index + 1) as i32);
    }
    NativeCanonicalPlan {
        forced_main_return: compute_forced_main_return(fir, enforce_contract_checks),
        string_literal_ids: build_string_literal_ids(&collect_native_string_literals(fir)),
        global_const_i32: build_global_const_i32_map(fir),
        mutable_static_i32: build_mutable_static_i32_map(fir),
        variant_tags,
        task_ref_ids,
        cfg_by_function,
        data_ops_by_function: fir
            .typed_functions
            .par_iter()
            .filter(|function| !is_extern_c_import_decl(function))
            .map(|function| {
                (
                    function.name.clone(),
                    collect_native_data_ops_for_function(function),
                )
            })
            .collect(),
    }
}

fn native_mangle_symbol(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn llvm_emit_expr(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    if let Some(result) = llvm_emit_complex_expr(expr, ctx, string_literal_ids, task_ref_ids) {
        return result;
    }
    if let Some(result) = llvm_emit_simple_expr(expr, ctx, string_literal_ids, task_ref_ids) {
        return result;
    }
    Ok(match expr {
        ast::Expr::Int(v) => {
            let ty = if i32::try_from(*v).is_ok() {
                "i32"
            } else {
                "i64"
            };
            LlvmValue {
                value: v.to_string(),
                ty: ty.to_string(),
            }
        }
        ast::Expr::Float { value, bits } => LlvmValue {
            value: llvm_float_literal(*value),
            ty: if bits.unwrap_or(64) == 32 {
                "float".to_string()
            } else {
                "double".to_string()
            },
        },
        ast::Expr::Char(value) => LlvmValue {
            value: (*value as i32).to_string(),
            ty: "i32".to_string(),
        },
        ast::Expr::Bool(v) => LlvmValue {
            value: if *v { "1".to_string() } else { "0".to_string() },
            ty: "i8".to_string(),
        },
        ast::Expr::Str(value) => LlvmValue {
            value: string_literal_ids
                .get(value)
                .copied()
                .unwrap_or(0)
                .to_string(),
            ty: "i32".to_string(),
        },
        ast::Expr::Ident(_) => unreachable!("simple expressions are handled above"),
        ast::Expr::Group(inner) => llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids)?,
        ast::Expr::Await(inner) => llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids)?,
        ast::Expr::Discard(_) => unreachable!("simple expressions are handled above"),
        ast::Expr::Closure { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::Unary { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::FieldAccess { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::StructInit { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::EnumInit { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::TryCatch { try_expr, .. } => {
            llvm_emit_expr(try_expr, ctx, string_literal_ids, task_ref_ids)?
        }
        ast::Expr::If { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::Range { start, .. } => {
            llvm_emit_expr(start, ctx, string_literal_ids, task_ref_ids)?
        }
        ast::Expr::ArrayLiteral(items) => {
            // Array literals are materialized by statement lowering into element slots.
            // Expression-position array literals are unsupported in direct-memory mode.
            for item in items {
                let _ = llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids)?;
            }
            LlvmValue {
                value: "0".to_string(),
                ty: "i32".to_string(),
            }
        }
        ast::Expr::ObjectLiteral(_) => unreachable!("complex expressions are handled above"),
        ast::Expr::Index { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::Call { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::UnsafeBlock { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::Binary { op, left, right } => {
            llvm_emit_binary_expr(*op, left, right, ctx, string_literal_ids, task_ref_ids)?
        }
        _ => LlvmValue {
            value: "0".to_string(),
            ty: "i32".to_string(),
        },
    })
}


fn expr_task_ref_name(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => Some(name.clone()),
        ast::Expr::FieldAccess { base, field } => {
            let mut name = expr_task_ref_name(base)?;
            name.push('.');
            name.push_str(field);
            Some(name)
        }
        ast::Expr::Group(inner) => expr_task_ref_name(inner),
        ast::Expr::Unary { expr, .. } => expr_task_ref_name(expr),
        _ => None,
    }
}

fn eval_const_string_expr(
    expr: &ast::Expr,
    const_strings: &HashMap<String, String>,
) -> Option<String> {
    match expr {
        ast::Expr::Str(value) => Some(value.clone()),
        ast::Expr::Ident(name) => const_strings.get(name).cloned(),
        ast::Expr::Group(inner) => eval_const_string_expr(inner, const_strings),
        ast::Expr::Call { callee, args } => eval_const_string_call(callee, args, const_strings),
        _ => None,
    }
}

fn eval_const_string_call(
    callee: &str,
    args: &[ast::Expr],
    const_strings: &HashMap<String, String>,
) -> Option<String> {
    match callee {
        "str.concat2" if args.len() == 2 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            Some(format!("{a}{b}"))
        }
        "str.concat3" if args.len() == 3 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            let c = eval_const_string_expr(&args[2], const_strings)?;
            Some(format!("{a}{b}{c}"))
        }
        "str.concat4" if args.len() == 4 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            let c = eval_const_string_expr(&args[2], const_strings)?;
            let d = eval_const_string_expr(&args[3], const_strings)?;
            Some(format!("{a}{b}{c}{d}"))
        }
        "str.concat" if !args.is_empty() => {
            let mut out = String::new();
            for arg in args {
                out.push_str(&eval_const_string_expr(arg, const_strings)?);
            }
            Some(out)
        }
        "str.trim" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            Some(value.trim().to_string())
        }
        "str.replace" if args.len() == 3 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let from = eval_const_string_expr(&args[1], const_strings)?;
            let to = eval_const_string_expr(&args[2], const_strings)?;
            Some(value.replace(&from, &to))
        }
        "str.slice" if args.len() == 3 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let start = eval_const_i32_expr(&args[1], const_strings)
                .unwrap_or(0)
                .max(0) as usize;
            let span = eval_const_i32_expr(&args[2], const_strings)
                .unwrap_or(0)
                .max(0) as usize;
            let len = value.len();
            let s = start.min(len);
            let e = s.saturating_add(span).min(len);
            if value.is_char_boundary(s) && value.is_char_boundary(e) {
                Some(value[s..e].to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn eval_const_i32_expr(expr: &ast::Expr, const_strings: &HashMap<String, String>) -> Option<i32> {
    match expr {
        ast::Expr::Int(value) => i32::try_from(*value).ok(),
        ast::Expr::Bool(value) => Some(if *value { 1 } else { 0 }),
        ast::Expr::Group(inner) => eval_const_i32_expr(inner, const_strings),
        ast::Expr::Call { callee, args } => eval_const_i32_call(callee, args, const_strings),
        _ => None,
    }
}

fn eval_const_i32_call(
    callee: &str,
    args: &[ast::Expr],
    const_strings: &HashMap<String, String>,
) -> Option<i32> {
    match callee {
        "str.contains" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let needle = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.contains(&needle) { 1 } else { 0 })
        }
        "str.starts_with" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let prefix = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.starts_with(&prefix) { 1 } else { 0 })
        }
        "str.ends_with" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let suffix = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.ends_with(&suffix) { 1 } else { 0 })
        }
        "str.len" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            i32::try_from(value.len()).ok()
        }
        _ => None,
    }
}

fn is_native_data_plane_string_call(callee: &str) -> bool {
    matches!(callee, "str.concat")
        || native_data_plane_import_for_callee(callee)
            .is_some_and(|import| import.callee.starts_with("str."))
}

fn canonicalize_array_index_window(expr: &ast::Expr) -> Option<(String, i32)> {
    match expr {
        ast::Expr::Ident(name) => Some((name.clone(), 0)),
        ast::Expr::Group(inner) => canonicalize_array_index_window(inner),
        ast::Expr::Binary { op, left, right } => match op {
            ast::BinaryOp::Add => match (left.as_ref(), right.as_ref()) {
                (ast::Expr::Ident(name), ast::Expr::Int(offset)) => {
                    i32::try_from(*offset).ok().map(|off| (name.clone(), off))
                }
                (ast::Expr::Int(offset), ast::Expr::Ident(name)) => {
                    i32::try_from(*offset).ok().map(|off| (name.clone(), off))
                }
                _ => None,
            },
            ast::BinaryOp::Sub => match (left.as_ref(), right.as_ref()) {
                (ast::Expr::Ident(name), ast::Expr::Int(offset)) => i32::try_from(*offset)
                    .ok()
                    .and_then(|off| off.checked_neg())
                    .map(|off| (name.clone(), off)),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn collect_used_runtime_imports_from_stmt(
    stmt: &ast::Stmt,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_used_runtime_imports_from_expr(value, seen, used),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            for nested in then_body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
            for nested in else_body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_used_runtime_imports_from_stmt(init, seen, used);
            }
            if let Some(condition) = condition {
                collect_used_runtime_imports_from_expr(condition, seen, used);
            }
            if let Some(step) = step {
                collect_used_runtime_imports_from_stmt(step, seen, used);
            }
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_used_runtime_imports_from_expr(iterable, seen, used);
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_used_runtime_imports_from_expr(scrutinee, seen, used);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_used_runtime_imports_from_expr(guard, seen, used);
                }
                collect_used_runtime_imports_from_expr(&arm.value, seen, used);
            }
        }
    }
}

fn collect_used_runtime_imports_from_expr(
    expr: &ast::Expr,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            let empty_const_strings = HashMap::<String, String>::new();
            let folded_const = eval_const_string_call(callee, args, &empty_const_strings).is_some()
                || eval_const_i32_call(callee, args, &empty_const_strings).is_some();
            if !folded_const {
                if let Some(import) = native_runtime_import_for_callee(callee) {
                    if seen.insert(import.symbol) {
                        used.push(import);
                    }
                }
            }
            for arg in args {
                collect_used_runtime_imports_from_expr(arg, seen, used);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::FieldAccess { base, .. } => {
            collect_used_runtime_imports_from_expr(base, seen, used);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::ObjectLiteral(fields) => {
            if let Some(import) = native_runtime_import_for_callee("map.new") {
                if seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            if let Some(import) = native_runtime_import_for_callee("map.set") {
                if seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            for (_, value) in fields {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_used_runtime_imports_from_expr(body, seen, used);
        }
        ast::Expr::Group(inner) => {
            collect_used_runtime_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_used_runtime_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_used_runtime_imports_from_expr(expr, seen, used);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_used_runtime_imports_from_expr(try_expr, seen, used);
            collect_used_runtime_imports_from_expr(catch_expr, seen, used);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            collect_used_runtime_imports_from_expr(then_expr, seen, used);
            collect_used_runtime_imports_from_expr(else_expr, seen, used);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_used_runtime_imports_from_expr(left, seen, used);
            collect_used_runtime_imports_from_expr(right, seen, used);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_used_runtime_imports_from_expr(start, seen, used);
            collect_used_runtime_imports_from_expr(end, seen, used);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_used_runtime_imports_from_expr(item, seen, used);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_used_runtime_imports_from_expr(base, seen, used);
            collect_used_runtime_imports_from_expr(index, seen, used);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn collect_used_data_plane_imports_from_stmt(
    stmt: &ast::Stmt,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_used_data_plane_imports_from_expr(value, seen, used),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            for nested in then_body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
            for nested in else_body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_used_data_plane_imports_from_stmt(init, seen, used);
            }
            if let Some(condition) = condition {
                collect_used_data_plane_imports_from_expr(condition, seen, used);
            }
            if let Some(step) = step {
                collect_used_data_plane_imports_from_stmt(step, seen, used);
            }
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_used_data_plane_imports_from_expr(iterable, seen, used);
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_used_data_plane_imports_from_expr(scrutinee, seen, used);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_used_data_plane_imports_from_expr(guard, seen, used);
                }
                collect_used_data_plane_imports_from_expr(&arm.value, seen, used);
            }
        }
    }
}

fn collect_used_data_plane_imports_from_expr(
    expr: &ast::Expr,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if let Some(import) = native_data_plane_import_for_callee(callee) {
                let empty_const_strings = HashMap::<String, String>::new();
                let folded_const = eval_const_string_call(callee, args, &empty_const_strings)
                    .is_some()
                    || eval_const_i32_call(callee, args, &empty_const_strings).is_some();
                let can_skip = folded_const && callee.starts_with("str.");
                if !can_skip && seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            for arg in args {
                collect_used_data_plane_imports_from_expr(arg, seen, used);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::FieldAccess { base, .. } => {
            collect_used_data_plane_imports_from_expr(base, seen, used);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_used_data_plane_imports_from_expr(body, seen, used);
        }
        ast::Expr::Group(inner) => {
            collect_used_data_plane_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_used_data_plane_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_used_data_plane_imports_from_expr(expr, seen, used);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_used_data_plane_imports_from_expr(try_expr, seen, used);
            collect_used_data_plane_imports_from_expr(catch_expr, seen, used);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            collect_used_data_plane_imports_from_expr(then_expr, seen, used);
            collect_used_data_plane_imports_from_expr(else_expr, seen, used);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_used_data_plane_imports_from_expr(left, seen, used);
            collect_used_data_plane_imports_from_expr(right, seen, used);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_used_data_plane_imports_from_expr(start, seen, used);
            collect_used_data_plane_imports_from_expr(end, seen, used);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_used_data_plane_imports_from_expr(item, seen, used);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_used_data_plane_imports_from_expr(base, seen, used);
            collect_used_data_plane_imports_from_expr(index, seen, used);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

struct ResolvedSource {
    source_path: PathBuf,
    project_root: PathBuf,
    manifest: Option<manifest::Manifest>,
    dependency_graph_hash: Option<String>,
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
    let mut parsed = manifest::load(&contents).context("failed parsing fozzy.toml")?;
    apply_workspace_policy(dir, &mut parsed)?;
    parsed
        .validate()
        .map_err(|err| anyhow!("invalid fozzy.toml: {err}"))?;
    validate_dependency_paths(dir, &parsed)?;
    let graph_hash = write_lockfile(dir, &parsed, &contents, lock_mode)?;
    Ok((parsed, primary, graph_hash))
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
                    return Err(anyhow!(
                        "lockfile drift detected at {}: expected dependencyGraphHash={} (run `fz vendor {}` to refresh)",
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
                let dep_manifest_path = canonical.join("fozzy.toml");
                let dep_manifest_text =
                    std::fs::read_to_string(&dep_manifest_path).with_context(|| {
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
                    "sourceType": "path",
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
            "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
            other
        )),
    }
}

fn emit_native_libraries(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let backend = resolve_native_backend(profile, backend_override)?;
    match backend.as_str() {
        "llvm" => emit_native_libraries_llvm(fir, project_root, profile, manifest),
        "cranelift" => emit_native_libraries_cranelift(fir, project_root, profile, manifest),
        other => Err(anyhow!(
            "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
            other
        )),
    }
}

fn emit_native_libraries_llvm(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let ll_path = build_dir.join(format!("{}.ll", fir.name));
    let obj_path = build_dir.join(format!("{}.ffi.o", fir.name));
    let shim_obj_path = build_dir.join(format!("{}.ffi.runtime.o", fir.name));
    let static_path = build_dir.join(format!("lib{}.a", fir.name));
    let shared_path = build_dir.join(format!("lib{}.{}", fir.name, shared_lib_extension()));

    let string_literals = collect_native_string_literals(fir);
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    let async_exports = collect_async_c_exports(fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &async_exports,
    )?;
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let llvm_ir = lower_llvm_ir(fir, enforce_contract_checks)?;
    std::fs::write(&ll_path, llvm_ir)
        .with_context(|| format!("failed writing llvm ir: {}", ll_path.display()))?;

    let candidates = linker_candidates();
    let mut obj_compiled = false;
    let mut shim_compiled = false;
    let mut last_error = None;
    for tool in &candidates {
        let mut obj_cmd = Command::new(tool);
        obj_cmd
            .arg("-x")
            .arg("ir")
            .arg(&ll_path)
            .arg("-c")
            .arg("-fPIC")
            .arg("-o")
            .arg(&obj_path);
        apply_target_link_flags(&mut obj_cmd);
        apply_profile_optimization_flags(&mut obj_cmd, profile, manifest);
        apply_pgo_flags(&mut obj_cmd)?;
        match obj_cmd.output() {
            Ok(output) if output.status.success() => {
                obj_compiled = true;
            }
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed compiling llvm object: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
                continue;
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
                continue;
            }
        }

        let mut shim_cmd = Command::new(tool);
        shim_cmd
            .arg("-x")
            .arg("c")
            .arg(&runtime_shim_path)
            .arg("-c")
            .arg("-fPIC")
            .arg("-o")
            .arg(&shim_obj_path);
        apply_target_link_flags(&mut shim_cmd);
        apply_profile_optimization_flags(&mut shim_cmd, profile, manifest);
        apply_pgo_flags(&mut shim_cmd)?;
        match shim_cmd.output() {
            Ok(output) if output.status.success() => {
                shim_compiled = true;
                break;
            }
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed compiling runtime shim object: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    if !obj_compiled || !shim_compiled {
        return Err(anyhow!(
            "failed compiling ffi library objects: {}",
            last_error.unwrap_or_else(|| "unknown compiler error".to_string())
        ));
    }

    create_static_archive(&static_path, &[obj_path.as_path(), shim_obj_path.as_path()])?;
    let allow_undefined = !collect_extern_c_imports(fir).is_empty();
    link_shared_library(
        &shared_path,
        &[obj_path.as_path(), shim_obj_path.as_path()],
        manifest,
        allow_undefined,
    )?;
    Ok((Some(static_path), Some(shared_path)))
}

fn emit_native_libraries_cranelift(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;
    let object_path = build_dir.join(format!("{}.ffi.o", fir.name));
    let shim_obj_path = build_dir.join(format!("{}.ffi.runtime.o", fir.name));
    let static_path = build_dir.join(format!("lib{}.a", fir.name));
    let shared_path = build_dir.join(format!("lib{}.{}", fir.name, shared_lib_extension()));

    let string_literals = collect_native_string_literals(fir);
    let plan = build_native_canonical_plan(fir, true);
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
    flags_builder
        .set("is_pic", "true")
        .map_err(|error| anyhow!("failed enabling cranelift PIC codegen: {error}"))?;
    let flags = settings::Flags::new(flags_builder);
    let isa_builder = cranelift_native::builder()
        .map_err(|error| anyhow!("failed constructing cranelift native isa: {error}"))?;
    let isa = isa_builder
        .finish(flags)
        .map_err(|error| anyhow!("failed finalizing cranelift isa: {error}"))?;
    let object_builder = ObjectBuilder::new(isa, fir.name.clone(), default_libcall_names())
        .map_err(|error| anyhow!("failed creating cranelift object builder: {error}"))?;
    let mut module = ObjectModule::new(object_builder);

    let mut function_ids = HashMap::new();
    let mut function_signatures = HashMap::new();
    let mut mutable_global_data_ids = HashMap::<String, cranelift_module::DataId>::new();
    let mut mutable_globals_sorted = plan
        .mutable_static_i32
        .iter()
        .map(|(name, value)| (name.clone(), *value))
        .collect::<Vec<_>>();
    mutable_globals_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in mutable_globals_sorted {
        let symbol = llvm_static_symbol_name(&name);
        let data_id = module
            .declare_data(&symbol, Linkage::Local, true, false)
            .map_err(|error| anyhow!("failed declaring mutable static `{name}` data: {error}"))?;
        let mut data = DataDescription::new();
        data.define((value as i32).to_le_bytes().to_vec().into_boxed_slice());
        module
            .define_data(data_id, &data)
            .map_err(|error| anyhow!("failed defining mutable static `{name}` data: {error}"))?;
        mutable_global_data_ids.insert(name, data_id);
    }
    for function in &fir.typed_functions {
        let mut sig = module.make_signature();
        let mut param_tys = Vec::new();
        for param in &function.params {
            let ty = ast_signature_type_to_clif_type(&param.ty)
                .ok_or_else(|| anyhow!("unsupported native parameter type `{}`", param.ty))?;
            sig.params.push(AbiParam::new(ty));
            param_tys.push(ty);
        }
        let ret_ty = ast_signature_type_to_clif_type(&function.return_type);
        if let Some(ret_ty) = ret_ty {
            sig.returns.push(AbiParam::new(ret_ty));
        }
        let linkage = if is_extern_c_import_decl(function) {
            Linkage::Import
        } else {
            Linkage::Export
        };
        let symbol_name = native_link_symbol_for_function(function);
        let id = module
            .declare_function(symbol_name.as_str(), linkage, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring cranelift ffi symbol `{}`: {error}",
                    function.name
                )
            })?;
        function_ids.insert(function.name.clone(), id);
        function_signatures.insert(
            function.name.clone(),
            ClifFunctionSignature {
                params: param_tys,
                ret: ret_ty,
            },
        );
    }
    declare_native_runtime_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    declare_native_data_plane_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    for function in &fir.typed_functions {
        if is_extern_c_import_decl(function) {
            continue;
        }
        let Some(function_id) = function_ids.get(&function.name).copied() else {
            continue;
        };
        let mut context = module.make_context();
        context.func.signature.params.clear();
        context.func.signature.returns.clear();
        let signature = function_signatures
            .get(&function.name)
            .ok_or_else(|| anyhow!("missing signature for `{}`", function.name))?;
        for param_ty in &signature.params {
            context.func.signature.params.push(AbiParam::new(*param_ty));
        }
        if let Some(ret_ty) = signature.ret {
            context.func.signature.returns.push(AbiParam::new(ret_ty));
        }

        let mut function_builder_context = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);

        let mut locals = HashMap::<String, LocalBinding>::new();
        for (index, param) in function.params.iter().enumerate() {
            let var = Variable::from_u32(index as u32);
            let param_ty =
                signature.params.get(index).copied().ok_or_else(|| {
                    anyhow!("missing param {} type for `{}`", index, function.name)
                })?;
            builder.declare_var(var, param_ty);
            let value = builder.block_params(entry)[index];
            builder.def_var(var, value);
            locals.insert(param.name.clone(), LocalBinding { var, ty: param_ty });
        }
        let mut next_var = function.params.len();
        let cfg = match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => cfg,
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        };
        clif_emit_function_cfg(
            &mut builder,
            &mut module,
            &function_ids,
            &function_signatures,
            &plan.string_literal_ids,
            &plan.task_ref_ids,
            &plan.global_const_i32,
            &plan.variant_tags,
            &mutable_global_data_ids,
            signature.ret,
            cfg,
            entry,
            &mut locals,
            &mut next_var,
            None,
        )?;
        builder.finalize();
        module
            .define_function(function_id, &mut context)
            .map_err(|error| {
                anyhow!(
                    "failed defining cranelift ffi function `{}`: {error}",
                    function.name
                )
            })?;
        module.clear_context(&mut context);
    }
    let object_product = module.finish();
    let object_bytes = object_product
        .emit()
        .map_err(|error| anyhow!("failed emitting cranelift object bytes: {error}"))?;
    std::fs::write(&object_path, object_bytes).with_context(|| {
        format!(
            "failed writing cranelift ffi object: {}",
            object_path.display()
        )
    })?;

    let async_exports = collect_async_c_exports(fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &async_exports,
    )?;
    compile_runtime_shim_object(&runtime_shim_path, &shim_obj_path, profile, manifest)?;
    create_static_archive(
        &static_path,
        &[object_path.as_path(), shim_obj_path.as_path()],
    )?;
    let allow_undefined = !collect_extern_c_imports(fir).is_empty();
    link_shared_library(
        &shared_path,
        &[object_path.as_path(), shim_obj_path.as_path()],
        manifest,
        allow_undefined,
    )?;
    Ok((Some(static_path), Some(shared_path)))
}

fn create_static_archive(output: &Path, objects: &[&Path]) -> Result<()> {
    let candidates = archiver_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("rcs").arg(output);
        for object in objects {
            cmd.arg(object);
        }
        match cmd.output() {
            Ok(output_result) if output_result.status.success() => return Ok(()),
            Ok(output_result) => {
                last_error = Some(format!(
                    "{} failed creating static archive: {}",
                    tool,
                    String::from_utf8_lossy(&output_result.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    Err(anyhow!(
        "failed to create static archive {}: {}",
        output.display(),
        last_error.unwrap_or_else(|| "unknown archiver error".to_string())
    ))
}

fn link_shared_library(
    output: &Path,
    objects: &[&Path],
    manifest: Option<&manifest::Manifest>,
    allow_undefined: bool,
) -> Result<()> {
    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        if cfg!(target_vendor = "apple") {
            cmd.arg("-dynamiclib");
            if allow_undefined {
                cmd.arg("-Wl,-undefined,dynamic_lookup");
            }
        } else {
            cmd.arg("-shared");
            if allow_undefined {
                cmd.arg("-Wl,--allow-shlib-undefined");
            }
        }
        for object in objects {
            cmd.arg(object);
        }
        cmd.arg("-o").arg(output);
        apply_target_link_flags(&mut cmd);
        apply_manifest_link_args(&mut cmd, manifest);
        apply_extra_linker_args(&mut cmd);
        apply_pgo_flags(&mut cmd)?;
        match cmd.output() {
            Ok(output_result) if output_result.status.success() => return Ok(()),
            Ok(output_result) => {
                last_error = Some(format!(
                    "{} failed linking shared library: {}",
                    tool,
                    String::from_utf8_lossy(&output_result.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    Err(anyhow!(
        "failed to link shared library {}: {}",
        output.display(),
        last_error.unwrap_or_else(|| "unknown linker error".to_string())
    ))
}

fn shared_lib_extension() -> &'static str {
    if cfg!(target_vendor = "apple") {
        "dylib"
    } else if cfg!(target_os = "windows") {
        "dll"
    } else {
        "so"
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
    if let Ok(explicit) = std::env::var("FZ_NATIVE_BACKEND") {
        let normalized = explicit.trim().to_ascii_lowercase();
        return match normalized.as_str() {
            "llvm" | "cranelift" => Ok(normalized),
            other => Err(anyhow!(
                "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
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
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let ll_path = build_dir.join(format!("{}.ll", fir.name));
    let bin_path = build_dir.join(fir.name.as_str());
    let string_literals = collect_native_string_literals(fir);
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    let async_exports = collect_async_c_exports(fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &async_exports,
    )?;
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let llvm_ir = lower_llvm_ir(fir, enforce_contract_checks)?;
    std::fs::write(&ll_path, llvm_ir)
        .with_context(|| format!("failed writing llvm ir: {}", ll_path.display()))?;

    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("-x")
            .arg("ir")
            .arg(&ll_path)
            .arg("-x")
            .arg("c")
            .arg(&runtime_shim_path)
            .arg("-o")
            .arg(&bin_path);
        apply_target_link_flags(&mut cmd);
        apply_manifest_link_args(&mut cmd, manifest);
        apply_profile_optimization_flags(&mut cmd, profile, manifest);
        apply_extra_linker_args(&mut cmd);
        apply_pgo_flags(&mut cmd)?;

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
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let object_path = build_dir.join(format!("{}.o", fir.name));
    let bin_path = build_dir.join(fir.name.as_str());
    let string_literals = collect_native_string_literals(fir);
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
    flags_builder
        .set("is_pic", "true")
        .map_err(|error| anyhow!("failed enabling cranelift PIC codegen: {error}"))?;
    let flags = settings::Flags::new(flags_builder);
    let isa_builder = cranelift_native::builder()
        .map_err(|error| anyhow!("failed constructing cranelift native isa: {error}"))?;
    let isa = isa_builder
        .finish(flags)
        .map_err(|error| anyhow!("failed finalizing cranelift isa: {error}"))?;

    let object_builder = ObjectBuilder::new(isa, fir.name.clone(), default_libcall_names())
        .map_err(|error| anyhow!("failed creating cranelift object builder: {error}"))?;
    let mut module = ObjectModule::new(object_builder);
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let plan = build_native_canonical_plan(fir, enforce_contract_checks);

    let mut function_ids = HashMap::new();
    let mut function_signatures = HashMap::new();
    let mut mutable_global_data_ids = HashMap::<String, cranelift_module::DataId>::new();
    let mut mutable_globals_sorted = plan
        .mutable_static_i32
        .iter()
        .map(|(name, value)| (name.clone(), *value))
        .collect::<Vec<_>>();
    mutable_globals_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in mutable_globals_sorted {
        let symbol = llvm_static_symbol_name(&name);
        let data_id = module
            .declare_data(&symbol, Linkage::Local, true, false)
            .map_err(|error| anyhow!("failed declaring mutable static `{name}` data: {error}"))?;
        let mut data = DataDescription::new();
        data.define((value as i32).to_le_bytes().to_vec().into_boxed_slice());
        module
            .define_data(data_id, &data)
            .map_err(|error| anyhow!("failed defining mutable static `{name}` data: {error}"))?;
        mutable_global_data_ids.insert(name, data_id);
    }
    for function in &fir.typed_functions {
        let mut sig = module.make_signature();
        let mut param_tys = Vec::new();
        for param in &function.params {
            let ty = ast_signature_type_to_clif_type(&param.ty)
                .ok_or_else(|| anyhow!("unsupported native parameter type `{}`", param.ty))?;
            sig.params.push(AbiParam::new(ty));
            param_tys.push(ty);
        }
        let ret_ty = ast_signature_type_to_clif_type(&function.return_type);
        if let Some(ret_ty) = ret_ty {
            sig.returns.push(AbiParam::new(ret_ty));
        }
        let linkage = if is_extern_c_import_decl(function) {
            Linkage::Import
        } else {
            Linkage::Export
        };
        let symbol_name = native_link_symbol_for_function(function);
        let id = module
            .declare_function(symbol_name.as_str(), linkage, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring cranelift symbol `{}`: {error}",
                    function.name
                )
            })?;
        function_ids.insert(function.name.clone(), id);
        function_signatures.insert(
            function.name.clone(),
            ClifFunctionSignature {
                params: param_tys,
                ret: ret_ty,
            },
        );
    }
    declare_native_runtime_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    declare_native_data_plane_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    let async_exports = collect_async_c_exports(fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &async_exports,
    )?;

    for function in &fir.typed_functions {
        if is_extern_c_import_decl(function) {
            continue;
        }
        let Some(function_id) = function_ids.get(&function.name).copied() else {
            continue;
        };
        let mut context = module.make_context();
        context.func.signature.params.clear();
        context.func.signature.returns.clear();
        let signature = function_signatures
            .get(&function.name)
            .ok_or_else(|| anyhow!("missing signature for `{}`", function.name))?;
        for param_ty in &signature.params {
            context.func.signature.params.push(AbiParam::new(*param_ty));
        }
        if let Some(ret_ty) = signature.ret {
            context.func.signature.returns.push(AbiParam::new(ret_ty));
        }

        let mut function_builder_context = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);

        let mut locals = HashMap::<String, LocalBinding>::new();
        for (index, param) in function.params.iter().enumerate() {
            let var = Variable::from_u32(index as u32);
            let param_ty =
                signature.params.get(index).copied().ok_or_else(|| {
                    anyhow!("missing param {} type for `{}`", index, function.name)
                })?;
            builder.declare_var(var, param_ty);
            let value = builder.block_params(entry)[index];
            builder.def_var(var, value);
            locals.insert(param.name.clone(), LocalBinding { var, ty: param_ty });
        }
        let mut next_var = function.params.len();
        let cfg = match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => cfg,
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        };
        clif_emit_function_cfg(
            &mut builder,
            &mut module,
            &function_ids,
            &function_signatures,
            &plan.string_literal_ids,
            &plan.task_ref_ids,
            &plan.global_const_i32,
            &plan.variant_tags,
            &mutable_global_data_ids,
            signature.ret,
            cfg,
            entry,
            &mut locals,
            &mut next_var,
            if function.name == "main" && signature.ret == Some(types::I32) {
                Some(
                    plan.forced_main_return
                        .or(fir.entry_return_const_i32)
                        .unwrap_or(0),
                )
            } else {
                None
            },
        )?;
        builder.finalize();

        module
            .define_function(function_id, &mut context)
            .map_err(|error| {
                anyhow!(
                    "failed defining cranelift function `{}`: {error}",
                    function.name
                )
            })?;
        module.clear_context(&mut context);
    }
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
        cmd.arg(&object_path)
            .arg(&runtime_shim_path)
            .arg("-o")
            .arg(&bin_path)
            .arg("-lpthread");
        apply_target_link_flags(&mut cmd);
        apply_manifest_link_args(&mut cmd, manifest);
        // Object code is already generated at selected Cranelift optimization level.
        apply_extra_linker_args(&mut cmd);
        apply_pgo_flags(&mut cmd)?;

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


#[cfg(test)]
mod tests;
