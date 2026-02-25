use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{types, AbiParam, InstBuilder};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_module::{default_libcall_names, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy)]
struct NativeRuntimeImport {
    callee: &'static str,
    symbol: &'static str,
    arity: usize,
}

const NATIVE_RUNTIME_IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "net.bind",
        symbol: "fz_native_net_bind",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "net.listen",
        symbol: "fz_native_net_listen",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "net.accept",
        symbol: "fz_native_net_accept",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "net.read",
        symbol: "fz_native_net_read",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "env.get",
        symbol: "fz_native_env_get",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.now",
        symbol: "fz_native_time_now",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "str.concat",
        symbol: "fz_native_str_concat2",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.concat2",
        symbol: "fz_native_str_concat2",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.concat3",
        symbol: "fz_native_str_concat3",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "str.concat4",
        symbol: "fz_native_str_concat4",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "str.contains",
        symbol: "fz_native_str_contains",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.starts_with",
        symbol: "fz_native_str_starts_with",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.ends_with",
        symbol: "fz_native_str_ends_with",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.replace",
        symbol: "fz_native_str_replace",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "str.trim",
        symbol: "fz_native_str_trim",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.split",
        symbol: "fz_native_str_split",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.len",
        symbol: "fz_native_str_len",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.slice",
        symbol: "fz_native_str_slice",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.header",
        symbol: "fz_native_http_header",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.post_json",
        symbol: "fz_native_http_post_json",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.post_json_capture",
        symbol: "fz_native_http_post_json_capture",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.last_status",
        symbol: "fz_native_http_last_status",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "json.escape",
        symbol: "fz_native_json_escape",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.str",
        symbol: "fz_native_json_str",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.raw",
        symbol: "fz_native_json_raw",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.array1",
        symbol: "fz_native_json_array1",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.array2",
        symbol: "fz_native_json_array2",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "json.array3",
        symbol: "fz_native_json_array3",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "json.array4",
        symbol: "fz_native_json_array4",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "json.object1",
        symbol: "fz_native_json_object1",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "json.object2",
        symbol: "fz_native_json_object2",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "json.object3",
        symbol: "fz_native_json_object3",
        arity: 6,
    },
    NativeRuntimeImport {
        callee: "json.object4",
        symbol: "fz_native_json_object4",
        arity: 8,
    },
    NativeRuntimeImport {
        callee: "json.from_list",
        symbol: "fz_native_json_from_list",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.from_map",
        symbol: "fz_native_json_from_map",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.to_list",
        symbol: "fz_native_json_to_list",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.to_map",
        symbol: "fz_native_json_to_map",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "net.method",
        symbol: "fz_native_net_method",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "net.path",
        symbol: "fz_native_net_path",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "net.body",
        symbol: "fz_native_net_body",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "net.header",
        symbol: "fz_native_net_header",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "net.query",
        symbol: "fz_native_net_query",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "net.param",
        symbol: "fz_native_net_param",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "net.headers",
        symbol: "fz_native_net_headers",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "net.request_id",
        symbol: "fz_native_net_request_id",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "net.remote_addr",
        symbol: "fz_native_net_remote_addr",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "net.write",
        symbol: "fz_native_net_write",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "net.write_json",
        symbol: "fz_native_net_write_json",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "net.write_response",
        symbol: "fz_native_net_write_response",
        arity: 5,
    },
    NativeRuntimeImport {
        callee: "net.close",
        symbol: "fz_native_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "route.match",
        symbol: "fz_native_route_match",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "route.write_404",
        symbol: "fz_native_route_write_404",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "route.write_405",
        symbol: "fz_native_route_write_405",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.open",
        symbol: "fz_native_fs_open",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.write",
        symbol: "fz_native_fs_write",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.read",
        symbol: "fz_native_fs_read",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.flush",
        symbol: "fz_native_fs_flush",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.fsync",
        symbol: "fz_native_fs_fsync",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.atomic_write",
        symbol: "fz_native_fs_atomic_write",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.rename_atomic",
        symbol: "fz_native_fs_rename_atomic",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.read_file",
        symbol: "fz_native_fs_read_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.write_file",
        symbol: "fz_native_fs_write_file",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "fs.mkdir",
        symbol: "fz_native_fs_mkdir",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.exists",
        symbol: "fz_native_fs_exists",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.stat_size",
        symbol: "fz_native_fs_stat_size",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.listdir",
        symbol: "fz_native_fs_listdir",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.remove_file",
        symbol: "fz_native_fs_remove_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.temp_file",
        symbol: "fz_native_fs_temp_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "path.join",
        symbol: "fz_native_path_join",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "path.normalize",
        symbol: "fz_native_path_normalize",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "list.new",
        symbol: "fz_native_list_new",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "list.push",
        symbol: "fz_native_list_push",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "list.pop",
        symbol: "fz_native_list_pop",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "list.len",
        symbol: "fz_native_list_len",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "list.get",
        symbol: "fz_native_list_get",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "list.set",
        symbol: "fz_native_list_set",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "list.clear",
        symbol: "fz_native_list_clear",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "list.join",
        symbol: "fz_native_list_join",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.new",
        symbol: "fz_native_map_new",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "map.set",
        symbol: "fz_native_map_set",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "map.get",
        symbol: "fz_native_map_get",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.has",
        symbol: "fz_native_map_has",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.delete",
        symbol: "fz_native_map_delete",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.keys",
        symbol: "fz_native_map_keys",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "map.len",
        symbol: "fz_native_map_len",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.info",
        symbol: "fz_native_log_info",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "log.warn",
        symbol: "fz_native_log_warn",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "log.error",
        symbol: "fz_native_log_error",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "log.set_json",
        symbol: "fz_native_log_set_json",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.correlation_id",
        symbol: "fz_native_log_correlation_id",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "error.code",
        symbol: "fz_native_error_code",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "error.class",
        symbol: "fz_native_error_class",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "error.message",
        symbol: "fz_native_error_message",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "error.context",
        symbol: "fz_native_error_context",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.monotonic_ms",
        symbol: "fz_native_time_now",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "time.sleep_ms",
        symbol: "fz_native_time_sleep_ms",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.interval",
        symbol: "fz_native_time_interval",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.tick",
        symbol: "fz_native_time_tick",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.elapsed_ms",
        symbol: "fz_native_time_elapsed_ms",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.deadline_after",
        symbol: "fz_native_time_deadline_after",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "close",
        symbol: "fz_native_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "spawn",
        symbol: "fz_native_spawn",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "yield",
        symbol: "fz_native_yield",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "checkpoint",
        symbol: "fz_native_checkpoint",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "pulse",
        symbol: "fz_native_pulse",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "net.poll_next",
        symbol: "fz_native_net_poll_next",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "process.run",
        symbol: "fz_native_proc_run",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.run",
        symbol: "fz_native_proc_run",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "process.spawn",
        symbol: "fz_native_proc_spawn",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "process.runv",
        symbol: "fz_native_proc_runv",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.runv",
        symbol: "fz_native_proc_runv",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "process.spawnv",
        symbol: "fz_native_proc_spawnv",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.spawnv",
        symbol: "fz_native_proc_spawnv",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.spawn",
        symbol: "fz_native_proc_spawn",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "process.exec_timeout",
        symbol: "fz_native_proc_exec_timeout",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.exec_timeout",
        symbol: "fz_native_proc_exec_timeout",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "process.exit_class",
        symbol: "fz_native_proc_exit_class",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "proc.exit_class",
        symbol: "fz_native_proc_exit_class",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "process.wait",
        symbol: "fz_native_proc_wait",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.wait",
        symbol: "fz_native_proc_wait",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "process.poll",
        symbol: "fz_native_proc_poll",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.poll",
        symbol: "fz_native_proc_poll",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "process.event",
        symbol: "fz_native_proc_event",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.event",
        symbol: "fz_native_proc_event",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "process.read_stdout",
        symbol: "fz_native_proc_read_stdout",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.read_stdout",
        symbol: "fz_native_proc_read_stdout",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "process.read_stderr",
        symbol: "fz_native_proc_read_stderr",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.read_stderr",
        symbol: "fz_native_proc_read_stderr",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "process.stdout",
        symbol: "fz_native_proc_stdout",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.stdout",
        symbol: "fz_native_proc_stdout",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "process.stderr",
        symbol: "fz_native_proc_stderr",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.stderr",
        symbol: "fz_native_proc_stderr",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "process.exit_code",
        symbol: "fz_native_proc_exit_code",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.exit_code",
        symbol: "fz_native_proc_exit_code",
        arity: 1,
    },
];

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
    let native_lowerability_errors = native_lowerability_diagnostics(&parsed.module);
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
    let has_verifier_errors = report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_native_lowerability_errors = !native_lowerability_errors.is_empty();
    let status = if has_native_lowerability_errors || (checks_enabled && has_verifier_errors) {
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
        diagnostics: report.diagnostics.len() + native_lowerability_errors.len(),
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
    let typed = hir::lower(&parsed.module);
    let fir = fir::build(&typed);
    let report = verifier::verify(&fir);
    diagnostics.extend(report.diagnostics);
    for diagnostic in &mut diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(resolved.source_path.display().to_string());
        }
    }
    enrich_diagnostics_context(&mut diagnostics);

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
    let typed = hir::lower(&parsed.module);
    let fir = fir::build(&typed);
    let report = verifier::verify(&fir);
    diagnostics.extend(report.diagnostics);
    for diagnostic in &mut diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(source_path.display().to_string());
        }
    }
    enrich_diagnostics_context(&mut diagnostics);
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
    load_module_recursive(&canonical, &canonical, &mut state)?;

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
    canonicalize_call_targets(&mut merged);

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

fn load_module_recursive(
    path: &Path,
    root_source: &Path,
    state: &mut ModuleLoadState,
) -> Result<()> {
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
    let mut ast = parser::parse(&source, module_name)
        .map_err(|diagnostics| anyhow!(render_parse_failure(&canonical, &diagnostics)))?;
    let namespace = module_namespace(root_source, &canonical)?;
    qualify_module_symbols(&mut ast, &namespace);

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
        load_module_recursive(&module_path, root_source, state)?;
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
    let module_aliases = module
        .modules
        .iter()
        .map(|module_name| {
            (
                module_name.clone(),
                qualify_name(namespace, module_name.as_str()),
            )
        })
        .collect::<HashMap<_, _>>();

    for item in &mut module.items {
        if let ast::Item::Function(function) = item {
            qualify_function(function, namespace, &local_functions, &module_aliases);
        }
    }
}

fn qualify_function(
    function: &mut ast::Function,
    namespace: &str,
    local_functions: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    if !function.is_extern {
        function.name = qualify_name(namespace, &function.name);
    }
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
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::Return(value)
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => qualify_expr(value, namespace, local_functions, module_aliases),
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
        ast::Expr::Group(inner) => {
            qualify_expr(inner, namespace, local_functions, module_aliases);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            qualify_expr(try_expr, namespace, local_functions, module_aliases);
            qualify_expr(catch_expr, namespace, local_functions, module_aliases);
        }
        ast::Expr::Binary { left, right, .. } => {
            qualify_expr(left, namespace, local_functions, module_aliases);
            qualify_expr(right, namespace, local_functions, module_aliases);
        }
        ast::Expr::Int(_) | ast::Expr::Bool(_) | ast::Expr::Str(_) | ast::Expr::Ident(_) => {}
    }
}

fn qualify_callee(
    callee: &str,
    namespace: &str,
    local_functions: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) -> String {
    let (base, generic_suffix) = split_generic_suffix(callee);
    let qualified_base = if let Some((head, tail)) = base.split_once('.') {
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
    let known_functions = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) => Some(function.name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
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

fn canonicalize_stmt_calls(
    stmt: &mut ast::Stmt,
    namespace: &str,
    known_functions: &HashSet<String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::Return(value)
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => canonicalize_expr_calls(value, namespace, known_functions),
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
            for arg in args {
                canonicalize_expr_calls(arg, namespace, known_functions);
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
        ast::Expr::Group(inner) => {
            canonicalize_expr_calls(inner, namespace, known_functions);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            canonicalize_expr_calls(try_expr, namespace, known_functions);
            canonicalize_expr_calls(catch_expr, namespace, known_functions);
        }
        ast::Expr::Binary { left, right, .. } => {
            canonicalize_expr_calls(left, namespace, known_functions);
            canonicalize_expr_calls(right, namespace, known_functions);
        }
        ast::Expr::Int(_) | ast::Expr::Bool(_) | ast::Expr::Str(_) | ast::Expr::Ident(_) => {}
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

fn collect_parse_diagnostics(source_path: &Path) -> Result<Vec<diagnostics::Diagnostic>> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    let mut visited = HashSet::<PathBuf>::new();
    let mut visiting = HashSet::<PathBuf>::new();
    match collect_parse_diagnostics_recursive(&canonical, &mut visited, &mut visiting)? {
        Some((failed_path, diagnostics)) => Ok(diagnostics
            .into_iter()
            .map(|diagnostic| annotate_parse_diagnostic(diagnostic, &failed_path))
            .collect()),
        None => Ok(Vec::new()),
    }
}

fn collect_parse_diagnostics_recursive(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    visiting: &mut HashSet<PathBuf>,
) -> Result<Option<(PathBuf, Vec<diagnostics::Diagnostic>)>> {
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
        Err(diagnostics) => return Ok(Some((canonical.clone(), diagnostics))),
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
        if let Some(failure) = collect_parse_diagnostics_recursive(&module_path, visited, visiting)?
        {
            return Ok(Some(failure));
        }
    }
    visiting.remove(&canonical);
    Ok(None)
}

fn annotate_parse_diagnostic(
    mut diagnostic: diagnostics::Diagnostic,
    module_path: &Path,
) -> diagnostics::Diagnostic {
    diagnostic.path = Some(module_path.display().to_string());
    let mut help = diagnostic.help.unwrap_or_default();
    if !help.is_empty() {
        help.push(' ');
    }
    help.push_str(&format!("source: {}", module_path.display()));
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
            }
        }
    }
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
    let forced_main_return = if enforce_contract_checks {
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
    } else {
        None
    };
    if fir.typed_functions.is_empty() {
        let ret = forced_main_return
            .or(fir.entry_return_const_i32)
            .unwrap_or(0);
        return format!(
            "; ModuleID = '{name}'\ndefine i32 @main() {{\nentry:\n  ret i32 {ret}\n}}\n",
            name = fir.name
        );
    }

    let mut out = format!("; ModuleID = '{}'\n", fir.name);
    let used_imports = collect_used_native_runtime_imports(fir);
    for import in &used_imports {
        let mut params = String::new();
        for index in 0..import.arity {
            if index > 0 {
                params.push_str(", ");
            }
            params.push_str("i32");
        }
        let _ = writeln!(&mut out, "declare i32 @{}({})", import.symbol, params);
    }
    if !used_imports.is_empty() {
        out.push('\n');
    }
    let string_literal_ids = build_string_literal_ids(&collect_string_literals(fir));
    for function in &fir.typed_functions {
        out.push_str(&llvm_emit_function(
            function,
            forced_main_return.filter(|_| function.name == "main"),
            &string_literal_ids,
        ));
        out.push('\n');
    }
    out
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

struct LlvmFuncCtx {
    next_value: usize,
    next_label: usize,
    slots: HashMap<String, String>,
    code: String,
}

impl LlvmFuncCtx {
    fn new() -> Self {
        Self {
            next_value: 0,
            next_label: 0,
            slots: HashMap::new(),
            code: String::new(),
        }
    }

    fn value(&mut self) -> String {
        let id = self.next_value;
        self.next_value += 1;
        format!("%v{id}")
    }

    fn label(&mut self, prefix: &str) -> String {
        let id = self.next_label;
        self.next_label += 1;
        format!("{prefix}.{id}")
    }
}

fn llvm_emit_function(
    function: &hir::TypedFunction,
    forced_return: Option<i32>,
    string_literal_ids: &HashMap<String, i32>,
) -> String {
    let params = function
        .params
        .iter()
        .enumerate()
        .map(|(i, _)| format!("i32 %arg{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut ctx = LlvmFuncCtx::new();
    let mut out = format!("define i32 @{}({params}) {{\nentry:\n", function.name);
    for (index, param) in function.params.iter().enumerate() {
        let slot = format!("%slot_{}", param.name);
        ctx.code.push_str(&format!(
            "  {slot} = alloca i32\n  store i32 %arg{index}, ptr {slot}\n"
        ));
        ctx.slots.insert(param.name.clone(), slot);
    }
    let terminated = llvm_emit_block(&function.body, &mut ctx, string_literal_ids);
    out.push_str(&ctx.code);
    if !terminated {
        let fallback = forced_return.unwrap_or(0);
        out.push_str(&format!("  ret i32 {fallback}\n"));
    }
    out.push_str("}\n");
    out
}

fn llvm_emit_block(
    body: &[ast::Stmt],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
) -> bool {
    for stmt in body {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                let rendered = llvm_emit_expr(value, ctx, string_literal_ids);
                let slot = format!("%slot_{}_{}", name, ctx.next_value);
                ctx.code.push_str(&format!(
                    "  {slot} = alloca i32\n  store i32 {rendered}, ptr {slot}\n"
                ));
                ctx.slots.insert(name.clone(), slot);
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_value = llvm_emit_expr(field_expr, ctx, string_literal_ids);
                        let field_slot = format!("%slot_{}_{}_{}", name, field, ctx.next_value);
                        ctx.code.push_str(&format!(
                            "  {field_slot} = alloca i32\n  store i32 {field_value}, ptr {field_slot}\n"
                        ));
                        ctx.slots.insert(format!("{name}.{field}"), field_slot);
                    }
                }
            }
            ast::Stmt::Assign { target, value } => {
                let value = llvm_emit_expr(value, ctx, string_literal_ids);
                let slot = ctx
                    .slots
                    .entry(target.clone())
                    .or_insert_with(|| format!("%slot_{}_{}", target, ctx.next_value))
                    .clone();
                if !ctx.code.contains(&format!("{slot} = alloca i32")) {
                    ctx.code.push_str(&format!("  {slot} = alloca i32\n"));
                }
                ctx.code
                    .push_str(&format!("  store i32 {value}, ptr {slot}\n"));
            }
            ast::Stmt::Return(expr) => {
                let value = llvm_emit_expr(expr, ctx, string_literal_ids);
                ctx.code.push_str(&format!("  ret i32 {value}\n"));
                return true;
            }
            ast::Stmt::Expr(expr)
            | ast::Stmt::Requires(expr)
            | ast::Stmt::Ensures(expr)
            | ast::Stmt::Defer(expr) => {
                let _ = llvm_emit_expr(expr, ctx, string_literal_ids);
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let cond = llvm_emit_expr(condition, ctx, string_literal_ids);
                let pred = ctx.value();
                let then_label = ctx.label("then");
                let else_label = ctx.label("else");
                let cont_label = ctx.label("ifend");
                ctx.code.push_str(&format!(
                    "  {pred} = icmp ne i32 {cond}, 0\n  br i1 {pred}, label %{then_label}, label %{else_label}\n{then_label}:\n"
                ));
                let then_terminated = llvm_emit_block(then_body, ctx, string_literal_ids);
                if !then_terminated {
                    ctx.code.push_str(&format!("  br label %{cont_label}\n"));
                }
                ctx.code.push_str(&format!("{else_label}:\n"));
                let else_terminated = llvm_emit_block(else_body, ctx, string_literal_ids);
                if !else_terminated {
                    ctx.code.push_str(&format!("  br label %{cont_label}\n"));
                }
                if then_terminated && else_terminated {
                    return true;
                }
                ctx.code.push_str(&format!("{cont_label}:\n"));
            }
            ast::Stmt::While { condition, body } => {
                let head_label = ctx.label("while_head");
                let body_label = ctx.label("while_body");
                let end_label = ctx.label("while_end");
                ctx.code
                    .push_str(&format!("  br label %{head_label}\n{head_label}:\n"));
                let cond = llvm_emit_expr(condition, ctx, string_literal_ids);
                let pred = ctx.value();
                ctx.code.push_str(&format!(
                    "  {pred} = icmp ne i32 {cond}, 0\n  br i1 {pred}, label %{body_label}, label %{end_label}\n{body_label}:\n"
                ));
                let terminated = llvm_emit_block(body, ctx, string_literal_ids);
                if !terminated {
                    ctx.code.push_str(&format!("  br label %{head_label}\n"));
                }
                ctx.code.push_str(&format!("{end_label}:\n"));
            }
            ast::Stmt::Match { .. } => {}
        }
    }
    false
}

fn llvm_emit_expr(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
) -> String {
    match expr {
        ast::Expr::Int(v) => v.to_string(),
        ast::Expr::Bool(v) => {
            if *v {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        ast::Expr::Str(value) => string_literal_ids
            .get(value)
            .copied()
            .unwrap_or(0)
            .to_string(),
        ast::Expr::Ident(name) => {
            if let Some(slot) = ctx.slots.get(name).cloned() {
                let val = ctx.value();
                ctx.code
                    .push_str(&format!("  {val} = load i32, ptr {slot}\n"));
                val
            } else {
                "0".to_string()
            }
        }
        ast::Expr::Group(inner) => llvm_emit_expr(inner, ctx, string_literal_ids),
        ast::Expr::FieldAccess { base, field } => {
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(slot) = ctx.slots.get(&format!("{name}.{field}")).cloned() {
                    let val = ctx.value();
                    ctx.code
                        .push_str(&format!("  {val} = load i32, ptr {slot}\n"));
                    return val;
                }
            }
            llvm_emit_expr(base, ctx, string_literal_ids)
        }
        ast::Expr::StructInit { fields, .. } => {
            let mut first = None;
            for (_, value) in fields {
                let current = llvm_emit_expr(value, ctx, string_literal_ids);
                if first.is_none() {
                    first = Some(current);
                }
            }
            first.unwrap_or_else(|| "0".to_string())
        }
        ast::Expr::EnumInit {
            enum_name: _,
            variant,
            payload,
        } => {
            for value in payload {
                let _ = llvm_emit_expr(value, ctx, string_literal_ids);
            }
            (variant.bytes().fold(0u32, |acc, byte| {
                acc.wrapping_mul(33).wrapping_add(byte as u32)
            }) & 0x7fff_ffff)
                .to_string()
        }
        ast::Expr::TryCatch { try_expr, .. } => llvm_emit_expr(try_expr, ctx, string_literal_ids),
        ast::Expr::Call { callee, args } => {
            let args = args
                .iter()
                .map(|arg| format!("i32 {}", llvm_emit_expr(arg, ctx, string_literal_ids)))
                .collect::<Vec<_>>()
                .join(", ");
            let symbol = native_runtime_import_for_callee(callee)
                .map(|import| import.symbol)
                .unwrap_or(callee.as_str());
            let val = ctx.value();
            ctx.code
                .push_str(&format!("  {val} = call i32 @{symbol}({args})\n"));
            val
        }
        ast::Expr::Binary { op, left, right } => {
            let lhs = llvm_emit_expr(left, ctx, string_literal_ids);
            let rhs = llvm_emit_expr(right, ctx, string_literal_ids);
            let out = ctx.value();
            match op {
                ast::BinaryOp::Add => ctx
                    .code
                    .push_str(&format!("  {out} = add i32 {lhs}, {rhs}\n")),
                ast::BinaryOp::Sub => ctx
                    .code
                    .push_str(&format!("  {out} = sub i32 {lhs}, {rhs}\n")),
                ast::BinaryOp::Mul => ctx
                    .code
                    .push_str(&format!("  {out} = mul i32 {lhs}, {rhs}\n")),
                ast::BinaryOp::Div => ctx
                    .code
                    .push_str(&format!("  {out} = sdiv i32 {lhs}, {rhs}\n")),
                ast::BinaryOp::Eq
                | ast::BinaryOp::Neq
                | ast::BinaryOp::Lt
                | ast::BinaryOp::Lte
                | ast::BinaryOp::Gt
                | ast::BinaryOp::Gte => {
                    let pred = ctx.value();
                    let cmp = match op {
                        ast::BinaryOp::Eq => "eq",
                        ast::BinaryOp::Neq => "ne",
                        ast::BinaryOp::Lt => "slt",
                        ast::BinaryOp::Lte => "sle",
                        ast::BinaryOp::Gt => "sgt",
                        ast::BinaryOp::Gte => "sge",
                        _ => unreachable!(),
                    };
                    ctx.code
                        .push_str(&format!("  {pred} = icmp {cmp} i32 {lhs}, {rhs}\n"));
                    ctx.code
                        .push_str(&format!("  {out} = zext i1 {pred} to i32\n"));
                }
            }
            out
        }
    }
}

fn native_runtime_import_for_callee(callee: &str) -> Option<&'static NativeRuntimeImport> {
    NATIVE_RUNTIME_IMPORTS
        .iter()
        .find(|import| import.callee == callee)
}

fn collect_used_native_runtime_imports(fir: &fir::FirModule) -> Vec<&'static NativeRuntimeImport> {
    let mut seen = HashSet::<&'static str>::new();
    let mut used = Vec::<&'static NativeRuntimeImport>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_used_runtime_imports_from_stmt(stmt, &mut seen, &mut used);
        }
    }
    used
}

fn collect_string_literals(fir: &fir::FirModule) -> Vec<String> {
    let mut literals = HashSet::<String>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_string_literals_from_stmt(stmt, &mut literals);
        }
    }
    let mut literals = literals.into_iter().collect::<Vec<_>>();
    literals.sort();
    literals
}

fn collect_string_literals_from_stmt(stmt: &ast::Stmt, literals: &mut HashSet<String>) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::Return(value)
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_string_literals_from_expr(value, literals),
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_string_literals_from_expr(condition, literals);
            for nested in then_body {
                collect_string_literals_from_stmt(nested, literals);
            }
            for nested in else_body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_string_literals_from_expr(condition, literals);
            for nested in body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_string_literals_from_expr(scrutinee, literals);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_string_literals_from_expr(guard, literals);
                }
                collect_string_literals_from_expr(&arm.value, literals);
            }
        }
    }
}

fn collect_string_literals_from_expr(expr: &ast::Expr, literals: &mut HashSet<String>) {
    match expr {
        ast::Expr::Str(value) => {
            literals.insert(value.clone());
        }
        ast::Expr::Call { args, .. } => {
            for arg in args {
                collect_string_literals_from_expr(arg, literals);
            }
        }
        ast::Expr::FieldAccess { base, .. } => collect_string_literals_from_expr(base, literals),
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_string_literals_from_expr(value, literals);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_string_literals_from_expr(value, literals);
            }
        }
        ast::Expr::Group(inner) => collect_string_literals_from_expr(inner, literals),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_string_literals_from_expr(try_expr, literals);
            collect_string_literals_from_expr(catch_expr, literals);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_string_literals_from_expr(left, literals);
            collect_string_literals_from_expr(right, literals);
        }
        ast::Expr::Int(_) | ast::Expr::Bool(_) | ast::Expr::Ident(_) => {}
    }
}

fn build_string_literal_ids(literals: &[String]) -> HashMap<String, i32> {
    literals
        .iter()
        .enumerate()
        .map(|(index, value)| (value.clone(), index as i32 + 1))
        .collect()
}

fn collect_spawn_task_symbols(fir: &fir::FirModule) -> Vec<String> {
    fir.typed_functions
        .iter()
        .filter(|function| function.params.is_empty())
        .map(|function| function.name.clone())
        .collect()
}

fn escape_c_string(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
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
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::Return(value)
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_used_runtime_imports_from_expr(value, seen, used),
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
            if let Some(import) = native_runtime_import_for_callee(callee) {
                if seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            for arg in args {
                collect_used_runtime_imports_from_expr(arg, seen, used);
            }
        }
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
        ast::Expr::Group(inner) => {
            collect_used_runtime_imports_from_expr(inner, seen, used);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_used_runtime_imports_from_expr(try_expr, seen, used);
            collect_used_runtime_imports_from_expr(catch_expr, seen, used);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_used_runtime_imports_from_expr(left, seen, used);
            collect_used_runtime_imports_from_expr(right, seen, used);
        }
        ast::Expr::Int(_) | ast::Expr::Bool(_) | ast::Expr::Str(_) | ast::Expr::Ident(_) => {}
    }
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
    let string_literals = collect_string_literals(fir);
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    let runtime_shim_path =
        ensure_native_runtime_shim(&build_dir, &string_literals, &spawn_task_symbols)?;
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
            .arg("-x")
            .arg("c")
            .arg(&runtime_shim_path)
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
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let object_path = build_dir.join(format!("{}.o", fir.name));
    let bin_path = build_dir.join(fir.name.as_str());
    let string_literals = collect_string_literals(fir);
    let string_literal_ids = build_string_literal_ids(&string_literals);
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
    let forced_main_return = if enforce_contract_checks {
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
    } else {
        None
    };

    let mut function_ids = HashMap::new();
    for function in &fir.typed_functions {
        let mut sig = module.make_signature();
        for _ in &function.params {
            sig.params.push(AbiParam::new(types::I32));
        }
        sig.returns.push(AbiParam::new(types::I32));
        let linkage = Linkage::Export;
        let id = module
            .declare_function(function.name.as_str(), linkage, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring cranelift symbol `{}`: {error}",
                    function.name
                )
            })?;
        function_ids.insert(function.name.clone(), id);
    }
    declare_native_runtime_imports(&mut module, &mut function_ids)?;
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    let mut task_ref_ids = HashMap::<String, i32>::new();
    for (index, symbol) in spawn_task_symbols.iter().enumerate() {
        task_ref_ids.insert(symbol.clone(), (index + 1) as i32);
    }
    let runtime_shim_path =
        ensure_native_runtime_shim(&build_dir, &string_literals, &spawn_task_symbols)?;

    for function in &fir.typed_functions {
        let Some(function_id) = function_ids.get(&function.name).copied() else {
            continue;
        };
        let mut context = module.make_context();
        context.func.signature.params.clear();
        context.func.signature.returns.clear();
        for _ in &function.params {
            context
                .func
                .signature
                .params
                .push(AbiParam::new(types::I32));
        }
        context
            .func
            .signature
            .returns
            .push(AbiParam::new(types::I32));

        let mut function_builder_context = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);
        builder.seal_block(entry);

        let mut locals = HashMap::<String, Variable>::new();
        for (index, param) in function.params.iter().enumerate() {
            let var = Variable::from_u32(index as u32);
            builder.declare_var(var, types::I32);
            let value = builder.block_params(entry)[index];
            builder.def_var(var, value);
            locals.insert(param.name.clone(), var);
        }
        let mut next_var = function.params.len();

        let terminated = clif_emit_block(
            &mut builder,
            &mut module,
            &function_ids,
            &function.body,
            &mut locals,
            &mut next_var,
            &string_literal_ids,
            &task_ref_ids,
        )?;
        if !terminated {
            let fallback = if function.name == "main" {
                forced_main_return
                    .or(fir.entry_return_const_i32)
                    .unwrap_or(0)
            } else {
                0
            };
            let ret = builder.ins().iconst(types::I32, fallback as i64);
            builder.ins().return_(&[ret]);
        }
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

fn clif_emit_block(
    builder: &mut FunctionBuilder,
    module: &mut ObjectModule,
    function_ids: &HashMap<String, cranelift_module::FuncId>,
    body: &[ast::Stmt],
    locals: &mut HashMap<String, Variable>,
    next_var: &mut usize,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<bool> {
    for stmt in body {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                let val = clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    value,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                let var = if let Some(existing) = locals.get(name).copied() {
                    existing
                } else {
                    let var = Variable::from_u32(*next_var as u32);
                    *next_var += 1;
                    builder.declare_var(var, types::I32);
                    locals.insert(name.clone(), var);
                    var
                };
                builder.def_var(var, val);
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_val = clif_emit_expr(
                            builder,
                            module,
                            function_ids,
                            field_expr,
                            locals,
                            next_var,
                            string_literal_ids,
                            task_ref_ids,
                        )?;
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, types::I32);
                        builder.def_var(field_var, field_val);
                        locals.insert(format!("{name}.{field}"), field_var);
                    }
                }
            }
            ast::Stmt::Assign { target, value } => {
                let val = clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    value,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                let var = if let Some(existing) = locals.get(target).copied() {
                    existing
                } else {
                    let var = Variable::from_u32(*next_var as u32);
                    *next_var += 1;
                    builder.declare_var(var, types::I32);
                    locals.insert(target.clone(), var);
                    var
                };
                builder.def_var(var, val);
            }
            ast::Stmt::Return(expr) => {
                let value = clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    expr,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                builder.ins().return_(&[value]);
                return Ok(true);
            }
            ast::Stmt::Expr(expr)
            | ast::Stmt::Requires(expr)
            | ast::Stmt::Ensures(expr)
            | ast::Stmt::Defer(expr) => {
                let _ = clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    expr,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let cond_val = clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    condition,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                let zero = builder.ins().iconst(types::I32, 0);
                let cond = builder.ins().icmp(IntCC::NotEqual, cond_val, zero);
                let then_block = builder.create_block();
                let else_block = builder.create_block();
                let cont_block = builder.create_block();
                builder.ins().brif(cond, then_block, &[], else_block, &[]);

                builder.switch_to_block(then_block);
                let then_terminated = clif_emit_block(
                    builder,
                    module,
                    function_ids,
                    then_body,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                if !then_terminated {
                    builder.ins().jump(cont_block, &[]);
                }
                builder.seal_block(then_block);

                builder.switch_to_block(else_block);
                let else_terminated = clif_emit_block(
                    builder,
                    module,
                    function_ids,
                    else_body,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                if !else_terminated {
                    builder.ins().jump(cont_block, &[]);
                }
                builder.seal_block(else_block);

                if then_terminated && else_terminated {
                    return Ok(true);
                }
                builder.switch_to_block(cont_block);
                builder.seal_block(cont_block);
            }
            ast::Stmt::While { condition, body } => {
                let head = builder.create_block();
                let loop_body = builder.create_block();
                let exit = builder.create_block();
                builder.ins().jump(head, &[]);
                builder.switch_to_block(head);
                let cond_val = clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    condition,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                let zero = builder.ins().iconst(types::I32, 0);
                let cond = builder.ins().icmp(IntCC::NotEqual, cond_val, zero);
                builder.ins().brif(cond, loop_body, &[], exit, &[]);

                builder.switch_to_block(loop_body);
                let body_terminated = clif_emit_block(
                    builder,
                    module,
                    function_ids,
                    body,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                if !body_terminated {
                    builder.ins().jump(head, &[]);
                }
                builder.seal_block(loop_body);
                builder.seal_block(head);

                builder.switch_to_block(exit);
                builder.seal_block(exit);
            }
            ast::Stmt::Match { .. } => {}
        }
    }
    Ok(false)
}

fn clif_emit_expr(
    builder: &mut FunctionBuilder,
    module: &mut ObjectModule,
    function_ids: &HashMap<String, cranelift_module::FuncId>,
    expr: &ast::Expr,
    locals: &mut HashMap<String, Variable>,
    next_var: &mut usize,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<cranelift_codegen::ir::Value> {
    Ok(match expr {
        ast::Expr::Int(v) => builder.ins().iconst(types::I32, *v as i64),
        ast::Expr::Bool(v) => builder.ins().iconst(types::I32, if *v { 1 } else { 0 }),
        ast::Expr::Str(value) => builder.ins().iconst(
            types::I32,
            string_literal_ids.get(value).copied().unwrap_or(0) as i64,
        ),
        ast::Expr::Ident(name) => {
            if let Some(var) = locals.get(name).copied() {
                builder.use_var(var)
            } else if let Some(task_ref) = task_ref_ids.get(name).copied() {
                builder.ins().iconst(types::I32, task_ref as i64)
            } else {
                builder.ins().iconst(types::I32, 0)
            }
        }
        ast::Expr::Group(inner) => clif_emit_expr(
            builder,
            module,
            function_ids,
            inner,
            locals,
            next_var,
            string_literal_ids,
            task_ref_ids,
        )?,
        ast::Expr::FieldAccess { base, field } => {
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(var) = locals.get(&format!("{name}.{field}")).copied() {
                    builder.use_var(var)
                } else if let Some(task_ref_name) = expr_task_ref_name(expr) {
                    if let Some(task_ref) = task_ref_ids.get(&task_ref_name).copied() {
                        builder.ins().iconst(types::I32, task_ref as i64)
                    } else {
                        clif_emit_expr(
                            builder,
                            module,
                            function_ids,
                            base,
                            locals,
                            next_var,
                            string_literal_ids,
                            task_ref_ids,
                        )?
                    }
                } else {
                    clif_emit_expr(
                        builder,
                        module,
                        function_ids,
                        base,
                        locals,
                        next_var,
                        string_literal_ids,
                        task_ref_ids,
                    )?
                }
            } else {
                clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    base,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?
            }
        }
        ast::Expr::StructInit { fields, .. } => {
            let mut first = None;
            for (_, value) in fields {
                let out = clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    value,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                if first.is_none() {
                    first = Some(out);
                }
            }
            first.unwrap_or_else(|| builder.ins().iconst(types::I32, 0))
        }
        ast::Expr::EnumInit {
            variant, payload, ..
        } => {
            for value in payload {
                let _ = clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    value,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?;
            }
            let tag = variant.bytes().fold(0u32, |acc, byte| {
                acc.wrapping_mul(33).wrapping_add(byte as u32)
            });
            builder.ins().iconst(types::I32, (tag & 0x7fff_ffff) as i64)
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => clif_emit_expr(
            builder,
            module,
            function_ids,
            try_expr,
            locals,
            next_var,
            string_literal_ids,
            task_ref_ids,
        )
        .or_else(|_| {
            clif_emit_expr(
                builder,
                module,
                function_ids,
                catch_expr,
                locals,
                next_var,
                string_literal_ids,
                task_ref_ids,
            )
        })?,
        ast::Expr::Binary { op, left, right } => {
            let lhs = clif_emit_expr(
                builder,
                module,
                function_ids,
                left,
                locals,
                next_var,
                string_literal_ids,
                task_ref_ids,
            )?;
            let rhs = clif_emit_expr(
                builder,
                module,
                function_ids,
                right,
                locals,
                next_var,
                string_literal_ids,
                task_ref_ids,
            )?;
            match op {
                ast::BinaryOp::Add => builder.ins().iadd(lhs, rhs),
                ast::BinaryOp::Sub => builder.ins().isub(lhs, rhs),
                ast::BinaryOp::Mul => builder.ins().imul(lhs, rhs),
                ast::BinaryOp::Div => builder.ins().sdiv(lhs, rhs),
                ast::BinaryOp::Eq => {
                    let c = builder.ins().icmp(IntCC::Equal, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
                ast::BinaryOp::Neq => {
                    let c = builder.ins().icmp(IntCC::NotEqual, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
                ast::BinaryOp::Lt => {
                    let c = builder.ins().icmp(IntCC::SignedLessThan, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
                ast::BinaryOp::Lte => {
                    let c = builder.ins().icmp(IntCC::SignedLessThanOrEqual, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
                ast::BinaryOp::Gt => {
                    let c = builder.ins().icmp(IntCC::SignedGreaterThan, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
                ast::BinaryOp::Gte => {
                    let c = builder
                        .ins()
                        .icmp(IntCC::SignedGreaterThanOrEqual, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
            }
        }
        ast::Expr::Call { callee, args } => {
            let mut values = Vec::with_capacity(args.len());
            for arg in args {
                values.push(clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    arg,
                    locals,
                    next_var,
                    string_literal_ids,
                    task_ref_ids,
                )?);
            }
            if let Some(function_id) = function_ids.get(callee).copied() {
                let func_ref = module.declare_func_in_func(function_id, builder.func);
                let call = builder.ins().call(func_ref, &values);
                if let Some(value) = builder.inst_results(call).first().copied() {
                    value
                } else {
                    builder.ins().iconst(types::I32, 0)
                }
            } else {
                return Err(anyhow!(
                    "native backend cannot lower unresolved call target `{}`",
                    callee
                ));
            }
        }
    })
}

fn native_lowerability_diagnostics(module: &ast::Module) -> Vec<diagnostics::Diagnostic> {
    let defined_functions = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) => Some(function.name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut unresolved = HashSet::<String>::new();
    for item in &module.items {
        if let ast::Item::Function(function) = item {
            for stmt in &function.body {
                collect_unresolved_calls_from_stmt(stmt, &defined_functions, &mut unresolved);
            }
        }
    }
    let mut unresolved = unresolved.into_iter().collect::<Vec<_>>();
    unresolved.sort();
    unresolved
        .into_iter()
        .map(|callee| {
            diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!("native backend cannot execute unresolved call `{callee}`"),
                Some(
                    "run via Fozzy scenario/host backends or provide a real native implementation for this symbol"
                        .to_string(),
                ),
            )
        })
        .collect()
}

fn collect_unresolved_calls_from_stmt(
    stmt: &ast::Stmt,
    defined_functions: &HashSet<String>,
    unresolved: &mut HashSet<String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::Return(value)
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => {
            collect_unresolved_calls_from_expr(value, defined_functions, unresolved)
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_unresolved_calls_from_expr(condition, defined_functions, unresolved);
            for nested in then_body {
                collect_unresolved_calls_from_stmt(nested, defined_functions, unresolved);
            }
            for nested in else_body {
                collect_unresolved_calls_from_stmt(nested, defined_functions, unresolved);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_unresolved_calls_from_expr(condition, defined_functions, unresolved);
            for nested in body {
                collect_unresolved_calls_from_stmt(nested, defined_functions, unresolved);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_unresolved_calls_from_expr(scrutinee, defined_functions, unresolved);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_unresolved_calls_from_expr(guard, defined_functions, unresolved);
                }
                collect_unresolved_calls_from_expr(&arm.value, defined_functions, unresolved);
            }
        }
    }
}

fn collect_unresolved_calls_from_expr(
    expr: &ast::Expr,
    defined_functions: &HashSet<String>,
    unresolved: &mut HashSet<String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if !defined_functions.contains(callee) && !native_backend_supports_call(callee) {
                unresolved.insert(callee.clone());
            }
            for arg in args {
                collect_unresolved_calls_from_expr(arg, defined_functions, unresolved);
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_unresolved_calls_from_expr(base, defined_functions, unresolved);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_unresolved_calls_from_expr(value, defined_functions, unresolved);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_unresolved_calls_from_expr(value, defined_functions, unresolved);
            }
        }
        ast::Expr::Group(inner) => {
            collect_unresolved_calls_from_expr(inner, defined_functions, unresolved);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_unresolved_calls_from_expr(try_expr, defined_functions, unresolved);
            collect_unresolved_calls_from_expr(catch_expr, defined_functions, unresolved);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_unresolved_calls_from_expr(left, defined_functions, unresolved);
            collect_unresolved_calls_from_expr(right, defined_functions, unresolved);
        }
        ast::Expr::Int(_) | ast::Expr::Bool(_) | ast::Expr::Str(_) | ast::Expr::Ident(_) => {}
    }
}

fn native_backend_supports_call(callee: &str) -> bool {
    native_runtime_import_for_callee(callee).is_some()
}

fn declare_native_runtime_imports(
    module: &mut ObjectModule,
    function_ids: &mut HashMap<String, cranelift_module::FuncId>,
) -> Result<()> {
    for import in NATIVE_RUNTIME_IMPORTS {
        if function_ids.contains_key(import.callee) {
            continue;
        }
        let mut sig = module.make_signature();
        for _ in 0..import.arity {
            sig.params.push(AbiParam::new(types::I32));
        }
        sig.returns.push(AbiParam::new(types::I32));
        let id = module
            .declare_function(import.symbol, Linkage::Import, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring native runtime import `{}` for `{}`: {error}",
                    import.symbol,
                    import.callee
                )
            })?;
        function_ids.insert(import.callee.to_string(), id);
    }
    Ok(())
}

fn ensure_native_runtime_shim(
    build_dir: &Path,
    string_literals: &[String],
    task_symbols: &[String],
) -> Result<PathBuf> {
    let runtime_shim_path = build_dir.join("fz_native_runtime.c");
    std::fs::write(
        &runtime_shim_path,
        render_native_runtime_shim(string_literals, task_symbols),
    )
    .with_context(|| {
        format!(
            "failed writing native runtime shim source: {}",
            runtime_shim_path.display()
        )
    })?;
    Ok(runtime_shim_path)
}

fn render_native_runtime_shim(string_literals: &[String], task_symbols: &[String]) -> String {
    let mut literal_entries = String::new();
    for literal in string_literals {
        let _ = writeln!(&mut literal_entries, "  \"{}\",", escape_c_string(literal));
    }
    if literal_entries.is_empty() {
        literal_entries.push_str("  NULL,\n");
    }
    let mut task_declarations = String::new();
    let mut task_entries = String::new();
    for (index, symbol) in task_symbols.iter().enumerate() {
        let linker_symbol = if cfg!(target_vendor = "apple") {
            format!("_{}", symbol)
        } else {
            symbol.clone()
        };
        let _ = writeln!(
            &mut task_declarations,
            "extern int32_t fz_task_entry_{}(void) __asm__(\"{}\");",
            index,
            escape_c_string(&linker_symbol)
        );
        let _ = writeln!(&mut task_entries, "  fz_task_entry_{},", index);
    }
    if task_entries.is_empty() {
        task_entries.push_str("  NULL,\n");
    }
    let count = string_literals.len();
    let task_count = task_symbols.len();
    let mut c = String::new();
    c.push_str(
        r#"#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char** environ;

"#,
    );
    c.push_str("typedef int32_t (*fz_task_entry_fn)(void);\n");
    c.push_str(&task_declarations);
    c.push_str("static fz_task_entry_fn fz_task_entries[] = {\n");
    c.push_str(&task_entries);
    c.push_str("};\n");
    c.push_str(&format!(
        "static const int fz_task_entry_count = {};\n\n",
        task_count
    ));
    c.push_str("static const char* fz_string_literals[] = {\n");
    c.push_str(&literal_entries);
    c.push_str("};\n");
    c.push_str(&format!(
        "static const int fz_string_literal_count = {};\n\n",
        count
    ));
    c.push_str(
        r#"#define FZ_MAX_DYNAMIC_STRINGS 16384
#define FZ_MAX_CONN_STATES 2048
#define FZ_MAX_HTTP_READ 262144
#define FZ_MAX_PROC_STATES 1024
#define FZ_MAX_HTTP_HEADERS 128
#define FZ_MAX_SPAWN_THREADS 4096
#define FZ_MAX_CONN_META 128
#define FZ_MAX_ROUTE_PARAMS 64
#define FZ_MAX_LISTS 2048
#define FZ_MAX_LIST_ITEMS 4096
#define FZ_MAX_MAPS 2048
#define FZ_MAX_MAP_ENTRIES 4096
#define FZ_MAX_INTERVALS 512

static char* fz_dynamic_strings[FZ_MAX_DYNAMIC_STRINGS];
static int fz_dynamic_string_count = 0;
static pthread_mutex_t fz_string_lock = PTHREAD_MUTEX_INITIALIZER;

static int fz_listener_fd = -1;
static pthread_mutex_t fz_listener_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  int in_use;
  int fd;
  int32_t method_id;
  int32_t path_id;
  int32_t body_id;
  int32_t request_id;
  int32_t remote_addr_id;
  int keep_alive;
  int header_count;
  int32_t header_key_ids[FZ_MAX_CONN_META];
  int32_t header_value_ids[FZ_MAX_CONN_META];
  int query_count;
  int32_t query_key_ids[FZ_MAX_CONN_META];
  int32_t query_value_ids[FZ_MAX_CONN_META];
  int param_count;
  int32_t param_key_ids[FZ_MAX_ROUTE_PARAMS];
  int32_t param_value_ids[FZ_MAX_ROUTE_PARAMS];
} fz_conn_state;

static fz_conn_state fz_conn_states[FZ_MAX_CONN_STATES];
static pthread_mutex_t fz_conn_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  char* data;
  size_t len;
  size_t cap;
} fz_bytes_buf;

typedef struct {
  int in_use;
  pid_t pid;
  int stdout_fd;
  int stderr_fd;
  int done;
  int exit_notified;
  int exit_code;
  size_t stdout_read_pos;
  size_t stderr_read_pos;
  int32_t stdout_id;
  int32_t stderr_id;
  fz_bytes_buf stdout_buf;
  fz_bytes_buf stderr_buf;
} fz_proc_state;

typedef struct {
  int in_use;
  int count;
  char* items[FZ_MAX_LIST_ITEMS];
} fz_list_state;

typedef struct {
  int in_use;
  int count;
  char* keys[FZ_MAX_MAP_ENTRIES];
  char* values[FZ_MAX_MAP_ENTRIES];
} fz_map_state;

typedef struct {
  int in_use;
  int32_t period_ms;
  int64_t next_ms;
} fz_interval_state;

static fz_proc_state fz_proc_states[FZ_MAX_PROC_STATES];
static pthread_mutex_t fz_proc_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_proc_default_timeout_ms = 30000;
static int32_t fz_proc_last_error_id = 0;
static int32_t fz_last_exit_class = 0;
static fz_list_state fz_lists[FZ_MAX_LISTS];
static fz_map_state fz_maps[FZ_MAX_MAPS];
static fz_interval_state fz_intervals[FZ_MAX_INTERVALS];
static pthread_mutex_t fz_collections_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_time_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_conn_request_counter = 0;
static int32_t fz_last_error_code = 0;
static int32_t fz_last_error_class = 0;
static int32_t fz_last_error_message_id = 0;
static int fz_log_json = 0;

typedef struct {
  int32_t key_id;
  int32_t value_id;
} fz_http_header_pair;

static fz_http_header_pair fz_http_headers[FZ_MAX_HTTP_HEADERS];
static int fz_http_header_count = 0;
static pthread_mutex_t fz_http_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_http_last_status = 0;
static int32_t fz_http_last_body_id = 0;
static int32_t fz_http_last_error_id = 0;
static int fz_fs_fd = -1;
static char fz_fs_base_path[512] = {0};
static char fz_fs_tmp_path[544] = {0};
static pthread_mutex_t fz_fs_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t fz_spawn_threads[FZ_MAX_SPAWN_THREADS];
static int fz_spawn_thread_count = 0;
static pthread_mutex_t fz_spawn_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t fz_spawn_atexit_once = PTHREAD_ONCE_INIT;

typedef struct {
  fz_task_entry_fn entry;
} fz_spawn_ctx;

static int fz_mark_cloexec(int fd);
static void fz_proc_set_last_error(const char* msg);
static int fz_parse_json_string_array(const char* raw, char*** out_items, int* out_count);
static int fz_parse_json_env_object(const char* raw, char*** out_items, int* out_count);
static void fz_free_string_list(char** items, int count);
int32_t fz_native_net_request_id(int32_t conn_fd);
int32_t fz_native_net_write(int32_t conn_fd, int32_t status_code, int32_t body_id);


static const char* fz_lookup_string(int32_t id) {
  if (id <= 0) {
    return "";
  }
  if (id <= fz_string_literal_count) {
    const char* literal = fz_string_literals[id - 1];
    return literal == NULL ? "" : literal;
  }
  int dynamic_index = id - fz_string_literal_count - 1;
  if (dynamic_index < 0 || dynamic_index >= fz_dynamic_string_count) {
    return "";
  }
  const char* value = fz_dynamic_strings[dynamic_index];
  return value == NULL ? "" : value;
}

static int32_t fz_intern_owned(char* owned) {
  if (owned == NULL) {
    return 0;
  }
  pthread_mutex_lock(&fz_string_lock);
  for (int i = 0; i < fz_string_literal_count; i++) {
    const char* literal = fz_string_literals[i];
    if (literal != NULL && strcmp(literal, owned) == 0) {
      pthread_mutex_unlock(&fz_string_lock);
      free(owned);
      return i + 1;
    }
  }
  for (int i = 0; i < fz_dynamic_string_count; i++) {
    const char* existing = fz_dynamic_strings[i];
    if (existing != NULL && strcmp(existing, owned) == 0) {
      pthread_mutex_unlock(&fz_string_lock);
      free(owned);
      return fz_string_literal_count + i + 1;
    }
  }
  if (fz_dynamic_string_count >= FZ_MAX_DYNAMIC_STRINGS) {
    pthread_mutex_unlock(&fz_string_lock);
    free(owned);
    return 0;
  }
  int index = fz_dynamic_string_count++;
  fz_dynamic_strings[index] = owned;
  pthread_mutex_unlock(&fz_string_lock);
  return fz_string_literal_count + index + 1;
}

static int32_t fz_intern_slice(const char* data, size_t len) {
  char* owned = (char*)malloc(len + 1);
  if (owned == NULL) {
    return 0;
  }
  if (len > 0) {
    memcpy(owned, data, len);
  }
  owned[len] = '\0';
  return fz_intern_owned(owned);
}

static void fz_set_last_error(int32_t code, int32_t class_id, const char* message) {
  if (message == NULL) {
    message = "";
  }
  fz_last_error_code = code;
  fz_last_error_class = class_id;
  fz_last_error_message_id = fz_intern_slice(message, strlen(message));
}

static int32_t fz_list_alloc(void) {
  for (int i = 0; i < FZ_MAX_LISTS; i++) {
    if (!fz_lists[i].in_use) {
      memset(&fz_lists[i], 0, sizeof(fz_lists[i]));
      fz_lists[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_list_state* fz_list_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_LISTS) {
    return NULL;
  }
  fz_list_state* list = &fz_lists[handle - 1];
  return list->in_use ? list : NULL;
}

static int fz_list_push_cstr(fz_list_state* list, const char* value) {
  if (list == NULL || list->count >= FZ_MAX_LIST_ITEMS) {
    return -1;
  }
  if (value == NULL) {
    value = "";
  }
  char* dup = strdup(value);
  if (dup == NULL) {
    return -1;
  }
  list->items[list->count++] = dup;
  return 0;
}

static int32_t fz_map_alloc(void) {
  for (int i = 0; i < FZ_MAX_MAPS; i++) {
    if (!fz_maps[i].in_use) {
      memset(&fz_maps[i], 0, sizeof(fz_maps[i]));
      fz_maps[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_map_state* fz_map_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_MAPS) {
    return NULL;
  }
  fz_map_state* map = &fz_maps[handle - 1];
  return map->in_use ? map : NULL;
}

static int fz_map_find_index(fz_map_state* map, const char* key) {
  if (map == NULL || key == NULL) {
    return -1;
  }
  for (int i = 0; i < map->count; i++) {
    if (map->keys[i] != NULL && strcmp(map->keys[i], key) == 0) {
      return i;
    }
  }
  return -1;
}

static int fz_default_port(void) {
  const char* raw = getenv("AGENT_PORT");
  if (raw == NULL || raw[0] == '\0') {
    return 8080;
  }
  char* end = NULL;
  long parsed = strtol(raw, &end, 10);
  if (end == raw || parsed <= 0 || parsed > 65535) {
    return 8080;
  }
  return (int)parsed;
}

static uint32_t fz_default_addr(void) {
  const char* host = getenv("AGENT_HOST");
  if (host == NULL || host[0] == '\0') {
    host = "127.0.0.1";
  }
  struct in_addr addr;
  if (inet_pton(AF_INET, host, &addr) == 1) {
    return addr.s_addr;
  }
  if (strcmp(host, "localhost") == 0) {
    return htonl(INADDR_LOOPBACK);
  }
  return htonl(INADDR_LOOPBACK);
}

static int64_t fz_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

static int32_t fz_exit_class_from_status(int timed_out, int status, int spawn_error) {
  if (spawn_error) {
    return 3;
  }
  if (timed_out) {
    return 2;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status) == 0 ? 0 : 1;
  }
  if (WIFSIGNALED(status)) {
    return 1;
  }
  return 1;
}

static const char* fz_fs_path(void) {
  if (fz_fs_base_path[0] != '\0') {
    return fz_fs_base_path;
  }
  const char* from_env = getenv("FZ_FS_PATH");
  if (from_env == NULL || from_env[0] == '\0') {
    from_env = "/tmp/fozzy_native_store.dat";
  }
  snprintf(fz_fs_base_path, sizeof(fz_fs_base_path), "%s", from_env);
  snprintf(fz_fs_tmp_path, sizeof(fz_fs_tmp_path), "%s.tmp", from_env);
  return fz_fs_base_path;
}

static int fz_fs_ensure_open(void) {
  if (fz_fs_fd >= 0) {
    return fz_fs_fd;
  }
  const char* path = fz_fs_path();
  int fd = open(path, O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    return -1;
  }
  (void)fz_mark_cloexec(fd);
  fz_fs_fd = fd;
  return fd;
}

static void fz_http_headers_clear(void) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_header_count = 0;
  pthread_mutex_unlock(&fz_http_lock);
}

static char* fz_json_escape_owned(const char* input) {
  if (input == NULL) {
    input = "";
  }
  size_t in_len = strlen(input);
  size_t cap = (in_len * 6) + 1;
  char* out = (char*)malloc(cap);
  if (out == NULL) {
    return NULL;
  }
  size_t j = 0;
  for (size_t i = 0; i < in_len; i++) {
    unsigned char ch = (unsigned char)input[i];
    switch (ch) {
      case '\"': out[j++] = '\\'; out[j++] = '\"'; break;
      case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
      case '\b': out[j++] = '\\'; out[j++] = 'b'; break;
      case '\f': out[j++] = '\\'; out[j++] = 'f'; break;
      case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
      case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
      case '\t': out[j++] = '\\'; out[j++] = 't'; break;
      default:
        if (ch < 0x20) {
          static const char* hex = "0123456789abcdef";
          out[j++] = '\\';
          out[j++] = 'u';
          out[j++] = '0';
          out[j++] = '0';
          out[j++] = hex[(ch >> 4) & 0xF];
          out[j++] = hex[ch & 0xF];
        } else {
          out[j++] = (char)ch;
        }
        break;
    }
  }
  out[j] = '\0';
  return out;
}


static int fz_send_all(int fd, const char* data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t wrote = send(fd, data + sent, len - sent, 0);
    if (wrote < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (wrote == 0) {
      return -1;
    }
    sent += (size_t)wrote;
  }
  return 0;
}

static const char* fz_http_reason(int status_code) {
  switch (status_code) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 422: return "Unprocessable Entity";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    default: return "OK";
  }
}

static fz_conn_state* fz_conn_state_for(int fd, int create_if_missing) {
  fz_conn_state* free_slot = NULL;
  for (int i = 0; i < FZ_MAX_CONN_STATES; i++) {
    if (fz_conn_states[i].in_use && fz_conn_states[i].fd == fd) {
      return &fz_conn_states[i];
    }
    if (!fz_conn_states[i].in_use && free_slot == NULL) {
      free_slot = &fz_conn_states[i];
    }
  }
  if (!create_if_missing || free_slot == NULL) {
    return NULL;
  }
  memset(free_slot, 0, sizeof(*free_slot));
  free_slot->in_use = 1;
  free_slot->fd = fd;
  return free_slot;
}

static void fz_conn_state_drop(int fd) {
  pthread_mutex_lock(&fz_conn_lock);
  for (int i = 0; i < FZ_MAX_CONN_STATES; i++) {
    if (fz_conn_states[i].in_use && fz_conn_states[i].fd == fd) {
      memset(&fz_conn_states[i], 0, sizeof(fz_conn_states[i]));
      break;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
}

static int fz_find_header_end(const char* buf, int len) {
  for (int i = 0; i + 3 < len; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
      return i + 4;
    }
  }
  return -1;
}

static int fz_contains_ci(const char* hay, size_t hay_len, const char* needle) {
  size_t needle_len = strlen(needle);
  if (needle_len == 0 || hay_len < needle_len) {
    return 0;
  }
  for (size_t i = 0; i + needle_len <= hay_len; i++) {
    size_t j = 0;
    while (j < needle_len) {
      char a = (char)tolower((unsigned char)hay[i + j]);
      char b = (char)tolower((unsigned char)needle[j]);
      if (a != b) {
        break;
      }
      j++;
    }
    if (j == needle_len) {
      return 1;
    }
  }
  return 0;
}

static int64_t fz_parse_content_length(const char* headers, int header_len) {
  const char* cursor = headers;
  const char* end = headers + header_len;
  while (cursor < end) {
    const char* line_end = strstr(cursor, "\r\n");
    if (line_end == NULL || line_end > end) {
      break;
    }
    if (line_end == cursor) {
      break;
    }
    size_t line_len = (size_t)(line_end - cursor);
    if (line_len >= 15 && strncasecmp(cursor, "Content-Length:", 15) == 0) {
      const char* value = cursor + 15;
      while (value < line_end && (*value == ' ' || *value == '\t')) {
        value++;
      }
      char tmp[32];
      size_t max = (size_t)(line_end - value);
      if (max >= sizeof(tmp)) {
        max = sizeof(tmp) - 1;
      }
      memcpy(tmp, value, max);
      tmp[max] = '\0';
      char* parse_end = NULL;
      long long parsed = strtoll(tmp, &parse_end, 10);
      if (parse_end != tmp && parsed >= 0) {
        return parsed;
      }
    }
    cursor = line_end + 2;
  }
  return -1;
}

static int fz_parse_keep_alive(const char* headers, int header_len, const char* version, int version_len) {
  int keep_alive = (version_len >= 8 && strncasecmp(version, "HTTP/1.1", 8) == 0) ? 1 : 0;
  const char* cursor = headers;
  const char* end = headers + header_len;
  while (cursor < end) {
    const char* line_end = strstr(cursor, "\r\n");
    if (line_end == NULL || line_end > end) {
      break;
    }
    if (line_end == cursor) {
      break;
    }
    size_t line_len = (size_t)(line_end - cursor);
    if (line_len >= 11 && strncasecmp(cursor, "Connection:", 11) == 0) {
      const char* value = cursor + 11;
      while (value < line_end && (*value == ' ' || *value == '\t')) {
        value++;
      }
      size_t value_len = (size_t)(line_end - value);
      if (fz_contains_ci(value, value_len, "close")) {
        keep_alive = 0;
      } else if (fz_contains_ci(value, value_len, "keep-alive")) {
        keep_alive = 1;
      }
      break;
    }
    cursor = line_end + 2;
  }
  return keep_alive;
}

static int fz_send_http_response(int conn_fd, int status_code, const char* content_type, const char* body, int close_after) {
  if (conn_fd < 0) {
    return -1;
  }
  if (content_type == NULL || content_type[0] == '\0') {
    content_type = "text/plain; charset=utf-8";
  }
  if (body == NULL) {
    body = "";
  }
  int body_len = (int)strlen(body);
  const char* reason = fz_http_reason(status_code);
  char header[512];
  int header_len = snprintf(
      header,
      sizeof(header),
      "HTTP/1.1 %d %s\r\n"
      "Content-Type: %s\r\n"
      "Content-Length: %d\r\n"
      "Connection: %s\r\n"
      "\r\n",
      status_code,
      reason,
      content_type,
      body_len,
      close_after ? "close" : "keep-alive");
  if (header_len <= 0 || header_len >= (int)sizeof(header)) {
    return -1;
  }
  if (fz_send_all(conn_fd, header, (size_t)header_len) != 0) {
    return -1;
  }
  if (body_len > 0 && fz_send_all(conn_fd, body, (size_t)body_len) != 0) {
    return -1;
  }
  if (close_after) {
    shutdown(conn_fd, SHUT_RDWR);
    close(conn_fd);
    fz_conn_state_drop(conn_fd);
  }
  return 0;
}

static void fz_bytes_buf_init(fz_bytes_buf* buf) {
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
}

static void fz_bytes_buf_free(fz_bytes_buf* buf) {
  if (buf->data != NULL) {
    free(buf->data);
  }
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
}

static int fz_bytes_buf_append(fz_bytes_buf* buf, const char* data, size_t len) {
  if (len == 0) {
    return 0;
  }
  size_t needed = buf->len + len + 1;
  if (needed > buf->cap) {
    size_t next_cap = buf->cap == 0 ? 4096 : buf->cap;
    while (next_cap < needed) {
      next_cap *= 2;
    }
    char* next = (char*)realloc(buf->data, next_cap);
    if (next == NULL) {
      return -1;
    }
    buf->data = next;
    buf->cap = next_cap;
  }
  memcpy(buf->data + buf->len, data, len);
  buf->len += len;
  buf->data[buf->len] = '\0';
  return 0;
}

static int fz_drain_fd(int fd, fz_bytes_buf* buf) {
  if (fd < 0) {
    return 0;
  }
  char tmp[4096];
  for (;;) {
    ssize_t got = read(fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(buf, tmp, (size_t)got) != 0) {
        return -1;
      }
      continue;
    }
    if (got == 0) {
      return 1;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return -1;
  }
}

static int fz_set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int fz_mark_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static fz_proc_state* fz_proc_state_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_PROC_STATES) {
    return NULL;
  }
  fz_proc_state* state = &fz_proc_states[handle - 1];
  if (!state->in_use) {
    return NULL;
  }
  return state;
}

static void fz_proc_set_last_error(const char* msg) {
  if (msg == NULL) {
    msg = "proc error";
  }
  fz_proc_last_error_id = fz_intern_slice(msg, strlen(msg));
}

static int32_t fz_proc_state_alloc(pid_t pid, int stdout_fd, int stderr_fd) {
  for (int i = 0; i < FZ_MAX_PROC_STATES; i++) {
    if (!fz_proc_states[i].in_use) {
      fz_proc_states[i].in_use = 1;
      fz_proc_states[i].pid = pid;
      fz_proc_states[i].stdout_fd = stdout_fd;
      fz_proc_states[i].stderr_fd = stderr_fd;
      fz_proc_states[i].done = 0;
      fz_proc_states[i].exit_notified = 0;
      fz_proc_states[i].exit_code = -1;
      fz_proc_states[i].stdout_read_pos = 0;
      fz_proc_states[i].stderr_read_pos = 0;
      fz_proc_states[i].stdout_id = 0;
      fz_proc_states[i].stderr_id = 0;
      fz_bytes_buf_init(&fz_proc_states[i].stdout_buf);
      fz_bytes_buf_init(&fz_proc_states[i].stderr_buf);
      return i + 1;
    }
  }
  return -1;
}

static void fz_proc_finalize(fz_proc_state* state, int exit_code) {
  if (state->stdout_fd >= 0) {
    (void)fz_drain_fd(state->stdout_fd, &state->stdout_buf);
    close(state->stdout_fd);
    state->stdout_fd = -1;
  }
  if (state->stderr_fd >= 0) {
    (void)fz_drain_fd(state->stderr_fd, &state->stderr_buf);
    close(state->stderr_fd);
    state->stderr_fd = -1;
  }
  state->stdout_id = fz_intern_slice(
      state->stdout_buf.data == NULL ? "" : state->stdout_buf.data,
      state->stdout_buf.data == NULL ? 0 : state->stdout_buf.len);
  state->stderr_id = fz_intern_slice(
      state->stderr_buf.data == NULL ? "" : state->stderr_buf.data,
      state->stderr_buf.data == NULL ? 0 : state->stderr_buf.len);
  state->exit_code = exit_code;
  state->done = 1;
}

static void fz_spawn_join_all(void) {
  for (;;) {
    pthread_t thread;
    int has_thread = 0;
    pthread_mutex_lock(&fz_spawn_lock);
    if (fz_spawn_thread_count > 0) {
      fz_spawn_thread_count--;
      thread = fz_spawn_threads[fz_spawn_thread_count];
      has_thread = 1;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    if (!has_thread) {
      break;
    }
    (void)pthread_join(thread, NULL);
  }
}

static void fz_spawn_register_atexit(void) {
  (void)atexit(fz_spawn_join_all);
}

static void* fz_spawn_thread_main(void* arg) {
  fz_spawn_ctx* ctx = (fz_spawn_ctx*)arg;
  if (ctx == NULL) {
    return NULL;
  }
  fz_task_entry_fn entry = ctx->entry;
  free(ctx);
  if (entry != NULL) {
    (void)entry();
  }
  return NULL;
}

int32_t fz_native_env_get(int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  if (key == NULL || key[0] == '\0') {
    return 0;
  }
  const char* value = getenv(key);
  if (value == NULL) {
    value = "";
  }
  return fz_intern_slice(value, strlen(value));
}

int32_t fz_native_time_now(void) {
  return (int32_t)fz_now_ms();
}

static int32_t fz_native_str_concat(const int32_t* ids, int count) {
  if (ids == NULL || count <= 0) {
    return fz_intern_slice("", 0);
  }
  size_t total = 0;
  for (int i = 0; i < count; i++) {
    total += strlen(fz_lookup_string(ids[i]));
  }
  char* out = (char*)malloc(total + 1);
  if (out == NULL) {
    return 0;
  }
  size_t used = 0;
  for (int i = 0; i < count; i++) {
    const char* part = fz_lookup_string(ids[i]);
    size_t len = strlen(part);
    if (len > 0) {
      memcpy(out + used, part, len);
      used += len;
    }
  }
  out[used] = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_str_concat2(int32_t a_id, int32_t b_id) {
  int32_t ids[] = {a_id, b_id};
  return fz_native_str_concat(ids, 2);
}

int32_t fz_native_str_concat3(int32_t a_id, int32_t b_id, int32_t c_id) {
  int32_t ids[] = {a_id, b_id, c_id};
  return fz_native_str_concat(ids, 3);
}

int32_t fz_native_str_concat4(int32_t a_id, int32_t b_id, int32_t c_id, int32_t d_id) {
  int32_t ids[] = {a_id, b_id, c_id, d_id};
  return fz_native_str_concat(ids, 4);
}

int32_t fz_native_str_contains(int32_t haystack_id, int32_t needle_id) {
  const char* hay = fz_lookup_string(haystack_id);
  const char* needle = fz_lookup_string(needle_id);
  if (needle == NULL || needle[0] == '\0') {
    return 1;
  }
  return strstr(hay == NULL ? "" : hay, needle) != NULL ? 1 : 0;
}

int32_t fz_native_str_starts_with(int32_t value_id, int32_t prefix_id) {
  const char* value = fz_lookup_string(value_id);
  const char* prefix = fz_lookup_string(prefix_id);
  size_t value_len = strlen(value == NULL ? "" : value);
  size_t prefix_len = strlen(prefix == NULL ? "" : prefix);
  if (prefix_len > value_len) {
    return 0;
  }
  return strncmp(value == NULL ? "" : value, prefix == NULL ? "" : prefix, prefix_len) == 0 ? 1 : 0;
}

int32_t fz_native_str_ends_with(int32_t value_id, int32_t suffix_id) {
  const char* value = fz_lookup_string(value_id);
  const char* suffix = fz_lookup_string(suffix_id);
  size_t value_len = strlen(value == NULL ? "" : value);
  size_t suffix_len = strlen(suffix == NULL ? "" : suffix);
  if (suffix_len > value_len) {
    return 0;
  }
  return strcmp((value == NULL ? "" : value) + (value_len - suffix_len), suffix == NULL ? "" : suffix) == 0 ? 1 : 0;
}

int32_t fz_native_str_len(int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  return (int32_t)strlen(value == NULL ? "" : value);
}

int32_t fz_native_str_trim(int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) {
    return fz_intern_slice("", 0);
  }
  size_t len = strlen(value);
  size_t start = 0;
  while (start < len && isspace((unsigned char)value[start])) {
    start++;
  }
  size_t end = len;
  while (end > start && isspace((unsigned char)value[end - 1])) {
    end--;
  }
  return fz_intern_slice(value + start, end - start);
}

int32_t fz_native_str_slice(int32_t value_id, int32_t start, int32_t span_len) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) {
    return fz_intern_slice("", 0);
  }
  size_t len = strlen(value);
  size_t s = (start < 0) ? 0 : (size_t)start;
  if (s > len) {
    s = len;
  }
  size_t n = span_len < 0 ? 0 : (size_t)span_len;
  if (s + n > len) {
    n = len - s;
  }
  return fz_intern_slice(value + s, n);
}

int32_t fz_native_str_replace(int32_t value_id, int32_t from_id, int32_t to_id) {
  const char* value = fz_lookup_string(value_id);
  const char* from = fz_lookup_string(from_id);
  const char* to = fz_lookup_string(to_id);
  if (value == NULL) value = "";
  if (from == NULL || from[0] == '\0') {
    return fz_intern_slice(value, strlen(value));
  }
  if (to == NULL) {
    to = "";
  }
  size_t from_len = strlen(from);
  size_t to_len = strlen(to);
  size_t value_len = strlen(value);
  size_t cap = value_len + 1;
  char* out = (char*)malloc(cap);
  if (out == NULL) {
    return 0;
  }
  size_t out_len = 0;
  const char* cursor = value;
  const char* hit = NULL;
  while ((hit = strstr(cursor, from)) != NULL) {
    size_t prefix = (size_t)(hit - cursor);
    size_t needed = out_len + prefix + to_len + 1;
    if (needed > cap) {
      while (cap < needed) cap *= 2;
      char* next = (char*)realloc(out, cap);
      if (next == NULL) {
        free(out);
        return 0;
      }
      out = next;
    }
    memcpy(out + out_len, cursor, prefix);
    out_len += prefix;
    memcpy(out + out_len, to, to_len);
    out_len += to_len;
    cursor = hit + from_len;
  }
  size_t tail = strlen(cursor);
  if (out_len + tail + 1 > cap) {
    cap = out_len + tail + 1;
    char* next = (char*)realloc(out, cap);
    if (next == NULL) {
      free(out);
      return 0;
    }
    out = next;
  }
  memcpy(out + out_len, cursor, tail);
  out_len += tail;
  out[out_len] = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_str_split(int32_t value_id, int32_t sep_id) {
  const char* value = fz_lookup_string(value_id);
  const char* sep = fz_lookup_string(sep_id);
  if (value == NULL) value = "";
  if (sep == NULL) sep = "";
  int32_t handle = fz_list_alloc();
  if (handle < 0) {
    return -1;
  }
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL) {
    return -1;
  }
  size_t sep_len = strlen(sep);
  if (sep_len == 0) {
    (void)fz_list_push_cstr(list, value);
    return handle;
  }
  const char* cursor = value;
  const char* hit = NULL;
  while ((hit = strstr(cursor, sep)) != NULL) {
    size_t n = (size_t)(hit - cursor);
    char* part = (char*)malloc(n + 1);
    if (part == NULL) {
      break;
    }
    memcpy(part, cursor, n);
    part[n] = '\0';
    if (fz_list_push_cstr(list, part) != 0) {
      free(part);
      break;
    }
    free(part);
    cursor = hit + sep_len;
  }
  (void)fz_list_push_cstr(list, cursor);
  return handle;
}

int32_t fz_native_http_header(int32_t key_id, int32_t value_id) {
  if (key_id <= 0 || value_id <= 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_http_lock);
  if (fz_http_header_count >= FZ_MAX_HTTP_HEADERS) {
    pthread_mutex_unlock(&fz_http_lock);
    return -1;
  }
  fz_http_headers[fz_http_header_count].key_id = key_id;
  fz_http_headers[fz_http_header_count].value_id = value_id;
  fz_http_header_count++;
  pthread_mutex_unlock(&fz_http_lock);
  return 0;
}

int32_t fz_native_json_escape(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  char* escaped = fz_json_escape_owned(input);
  if (escaped == NULL) {
    return 0;
  }
  return fz_intern_owned(escaped);
}

int32_t fz_native_json_str(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  char* escaped = fz_json_escape_owned(input);
  if (escaped == NULL) {
    return 0;
  }
  size_t len = strlen(escaped);
  char* wrapped = (char*)malloc(len + 3);
  if (wrapped == NULL) {
    free(escaped);
    return 0;
  }
  wrapped[0] = '\"';
  if (len > 0) {
    memcpy(wrapped + 1, escaped, len);
  }
  wrapped[len + 1] = '\"';
  wrapped[len + 2] = '\0';
  free(escaped);
  return fz_intern_owned(wrapped);
}

int32_t fz_native_json_raw(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  if (input == NULL || input[0] == '\0') {
    return fz_intern_slice("null", 4);
  }
  return fz_intern_slice(input, strlen(input));
}

static int32_t fz_native_json_array_from_values(const int32_t* ids, int value_count) {
  if (ids == NULL || value_count <= 0) {
    return fz_intern_slice("[]", 2);
  }
  size_t total = 3;
  for (int i = 0; i < value_count; i++) {
    const char* value = fz_lookup_string(ids[i]);
    total += strlen(value == NULL || value[0] == '\0' ? "null" : value) + 1;
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    return 0;
  }
  size_t used = 0;
  out[used++] = '[';
  for (int i = 0; i < value_count; i++) {
    if (i > 0) {
      out[used++] = ',';
    }
    const char* value = fz_lookup_string(ids[i]);
    if (value == NULL || value[0] == '\0') {
      value = "null";
    }
    size_t len = strlen(value);
    if (len > 0) {
      memcpy(out + used, value, len);
      used += len;
    }
  }
  out[used++] = ']';
  out[used] = '\0';
  return fz_intern_owned(out);
}

static int32_t fz_native_json_object_from_pairs(const int32_t* ids, int pair_count) {
  if (ids == NULL || pair_count <= 0) {
    return fz_intern_slice("{}", 2);
  }
  char** escaped_keys = (char**)calloc((size_t)pair_count, sizeof(char*));
  if (escaped_keys == NULL) {
    return 0;
  }
  size_t total = 3;
  for (int i = 0; i < pair_count; i++) {
    const char* key = fz_lookup_string(ids[i * 2]);
    const char* raw_value = fz_lookup_string(ids[(i * 2) + 1]);
    if (raw_value == NULL || raw_value[0] == '\0') {
      raw_value = "null";
    }
    escaped_keys[i] = fz_json_escape_owned(key);
    if (escaped_keys[i] == NULL) {
      for (int j = 0; j <= i; j++) {
        free(escaped_keys[j]);
      }
      free(escaped_keys);
      return 0;
    }
    total += strlen(escaped_keys[i]) + strlen(raw_value) + 5;
  }
  char* body = (char*)malloc(total);
  if (body == NULL) {
    for (int i = 0; i < pair_count; i++) {
      free(escaped_keys[i]);
    }
    free(escaped_keys);
    return 0;
  }
  size_t used = 0;
  body[used++] = '{';
  for (int i = 0; i < pair_count; i++) {
    if (i > 0) {
      body[used++] = ',';
    }
    body[used++] = '\"';
    size_t key_len = strlen(escaped_keys[i]);
    memcpy(body + used, escaped_keys[i], key_len);
    used += key_len;
    body[used++] = '\"';
    body[used++] = ':';
    const char* raw_value = fz_lookup_string(ids[(i * 2) + 1]);
    if (raw_value == NULL || raw_value[0] == '\0') {
      raw_value = "null";
    }
    size_t value_len = strlen(raw_value);
    memcpy(body + used, raw_value, value_len);
    used += value_len;
  }
  body[used++] = '}';
  body[used] = '\0';
  for (int i = 0; i < pair_count; i++) {
    free(escaped_keys[i]);
  }
  free(escaped_keys);
  return fz_intern_owned(body);
}

int32_t fz_native_json_array1(int32_t v1_id) {
  int32_t ids[] = {v1_id};
  return fz_native_json_array_from_values(ids, 1);
}

int32_t fz_native_json_array2(int32_t v1_id, int32_t v2_id) {
  int32_t ids[] = {v1_id, v2_id};
  return fz_native_json_array_from_values(ids, 2);
}

int32_t fz_native_json_array3(int32_t v1_id, int32_t v2_id, int32_t v3_id) {
  int32_t ids[] = {v1_id, v2_id, v3_id};
  return fz_native_json_array_from_values(ids, 3);
}

int32_t fz_native_json_array4(int32_t v1_id, int32_t v2_id, int32_t v3_id, int32_t v4_id) {
  int32_t ids[] = {v1_id, v2_id, v3_id, v4_id};
  return fz_native_json_array_from_values(ids, 4);
}

int32_t fz_native_json_object1(int32_t k1_id, int32_t v1_id) {
  int32_t ids[] = {k1_id, v1_id};
  return fz_native_json_object_from_pairs(ids, 1);
}

int32_t fz_native_json_object2(int32_t k1_id, int32_t v1_id, int32_t k2_id, int32_t v2_id) {
  int32_t ids[] = {k1_id, v1_id, k2_id, v2_id};
  return fz_native_json_object_from_pairs(ids, 2);
}

int32_t fz_native_json_object3(
    int32_t k1_id,
    int32_t v1_id,
    int32_t k2_id,
    int32_t v2_id,
    int32_t k3_id,
    int32_t v3_id) {
  int32_t ids[] = {k1_id, v1_id, k2_id, v2_id, k3_id, v3_id};
  return fz_native_json_object_from_pairs(ids, 3);
}

int32_t fz_native_json_object4(
    int32_t k1_id,
    int32_t v1_id,
    int32_t k2_id,
    int32_t v2_id,
    int32_t k3_id,
    int32_t v3_id,
    int32_t k4_id,
    int32_t v4_id) {
  int32_t ids[] = {k1_id, v1_id, k2_id, v2_id, k3_id, v3_id, k4_id, v4_id};
  return fz_native_json_object_from_pairs(ids, 4);
}

int32_t fz_native_list_new(void) {
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_list_alloc();
  pthread_mutex_unlock(&fz_collections_lock);
  return handle;
}

int32_t fz_native_list_push(int32_t handle, int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  int ok = list != NULL && fz_list_push_cstr(list, value) == 0 ? 0 : -1;
  pthread_mutex_unlock(&fz_collections_lock);
  return ok;
}

int32_t fz_native_list_pop(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || list->count <= 0) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  char* item = list->items[list->count - 1];
  list->items[list->count - 1] = NULL;
  list->count--;
  int32_t id = fz_intern_slice(item == NULL ? "" : item, item == NULL ? 0 : strlen(item));
  free(item);
  pthread_mutex_unlock(&fz_collections_lock);
  return id;
}

int32_t fz_native_list_len(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  int32_t len = list == NULL ? -1 : list->count;
  pthread_mutex_unlock(&fz_collections_lock);
  return len;
}

int32_t fz_native_list_get(int32_t handle, int32_t index) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || index < 0 || index >= list->count) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  const char* item = list->items[index] == NULL ? "" : list->items[index];
  int32_t id = fz_intern_slice(item, strlen(item));
  pthread_mutex_unlock(&fz_collections_lock);
  return id;
}

int32_t fz_native_list_set(int32_t handle, int32_t index, int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) value = "";
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || index < 0 || index >= list->count) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  char* dup = strdup(value);
  if (dup == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  free(list->items[index]);
  list->items[index] = dup;
  pthread_mutex_unlock(&fz_collections_lock);
  return 0;
}

int32_t fz_native_list_clear(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  for (int i = 0; i < list->count; i++) {
    free(list->items[i]);
    list->items[i] = NULL;
  }
  list->count = 0;
  pthread_mutex_unlock(&fz_collections_lock);
  return 0;
}

int32_t fz_native_list_join(int32_t handle, int32_t sep_id) {
  const char* sep = fz_lookup_string(sep_id);
  if (sep == NULL) sep = "";
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  size_t sep_len = strlen(sep);
  size_t total = 1;
  for (int i = 0; i < list->count; i++) {
    total += strlen(list->items[i] == NULL ? "" : list->items[i]);
    if (i > 0) total += sep_len;
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  size_t used = 0;
  for (int i = 0; i < list->count; i++) {
    if (i > 0 && sep_len > 0) {
      memcpy(out + used, sep, sep_len);
      used += sep_len;
    }
    const char* item = list->items[i] == NULL ? "" : list->items[i];
    size_t len = strlen(item);
    if (len > 0) {
      memcpy(out + used, item, len);
      used += len;
    }
  }
  out[used] = '\0';
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_intern_owned(out);
}

int32_t fz_native_map_new(void) {
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_map_alloc();
  pthread_mutex_unlock(&fz_collections_lock);
  return handle;
}

int32_t fz_native_map_set(int32_t handle, int32_t key_id, int32_t value_id) {
  const char* key = fz_lookup_string(key_id);
  const char* value = fz_lookup_string(value_id);
  if (key == NULL || key[0] == '\0') {
    return -1;
  }
  if (value == NULL) value = "";
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int idx = fz_map_find_index(map, key);
  if (idx >= 0) {
    char* dup = strdup(value);
    if (dup == NULL) {
      pthread_mutex_unlock(&fz_collections_lock);
      return -1;
    }
    free(map->values[idx]);
    map->values[idx] = dup;
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  if (map->count >= FZ_MAX_MAP_ENTRIES) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  map->keys[map->count] = strdup(key);
  map->values[map->count] = strdup(value);
  if (map->keys[map->count] == NULL || map->values[map->count] == NULL) {
    free(map->keys[map->count]);
    free(map->values[map->count]);
    map->keys[map->count] = NULL;
    map->values[map->count] = NULL;
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  map->count++;
  pthread_mutex_unlock(&fz_collections_lock);
  return 0;
}

int32_t fz_native_map_get(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  int idx = fz_map_find_index(map, key);
  const char* value = (idx >= 0 && map->values[idx] != NULL) ? map->values[idx] : "";
  int32_t out = fz_intern_slice(value, strlen(value));
  pthread_mutex_unlock(&fz_collections_lock);
  return out;
}

int32_t fz_native_map_has(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  int ok = (map != NULL && key != NULL && fz_map_find_index(map, key) >= 0) ? 1 : 0;
  pthread_mutex_unlock(&fz_collections_lock);
  return ok;
}

int32_t fz_native_map_delete(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int idx = fz_map_find_index(map, key);
  if (idx < 0) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  free(map->keys[idx]);
  free(map->values[idx]);
  for (int i = idx; i + 1 < map->count; i++) {
    map->keys[i] = map->keys[i + 1];
    map->values[i] = map->values[i + 1];
  }
  map->count--;
  map->keys[map->count] = NULL;
  map->values[map->count] = NULL;
  pthread_mutex_unlock(&fz_collections_lock);
  return 1;
}

int32_t fz_native_map_keys(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  for (int i = 0; i < map->count; i++) {
    (void)fz_list_push_cstr(list, map->keys[i] == NULL ? "" : map->keys[i]);
  }
  pthread_mutex_unlock(&fz_collections_lock);
  return list_handle;
}

int32_t fz_native_map_len(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  int32_t len = map == NULL ? -1 : map->count;
  pthread_mutex_unlock(&fz_collections_lock);
  return len;
}

int32_t fz_native_json_from_list(int32_t list_handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(list_handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("[]", 2);
  }
  size_t total = 3;
  for (int i = 0; i < list->count; i++) {
    char* escaped = fz_json_escape_owned(list->items[i] == NULL ? "" : list->items[i]);
    if (escaped == NULL) continue;
    total += strlen(escaped) + 3;
    free(escaped);
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  size_t used = 0;
  out[used++] = '[';
  for (int i = 0; i < list->count; i++) {
    if (i > 0) out[used++] = ',';
    char* escaped = fz_json_escape_owned(list->items[i] == NULL ? "" : list->items[i]);
    if (escaped == NULL) {
      out[used++] = '\"';
      out[used++] = '\"';
      continue;
    }
    out[used++] = '\"';
    size_t n = strlen(escaped);
    memcpy(out + used, escaped, n);
    used += n;
    out[used++] = '\"';
    free(escaped);
  }
  out[used++] = ']';
  out[used] = '\0';
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_intern_owned(out);
}

int32_t fz_native_json_from_map(int32_t map_handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(map_handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("{}", 2);
  }
  size_t total = 3;
  for (int i = 0; i < map->count; i++) {
    char* k = fz_json_escape_owned(map->keys[i] == NULL ? "" : map->keys[i]);
    char* v = fz_json_escape_owned(map->values[i] == NULL ? "" : map->values[i]);
    if (k != NULL && v != NULL) {
      total += strlen(k) + strlen(v) + 7;
    }
    free(k);
    free(v);
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  size_t used = 0;
  out[used++] = '{';
  for (int i = 0; i < map->count; i++) {
    if (i > 0) out[used++] = ',';
    char* k = fz_json_escape_owned(map->keys[i] == NULL ? "" : map->keys[i]);
    char* v = fz_json_escape_owned(map->values[i] == NULL ? "" : map->values[i]);
    if (k == NULL || v == NULL) {
      free(k);
      free(v);
      out[used++] = '\"';
      out[used++] = '\"';
      out[used++] = ':';
      out[used++] = '\"';
      out[used++] = '\"';
      continue;
    }
    out[used++] = '\"';
    size_t kn = strlen(k);
    memcpy(out + used, k, kn);
    used += kn;
    out[used++] = '\"';
    out[used++] = ':';
    out[used++] = '\"';
    size_t vn = strlen(v);
    memcpy(out + used, v, vn);
    used += vn;
    out[used++] = '\"';
    free(k);
    free(v);
  }
  out[used++] = '}';
  out[used] = '\0';
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_intern_owned(out);
}

int32_t fz_native_json_to_list(int32_t json_id) {
  const char* raw = fz_lookup_string(json_id);
  char** items = NULL;
  int count = 0;
  if (fz_parse_json_string_array(raw, &items, &count) != 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(handle);
  if (list != NULL) {
    for (int i = 0; i < count; i++) {
      (void)fz_list_push_cstr(list, items[i] == NULL ? "" : items[i]);
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  fz_free_string_list(items, count);
  return handle;
}

int32_t fz_native_json_to_map(int32_t json_id) {
  const char* raw = fz_lookup_string(json_id);
  char** pairs = NULL;
  int count = 0;
  if (fz_parse_json_env_object(raw, &pairs, &count) != 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_map_alloc();
  fz_map_state* map = fz_map_get(handle);
  if (map != NULL) {
    for (int i = 0; i < count && map->count < FZ_MAX_MAP_ENTRIES; i++) {
      char* eq = strchr(pairs[i], '=');
      if (eq == NULL) continue;
      *eq = '\0';
      map->keys[map->count] = strdup(pairs[i]);
      map->values[map->count] = strdup(eq + 1);
      if (map->keys[map->count] != NULL && map->values[map->count] != NULL) {
        map->count++;
      }
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  fz_free_string_list(pairs, count);
  return handle;
}

static void fz_http_set_last_result(int status_code, const char* body, const char* err) {
  if (body == NULL) {
    body = "";
  }
  if (err == NULL) {
    err = "";
  }
  pthread_mutex_lock(&fz_http_lock);
  fz_http_last_status = status_code;
  fz_http_last_body_id = fz_intern_slice(body, strlen(body));
  fz_http_last_error_id = fz_intern_slice(err, strlen(err));
  pthread_mutex_unlock(&fz_http_lock);
}

static int fz_http_extract_status(char* payload, size_t payload_len, int* status_code, size_t* body_len) {
  if (status_code != NULL) {
    *status_code = 0;
  }
  if (body_len != NULL) {
    *body_len = payload_len;
  }
  if (payload == NULL || payload_len == 0) {
    return -1;
  }
  ssize_t i = (ssize_t)payload_len - 1;
  while (i >= 0 && (payload[i] == '\n' || payload[i] == '\r' || payload[i] == ' ' || payload[i] == '\t')) {
    i--;
  }
  if (i < 2) {
    return -1;
  }
  if (!isdigit((unsigned char)payload[i]) || !isdigit((unsigned char)payload[i - 1]) || !isdigit((unsigned char)payload[i - 2])) {
    return -1;
  }
  int parsed = (payload[i - 2] - '0') * 100 + (payload[i - 1] - '0') * 10 + (payload[i] - '0');
  ssize_t j = i - 3;
  while (j >= 0 && (payload[j] == '\n' || payload[j] == '\r')) {
    j--;
  }
  if (status_code != NULL) {
    *status_code = parsed;
  }
  if (body_len != NULL) {
    *body_len = (size_t)(j + 1);
  }
  return 0;
}

static int32_t fz_native_http_post_json_inner(int32_t endpoint_id, int32_t body_id, int return_body) {
  const char* endpoint = fz_lookup_string(endpoint_id);
  const char* body = fz_lookup_string(body_id);
  if (endpoint == NULL || endpoint[0] == '\0') {
    fz_last_exit_class = 3;
    fz_http_set_last_result(0, "", "http_post_json: empty endpoint");
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  if (body == NULL || body[0] == '\0') {
    body = "{}";
  }

  char* header_buf[FZ_MAX_HTTP_HEADERS];
  int header_count = 0;
  pthread_mutex_lock(&fz_http_lock);
  for (int i = 0; i < fz_http_header_count && i < FZ_MAX_HTTP_HEADERS; i++) {
    const char* key = fz_lookup_string(fz_http_headers[i].key_id);
    const char* value = fz_lookup_string(fz_http_headers[i].value_id);
    if (key == NULL || key[0] == '\0') {
      continue;
    }
    if (value == NULL) {
      value = "";
    }
    size_t n = strlen(key) + strlen(value) + 3;
    char* kv = (char*)malloc(n);
    if (kv == NULL) {
      continue;
    }
    snprintf(kv, n, "%s: %s", key, value);
    header_buf[header_count++] = kv;
  }
  fz_http_header_count = 0;
  pthread_mutex_unlock(&fz_http_lock);

  int max_args = 20 + (header_count * 2);
  char** argv = (char**)calloc((size_t)max_args, sizeof(char*));
  if (argv == NULL) {
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_http_set_last_result(0, "", "http_post_json: alloc failed");
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  int ai = 0;
  argv[ai++] = "curl";
  argv[ai++] = "-sS";
  argv[ai++] = "-X";
  argv[ai++] = "POST";
  argv[ai++] = (char*)endpoint;
  for (int i = 0; i < header_count; i++) {
    argv[ai++] = "-H";
    argv[ai++] = header_buf[i];
  }
  argv[ai++] = "--data";
  argv[ai++] = (char*)body;
  argv[ai++] = "-w";
  argv[ai++] = "\n%{http_code}";
  argv[ai++] = NULL;

  int out_pipe[2];
  if (pipe(out_pipe) != 0) {
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_http_set_last_result(0, "", "http_post_json: pipe failed");
    return return_body ? fz_intern_slice("", 0) : -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_http_set_last_result(0, "", "http_post_json: fork failed");
    return return_body ? fz_intern_slice("", 0) : -1;
  }

  if (pid == 0) {
    (void)dup2(out_pipe[1], STDOUT_FILENO);
    close(out_pipe[0]);
    close(out_pipe[1]);
    execvp("curl", argv);
    _exit(127);
  }

  close(out_pipe[1]);
  fz_bytes_buf out;
  fz_bytes_buf_init(&out);
  for (;;) {
    char tmp[4096];
    ssize_t got = read(out_pipe[0], tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&out, tmp, (size_t)got) != 0) {
        break;
      }
      continue;
    }
    if (got == 0) {
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    break;
  }
  close(out_pipe[0]);

  int status = 0;
  int waited = waitpid(pid, &status, 0);
  free(argv);
  for (int i = 0; i < header_count; i++) free(header_buf[i]);
  if (waited < 0) {
    fz_last_exit_class = 3;
    fz_http_set_last_result(0, "", "http_post_json: waitpid failed");
    fz_bytes_buf_free(&out);
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  fz_last_exit_class = fz_exit_class_from_status(0, status, 0);

  int status_code = 0;
  size_t body_len = out.len;
  (void)fz_http_extract_status(out.data, out.len, &status_code, &body_len);
  const char* body_text = out.data == NULL ? "" : out.data;
  char saved = '\0';
  if (out.data != NULL && body_len < out.len) {
    saved = out.data[body_len];
    out.data[body_len] = '\0';
  }
  fz_http_set_last_result(status_code, body_text, "");
  int32_t body_value_id = fz_intern_slice(body_text, strlen(body_text));
  if (out.data != NULL && body_len < out.len) {
    out.data[body_len] = saved;
  }
  fz_bytes_buf_free(&out);

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    return return_body ? body_value_id : 0;
  }
  if (return_body) {
    return body_value_id;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return -1;
}

int32_t fz_native_http_post_json(int32_t endpoint_id, int32_t body_id) {
  return fz_native_http_post_json_inner(endpoint_id, body_id, 0);
}

int32_t fz_native_http_post_json_capture(int32_t endpoint_id, int32_t body_id) {
  return fz_native_http_post_json_inner(endpoint_id, body_id, 1);
}

int32_t fz_native_http_last_status(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_status;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_http_last_body(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_body_id;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_http_last_error(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_error_id;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_error_code(void) {
  return fz_last_error_code;
}

int32_t fz_native_error_class(void) {
  return fz_last_error_class;
}

int32_t fz_native_error_message(void) {
  return fz_last_error_message_id;
}

int32_t fz_native_error_context(int32_t ctx_id) {
  const char* ctx = fz_lookup_string(ctx_id);
  const char* msg = fz_lookup_string(fz_last_error_message_id);
  if (ctx == NULL || ctx[0] == '\0') {
    return 0;
  }
  if (msg == NULL) {
    msg = "";
  }
  size_t n = strlen(msg) + strlen(ctx) + 4;
  char* out = (char*)malloc(n);
  if (out == NULL) {
    return -1;
  }
  snprintf(out, n, "%s: %s", msg, ctx);
  fz_last_error_message_id = fz_intern_owned(out);
  return 0;
}

static int32_t fz_log_emit(const char* level, const char* message, const char* fields) {
  if (level == NULL) level = "info";
  if (message == NULL) message = "";
  if (fields == NULL) fields = "{}";
  int64_t ts = fz_now_ms();
  if (fz_log_json || fields[0] != '\0') {
    fprintf(stdout, "{\"ts\":%lld,\"level\":\"%s\",\"msg\":\"", (long long)ts, level);
    for (const char* p = message; *p; p++) {
      if (*p == '"' || *p == '\\') fputc('\\', stdout);
      fputc(*p, stdout);
    }
    fprintf(stdout, "\",\"fields\":%s}\n", fields[0] == '\0' ? "{}" : fields);
  } else {
    fprintf(stdout, "[%lld] %s %s\n", (long long)ts, level, message);
  }
  fflush(stdout);
  return 0;
}

int32_t fz_native_log_info(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("info", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_warn(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("warn", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_error(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("error", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_set_json(int32_t enabled) {
  fz_log_json = enabled != 0 ? 1 : 0;
  return 0;
}

int32_t fz_native_log_correlation_id(int32_t conn_fd) {
  return fz_native_net_request_id(conn_fd);
}

int32_t fz_native_time_sleep_ms(int32_t ms) {
  if (ms > 0) {
    usleep((useconds_t)ms * 1000);
  }
  return 0;
}

int32_t fz_native_time_elapsed_ms(int32_t start_ms) {
  int64_t now = fz_now_ms();
  return (int32_t)(now - (int64_t)start_ms);
}

int32_t fz_native_time_deadline_after(int32_t delta_ms) {
  int64_t now = fz_now_ms();
  return (int32_t)(now + (int64_t)delta_ms);
}

int32_t fz_native_time_interval(int32_t period_ms) {
  if (period_ms <= 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_time_lock);
  int32_t handle = -1;
  for (int i = 0; i < FZ_MAX_INTERVALS; i++) {
    if (!fz_intervals[i].in_use) {
      fz_intervals[i].in_use = 1;
      fz_intervals[i].period_ms = period_ms;
      fz_intervals[i].next_ms = fz_now_ms() + period_ms;
      handle = i + 1;
      break;
    }
  }
  pthread_mutex_unlock(&fz_time_lock);
  return handle;
}

int32_t fz_native_time_tick(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_INTERVALS) {
    return -1;
  }
  pthread_mutex_lock(&fz_time_lock);
  fz_interval_state* interval = &fz_intervals[handle - 1];
  if (!interval->in_use) {
    pthread_mutex_unlock(&fz_time_lock);
    return -1;
  }
  int64_t now = fz_now_ms();
  int64_t wait_ms = interval->next_ms - now;
  if (wait_ms > 0) {
    pthread_mutex_unlock(&fz_time_lock);
    usleep((useconds_t)wait_ms * 1000);
    pthread_mutex_lock(&fz_time_lock);
    interval = &fz_intervals[handle - 1];
  }
  now = fz_now_ms();
  interval->next_ms = now + interval->period_ms;
  pthread_mutex_unlock(&fz_time_lock);
  return 0;
}

int32_t fz_native_fs_open(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  pthread_mutex_unlock(&fz_fs_lock);
  return fd;
}

int32_t fz_native_fs_write(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  if (fd < 0) {
    pthread_mutex_unlock(&fz_fs_lock);
    return -1;
  }
  const char* payload = "fozzy\n";
  ssize_t wrote = write(fd, payload, strlen(payload));
  pthread_mutex_unlock(&fz_fs_lock);
  return wrote < 0 ? -1 : (int32_t)wrote;
}

int32_t fz_native_fs_read(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  if (fd < 0) {
    pthread_mutex_unlock(&fz_fs_lock);
    return -1;
  }
  lseek(fd, 0, SEEK_SET);
  char buf[4096];
  ssize_t got = read(fd, buf, sizeof(buf));
  pthread_mutex_unlock(&fz_fs_lock);
  return got < 0 ? -1 : (int32_t)got;
}

int32_t fz_native_fs_flush(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  int rc = (fd < 0) ? -1 : fsync(fd);
  pthread_mutex_unlock(&fz_fs_lock);
  return rc == 0 ? 0 : -1;
}

int32_t fz_native_fs_fsync(void) {
  return fz_native_fs_flush();
}

int32_t fz_native_fs_atomic_write(void) {
  pthread_mutex_lock(&fz_fs_lock);
  const char* path = fz_fs_path();
  (void)path;
  int fd = open(fz_fs_tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    pthread_mutex_unlock(&fz_fs_lock);
    return -1;
  }
  const char* payload = "{}\n";
  int ok = 0;
  if (write(fd, payload, strlen(payload)) < 0) {
    ok = -1;
  }
  if (fsync(fd) != 0) {
    ok = -1;
  }
  close(fd);
  pthread_mutex_unlock(&fz_fs_lock);
  return ok;
}

int32_t fz_native_fs_rename_atomic(void) {
  pthread_mutex_lock(&fz_fs_lock);
  const char* path = fz_fs_path();
  int rc = rename(fz_fs_tmp_path, path);
  pthread_mutex_unlock(&fz_fs_lock);
  return rc == 0 ? 0 : -1;
}

int32_t fz_native_fs_read_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    return fz_intern_slice("", 0);
  }
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.read_file failed");
    return fz_intern_slice("", 0);
  }
  fz_bytes_buf buf;
  fz_bytes_buf_init(&buf);
  char tmp[4096];
  for (;;) {
    ssize_t got = read(fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&buf, tmp, (size_t)got) != 0) {
        break;
      }
      continue;
    }
    if (got == 0) break;
    if (errno == EINTR) continue;
    break;
  }
  close(fd);
  int32_t out = fz_intern_slice(buf.data == NULL ? "" : buf.data, buf.len);
  fz_bytes_buf_free(&buf);
  return out;
}

int32_t fz_native_fs_write_file(int32_t path_id, int32_t content_id) {
  const char* path = fz_lookup_string(path_id);
  const char* content = fz_lookup_string(content_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (content == NULL) content = "";
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.write_file open failed");
    return -1;
  }
  size_t left = strlen(content);
  const char* p = content;
  while (left > 0) {
    ssize_t wrote = write(fd, p, left);
    if (wrote < 0) {
      if (errno == EINTR) continue;
      close(fd);
      fz_set_last_error(errno, 3, "fs.write_file write failed");
      return -1;
    }
    if (wrote == 0) break;
    p += wrote;
    left -= (size_t)wrote;
  }
  close(fd);
  return 0;
}

int32_t fz_native_fs_mkdir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
  return -1;
}

int32_t fz_native_fs_exists(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return 0;
  struct stat st;
  return stat(path, &st) == 0 ? 1 : 0;
}

int32_t fz_native_fs_stat_size(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  struct stat st;
  if (stat(path, &st) != 0) return -1;
  return (int32_t)st.st_size;
}

int32_t fz_native_fs_listdir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  DIR* dir = opendir(path);
  if (dir == NULL) return -1;
  pthread_mutex_lock(&fz_collections_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list != NULL) {
    struct dirent* ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
      if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
      (void)fz_list_push_cstr(list, ent->d_name);
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  closedir(dir);
  return list_handle;
}

int32_t fz_native_fs_remove_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  return unlink(path) == 0 ? 0 : -1;
}

int32_t fz_native_fs_temp_file(int32_t prefix_id) {
  const char* prefix = fz_lookup_string(prefix_id);
  if (prefix == NULL || prefix[0] == '\0') prefix = "fz";
  char tmpl[512];
  snprintf(tmpl, sizeof(tmpl), "/tmp/%s-XXXXXX", prefix);
  int fd = mkstemp(tmpl);
  if (fd < 0) return fz_intern_slice("", 0);
  close(fd);
  return fz_intern_slice(tmpl, strlen(tmpl));
}

int32_t fz_native_path_join(int32_t left_id, int32_t right_id) {
  const char* left = fz_lookup_string(left_id);
  const char* right = fz_lookup_string(right_id);
  if (left == NULL) left = "";
  if (right == NULL) right = "";
  size_t left_len = strlen(left);
  size_t right_len = strlen(right);
  int need_sep = left_len > 0 && left[left_len - 1] != '/';
  char* out = (char*)malloc(left_len + right_len + (need_sep ? 2 : 1));
  if (out == NULL) return 0;
  strcpy(out, left);
  if (need_sep) strcat(out, "/");
  strcat(out, right);
  return fz_intern_owned(out);
}

int32_t fz_native_path_normalize(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL) path = "";
  char* out = strdup(path);
  if (out == NULL) return 0;
  size_t w = 0;
  for (size_t r = 0; out[r] != '\0'; r++) {
    if (out[r] == '/' && w > 0 && out[w - 1] == '/') continue;
    out[w++] = out[r];
  }
  if (w > 1 && out[w - 1] == '/') w--;
  out[w] = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_net_bind(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  (void)fz_mark_cloexec(fd);
  int yes = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = fz_default_addr();
  addr.sin_port = htons((uint16_t)fz_default_port());
  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  pthread_mutex_lock(&fz_listener_lock);
  fz_listener_fd = fd;
  pthread_mutex_unlock(&fz_listener_lock);
  return fd;
}

int32_t fz_native_net_listen(int32_t fd) {
  int listener = fd;
  if (listener < 0) {
    pthread_mutex_lock(&fz_listener_lock);
    listener = fz_listener_fd;
    pthread_mutex_unlock(&fz_listener_lock);
  }
  if (listener < 0) {
    return -1;
  }
  return listen(listener, 128) == 0 ? 0 : -1;
}

int32_t fz_native_net_accept(void) {
  int listener = -1;
  pthread_mutex_lock(&fz_listener_lock);
  listener = fz_listener_fd;
  pthread_mutex_unlock(&fz_listener_lock);
  if (listener < 0) {
    return -1;
  }
  struct sockaddr_in peer;
  socklen_t peer_len = sizeof(peer);
  int conn_fd = accept(listener, (struct sockaddr*)&peer, &peer_len);
  if (conn_fd < 0) {
    return -1;
  }
  (void)fz_mark_cloexec(conn_fd);
  char peer_addr[64];
  const char* rendered = inet_ntop(AF_INET, &peer.sin_addr, peer_addr, sizeof(peer_addr));
  if (rendered == NULL) {
    rendered = "";
  }
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 1);
  if (state != NULL) {
    state->remote_addr_id = fz_intern_slice(rendered, strlen(rendered));
    state->request_id = 0;
    state->header_count = 0;
    state->query_count = 0;
    state->param_count = 0;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return conn_fd;
}

int32_t fz_native_net_read(int32_t conn_fd) {
  if (conn_fd < 0) {
    return -1;
  }
  char* req = (char*)malloc(FZ_MAX_HTTP_READ + 1);
  if (req == NULL) {
    return -1;
  }
  int total = 0;
  int header_end = -1;
  int64_t content_length = -1;
  while (total < FZ_MAX_HTTP_READ) {
    ssize_t got = recv(conn_fd, req + total, (size_t)(FZ_MAX_HTTP_READ - total), 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      free(req);
      return -1;
    }
    if (got == 0) {
      break;
    }
    total += (int)got;
    req[total] = '\0';
    if (header_end < 0) {
      header_end = fz_find_header_end(req, total);
      if (header_end >= 0) {
        content_length = fz_parse_content_length(req, header_end);
      }
    }
    if (header_end >= 0) {
      if (content_length >= 0) {
        if (total >= header_end + content_length) {
          break;
        }
      } else {
        break;
      }
    }
  }
  if (total <= 0) {
    free(req);
    return total;
  }
  if (header_end < 0) {
    free(req);
    return -1;
  }

  const char* line_end = strstr(req, "\r\n");
  if (line_end == NULL) {
    free(req);
    return -1;
  }
  const char* sp1 = memchr(req, ' ', (size_t)(line_end - req));
  if (sp1 == NULL) {
    free(req);
    return -1;
  }
  const char* sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - (sp1 + 1)));
  if (sp2 == NULL) {
    free(req);
    return -1;
  }

  size_t method_len = (size_t)(sp1 - req);
  size_t path_len = (size_t)(sp2 - (sp1 + 1));
  const char* version = sp2 + 1;
  int version_len = (int)(line_end - version);

  int body_len = total - header_end;
  if (content_length >= 0 && body_len > content_length) {
    body_len = (int)content_length;
  }
  if (body_len < 0) {
    body_len = 0;
  }

  const char* raw_path = sp1 + 1;
  const char* query_mark = memchr(raw_path, '?', path_len);
  size_t clean_path_len = query_mark == NULL ? path_len : (size_t)(query_mark - raw_path);

  int32_t method_id = fz_intern_slice(req, method_len);
  int32_t path_id = fz_intern_slice(raw_path, clean_path_len);
  int32_t body_id = fz_intern_slice(req + header_end, (size_t)body_len);
  int keep_alive = fz_parse_keep_alive(req, header_end, version, version_len);

  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 1);
  if (state != NULL) {
    state->method_id = method_id;
    state->path_id = path_id;
    state->body_id = body_id;
    state->keep_alive = keep_alive;
    state->header_count = 0;
    state->query_count = 0;
    state->param_count = 0;
    fz_conn_request_counter += 1;
    char rid[64];
    snprintf(rid, sizeof(rid), "req-%d", fz_conn_request_counter);
    state->request_id = fz_intern_slice(rid, strlen(rid));
    const char* cursor = line_end + 2;
    while (cursor < req + header_end && state->header_count < FZ_MAX_CONN_META) {
      const char* next = strstr(cursor, "\r\n");
      if (next == NULL || next <= cursor) break;
      const char* colon = memchr(cursor, ':', (size_t)(next - cursor));
      if (colon != NULL) {
        const char* v = colon + 1;
        while (v < next && (*v == ' ' || *v == '\t')) v++;
        state->header_key_ids[state->header_count] = fz_intern_slice(cursor, (size_t)(colon - cursor));
        state->header_value_ids[state->header_count] = fz_intern_slice(v, (size_t)(next - v));
        state->header_count++;
      }
      cursor = next + 2;
    }
    if (query_mark != NULL) {
      const char* q = query_mark + 1;
      const char* q_end = raw_path + path_len;
      while (q < q_end && state->query_count < FZ_MAX_CONN_META) {
        const char* amp = memchr(q, '&', (size_t)(q_end - q));
        const char* token_end = amp == NULL ? q_end : amp;
        const char* eq = memchr(q, '=', (size_t)(token_end - q));
        if (eq == NULL) {
          state->query_key_ids[state->query_count] = fz_intern_slice(q, (size_t)(token_end - q));
          state->query_value_ids[state->query_count] = fz_intern_slice("", 0);
          state->query_count++;
        } else {
          state->query_key_ids[state->query_count] = fz_intern_slice(q, (size_t)(eq - q));
          state->query_value_ids[state->query_count] = fz_intern_slice(eq + 1, (size_t)(token_end - (eq + 1)));
          state->query_count++;
        }
        if (amp == NULL) break;
        q = amp + 1;
      }
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);

  free(req);
  return total;
}

int32_t fz_native_net_method(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->method_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_path(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->path_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_body(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->body_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_header(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->header_count; i++) {
    const char* k = fz_lookup_string(state->header_key_ids[i]);
    if (k != NULL && strcasecmp(k, key) == 0) {
      int32_t value = state->header_value_ids[i];
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_query(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->query_count; i++) {
    const char* k = fz_lookup_string(state->query_key_ids[i]);
    if (k != NULL && strcmp(k, key) == 0) {
      int32_t value = state->query_value_ids[i];
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_param(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->param_count; i++) {
    const char* k = fz_lookup_string(state->param_key_ids[i]);
    if (k != NULL && strcmp(k, key) == 0) {
      int32_t value = state->param_value_ids[i];
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_headers(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list != NULL) {
    for (int i = 0; i < state->header_count; i++) {
      const char* k = fz_lookup_string(state->header_key_ids[i]);
      const char* v = fz_lookup_string(state->header_value_ids[i]);
      size_t n = strlen(k == NULL ? "" : k) + strlen(v == NULL ? "" : v) + 3;
      char* kv = (char*)malloc(n);
      if (kv == NULL) continue;
      snprintf(kv, n, "%s:%s", k == NULL ? "" : k, v == NULL ? "" : v);
      (void)fz_list_push_cstr(list, kv);
      free(kv);
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  pthread_mutex_unlock(&fz_conn_lock);
  return list_handle;
}

int32_t fz_native_net_request_id(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->request_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_remote_addr(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->remote_addr_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

static int fz_route_match_path_and_capture(fz_conn_state* state, const char* pattern) {
  if (state == NULL || pattern == NULL) {
    return 0;
  }
  const char* path = fz_lookup_string(state->path_id);
  if (path == NULL) path = "";
  state->param_count = 0;
  const char* p = path;
  const char* t = pattern;
  while (*p == '/') p++;
  while (*t == '/') t++;
  for (;;) {
    const char* p_end = strchr(p, '/');
    const char* t_end = strchr(t, '/');
    size_t p_len = p_end == NULL ? strlen(p) : (size_t)(p_end - p);
    size_t t_len = t_end == NULL ? strlen(t) : (size_t)(t_end - t);
    if (p_len == 0 && t_len == 0) return 1;
    if (p_len == 0 || t_len == 0) return 0;
    if (t[0] == ':') {
      if (state->param_count < FZ_MAX_ROUTE_PARAMS) {
        state->param_key_ids[state->param_count] = fz_intern_slice(t + 1, t_len - 1);
        state->param_value_ids[state->param_count] = fz_intern_slice(p, p_len);
        state->param_count++;
      }
    } else if (p_len != t_len || strncmp(p, t, p_len) != 0) {
      return 0;
    }
    if (p_end == NULL && t_end == NULL) return 1;
    if (p_end == NULL || t_end == NULL) return 0;
    p = p_end + 1;
    t = t_end + 1;
  }
}

int32_t fz_native_route_match(int32_t conn_fd, int32_t method_id, int32_t pattern_id) {
  const char* method = fz_lookup_string(method_id);
  const char* pattern = fz_lookup_string(pattern_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return 0;
  }
  if (method != NULL && method[0] != '\0') {
    const char* req_method = fz_lookup_string(state->method_id);
    if (req_method == NULL || strcmp(req_method, method) != 0) {
      pthread_mutex_unlock(&fz_conn_lock);
      return 0;
    }
  }
  int ok = fz_route_match_path_and_capture(state, pattern == NULL ? "" : pattern);
  pthread_mutex_unlock(&fz_conn_lock);
  return ok ? 1 : 0;
}

int32_t fz_native_route_write_404(int32_t conn_fd) {
  return fz_native_net_write(conn_fd, 404, fz_intern_slice("not found", 9));
}

int32_t fz_native_route_write_405(int32_t conn_fd) {
  return fz_native_net_write(conn_fd, 405, fz_intern_slice("method not allowed", 18));
}

int32_t fz_native_net_write_response(
    int32_t conn_fd,
    int32_t status_code,
    int32_t content_type_id,
    int32_t body_id,
    int32_t close_after) {
  const char* content_type = fz_lookup_string(content_type_id);
  const char* body = fz_lookup_string(body_id);
  return fz_send_http_response(conn_fd, status_code, content_type, body, close_after != 0);
}

int32_t fz_native_net_write(int32_t conn_fd, int32_t status_code, int32_t body_id) {
  int close_after = 1;
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state != NULL) {
    close_after = state->keep_alive ? 0 : 1;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_send_http_response(
      conn_fd,
      status_code,
      "text/plain; charset=utf-8",
      fz_lookup_string(body_id),
      close_after);
}

int32_t fz_native_net_write_json(int32_t conn_fd, int32_t status_code, int32_t body_id) {
  int close_after = 1;
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state != NULL) {
    close_after = state->keep_alive ? 0 : 1;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_send_http_response(
      conn_fd,
      status_code,
      "application/json",
      fz_lookup_string(body_id),
      close_after);
}

int32_t fz_native_close(int32_t fd) {
  if (fd >= 0) {
    shutdown(fd, SHUT_RDWR);
    close(fd);
  }
  fz_conn_state_drop(fd);
  return 0;
}

static const char* fz_json_skip_ws(const char* p) {
  while (p != NULL && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) {
    p++;
  }
  return p;
}

static int fz_json_parse_string(const char** cursor, char** out) {
  if (cursor == NULL || *cursor == NULL || out == NULL) {
    return -1;
  }
  const char* p = fz_json_skip_ws(*cursor);
  if (p == NULL || *p != '\"') {
    return -1;
  }
  p++;
  size_t cap = 32;
  size_t len = 0;
  char* buf = (char*)malloc(cap);
  if (buf == NULL) {
    return -1;
  }
  while (*p != '\0') {
    char ch = *p++;
    if (ch == '\"') {
      buf[len] = '\0';
      *out = buf;
      *cursor = p;
      return 0;
    }
    if (ch == '\\') {
      char esc = *p++;
      if (esc == '\0') {
        free(buf);
        return -1;
      }
      switch (esc) {
        case '\"': ch = '\"'; break;
        case '\\': ch = '\\'; break;
        case '/': ch = '/'; break;
        case 'b': ch = '\b'; break;
        case 'f': ch = '\f'; break;
        case 'n': ch = '\n'; break;
        case 'r': ch = '\r'; break;
        case 't': ch = '\t'; break;
        case 'u':
          for (int i = 0; i < 4; i++) {
            if (!isxdigit((unsigned char)p[i])) {
              free(buf);
              return -1;
            }
          }
          p += 4;
          ch = '?';
          break;
        default:
          free(buf);
          return -1;
      }
    }
    if (len + 2 > cap) {
      cap *= 2;
      char* next = (char*)realloc(buf, cap);
      if (next == NULL) {
        free(buf);
        return -1;
      }
      buf = next;
    }
    buf[len++] = ch;
  }
  free(buf);
  return -1;
}

static int fz_parse_json_string_array(const char* raw, char*** out_items, int* out_count) {
  if (out_items == NULL || out_count == NULL) {
    return -1;
  }
  *out_items = NULL;
  *out_count = 0;
  if (raw == NULL || raw[0] == '\0') {
    return 0;
  }
  const char* p = fz_json_skip_ws(raw);
  if (*p != '[') {
    return -1;
  }
  p = fz_json_skip_ws(p + 1);
  int cap = 4;
  int count = 0;
  char** items = (char**)calloc((size_t)cap, sizeof(char*));
  if (items == NULL) {
    return -1;
  }
  if (*p == ']') {
    *out_items = items;
    *out_count = 0;
    return 0;
  }
  for (;;) {
    char* item = NULL;
    if (fz_json_parse_string(&p, &item) != 0) {
      for (int i = 0; i < count; i++) free(items[i]);
      free(items);
      return -1;
    }
    if (count >= cap) {
      cap *= 2;
      char** next = (char**)realloc(items, (size_t)cap * sizeof(char*));
      if (next == NULL) {
        free(item);
        for (int i = 0; i < count; i++) free(items[i]);
        free(items);
        return -1;
      }
      items = next;
    }
    items[count++] = item;
    p = fz_json_skip_ws(p);
    if (*p == ',') {
      p = fz_json_skip_ws(p + 1);
      continue;
    }
    if (*p == ']') {
      break;
    }
    for (int i = 0; i < count; i++) free(items[i]);
    free(items);
    return -1;
  }
  *out_items = items;
  *out_count = count;
  return 0;
}

static int fz_parse_json_env_object(const char* raw, char*** out_items, int* out_count) {
  if (out_items == NULL || out_count == NULL) {
    return -1;
  }
  *out_items = NULL;
  *out_count = 0;
  if (raw == NULL || raw[0] == '\0') {
    return 0;
  }
  const char* p = fz_json_skip_ws(raw);
  if (*p != '{') {
    return -1;
  }
  p = fz_json_skip_ws(p + 1);
  int cap = 4;
  int count = 0;
  char** entries = (char**)calloc((size_t)cap, sizeof(char*));
  if (entries == NULL) {
    return -1;
  }
  if (*p == '}') {
    *out_items = entries;
    *out_count = 0;
    return 0;
  }
  for (;;) {
    char* key = NULL;
    char* value = NULL;
    if (fz_json_parse_string(&p, &key) != 0) {
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    p = fz_json_skip_ws(p);
    if (*p != ':') {
      free(key);
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    p = fz_json_skip_ws(p + 1);
    if (fz_json_parse_string(&p, &value) != 0) {
      free(key);
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    size_t n = strlen(key) + strlen(value) + 2;
    char* joined = (char*)malloc(n);
    if (joined == NULL) {
      free(key);
      free(value);
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    snprintf(joined, n, "%s=%s", key, value);
    free(key);
    free(value);
    if (count >= cap) {
      cap *= 2;
      char** next = (char**)realloc(entries, (size_t)cap * sizeof(char*));
      if (next == NULL) {
        free(joined);
        for (int i = 0; i < count; i++) free(entries[i]);
        free(entries);
        return -1;
      }
      entries = next;
    }
    entries[count++] = joined;
    p = fz_json_skip_ws(p);
    if (*p == ',') {
      p = fz_json_skip_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      break;
    }
    for (int i = 0; i < count; i++) free(entries[i]);
    free(entries);
    return -1;
  }
  *out_items = entries;
  *out_count = count;
  return 0;
}

static void fz_free_string_list(char** items, int count) {
  if (items == NULL) {
    return;
  }
  for (int i = 0; i < count; i++) {
    free(items[i]);
  }
  free(items);
}

static int fz_env_key_match(const char* entry, const char* key, size_t key_len) {
  if (entry == NULL || key == NULL) {
    return 0;
  }
  return strncmp(entry, key, key_len) == 0 && entry[key_len] == '=';
}

static char** fz_clone_env_with_overrides(char** overrides, int override_count) {
  int base_count = 0;
  while (environ != NULL && environ[base_count] != NULL) {
    base_count++;
  }
  int cap = base_count + override_count + 1;
  char** envp = (char**)calloc((size_t)cap, sizeof(char*));
  if (envp == NULL) {
    return NULL;
  }
  int count = 0;
  for (int i = 0; i < base_count; i++) {
    envp[count] = strdup(environ[i]);
    if (envp[count] == NULL) {
      for (int j = 0; j < count; j++) free(envp[j]);
      free(envp);
      return NULL;
    }
    count++;
  }
  for (int i = 0; i < override_count; i++) {
    const char* item = overrides[i];
    const char* eq = item == NULL ? NULL : strchr(item, '=');
    if (eq == NULL || eq == item) {
      continue;
    }
    size_t key_len = (size_t)(eq - item);
    int replaced = 0;
    for (int j = 0; j < count; j++) {
      if (fz_env_key_match(envp[j], item, key_len)) {
        char* dup = strdup(item);
        if (dup == NULL) {
          continue;
        }
        free(envp[j]);
        envp[j] = dup;
        replaced = 1;
        break;
      }
    }
    if (!replaced && count < cap - 1) {
      envp[count] = strdup(item);
      if (envp[count] != NULL) {
        count++;
      }
    }
  }
  envp[count] = NULL;
  return envp;
}

static void fz_free_env(char** envp) {
  if (envp == NULL) {
    return;
  }
  for (int i = 0; envp[i] != NULL; i++) {
    free(envp[i]);
  }
  free(envp);
}

static int32_t fz_native_proc_spawn_argv(
    const char* executable,
    char* const* argv,
    char* const* envp,
    const char* stdin_payload) {
  if (executable == NULL || executable[0] == '\0' || argv == NULL || argv[0] == NULL) {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: invalid argv");
    return -1;
  }

  int out_pipe[2];
  int err_pipe[2];
  int in_pipe[2] = {-1, -1};
  if (pipe(out_pipe) != 0) {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: stdout pipe failed");
    return -1;
  }
  if (pipe(err_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: stderr pipe failed");
    return -1;
  }
  if (stdin_payload != NULL && pipe(in_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: stdin pipe failed");
    return -1;
  }
  (void)fz_mark_cloexec(out_pipe[0]);
  (void)fz_mark_cloexec(err_pipe[0]);

  posix_spawn_file_actions_t file_actions;
  if (posix_spawn_file_actions_init(&file_actions) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    if (in_pipe[0] >= 0) {
      close(in_pipe[0]);
      close(in_pipe[1]);
    }
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: file actions init failed");
    return -1;
  }
  int file_actions_ok = 1;
  if (posix_spawn_file_actions_adddup2(&file_actions, out_pipe[1], STDOUT_FILENO) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_adddup2(&file_actions, err_pipe[1], STDERR_FILENO) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok && in_pipe[0] >= 0
      && posix_spawn_file_actions_adddup2(&file_actions, in_pipe[0], STDIN_FILENO) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, out_pipe[0]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, out_pipe[1]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, err_pipe[0]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, err_pipe[1]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok && in_pipe[0] >= 0
      && posix_spawn_file_actions_addclose(&file_actions, in_pipe[0]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok && in_pipe[1] >= 0
      && posix_spawn_file_actions_addclose(&file_actions, in_pipe[1]) != 0) {
    file_actions_ok = 0;
  }
  if (!file_actions_ok) {
    (void)posix_spawn_file_actions_destroy(&file_actions);
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    if (in_pipe[0] >= 0) {
      close(in_pipe[0]);
      close(in_pipe[1]);
    }
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: file actions setup failed");
    return -1;
  }

  pid_t pid = 0;
  int spawn_rc = posix_spawnp(
      &pid,
      executable,
      &file_actions,
      NULL,
      argv,
      envp == NULL ? environ : envp);
  (void)posix_spawn_file_actions_destroy(&file_actions);
  if (spawn_rc != 0 || pid <= 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    if (in_pipe[0] >= 0) {
      close(in_pipe[0]);
      close(in_pipe[1]);
    }
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: posix_spawnp failed");
    return -1;
  }

  if (in_pipe[0] >= 0) {
    close(in_pipe[0]);
    size_t remaining = strlen(stdin_payload);
    const char* cursor = stdin_payload;
    while (remaining > 0) {
      ssize_t wrote = write(in_pipe[1], cursor, remaining);
      if (wrote < 0) {
        if (errno == EINTR) {
          continue;
        }
        break;
      }
      if (wrote == 0) {
        break;
      }
      cursor += wrote;
      remaining -= (size_t)wrote;
    }
    close(in_pipe[1]);
  }

  close(out_pipe[1]);
  close(err_pipe[1]);
  (void)fz_set_nonblocking(out_pipe[0]);
  (void)fz_set_nonblocking(err_pipe[0]);

  pthread_mutex_lock(&fz_proc_lock);
  int32_t handle = fz_proc_state_alloc(pid, out_pipe[0], err_pipe[0]);
  pthread_mutex_unlock(&fz_proc_lock);
  if (handle < 0) {
    kill(pid, SIGKILL);
    close(out_pipe[0]);
    close(err_pipe[0]);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: state allocation failed");
    return -1;
  }
  fz_proc_set_last_error("");
  return handle;
}

int32_t fz_native_proc_spawn(int32_t command_id) {
  const char* command = fz_lookup_string(command_id);
  if (command == NULL || command[0] == '\0') {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: empty command");
    return -1;
  }
  char* const argv[] = {"sh", "-lc", (char*)command, NULL};
  return fz_native_proc_spawn_argv("sh", argv, environ, NULL);
}

int32_t fz_native_proc_spawnv(
    int32_t command_id,
    int32_t args_json_id,
    int32_t env_json_id,
    int32_t stdin_id) {
  const char* command = fz_lookup_string(command_id);
  const char* args_json = fz_lookup_string(args_json_id);
  const char* env_json = fz_lookup_string(env_json_id);
  const char* stdin_payload = fz_lookup_string(stdin_id);
  if (command == NULL || command[0] == '\0') {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnv: empty command");
    return -1;
  }

  char** arg_items = NULL;
  int arg_count = 0;
  if (fz_parse_json_string_array(args_json, &arg_items, &arg_count) != 0) {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnv: args_json must be a JSON string array");
    return -1;
  }
  char** env_items = NULL;
  int env_count = 0;
  if (fz_parse_json_env_object(env_json, &env_items, &env_count) != 0) {
    fz_free_string_list(arg_items, arg_count);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnv: env_json must be a JSON object<string,string>");
    return -1;
  }

  int argv_count = arg_count + 2;
  char** argv = (char**)calloc((size_t)argv_count, sizeof(char*));
  if (argv == NULL) {
    fz_free_string_list(arg_items, arg_count);
    fz_free_string_list(env_items, env_count);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnv: argv alloc failed");
    return -1;
  }
  argv[0] = (char*)command;
  for (int i = 0; i < arg_count; i++) {
    argv[i + 1] = arg_items[i];
  }
  argv[argv_count - 1] = NULL;

  char** envp = fz_clone_env_with_overrides(env_items, env_count);
  int32_t handle = fz_native_proc_spawn_argv(
      command,
      argv,
      envp == NULL ? environ : envp,
      (stdin_payload == NULL || stdin_payload[0] == '\0') ? NULL : stdin_payload);

  fz_free_env(envp);
  free(argv);
  fz_free_string_list(arg_items, arg_count);
  fz_free_string_list(env_items, env_count);
  return handle;
}

int32_t fz_native_proc_wait(int32_t handle, int32_t timeout_ms) {
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_proc_lock);
    fz_proc_set_last_error("proc_wait: invalid handle");
    return -1;
  }
  if (state->done) {
    pthread_mutex_unlock(&fz_proc_lock);
    return 0;
  }

  int64_t start = fz_now_ms();
  int status = 0;
  int timed_out = 0;
  for (;;) {
    if (fz_drain_fd(state->stdout_fd, &state->stdout_buf) < 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      fz_proc_set_last_error("proc_wait: stdout drain failed");
      return -1;
    }
    if (fz_drain_fd(state->stderr_fd, &state->stderr_buf) < 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      fz_proc_set_last_error("proc_wait: stderr drain failed");
      return -1;
    }

    pid_t waited = waitpid(state->pid, &status, WNOHANG);
    if (waited == state->pid) {
      break;
    }
    if (waited < 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      fz_proc_set_last_error("proc_wait: waitpid failed");
      return -1;
    }
    if (timeout_ms == 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      return 1;
    }
    if (timeout_ms > 0 && (fz_now_ms() - start) >= timeout_ms) {
      kill(state->pid, SIGKILL);
      (void)waitpid(state->pid, &status, 0);
      timed_out = 1;
      break;
    }
    usleep(10 * 1000);
  }

  int exit_code = -1;
  if (timed_out) {
    exit_code = -124;
  } else if (WIFEXITED(status)) {
    exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    exit_code = 128 + WTERMSIG(status);
  }
  fz_last_exit_class = fz_exit_class_from_status(timed_out, status, 0);
  fz_proc_finalize(state, exit_code);
  pthread_mutex_unlock(&fz_proc_lock);
  fz_proc_set_last_error("");
  return 0;
}

int32_t fz_native_proc_run(int32_t command_id) {
  int32_t handle = fz_native_proc_spawn(command_id);
  if (handle < 0) {
    return -1;
  }
  int32_t waited = fz_native_proc_wait(handle, fz_proc_default_timeout_ms);
  if (waited < 0) {
    return -1;
  }
  return handle;
}

int32_t fz_native_proc_runv(
    int32_t command_id,
    int32_t args_json_id,
    int32_t env_json_id,
    int32_t stdin_id) {
  int32_t handle = fz_native_proc_spawnv(command_id, args_json_id, env_json_id, stdin_id);
  if (handle < 0) {
    return -1;
  }
  int32_t waited = fz_native_proc_wait(handle, fz_proc_default_timeout_ms);
  if (waited < 0) {
    return -1;
  }
  return handle;
}

int32_t fz_native_proc_poll(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return -1;
  }
  return wait_result == 0 ? 1 : 0;
}

static int32_t fz_native_proc_read_stream_chunk(int32_t handle, int32_t max_bytes, int use_stdout) {
  if (max_bytes <= 0) {
    max_bytes = 4096;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_proc_lock);
    return fz_intern_slice("", 0);
  }
  if (!state->done) {
    (void)fz_drain_fd(state->stdout_fd, &state->stdout_buf);
    (void)fz_drain_fd(state->stderr_fd, &state->stderr_buf);
  }
  fz_bytes_buf* buf = use_stdout ? &state->stdout_buf : &state->stderr_buf;
  size_t* cursor = use_stdout ? &state->stdout_read_pos : &state->stderr_read_pos;
  size_t remaining = buf->len > *cursor ? (buf->len - *cursor) : 0;
  size_t take = remaining < (size_t)max_bytes ? remaining : (size_t)max_bytes;
  int32_t out = fz_intern_slice(buf->data == NULL ? "" : (buf->data + *cursor), take);
  *cursor += take;
  pthread_mutex_unlock(&fz_proc_lock);
  return out;
}

int32_t fz_native_proc_read_stdout(int32_t handle, int32_t max_bytes) {
  return fz_native_proc_read_stream_chunk(handle, max_bytes, 1);
}

int32_t fz_native_proc_read_stderr(int32_t handle, int32_t max_bytes) {
  return fz_native_proc_read_stream_chunk(handle, max_bytes, 0);
}

int32_t fz_native_proc_event(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return -1;
  }
  if (wait_result > 0) {
    return 0;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_proc_lock);
    return -1;
  }
  int emit = state->exit_notified ? 0 : 1;
  state->exit_notified = 1;
  pthread_mutex_unlock(&fz_proc_lock);
  return emit;
}

int32_t fz_native_proc_stdout(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return fz_proc_last_error_id;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t value = (state == NULL) ? 0 : state->stdout_id;
  pthread_mutex_unlock(&fz_proc_lock);
  return value;
}

int32_t fz_native_proc_stderr(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return fz_proc_last_error_id;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t value = (state == NULL) ? 0 : state->stderr_id;
  pthread_mutex_unlock(&fz_proc_lock);
  return value;
}

int32_t fz_native_proc_exit_code(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return -1;
  }
  if (wait_result > 0) {
    return -2;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t value = (state == NULL) ? -1 : state->exit_code;
  pthread_mutex_unlock(&fz_proc_lock);
  return value;
}

int32_t fz_native_proc_exec_timeout(int32_t timeout_ms) {
  if (timeout_ms > 0) {
    fz_proc_default_timeout_ms = timeout_ms;
  }
  return 0;
}

int32_t fz_native_proc_exit_class(void) {
  return fz_last_exit_class;
}

int32_t fz_native_spawn(int32_t task_ref) {
  if (task_ref <= 0 || task_ref > fz_task_entry_count) {
    return -1;
  }
  fz_task_entry_fn entry = fz_task_entries[task_ref - 1];
  if (entry == NULL) {
    return -1;
  }
  fz_spawn_ctx* ctx = (fz_spawn_ctx*)malloc(sizeof(fz_spawn_ctx));
  if (ctx == NULL) {
    return -1;
  }
  ctx->entry = entry;
  pthread_t thread;
  if (pthread_create(&thread, NULL, fz_spawn_thread_main, ctx) != 0) {
    free(ctx);
    return -1;
  }
  pthread_once(&fz_spawn_atexit_once, fz_spawn_register_atexit);
  pthread_mutex_lock(&fz_spawn_lock);
  if (fz_spawn_thread_count >= FZ_MAX_SPAWN_THREADS) {
    pthread_mutex_unlock(&fz_spawn_lock);
    (void)pthread_join(thread, NULL);
    return -1;
  }
  fz_spawn_threads[fz_spawn_thread_count++] = thread;
  pthread_mutex_unlock(&fz_spawn_lock);
  return task_ref;
}

int32_t fz_native_yield(void) {
  sched_yield();
  return 0;
}

int32_t fz_native_checkpoint(void) {
  sched_yield();
  return 0;
}

int32_t fz_native_pulse(void) {
  sched_yield();
  return 0;
}

int32_t fz_native_net_poll_next(void) {
  return -1;
}
"#,
    );
    c
}

fn linker_candidates() -> Vec<String> {
    if let Ok(explicit) = std::env::var("FZ_CC") {
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
    if let Ok(extra) = std::env::var("FZ_LINKER_ARGS") {
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
        render_native_runtime_shim, verify_file, BuildProfile,
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
            "use core.time;\nfn main() -> i32 {\n    return 0\n}\n",
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
            "use core.time;\nfn main() -> i32 {\n    return 0\n}\n",
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
            "mod infra;\nfn main() -> i32 {\n    let listener = net.bind()\n    return listener\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/infra.fzy"), "use core.net;\n")
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
            "use core.net;\nfn main() -> i32 {\n    let listener = net.bind()\n    return listener\n}\n",
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
            "use core.net;\nfn main() -> i32 {\n    let c = net.connect()\n    return 0\n}\n",
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
    fn native_runtime_shim_exposes_request_response_and_process_result_apis() {
        let shim = render_native_runtime_shim(
            &[
                "GET".to_string(),
                "/healthz".to_string(),
                "{\"ok\":true}".to_string(),
            ],
            &["worker.run".to_string()],
        );
        assert!(shim.contains("int32_t fz_native_net_method(int32_t conn_fd)"));
        assert!(shim.contains("int32_t fz_native_net_path(int32_t conn_fd)"));
        assert!(shim.contains("int32_t fz_native_net_body(int32_t conn_fd)"));
        assert!(shim.contains("int32_t fz_native_net_write_response("));
        assert!(shim.contains("int32_t fz_native_proc_wait(int32_t handle, int32_t timeout_ms)"));
        assert!(shim.contains("int32_t fz_native_proc_stdout(int32_t handle)"));
        assert!(shim.contains("int32_t fz_native_proc_stderr(int32_t handle)"));
        assert!(shim.contains("int32_t fz_native_proc_exit_code(int32_t handle)"));
        assert!(shim.contains("int32_t fz_native_env_get(int32_t key_id)"));
        assert!(shim.contains("int32_t fz_native_str_concat2(int32_t a_id, int32_t b_id)"));
        assert!(shim.contains("int32_t fz_native_str_contains(int32_t haystack_id, int32_t needle_id)"));
        assert!(shim.contains("int32_t fz_native_http_header(int32_t key_id, int32_t value_id)"));
        assert!(
            shim.contains("int32_t fz_native_http_post_json(int32_t endpoint_id, int32_t body_id)")
        );
        assert!(shim.contains(
            "int32_t fz_native_http_post_json_capture(int32_t endpoint_id, int32_t body_id)"
        ));
        assert!(shim.contains("int32_t fz_native_http_last_status(void)"));
        assert!(shim.contains("int32_t fz_native_json_escape(int32_t input_id)"));
        assert!(shim.contains("int32_t fz_native_json_str(int32_t input_id)"));
        assert!(shim.contains("int32_t fz_native_json_raw(int32_t input_id)"));
        assert!(shim.contains("int32_t fz_native_json_array4("));
        assert!(shim.contains("int32_t fz_native_json_from_map(int32_t map_handle)"));
        assert!(
            shim.contains("int32_t fz_native_json_object1(int32_t k1_id, int32_t v1_id)")
        );
        assert!(shim.contains(
            "int32_t fz_native_json_object2(int32_t k1_id, int32_t v1_id, int32_t k2_id, int32_t v2_id)"
        ));
        assert!(shim.contains("int32_t fz_native_json_object3("));
        assert!(shim.contains("int32_t fz_native_json_object4("));
        assert!(shim.contains("posix_spawnp"));
        assert!(shim.contains("int32_t fz_native_proc_spawnv("));
        assert!(shim.contains("int32_t fz_native_proc_runv("));
        assert!(shim.contains("int32_t fz_native_proc_poll(int32_t handle)"));
        assert!(shim.contains("int32_t fz_native_proc_read_stdout(int32_t handle, int32_t max_bytes)"));
        assert!(shim.contains("int32_t fz_native_net_header(int32_t conn_fd, int32_t key_id)"));
        assert!(shim.contains("int32_t fz_native_route_match(int32_t conn_fd, int32_t method_id, int32_t pattern_id)"));
        assert!(shim.contains("int32_t fz_native_fs_read_file(int32_t path_id)"));
        assert!(shim.contains("int32_t fz_native_time_tick(int32_t handle)"));
        assert!(shim.contains("int32_t fz_native_error_code(void)"));
        assert!(shim.contains("int32_t fz_native_log_info(int32_t message_id, int32_t fields_id)"));
        assert!(shim.contains("FD_CLOEXEC"));
        assert!(shim.contains("int32_t fz_native_proc_exit_class(void)"));
        assert!(shim.contains("int32_t fz_native_time_now(void)"));
        assert!(shim.contains("int32_t fz_native_fs_open(void)"));
        assert!(shim.contains("int32_t fz_native_pulse(void)"));
        assert!(shim.contains("static const int fz_task_entry_count = 1;"));
        assert!(shim.contains("fz_spawn_thread_main"));
    }

    #[test]
    fn native_runtime_shim_does_not_use_env_response_templates() {
        let shim = render_native_runtime_shim(&[], &[]);
        assert!(!shim.contains("FZ_NET_WRITE_JSON_BODY"));
        assert!(!shim.contains("FZ_NET_WRITE_BODY"));
        assert!(!shim.contains("fz_env_or_default"));
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
        assert!(root.join(".fz/build/main.o").exists());

        let release = compile_file_with_backend(&root, BuildProfile::Release, None)
            .expect("release build should succeed");
        assert_eq!(release.status, "ok");
        assert!(root.join(".fz/build/main.ll").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_accepts_runtime_and_dotted_native_calls() {
        let file_name = format!(
            "fozzylang-native-supported-runtime-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "use core.net;\nfn main() -> i32 {\n    let listener = net.bind()\n    net.listen(listener)\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| diag
            .message
            .contains("native backend cannot execute unresolved call")));

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

    #[test]
    fn emit_ir_canonicalizes_sibling_module_calls() {
        let project_name = format!(
            "fozzylang-call-canonicalize-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src/services")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\nfn main() -> i32 {\n    services.http.start_server()\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/services/mod.fzy"), "mod web;\nmod http;\n")
            .expect("services mod should be written");
        std::fs::write(
            root.join("src/services/web.fzy"),
            "fn start_listener() -> i32 {\n    return 0\n}\n",
        )
        .expect("web source should be written");
        std::fs::write(
            root.join("src/services/http.fzy"),
            "fn start_server() -> i32 {\n    web.start_listener()\n    return 0\n}\n",
        )
        .expect("http source should be written");

        let output = emit_ir(&root).expect("emit ir should run");
        let ir = output.backend_ir.expect("backend ir should be available");
        assert!(ir.contains("@services.web.start_listener"));
        assert!(!ir.contains("@web.start_listener"));

        let _ = std::fs::remove_dir_all(root);
    }
}
