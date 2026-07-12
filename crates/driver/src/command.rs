use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::error::Error as StdError;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use formatter::{format_source, is_fzy_source_path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli_output;
use crate::lsp;
use crate::pipeline::{
    check_file, compile_file_incremental_with_backend, compile_file_with_backend,
    compile_library_incremental_with_backend, compile_library_with_backend,
    embedded_core_stdlib_module_source, emit_ir, gpu_backend_report_json,
    lower_fir_cached_with_metadata, parse_program, parse_program_with_metadata, refresh_lockfile,
    verify_file, BuildArtifact, BuildProfile, LibraryArtifact, Output,
};

mod interop;
mod non_scenario;
mod source;
mod trace_native;

use self::interop::{
    generate_c_headers, generate_rpc_artifacts, render_headers, render_rpc_artifacts,
    HeaderArtifact,
};
use self::non_scenario::run_non_scenario_test_plan_with_root_guidance;
use self::source::{
    discover_nested_project_roots, discover_project_roots, load_resolved_module_set,
    resolve_source, ResolvedModuleSource,
};
use self::trace_native::{
    ci_native_test_artifacts, convert_fozzy_trace_to_native, is_native_test_artifact_target,
    native_explore, render_trace_native_artifacts, replay_native_test_artifacts,
    resolve_replay_target, verify_native_test_artifacts,
};

#[cfg(test)]
use self::trace_native::{build_live_http_probe_steps, FOZZY_TRACE_FORMAT, FOZZY_TRACE_VERSION};

mod diagnostics_lint;
mod dispatch;
mod docs_format;
mod ffi_surface;
mod gpu_trace;
mod perf_doctor_dx;
mod project_artifacts;
mod rendering;
mod runtime_exec;
mod scenario_analysis;
mod scenario_runtime;
mod spec_surface;
mod trace_threads;

pub use self::dispatch::{run, run_with_metadata};
pub(crate) use self::project_artifacts::{
    resolve_diagnostic_explain, LSP_DIAGNOSTIC_DATA_SCHEMA_VERSION,
};

use self::diagnostics_lint::*;
use self::docs_format::*;
use self::ffi_surface::*;
use self::gpu_trace::*;
use self::perf_doctor_dx::*;
use self::project_artifacts::*;
use self::rendering::*;
use self::runtime_exec::*;
use self::scenario_analysis::*;
use self::scenario_runtime::*;
use self::spec_surface::*;
use self::trace_threads::*;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

#[derive(Debug, Clone)]
pub struct CommandFailure {
    pub exit_code: i32,
    pub output: String,
}

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub output: String,
    pub exit_code: Option<i32>,
}

impl fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "command failed with exit code {}", self.exit_code)
    }
}

impl StdError for CommandFailure {}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

#[derive(Debug, Clone)]
struct BuildInteropArtifacts {
    library: LibraryArtifact,
    headers: HeaderArtifact,
    artifact_manifest: PathBuf,
    export_symbols: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Init {
        path: PathBuf,
        package_name: Option<String>,
        template: Option<String>,
        with: Vec<String>,
        force: bool,
    },
    Build {
        path: PathBuf,
        release: bool,
        strict: bool,
        incremental: bool,
        lib: bool,
        threads: Option<u16>,
        backend: Option<String>,
        pgo_generate: bool,
        pgo_use: Option<PathBuf>,
        link_libs: Vec<String>,
        link_search: Vec<String>,
        frameworks: Vec<String>,
    },
    Run {
        path: PathBuf,
        args: Vec<String>,
        deterministic: bool,
        strict_verify: bool,
        safe_profile: bool,
        seed: Option<u64>,
        record: Option<PathBuf>,
        host_backends: bool,
        backend: Option<String>,
        max_seconds: Option<u64>,
        exit_on_healthcheck: Option<String>,
        smoke_http: Option<String>,
    },
    Test {
        path: PathBuf,
        deterministic: bool,
        strict_verify: bool,
        safe_profile: bool,
        seed: Option<u64>,
        record: Option<PathBuf>,
        host_backends: bool,
        backend: Option<String>,
        scheduler: Option<String>,
        rich_artifacts: bool,
        filter: Option<String>,
    },
    Fmt {
        targets: Vec<PathBuf>,
        check: bool,
    },
    Check {
        path: PathBuf,
    },
    Verify {
        path: PathBuf,
    },
    Lint {
        path: PathBuf,
        tier: String,
    },
    Explain {
        diag_code: String,
    },
    DoctorProject {
        path: PathBuf,
        strict: bool,
    },
    ScenarioDoctor {
        scenario: PathBuf,
        runs: Option<u64>,
        seed: Option<u64>,
        strict: bool,
        deep: bool,
        host_backends: bool,
    },
    DevLoop {
        path: PathBuf,
        backend: Option<String>,
    },
    DxCheck {
        path: PathBuf,
        strict: bool,
    },
    SpecCheck,
    EmitIr {
        path: PathBuf,
        backend: Option<String>,
    },
    Perf {
        artifact: Option<PathBuf>,
    },
    ArtifactsLsLatest,
    ReportShowLatest {
        output_format: String,
    },
    ReportQueryLatest {
        jq: Option<String>,
        list_paths: bool,
    },
    StabilityDashboard,
    Parity {
        path: PathBuf,
        seed: Option<u64>,
    },
    AuditUnsafe {
        path: PathBuf,
        workspace: bool,
    },
    AuditFfi {
        path: PathBuf,
    },
    AuditMemory {
        path: PathBuf,
    },
    Vendor {
        path: PathBuf,
    },
    AbiCheck {
        current: PathBuf,
        baseline: PathBuf,
    },
    DebugCheck {
        path: PathBuf,
    },
    PgoMerge {
        path: PathBuf,
        output: Option<PathBuf>,
    },
    LspDiagnostics {
        path: PathBuf,
    },
    LspDefinition {
        path: PathBuf,
        symbol: String,
    },
    LspHover {
        path: PathBuf,
        symbol: String,
    },
    LspRename {
        path: PathBuf,
        from: String,
        to: String,
    },
    LspSmoke {
        path: PathBuf,
    },
    LspServe {
        path: Option<PathBuf>,
    },
    Fuzz {
        target: PathBuf,
    },
    Explore {
        target: PathBuf,
    },
    MapSuites {
        root: PathBuf,
        scenario_root: PathBuf,
        profile: String,
        limit: usize,
        offset: usize,
        max_matched_scenarios: usize,
    },
    Usage,
    Env,
    Schema,
    Validate {
        scenario: PathBuf,
    },
    TraceVerify {
        trace: PathBuf,
        strict: bool,
    },
    Replay {
        trace: PathBuf,
    },
    Shrink {
        trace: PathBuf,
    },
    Ci {
        trace: PathBuf,
        strict: bool,
    },
    TraceNative {
        trace: PathBuf,
        output: Option<PathBuf>,
    },
    Headers {
        path: PathBuf,
        output: Option<PathBuf>,
    },
    RpcGen {
        path: PathBuf,
        out_dir: Option<PathBuf>,
    },
    DocGen {
        path: PathBuf,
        format: String,
        out: Option<PathBuf>,
        reference: Option<PathBuf>,
    },
    InspectSurface,
    InspectArtifacts {
        path: PathBuf,
        release: bool,
        backend: Option<String>,
    },
    InspectEmbedding {
        path: PathBuf,
    },
    InspectStdlib {
        module: String,
    },
    Version,
}
