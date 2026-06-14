use super::*;

#[path = "native_emit/clif.rs"]
mod crane;
#[path = "native_emit/incr.rs"]
mod incr;
#[path = "native_emit/link.rs"]
mod link;
#[path = "native_emit/llvm.rs"]
mod ll;

pub(crate) fn emit_native_incremental_binary(
    fir: &fir::FirModule,
    parsed: &ParsedProgram,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
    module_plans: &[IncrementalModuleUnitPlan],
) -> Result<(PathBuf, IncrementalBuildReport)> {
    incr::emit_native_incremental_binary(
        fir,
        parsed,
        project_root,
        artifact_stem,
        profile,
        manifest,
        backend_override,
        module_plans,
    )
}

pub(crate) fn emit_native_incremental_libraries(
    fir: &fir::FirModule,
    parsed: &ParsedProgram,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
    module_plans: &[IncrementalModuleUnitPlan],
) -> Result<((Option<PathBuf>, Option<PathBuf>), IncrementalBuildReport)> {
    incr::emit_native_incremental_libraries(
        fir,
        parsed,
        project_root,
        artifact_stem,
        profile,
        manifest,
        backend_override,
        module_plans,
    )
}

pub(crate) fn resolve_native_backend(
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<String> {
    incr::resolve_native_backend(profile, backend_override)
}

pub(super) fn emit_native_artifact(
    fir: &fir::FirModule,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
) -> Result<PathBuf> {
    let backend = resolve_native_backend(profile, backend_override)?;
    match backend.as_str() {
        "llvm" => ll::emit_native_artifact_llvm(fir, project_root, artifact_stem, profile, manifest),
        "cranelift" => {
            crane::emit_native_artifact_cranelift(
                fir,
                project_root,
                artifact_stem,
                profile,
                manifest,
            )
        }
        other => Err(anyhow!(
            "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
            other
        )),
    }
}

pub(super) fn emit_native_libraries(
    fir: &fir::FirModule,
    project_root: &Path,
    artifact_stem: &str,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let backend = resolve_native_backend(profile, backend_override)?;
    match backend.as_str() {
        "llvm" => ll::emit_native_libraries_llvm(fir, project_root, artifact_stem, profile, manifest),
        "cranelift" => {
            crane::emit_native_libraries_cranelift(
                fir,
                project_root,
                artifact_stem,
                profile,
                manifest,
            )
        }
        other => Err(anyhow!(
            "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
            other
        )),
    }
}
