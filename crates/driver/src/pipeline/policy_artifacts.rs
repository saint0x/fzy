use std::path::Path;

use anyhow::{Context, Result};

use super::*;

#[path = "policy_artifacts/compat.rs"]
mod compat;
#[path = "policy_artifacts/gpu.rs"]
mod gpu;
#[path = "policy_artifacts/lang.rs"]
mod lang;
#[path = "policy_artifacts/release.rs"]
mod release;
#[path = "policy_artifacts/stdlib.rs"]
mod stdlib;

pub(super) fn write_safety_artifacts(
    project_root: &Path,
    parsed: &ParsedProgram,
    typed: &hir::TypedModule,
    fir: &fir::FirModule,
    manifest: Option<&manifest::Manifest>,
) -> Result<()> {
    let out_dir = project_root.join(".fz");
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed creating safety artifact dir: {}", out_dir.display()))?;

    let memory_report = build_memory_report(fir);
    let memory_json = serde_json::to_value(&memory_report)?;
    write_artifact_if_changed(
        &out_dir.join("memory-report.json"),
        &serde_json::to_vec_pretty(&memory_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("memory-report.md"),
        render_memory_report_markdown(&memory_report).as_bytes(),
    )?;

    let unsafe_report = build_unsafe_report(fir);
    let unsafe_json = serde_json::to_value(&unsafe_report)?;
    write_artifact_if_changed(
        &out_dir.join("unsafe-report.json"),
        &serde_json::to_vec_pretty(&unsafe_json)?,
    )?;

    let async_json = build_async_safety_json(fir);
    write_artifact_if_changed(
        &out_dir.join("async-safety.json"),
        &serde_json::to_vec_pretty(&async_json)?,
    )?;

    let rpc_json = build_rpc_safety_json(&parsed.module, fir);
    write_artifact_if_changed(
        &out_dir.join("rpc-safety.json"),
        &serde_json::to_vec_pretty(&rpc_json)?,
    )?;

    let ffi_report = build_ffi_report(fir);
    let ffi_json = serde_json::to_value(&ffi_report)?;
    write_artifact_if_changed(
        &out_dir.join("ffi-report.json"),
        &serde_json::to_vec_pretty(&ffi_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("ffi-report.md"),
        render_ffi_report_markdown(&ffi_report).as_bytes(),
    )?;

    let runtime_contracts = build_native_runtime_contracts_report();
    let runtime_contracts_json = serde_json::to_value(&runtime_contracts)?;
    write_artifact_if_changed(
        &out_dir.join("native-runtime-contracts.json"),
        &serde_json::to_vec_pretty(&runtime_contracts_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("native-runtime-contracts.md"),
        render_native_runtime_contracts_markdown(&runtime_contracts).as_bytes(),
    )?;

    let handle_contracts_json = build_handle_contracts_json();
    write_artifact_if_changed(
        &out_dir.join("handle-contracts.json"),
        &serde_json::to_vec_pretty(&handle_contracts_json)?,
    )?;

    let gpu_kernel_package = gpu::build_gpu_kernel_package(typed);
    let gpu_kernel_package_json = gpu_kernel_package.to_json();
    std::fs::write(
        out_dir.join("gpu-kernel-package.json"),
        serde_json::to_vec_pretty(&gpu_kernel_package_json)?,
    )
    .with_context(|| {
        format!(
            "failed writing {}",
            out_dir.join("gpu-kernel-package.json").display()
        )
    })?;
    std::fs::write(
        out_dir.join("gpu-kernel-package.md"),
        gpu::render_gpu_kernel_package_markdown(&gpu_kernel_package),
    )
    .with_context(|| {
        format!(
            "failed writing {}",
            out_dir.join("gpu-kernel-package.md").display()
        )
    })?;

    let language_policy = lang::build_language_policy_report(manifest);
    let language_policy_json = serde_json::to_value(&language_policy)?;
    write_artifact_if_changed(
        &out_dir.join("language-policy.json"),
        &serde_json::to_vec_pretty(&language_policy_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("language-policy.md"),
        lang::render_language_policy_markdown(&language_policy).as_bytes(),
    )?;

    let release_policy = release::build_release_policy_report();
    let release_policy_json = serde_json::to_value(&release_policy)?;
    write_artifact_if_changed(
        &out_dir.join("release-policy.json"),
        &serde_json::to_vec_pretty(&release_policy_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("release-policy.md"),
        release::render_release_policy_markdown(&release_policy).as_bytes(),
    )?;

    let stdlib_policy = stdlib::build_stdlib_capability_policy_report();
    let stdlib_policy_json = serde_json::to_value(&stdlib_policy)?;
    write_artifact_if_changed(
        &out_dir.join("stdlib-capability-policy.json"),
        &serde_json::to_vec_pretty(&stdlib_policy_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("stdlib-capability-policy.md"),
        stdlib::render_stdlib_capability_policy_markdown(&stdlib_policy).as_bytes(),
    )?;

    Ok(())
}

fn write_artifact_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    if std::fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    std::fs::write(path, bytes).with_context(|| format!("failed writing {}", path.display()))
}
