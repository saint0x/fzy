use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use super::super::super::*;
use super::super::ffi_exports::NativeAsyncExport;
use super::render::render_native_runtime_shim;

pub(crate) fn ensure_native_runtime_shim(
    build_dir: &Path,
    string_literals: &[String],
    task_symbols: &[String],
    async_exports: &[NativeAsyncExport],
) -> Result<PathBuf> {
    let mut hasher = Sha256::new();
    for literal in string_literals {
        hasher.update(literal.as_bytes());
        hasher.update([0u8]);
    }
    for symbol in task_symbols {
        hasher.update(symbol.as_bytes());
        hasher.update([0u8]);
    }
    for export in async_exports {
        hasher.update(export.name.as_bytes());
        hasher.update([0u8]);
        hasher.update(export.mangled_symbol.as_bytes());
        hasher.update([0u8]);
        for (ty, name) in &export.params {
            hasher.update(ty.as_bytes());
            hasher.update([0u8]);
            hasher.update(name.as_bytes());
            hasher.update([0u8]);
        }
    }
    let digest = hasher.finalize();
    let tag = hex_encode(&digest[..8]);
    let runtime_shim_path = build_dir.join(format!("fz_native_runtime_{tag}.c"));
    std::fs::write(
        &runtime_shim_path,
        render_native_runtime_shim(string_literals, task_symbols, async_exports),
    )
    .with_context(|| {
        format!(
            "failed writing native runtime shim source: {}",
            runtime_shim_path.display()
        )
    })?;
    Ok(runtime_shim_path)
}

pub(crate) fn compile_runtime_shim_object(
    runtime_shim_path: &Path,
    out_object: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<()> {
    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("-x")
            .arg("c")
            .arg(runtime_shim_path)
            .arg("-c")
            .arg("-fPIC")
            .arg("-o")
            .arg(out_object);
        apply_target_link_flags(&mut cmd);
        apply_profile_optimization_flags(&mut cmd, profile, manifest);
        apply_pgo_flags(&mut cmd)?;
        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(()),
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
    Err(anyhow!(
        "failed to compile runtime shim object: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}
