use super::*;

pub(super) fn create_static_archive(output: &Path, objects: &[&Path]) -> Result<()> {
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

pub(super) fn link_shared_library(
    output: &Path,
    objects: &[&Path],
    fir: &fir::FirModule,
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
        apply_gpu_backend_link_args(&mut cmd, fir);
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

pub(super) fn shared_lib_extension() -> &'static str {
    if cfg!(target_vendor = "apple") {
        "dylib"
    } else if cfg!(target_os = "windows") {
        "dll"
    } else {
        "so"
    }
}
