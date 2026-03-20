use super::*;

pub(super) fn apply_profile_optimization_flags(
    cmd: &mut Command,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) {
    let optimize_override = manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.optimize);
    match (profile, optimize_override) {
        (_, Some(true)) => {
            cmd.arg("-O3");
            cmd.arg("-fomit-frame-pointer");
            cmd.arg("-fno-semantic-interposition");
        }
        (_, Some(false)) => {
            cmd.arg("-O0");
        }
        (BuildProfile::Dev, None) => {
            cmd.arg("-O0");
        }
        (BuildProfile::Release, None) => {
            cmd.arg("-O3");
            cmd.arg("-fomit-frame-pointer");
            cmd.arg("-fno-semantic-interposition");
        }
        (BuildProfile::Verify, None) => {
            cmd.arg("-O1").arg("-g");
        }
    }
}

pub(super) fn apply_pgo_flags(cmd: &mut Command) -> Result<()> {
    let pgo = configured_pgo();
    if let Some(dir) = pgo.generate_dir {
        std::fs::create_dir_all(&dir).with_context(|| {
            format!(
                "failed creating PGO profile generation directory: {}",
                dir.display()
            )
        })?;
        cmd.arg(format!("-fprofile-generate={}", dir.display()));
    }
    if let Some(profile) = pgo.use_profile {
        if !profile.exists() {
            bail!("PGO profile data not found: {}", profile.display());
        }
        cmd.arg(format!("-fprofile-use={}", profile.display()));
        cmd.arg("-fprofile-correction");
    }
    Ok(())
}

pub(super) fn archiver_candidates() -> Vec<String> {
    if let Ok(explicit) = std::env::var("FZ_AR") {
        if !explicit.trim().is_empty() {
            return vec![explicit];
        }
    }
    vec!["ar".to_string()]
}

pub(super) fn linker_candidates() -> Vec<String> {
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

pub(super) fn apply_target_link_flags(cmd: &mut Command) {
    if let Ok(target) = std::env::var("TARGET") {
        let target = target.trim();
        if !target.is_empty() {
            cmd.arg("-target").arg(target);
        }
    }
}

pub(super) fn apply_manifest_link_args(cmd: &mut Command, manifest: Option<&manifest::Manifest>) {
    let Some(manifest) = manifest else {
        return;
    };
    for search in &manifest.link.search {
        let trimmed = search.trim();
        if !trimmed.is_empty() {
            cmd.arg(format!("-L{trimmed}"));
        }
    }
    for lib in &manifest.link.libs {
        let trimmed = lib.trim();
        if !trimmed.is_empty() {
            cmd.arg(format!("-l{trimmed}"));
        }
    }
    if cfg!(target_vendor = "apple") {
        for framework in &manifest.link.frameworks {
            let trimmed = framework.trim();
            if !trimmed.is_empty() {
                cmd.arg("-framework").arg(trimmed);
            }
        }
    }
}

pub(super) fn apply_extra_linker_args(cmd: &mut Command) {
    if let Ok(extra) = std::env::var("FZ_LINKER_ARGS") {
        for arg in extra.split_whitespace() {
            if !arg.trim().is_empty() {
                cmd.arg(arg);
            }
        }
    }
}

pub(super) fn profile_config(
    manifest: &manifest::Manifest,
    profile: BuildProfile,
) -> Option<&manifest::Profile> {
    match profile {
        BuildProfile::Dev => manifest.profiles.dev.as_ref(),
        BuildProfile::Release => manifest.profiles.release.as_ref(),
        BuildProfile::Verify => manifest.profiles.verify.as_ref(),
    }
}

pub(super) fn unsafe_contracts_enforced(
    manifest: Option<&manifest::Manifest>,
    profile: BuildProfile,
) -> bool {
    if let Some(manifest) = manifest {
        let unsafe_policy = &manifest.unsafe_policy;
        return match profile {
            BuildProfile::Dev => unsafe_policy.enforce_dev.unwrap_or(false),
            BuildProfile::Verify => unsafe_policy.enforce_verify.unwrap_or(true),
            BuildProfile::Release => unsafe_policy.enforce_release.unwrap_or(true),
        };
    }
    !matches!(profile, BuildProfile::Dev)
}

pub(super) fn unsafe_scope_policy(
    manifest: Option<&manifest::Manifest>,
) -> (Vec<String>, Vec<String>) {
    let Some(manifest) = manifest else {
        return (Vec::new(), Vec::new());
    };
    (
        manifest.unsafe_policy.deny_unsafe_in.clone(),
        manifest.unsafe_policy.allow_unsafe_in.clone(),
    )
}
