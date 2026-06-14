use super::*;

pub(super) fn compatibility_versions_json() -> serde_json::Value {
    let compatibility = fzscenario::compatibility_info();
    serde_json::json!({
        "languageVersion": compatibility.language_version,
        "traceSchemaVersion": compatibility.trace_schema_version,
        "manifestSchemaVersion": compatibility.manifest_schema_version,
        "runtimeAbiVersion": compatibility.runtime_abi_version,
        "nativeImportTableVersion": compatibility.native_import_table_version,
        "diagnosticCatalogVersion": compatibility.diagnostic_catalog_version,
    })
}

pub(super) fn syntax_freeze_entries() -> &'static [(&'static str, &'static str)] {
    &[
        ("fn", "function declarations"),
        ("let", "immutable bindings"),
        ("let mut", "mutable bindings"),
        ("struct", "struct declarations"),
        ("enum", "enum declarations"),
        ("match", "pattern matching"),
        ("trait", "trait declarations"),
        ("impl", "impl blocks"),
        ("async", "async declarations"),
        ("await", "async suspension"),
        ("rpc", "rpc declarations"),
        ("unsafe metadata", "compiler-generated unsafe contracts"),
        ("defer", "scope cleanup"),
        ("use core.*", "capability and stdlib imports"),
        ("extern", "external ABI imports"),
        ("pubext", "public ABI exports"),
    ]
}

pub(super) fn default_profile_backend(profile: BuildProfile) -> &'static str {
    match profile {
        BuildProfile::Dev => "cranelift",
        BuildProfile::Release | BuildProfile::Verify | BuildProfile::Strict => "llvm",
    }
}

pub(super) fn default_profile_optimize(profile: BuildProfile) -> bool {
    !matches!(profile, BuildProfile::Dev)
}

pub(super) fn default_profile_optimization_level(profile: BuildProfile) -> &'static str {
    match profile {
        BuildProfile::Dev => "O0",
        BuildProfile::Verify => "O1+g",
        BuildProfile::Strict => "O2+g",
        BuildProfile::Release => "O3",
    }
}

pub(super) fn default_profile_diagnostic_strictness(profile: BuildProfile) -> &'static str {
    if matches!(profile, BuildProfile::Strict) {
        "strict"
    } else {
        "standard"
    }
}

pub(super) fn resolved_profile_emit_safety_artifacts(
    manifest: Option<&manifest::Manifest>,
    profile: BuildProfile,
) -> bool {
    manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.emit_safety_artifacts)
        .unwrap_or(true)
}

pub(super) fn resolved_profile_checks(
    manifest: Option<&manifest::Manifest>,
    profile: BuildProfile,
) -> bool {
    manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.checks)
        .unwrap_or(true)
}

pub(super) fn resolved_profile_backend(
    manifest: Option<&manifest::Manifest>,
    profile: BuildProfile,
) -> String {
    manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.backend.clone())
        .unwrap_or_else(|| default_profile_backend(profile).to_string())
}

pub(super) fn resolved_profile_optimize(
    manifest: Option<&manifest::Manifest>,
    profile: BuildProfile,
) -> bool {
    manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.optimize)
        .unwrap_or_else(|| default_profile_optimize(profile))
}

pub(super) fn resolved_profile_diagnostic_strictness(
    manifest: Option<&manifest::Manifest>,
    profile: BuildProfile,
) -> String {
    manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.diagnostic_strictness.clone())
        .unwrap_or_else(|| default_profile_diagnostic_strictness(profile).to_string())
}

pub(super) fn safety_artifact_names() -> &'static [&'static str] {
    &[
        "memory-report.json",
        "memory-report.md",
        "unsafe-report.json",
        "async-safety.json",
        "rpc-safety.json",
        "ffi-report.json",
        "ffi-report.md",
        "native-runtime-contracts.json",
        "native-runtime-contracts.md",
        "handle-contracts.json",
        "gpu-kernel-package.json",
        "gpu-kernel-package.md",
        "language-policy.json",
        "language-policy.md",
        "release-policy.json",
        "release-policy.md",
        "stdlib-capability-policy.json",
        "stdlib-capability-policy.md",
    ]
}
