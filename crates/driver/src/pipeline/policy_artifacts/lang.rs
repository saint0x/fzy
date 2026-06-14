use super::*;

pub(super) fn build_language_policy_json(
    manifest: Option<&manifest::Manifest>,
) -> serde_json::Value {
    let profiles = [
        BuildProfile::Dev,
        BuildProfile::Verify,
        BuildProfile::Release,
        BuildProfile::Strict,
    ]
    .into_iter()
    .map(|profile| {
        let profile_name = profile.as_str();
        (
            profile_name.to_string(),
            serde_json::json!({
                "checksEnabled": super::compat::resolved_profile_checks(manifest, profile),
                "unsafeContractsEnforced": unsafe_contracts_enforced(manifest, profile),
                "backend": super::compat::resolved_profile_backend(manifest, profile),
                "runtimeImportsAllowed": "declared_native_runtime_contracts_only",
                "capabilityPolicy": "explicit_compiler_checked",
                "emitSafetyArtifacts": super::compat::resolved_profile_emit_safety_artifacts(manifest, profile),
                "optimize": super::compat::resolved_profile_optimize(manifest, profile),
                "optimizationLevel": super::compat::default_profile_optimization_level(profile),
                "diagnosticStrictness": super::compat::resolved_profile_diagnostic_strictness(manifest, profile),
                "experimentalFeaturesAllowed": manifest.map(|m| m.language.tier == "experimental" && m.language.allow_experimental).unwrap_or(false),
                "artifactEmission": super::compat::safety_artifact_names(),
            }),
        )
    })
    .collect::<serde_json::Map<String, serde_json::Value>>();
    serde_json::json!({
        "schemaVersion": "fozzylang.language_policy.v1",
        "versions": super::compat::compatibility_versions_json(),
        "language": {
            "defaultTier": manifest.map(|m| m.language.tier.as_str()).unwrap_or("core_v1"),
            "experimentalOptInRequired": true,
            "allowExperimental": manifest.map(|m| m.language.allow_experimental).unwrap_or(false),
            "changePolicy": "additive_only",
        },
        "syntaxFreeze": {
            "frozen": true,
            "surface": super::compat::syntax_freeze_entries().iter().map(|(name, description)| {
                serde_json::json!({
                    "name": name,
                    "description": description,
                })
            }).collect::<Vec<_>>(),
        },
        "profiles": profiles,
    })
}

pub(super) fn render_language_policy_markdown(value: &serde_json::Value) -> String {
    let mut out = String::from("# Language Policy\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Language tier: `{}`\n- Experimental opt-in required: `{}`\n- Change policy: `{}`\n\n",
        value["schemaVersion"].as_str().unwrap_or("unknown"),
        value["language"]["defaultTier"].as_str().unwrap_or("core_v1"),
        value["language"]["experimentalOptInRequired"].as_bool().unwrap_or(true),
        value["language"]["changePolicy"].as_str().unwrap_or("additive_only"),
    ));
    out.push_str("## Syntax Freeze\n\n");
    if let Some(items) = value["syntaxFreeze"]["surface"].as_array() {
        for item in items {
            out.push_str(&format!(
                "- `{}`: {}\n",
                item["name"].as_str().unwrap_or("?"),
                item["description"].as_str().unwrap_or("?")
            ));
        }
    }
    out.push_str("\n## Profiles\n\n");
    out.push_str("| Profile | Checks | Unsafe | Backend | Runtime Imports | Capabilities | Emit Safety Artifacts | Optimize | Optimization | Diagnostics |\n|---|---|---|---|---|---|---|---|---|---|\n");
    if let Some(profiles) = value["profiles"].as_object() {
        for (name, profile) in profiles {
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |\n",
                name,
                profile["checksEnabled"].as_bool().unwrap_or(true),
                profile["unsafeContractsEnforced"]
                    .as_bool()
                    .unwrap_or(false),
                profile["backend"].as_str().unwrap_or("?"),
                profile["runtimeImportsAllowed"].as_str().unwrap_or("?"),
                profile["capabilityPolicy"].as_str().unwrap_or("?"),
                profile["emitSafetyArtifacts"].as_bool().unwrap_or(true),
                profile["optimize"].as_bool().unwrap_or(false),
                profile["optimizationLevel"].as_str().unwrap_or("?"),
                profile["diagnosticStrictness"].as_str().unwrap_or("?"),
            ));
        }
    }
    out
}
