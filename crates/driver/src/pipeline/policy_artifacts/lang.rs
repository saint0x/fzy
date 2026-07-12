use super::*;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(super) struct LanguagePolicyReport {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    versions: super::compat::CompatibilityVersions,
    language: LanguageSettings,
    #[serde(rename = "syntaxFreeze")]
    syntax_freeze: SyntaxFreeze,
    profiles: ProfileMap,
}

#[derive(Debug, Clone, Serialize)]
struct LanguageSettings {
    #[serde(rename = "defaultTier")]
    default_tier: String,
    #[serde(rename = "experimentalOptInRequired")]
    experimental_opt_in_required: bool,
    #[serde(rename = "allowExperimental")]
    allow_experimental: bool,
    #[serde(rename = "changePolicy")]
    change_policy: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct SyntaxFreeze {
    frozen: bool,
    surface: Vec<SyntaxFreezeEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct SyntaxFreezeEntry {
    name: &'static str,
    description: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct LanguageProfile {
    #[serde(rename = "checksEnabled")]
    checks_enabled: bool,
    #[serde(rename = "unsafeContractsEnforced")]
    unsafe_contracts_enforced: bool,
    backend: String,
    #[serde(rename = "runtimeImportsAllowed")]
    runtime_imports_allowed: &'static str,
    #[serde(rename = "capabilityPolicy")]
    capability_policy: &'static str,
    #[serde(rename = "emitSafetyArtifacts")]
    emit_safety_artifacts: bool,
    optimize: bool,
    #[serde(rename = "optimizationLevel")]
    optimization_level: &'static str,
    #[serde(rename = "diagnosticStrictness")]
    diagnostic_strictness: String,
    #[serde(rename = "experimentalFeaturesAllowed")]
    experimental_features_allowed: bool,
    #[serde(rename = "artifactEmission")]
    artifact_emission: Vec<&'static str>,
}

#[derive(Debug, Clone)]
struct NamedLanguageProfile {
    name: String,
    profile: LanguageProfile,
}

#[derive(Debug, Clone)]
struct ProfileMap(Vec<NamedLanguageProfile>);

impl Serialize for ProfileMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for entry in &self.0 {
            map.serialize_entry(&entry.name, &entry.profile)?;
        }
        map.end()
    }
}

pub(super) fn build_language_policy_report(
    manifest: Option<&manifest::Manifest>,
) -> LanguagePolicyReport {
    let experimental_allowed = manifest
        .map(|m| m.language.tier == "experimental" && m.language.allow_experimental)
        .unwrap_or(false);
    let profiles = [
        BuildProfile::Dev,
        BuildProfile::Verify,
        BuildProfile::Release,
        BuildProfile::Strict,
    ]
    .into_iter()
    .map(|profile| NamedLanguageProfile {
        name: profile.as_str().to_string(),
        profile: LanguageProfile {
            checks_enabled: super::compat::resolved_profile_checks(manifest, profile),
            unsafe_contracts_enforced: unsafe_contracts_enforced(manifest, profile),
            backend: super::compat::resolved_profile_backend(manifest, profile),
            runtime_imports_allowed: "declared_native_runtime_contracts_only",
            capability_policy: "explicit_compiler_checked",
            emit_safety_artifacts: super::compat::resolved_profile_emit_safety_artifacts(
                manifest, profile,
            ),
            optimize: super::compat::resolved_profile_optimize(manifest, profile),
            optimization_level: super::compat::default_profile_optimization_level(profile),
            diagnostic_strictness: super::compat::resolved_profile_diagnostic_strictness(
                manifest, profile,
            ),
            experimental_features_allowed: experimental_allowed,
            artifact_emission: super::compat::safety_artifact_names().to_vec(),
        },
    })
    .collect();

    LanguagePolicyReport {
        schema_version: "fozzylang.language_policy.v1",
        versions: super::compat::compatibility_versions(),
        language: LanguageSettings {
            default_tier: manifest
                .map(|m| m.language.tier.clone())
                .unwrap_or_else(|| "core_v1".to_string()),
            experimental_opt_in_required: true,
            allow_experimental: manifest
                .map(|m| m.language.allow_experimental)
                .unwrap_or(false),
            change_policy: "additive_only",
        },
        syntax_freeze: SyntaxFreeze {
            frozen: true,
            surface: super::compat::syntax_freeze_entries()
                .iter()
                .map(|(name, description)| SyntaxFreezeEntry { name, description })
                .collect(),
        },
        profiles: ProfileMap(profiles),
    }
}

pub(super) fn render_language_policy_markdown(report: &LanguagePolicyReport) -> String {
    let mut out = String::from("# Language Policy\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Language tier: `{}`\n- Experimental opt-in required: `{}`\n- Change policy: `{}`\n\n",
        report.schema_version,
        report.language.default_tier,
        report.language.experimental_opt_in_required,
        report.language.change_policy,
    ));
    out.push_str("## Syntax Freeze\n\n");
    for item in &report.syntax_freeze.surface {
        out.push_str(&format!("- `{}`: {}\n", item.name, item.description));
    }
    out.push_str("\n## Profiles\n\n");
    out.push_str("| Profile | Checks | Unsafe | Backend | Runtime Imports | Capabilities | Emit Safety Artifacts | Optimize | Optimization | Diagnostics |\n|---|---|---|---|---|---|---|---|---|---|\n");
    for entry in &report.profiles.0 {
        let profile = &entry.profile;
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |\n",
            entry.name,
            profile.checks_enabled,
            profile.unsafe_contracts_enforced,
            profile.backend,
            profile.runtime_imports_allowed,
            profile.capability_policy,
            profile.emit_safety_artifacts,
            profile.optimize,
            profile.optimization_level,
            profile.diagnostic_strictness,
        ));
    }
    out
}
