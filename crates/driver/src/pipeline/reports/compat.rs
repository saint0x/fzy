#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct CompatibilityVersions {
    #[serde(rename = "languageVersion")]
    pub(super) language_version: String,
    #[serde(rename = "traceSchemaVersion")]
    pub(super) trace_schema_version: String,
    #[serde(rename = "manifestSchemaVersion")]
    pub(super) manifest_schema_version: String,
    #[serde(rename = "runtimeAbiVersion")]
    pub(super) runtime_abi_version: String,
    #[serde(rename = "nativeImportTableVersion")]
    pub(super) native_import_table_version: String,
    #[serde(rename = "diagnosticCatalogVersion")]
    pub(super) diagnostic_catalog_version: String,
}

pub(crate) fn compatibility_versions() -> CompatibilityVersions {
    let compatibility = fzscenario::compatibility_info();
    CompatibilityVersions {
        language_version: compatibility.language_version,
        trace_schema_version: compatibility.trace_schema_version,
        manifest_schema_version: compatibility.manifest_schema_version,
        runtime_abi_version: compatibility.runtime_abi_version,
        native_import_table_version: compatibility.native_import_table_version,
        diagnostic_catalog_version: compatibility.diagnostic_catalog_version,
    }
}

pub(super) fn compatibility_versions_json() -> serde_json::Value {
    serde_json::to_value(compatibility_versions()).expect("compatibility versions should serialize")
}
