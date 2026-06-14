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
