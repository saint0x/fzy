use super::*;
pub(crate) fn abi_check_command(current: &Path, baseline: &Path, format: Format) -> Result<String> {
    ensure_exists(current)?;
    ensure_exists(baseline)?;
    let current_text = std::fs::read_to_string(current)
        .with_context(|| format!("failed reading current abi: {}", current.display()))?;
    let baseline_text = std::fs::read_to_string(baseline)
        .with_context(|| format!("failed reading baseline abi: {}", baseline.display()))?;
    let current_json: serde_json::Value = serde_json::from_str(&current_text)
        .with_context(|| format!("failed parsing current abi: {}", current.display()))?;
    let baseline_json: serde_json::Value = serde_json::from_str(&baseline_text)
        .with_context(|| format!("failed parsing baseline abi: {}", baseline.display()))?;
    let current_manifest = parse_abi_manifest(&current_json, current)?;
    let baseline_manifest = parse_abi_manifest(&baseline_json, baseline)?;
    let mut issues = Vec::new();
    if let (Some(current_package), Some(baseline_package)) = (
        current_manifest.package_name.as_deref(),
        baseline_manifest.package_name.as_deref(),
    ) {
        if current_package != baseline_package {
            issues.push(format!(
                "package mismatch: current={} baseline={}",
                current_package, baseline_package
            ));
        }
    }
    if let (Some(current_boundary), Some(baseline_boundary)) = (
        current_manifest.panic_boundary.as_deref(),
        baseline_manifest.panic_boundary.as_deref(),
    ) {
        if current_boundary != baseline_boundary {
            issues.push(format!(
                "panicBoundary mismatch: current={} baseline={}",
                current_boundary, baseline_boundary
            ));
        }
    }
    for (name, baseline_export) in &baseline_manifest.exports {
        let Some(current_export) = current_manifest.exports.get(name) else {
            issues.push(format!(
                "missing export in current ABI: {}",
                baseline_export.signature()
            ));
            continue;
        };
        if current_export.normalized_signature != baseline_export.normalized_signature {
            issues.push(format!(
                "signature changed for export `{}`: current={} baseline={}",
                name, current_export.normalized_signature, baseline_export.normalized_signature
            ));
        }
        if current_export.contract_signature != baseline_export.contract_signature {
            issues.push(format!(
                "contract weakened/changed for export `{}`: current={} baseline={}",
                name, current_export.contract_signature, baseline_export.contract_signature
            ));
        }
        if current_export.symbol_version < baseline_export.symbol_version {
            issues.push(format!(
                "symbolVersion regressed for `{}`: current={} baseline={}",
                name, current_export.symbol_version, baseline_export.symbol_version
            ));
        }
    }
    let mut added_exports = Vec::new();
    for (name, export) in &current_manifest.exports {
        if !baseline_manifest.exports.contains_key(name) {
            added_exports.push(export.signature());
        }
    }
    if !issues.is_empty() {
        bail!(
            "abi-check failed for {} vs {}: {}",
            current.display(),
            baseline.display(),
            issues.join("; ")
        );
    }
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "abi-check".to_string()),
            ("current", current.display().to_string()),
            ("baseline", baseline.display().to_string()),
            (
                "compared_exports",
                baseline_manifest.exports.len().to_string(),
            ),
            ("added_exports", added_exports.len().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "current": current.display().to_string(),
            "baseline": baseline.display().to_string(),
            "package": current_manifest.package_name,
            "panicBoundary": current_manifest.panic_boundary,
            "comparedExports": baseline_manifest.exports.keys().cloned().collect::<Vec<_>>(),
            "addedExports": added_exports,
            "issues": issues,
        })
        .to_string()),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AbiManifest {
    package_name: Option<String>,
    panic_boundary: Option<String>,
    exports: BTreeMap<String, AbiExport>,
}

#[derive(Debug, Clone)]
pub(crate) struct AbiExport {
    normalized_signature: String,
    contract_signature: String,
    symbol_version: u64,
}

impl AbiExport {
    fn signature(&self) -> String {
        self.normalized_signature.clone()
    }
}

pub(crate) fn parse_abi_manifest(value: &serde_json::Value, path: &Path) -> Result<AbiManifest> {
    let schema = value
        .get("schemaVersion")
        .and_then(|item| item.as_str())
        .ok_or_else(|| anyhow!("abi manifest missing schemaVersion: {}", path.display()))?;
    if schema != "fozzylang.ffi_abi.v1" {
        bail!(
            "unsupported abi schema `{}` in {}; expected fozzylang.ffi_abi.v1",
            schema,
            path.display()
        );
    }
    let package_name = match value.get("package") {
        Some(serde_json::Value::String(name)) => Some(name.clone()),
        Some(serde_json::Value::Object(obj)) => obj
            .get("name")
            .and_then(|item| item.as_str())
            .map(str::to_string),
        _ => None,
    };
    let panic_boundary = value
        .get("panicBoundary")
        .and_then(|item| item.as_str())
        .map(str::to_string);
    let mut exports = BTreeMap::new();
    let export_items = value
        .get("exports")
        .and_then(|item| item.as_array())
        .cloned()
        .unwrap_or_default();
    for export in export_items {
        let name = export
            .get("name")
            .and_then(|item| item.as_str())
            .unwrap_or("<unknown>")
            .to_string();
        let params = export
            .get("params")
            .and_then(|item| item.as_array())
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|param| {
                param
                    .get("c")
                    .and_then(|item| item.as_str())
                    .unwrap_or("void*")
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(",");
        let ret = export
            .get("return")
            .and_then(|item| item.get("c"))
            .and_then(|item| item.as_str())
            .unwrap_or("void*");
        let symbol_version = export
            .get("symbolVersion")
            .and_then(|item| item.as_u64())
            .unwrap_or(1);
        let export_mode = if export
            .get("async")
            .and_then(|item| item.as_bool())
            .unwrap_or(false)
        {
            "async"
        } else {
            "sync"
        };
        let param_contracts = export
            .get("params")
            .and_then(|item| item.as_array())
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|param| {
                serde_json::json!({
                    "name": param.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    "contract": param.get("contract").cloned().unwrap_or(serde_json::Value::Null),
                })
            })
            .collect::<Vec<_>>();
        let return_contract = export
            .get("return")
            .and_then(|item| item.get("contract"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let export_contract =
            normalize_abi_export_contract(export.get("contract"), export_mode == "async");
        let contract_signature = serde_json::to_string(&serde_json::json!({
            "params": param_contracts,
            "return": return_contract,
            "export": export_contract,
        }))
        .unwrap_or_else(|_| "{}".to_string());
        exports.insert(
            name.clone(),
            AbiExport {
                normalized_signature: format!("{name}:{export_mode}({params})->{ret}"),
                contract_signature,
                symbol_version,
            },
        );
    }
    Ok(AbiManifest {
        package_name,
        panic_boundary,
        exports,
    })
}

pub(crate) fn normalize_abi_export_contract(
    contract: Option<&serde_json::Value>,
    is_async: bool,
) -> serde_json::Value {
    let mut normalized = match contract {
        Some(serde_json::Value::Object(map)) => map.clone(),
        _ => serde_json::Map::new(),
    };
    normalized
        .entry("callbackBindings".to_string())
        .or_insert_with(|| serde_json::json!([]));
    normalized
        .entry("execution".to_string())
        .or_insert_with(|| {
            serde_json::Value::String(if is_async {
                "async-handle-v1".to_string()
            } else {
                "sync".to_string()
            })
        });
    normalized
        .entry("asyncBoundary".to_string())
        .or_insert(serde_json::Value::Null);
    serde_json::Value::Object(normalized)
}

