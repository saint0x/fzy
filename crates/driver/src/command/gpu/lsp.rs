use super::*;
use crate::lsp as ide;
pub(crate) fn lsp_diagnostics_command(path: &Path, format: Format) -> Result<String> {
    let payload = ide::diagnostics_for_path(path)?;
    let ok = payload
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let module = payload
        .get("module")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let diagnostics = payload
        .get("diagnostics")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    match format {
        Format::Text => {
            let parsed_items = diagnostics
                .iter()
                .filter_map(|value| {
                    serde_json::from_value::<diagnostics::Diagnostic>(value.clone()).ok()
                })
                .collect::<Vec<_>>();
            let details = render_diagnostics_text(&parsed_items);
            let mut rendered = render_text_fields(&[
                ("status", if ok { "ok" } else { "error" }.to_string()),
                ("mode", "lsp-diagnostics".to_string()),
                ("module", module.to_string()),
                ("diagnostics", diagnostics.len().to_string()),
            ]);
            if details.is_empty() {
                Ok(rendered)
            } else {
                rendered.push('\n');
                rendered.push_str(&details);
                Ok(rendered)
            }
        }
        Format::Json => Ok(payload.to_string()),
    }
}

pub(crate) fn lsp_definition_command(path: &Path, symbol: &str, format: Format) -> Result<String> {
    let hit = ide::definition_for_symbol(path, symbol)?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "lsp-definition".to_string()),
            ("symbol", symbol.to_string()),
            ("kind", hit.kind.clone()),
            ("file", hit.file.clone()),
            ("line", hit.line.to_string()),
            ("col", hit.col.to_string()),
            ("detail", hit.detail.clone()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "symbol": hit,
        })
        .to_string()),
    }
}

pub(crate) fn lsp_hover_command(path: &Path, symbol: &str, format: Format) -> Result<String> {
    let info = ide::hover_for_symbol(path, symbol)?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "lsp-hover".to_string()),
            ("symbol", symbol.to_string()),
            (
                "kind",
                info.get("kind")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            ),
            (
                "signature",
                info.get("signature")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            ),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "hover": info,
        })
        .to_string()),
    }
}

pub(crate) fn lsp_rename_command(
    path: &Path,
    from: &str,
    to: &str,
    format: Format,
) -> Result<String> {
    let summary = ide::rename_on_disk(path, from, to)?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "lsp-rename".to_string()),
            ("from", summary.from.clone()),
            ("to", summary.to.clone()),
            ("replacements", summary.replacements.to_string()),
            ("files", summary.files.len().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "from": summary.from,
            "to": summary.to,
            "replacements": summary.replacements,
            "files": summary.files,
        })
        .to_string()),
    }
}

pub(crate) fn lsp_smoke_command(path: &Path, format: Format) -> Result<String> {
    let payload = ide::smoke(path)?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "lsp-smoke".to_string()),
            (
                "symbols",
                payload
                    .get("symbols")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    .to_string(),
            ),
            (
                "diagnostics",
                payload
                    .get("diagnostics")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    .to_string(),
            ),
        ])),
        Format::Json => Ok(payload.to_string()),
    }
}
