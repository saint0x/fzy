use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use crate::pipeline::parse_program;

#[derive(Debug, Clone, Serialize)]
pub struct LspSymbol {
    pub symbol: String,
    pub kind: String,
    pub file: String,
    pub line: usize,
    pub col: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenameSummary {
    pub from: String,
    pub to: String,
    pub replacements: usize,
    pub files: Vec<String>,
}

#[derive(Debug, Clone)]
struct Document {
    path: PathBuf,
    version: i64,
    text: String,
}

#[derive(Debug, Clone)]
struct SymbolOccurrence {
    name: String,
    kind: String,
    line: usize,
    col: usize,
    len: usize,
    detail: String,
}

#[derive(Debug, Default)]
struct WorkspaceState {
    root: Option<PathBuf>,
    docs: BTreeMap<String, Document>,
    shutting_down: bool,
}

pub fn diagnostics_for_path(path: &Path) -> Result<Value> {
    let resolved = resolve_source(path)?;
    let source = std::fs::read_to_string(&resolved.source_path).with_context(|| {
        format!(
            "failed reading source for diagnostics: {}",
            resolved.source_path.display()
        )
    })?;
    let module_name = resolved
        .source_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("module");
    let mut diagnostics = Vec::new();
    match parser::parse(&source, module_name) {
        Err(parse_errors) => diagnostics.extend(parse_errors),
        Ok(module) => {
            let typed = hir::lower(&module);
            diagnostics.extend(type_diagnostics(&typed));
            let fir = fir::build_owned(typed);
            let verify = verifier::verify(&fir);
            diagnostics.extend(verify.diagnostics);
        }
    }
    hydrate_document_context(
        &mut diagnostics,
        &source,
        resolved.source_path.display().to_string(),
    );

    let ok = diagnostics
        .iter()
        .all(|diag| !matches!(diag.severity, diagnostics::Severity::Error));
    Ok(json!({
        "schemaVersion": diagnostics::DIAGNOSTICS_SCHEMA_VERSION,
        "ok": ok,
        "module": module_name,
        "diagnostics": diagnostics,
    }))
}

pub fn definition_for_symbol(path: &Path, symbol: &str) -> Result<LspSymbol> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let symbols = index_semantic_symbols_from_paths(&parsed.module_paths)?;
    symbols
        .into_iter()
        .find(|entry| entry.symbol == symbol)
        .ok_or_else(|| anyhow!("symbol `{symbol}` not found"))
}

pub fn hover_for_symbol(path: &Path, symbol: &str) -> Result<Value> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let info = parsed.module.items.iter().find_map(|item| match item {
        ast::Item::Function(function) if function.name == symbol => Some(json!({
            "symbol": symbol,
            "kind": "function",
            "signature": format!(
                "fn {}({}) -> {}",
                function.name,
                function
                    .params
                    .iter()
                    .map(|param| format!("{}: {}", param.name, param.ty))
                    .collect::<Vec<_>>()
                    .join(", "),
                function.return_type
            ),
        })),
        ast::Item::Struct(s) if s.name == symbol => Some(json!({
            "symbol": symbol,
            "kind": "struct",
            "signature": format!("struct {}", s.name),
        })),
        ast::Item::Enum(e) if e.name == symbol => Some(json!({
            "symbol": symbol,
            "kind": "enum",
            "signature": format!("enum {}", e.name),
        })),
        ast::Item::Trait(t) if t.name == symbol => Some(json!({
            "symbol": symbol,
            "kind": "trait",
            "signature": format!("trait {}", t.name),
        })),
        ast::Item::Test(test) if test.name == symbol => Some(json!({
            "symbol": symbol,
            "kind": "test",
            "signature": format!("test \"{}\" {}", test.name, if test.deterministic { "{}" } else { "nondet {}" }),
        })),
        _ => None,
    });

    info.ok_or_else(|| anyhow!("symbol `{symbol}` not found"))
}

pub fn rename_on_disk(path: &Path, from: &str, to: &str) -> Result<RenameSummary> {
    if from.trim().is_empty() || to.trim().is_empty() {
        bail!("rename requires non-empty symbols");
    }
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let symbols = index_semantic_symbols_from_paths(&parsed.module_paths)?;
    let is_declared = symbols.iter().any(|entry| entry.symbol == from);
    if !is_declared {
        bail!("rename target `{from}` is not a declared semantic symbol");
    }
    let mut changed_files = Vec::new();
    let mut replacements = 0usize;

    for module_path in &parsed.module_paths {
        let original = std::fs::read_to_string(module_path).with_context(|| {
            format!(
                "failed reading module for rename: {}",
                module_path.display()
            )
        })?;
        let (updated, count) = replace_symbol_identifier_tokens(&original, from, to);
        if count > 0 {
            std::fs::write(module_path, updated.as_bytes()).with_context(|| {
                format!("failed writing renamed module: {}", module_path.display())
            })?;
            replacements += count;
            changed_files.push(module_path.display().to_string());
        }
    }

    Ok(RenameSummary {
        from: from.to_string(),
        to: to.to_string(),
        replacements,
        files: changed_files,
    })
}

pub fn smoke(path: &Path) -> Result<Value> {
    let diagnostics = diagnostics_for_path(path)?;
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let symbols = index_symbols_from_paths(&parsed.module_paths)?;
    let has_main = symbols.iter().any(|entry| entry.symbol == "main");
    if !has_main {
        bail!("lsp smoke failed: no `main` definition found");
    }
    Ok(json!({
        "ok": true,
        "symbols": symbols.len(),
        "diagnostics": diagnostics
            .get("diagnostics")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        "features": [
            "diagnostics",
            "definition",
            "hover",
            "completion",
            "references",
            "rename",
            "semanticTokens"
        ]
    }))
}

pub fn serve_stdio(root_hint: Option<&Path>) -> Result<()> {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();

    let mut ws = WorkspaceState {
        root: root_hint.map(Path::to_path_buf),
        ..WorkspaceState::default()
    };

    while let Some(msg) = read_lsp_message(&mut reader)? {
        handle_lsp_message(&mut ws, &msg, &mut writer)?;
        if msg.get("method").and_then(Value::as_str) == Some("exit") {
            break;
        }
    }

    Ok(())
}

fn handle_lsp_message(ws: &mut WorkspaceState, msg: &Value, writer: &mut dyn Write) -> Result<()> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str);
    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));

    let Some(method) = method else {
        return Ok(());
    };

    if ws.shutting_down && method != "exit" {
        if let Some(id) = id {
            write_lsp_message(
                writer,
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32600,
                        "message": "server is shutting down"
                    }
                }),
            )?;
        }
        return Ok(());
    }

    match method {
        "initialize" => {
            if let Some(root_uri) = params.get("rootUri").and_then(Value::as_str) {
                ws.root = uri_to_path(root_uri);
            }
            if let Some(id) = id {
                write_lsp_message(
                    writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "capabilities": {
                                "textDocumentSync": {
                                    "openClose": true,
                                    "change": 2,
                                    "save": true
                                },
                                "hoverProvider": true,
                                "definitionProvider": true,
                                "referencesProvider": true,
                                "renameProvider": true,
                                "completionProvider": {
                                    "triggerCharacters": ["."]
                                },
                                "semanticTokensProvider": {
                                    "legend": {
                                        "tokenTypes": ["keyword", "function", "struct", "enum", "type", "variable", "string", "number", "comment", "operator"],
                                        "tokenModifiers": []
                                    },
                                    "full": true
                                }
                            },
                            "serverInfo": {
                                "name": "fozzy-lsp",
                                "version": "1.0.0"
                            }
                        }
                    }),
                )?;
            }
        }
        "initialized" => {}
        "shutdown" => {
            ws.shutting_down = true;
            if let Some(id) = id {
                write_lsp_message(writer, &json!({"jsonrpc": "2.0", "id": id, "result": null}))?;
            }
        }
        "exit" => {}
        "textDocument/didOpen" => {
            let text_doc = params
                .get("textDocument")
                .ok_or_else(|| anyhow!("didOpen missing textDocument"))?;
            let uri = text_doc
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("didOpen missing uri"))?;
            let text = text_doc
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let version = text_doc.get("version").and_then(Value::as_i64).unwrap_or(0);
            if let Some(path) = uri_to_path(uri) {
                ws.docs.insert(
                    uri.to_string(),
                    Document {
                        path,
                        version,
                        text: text.to_string(),
                    },
                );
                publish_diagnostics(ws, uri, writer)?;
            }
        }
        "textDocument/didChange" => {
            let text_doc = params
                .get("textDocument")
                .ok_or_else(|| anyhow!("didChange missing textDocument"))?;
            let uri = text_doc
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("didChange missing uri"))?;
            let version = text_doc.get("version").and_then(Value::as_i64).unwrap_or(0);
            let Some(doc) = ws.docs.get_mut(uri) else {
                return Ok(());
            };
            let changes = params
                .get("contentChanges")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            apply_incremental_changes(&mut doc.text, &changes)?;
            doc.version = version;
            publish_diagnostics(ws, uri, writer)?;
        }
        "textDocument/didClose" => {
            if let Some(uri) = params
                .get("textDocument")
                .and_then(|td| td.get("uri"))
                .and_then(Value::as_str)
            {
                ws.docs.remove(uri);
            }
        }
        "textDocument/hover" => {
            if let Some(id) = id {
                let result = lsp_hover_at_position(ws, &params)?;
                write_lsp_message(
                    writer,
                    &json!({"jsonrpc": "2.0", "id": id, "result": result}),
                )?;
            }
        }
        "textDocument/definition" => {
            if let Some(id) = id {
                let result = lsp_definition_at_position(ws, &params)?;
                write_lsp_message(
                    writer,
                    &json!({"jsonrpc": "2.0", "id": id, "result": result}),
                )?;
            }
        }
        "textDocument/completion" => {
            if let Some(id) = id {
                let result = lsp_completion(ws, &params)?;
                write_lsp_message(
                    writer,
                    &json!({"jsonrpc": "2.0", "id": id, "result": result}),
                )?;
            }
        }
        "textDocument/references" => {
            if let Some(id) = id {
                let result = lsp_references(ws, &params)?;
                write_lsp_message(
                    writer,
                    &json!({"jsonrpc": "2.0", "id": id, "result": result}),
                )?;
            }
        }
        "textDocument/rename" => {
            if let Some(id) = id {
                let result = lsp_rename(ws, &params)?;
                write_lsp_message(
                    writer,
                    &json!({"jsonrpc": "2.0", "id": id, "result": result}),
                )?;
            }
        }
        "textDocument/semanticTokens/full" => {
            if let Some(id) = id {
                let result = lsp_semantic_tokens(ws, &params)?;
                write_lsp_message(
                    writer,
                    &json!({"jsonrpc": "2.0", "id": id, "result": result}),
                )?;
            }
        }
        _ => {
            if let Some(id) = id {
                write_lsp_message(
                    writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32601,
                            "message": format!("unsupported method: {method}")
                        }
                    }),
                )?;
            }
        }
    }

    Ok(())
}

fn lsp_hover_at_position(ws: &WorkspaceState, params: &Value) -> Result<Value> {
    let (uri, line, character) = request_position(params)?;
    let doc = workspace_doc(ws, &uri)?;
    let token = identifier_at_position(&doc.text, line, character);
    let Some(symbol) = token else {
        return Ok(Value::Null);
    };
    let occurrences = collect_symbol_occurrences(&doc.text, &doc.path);
    let hover = occurrences
        .iter()
        .find(|occ| {
            occ.name == symbol
                && matches!(
                    occ.kind.as_str(),
                    "function" | "struct" | "enum" | "trait" | "rpc"
                )
        })
        .map(|occ| {
            json!({
                "contents": {
                    "kind": "markdown",
                    "value": format!("```fzy\n{}\n```", occ.detail)
                },
                "range": symbol_range(line, occ.col, occ.len)
            })
        });
    Ok(hover.unwrap_or(Value::Null))
}

fn lsp_definition_at_position(ws: &WorkspaceState, params: &Value) -> Result<Value> {
    let (uri, line, character) = request_position(params)?;
    let doc = workspace_doc(ws, &uri)?;
    let Some(symbol) = identifier_at_position(&doc.text, line, character) else {
        return Ok(json!([]));
    };

    let docs = all_workspace_docs(ws)?;
    let paths = docs.into_iter().map(|doc| doc.path).collect::<Vec<_>>();
    let mut locations = Vec::new();
    for decl in index_semantic_symbols_from_paths(&paths)? {
        if decl.symbol == symbol
            && matches!(
                decl.kind.as_str(),
                "function" | "struct" | "enum" | "trait" | "test"
            )
        {
            locations.push(json!({
                "uri": path_to_uri(Path::new(&decl.file)),
                "range": symbol_range(
                    decl.line.saturating_sub(1),
                    decl.col.saturating_sub(1),
                    decl.symbol.len(),
                ),
            }));
        }
    }
    Ok(json!(locations))
}

fn lsp_completion(ws: &WorkspaceState, params: &Value) -> Result<Value> {
    let uri = params
        .get("textDocument")
        .and_then(|td| td.get("uri"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("completion missing uri"))?;
    let _doc = workspace_doc(ws, uri)?;

    let mut seen = BTreeSet::new();
    let mut items = Vec::new();

    let keywords = [
        "fn", "struct", "enum", "trait", "impl", "test", "async", "return", "if", "else", "while",
        "match", "let", "requires", "ensures", "defer", "mod", "use", "rpc",
    ];
    for kw in keywords {
        seen.insert(kw.to_string());
        items.push(json!({"label": kw, "kind": 14}));
    }

    for doc in all_workspace_docs(ws)? {
        for occ in collect_symbol_occurrences(&doc.text, &doc.path) {
            if seen.insert(occ.name.clone()) {
                items.push(json!({
                    "label": occ.name,
                    "kind": completion_kind(&occ.kind),
                    "detail": occ.detail,
                }));
            }
        }
    }

    Ok(json!({"isIncomplete": false, "items": items}))
}

fn lsp_references(ws: &WorkspaceState, params: &Value) -> Result<Value> {
    let (uri, line, character) = request_position(params)?;
    let doc = workspace_doc(ws, &uri)?;
    let Some(symbol) = identifier_at_position(&doc.text, line, character) else {
        return Ok(json!([]));
    };
    let refs = collect_references(ws, &symbol)?;
    Ok(json!(refs))
}

fn lsp_rename(ws: &WorkspaceState, params: &Value) -> Result<Value> {
    let (uri, line, character) = request_position(params)?;
    let new_name = params
        .get("newName")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("rename missing newName"))?;
    let doc = workspace_doc(ws, &uri)?;
    let Some(symbol) = identifier_at_position(&doc.text, line, character) else {
        return Ok(Value::Null);
    };

    let mut changes = BTreeMap::<String, Vec<Value>>::new();
    for doc in all_workspace_docs(ws)? {
        let refs = symbol_spans_identifier_tokens(&doc.text, &symbol);
        if refs.is_empty() {
            continue;
        }
        changes.insert(
            path_to_uri(&doc.path),
            refs.into_iter()
                .map(|(line, col, len)| {
                    json!({
                        "range": symbol_range(line, col, len),
                        "newText": new_name,
                    })
                })
                .collect::<Vec<_>>(),
        );
    }
    Ok(json!({"changes": changes}))
}

fn lsp_semantic_tokens(ws: &WorkspaceState, params: &Value) -> Result<Value> {
    let uri = params
        .get("textDocument")
        .and_then(|td| td.get("uri"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("semanticTokens missing uri"))?;
    let doc = workspace_doc(ws, uri)?;
    let mut tokens = collect_semantic_tokens(&doc.text);
    tokens.sort_by_key(|token| (token.0, token.1));

    let mut data = Vec::<u32>::new();
    let mut prev_line = 0usize;
    let mut prev_col = 0usize;

    for (line, col, len, token_type) in tokens {
        let delta_line = line.saturating_sub(prev_line);
        let delta_start = if delta_line == 0 {
            col.saturating_sub(prev_col)
        } else {
            col
        };
        data.push(delta_line as u32);
        data.push(delta_start as u32);
        data.push(len as u32);
        data.push(token_type as u32);
        data.push(0);
        prev_line = line;
        prev_col = col;
    }

    Ok(json!({"data": data}))
}

fn publish_diagnostics(ws: &WorkspaceState, uri: &str, writer: &mut dyn Write) -> Result<()> {
    let doc = workspace_doc(ws, uri)?;
    let module_name = doc
        .path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("module");

    let mut diagnostics = Vec::new();
    if let Err(parse_errors) = parser::parse(&doc.text, module_name) {
        diagnostics.extend(parse_errors);
    } else if let Ok(parsed) = parse_program(&doc.path) {
        let typed = hir::lower(&parsed.module);
        diagnostics.extend(type_diagnostics(&typed));
        let fir = fir::build_owned(typed);
        diagnostics.extend(verifier::verify(&fir).diagnostics);
    }
    hydrate_document_context(&mut diagnostics, &doc.text, doc.path.display().to_string());

    let payload = diagnostics
        .iter()
        .map(to_lsp_diagnostic)
        .collect::<Vec<_>>();
    write_lsp_message(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {
                "uri": uri,
                "diagnostics": payload,
            }
        }),
    )
}

fn collect_references(ws: &WorkspaceState, symbol: &str) -> Result<Vec<Value>> {
    let mut refs = Vec::new();
    for doc in all_workspace_docs(ws)? {
        for (line, col, len) in symbol_spans_identifier_tokens(&doc.text, symbol) {
            refs.push(json!({
                "uri": path_to_uri(&doc.path),
                "range": symbol_range(line, col, len),
            }));
        }
    }
    Ok(refs)
}

fn index_semantic_symbols_from_paths(paths: &[PathBuf]) -> Result<Vec<LspSymbol>> {
    let mut symbols = Vec::new();
    for module_path in paths {
        let source = std::fs::read_to_string(module_path).with_context(|| {
            format!(
                "failed reading module for semantic lsp index: {}",
                module_path.display()
            )
        })?;
        let module_name = module_path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("module");
        let module = parser::parse(&source, module_name).map_err(|_| {
            anyhow!(
                "failed parsing module for semantic lsp index: {}",
                module_path.display()
            )
        })?;
        for (kind, name, detail) in semantic_decl_symbols(&module) {
            let (line, col) = find_decl_position(&source, &kind, &name).unwrap_or((0, 0));
            symbols.push(LspSymbol {
                symbol: name,
                kind,
                file: module_path.display().to_string(),
                line: line + 1,
                col: col + 1,
                detail,
            });
        }
    }
    Ok(symbols)
}

fn semantic_decl_symbols(module: &ast::Module) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for item in &module.items {
        match item {
            ast::Item::Function(function) => out.push((
                "function".to_string(),
                function.name.clone(),
                format!(
                    "fn {}({}) -> {}",
                    function.name,
                    function
                        .params
                        .iter()
                        .map(|param| format!("{}: {}", param.name, param.ty))
                        .collect::<Vec<_>>()
                        .join(", "),
                    function.return_type
                ),
            )),
            ast::Item::Struct(item) => out.push((
                "struct".to_string(),
                item.name.clone(),
                format!("struct {}", item.name),
            )),
            ast::Item::Enum(item) => out.push((
                "enum".to_string(),
                item.name.clone(),
                format!("enum {}", item.name),
            )),
            ast::Item::Trait(item) => out.push((
                "trait".to_string(),
                item.name.clone(),
                format!("trait {}", item.name),
            )),
            ast::Item::Test(item) => out.push((
                "test".to_string(),
                item.name.clone(),
                format!("test \"{}\"", item.name),
            )),
            ast::Item::Impl(_) => {}
        }
    }
    out
}

fn find_decl_position(source: &str, kind: &str, symbol: &str) -> Option<(usize, usize)> {
    for (line_idx, raw_line) in source.lines().enumerate() {
        if let Some((found_kind, found_name, col)) = parse_decl_symbol(raw_line) {
            if found_kind == kind && found_name == symbol {
                return Some((line_idx, col));
            }
        }
    }
    None
}

fn index_symbols_from_paths(paths: &[PathBuf]) -> Result<Vec<LspSymbol>> {
    let mut symbols = Vec::new();
    for module_path in paths {
        let source = std::fs::read_to_string(module_path).with_context(|| {
            format!(
                "failed reading module for lsp index: {}",
                module_path.display()
            )
        })?;
        for occ in collect_symbol_occurrences(&source, module_path) {
            if matches!(
                occ.kind.as_str(),
                "function" | "struct" | "enum" | "trait" | "test" | "rpc"
            ) {
                symbols.push(LspSymbol {
                    symbol: occ.name,
                    kind: occ.kind,
                    file: module_path.display().to_string(),
                    line: occ.line + 1,
                    col: occ.col + 1,
                    detail: occ.detail,
                });
            }
        }
    }
    Ok(symbols)
}

fn collect_symbol_occurrences(source: &str, path: &Path) -> Vec<SymbolOccurrence> {
    let mut out = Vec::new();
    for (line_number, raw_line) in source.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        if let Some((kind, name, col)) = parse_decl_symbol(raw_line) {
            out.push(SymbolOccurrence {
                name,
                kind,
                line: line_number,
                col,
                len: symbol_len(raw_line, col),
                detail: line.to_string(),
            });
        }

        if line.starts_with("let ") {
            if let Some((name, col)) = parse_let_symbol(raw_line) {
                out.push(SymbolOccurrence {
                    name,
                    kind: "variable".to_string(),
                    line: line_number,
                    col,
                    len: symbol_len(raw_line, col),
                    detail: line.to_string(),
                });
            }
        }
    }

    if out.is_empty() {
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("module")
            .to_string();
        out.push(SymbolOccurrence {
            name: stem,
            kind: "module".to_string(),
            line: 0,
            col: 0,
            len: 1,
            detail: "module".to_string(),
        });
    }

    out
}

fn parse_decl_symbol(raw_line: &str) -> Option<(String, String, usize)> {
    let prefixes = [
        ("pub extern \"C\" fn ", "function"),
        ("pub fn ", "function"),
        ("fn ", "function"),
        ("struct ", "struct"),
        ("enum ", "enum"),
        ("trait ", "trait"),
        ("rpc ", "rpc"),
    ];

    for (prefix, kind) in prefixes {
        if let Some(start) = raw_line.find(prefix) {
            let name_start = start + prefix.len();
            let suffix = &raw_line[name_start..];
            let name = suffix
                .split(|ch: char| ch == '(' || ch == '{' || ch == '<' || ch.is_whitespace())
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())?;
            return Some((kind.to_string(), name.to_string(), name_start));
        }
    }

    if raw_line.contains("test \"") {
        let prefix_start = raw_line.find("test \"")?;
        let start = prefix_start + "test \"".len();
        let tail = &raw_line[start..];
        let end = tail.find('"')?;
        return Some(("test".to_string(), tail[..end].to_string(), start));
    }

    None
}

fn parse_let_symbol(raw_line: &str) -> Option<(String, usize)> {
    let start = raw_line.find("let ")? + 4;
    let tail = &raw_line[start..];
    let name = tail
        .split(|ch: char| ch == ':' || ch == '=' || ch.is_whitespace())
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some((name.to_string(), start))
}

fn symbol_spans_identifier_tokens(source: &str, symbol: &str) -> Vec<(usize, usize, usize)> {
    let mut spans = Vec::new();
    if symbol.is_empty() {
        return spans;
    }
    for (line_idx, line) in source.lines().enumerate() {
        let bytes = line.as_bytes();
        let mut i = 0usize;
        let mut in_string = false;
        while i < bytes.len() {
            let byte = bytes[i];
            if in_string {
                if byte == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if byte == b'"' {
                    in_string = false;
                }
                i += 1;
                continue;
            }
            if byte == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                break;
            }
            if byte == b'"' {
                in_string = true;
                i += 1;
                continue;
            }
            if is_ident_byte(byte) {
                let start = i;
                let mut end = i + 1;
                while end < bytes.len() && is_ident_byte(bytes[end]) {
                    end += 1;
                }
                if &line[start..end] == symbol {
                    spans.push((line_idx, start, symbol.len()));
                }
                i = end;
                continue;
            }
            i += 1;
        }
    }
    spans
}

fn replace_symbol_identifier_tokens(source: &str, from: &str, to: &str) -> (String, usize) {
    if from == to || from.is_empty() {
        return (source.to_string(), 0);
    }

    let mut out = String::with_capacity(source.len());
    let mut replacements = 0usize;
    let bytes = source.as_bytes();
    let mut i = 0usize;
    let mut in_string = false;
    let mut in_comment = false;

    while i < bytes.len() {
        let byte = bytes[i];
        if in_comment {
            out.push(byte as char);
            if byte == b'\n' {
                in_comment = false;
            }
            i += 1;
            continue;
        }
        if in_string {
            out.push(byte as char);
            if byte == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if byte == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if byte == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            out.push('/');
            out.push('/');
            in_comment = true;
            i += 2;
            continue;
        }
        if byte == b'"' {
            out.push('"');
            in_string = true;
            i += 1;
            continue;
        }
        if is_ident_byte(byte) {
            let start = i;
            let mut end = i + 1;
            while end < bytes.len() && is_ident_byte(bytes[end]) {
                end += 1;
            }
            let token = &source[start..end];
            if token == from {
                out.push_str(to);
                replacements += 1;
            } else {
                out.push_str(token);
            }
            i = end;
            continue;
        }

        out.push(byte as char);
        i += 1;
    }

    (out, replacements)
}

fn symbol_range(line: usize, col: usize, len: usize) -> Value {
    json!({
        "start": {"line": line, "character": col},
        "end": {"line": line, "character": col + len},
    })
}

fn identifier_at_position(source: &str, line: usize, character: usize) -> Option<String> {
    let row = source.lines().nth(line)?;
    if row.is_empty() {
        return None;
    }

    let mut pos = character.min(row.len());
    if pos == row.len() {
        pos = pos.saturating_sub(1);
    }

    let bytes = row.as_bytes();
    if !is_ident_byte(*bytes.get(pos)?) {
        if pos > 0 && is_ident_byte(*bytes.get(pos - 1)?) {
            pos -= 1;
        } else {
            return None;
        }
    }

    let mut start = pos;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = pos;
    while end + 1 < bytes.len() && is_ident_byte(bytes[end + 1]) {
        end += 1;
    }
    Some(row[start..=end].to_string())
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.'
}

fn symbol_len(line: &str, start: usize) -> usize {
    line[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '.')
        .count()
        .max(1)
}

fn completion_kind(kind: &str) -> usize {
    match kind {
        "function" | "rpc" => 3,
        "struct" | "enum" | "trait" => 7,
        "variable" => 6,
        _ => 1,
    }
}

fn collect_semantic_tokens(source: &str) -> Vec<(usize, usize, usize, usize)> {
    let mut out = Vec::new();
    for (line, raw) in source.lines().enumerate() {
        let trimmed = raw.trim_start();
        let leading = raw.len() - trimmed.len();

        if trimmed.starts_with("//") {
            out.push((line, leading, trimmed.len(), 8));
            continue;
        }

        if let Some(pos) = raw.find("fn ") {
            out.push((line, pos, 2, 0));
            if let Some((_, name, col)) = parse_decl_symbol(raw) {
                out.push((line, col, name.len(), 1));
            }
        }
        if let Some(pos) = raw.find("struct ") {
            out.push((line, pos, 6, 0));
            if let Some((_, name, col)) = parse_decl_symbol(raw) {
                out.push((line, col, name.len(), 2));
            }
        }
        if let Some(pos) = raw.find("enum ") {
            out.push((line, pos, 4, 0));
            if let Some((_, name, col)) = parse_decl_symbol(raw) {
                out.push((line, col, name.len(), 3));
            }
        }
        if let Some(pos) = raw.find("let ") {
            out.push((line, pos, 3, 0));
            if let Some((name, col)) = parse_let_symbol(raw) {
                out.push((line, col, name.len(), 5));
            }
        }

        let mut cursor = 0usize;
        while let Some(idx) = raw[cursor..].find('"') {
            let start = cursor + idx;
            let Some(rel_end) = raw[start + 1..].find('"') else {
                break;
            };
            let end = start + rel_end + 2;
            out.push((line, start, end - start, 6));
            cursor = end;
        }

        for (idx, token) in raw.split_whitespace().enumerate() {
            if token.chars().all(|ch| ch.is_ascii_digit()) {
                let mut search_from = 0usize;
                for _ in 0..=idx {
                    let hit = raw[search_from..].find(token).unwrap_or(0);
                    search_from += hit;
                }
                out.push((line, search_from, token.len(), 7));
            }
        }
    }
    out
}

fn to_lsp_diagnostic(diag: &diagnostics::Diagnostic) -> Value {
    let (start_line, start_col, end_line, end_col) = if let Some(span) = &diag.span {
        (
            span.start_line.saturating_sub(1),
            span.start_col.saturating_sub(1),
            span.end_line.saturating_sub(1),
            span.end_col.saturating_sub(1),
        )
    } else {
        (0, 0, 0, 1)
    };
    let related_information = diag
        .labels
        .iter()
        .filter_map(|label| {
            let span = label.span.as_ref()?;
            let path = diag.path.as_ref()?;
            Some(json!({
                "location": {
                    "uri": path_to_uri(Path::new(path)),
                    "range": {
                        "start": {
                            "line": span.start_line.saturating_sub(1),
                            "character": span.start_col.saturating_sub(1),
                        },
                        "end": {
                            "line": span.end_line.saturating_sub(1),
                            "character": span.end_col.saturating_sub(1),
                        }
                    }
                },
                "message": label.message
            }))
        })
        .collect::<Vec<_>>();
    let mut message = diag.message.clone();
    if let Some(help) = &diag.help {
        message.push_str("\nhelp: ");
        message.push_str(help);
    }
    json!({
        "range": {
            "start": {"line": start_line, "character": start_col},
            "end": {"line": end_line, "character": end_col},
        },
        "severity": severity_to_lsp(&diag.severity),
        "message": message,
        "code": diag.code,
        "source": "fozzy",
        "relatedInformation": related_information,
        "codeDescription": diag.code.as_ref().map(|code| json!({"href": format!("https://fozzylang.dev/diagnostics/{code}")})),
        "data": {
            "path": diag.path.clone(),
            "help": diag.help.clone(),
            "fix": diag.fix.clone(),
            "notes": diag.notes.clone(),
            "suggestedFixes": diag.suggested_fixes.clone(),
            "snippet": diag.snippet.clone(),
            "labels": diag.labels.clone(),
        }
    })
}

fn severity_to_lsp(severity: &diagnostics::Severity) -> u8 {
    match severity {
        diagnostics::Severity::Error => 1,
        diagnostics::Severity::Warning => 2,
        diagnostics::Severity::Note => 3,
    }
}

fn type_diagnostics(typed: &hir::TypedModule) -> Vec<diagnostics::Diagnostic> {
    let mut out = Vec::new();
    for detail in &typed.type_error_details {
        out.push(diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            detail.clone(),
            Some("fix type mismatch before running".to_string()),
        ));
    }
    for violation in &typed.trait_violations {
        out.push(diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            violation.clone(),
            Some("trait implementation contract violated".to_string()),
        ));
    }
    for violation in &typed.ownership_violations {
        out.push(diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            violation.clone(),
            Some("ownership rule violation".to_string()),
        ));
    }
    for violation in &typed.reference_lifetime_violations {
        out.push(diagnostics::Diagnostic::new(
            diagnostics::Severity::Warning,
            violation.clone(),
            Some("reference lifetime issue".to_string()),
        ));
    }
    diagnostics::assign_stable_codes(&mut out, diagnostics::DiagnosticDomain::Hir);
    out
}

fn hydrate_document_context(
    diagnostics: &mut [diagnostics::Diagnostic],
    source: &str,
    path: String,
) {
    let lines = source.lines().map(ToString::to_string).collect::<Vec<_>>();
    for diagnostic in diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(path.clone());
        }
        if let Some(span) = &diagnostic.span {
            if diagnostic.snippet.is_none() && span.start_line > 0 && span.start_line <= lines.len()
            {
                diagnostic.snippet = Some(lines[span.start_line - 1].clone());
            }
            if diagnostic.labels.is_empty() {
                diagnostic.labels.push(diagnostics::Label {
                    message: diagnostic.message.clone(),
                    primary: true,
                    span: Some(span.clone()),
                });
            }
        }
    }
}

fn workspace_doc<'a>(ws: &'a WorkspaceState, uri: &str) -> Result<&'a Document> {
    ws.docs
        .get(uri)
        .ok_or_else(|| anyhow!("document is not open: {uri}"))
}

fn all_workspace_docs(ws: &WorkspaceState) -> Result<Vec<Document>> {
    if !ws.docs.is_empty() {
        return Ok(ws.docs.values().cloned().collect::<Vec<_>>());
    }
    let root = ws
        .root
        .as_ref()
        .ok_or_else(|| anyhow!("workspace root is not set"))?;
    let mut out = Vec::new();
    collect_docs_recursive(root, &mut out)?;
    Ok(out)
}

fn collect_docs_recursive(dir: &Path, out: &mut Vec<Document>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed reading workspace dir: {}", dir.display()))?;
    let mut materialized = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| "failed iterating workspace entry".to_string())?;
        materialized.push(entry.path());
    }
    materialized.sort();

    for path in materialized {
        let file_type = std::fs::metadata(&path)
            .map(|meta| meta.file_type())
            .with_context(|| format!("failed reading file type for {}", path.display()))?;
        if file_type.is_dir() {
            let name = path
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or_default();
            if matches!(name, ".git" | "target" | "vendor" | ".fz") {
                continue;
            }
            collect_docs_recursive(&path, out)?;
            continue;
        }
        if path.extension().and_then(|v| v.to_str()) != Some("fzy") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed reading file: {}", path.display()))?;
        out.push(Document {
            path,
            version: 0,
            text,
        });
    }
    Ok(())
}

fn read_lsp_message(reader: &mut dyn BufRead) -> Result<Option<Value>> {
    let mut content_length = None::<usize>;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return Ok(None);
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .context("invalid Content-Length header")?;
            content_length = Some(parsed);
        }
    }

    let len = content_length.ok_or_else(|| anyhow!("missing Content-Length header"))?;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    let value = serde_json::from_slice::<Value>(&payload).context("invalid JSON-RPC payload")?;
    Ok(Some(value))
}

fn write_lsp_message(writer: &mut dyn Write, value: &Value) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

fn request_position(params: &Value) -> Result<(String, usize, usize)> {
    let uri = params
        .get("textDocument")
        .and_then(|td| td.get("uri"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing textDocument.uri"))?
        .to_string();
    let line = params
        .get("position")
        .and_then(|p| p.get("line"))
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing position.line"))? as usize;
    let character = params
        .get("position")
        .and_then(|p| p.get("character"))
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing position.character"))? as usize;
    Ok((uri, line, character))
}

fn apply_incremental_changes(text: &mut String, changes: &[Value]) -> Result<()> {
    for change in changes {
        let replacement = change
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(range) = change.get("range") else {
            *text = replacement.to_string();
            continue;
        };
        let start_line = range
            .get("start")
            .and_then(|v| v.get("line"))
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("change.range.start.line missing"))?
            as usize;
        let start_char = range
            .get("start")
            .and_then(|v| v.get("character"))
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("change.range.start.character missing"))?
            as usize;
        let end_line = range
            .get("end")
            .and_then(|v| v.get("line"))
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("change.range.end.line missing"))?
            as usize;
        let end_char = range
            .get("end")
            .and_then(|v| v.get("character"))
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("change.range.end.character missing"))?
            as usize;

        let start = line_char_to_byte_index(text, start_line, start_char)?;
        let end = line_char_to_byte_index(text, end_line, end_char)?;
        text.replace_range(start..end, replacement);
    }
    Ok(())
}

fn line_char_to_byte_index(text: &str, line: usize, character: usize) -> Result<usize> {
    let mut byte_idx = 0usize;
    for (line_idx, row) in text.split_inclusive('\n').enumerate() {
        if line_idx == line {
            let row_without_newline = row.strip_suffix('\n').unwrap_or(row);
            let mut utf16 = 0usize;
            for (idx, ch) in row_without_newline.char_indices() {
                if utf16 >= character {
                    return Ok(byte_idx + idx);
                }
                utf16 += ch.len_utf16();
            }
            return Ok(byte_idx + row_without_newline.len());
        }
        byte_idx += row.len();
    }

    if line == text.lines().count() {
        return Ok(text.len());
    }
    bail!("line index out of range: {line}");
}

fn resolve_source(path: &Path) -> Result<ResolvedSource> {
    if path.is_file() {
        return Ok(ResolvedSource {
            source_path: path.to_path_buf(),
        });
    }
    if !path.is_dir() {
        bail!(
            "path is neither a source file nor a project directory: {}",
            path.display()
        );
    }
    let manifest_path = path.join("fozzy.toml");
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("missing manifest: {}", manifest_path.display()))?;
    let manifest = manifest::load(&manifest_text).context("failed parsing fozzy.toml")?;
    manifest
        .validate()
        .map_err(|error| anyhow!("invalid fozzy.toml: {error}"))?;
    let relative = manifest.primary_bin_path().ok_or_else(|| {
        anyhow!(
            "no [[target.bin]] entry in {} for source resolution",
            manifest_path.display()
        )
    })?;
    Ok(ResolvedSource {
        source_path: path.join(relative),
    })
}

#[derive(Debug, Clone)]
struct ResolvedSource {
    source_path: PathBuf,
}

fn path_to_uri(path: &Path) -> String {
    format!("file://{}", path.to_string_lossy())
}

fn uri_to_path(uri: &str) -> Option<PathBuf> {
    let raw = uri.strip_prefix("file://")?;
    Some(PathBuf::from(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn incremental_edit_applies_range() {
        let mut text = "fn main() -> i32 {\n    let value = 1\n    return value\n}\n".to_string();
        let changes = vec![json!({
            "range": {
                "start": {"line": 1, "character": 8},
                "end": {"line": 1, "character": 13}
            },
            "text": "answer"
        })];
        apply_incremental_changes(&mut text, &changes).expect("edit should apply");
        assert!(text.contains("let answer = 1"));
    }

    #[test]
    fn symbol_and_reference_scan_finds_occurrences() {
        let source =
            "fn ping() -> i32 {\n    let ping_count = 1\n    ping()\n    return ping_count\n}\n";
        let spans = symbol_spans_identifier_tokens(source, "ping");
        assert!(spans.len() >= 2);
        let defs = collect_symbol_occurrences(source, Path::new("/tmp/t.fzy"));
        assert!(defs.iter().any(|entry| entry.name == "ping"));
    }

    #[test]
    fn semantic_tokens_emit_stable_data() {
        let source = "// comment\nfn main() -> i32 {\n    let n = 42\n    return n\n}\n";
        let tokens = collect_semantic_tokens(source);
        assert!(!tokens.is_empty());
        assert!(tokens.iter().any(|entry| entry.3 == 8));
        assert!(tokens.iter().any(|entry| entry.3 == 1));
        assert!(tokens.iter().any(|entry| entry.3 == 7));
    }

    #[test]
    fn lsp_rejects_requests_after_shutdown() {
        let mut ws = WorkspaceState::default();
        ws.shutting_down = true;
        let mut out = Vec::<u8>::new();
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "textDocument/hover",
            "params": {}
        });
        handle_lsp_message(&mut ws, &msg, &mut out).expect("message handling should succeed");
        let framed = decode_lsp_frame(&out).expect("frame should decode");
        assert_eq!(framed.get("id").and_then(Value::as_i64), Some(7));
        assert_eq!(
            framed
                .get("error")
                .and_then(|v| v.get("code"))
                .and_then(Value::as_i64),
            Some(-32600)
        );
    }

    #[test]
    fn workspace_doc_walk_is_stably_sorted() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-lsp-doc-sort-{suffix}"));
        std::fs::create_dir_all(root.join("z")).expect("subdir z");
        std::fs::create_dir_all(root.join("a")).expect("subdir a");
        std::fs::write(root.join("z/zeta.fzy"), "fn z() -> i32 { return 0 }\n").expect("zeta");
        std::fs::write(root.join("a/alpha.fzy"), "fn a() -> i32 { return 0 }\n").expect("alpha");
        std::fs::write(root.join("m.fzy"), "fn m() -> i32 { return 0 }\n").expect("mid");

        let mut out = Vec::new();
        collect_docs_recursive(&root, &mut out).expect("walk should succeed");
        let names: Vec<String> = out
            .iter()
            .map(|doc| doc.path.display().to_string())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);

        let _ = std::fs::remove_dir_all(root);
    }

    fn decode_lsp_frame(bytes: &[u8]) -> Result<Value> {
        let text = String::from_utf8(bytes.to_vec())?;
        let marker = "\r\n\r\n";
        let split = text
            .find(marker)
            .ok_or_else(|| anyhow!("missing lsp frame delimiter"))?;
        let body = &text[(split + marker.len())..];
        Ok(serde_json::from_str(body)?)
    }
}
