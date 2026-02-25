use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

const REF_START: &str = "<!-- fozzydoc:api:start -->";
const REF_END: &str = "<!-- fozzydoc:api:end -->";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Html,
    Markdown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DocItem {
    kind: String,
    name: String,
    signature: String,
    module: String,
    path: String,
    line: usize,
    docs: String,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        bail!("missing <path>");
    }

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    let path = PathBuf::from(&args[0]);
    let format = parse_format(&args)?;
    let out = parse_out_path(&args)?;
    let reference = parse_reference_path(&args)?;
    let files = discover_sources(&path)?;

    let mut items = Vec::new();
    for file in files {
        items.extend(extract_items(&file)?);
    }

    items.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    let rendered = match format {
        OutputFormat::Json => render_json(&items)?,
        OutputFormat::Html => render_html(&items),
        OutputFormat::Markdown => render_markdown(&items),
    };

    if let Some(reference_path) = reference {
        integrate_reference(&reference_path, &items)?;
    }

    if let Some(out_path) = out {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed creating output directory: {}", parent.display())
            })?;
        }
        fs::write(&out_path, rendered)
            .with_context(|| format!("failed writing output file: {}", out_path.display()))?;
    } else {
        println!("{rendered}");
    }

    Ok(())
}

fn print_help() {
    eprintln!(
        "fozzydoc <path> [--format json|html|markdown] [--out <file>] [--reference <language-reference.md>]\n\
extracts docs for fn/struct/enum/rpc/test declarations from .fzy files\n\
--reference inserts/updates an API section between markers in the language reference"
    );
}

fn parse_format(args: &[String]) -> Result<OutputFormat> {
    if let Some(idx) = args.iter().position(|arg| arg == "--format") {
        let raw = args
            .get(idx + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for --format"))?;
        return match raw.as_str() {
            "json" => Ok(OutputFormat::Json),
            "html" => Ok(OutputFormat::Html),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            _ => bail!("unsupported --format value `{raw}` (expected json|html|markdown)"),
        };
    }

    Ok(OutputFormat::Json)
}

fn parse_out_path(args: &[String]) -> Result<Option<PathBuf>> {
    if let Some(idx) = args.iter().position(|arg| arg == "--out") {
        let raw = args
            .get(idx + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for --out"))?;
        return Ok(Some(PathBuf::from(raw)));
    }
    Ok(None)
}

fn parse_reference_path(args: &[String]) -> Result<Option<PathBuf>> {
    if let Some(idx) = args.iter().position(|arg| arg == "--reference") {
        let raw = args
            .get(idx + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for --reference"))?;
        return Ok(Some(PathBuf::from(raw)));
    }
    Ok(None)
}

fn discover_sources(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        bail!(
            "input path is neither a file nor directory: {}",
            path.display()
        );
    }

    let mut files = Vec::new();
    walk(path, &mut files)?;
    Ok(files)
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("failed iterating {}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            walk(&path, files)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("fzy") {
            files.push(path);
        }
    }
    Ok(())
}

fn extract_items(path: &Path) -> Result<Vec<DocItem>> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed reading source file: {}", path.display()))?;
    let module = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown")
        .to_string();
    let path_string = path.display().to_string();

    let mut items = Vec::new();
    let mut pending_docs = Vec::<String>::new();
    let mut in_block_doc = false;

    for (index, raw) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();

        if in_block_doc {
            if let Some(prefix) = line.strip_suffix("*/") {
                let cleaned = prefix.trim_start_matches('*').trim();
                if !cleaned.is_empty() {
                    pending_docs.push(cleaned.to_string());
                }
                in_block_doc = false;
                continue;
            }

            let cleaned = line.trim_start_matches('*').trim();
            if !cleaned.is_empty() {
                pending_docs.push(cleaned.to_string());
            }
            continue;
        }

        if let Some(doc) = line.strip_prefix("///") {
            pending_docs.push(doc.trim().to_string());
            continue;
        }

        if let Some(after) = line.strip_prefix("/**") {
            if let Some(mid) = after.strip_suffix("*/") {
                let cleaned = mid.trim();
                if !cleaned.is_empty() {
                    pending_docs.push(cleaned.to_string());
                }
            } else {
                let cleaned = after.trim_start_matches('*').trim();
                if !cleaned.is_empty() {
                    pending_docs.push(cleaned.to_string());
                }
                in_block_doc = true;
            }
            continue;
        }

        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        let without_attrs = strip_leading_attributes(line);
        if without_attrs.is_empty() {
            continue;
        }

        if let Some((kind, name, signature)) = parse_decl(without_attrs) {
            items.push(DocItem {
                kind: kind.to_string(),
                name,
                signature,
                module: module.clone(),
                path: path_string.clone(),
                line: line_number,
                docs: pending_docs.join("\n"),
            });
            pending_docs.clear();
            continue;
        }

        pending_docs.clear();
    }

    Ok(items)
}

fn parse_decl(line: &str) -> Option<(&'static str, String, String)> {
    if let Some(rest) = line.strip_prefix("fn ") {
        return parse_symbol(rest, '(').map(|name| ("fn", name, clean_signature(line)));
    }
    if let Some(rest) = line.strip_prefix("struct ") {
        return parse_symbol(rest, '{').map(|name| ("struct", name, clean_signature(line)));
    }
    if let Some(rest) = line.strip_prefix("enum ") {
        return parse_symbol(rest, '{').map(|name| ("enum", name, clean_signature(line)));
    }
    if let Some(rest) = line.strip_prefix("trait ") {
        return parse_symbol(rest, '{').map(|name| ("trait", name, clean_signature(line)));
    }
    if let Some(rest) = line.strip_prefix("impl ") {
        return parse_symbol(rest, '{').map(|name| ("impl", name, clean_signature(line)));
    }
    if let Some(rest) = line.strip_prefix("rpc ") {
        return parse_symbol(rest, '(').map(|name| ("rpc", name, clean_signature(line)));
    }
    if let Some(rest) = line.strip_prefix("test ") {
        let name = rest
            .trim()
            .trim_start_matches('"')
            .split('"')
            .next()
            .unwrap_or(rest.trim())
            .trim()
            .to_string();
        if !name.is_empty() {
            return Some(("test", name, clean_signature(line)));
        }
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if let Some(idx) = token_index(&tokens, "fn") {
        let token = tokens.get(idx + 1)?;
        let name = token.split('(').next()?.trim();
        let cleaned = clean_name(name);
        if !cleaned.is_empty() {
            return Some(("fn", cleaned, clean_signature(line)));
        }
    }
    if let Some(idx) = token_index(&tokens, "struct") {
        let token = tokens.get(idx + 1)?;
        let cleaned = clean_name(token);
        if !cleaned.is_empty() {
            return Some(("struct", cleaned, clean_signature(line)));
        }
    }
    if let Some(idx) = token_index(&tokens, "enum") {
        let token = tokens.get(idx + 1)?;
        let cleaned = clean_name(token);
        if !cleaned.is_empty() {
            return Some(("enum", cleaned, clean_signature(line)));
        }
    }
    if let Some(idx) = token_index(&tokens, "trait") {
        let token = tokens.get(idx + 1)?;
        let cleaned = clean_name(token);
        if !cleaned.is_empty() {
            return Some(("trait", cleaned, clean_signature(line)));
        }
    }
    if let Some(idx) = token_index(&tokens, "impl") {
        let token = tokens.get(idx + 1)?;
        let cleaned = clean_name(token);
        if !cleaned.is_empty() {
            return Some(("impl", cleaned, clean_signature(line)));
        }
    }
    if let Some(idx) = token_index(&tokens, "rpc") {
        let token = tokens.get(idx + 1)?;
        let name = token.split('(').next()?.trim();
        let cleaned = clean_name(name);
        if !cleaned.is_empty() {
            return Some(("rpc", cleaned, clean_signature(line)));
        }
    }
    None
}

fn parse_symbol(input: &str, terminal: char) -> Option<String> {
    let raw = input.trim().split(terminal).next()?.trim().to_string();
    let cleaned = clean_name(&raw);
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn render_json(items: &[DocItem]) -> Result<String> {
    serde_json::to_string_pretty(items).context("failed serializing docs to json")
}

fn render_html(items: &[DocItem]) -> String {
    let mut out = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>fozzydoc</title></head><body>",
    );
    out.push_str("<h1>fzy docs</h1><ul>");
    for item in items {
        out.push_str("<li>");
        out.push_str(&format!(
            "<h2>{} {}</h2><p><strong>module:</strong> {}</p><p><strong>path:</strong> {}:{}</p><pre>{}</pre>",
            escape_html(&item.kind),
            escape_html(&item.name),
            escape_html(&item.module),
            escape_html(&item.path),
            item.line,
            escape_html(&item.signature),
        ));
        if !item.docs.trim().is_empty() {
            out.push_str(&format!("<pre>{}</pre>", escape_html(&item.docs)));
        }
        out.push_str("</li>");
    }
    out.push_str("</ul></body></html>");
    out
}

fn render_markdown(items: &[DocItem]) -> String {
    let mut out = String::from("# API Documentation\n\n");
    for item in items {
        out.push_str(&format!(
            "## `{}` `{}`\n\n",
            item.kind.trim(),
            item.name.trim()
        ));
        out.push_str(&format!("- Module: `{}`\n", item.module));
        out.push_str(&format!("- Location: `{}:{}`\n\n", item.path, item.line));
        out.push_str("```fzy\n");
        out.push_str(&item.signature);
        out.push_str("\n```\n\n");
        if item.docs.trim().is_empty() {
            out.push_str("_No docs provided._\n\n");
            continue;
        }
        out.push_str("```text\n");
        out.push_str(&item.docs);
        out.push_str("\n```\n\n");
    }
    out
}

fn integrate_reference(reference_path: &Path, items: &[DocItem]) -> Result<()> {
    let current = fs::read_to_string(reference_path).with_context(|| {
        format!(
            "failed reading reference file: {}",
            reference_path.display()
        )
    })?;
    let section = format!(
        "{REF_START}\n\n{}\n{REF_END}",
        render_markdown(items).trim_end()
    );

    let updated = if let Some(start) = current.find(REF_START) {
        if let Some(end) = current.find(REF_END) {
            let end_idx = end + REF_END.len();
            format!("{}{}{}", &current[..start], section, &current[end_idx..])
        } else {
            format!("{}\n\n{}\n", current.trim_end(), section)
        }
    } else {
        format!("{}\n\n{}\n", current.trim_end(), section)
    };

    fs::write(reference_path, updated).with_context(|| {
        format!(
            "failed writing reference file: {}",
            reference_path.display()
        )
    })?;
    Ok(())
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn strip_leading_attributes(line: &str) -> &str {
    let mut rest = line.trim_start();
    loop {
        if !rest.starts_with("#[") {
            return rest;
        }
        let Some(end) = rest.find(']') else {
            return "";
        };
        rest = rest[end + 1..].trim_start();
    }
}

fn token_index(tokens: &[&str], needle: &str) -> Option<usize> {
    tokens.iter().position(|token| *token == needle)
}

fn clean_name(raw: &str) -> String {
    raw.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .to_string()
}

fn clean_signature(line: &str) -> String {
    line.trim()
        .trim_end_matches('{')
        .trim_end_matches(';')
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        extract_items, parse_decl, render_html, render_markdown, strip_leading_attributes,
    };

    #[test]
    fn parse_declaration_kinds() {
        assert_eq!(
            parse_decl("fn main() -> i32 {"),
            Some(("fn", "main".into(), "fn main() -> i32".into()))
        );
        assert_eq!(
            parse_decl("struct User {"),
            Some(("struct", "User".into(), "struct User".into()))
        );
        assert_eq!(
            parse_decl("enum Kind {"),
            Some(("enum", "Kind".into(), "enum Kind".into()))
        );
        assert_eq!(
            parse_decl("pub extern \"C\" fn fs_open(path: *u8) -> i32;"),
            Some((
                "fn",
                "fs_open".into(),
                "pub extern \"C\" fn fs_open(path: *u8) -> i32".into(),
            ))
        );
        assert_eq!(
            parse_decl("rpc Ping(req: Req) -> Res;"),
            Some(("rpc", "Ping".into(), "rpc Ping(req: Req) -> Res".into()))
        );
        assert_eq!(
            parse_decl("test \"smoke\" {}"),
            Some(("test", "smoke".into(), "test \"smoke\" {}".into()))
        );
    }

    #[test]
    fn extracts_doc_items_from_source() {
        let file_name = format!(
            "fozzydoc-test-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "/// app entrypoint\nfn main() -> i32 {\n    return 0\n}\n/**\n * request-response endpoint\n */\nrpc Ping(req: Req) -> Res;\n#[ffi_panic(error)] pub extern \"C\" fn fs_open(path: *u8) -> i32;\n",
        )
        .expect("source should be written");

        let items = extract_items(&path).expect("extraction should succeed");
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].name, "main");
        assert_eq!(items[1].kind, "rpc");
        assert_eq!(items[2].name, "fs_open");
        assert!(items[2].docs.is_empty());
        assert!(render_html(&items).contains("fzy docs"));
        assert!(render_markdown(&items).contains("request-response endpoint"));
        assert!(render_markdown(&items).contains("_No docs provided._"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn strips_attribute_prefixes() {
        assert_eq!(
            strip_leading_attributes("#[ffi_panic(error)] pub extern \"C\" fn fs_open() -> i32;"),
            "pub extern \"C\" fn fs_open() -> i32;"
        );
    }
}
