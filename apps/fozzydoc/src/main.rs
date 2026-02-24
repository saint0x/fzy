use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Html,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DocItem {
    kind: String,
    name: String,
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
    let files = discover_sources(&path)?;

    let mut items = Vec::new();
    for file in files {
        items.extend(extract_items(&file)?);
    }

    items.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    let rendered = match format {
        OutputFormat::Json => render_json(&items)?,
        OutputFormat::Html => render_html(&items),
    };

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
        "fozzydoc <path> [--format json|html] [--out <file>]\n\
extracts `///` docs for fn/struct/enum/test declarations from .fzy files"
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
            _ => bail!("unsupported --format value `{raw}` (expected json|html)"),
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

    for (index, raw) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();
        if let Some(doc) = line.strip_prefix("///") {
            pending_docs.push(doc.trim().to_string());
            continue;
        }

        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        if let Some((kind, name)) = parse_decl(line) {
            if !pending_docs.is_empty() {
                items.push(DocItem {
                    kind: kind.to_string(),
                    name,
                    module: module.clone(),
                    path: path_string.clone(),
                    line: line_number,
                    docs: pending_docs.join("\n"),
                });
            }
        }

        pending_docs.clear();
    }

    Ok(items)
}

fn parse_decl(line: &str) -> Option<(&'static str, String)> {
    if let Some(rest) = line.strip_prefix("fn ") {
        return parse_symbol(rest, '(').map(|name| ("fn", name));
    }
    if let Some(rest) = line.strip_prefix("struct ") {
        return parse_symbol(rest, '{').map(|name| ("struct", name));
    }
    if let Some(rest) = line.strip_prefix("enum ") {
        return parse_symbol(rest, '{').map(|name| ("enum", name));
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
            return Some(("test", name));
        }
    }
    None
}

fn parse_symbol(input: &str, terminal: char) -> Option<String> {
    let mut raw = input.trim().split(terminal).next()?.trim().to_string();
    if raw.ends_with(';') {
        raw.pop();
    }
    if raw.is_empty() {
        None
    } else {
        Some(raw)
    }
}

fn render_json(items: &[DocItem]) -> Result<String> {
    serde_json::to_string_pretty(items).context("failed serializing docs to json")
}

fn render_html(items: &[DocItem]) -> String {
    let mut out = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>fozzydoc</title></head><body>",
    );
    out.push_str("<h1>FozzyLang Docs</h1><ul>");
    for item in items {
        out.push_str("<li>");
        out.push_str(&format!(
            "<h2>{} {}</h2><p><strong>module:</strong> {}</p><p><strong>path:</strong> {}:{}</p><pre>{}</pre>",
            escape_html(&item.kind),
            escape_html(&item.name),
            escape_html(&item.module),
            escape_html(&item.path),
            item.line,
            escape_html(&item.docs),
        ));
        out.push_str("</li>");
    }
    out.push_str("</ul></body></html>");
    out
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{extract_items, parse_decl, render_html};

    #[test]
    fn parse_declaration_kinds() {
        assert_eq!(
            parse_decl("fn main() -> i32 {"),
            Some(("fn", "main".into()))
        );
        assert_eq!(parse_decl("struct User {"), Some(("struct", "User".into())));
        assert_eq!(parse_decl("enum Kind {"), Some(("enum", "Kind".into())));
        assert_eq!(
            parse_decl("test \"smoke\" {}"),
            Some(("test", "smoke".into()))
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
            "/// app entrypoint\nfn main() -> i32 {\n    return 0\n}\n/// model\nenum Kind {}\n",
        )
        .expect("source should be written");

        let items = extract_items(&path).expect("extraction should succeed");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "main");
        assert_eq!(items[1].kind, "enum");
        assert!(render_html(&items).contains("FozzyLang Docs"));

        let _ = std::fs::remove_file(path);
    }
}
