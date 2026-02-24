use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(err) = run() {
        eprintln!("fozzyfmt error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_help();
        return if args.is_empty() {
            Err("missing <path>".to_string())
        } else {
            Ok(())
        };
    }

    let check = args.iter().any(|arg| arg == "--check");
    let mut changed = Vec::new();

    for input in args.iter().filter(|arg| !arg.starts_with("--")) {
        let path = PathBuf::from(input);
        let files = discover_sources(&path)?;
        for file in files {
            let source = fs::read_to_string(&file)
                .map_err(|err| format!("failed reading {}: {err}", file.display()))?;
            let formatted = format_source(&source);
            if formatted != source {
                changed.push(file.clone());
                if !check {
                    fs::write(&file, formatted)
                        .map_err(|err| format!("failed writing {}: {err}", file.display()))?;
                }
            }
        }
    }

    if check {
        if changed.is_empty() {
            println!("fozzyfmt: clean");
            return Ok(());
        }
        for path in &changed {
            println!("needs-format: {}", path.display());
        }
        return Err(format!("{} file(s) need formatting", changed.len()));
    }

    if changed.is_empty() {
        println!("fozzyfmt: no changes");
    } else {
        println!("fozzyfmt: formatted {} file(s)", changed.len());
    }

    Ok(())
}

fn print_help() {
    eprintln!(
        "fozzyfmt <path> [<path> ...] [--check]\n\
formats .fzy files recursively\n\
--check  verify formatting without writing"
    );
}

fn discover_sources(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) == Some("fzy") {
            return Ok(vec![path.to_path_buf()]);
        }
        return Ok(Vec::new());
    }

    if !path.is_dir() {
        return Err(format!("path is neither file nor dir: {}", path.display()));
    }

    let mut files = Vec::new();
    walk(path, &mut files)?;
    Ok(files)
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|err| format!("failed reading {}: {err}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    entries.sort();

    for path in entries {
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

fn format_source(source: &str) -> String {
    let mut out = String::new();
    let mut indent = 0usize;

    for raw in source.lines() {
        let trimmed_end = raw.trim_end();
        let line = trimmed_end.trim_start();

        if line.is_empty() {
            out.push('\n');
            continue;
        }

        let effective_indent = if line.starts_with('}') {
            indent.saturating_sub(1)
        } else {
            indent
        };

        out.push_str(&" ".repeat(effective_indent * 4));
        out.push_str(line);
        out.push('\n');

        let open_count = line.chars().filter(|ch| *ch == '{').count();
        let close_count = line.chars().filter(|ch| *ch == '}').count();

        if open_count >= close_count {
            indent += open_count - close_count;
        } else {
            indent = indent.saturating_sub(close_count - open_count);
        }
    }

    if !out.ends_with('\n') {
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::format_source;

    #[test]
    fn normalizes_indent_and_trailing_whitespace() {
        let source = "fn main() -> i32 {   \nlet x = 1\nif x {\nreturn x\n}\n}\n";
        let got = format_source(source);
        let expected =
            "fn main() -> i32 {\n    let x = 1\n    if x {\n        return x\n    }\n}\n";
        assert_eq!(got, expected);
    }
}
