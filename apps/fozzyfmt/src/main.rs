use std::fs;
use std::path::{Path, PathBuf};

use formatter::{format_source, is_fzy_source_path};

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
        if is_fzy_source_path(path) {
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
        if is_fzy_source_path(&path) {
            files.push(path);
        }
    }
    Ok(())
}
