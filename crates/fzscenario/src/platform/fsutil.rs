//! Small filesystem utilities.

use globset::{Glob, GlobSet, GlobSetBuilder};

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::{FozzyError, FozzyResult};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchFilesResult {
    pub files: Vec<PathBuf>,
    pub missing_literal_files: Vec<PathBuf>,
}

pub fn find_matching_files(patterns: &[String]) -> FozzyResult<Vec<PathBuf>> {
    Ok(resolve_matching_files(patterns)?.files)
}

pub fn resolve_matching_files(patterns: &[String]) -> FozzyResult<MatchFilesResult> {
    let set = compile_globset(patterns)?;
    let cwd = std::env::current_dir()?;
    let check_abs = patterns.iter().any(|p| Path::new(p).is_absolute());
    let mut out = BTreeSet::new();
    let mut missing_literal_files = BTreeSet::new();
    let mut walk_required = false;

    // Accept direct file paths (absolute or relative) even when they are outside cwd.
    for pattern in patterns {
        if has_glob_meta(pattern) {
            walk_required = true;
            continue;
        }
        let candidate = PathBuf::from(pattern);
        if candidate.is_file() {
            out.insert(candidate);
        } else if candidate.is_dir() {
            walk_required = true;
        } else {
            missing_literal_files.insert(candidate);
        }
    }
    if !walk_required {
        let files = out.into_iter().collect::<Vec<_>>();
        return Ok(MatchFilesResult {
            files,
            missing_literal_files: missing_literal_files.into_iter().collect(),
        });
    }

    for root in walk_roots(patterns) {
        if root.is_file() {
            insert_if_matching(&mut out, root.as_path(), &cwd, &set, check_abs);
            continue;
        }
        for entry in WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !should_skip_dir(e.path()))
        {
            let entry = entry.map_err(|e| {
                let msg = e.to_string();
                FozzyError::Io(
                    e.into_io_error()
                        .unwrap_or_else(|| std::io::Error::other(msg)),
                )
            })?;
            if !entry.file_type().is_file() {
                continue;
            }
            insert_if_matching(&mut out, entry.path(), &cwd, &set, check_abs);
        }
    }
    let files = out.into_iter().collect::<Vec<_>>();
    let file_set = files.iter().cloned().collect::<BTreeSet<_>>();
    Ok(MatchFilesResult {
        files,
        missing_literal_files: missing_literal_files
            .into_iter()
            .filter(|path| !file_set.contains(path))
            .collect(),
    })
}

pub(crate) fn walk_roots(patterns: &[String]) -> BTreeSet<PathBuf> {
    let mut roots = Vec::new();
    for pattern in patterns {
        if has_glob_meta(pattern) {
            let prefix = pattern
                .split(['*', '?', '[', ']', '{', '}'])
                .next()
                .unwrap_or_default();
            let trimmed = prefix.trim_end_matches('/');
            if trimmed.is_empty() {
                roots.push(PathBuf::from("."));
                continue;
            }
            let p = PathBuf::from(trimmed);
            if p.is_dir() {
                roots.push(p);
            } else if let Some(parent) = p.parent() {
                if parent.as_os_str().is_empty() {
                    roots.push(PathBuf::from("."));
                } else {
                    roots.push(parent.to_path_buf());
                }
            } else {
                roots.push(PathBuf::from("."));
            }
            continue;
        }

        let p = PathBuf::from(pattern);
        if p.is_dir() {
            roots.push(p);
        } else if p.is_file() {
            roots.push(p);
        } else if let Some(parent) = p.parent() {
            if parent.as_os_str().is_empty() {
                roots.push(PathBuf::from("."));
            } else {
                roots.push(parent.to_path_buf());
            }
        } else {
            roots.push(PathBuf::from("."));
        }
    }
    if roots.is_empty() {
        roots.push(PathBuf::from("."));
    }
    prune_nested_roots(roots)
}

fn prune_nested_roots(roots: Vec<PathBuf>) -> BTreeSet<PathBuf> {
    let mut sorted = roots;
    sorted.sort();
    let mut kept = BTreeSet::new();
    'outer: for root in sorted {
        for existing in &kept {
            if root == *existing || root.starts_with(existing) {
                continue 'outer;
            }
        }
        kept.retain(|existing: &PathBuf| !existing.starts_with(&root));
        kept.insert(root);
    }
    kept
}

fn insert_if_matching(
    out: &mut BTreeSet<PathBuf>,
    path: &Path,
    cwd: &Path,
    set: &GlobSet,
    check_abs: bool,
) {
    let rel = path.strip_prefix(".").unwrap_or(path);
    let rel_match = set.is_match(rel);
    let abs_match = check_abs && set.is_match(cwd.join(rel));
    if rel_match || abs_match {
        out.insert(rel.to_path_buf());
    }
}

pub(crate) fn should_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(should_skip_dir_name)
}

fn should_skip_dir_name(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "target"
            | "node_modules"
            | ".fozzy"
            | "dist"
            | "build"
            | "coverage"
            | "__pycache__"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".ruff_cache"
            | ".cache"
            | "venv"
            | ".venv"
            | ".tox"
    ) || name == "tmp"
        || name.starts_with("tmp_")
        || name.starts_with("tmp-")
        || name.starts_with("tmp.")
}

#[allow(dead_code)]
pub(crate) fn list_files_shallow(dir: &Path) -> FozzyResult<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

fn compile_globset(patterns: &[String]) -> FozzyResult<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let g = Glob::new(p)
            .map_err(|e| FozzyError::InvalidArgument(format!("invalid glob {p:?}: {e}")))?;
        b.add(g);
    }
    b.build()
        .map_err(|e| FozzyError::InvalidArgument(format!("invalid globset: {e}")))
}

fn has_glob_meta(pattern: &str) -> bool {
    pattern.contains('*')
        || pattern.contains('?')
        || pattern.contains('[')
        || pattern.contains(']')
        || pattern.contains('{')
        || pattern.contains('}')
}

pub fn default_min_trace_path(input: &std::path::Path) -> PathBuf {
    let parent = input
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("trace.fozzy");

    let out_name = if let Some(stem) = file_name.strip_suffix(".fozzy") {
        format!("{stem}.min.fozzy")
    } else {
        format!("{file_name}.min.fozzy")
    };

    parent.join(out_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fozzy-fsutil-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn find_matching_files_accepts_absolute_file_path() {
        let root = temp_dir("abs-file");
        let scenario = root.join("abs.fozzy.json");
        std::fs::write(&scenario, br#"{"version":1,"name":"x","steps":[]}"#)
            .expect("write scenario");
        let matches =
            find_matching_files(&[scenario.to_string_lossy().to_string()]).expect("match files");
        assert!(matches.iter().any(|p| p == &scenario));
    }

    #[test]
    fn resolve_matching_files_reports_missing_literal_file() {
        let root = temp_dir("missing-literal");
        let missing = root.join("missing.fozzy.json");
        let resolved =
            resolve_matching_files(&[missing.to_string_lossy().to_string()]).expect("resolve");
        assert!(resolved.files.is_empty());
        assert_eq!(resolved.missing_literal_files, vec![missing]);
    }

    #[test]
    fn resolve_matching_files_fast_path_returns_literal_files_without_walking() {
        let root = temp_dir("literal-fast-path");
        let first = root.join("one.fozzy.json");
        let second = root.join("two.fozzy.json");
        std::fs::write(&first, br#"{"version":1,"name":"one","steps":[]}"#).expect("write first");
        std::fs::write(&second, br#"{"version":1,"name":"two","steps":[]}"#).expect("write second");

        let resolved = resolve_matching_files(&[
            first.to_string_lossy().to_string(),
            second.to_string_lossy().to_string(),
        ])
        .expect("resolve literal files");

        assert_eq!(resolved.files, vec![first, second]);
        assert!(resolved.missing_literal_files.is_empty());
    }

    #[test]
    fn should_skip_dir_name_excludes_scratch_and_cache_dirs() {
        assert!(should_skip_dir_name("tmp"));
        assert!(should_skip_dir_name("tmp_eval"));
        assert!(should_skip_dir_name("tmp-build"));
        assert!(should_skip_dir_name("tmp.cache"));
        assert!(should_skip_dir_name("__pycache__"));
        assert!(should_skip_dir_name(".pytest_cache"));
        assert!(!should_skip_dir_name("src"));
        assert!(!should_skip_dir_name("runtime"));
    }
}
