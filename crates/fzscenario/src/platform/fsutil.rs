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

    // Accept direct file paths (absolute or relative) even when they are outside cwd.
    for pattern in patterns {
        if has_glob_meta(pattern) {
            continue;
        }
        let candidate = PathBuf::from(pattern);
        if candidate.is_file() {
            out.insert(candidate);
        } else {
            missing_literal_files.insert(candidate);
        }
    }

    for root in walk_roots(patterns) {
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
            let p = entry.path();
            let rel = p.strip_prefix(".").unwrap_or(p);
            let rel_match = set.is_match(rel);
            let abs_match = if check_abs {
                set.is_match(cwd.join(rel))
            } else {
                false
            };
            if rel_match || abs_match {
                out.insert(rel.to_path_buf());
            }
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

fn walk_roots(patterns: &[String]) -> BTreeSet<PathBuf> {
    let mut roots = BTreeSet::new();
    for pattern in patterns {
        if has_glob_meta(pattern) {
            let prefix = pattern
                .split(['*', '?', '[', ']', '{', '}'])
                .next()
                .unwrap_or_default();
            let trimmed = prefix.trim_end_matches('/');
            if trimmed.is_empty() {
                roots.insert(PathBuf::from("."));
                continue;
            }
            let p = PathBuf::from(trimmed);
            if p.is_dir() {
                roots.insert(p);
            } else if let Some(parent) = p.parent() {
                if parent.as_os_str().is_empty() {
                    roots.insert(PathBuf::from("."));
                } else {
                    roots.insert(parent.to_path_buf());
                }
            } else {
                roots.insert(PathBuf::from("."));
            }
            continue;
        }

        let p = PathBuf::from(pattern);
        if p.is_dir() {
            roots.insert(p);
        } else if let Some(parent) = p.parent() {
            if parent.as_os_str().is_empty() {
                roots.insert(PathBuf::from("."));
            } else {
                roots.insert(parent.to_path_buf());
            }
        } else {
            roots.insert(PathBuf::from("."));
        }
    }
    if roots.is_empty() {
        roots.insert(PathBuf::from("."));
    }
    roots
}

fn should_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                ".git" | "target" | "node_modules" | ".fozzy" | "dist" | "build" | "coverage"
            )
        })
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
}
