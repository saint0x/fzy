use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    TraversalEscapesBase,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraversalEscapesBase => write!(f, "path traversal escapes base directory"),
        }
    }
}

impl std::error::Error for PathError {}

pub fn split(path: &str) -> Vec<String> {
    path.replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub fn normalize(path: &str) -> String {
    let canonical = path.replace('\\', "/");
    let is_abs = canonical.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();

    for part in canonical.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if let Some(last) = parts.pop() {
                    if last == ".." {
                        parts.push(last);
                        parts.push("..");
                    }
                } else if !is_abs {
                    parts.push("..");
                }
            }
            component => parts.push(component),
        }
    }

    let joined = parts.join("/");
    if is_abs {
        if joined.is_empty() {
            "/".to_string()
        } else {
            format!("/{joined}")
        }
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

pub fn join(base: &str, child: &str) -> String {
    let right = child.replace('\\', "/");
    if right.starts_with('/') {
        return normalize(&right);
    }
    if base.is_empty() {
        return normalize(child);
    }
    normalize(&format!("{}/{}", base.trim_end_matches(['/', '\\']), child))
}

pub fn safe_join(base: &str, child: &str) -> Result<String, PathError> {
    let base_norm = normalize(base);
    let joined = join(&base_norm, child);

    let base_parts = split(&base_norm);
    let joined_parts = split(&joined);
    if joined_parts.len() < base_parts.len() {
        return Err(PathError::TraversalEscapesBase);
    }
    if !base_parts
        .iter()
        .zip(joined_parts.iter())
        .all(|(left, right)| left == right)
    {
        return Err(PathError::TraversalEscapesBase);
    }
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::{join, normalize, safe_join, split};

    #[test]
    fn normalize_collapses_segments() {
        assert_eq!(normalize("a/./b/../c"), "a/c");
        assert_eq!(normalize("/var//log/../tmp"), "/var/tmp");
        assert_eq!(normalize(""), ".");
    }

    #[test]
    fn join_and_split_are_platform_safe() {
        assert_eq!(join("a\\b", "c/d"), "a/b/c/d");
        assert_eq!(split("/a//b\\c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn safe_join_blocks_escape() {
        assert!(safe_join("/srv/app", "../etc/passwd").is_err());
        let ok = safe_join("/srv/app", "assets/img/logo.png").expect("safe path");
        assert_eq!(ok, "/srv/app/assets/img/logo.png");
    }
}
