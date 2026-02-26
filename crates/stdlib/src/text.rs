use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextError {
    InvalidUtf8Boundary,
    FormatTokenMismatch,
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8Boundary => write!(f, "invalid utf-8 byte boundary"),
            Self::FormatTokenMismatch => write!(f, "format token count does not match values"),
        }
    }
}

impl std::error::Error for TextError {}

pub fn split(value: &str, delim: &str) -> Vec<String> {
    if delim.is_empty() {
        return value.chars().map(|ch| ch.to_string()).collect();
    }
    value.split(delim).map(ToString::to_string).collect()
}

pub fn join(parts: &[impl AsRef<str>], delim: &str) -> String {
    parts
        .iter()
        .map(|part| part.as_ref())
        .collect::<Vec<_>>()
        .join(delim)
}

pub fn trim(value: &str) -> String {
    value.trim().to_string()
}

pub fn replace(value: &str, from: &str, to: &str) -> String {
    value.replace(from, to)
}

pub fn contains(value: &str, needle: &str) -> bool {
    value.contains(needle)
}

pub fn starts_with(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
}

pub fn ends_with(value: &str, suffix: &str) -> bool {
    value.ends_with(suffix)
}

pub fn slice_at_utf8_boundaries(value: &str, start: usize, end: usize) -> Result<String, TextError> {
    if start > end || end > value.len() {
        return Err(TextError::InvalidUtf8Boundary);
    }
    if !value.is_char_boundary(start) || !value.is_char_boundary(end) {
        return Err(TextError::InvalidUtf8Boundary);
    }
    Ok(value[start..end].to_string())
}

pub fn safe_interpolate(template: &str, values: &[impl AsRef<str>]) -> Result<String, TextError> {
    let mut out = String::with_capacity(template.len() + values.len() * 8);
    let mut idx = 0usize;
    let mut rest = template;
    while let Some(pos) = rest.find("{}") {
        out.push_str(&rest[..pos]);
        let Some(value) = values.get(idx) else {
            return Err(TextError::FormatTokenMismatch);
        };
        out.push_str(value.as_ref());
        idx += 1;
        rest = &rest[(pos + 2)..];
    }
    out.push_str(rest);
    if idx != values.len() {
        return Err(TextError::FormatTokenMismatch);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_primitives_work() {
        assert_eq!(split("a,b,c", ","), vec!["a", "b", "c"]);
        assert_eq!(join(&["a", "b", "c"], ","), "a,b,c");
        assert_eq!(trim("  hi  "), "hi");
        assert_eq!(replace("abc", "b", "x"), "axc");
        assert!(contains("abc", "b"));
        assert!(starts_with("abc", "a"));
        assert!(ends_with("abc", "c"));
    }

    #[test]
    fn utf8_boundary_checks_are_explicit() {
        let value = "h\u{00e9}llo";
        assert!(slice_at_utf8_boundaries(value, 0, 3).is_ok());
        assert_eq!(slice_at_utf8_boundaries(value, 0, 2), Err(TextError::InvalidUtf8Boundary));
    }

    #[test]
    fn interpolation_is_deterministic() {
        let rendered = safe_interpolate("{}:{}", &["k", "v"]).expect("format should work");
        assert_eq!(rendered, "k:v");
        assert_eq!(
            safe_interpolate("{}", &[] as &[&str]),
            Err(TextError::FormatTokenMismatch)
        );
    }
}
