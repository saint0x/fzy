//! Parsing and formatting for CLI duration values (e.g. "250ms", "30s", "5m", "2h").

use std::str::FromStr;
use std::time::Duration;

use crate::{FozzyError, FozzyResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FozzyDuration(pub Duration);

impl FromStr for FozzyDuration {
    type Err = FozzyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_duration(s).map(Self)
    }
}

pub fn parse_duration(input: &str) -> FozzyResult<Duration> {
    let s = input.trim();
    if s.is_empty() {
        return Err(FozzyError::InvalidArgument("empty duration".to_string()));
    }

    let (num_part, unit_part) = split_num_unit(s)?;
    let value: u64 = num_part.parse().map_err(|_| {
        FozzyError::InvalidArgument(format!(
            "invalid duration number: {num_part} (from {input:?})"
        ))
    })?;

    let dur = match unit_part {
        "ms" => Duration::from_millis(value),
        "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(value.saturating_mul(60)),
        "h" => Duration::from_secs(value.saturating_mul(60 * 60)),
        _ => {
            return Err(FozzyError::InvalidArgument(format!(
                "invalid duration unit {unit_part:?} (expected ms|s|m|h)"
            )));
        }
    };

    Ok(dur)
}

fn split_num_unit(s: &str) -> FozzyResult<(&str, &str)> {
    let mut idx = 0usize;
    for (i, ch) in s.char_indices() {
        if ch.is_ascii_digit() {
            idx = i + ch.len_utf8();
            continue;
        }
        idx = i;
        break;
    }

    if idx == 0 {
        return Err(FozzyError::InvalidArgument(format!(
            "invalid duration {s:?} (missing number)"
        )));
    }

    if idx >= s.len() {
        return Err(FozzyError::InvalidArgument(format!(
            "invalid duration {s:?} (missing unit; expected ms|s|m|h)"
        )));
    }

    Ok((&s[..idx], &s[idx..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_examples() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }
}
