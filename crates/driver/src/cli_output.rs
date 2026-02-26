use serde_json::Value;

use crate::command::Format;

pub fn format_message(format: Format, message: &str) -> String {
    match format {
        Format::Text => message.to_string(),
        Format::Json => format_json_value(&serde_json::json!({"message": message})),
    }
}

pub fn format_fields(fields: &[(&str, String)]) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{key}: {value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_fields_pretty(fields: &[(&str, String)]) -> String {
    if fields.is_empty() {
        return String::new();
    }
    let width = fields
        .iter()
        .map(|(key, _)| key.len())
        .max()
        .unwrap_or(0)
        .min(40);
    let mut out = String::new();
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let pad = " ".repeat(width.saturating_sub(key.len()));
        let mut lines = value.lines();
        if let Some(first) = lines.next() {
            out.push_str(&format!("{key}{pad} : {first}"));
        } else {
            out.push_str(&format!("{key}{pad} :"));
        }
        for line in lines {
            out.push('\n');
            out.push_str(&format!("{}   {line}", " ".repeat(width)));
        }
    }
    out
}

pub fn format_json_value(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}

pub fn normalize_cli_output(format: Format, output: &str) -> String {
    match format {
        Format::Json => {
            let Ok(parsed) = serde_json::from_str::<Value>(output) else {
                return output.trim_end().to_string();
            };
            serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| output.trim_end().to_string())
        }
        Format::Text => normalize_text_output(output),
    }
}

fn normalize_text_output(output: &str) -> String {
    let trimmed = output.trim_end();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut fields = Vec::<(String, String)>::new();
    for line in trimmed.lines() {
        if let Some((key, value)) = parse_field_line(line) {
            fields.push((key.to_string(), value.to_string()));
            continue;
        }
        if let Some((_, value)) = fields.last_mut() {
            if !value.is_empty() {
                value.push('\n');
            }
            value.push_str(line.trim_start());
        } else {
            return trimmed.to_string();
        }
    }

    if fields.len() < 2 {
        return trimmed.to_string();
    }

    let pretty_fields = fields
        .iter()
        .map(|(key, value)| (key.as_str(), value.clone()))
        .collect::<Vec<_>>();
    format_fields_pretty(&pretty_fields)
}

fn parse_field_line(line: &str) -> Option<(&str, &str)> {
    let idx = line.find(':')?;
    let key = line[..idx].trim();
    if key.is_empty() || !is_simple_key(key) {
        return None;
    }
    let value = line[(idx + 1)..].trim_start();
    Some((key, value))
}

fn is_simple_key(key: &str) -> bool {
    key.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_text_output_preserves_multiline_values() {
        let output = "status: ok\nmode: doctor-project\nchecks: - manifest:ok:loaded fozzy.toml\n- lockfile:ok:validated\n";
        let normalized = normalize_cli_output(Format::Text, output);
        assert!(normalized.contains("status"));
        assert!(normalized.contains("checks"));
        assert!(normalized.contains("- manifest:ok:loaded fozzy.toml"));
        assert!(normalized.contains("- lockfile:ok:validated"));
    }
}
