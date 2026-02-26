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
    let lines = trimmed.lines().collect::<Vec<_>>();
    let parsed = lines
        .iter()
        .map(|line| {
            line.find(':').map(|idx| {
                let key = line[..idx].trim();
                let value = line[(idx + 1)..].trim_start();
                (key, value)
            })
        })
        .collect::<Vec<_>>();
    let kv_count = parsed.iter().filter(|item| item.is_some()).count();
    if kv_count < 2 {
        return trimmed.to_string();
    }
    let mut fields = Vec::<(&str, String)>::new();
    for item in parsed {
        if let Some((key, value)) = item {
            fields.push((key, value.to_string()));
        } else {
            return trimmed.to_string();
        }
    }
    format_fields_pretty(&fields)
}
