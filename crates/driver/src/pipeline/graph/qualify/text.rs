use super::*;

pub(crate) fn qualify_type_name(
    name: &str,
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) -> String {
    if let Some(exact_alias) = module_aliases.get(name) {
        exact_alias.clone()
    } else if let Some((head, tail)) = name.split_once('.') {
        if let Some(qualified_head) = module_aliases.get(head) {
            format!("{qualified_head}.{tail}")
        } else {
            name.to_string()
        }
    } else if local_types.contains(name) {
        qualify_name(namespace, name)
    } else {
        name.to_string()
    }
}

pub(crate) fn split_generic_suffix(callee: &str) -> (&str, &str) {
    if let Some(index) = callee.find('<') {
        (&callee[..index], &callee[index..])
    } else {
        (callee, "")
    }
}

pub(crate) fn qualify_generic_suffix(
    suffix: &str,
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) -> String {
    if suffix.is_empty() {
        return String::new();
    }
    let Some(inner) = suffix.strip_prefix('<').and_then(|value| value.strip_suffix('>')) else {
        return suffix.to_string();
    };
    let Some(parts) = split_top_level_type_args(inner) else {
        return suffix.to_string();
    };
    let mut qualified = Vec::with_capacity(parts.len());
    for part in parts {
        let Ok(mut ty) = parser::parse_type_text(part) else {
            return suffix.to_string();
        };
        super::walk::qualify_type(&mut ty, namespace, local_types, module_aliases);
        qualified.push(ty.to_string());
    }
    format!("<{}>", qualified.join(", "))
}

fn split_top_level_type_args(input: &str) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    let mut depth_angle = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_paren = 0usize;
    let mut start = 0usize;
    for (idx, ch) in input.char_indices() {
        match ch {
            '<' => depth_angle += 1,
            '>' => {
                if depth_angle == 0 {
                    return None;
                }
                depth_angle -= 1;
            }
            '[' => depth_bracket += 1,
            ']' => {
                if depth_bracket == 0 {
                    return None;
                }
                depth_bracket -= 1;
            }
            '(' => depth_paren += 1,
            ')' => {
                if depth_paren == 0 {
                    return None;
                }
                depth_paren -= 1;
            }
            ',' if depth_angle == 0 && depth_bracket == 0 && depth_paren == 0 => {
                out.push(input[start..idx].trim());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    if depth_angle != 0 || depth_bracket != 0 || depth_paren != 0 {
        return None;
    }
    let tail = input[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    Some(out)
}

pub(crate) fn qualify_name(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}
