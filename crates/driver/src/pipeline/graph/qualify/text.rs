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

pub(crate) fn qualify_name(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}
