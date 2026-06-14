use super::*;

#[path = "qualify/base.rs"]
mod base;
#[path = "qualify/alias.rs"]
mod alias;
#[path = "qualify/walk.rs"]
mod walk;
#[path = "qualify/text.rs"]
mod text;

pub(crate) fn parse_and_qualify_module(
    module_path: &Path,
    discovered: &HashMap<PathBuf, DiscoveredModule>,
) -> Result<(PathBuf, LoadedModule)> {
    base::parse_and_qualify_module(module_path, discovered)
}

pub(crate) fn module_interface_fingerprint(module: &ast::Module) -> Result<String> {
    base::module_interface_fingerprint(module)
}

pub(crate) fn module_namespace_with_prefix(
    root_source: &Path,
    module_path: &Path,
    namespace_prefix: &str,
) -> Result<String> {
    base::module_namespace_with_prefix(root_source, module_path, namespace_prefix)
}

pub(crate) fn qualify_module_symbols(
    module: &mut ast::Module,
    namespace: &str,
    root_module_aliases: &HashMap<String, String>,
) {
    walk::qualify_module_symbols(module, namespace, root_module_aliases);
}

pub(crate) fn split_generic_suffix(callee: &str) -> (&str, &str) {
    text::split_generic_suffix(callee)
}

pub(crate) fn qualify_name(namespace: &str, name: &str) -> String {
    text::qualify_name(namespace, name)
}
