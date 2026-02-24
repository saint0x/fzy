use capabilities::CapabilitySet;
use hir::TypedModule;

#[derive(Debug, Clone)]
pub struct FirModule {
    pub name: String,
    pub effects: CapabilitySet,
    pub required_effects: CapabilitySet,
    pub unknown_effects: Vec<String>,
    pub nodes: usize,
    pub entry_return_type: Option<String>,
    pub entry_return_const_i32: Option<i32>,
    pub linear_resources: Vec<String>,
    pub deferred_resources: Vec<String>,
    pub matches_without_wildcard: usize,
    pub entry_requires: Vec<Option<bool>>,
    pub entry_ensures: Vec<Option<bool>>,
    pub host_syscall_sites: usize,
    pub extern_c_abi_functions: usize,
    pub repr_c_layout_items: usize,
}

pub fn build(typed: &TypedModule) -> FirModule {
    let mut effects = CapabilitySet::default();
    let mut required_effects = CapabilitySet::default();
    let mut unknown_effects = Vec::new();
    for capability in &typed.capabilities {
        if let Some(parsed) = capabilities::Capability::parse(capability) {
            effects.insert(parsed);
        } else {
            unknown_effects.push(capability.clone());
        }
    }
    for capability in &typed.inferred_capabilities {
        if let Some(parsed) = capabilities::Capability::parse(capability) {
            required_effects.insert(parsed);
        } else {
            unknown_effects.push(capability.clone());
        }
    }

    FirModule {
        name: typed.name.clone(),
        effects,
        required_effects,
        unknown_effects,
        nodes: typed.symbol_count,
        entry_return_type: typed.entry_return_type.clone(),
        entry_return_const_i32: typed.entry_return_const_i32,
        linear_resources: typed.linear_resources.clone(),
        deferred_resources: typed.deferred_resources.clone(),
        matches_without_wildcard: typed.matches_without_wildcard,
        entry_requires: typed.entry_requires.clone(),
        entry_ensures: typed.entry_ensures.clone(),
        host_syscall_sites: typed.host_syscall_sites,
        extern_c_abi_functions: typed.extern_c_abi_functions,
        repr_c_layout_items: typed.repr_c_layout_items,
    }
}
