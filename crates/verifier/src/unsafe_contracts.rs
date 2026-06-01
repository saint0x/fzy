pub(crate) fn unsafe_scope_matches(module_name: &str, pattern: &str) -> bool {
    let module_name = module_name.trim();
    let pattern = pattern.trim();
    if module_name.is_empty() || pattern.is_empty() {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("::*") {
        return module_name == prefix || module_name.starts_with(&format!("{prefix}::"));
    }
    module_name == pattern
}

pub(crate) fn unsafe_invariant_matches_owner(invariant: &str, owner: &str) -> bool {
    let invariant = invariant.trim();
    let owner = owner.trim();
    if invariant.is_empty() || owner.is_empty() {
        return false;
    }
    invariant == format!("owner_live({owner})")
}

pub(crate) fn unsafe_owner_id_matches_owner(
    function_name: &str,
    owner: &str,
    owner_id: &str,
) -> bool {
    let function_name = function_name.trim();
    let owner = owner.trim();
    let owner_id = owner_id.trim();
    if function_name.is_empty() || owner.is_empty() || owner_id.is_empty() {
        return false;
    }
    owner_id == format!("owner::{function_name}::{owner}")
}

pub(crate) fn unsafe_proof_ref_valid(proof_ref: &str) -> bool {
    let proof_ref = proof_ref.trim();
    if proof_ref.is_empty() {
        return false;
    }
    let Some((scheme, rest)) = proof_ref.split_once("://") else {
        return false;
    };
    if rest.trim().is_empty() {
        return false;
    }
    if matches!(scheme, "gate" | "rfc") {
        return true;
    }
    if !matches!(scheme, "trace" | "run" | "test" | "ci") {
        return false;
    }
    let path_part = rest.split('#').next().unwrap_or_default().trim();
    if path_part.is_empty() {
        return false;
    }
    std::path::Path::new(path_part).exists()
}

pub(crate) fn unsafe_contract_is_placeholder_generated(site: &fir::UnsafeContractSite) -> bool {
    site.proof_ref
        .as_deref()
        .is_some_and(|proof_ref| proof_ref.starts_with("gate://compiler-generated/"))
        || site
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("compiler-generated:"))
        || site.owner.as_deref() == Some("scope_root")
}
