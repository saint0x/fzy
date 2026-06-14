pub(super) fn build_unsafe_report_json(fir: &fir::FirModule) -> serde_json::Value {
    let unsafe_sites = fir
        .unsafe_contract_sites
        .iter()
        .filter(|site| site.kind != "unsafe_violation_callsite")
        .collect::<Vec<_>>();
    let reasoned = unsafe_sites
        .iter()
        .filter(|site| {
            site.reason
                .as_deref()
                .is_some_and(|value| !value.is_empty())
                && site
                    .invariant
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                && site.owner.as_deref().is_some_and(|value| !value.is_empty())
                && site.scope.as_deref().is_some_and(|value| !value.is_empty())
                && site
                    .risk_class
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                && site
                    .proof_ref
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                && !site
                    .proof_ref
                    .as_deref()
                    .unwrap_or_default()
                    .starts_with("gate://compiler-generated/")
        })
        .count();
    let ffi_sites = unsafe_sites
        .iter()
        .filter(|site| site.kind == "unsafe_import" || site.kind == "unsafe_wrapper")
        .count();
    let pointer_escape_sites = unsafe_sites
        .iter()
        .filter(|site| {
            site.kind.contains("pointer")
                || site
                    .risk_class
                    .as_deref()
                    .is_some_and(|value| value.contains("pointer"))
        })
        .count();

    serde_json::json!({
        "schemaVersion": "fozzylang.unsafe_report.v1",
        "versions": super::compat::compatibility_versions_json(),
        "unsafe_sites": unsafe_sites.len(),
        "reasoned": reasoned,
        "unreasoned": unsafe_sites.len().saturating_sub(reasoned),
        "ffi_sites": ffi_sites,
        "pointer_escape_sites": pointer_escape_sites,
        "strict_safe": true,
        "sites": unsafe_sites.iter().map(|site| {
            serde_json::json!({
                "siteId": site.site_id,
                "kind": site.kind,
                "function": site.function,
                "reason": site.reason,
                "owner": site.owner,
                "scope": site.scope,
                "riskClass": site.risk_class,
                "proofRef": site.proof_ref,
                "asyncContext": site.async_context,
            })
        }).collect::<Vec<_>>(),
    })
}
