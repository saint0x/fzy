#[derive(Clone, serde::Serialize)]
pub(crate) struct UnsafeReport {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    versions: super::compat::CompatibilityVersions,
    unsafe_sites: usize,
    reasoned: usize,
    unreasoned: usize,
    ffi_sites: usize,
    pointer_escape_sites: usize,
    strict_safe: bool,
    sites: Vec<UnsafeSiteReport>,
}

#[derive(Clone, serde::Serialize)]
struct UnsafeSiteReport {
    #[serde(rename = "siteId")]
    site_id: String,
    kind: String,
    function: String,
    reason: Option<String>,
    owner: Option<String>,
    scope: Option<String>,
    #[serde(rename = "riskClass")]
    risk_class: Option<String>,
    #[serde(skip_serializing)]
    invariant: Option<String>,
    #[serde(rename = "proofRef")]
    proof_ref: Option<String>,
    #[serde(rename = "asyncContext")]
    async_context: bool,
}

pub(crate) fn build_unsafe_report(fir: &fir::FirModule) -> UnsafeReport {
    let sites = fir
        .unsafe_contract_sites
        .iter()
        .filter(|site| site.kind != "unsafe_violation_callsite")
        .map(|site| UnsafeSiteReport {
            site_id: site.site_id.clone(),
            kind: site.kind.clone(),
            function: site.function.clone(),
            reason: site.reason.clone(),
            invariant: site.invariant.clone(),
            owner: site.owner.clone(),
            scope: site.scope.clone(),
            risk_class: site.risk_class.clone(),
            proof_ref: site.proof_ref.clone(),
            async_context: site.async_context,
        })
        .collect::<Vec<_>>();
    let reasoned = sites.iter().filter(|site| site.is_reasoned()).count();
    let ffi_sites = sites
        .iter()
        .filter(|site| site.kind == "unsafe_import" || site.kind == "unsafe_wrapper")
        .count();
    let pointer_escape_sites = sites.iter().filter(|site| site.is_pointer_escape()).count();

    UnsafeReport {
        schema_version: "fozzylang.unsafe_report.v1",
        versions: super::compatibility_versions(),
        unsafe_sites: sites.len(),
        reasoned,
        unreasoned: sites.len().saturating_sub(reasoned),
        ffi_sites,
        pointer_escape_sites,
        strict_safe: true,
        sites,
    }
}

impl UnsafeSiteReport {
    fn is_reasoned(&self) -> bool {
        self.reason
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            && self
                .invariant
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            && self.owner.as_deref().is_some_and(|value| !value.is_empty())
            && self.scope.as_deref().is_some_and(|value| !value.is_empty())
            && self
                .risk_class
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            && self
                .proof_ref
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            && !self
                .proof_ref
                .as_deref()
                .unwrap_or_default()
                .starts_with("gate://compiler-generated/")
    }

    fn is_pointer_escape(&self) -> bool {
        self.kind.contains("pointer")
            || self
                .risk_class
                .as_deref()
                .is_some_and(|value| value.contains("pointer"))
    }
}
