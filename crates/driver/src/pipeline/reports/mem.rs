use super::*;

#[derive(Clone)]
pub(crate) struct MemoryOwnerArtifact {
    pub(crate) function: String,
    pub(crate) name: String,
    pub(crate) owner_id: usize,
    pub(crate) created_at: String,
    pub(crate) terminal_state: String,
    pub(crate) terminal_at: Option<String>,
    pub(crate) transfer_edges: Vec<String>,
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct MemoryReport {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    versions: super::compat::CompatibilityVersions,
    functions: Vec<MemoryFunctionReport>,
    owners: Vec<MemoryOwnerRow>,
    moves: Vec<MemoryMoveRow>,
    borrows: Vec<MemoryBorrowRow>,
    owned_handles: Vec<MemoryResourceRow>,
    linear_resources: Vec<MemoryResourceRow>,
    freeze_phases: Vec<MemoryFreezePhaseRow>,
    violations: Vec<MemoryViolation>,
}

#[derive(Clone, serde::Serialize)]
struct MemoryFunctionReport {
    name: String,
    #[serde(rename = "isAsync")]
    is_async: bool,
    #[serde(rename = "isUnsafe")]
    is_unsafe: bool,
    #[serde(rename = "returnType")]
    return_type: String,
    params: Vec<MemoryFunctionParam>,
}

#[derive(Clone, serde::Serialize)]
struct MemoryFunctionParam {
    name: String,
    #[serde(rename = "type")]
    ty: String,
}

#[derive(Clone, serde::Serialize)]
struct MemoryOwnerRow {
    function: String,
    owner: String,
    #[serde(rename = "ownerId")]
    owner_id: usize,
    created_at: String,
    terminal_state: String,
    terminal_at: Option<String>,
    transfer_edges: Vec<String>,
}

#[derive(Clone, serde::Serialize)]
struct MemoryMoveRow {
    function: String,
    #[serde(rename = "ownerId")]
    owner_id: usize,
    edge: String,
}

#[derive(Clone, serde::Serialize)]
struct MemoryBorrowRow {
    function: String,
    name: String,
    kind: BorrowKind,
    #[serde(rename = "lifetimeSource")]
    lifetime_source: Option<String>,
    #[serde(rename = "type")]
    ty: String,
    origin: MemoryOrigin,
}

#[derive(Clone, serde::Serialize)]
struct MemoryResourceRow {
    function: String,
    name: String,
    #[serde(rename = "type")]
    ty: String,
    origin: MemoryOrigin,
}

#[derive(Clone, Copy, serde::Serialize)]
enum BorrowKind {
    #[serde(rename = "mut")]
    Mut,
    #[serde(rename = "shared")]
    Shared,
}

#[derive(Clone, Copy, serde::Serialize)]
enum MemoryOrigin {
    #[serde(rename = "param")]
    Param,
    #[serde(rename = "local")]
    Local,
}

#[derive(Clone, serde::Serialize)]
struct MemoryFreezePhaseRow {
    function: String,
    #[serde(rename = "entryUnfrozen")]
    entry_unfrozen: MemoryFreezeEntry,
    #[serde(rename = "entryFrozen")]
    entry_frozen: MemoryFreezeEntry,
}

#[derive(Clone, Copy, serde::Serialize)]
struct MemoryFreezeEntry {
    #[serde(rename = "mayExitUnfrozen")]
    may_exit_unfrozen: bool,
    #[serde(rename = "mayExitFrozen")]
    may_exit_frozen: bool,
    #[serde(rename = "allocWhileFrozen")]
    alloc_while_frozen: bool,
}

#[derive(Clone, serde::Serialize)]
struct MemoryViolation {
    kind: MemoryViolationKind,
    detail: String,
}

#[derive(Clone, Copy, serde::Serialize)]
enum MemoryViolationKind {
    #[serde(rename = "ownership")]
    Ownership,
    #[serde(rename = "borrow")]
    Borrow,
    #[serde(rename = "linear")]
    Linear,
    #[serde(rename = "freeze_phase")]
    FreezePhase,
}

pub(crate) fn build_memory_report(fir: &fir::FirModule) -> MemoryReport {
    let mut owner_rows = Vec::<MemoryOwnerArtifact>::new();
    let mut functions = Vec::<MemoryFunctionReport>::new();
    let mut borrows = Vec::<MemoryBorrowRow>::new();
    let mut owned_handles = Vec::<MemoryResourceRow>::new();
    let mut linear_resources = Vec::<MemoryResourceRow>::new();
    let freeze_phase_summaries = super::freeze::build_freeze_phase_summaries(fir);
    let freeze_phase_findings =
        super::freeze::collect_freeze_phase_findings(fir, &freeze_phase_summaries);

    for function in &fir.typed_functions {
        functions.push(MemoryFunctionReport {
            name: function.name.clone(),
            is_async: function.is_async,
            is_unsafe: function.is_unsafe,
            return_type: function.return_type.to_string(),
            params: function
                .params
                .iter()
                .map(|param| MemoryFunctionParam {
                    name: param.name.clone(),
                    ty: param.ty.to_string(),
                })
                .collect(),
        });
        collect_function_owner_artifacts(function, &mut owner_rows);
        for param in &function.params {
            if let ast::Type::Ref {
                mutable,
                lifetime,
                to,
            } = &param.ty
            {
                borrows.push(MemoryBorrowRow {
                    function: function.name.clone(),
                    name: param.name.clone(),
                    kind: if *mutable {
                        BorrowKind::Mut
                    } else {
                        BorrowKind::Shared
                    },
                    lifetime_source: lifetime.clone(),
                    ty: to.to_string(),
                    origin: MemoryOrigin::Param,
                });
            }
            if memory_report_is_linear_type(&param.ty) {
                linear_resources.push(MemoryResourceRow {
                    function: function.name.clone(),
                    name: param.name.clone(),
                    ty: param.ty.to_string(),
                    origin: MemoryOrigin::Param,
                });
            } else if memory_report_is_owned_handle_type(&param.ty) {
                owned_handles.push(MemoryResourceRow {
                    function: function.name.clone(),
                    name: param.name.clone(),
                    ty: param.ty.to_string(),
                    origin: MemoryOrigin::Param,
                });
            }
        }
        for (name, ty) in &function.local_types {
            if let ast::Type::Ref {
                mutable,
                lifetime,
                to,
            } = ty
            {
                borrows.push(MemoryBorrowRow {
                    function: function.name.clone(),
                    name: name.clone(),
                    kind: if *mutable {
                        BorrowKind::Mut
                    } else {
                        BorrowKind::Shared
                    },
                    lifetime_source: lifetime.clone(),
                    ty: to.to_string(),
                    origin: MemoryOrigin::Local,
                });
            }
            if memory_report_is_linear_type(ty) {
                linear_resources.push(MemoryResourceRow {
                    function: function.name.clone(),
                    name: name.clone(),
                    ty: ty.to_string(),
                    origin: MemoryOrigin::Local,
                });
            } else if memory_report_is_owned_handle_type(ty) {
                owned_handles.push(MemoryResourceRow {
                    function: function.name.clone(),
                    name: name.clone(),
                    ty: ty.to_string(),
                    origin: MemoryOrigin::Local,
                });
            }
        }
    }

    let owners = owner_rows
        .iter()
        .map(|owner| MemoryOwnerRow {
            function: owner.function.clone(),
            owner: owner.name.clone(),
            owner_id: owner.owner_id,
            created_at: owner.created_at.clone(),
            terminal_state: owner.terminal_state.clone(),
            terminal_at: owner.terminal_at.clone(),
            transfer_edges: owner.transfer_edges.clone(),
        })
        .collect::<Vec<_>>();
    let moves = owner_rows
        .iter()
        .flat_map(|owner| {
            owner.transfer_edges.iter().map(|edge| MemoryMoveRow {
                function: owner.function.clone(),
                owner_id: owner.owner_id,
                edge: edge.clone(),
            })
        })
        .collect::<Vec<_>>();
    let violations = fir
        .ownership_violations
        .iter()
        .map(|detail| MemoryViolation {
            kind: MemoryViolationKind::Ownership,
            detail: detail.clone(),
        })
        .chain(
            fir.reference_lifetime_violations
                .iter()
                .map(|detail| MemoryViolation {
                    kind: MemoryViolationKind::Borrow,
                    detail: detail.clone(),
                }),
        )
        .chain(
            fir.linear_type_violations
                .iter()
                .map(|detail| MemoryViolation {
                    kind: MemoryViolationKind::Linear,
                    detail: detail.clone(),
                }),
        )
        .chain(freeze_phase_findings.iter().map(|finding| MemoryViolation {
            kind: MemoryViolationKind::FreezePhase,
            detail: finding.message.clone(),
        }))
        .collect::<Vec<_>>();
    let freeze_phases = fir
        .typed_functions
        .iter()
        .map(|function| {
            let summary = freeze_phase_summaries
                .get(&function.name)
                .copied()
                .unwrap_or_default();
            MemoryFreezePhaseRow {
                function: function.name.clone(),
                entry_unfrozen: MemoryFreezeEntry {
                    may_exit_unfrozen: summary.exit_from_unfrozen.unfrozen,
                    may_exit_frozen: summary.exit_from_unfrozen.frozen,
                    alloc_while_frozen: summary.alloc_violation_from_unfrozen,
                },
                entry_frozen: MemoryFreezeEntry {
                    may_exit_unfrozen: summary.exit_from_frozen.unfrozen,
                    may_exit_frozen: summary.exit_from_frozen.frozen,
                    alloc_while_frozen: summary.alloc_violation_from_frozen,
                },
            }
        })
        .collect::<Vec<_>>();

    MemoryReport {
        schema_version: "fozzylang.memory_report.v1",
        versions: super::compatibility_versions(),
        functions,
        owners,
        moves,
        borrows,
        owned_handles,
        linear_resources,
        freeze_phases,
        violations,
    }
}

pub(crate) fn render_memory_report_markdown(report: &MemoryReport) -> String {
    let mut out = String::from("# Memory Report\n\n");
    out.push_str(&format!(
        "- Functions: {}\n- Owners: {}\n- Violations: {}\n\n",
        report.functions.len(),
        report.owners.len(),
        report.violations.len(),
    ));
    out.push_str(
        "| Function | Owner | Created At | Terminal State | Terminal At |\n|---|---|---|---|---|\n",
    );
    for owner in &report.owners {
        out.push_str(&format!(
            "| {} | {} | `{}` | {} | `{}` |\n",
            owner.function,
            owner.owner,
            owner.created_at,
            owner.terminal_state,
            owner.terminal_at.as_deref().unwrap_or("-"),
        ));
    }
    out.push_str("\n## Violations\n\n");
    if report.violations.is_empty() {
        out.push_str("_No violations._\n");
    } else {
        for violation in &report.violations {
            out.push_str(&format!(
                "- `{}`: {}\n",
                violation.kind.as_str(),
                violation.detail,
            ));
        }
    }
    if !report.freeze_phases.is_empty() {
        out.push_str("\n## Freeze Phases\n\n");
        out.push_str("| Function | Entry Unfrozen | Entry Frozen |\n|---|---|---|\n");
        for phase in &report.freeze_phases {
            out.push_str(&format!(
                "| {} | `{}` | `{}` |\n",
                phase.function,
                render_memory_freeze_entry(phase.entry_unfrozen),
                render_memory_freeze_entry(phase.entry_frozen),
            ));
        }
    }
    out
}

fn render_memory_freeze_entry(entry: MemoryFreezeEntry) -> String {
    format!(
        "exit(unfrozen={}, frozen={}), allocWhileFrozen={}",
        entry.may_exit_unfrozen, entry.may_exit_frozen, entry.alloc_while_frozen
    )
}

impl MemoryViolationKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ownership => "ownership",
            Self::Borrow => "borrow",
            Self::Linear => "linear",
            Self::FreezePhase => "freeze_phase",
        }
    }
}
