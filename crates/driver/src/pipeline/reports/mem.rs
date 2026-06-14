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

pub(super) fn build_memory_report_json(fir: &fir::FirModule) -> serde_json::Value {
    let mut owner_rows = Vec::<MemoryOwnerArtifact>::new();
    let mut functions = Vec::<serde_json::Value>::new();
    let mut borrows = Vec::<serde_json::Value>::new();
    let mut owned_handles = Vec::<serde_json::Value>::new();
    let mut linear_resources = Vec::<serde_json::Value>::new();
    let freeze_phase_summaries = super::freeze::build_freeze_phase_summaries(fir);
    let freeze_phase_findings =
        super::freeze::collect_freeze_phase_findings(fir, &freeze_phase_summaries);

    for function in &fir.typed_functions {
        functions.push(serde_json::json!({
            "name": function.name,
            "isAsync": function.is_async,
            "isUnsafe": function.is_unsafe,
            "returnType": function.return_type.to_string(),
            "params": function.params.iter().map(|param| {
                serde_json::json!({
                    "name": param.name,
                    "type": param.ty.to_string(),
                })
            }).collect::<Vec<_>>(),
        }));
        collect_function_owner_artifacts(function, &mut owner_rows);
        for param in &function.params {
            if let ast::Type::Ref {
                mutable,
                lifetime,
                to,
            } = &param.ty
            {
                borrows.push(serde_json::json!({
                    "function": function.name,
                    "name": param.name,
                    "kind": if *mutable { "mut" } else { "shared" },
                    "lifetimeSource": lifetime,
                    "type": to.to_string(),
                    "origin": "param",
                }));
            }
            if memory_report_is_linear_type(&param.ty) {
                linear_resources.push(serde_json::json!({
                    "function": function.name,
                    "name": param.name,
                    "type": param.ty.to_string(),
                    "origin": "param",
                }));
            } else if memory_report_is_owned_handle_type(&param.ty) {
                owned_handles.push(serde_json::json!({
                    "function": function.name,
                    "name": param.name,
                    "type": param.ty.to_string(),
                    "origin": "param",
                }));
            }
        }
        for (name, ty) in &function.local_types {
            if let ast::Type::Ref {
                mutable,
                lifetime,
                to,
            } = ty
            {
                borrows.push(serde_json::json!({
                    "function": function.name,
                    "name": name,
                    "kind": if *mutable { "mut" } else { "shared" },
                    "lifetimeSource": lifetime,
                    "type": to.to_string(),
                    "origin": "local",
                }));
            }
            if memory_report_is_linear_type(ty) {
                linear_resources.push(serde_json::json!({
                    "function": function.name,
                    "name": name,
                    "type": ty.to_string(),
                    "origin": "local",
                }));
            } else if memory_report_is_owned_handle_type(ty) {
                owned_handles.push(serde_json::json!({
                    "function": function.name,
                    "name": name,
                    "type": ty.to_string(),
                    "origin": "local",
                }));
            }
        }
    }

    let owners = owner_rows
        .iter()
        .map(|owner| {
            serde_json::json!({
                "function": owner.function,
                "owner": owner.name,
                "ownerId": owner.owner_id,
                "created_at": owner.created_at,
                "terminal_state": owner.terminal_state,
                "terminal_at": owner.terminal_at,
                "transfer_edges": owner.transfer_edges,
            })
        })
        .collect::<Vec<_>>();
    let moves = owner_rows
        .iter()
        .flat_map(|owner| {
            owner.transfer_edges.iter().map(|edge| {
                serde_json::json!({
                    "function": owner.function,
                    "ownerId": owner.owner_id,
                    "edge": edge,
                })
            })
        })
        .collect::<Vec<_>>();
    let violations = fir
        .ownership_violations
        .iter()
        .map(|detail| serde_json::json!({ "kind": "ownership", "detail": detail }))
        .chain(
            fir.reference_lifetime_violations
                .iter()
                .map(|detail| serde_json::json!({ "kind": "borrow", "detail": detail })),
        )
        .chain(
            fir.linear_type_violations
                .iter()
                .map(|detail| serde_json::json!({ "kind": "linear", "detail": detail })),
        )
        .chain(freeze_phase_findings.iter().map(|finding| {
            serde_json::json!({
                "kind": "freeze_phase",
                "detail": finding.message,
            })
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
            serde_json::json!({
                "function": function.name,
                "entryUnfrozen": {
                    "mayExitUnfrozen": summary.exit_from_unfrozen.unfrozen,
                    "mayExitFrozen": summary.exit_from_unfrozen.frozen,
                    "allocWhileFrozen": summary.alloc_violation_from_unfrozen,
                },
                "entryFrozen": {
                    "mayExitUnfrozen": summary.exit_from_frozen.unfrozen,
                    "mayExitFrozen": summary.exit_from_frozen.frozen,
                    "allocWhileFrozen": summary.alloc_violation_from_frozen,
                },
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "schemaVersion": "fozzylang.memory_report.v1",
        "versions": super::compat::compatibility_versions_json(),
        "functions": functions,
        "owners": owners,
        "moves": moves,
        "borrows": borrows,
        "owned_handles": owned_handles,
        "linear_resources": linear_resources,
        "freeze_phases": freeze_phases,
        "violations": violations,
    })
}

pub(super) fn render_memory_report_markdown(value: &serde_json::Value) -> String {
    let mut out = String::from("# Memory Report\n\n");
    let function_count = value["functions"].as_array().map(|v| v.len()).unwrap_or(0);
    let owner_count = value["owners"].as_array().map(|v| v.len()).unwrap_or(0);
    let violation_count = value["violations"].as_array().map(|v| v.len()).unwrap_or(0);
    out.push_str(&format!(
        "- Functions: {function_count}\n- Owners: {owner_count}\n- Violations: {violation_count}\n\n"
    ));
    out.push_str(
        "| Function | Owner | Created At | Terminal State | Terminal At |\n|---|---|---|---|---|\n",
    );
    if let Some(owners) = value["owners"].as_array() {
        for owner in owners {
            out.push_str(&format!(
                "| {} | {} | `{}` | {} | `{}` |\n",
                owner["function"].as_str().unwrap_or("?"),
                owner["owner"].as_str().unwrap_or("?"),
                owner["created_at"].as_str().unwrap_or("?"),
                owner["terminal_state"].as_str().unwrap_or("?"),
                owner["terminal_at"].as_str().unwrap_or("-"),
            ));
        }
    }
    out.push_str("\n## Violations\n\n");
    if let Some(violations) = value["violations"].as_array() {
        if violations.is_empty() {
            out.push_str("_No violations._\n");
        } else {
            for violation in violations {
                out.push_str(&format!(
                    "- `{}`: {}\n",
                    violation["kind"].as_str().unwrap_or("unknown"),
                    violation["detail"].as_str().unwrap_or("missing"),
                ));
            }
        }
    }
    if let Some(phases) = value["freeze_phases"].as_array() {
        out.push_str("\n## Freeze Phases\n\n");
        out.push_str("| Function | Entry Unfrozen | Entry Frozen |\n|---|---|---|\n");
        for phase in phases {
            let unfrozen = format!(
                "exit(unfrozen={}, frozen={}), allocWhileFrozen={}",
                phase["entryUnfrozen"]["mayExitUnfrozen"]
                    .as_bool()
                    .unwrap_or(false),
                phase["entryUnfrozen"]["mayExitFrozen"]
                    .as_bool()
                    .unwrap_or(false),
                phase["entryUnfrozen"]["allocWhileFrozen"]
                    .as_bool()
                    .unwrap_or(false),
            );
            let frozen = format!(
                "exit(unfrozen={}, frozen={}), allocWhileFrozen={}",
                phase["entryFrozen"]["mayExitUnfrozen"]
                    .as_bool()
                    .unwrap_or(false),
                phase["entryFrozen"]["mayExitFrozen"]
                    .as_bool()
                    .unwrap_or(false),
                phase["entryFrozen"]["allocWhileFrozen"]
                    .as_bool()
                    .unwrap_or(false),
            );
            out.push_str(&format!(
                "| {} | `{}` | `{}` |\n",
                phase["function"].as_str().unwrap_or("?"),
                unfrozen,
                frozen,
            ));
        }
    }
    out
}
