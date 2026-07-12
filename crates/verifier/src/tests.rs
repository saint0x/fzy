use core::Capability;
use fir::TypedFunction;

use super::{verify, verify_with_policy, VerifyPolicy};

fn unsafe_site_complete() -> fir::UnsafeContractSite {
    fir::UnsafeContractSite {
        site_id: "usite_test".to_string(),
        kind: "unsafe_block".to_string(),
        function: "main".to_string(),
        snippet: "main: unsafe { ... }".to_string(),
        reason: Some("compiler-generated".to_string()),
        invariant: Some("owner_live(scope_root)".to_string()),
        owner: Some("scope_root".to_string()),
        owner_id: Some("owner::main::scope_root".to_string()),
        scope: Some("main::unsafe_block".to_string()),
        risk_class: Some("memory".to_string()),
        proof_ref: Some("gate://compiler-generated/main/usite_test".to_string()),
        async_context: false,
    }
}

fn unsafe_site_bad_proof_ref() -> fir::UnsafeContractSite {
    fir::UnsafeContractSite {
        proof_ref: Some("bogus://missing".to_string()),
        ..unsafe_site_complete()
    }
}

fn unsafe_site_missing_trace_proof_ref() -> fir::UnsafeContractSite {
    fir::UnsafeContractSite {
        proof_ref: Some("trace:///definitely/missing/path.fozzy#site=usite_test".to_string()),
        ..unsafe_site_complete()
    }
}

fn unsafe_site_existing_trace_proof_ref() -> fir::UnsafeContractSite {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("fozzylang-verifier-proof-ref-{suffix}.fozzy"));
    std::fs::write(&path, "{}").expect("trace file should be written");
    fir::UnsafeContractSite {
        proof_ref: Some(format!("trace://{}#site=usite_test", path.display())),
        ..unsafe_site_complete()
    }
}

fn unsafe_site_bad_owner_id() -> fir::UnsafeContractSite {
    fir::UnsafeContractSite {
        owner_id: Some("owner::wrong::scope_root".to_string()),
        ..unsafe_site_complete()
    }
}

fn unsafe_site_missing() -> fir::UnsafeContractSite {
    fir::UnsafeContractSite {
        site_id: "usite_missing".to_string(),
        kind: "unsafe_block".to_string(),
        function: "main".to_string(),
        snippet: "main: unsafe { ... }".to_string(),
        reason: None,
        invariant: None,
        owner: None,
        owner_id: None,
        scope: None,
        risk_class: None,
        proof_ref: None,
        async_context: false,
    }
}

fn base_module() -> fir::FirModule {
    fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: Vec::new(),
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    }
}

fn extern_c_function(
    name: &str,
    params: Vec<ast::Param>,
    return_type: ast::Type,
    is_unsafe: bool,
) -> TypedFunction {
    TypedFunction {
        name: name.to_string(),
        link_name: None,
        generics: Vec::new(),
        params,
        local_types: std::collections::BTreeMap::new(),
        return_type,
        body: Vec::new(),
        is_unsafe,
        is_async: false,
        is_extern: true,
        execution_space: ast::ExecutionSpace::Host,
        abi: Some("c".to_string()),
        ffi_panic: None,
        is_test: false,
        required_capabilities: Vec::new(),
    }
}

fn rpc_function(name: &str, params: Vec<ast::Param>, return_type: ast::Type) -> TypedFunction {
    TypedFunction {
        name: name.to_string(),
        link_name: Some(name.to_string()),
        generics: Vec::new(),
        params,
        local_types: std::collections::BTreeMap::new(),
        return_type,
        body: Vec::new(),
        is_unsafe: false,
        is_async: false,
        is_extern: true,
        execution_space: ast::ExecutionSpace::Host,
        abi: Some("rpc".to_string()),
        ffi_panic: None,
        is_test: false,
        required_capabilities: Vec::new(),
    }
}

#[test]
fn warns_when_capability_boundary_is_implicit() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: Vec::new(),
        nodes: 1,
        entry_return_type: None,
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 1,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(report.diagnostics.iter().any(|d| d
        .message
        .contains("module has declarations but no explicit capabilities")));
}

#[test]
fn capability_free_host_facade_module_does_not_warn() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: Vec::new(),
        nodes: 1,
        entry_return_type: None,
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 1,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(!report.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("module has declarations but no explicit capabilities")
    }));
}

#[test]
fn rpc_boundary_rejects_borrowed_param_payloads() {
    let mut module = base_module();
    module.typed_functions = vec![rpc_function(
        "Ping",
        vec![ast::Param {
            name: "req".to_string(),
            ty: ast::Type::Ref {
                mutable: false,
                lifetime: None,
                to: Box::new(ast::Type::Str),
            },
        }],
        ast::Type::Int {
            signed: true,
            bits: 32,
        },
    )];

    let report = verify(&module);
    assert!(report.diagnostics.iter().any(|d| {
        d.message
            .contains("RPC method `Ping` parameter `req` uses unsupported payload type `&str`")
    }));
}

#[test]
fn rpc_boundary_rejects_borrowed_return_payloads() {
    let mut module = base_module();
    module.typed_functions = vec![rpc_function(
        "Ping",
        vec![ast::Param {
            name: "req".to_string(),
            ty: ast::Type::Int {
                signed: true,
                bits: 32,
            },
        }],
        ast::Type::Ref {
            mutable: false,
            lifetime: None,
            to: Box::new(ast::Type::Str),
        },
    )];

    let report = verify(&module);
    assert!(report.diagnostics.iter().any(|d| {
        d.message
            .contains("RPC method `Ping` returns unsupported payload type `&str`")
    }));
}

#[test]
fn rpc_boundary_allows_owned_value_payloads() {
    let mut module = base_module();
    module.typed_functions = vec![rpc_function(
        "Ping",
        vec![
            ast::Param {
                name: "req".to_string(),
                ty: ast::Type::Named {
                    name: "PingRequest".to_string(),
                    args: Vec::new(),
                },
            },
            ast::Param {
                name: "retry".to_string(),
                ty: ast::Type::Option(Box::new(ast::Type::Int {
                    signed: true,
                    bits: 32,
                })),
            },
        ],
        ast::Type::Named {
            name: "PingReply".to_string(),
            args: Vec::new(),
        },
    )];

    let report = verify(&module);
    assert!(!report.diagnostics.iter().any(|d| {
        d.message.contains("RPC method `Ping` parameter")
            || d.message
                .contains("RPC method `Ping` returns unsupported payload type")
    }));
}

#[test]
fn pure_helper_module_without_effects_does_not_warn() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: Vec::new(),
        nodes: 1,
        entry_return_type: None,
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(!report.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("module has declarations but no explicit capabilities")
    }));
}

#[test]
fn thread_boundary_borrowed_return_uses_thread_boundary_remediation() {
    let mut module = base_module();
    module.thread_boundary_violations.push(
            "function `worker` returns borrowed reference across thread-capable boundary; return owned/Send-safe handle instead"
                .to_string(),
        );

    let report = verify(&module);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|d| {
            d.message
                .contains("returns borrowed reference across thread-capable boundary")
        })
        .expect("thread-boundary diagnostic");
    let help = diagnostic.help.as_deref().unwrap_or_default();
    assert!(help.contains("return owned values or a Send/Sync-safe handle"));
    assert!(!help.contains("capability token parameters"));
}

#[test]
fn thread_boundary_mutable_param_uses_send_sync_wrapper_guidance() {
    let mut module = base_module();
    module.thread_boundary_violations.push(
        "function `worker` parameter `buf` requires Send/Sync-safe wrapper before thread crossing"
            .to_string(),
    );

    let report = verify(&module);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|d| {
            d.message
                .contains("requires Send/Sync-safe wrapper before thread crossing")
        })
        .expect("thread-boundary diagnostic");
    let help = diagnostic.help.as_deref().unwrap_or_default();
    assert!(help.contains("wrap borrowed references/pointers"));
    assert!(!help.contains("capability token parameters"));
}

#[test]
fn thread_boundary_shared_param_uses_send_sync_wrapper_guidance() {
    let mut module = base_module();
    module.thread_boundary_violations.push(
            "function `worker` parameter `shared` requires Send/Sync-safe wrapper before thread crossing"
                .to_string(),
        );

    let report = verify(&module);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|d| {
            d.message.contains(
                "parameter `shared` requires Send/Sync-safe wrapper before thread crossing",
            )
        })
        .expect("thread-boundary diagnostic");
    let help = diagnostic.help.as_deref().unwrap_or_default();
    assert!(help.contains("wrap borrowed references/pointers"));
    assert!(!help.contains("capability token parameters"));
}

#[test]
fn spawned_closure_borrow_capture_uses_spawn_specific_guidance() {
    let mut module = base_module();
    module.thread_boundary_violations.push(
        "function `main` spawn captures shared borrowed reference `shared` across thread boundary"
            .to_string(),
    );

    let report = verify(&module);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|d| {
            d.message.contains(
                "spawn captures shared borrowed reference `shared` across thread boundary",
            )
        })
        .expect("thread-boundary diagnostic");
    let help = diagnostic.help.as_deref().unwrap_or_default();
    assert!(help.contains("move owned data into the spawned task"));
    assert!(help.contains("wrap borrowed references/pointers"));
}

#[test]
fn capability_token_failures_keep_capability_specific_guidance() {
    let mut module = base_module();
    module
        .capability_token_violations
        .push("function `worker` delegates `fs` without explicit token handoff".to_string());

    let report = verify(&module);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|d| {
            d.message
                .contains("delegates `fs` without explicit token handoff")
        })
        .expect("capability-token diagnostic");
    let help = diagnostic.help.as_deref().unwrap_or_default();
    assert!(help.contains("capability token parameters"));
    assert!(!help.contains("Send/Sync-safe handle"));
}

#[test]
fn errors_for_unknown_capabilities() {
    let mut effects = core::CapabilitySet::default();
    effects.insert(Capability::Time);
    let module = fir::FirModule {
        name: "m".to_string(),
        effects,
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec!["weird".to_string()],
        nodes: 1,
        entry_return_type: None,
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unknown capability")));
}

#[test]
fn grouped_type_errors_use_human_readable_notes() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: None,
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 3,
        type_error_details: vec![
            "let binding `value` type mismatch: expected `i32`, got `str`".to_string(),
            "unresolved call target `missing_symbol`".to_string(),
            "unresolved call target `missing_symbol`".to_string(),
        ],
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("type-check failed"))
        .expect("grouped type diagnostic should be present");
    assert!(diagnostic
        .notes
        .iter()
        .any(|note| note.contains("detected 3 type-check failure(s)")));
    assert!(diagnostic
        .notes
        .iter()
        .any(|note| note.contains("additional grouped root cause: unresolved call target")));
    assert!(diagnostic
        .notes
        .iter()
        .all(|note| !note.contains("type_error_count=")));
}

#[test]
fn grouped_type_errors_do_not_repeat_primary_root_cause() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: None,
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 3,
        type_error_details: vec![
            "let binding `value` type mismatch: expected `i32`, got `str`".to_string(),
            "let binding `value` type mismatch: expected `i32`, got `str`".to_string(),
            "unresolved call target `missing_symbol`".to_string(),
        ],
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("type-check failed"))
        .expect("grouped type diagnostic should be present");
    assert!(diagnostic.notes.iter().any(|note| {
        note.contains("additional grouped root cause: unresolved call target `missing_symbol`")
    }));
    assert!(!diagnostic.notes.iter().any(|note| {
            note.contains(
                "additional grouped root cause: let binding `value` type mismatch: expected `i32`, got `str`",
            )
        }));
}

#[test]
fn invalid_capability_import_does_not_emit_missing_capability_warning() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec!["text".to_string()],
        nodes: 1,
        entry_return_type: None,
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("unknown capability: text")));
    assert!(!report.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("module has declarations but no explicit capabilities")
    }));
}

#[test]
fn removed_api_type_diagnostics_surface_fix_text() {
    let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: None,
            entry_return_const_i32: None,
            entry_has_return_expr: false,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 1,
            type_error_details: vec![
                "unresolved call target `json.object3` (autofix: use `json.object(map_handle)` instead)"
                    .to_string(),
            ],
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
    let report = verify(&module);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("type-check failed"))
        .expect("grouped type diagnostic should be present");
    assert_eq!(
        diagnostic.fix.as_deref(),
        Some(
            "replace fixed-arity call by building a map with `map.new()/map.set(...)`, then pass that map to `json.object(...)` only at the boundary"
        )
    );
    assert!(diagnostic
        .suggested_fixes
        .iter()
        .any(|fix| fix.contains("map.new()/map.set(...)")));
}

#[test]
fn grouped_nojson_decode_chain_errors_include_boundary_fix() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: None,
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 1,
        type_error_details: vec![
            "NOJSON: `json.parse(http.body(...))`-style internal decode chaining is forbidden in production code; decode once at the boundary with `http.body_json(...)`/`http.body_bind(...)` or map the transport body into typed domain values before internal logic".to_string(),
        ],
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("NOJSON"))
        .expect("grouped type diagnostic should be present");
    assert_eq!(
        diagnostic.fix.as_deref(),
        Some(
            "replace the decode chain with `http.body_json(...)`/`http.body_bind(...)`, then translate the boundary payload into typed domain values before internal use"
        )
    );
}

#[test]
fn removed_log_fields_arity_guidance_uses_map_builder_fix() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: None,
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 1,
        type_error_details: vec![
            "unresolved call target `log.fields2` (autofix: use `log.fields(map_handle)` instead)"
                .to_string(),
        ],
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("type-check failed"))
        .expect("grouped type diagnostic should be present");
    assert_eq!(
        diagnostic.fix.as_deref(),
        Some(
            "replace removed arity helper by building a map with `map.new()/map.set(...)`, then pass that map to `log.fields(...)`"
        )
    );
}

#[test]
fn errors_when_required_capability_missing() {
    let mut required = core::CapabilitySet::default();
    required.insert(Capability::Http);
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: required,
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: None,
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("missing required capability: http")));
}

#[test]
fn errors_when_i32_main_has_no_return_expr() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: None,
        entry_has_return_expr: false,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("main must return a `i32`")));
}

#[test]
fn errors_for_linear_type_violations() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: vec!["socket_res".to_string()],
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: vec![
            "function `main` linear value `socket_res` was not consumed/freed".to_string(),
        ],
    };
    let report = verify(&module);
    assert!(report.diagnostics.iter().any(|d| d
        .message
        .contains("function `main` linear value `socket_res` was not consumed/freed")));
}

#[test]
fn warns_for_non_exhaustive_match_baseline() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 1,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("non-exhaustive")));
}

#[test]
fn errors_for_unreachable_and_duplicate_match_catchalls() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 2,
        match_duplicate_catchall_arms: 1,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unreachable")));
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("duplicate catch-all")));
}

#[test]
fn safe_profile_rejects_unsafe_capabilities() {
    let mut effects = core::CapabilitySet::default();
    effects.insert(Capability::Http);
    effects.insert(Capability::Thread);
    let module = fir::FirModule {
        name: "m".to_string(),
        effects,
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            safe_profile: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("safe profile forbids capability: http")));
    assert!(report.diagnostics.iter().any(|d| d
        .message
        .contains("safe profile forbids capability: thread")));
}

#[test]
fn safe_profile_rejects_all_runtime_backed_effects() {
    let mut effects = core::CapabilitySet::default();
    for capability in [
        Capability::Time,
        Capability::Random,
        Capability::FileSystem,
        Capability::Storage,
        Capability::Http,
        Capability::Process,
        Capability::Memory,
        Capability::Thread,
    ] {
        effects.insert(capability);
    }
    let module = fir::FirModule {
        name: "m".to_string(),
        effects,
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            safe_profile: true,
            ..VerifyPolicy::default()
        },
    );
    for expected in [
        "time", "rng", "fs", "storage", "http", "proc", "mem", "thread",
    ] {
        assert!(report.diagnostics.iter().any(|d| d
            .message
            .contains(&format!("safe profile forbids capability: {expected}"))));
    }
}

#[test]
fn contract_false_conditions_error() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: vec![Some(false)],
        entry_ensures: vec![Some(false)],
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("requires[0] is statically false")));
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("ensures[0] is statically false")));
}

#[test]
fn host_syscall_requires_abi_boundary() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: vec![],
        entry_ensures: vec![],
        host_syscall_sites: 1,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 1,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify(&module);
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("ext c fn")));
}

#[test]
fn safe_extern_c_pointer_param_requires_unsafe_boundary() {
    let mut module = base_module();
    module.typed_functions.push(extern_c_function(
        "c_read",
        vec![ast::Param {
            name: "buf".to_string(),
            ty: ast::Type::Ptr {
                mutable: false,
                to: Box::new(ast::Type::Int {
                    signed: false,
                    bits: 8,
                }),
            },
        }],
        ast::Type::Int {
            signed: true,
            bits: 32,
        },
        false,
    ));

    let report = verify(&module);
    assert!(report.diagnostics.iter().any(|d| {
        d.message
            .contains("extern C import `c_read` exposes pointer-like contract")
    }));
}

#[test]
fn safe_extern_c_borrowed_pointer_param_requires_unsafe_boundary() {
    let mut module = base_module();
    module.typed_functions.push(extern_c_function(
        "c_read_borrowed",
        vec![ast::Param {
            name: "buf_borrowed".to_string(),
            ty: ast::Type::Ptr {
                mutable: false,
                to: Box::new(ast::Type::Int {
                    signed: false,
                    bits: 8,
                }),
            },
        }],
        ast::Type::Int {
            signed: true,
            bits: 32,
        },
        false,
    ));

    let report = verify(&module);
    assert!(report.diagnostics.iter().any(|d| {
        d.message
            .contains("extern C import `c_read_borrowed` exposes pointer-like contract")
    }));
}

#[test]
fn safe_extern_c_mixed_pointer_signature_requires_unsafe_boundary() {
    let mut module = base_module();
    module.typed_functions.push(extern_c_function(
        "acquire_and_fill",
        vec![ast::Param {
            name: "out_ptr".to_string(),
            ty: ast::Type::Ptr {
                mutable: true,
                to: Box::new(ast::Type::Int {
                    signed: false,
                    bits: 8,
                }),
            },
        }],
        ast::Type::Ptr {
            mutable: false,
            to: Box::new(ast::Type::Int {
                signed: false,
                bits: 8,
            }),
        },
        false,
    ));

    let report = verify(&module);
    assert!(report.diagnostics.iter().any(|d| {
        d.message
            .contains("extern C import `acquire_and_fill` exposes pointer-like contract")
    }));
}

#[test]
fn callback_extern_c_import_without_context_anchor_fails() {
    let mut module = base_module();
    module.typed_functions.push(extern_c_function(
        "register",
        vec![
            ast::Param {
                name: "cb_owned".to_string(),
                ty: ast::Type::Ptr {
                    mutable: false,
                    to: Box::new(ast::Type::Int {
                        signed: false,
                        bits: 8,
                    }),
                },
            },
            ast::Param {
                name: "cb".to_string(),
                ty: ast::Type::Function {
                    params: vec![ast::Type::Int {
                        signed: true,
                        bits: 32,
                    }],
                    ret: Box::new(ast::Type::Int {
                        signed: true,
                        bits: 32,
                    }),
                },
            },
        ],
        ast::Type::Int {
            signed: true,
            bits: 32,
        },
        true,
    ));

    let report = verify(&module);
    assert!(report.diagnostics.iter().any(|d| {
        d.message
            .contains("callback parameter `cb` requires an adjacent `*_ctx` or `*_context` anchor")
    }));
}

#[test]
fn callback_extern_c_import_with_adjacent_context_anchor_passes_structural_check() {
    let mut module = base_module();
    module.typed_functions.push(extern_c_function(
        "register",
        vec![
            ast::Param {
                name: "cb_ctx".to_string(),
                ty: ast::Type::Ptr {
                    mutable: false,
                    to: Box::new(ast::Type::Void),
                },
            },
            ast::Param {
                name: "cb".to_string(),
                ty: ast::Type::Function {
                    params: vec![ast::Type::Int {
                        signed: true,
                        bits: 32,
                    }],
                    ret: Box::new(ast::Type::Int {
                        signed: true,
                        bits: 32,
                    }),
                },
            },
        ],
        ast::Type::Int {
            signed: true,
            bits: 32,
        },
        true,
    ));

    let report = verify(&module);
    assert!(!report.diagnostics.iter().any(|d| {
        d.message
            .contains("callback parameter `cb` requires an adjacent `*_ctx` or `*_context` anchor")
    }));
}

#[test]
fn safe_profile_rejects_alloc_free_imbalance() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: vec![],
        entry_ensures: vec![],
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 2,
        free_sites: 1,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            safe_profile: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("memory lifecycle imbalance")));
}

#[test]
fn production_memory_safety_rejects_alloc_free_imbalance_without_safe_profile() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: vec![],
        entry_ensures: vec![],
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 2,
        free_sites: 1,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            production_memory_safety: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("memory lifecycle imbalance")));
}

#[test]
fn production_memory_safety_does_not_forbid_runtime_capability_set() {
    let mut effects = core::CapabilitySet::default();
    effects.insert(Capability::Http);
    let module = fir::FirModule {
        name: "m".to_string(),
        effects,
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: vec![],
        entry_ensures: vec![],
        host_syscall_sites: 0,
        unsafe_sites: 0,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: Vec::new(),
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            production_memory_safety: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(!report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("safe profile forbids capability")));
}

#[test]
fn production_mode_allows_unsafe_sites_with_warnings() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 1,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: vec![unsafe_site_complete()],
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            production_memory_safety: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(report.diagnostics.iter().any(|d| d.message.contains(
            "compiler unsafe-policy checks passed, and structural unsafe contract metadata is present for all sites"
        )));
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d
            .help
            .as_deref()
            .is_some_and(|help| help
                .contains("the compiler is satisfied with the current unsafe-policy checks"))));
    assert!(report.is_clean());
}

#[test]
fn production_mode_distinguishes_placeholder_unsafe_contracts_from_reasoned_evidence() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 1,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: vec![unsafe_site_complete()],
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            production_memory_safety: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(report.diagnostics.iter().any(|d| d.message.contains(
            "compiler unsafe-policy checks passed, and structural unsafe contract metadata is present for all sites"
        )));
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d
            .help
            .as_deref()
            .is_some_and(|help| help
                .contains("the compiler is satisfied with the current unsafe-policy checks"))));
    assert!(!report.diagnostics.iter().any(|d| {
        d.message.contains(
            "detected 1 explicit unsafe escape marker(s); compiler contract checks passed",
        )
    }));
    assert!(report.is_clean());
}

#[test]
fn safe_profile_rejects_unsafe_sites() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 1,
        unsafe_reasoned_sites: 1,
        unsafe_contract_sites: vec![unsafe_site_complete()],
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            safe_profile: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(!report.is_clean());
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unsafe escape marker")));
}

#[test]
fn strict_unsafe_contracts_reject_missing_metadata() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 1,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: vec![unsafe_site_missing()],
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            strict_unsafe_contracts: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(!report.is_clean());
    assert!(report.diagnostics.iter().any(|d| {
        matches!(d.severity, diagnostics::Severity::Error)
            && d.message
                .contains("unsafe escape site(s) missing required contract fields")
    }));
}

#[test]
fn strict_unsafe_contracts_reject_malformed_proof_refs() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 1,
        unsafe_reasoned_sites: 1,
        unsafe_contract_sites: vec![unsafe_site_bad_proof_ref()],
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            strict_unsafe_contracts: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("malformed proof references")));
    assert!(!report.is_clean());
}

#[test]
fn strict_unsafe_contracts_reject_missing_trace_artifact_proof_refs() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 1,
        unsafe_reasoned_sites: 1,
        unsafe_contract_sites: vec![unsafe_site_missing_trace_proof_ref()],
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            strict_unsafe_contracts: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("malformed proof references")));
    assert!(!report.is_clean());
}

#[test]
fn strict_unsafe_contracts_accept_existing_trace_artifact_proof_refs() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 1,
        unsafe_reasoned_sites: 1,
        unsafe_contract_sites: vec![unsafe_site_existing_trace_proof_ref()],
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            strict_unsafe_contracts: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(!report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("malformed proof references")));
    assert!(report.is_clean());
    if let Some(path) = module.unsafe_contract_sites[0]
        .proof_ref
        .as_deref()
        .and_then(|proof_ref| proof_ref.strip_prefix("trace://"))
        .and_then(|rest| rest.split('#').next())
    {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn strict_unsafe_contracts_reject_malformed_owner_ids() {
    let module = fir::FirModule {
        name: "m".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 1,
        unsafe_reasoned_sites: 1,
        unsafe_contract_sites: vec![unsafe_site_bad_owner_id()],
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            strict_unsafe_contracts: true,
            ..VerifyPolicy::default()
        },
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("malformed owner identity metadata")));
    assert!(!report.is_clean());
}

#[test]
fn deny_unsafe_scope_rejects_module() {
    let module = fir::FirModule {
        name: "tests::smoke".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 1,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: vec![unsafe_site_complete()],
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            deny_unsafe_in: vec!["tests::*".to_string()],
            ..VerifyPolicy::default()
        },
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unsafe usage is denied in module")));
}

#[test]
fn allowlist_unsafe_scope_rejects_non_allowlisted_module() {
    let module = fir::FirModule {
        name: "tests::smoke".to_string(),
        effects: core::CapabilitySet::default(),
        required_effects: core::CapabilitySet::default(),
        unknown_effects: vec![],
        nodes: 1,
        entry_return_type: Some(ast::Type::Int {
            signed: true,
            bits: 32,
        }),
        entry_return_const_i32: Some(0),
        entry_has_return_expr: true,
        linear_resources: Vec::new(),
        deferred_resources: Vec::new(),
        matches_without_wildcard: 0,
        match_unreachable_arms: 0,
        match_duplicate_catchall_arms: 0,
        entry_requires: Vec::new(),
        entry_ensures: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 1,
        unsafe_reasoned_sites: 0,
        unsafe_contract_sites: vec![unsafe_site_complete()],
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
        extern_c_abi_functions: 0,
        repr_c_layout_items: 0,
        generic_instantiations: Vec::new(),
        generic_specializations: Vec::new(),
        call_graph: Vec::new(),
        functions: Vec::new(),
        typed_functions: Vec::new(),
        typed_globals: Vec::new(),
        struct_defs: std::collections::HashMap::new(),
        enum_defs: std::collections::HashMap::new(),
        type_errors: 0,
        type_error_details: Vec::new(),
        function_capability_requirements: Vec::new(),
        ownership_violations: Vec::new(),
        unsafe_context_violations: Vec::new(),
        capability_token_violations: Vec::new(),
        thread_boundary_violations: Vec::new(),
        trait_violations: Vec::new(),
        reference_lifetime_violations: Vec::new(),
        linear_type_violations: Vec::new(),
    };
    let report = verify_with_policy(
        &module,
        VerifyPolicy {
            allow_unsafe_in: vec!["runtime::*".to_string()],
            ..VerifyPolicy::default()
        },
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("not in allowlisted unsafe scope")));
}
