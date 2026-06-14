#[derive(Debug, Clone, Copy)]
pub(super) struct NativeRuntimeImport {
    pub(super) callee: &'static str,
    pub(super) symbol: &'static str,
    pub(super) arity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NativeRuntimeImportContract {
    pub(super) callee: &'static str,
    pub(super) symbol: &'static str,
    pub(super) arity: usize,
    pub(super) arg_ownership: &'static str,
    pub(super) return_ownership: &'static str,
    pub(super) required_capability: &'static str,
    pub(super) linearity: &'static str,
    pub(super) error_behavior: &'static str,
    pub(super) trace_behavior: &'static str,
    pub(super) blocking_behavior: &'static str,
}

#[path = "native_runtime_tables/runtime.rs"]
mod runtime;
#[path = "native_runtime_tables/data.rs"]
mod data;
#[path = "native_runtime_tables/contract.rs"]
mod contract;

pub(super) use self::contract::*;
pub(super) use self::data::*;
pub(super) use self::runtime::*;
