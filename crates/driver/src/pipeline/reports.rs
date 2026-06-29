use super::*;

#[path = "reports/async.rs"]
mod async_report;
#[path = "reports/compat.rs"]
mod compat;
#[path = "reports/freeze.rs"]
mod freeze;
#[path = "reports/mem.rs"]
mod mem;
#[path = "reports/unsafe.rs"]
mod unsafe_report;

pub(crate) use self::freeze::{
    build_freeze_phase_summaries, collect_freeze_phase_findings, is_memory_phase_alloc_like_callee,
};
pub(crate) use self::mem::MemoryOwnerArtifact;

pub(super) fn compatibility_versions_json() -> serde_json::Value {
    compat::compatibility_versions_json()
}

pub(super) fn build_memory_report_json(fir: &fir::FirModule) -> serde_json::Value {
    mem::build_memory_report_json(fir)
}

pub(super) fn render_memory_report_markdown(value: &serde_json::Value) -> String {
    mem::render_memory_report_markdown(value)
}

pub(super) fn build_unsafe_report_json(fir: &fir::FirModule) -> serde_json::Value {
    unsafe_report::build_unsafe_report_json(fir)
}

pub(super) fn build_async_safety_json(fir: &fir::FirModule) -> serde_json::Value {
    async_report::build_async_safety_json(fir)
}
