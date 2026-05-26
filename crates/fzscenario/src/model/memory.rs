//! Memory capability models and deterministic memory artifacts.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use crate::FozzyResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemoryOptions {
    pub track: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_after_allocs: Option<u64>,
    pub fail_on_leak: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leak_budget_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragmentation_seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pressure_wave: Option<String>,
    pub artifacts: bool,
}

impl Default for MemoryOptions {
    fn default() -> Self {
        Self {
            track: true,
            limit_mb: None,
            fail_after_allocs: None,
            fail_on_leak: false,
            leak_budget_bytes: None,
            fragmentation_seed: None,
            pressure_wave: None,
            artifacts: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct MemorySummary {
    #[serde(rename = "allocCount")]
    pub alloc_count: u64,
    #[serde(rename = "freeCount")]
    pub free_count: u64,
    #[serde(rename = "failedAllocCount")]
    pub failed_alloc_count: u64,
    #[serde(rename = "inUseBytes")]
    pub in_use_bytes: u64,
    #[serde(rename = "peakBytes")]
    pub peak_bytes: u64,
    #[serde(rename = "leakedBytes")]
    pub leaked_bytes: u64,
    #[serde(rename = "leakedAllocs")]
    pub leaked_allocs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLeak {
    #[serde(rename = "allocId")]
    pub alloc_id: u64,
    pub bytes: u64,
    #[serde(rename = "callsiteHash")]
    pub callsite_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryTimelineEntry {
    pub index: usize,
    #[serde(rename = "timeMs")]
    pub time_ms: u64,
    pub kind: String,
    pub fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGraphNode {
    pub id: String,
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGraphEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryGraph {
    pub nodes: Vec<MemoryGraphNode>,
    pub edges: Vec<MemoryGraphEdge>,
}

impl MemoryGraph {
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.edges.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRunReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub options: MemoryOptions,
    pub summary: MemorySummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaks: Vec<MemoryLeak>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timeline: Vec<MemoryTimelineEntry>,
    #[serde(default)]
    pub graph: MemoryGraph,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryTrace {
    pub options: MemoryOptions,
    pub summary: MemorySummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaks: Vec<MemoryLeak>,
    #[serde(default, skip_serializing_if = "MemoryGraph::is_empty")]
    pub graph: MemoryGraph,
}

impl MemoryRunReport {
    pub fn to_trace(&self) -> MemoryTrace {
        MemoryTrace {
            options: self.options.clone(),
            summary: self.summary.clone(),
            leaks: self.leaks.clone(),
            graph: self.graph.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDelta {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "beforeLeakedBytes")]
    pub before_leaked_bytes: u64,
    #[serde(rename = "afterLeakedBytes")]
    pub after_leaked_bytes: u64,
    #[serde(rename = "beforeLeakedAllocs")]
    pub before_leaked_allocs: u64,
    #[serde(rename = "afterLeakedAllocs")]
    pub after_leaked_allocs: u64,
    #[serde(rename = "beforeAllocCount")]
    pub before_alloc_count: u64,
    #[serde(rename = "afterAllocCount")]
    pub after_alloc_count: u64,
}

pub fn write_memory_artifacts(report: &MemoryRunReport, artifacts_dir: &Path) -> FozzyResult<()> {
    std::fs::create_dir_all(artifacts_dir)?;
    std::fs::write(
        artifacts_dir.join("memory.timeline.json"),
        serde_json::to_vec_pretty(&report.timeline)?,
    )?;
    std::fs::write(
        artifacts_dir.join("memory.leaks.json"),
        serde_json::to_vec_pretty(&report.leaks)?,
    )?;
    std::fs::write(
        artifacts_dir.join("memory.graph.json"),
        serde_json::to_vec_pretty(&report.graph)?,
    )?;
    Ok(())
}

pub fn write_memory_delta_artifact(
    before: &MemoryRunReport,
    after: &MemoryRunReport,
    out_path: &Path,
) -> FozzyResult<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let delta = MemoryDelta {
        schema_version: "fozzy.memory_delta.v1".to_string(),
        before_leaked_bytes: before.summary.leaked_bytes,
        after_leaked_bytes: after.summary.leaked_bytes,
        before_leaked_allocs: before.summary.leaked_allocs,
        after_leaked_allocs: after.summary.leaked_allocs,
        before_alloc_count: before.summary.alloc_count,
        after_alloc_count: after.summary.alloc_count,
    };
    std::fs::write(out_path, serde_json::to_vec_pretty(&delta)?)?;
    Ok(())
}
