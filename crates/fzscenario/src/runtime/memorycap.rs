//! Deterministic memory capability runtime.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    MemoryGraph, MemoryGraphEdge, MemoryGraphNode, MemoryLeak, MemoryOptions, MemoryRunReport,
    MemorySummary, MemoryTimelineEntry,
};

#[derive(Debug, Clone)]
pub struct AllocRecord {
    pub bytes: u64,
    pub callsite_hash: String,
    pub tag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AllocOutcome {
    pub alloc_id: Option<u64>,
    pub failed_reason: Option<String>,
    pub callsite_hash: String,
}

#[derive(Debug, Clone)]
pub struct MemoryState {
    pub options: MemoryOptions,
    next_alloc_id: u64,
    alloc_ops: u64,
    in_use_bytes: u64,
    peak_bytes: u64,
    live: BTreeMap<u64, AllocRecord>,
    timeline: Vec<MemoryTimelineEntry>,
    graph_nodes: BTreeSet<String>,
    graph_edges: Vec<MemoryGraphEdge>,
    free_count: u64,
    failed_alloc_count: u64,
    pressure_wave_multipliers: Vec<u64>,
    fragmentation_seed: u64,
}

impl MemoryState {
    pub fn new(options: MemoryOptions) -> Self {
        Self {
            pressure_wave_multipliers: parse_pressure_wave(options.pressure_wave.as_deref()),
            fragmentation_seed: options.fragmentation_seed.unwrap_or(0),
            options,
            next_alloc_id: 1,
            alloc_ops: 0,
            in_use_bytes: 0,
            peak_bytes: 0,
            live: BTreeMap::new(),
            timeline: Vec::new(),
            graph_nodes: BTreeSet::new(),
            graph_edges: Vec::new(),
            free_count: 0,
            failed_alloc_count: 0,
        }
    }

    pub fn allocate(
        &mut self,
        bytes: u64,
        tag: Option<String>,
        callsite: &str,
        time_ms: u64,
    ) -> AllocOutcome {
        let callsite_hash = blake3::hash(callsite.as_bytes()).to_hex().to_string();
        self.alloc_ops = self.alloc_ops.saturating_add(1);
        let effective_bytes = self.effective_alloc_bytes(bytes);

        if let Some(limit_mb) = self.options.limit_mb {
            let limit = limit_mb.saturating_mul(1024 * 1024);
            if self.in_use_bytes.saturating_add(effective_bytes) > limit {
                self.failed_alloc_count = self.failed_alloc_count.saturating_add(1);
                self.push_timeline(
                    time_ms,
                    "alloc_fail",
                    vec![
                        ("bytes", serde_json::json!(bytes)),
                        ("effectiveBytes", serde_json::json!(effective_bytes)),
                        ("reason", serde_json::json!("limit_mb")),
                        ("callsiteHash", serde_json::json!(callsite_hash.clone())),
                    ],
                );
                return AllocOutcome {
                    alloc_id: None,
                    failed_reason: Some("limit_mb".to_string()),
                    callsite_hash,
                };
            }
        }

        if let Some(fail_after) = self.options.fail_after_allocs
            && self.alloc_ops > fail_after
        {
            self.failed_alloc_count = self.failed_alloc_count.saturating_add(1);
            self.push_timeline(
                time_ms,
                "alloc_fail",
                vec![
                    ("bytes", serde_json::json!(bytes)),
                    ("effectiveBytes", serde_json::json!(effective_bytes)),
                    ("reason", serde_json::json!("fail_after_allocs")),
                    ("callsiteHash", serde_json::json!(callsite_hash.clone())),
                ],
            );
            return AllocOutcome {
                alloc_id: None,
                failed_reason: Some("fail_after_allocs".to_string()),
                callsite_hash,
            };
        }

        let alloc_id = self.next_alloc_id;
        self.next_alloc_id = self.next_alloc_id.saturating_add(1);
        self.in_use_bytes = self.in_use_bytes.saturating_add(effective_bytes);
        self.peak_bytes = self.peak_bytes.max(self.in_use_bytes);
        self.live.insert(
            alloc_id,
            AllocRecord {
                bytes: effective_bytes,
                callsite_hash: callsite_hash.clone(),
                tag: tag.clone(),
            },
        );
        self.push_timeline(
            time_ms,
            "alloc",
            vec![
                ("allocId", serde_json::json!(alloc_id)),
                ("bytes", serde_json::json!(bytes)),
                ("effectiveBytes", serde_json::json!(effective_bytes)),
                ("inUseBytes", serde_json::json!(self.in_use_bytes)),
                ("callsiteHash", serde_json::json!(callsite_hash.clone())),
                ("tag", serde_json::json!(tag)),
            ],
        );

        let alloc_node = format!("alloc:{alloc_id}");
        let callsite_node = format!("callsite:{callsite_hash}");
        self.graph_nodes.insert(alloc_node.clone());
        self.graph_nodes.insert(callsite_node.clone());
        self.graph_edges.push(MemoryGraphEdge {
            from: callsite_node,
            to: alloc_node,
            kind: "allocates".to_string(),
        });

        AllocOutcome {
            alloc_id: Some(alloc_id),
            failed_reason: None,
            callsite_hash,
        }
    }

    pub fn free(&mut self, alloc_id: u64, time_ms: u64) -> bool {
        let Some(rec) = self.live.remove(&alloc_id) else {
            self.push_timeline(
                time_ms,
                "free_missing",
                vec![("allocId", serde_json::json!(alloc_id))],
            );
            return false;
        };
        self.free_count = self.free_count.saturating_add(1);
        self.in_use_bytes = self.in_use_bytes.saturating_sub(rec.bytes);
        self.push_timeline(
            time_ms,
            "free",
            vec![
                ("allocId", serde_json::json!(alloc_id)),
                ("bytes", serde_json::json!(rec.bytes)),
                ("inUseBytes", serde_json::json!(self.in_use_bytes)),
            ],
        );

        let free_node = format!("free:{alloc_id}");
        self.graph_nodes.insert(free_node.clone());
        self.graph_edges.push(MemoryGraphEdge {
            from: format!("alloc:{alloc_id}"),
            to: free_node,
            kind: "freed_by".to_string(),
        });
        true
    }

    pub fn checkpoint(&mut self, name: &str, time_ms: u64) {
        self.push_timeline(
            time_ms,
            "checkpoint",
            vec![
                ("name", serde_json::json!(name)),
                ("inUseBytes", serde_json::json!(self.in_use_bytes)),
                ("liveAllocs", serde_json::json!(self.live.len() as u64)),
            ],
        );
    }

    pub fn in_use_bytes(&self) -> u64 {
        self.in_use_bytes
    }

    pub fn finalize(self) -> MemoryRunReport {
        let leaks: Vec<MemoryLeak> = self
            .live
            .iter()
            .map(|(id, rec)| MemoryLeak {
                alloc_id: *id,
                bytes: rec.bytes,
                callsite_hash: rec.callsite_hash.clone(),
                tag: rec.tag.clone(),
            })
            .collect();

        let summary = MemorySummary {
            alloc_count: self.alloc_ops,
            free_count: self.free_count,
            failed_alloc_count: self.failed_alloc_count,
            in_use_bytes: self.in_use_bytes,
            peak_bytes: self.peak_bytes,
            leaked_bytes: leaks.iter().map(|l| l.bytes).sum(),
            leaked_allocs: leaks.len() as u64,
        };

        let mut nodes: Vec<MemoryGraphNode> = self
            .graph_nodes
            .iter()
            .map(|id| {
                let (kind, label) = if let Some(rest) = id.strip_prefix("alloc:") {
                    ("alloc", rest)
                } else if let Some(rest) = id.strip_prefix("free:") {
                    ("free", rest)
                } else if let Some(rest) = id.strip_prefix("callsite:") {
                    ("callsite", rest)
                } else {
                    ("node", id.as_str())
                };
                MemoryGraphNode {
                    id: id.clone(),
                    kind: kind.to_string(),
                    label: label.to_string(),
                }
            })
            .collect();
        nodes.sort_by(|a, b| a.id.cmp(&b.id));

        MemoryRunReport {
            schema_version: "fozzy.memory_report.v1".to_string(),
            options: self.options,
            summary,
            leaks,
            timeline: self.timeline,
            graph: MemoryGraph {
                nodes,
                edges: self.graph_edges,
            },
        }
    }

    fn push_timeline(&mut self, time_ms: u64, kind: &str, fields: Vec<(&str, serde_json::Value)>) {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(k.to_string(), v);
        }
        self.timeline.push(MemoryTimelineEntry {
            index: self.timeline.len(),
            time_ms,
            kind: kind.to_string(),
            fields: map,
        });
    }

    fn effective_alloc_bytes(&self, requested: u64) -> u64 {
        let mut scaled = if self.pressure_wave_multipliers.is_empty() {
            requested
        } else {
            let idx = ((self.alloc_ops.saturating_sub(1)) as usize)
                % self.pressure_wave_multipliers.len();
            requested.saturating_mul(self.pressure_wave_multipliers[idx])
        };

        if self.options.fragmentation_seed.is_some() {
            let mut input = [0u8; 24];
            input[0..8].copy_from_slice(&self.fragmentation_seed.to_le_bytes());
            input[8..16].copy_from_slice(&self.alloc_ops.to_le_bytes());
            input[16..24].copy_from_slice(&requested.to_le_bytes());
            let h = blake3::hash(&input);
            let pct = (h.as_bytes()[0] as u64) % 31; // 0..30%
            scaled = scaled.saturating_add((scaled.saturating_mul(pct)) / 100);
        }
        scaled
    }
}

fn parse_pressure_wave(pattern: Option<&str>) -> Vec<u64> {
    let Some(pattern) = pattern else {
        return Vec::new();
    };
    pattern
        .split(',')
        .filter_map(|s| s.trim().parse::<u64>().ok())
        .filter(|m| *m > 0)
        .collect()
}
