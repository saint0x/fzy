//! Memory artifact/report commands (`fozzy memory ...`).

use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{
    Config, ExitStatus, FozzyError, FozzyResult, MemoryGraph, MemoryLeak, MemorySummary, TraceFile,
};

#[derive(Debug, Subcommand)]
pub enum MemoryCommand {
    /// Show/export allocation graph for a run or trace
    Graph {
        #[arg(value_name = "RUN_OR_TRACE")]
        run: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Compare memory outcomes between two runs/traces
    Diff {
        #[arg(value_name = "LEFT_RUN_OR_TRACE")]
        left: String,
        #[arg(value_name = "RIGHT_RUN_OR_TRACE")]
        right: String,
    },
    /// Show top leak records by leaked bytes
    Top {
        #[arg(value_name = "RUN_OR_TRACE")]
        run: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDiff {
    pub left: String,
    pub right: String,
    #[serde(rename = "leftLeakedBytes")]
    pub left_leaked_bytes: u64,
    #[serde(rename = "rightLeakedBytes")]
    pub right_leaked_bytes: u64,
    #[serde(rename = "leftLeakedAllocs")]
    pub left_leaked_allocs: u64,
    #[serde(rename = "rightLeakedAllocs")]
    pub right_leaked_allocs: u64,
    #[serde(rename = "leftPeakBytes")]
    pub left_peak_bytes: u64,
    #[serde(rename = "rightPeakBytes")]
    pub right_peak_bytes: u64,
    #[serde(rename = "deltaLeakedBytes")]
    pub delta_leaked_bytes: i64,
    #[serde(rename = "deltaLeakedAllocs")]
    pub delta_leaked_allocs: i64,
    #[serde(rename = "deltaPeakBytes")]
    pub delta_peak_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryTop {
    pub run: String,
    pub limit: usize,
    pub total: usize,
    pub leaks: Vec<MemoryLeak>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGraphOutput {
    pub run: String,
    pub graph: MemoryGraph,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemoryBundle {
    summary: MemorySummary,
    leaks: Vec<MemoryLeak>,
    graph: MemoryGraph,
}

pub fn memory_command(config: &Config, command: &MemoryCommand) -> FozzyResult<serde_json::Value> {
    match command {
        MemoryCommand::Graph { run, out } => {
            let bundle = load_memory_bundle(config, run)?;
            let payload = MemoryGraphOutput {
                run: run.clone(),
                graph: bundle.graph,
            };
            if let Some(out_path) = out {
                write_json(out_path, &payload)?;
            }
            Ok(serde_json::to_value(payload)?)
        }
        MemoryCommand::Diff { left, right } => {
            let l = load_memory_bundle(config, left)?;
            let r = load_memory_bundle(config, right)?;
            let out = MemoryDiff {
                left: left.clone(),
                right: right.clone(),
                left_leaked_bytes: l.summary.leaked_bytes,
                right_leaked_bytes: r.summary.leaked_bytes,
                left_leaked_allocs: l.summary.leaked_allocs,
                right_leaked_allocs: r.summary.leaked_allocs,
                left_peak_bytes: l.summary.peak_bytes,
                right_peak_bytes: r.summary.peak_bytes,
                delta_leaked_bytes: r.summary.leaked_bytes as i64 - l.summary.leaked_bytes as i64,
                delta_leaked_allocs: r.summary.leaked_allocs as i64
                    - l.summary.leaked_allocs as i64,
                delta_peak_bytes: r.summary.peak_bytes as i64 - l.summary.peak_bytes as i64,
            };
            Ok(serde_json::to_value(out)?)
        }
        MemoryCommand::Top { run, limit } => {
            let mut bundle = load_memory_bundle(config, run)?;
            bundle.leaks.sort_by(|a, b| {
                b.bytes
                    .cmp(&a.bytes)
                    .then_with(|| a.alloc_id.cmp(&b.alloc_id))
            });
            let out = MemoryTop {
                run: run.clone(),
                limit: *limit,
                total: bundle.leaks.len(),
                leaks: bundle.leaks.into_iter().take(*limit).collect(),
            };
            Ok(serde_json::to_value(out)?)
        }
    }
}

fn load_memory_bundle(config: &Config, run: &str) -> FozzyResult<MemoryBundle> {
    let input = PathBuf::from(run);
    if input.exists()
        && input.is_file()
        && input
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("fozzy"))
    {
        return load_from_trace(&input, run);
    }

    let artifacts_dir = match crate::resolve_artifacts_dir(config, run) {
        Ok(dir) => dir,
        Err(err) => {
            if let Some(dir) = resolve_memory_alias_dir(config, run)? {
                dir
            } else {
                return Err(err);
            }
        }
    };
    let leaks_path = artifacts_dir.join("memory.leaks.json");
    let graph_path = artifacts_dir.join("memory.graph.json");
    if leaks_path.exists() || graph_path.exists() {
        let summary = load_summary_from_report(&artifacts_dir)?;
        let leaks: Vec<MemoryLeak> = if leaks_path.exists() {
            serde_json::from_slice(&std::fs::read(leaks_path)?)?
        } else {
            Vec::new()
        };
        let graph: MemoryGraph = if graph_path.exists() {
            serde_json::from_slice(&std::fs::read(graph_path)?)?
        } else {
            MemoryGraph::default()
        };
        return Ok(MemoryBundle {
            summary,
            leaks,
            graph,
        });
    }

    let trace_path = artifacts_dir.join("trace.fozzy");
    if trace_path.exists() {
        match load_from_trace(&trace_path, run) {
            Ok(bundle) => return Ok(bundle),
            Err(err) => {
                if let Some(dir) = resolve_memory_alias_dir(config, run)? {
                    let leaks_path = dir.join("memory.leaks.json");
                    let graph_path = dir.join("memory.graph.json");
                    if leaks_path.exists() || graph_path.exists() {
                        let summary = load_summary_from_report(&dir)?;
                        let leaks: Vec<MemoryLeak> = if leaks_path.exists() {
                            serde_json::from_slice(&std::fs::read(leaks_path)?)?
                        } else {
                            Vec::new()
                        };
                        let graph: MemoryGraph = if graph_path.exists() {
                            serde_json::from_slice(&std::fs::read(graph_path)?)?
                        } else {
                            MemoryGraph::default()
                        };
                        return Ok(MemoryBundle {
                            summary,
                            leaks,
                            graph,
                        });
                    }
                    let alt_trace = dir.join("trace.fozzy");
                    if alt_trace.exists() {
                        return load_from_trace(&alt_trace, run);
                    }
                }
                return Err(err);
            }
        }
    }

    if let Some(dir) = resolve_memory_alias_dir(config, run)? {
        let leaks_path = dir.join("memory.leaks.json");
        let graph_path = dir.join("memory.graph.json");
        if leaks_path.exists() || graph_path.exists() {
            let summary = load_summary_from_report(&dir)?;
            let leaks: Vec<MemoryLeak> = if leaks_path.exists() {
                serde_json::from_slice(&std::fs::read(leaks_path)?)?
            } else {
                Vec::new()
            };
            let graph: MemoryGraph = if graph_path.exists() {
                serde_json::from_slice(&std::fs::read(graph_path)?)?
            } else {
                MemoryGraph::default()
            };
            return Ok(MemoryBundle {
                summary,
                leaks,
                graph,
            });
        }
        let trace_path = dir.join("trace.fozzy");
        if trace_path.exists() {
            return load_from_trace(&trace_path, run);
        }
    }

    Err(FozzyError::InvalidArgument(format!(
        "no memory data found for {run:?}"
    )))
}

fn resolve_memory_alias_dir(config: &Config, run: &str) -> FozzyResult<Option<PathBuf>> {
    let key = run.trim().to_ascii_lowercase();
    if key != "latest" && key != "last-pass" && key != "last-fail" {
        return Ok(None);
    }
    let runs_dir = config.runs_dir();
    if !runs_dir.exists() {
        return Ok(None);
    }

    let mut run_dirs = std::fs::read_dir(&runs_dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            if !entry.file_type().ok()?.is_dir() {
                return None;
            }
            let md = entry.metadata().ok()?;
            let modified = md.modified().ok()?;
            Some((entry.path(), modified))
        })
        .collect::<Vec<_>>();
    run_dirs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if run_dirs.is_empty() {
        return Ok(None);
    }
    for (dir, _) in run_dirs {
        let report_path = dir.join("report.json");
        let summary = if report_path.exists() {
            serde_json::from_slice::<crate::RunSummary>(&std::fs::read(&report_path)?).ok()
        } else {
            None
        };
        let has_memory = summary.as_ref().and_then(|s| s.memory.as_ref()).is_some()
            || dir.join("memory.leaks.json").exists()
            || dir.join("memory.timeline.json").exists()
            || dir.join("memory.graph.json").exists()
            || dir.join("trace.fozzy").exists();
        if !has_memory {
            continue;
        }
        if key == "latest" {
            return Ok(Some(dir));
        }
        let status = summary
            .as_ref()
            .map(|s| s.status)
            .unwrap_or(ExitStatus::Fail);
        if (key == "last-pass" && status == ExitStatus::Pass)
            || (key == "last-fail" && status != ExitStatus::Pass)
        {
            return Ok(Some(dir));
        }
    }
    Ok(None)
}

fn load_summary_from_report(artifacts_dir: &Path) -> FozzyResult<MemorySummary> {
    let report_path = artifacts_dir.join("report.json");
    if !report_path.exists() {
        return Ok(MemorySummary::default());
    }
    let summary: crate::RunSummary = serde_json::from_slice(&std::fs::read(report_path)?)?;
    Ok(summary.memory.unwrap_or_default())
}

fn load_from_trace(path: &Path, run_name: &str) -> FozzyResult<MemoryBundle> {
    let trace = TraceFile::read_json(path)?;
    let Some(memory) = trace.memory else {
        return Err(FozzyError::InvalidArgument(format!(
            "trace {run_name:?} does not contain memory data"
        )));
    };
    let sibling_graph = path
        .parent()
        .map(|p| p.join("memory.graph.json"))
        .filter(|p| p.exists());
    let graph = if let Some(graph_path) = sibling_graph {
        serde_json::from_slice(&std::fs::read(graph_path)?)?
    } else {
        MemoryGraph::default()
    };
    Ok(MemoryBundle {
        summary: memory.summary,
        leaks: memory.leaks,
        graph: if memory.graph.is_empty() {
            graph
        } else {
            memory.graph
        },
    })
}

fn write_json(path: &Path, value: &impl Serialize) -> FozzyResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExitStatus, MemoryOptions, MemorySummary, RunIdentity, RunMode, RunSummary};

    #[test]
    fn top_sorts_descending_by_bytes() {
        let mut leaks = vec![
            MemoryLeak {
                alloc_id: 1,
                bytes: 10,
                callsite_hash: "a".to_string(),
                tag: None,
            },
            MemoryLeak {
                alloc_id: 2,
                bytes: 50,
                callsite_hash: "b".to_string(),
                tag: None,
            },
            MemoryLeak {
                alloc_id: 3,
                bytes: 20,
                callsite_hash: "c".to_string(),
                tag: None,
            },
        ];
        leaks.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        assert_eq!(leaks[0].bytes, 50);
        assert_eq!(leaks[1].bytes, 20);
        assert_eq!(leaks[2].bytes, 10);
    }

    #[test]
    fn memory_diff_from_trace_inputs() {
        let root = std::env::temp_dir().join(format!("fozzy-memory-cmd-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("mkdir");
        let mk_trace = |path: &Path, leaked: u64| {
            let trace = crate::TraceFile {
                format: crate::TRACE_FORMAT.to_string(),
                version: crate::CURRENT_TRACE_VERSION,
                engine: crate::version_info(),
                mode: RunMode::Run,
                scenario_path: None,
                scenario: Some(crate::ScenarioV1Steps {
                    version: 1,
                    name: "x".to_string(),
                    steps: Vec::new(),
                }),
                fuzz: None,
                explore: None,
                memory: Some(crate::MemoryTrace {
                    options: MemoryOptions::default(),
                    summary: MemorySummary {
                        leaked_bytes: leaked,
                        leaked_allocs: if leaked > 0 { 1 } else { 0 },
                        ..MemorySummary::default()
                    },
                    leaks: Vec::new(),
                    graph: MemoryGraph::default(),
                }),
                decisions: Vec::new(),
                events: Vec::new(),
                summary: RunSummary {
                    status: ExitStatus::Pass,
                    mode: RunMode::Run,
                    identity: RunIdentity {
                        run_id: "r1".to_string(),
                        seed: 1,
                        trace_path: None,
                        report_path: None,
                        artifacts_dir: None,
                    },
                    started_at: "2026-01-01T00:00:00Z".to_string(),
                    finished_at: "2026-01-01T00:00:00Z".to_string(),
                    duration_ms: 0,
                    duration_ns: 0,
                    tests: None,
                    memory: None,
                    findings: Vec::new(),
                },
                checksum: None,
            };
            trace.write_json(path).expect("write trace");
        };
        let left = root.join("left.fozzy");
        let right = root.join("right.fozzy");
        mk_trace(&left, 10);
        mk_trace(&right, 30);

        let cfg = Config::default();
        let out = memory_command(
            &cfg,
            &MemoryCommand::Diff {
                left: left.display().to_string(),
                right: right.display().to_string(),
            },
        )
        .expect("diff");
        let obj = out.as_object().expect("object");
        assert_eq!(
            obj.get("deltaLeakedBytes").and_then(|v| v.as_i64()),
            Some(20)
        );
    }
}
