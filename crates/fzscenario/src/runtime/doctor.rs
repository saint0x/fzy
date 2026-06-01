use serde::{Deserialize, Serialize};
use std::io::Write;

use crate::engine::{FsBackend, HttpBackend, ProcBackend, ScenarioRun, run_scenario_inner};
use crate::{
    Config, Decision, ExitStatus, Finding, FozzyResult, MemoryOptions, MemoryRunReport, RunMode,
    ScenarioPath, TraceEvent,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub issues: Vec<DoctorIssue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nondeterminism_signals: Option<Vec<NondeterminismSignal>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub determinism_audit: Option<DeterminismAudit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorIssue {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NondeterminismSignal {
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct DoctorOptions {
    pub deep: bool,
    pub scenario: Option<ScenarioPath>,
    pub runs: u32,
    pub seed: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterminismAudit {
    pub scenario: String,
    pub runs: u32,
    pub seed: u64,
    pub consistent: bool,
    pub signatures: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_mismatch_run: Option<u32>,
}

pub fn doctor(config: &Config, opt: &DoctorOptions) -> FozzyResult<DoctorReport> {
    let issues = Vec::new();
    let mut signals = Vec::new();

    if std::env::var("TZ").is_ok() {
        signals.push(NondeterminismSignal {
            source: "env".to_string(),
            detail: "TZ is set; local time can affect non-deterministic code paths".to_string(),
        });
    }

    if opt.deep && std::env::var("RUST_BACKTRACE").is_ok() {
        signals.push(NondeterminismSignal {
            source: "env".to_string(),
            detail: "RUST_BACKTRACE is set; ok, but note it can change stderr output".to_string(),
        });
    }
    let mut issues = issues;
    let determinism_audit = if opt.deep {
        if let Some(path) = opt.scenario.clone() {
            let runs = opt.runs.max(2);
            let seed = opt.seed.unwrap_or(0xC0DEC0DE_u64);
            let mut signatures = Vec::with_capacity(runs as usize);
            let mut consistent = true;
            let mut first_mismatch_run = None;
            let mut baseline: Option<String> = None;

            for i in 0..runs {
                let run = run_scenario_inner(
                    config,
                    RunMode::Run,
                    path.clone(),
                    seed,
                    true,
                    None,
                    ProcBackend::Scripted,
                    FsBackend::Virtual,
                    HttpBackend::Scripted,
                    MemoryOptions::default(),
                )?;
                if i == 0
                    && let Some(finding) = run.findings.iter().find(|f| f.title == "proc_unmatched")
                {
                    issues.push(DoctorIssue {
                        code: "proc_unmatched_preflight".to_string(),
                        message: "strict proc backend preflight found an undeclared subprocess"
                            .to_string(),
                        hint: Some(finding.message.clone()),
                    });
                }
                let sig = scenario_run_signature(&run);
                if let Some(b) = &baseline {
                    if b != &sig && first_mismatch_run.is_none() {
                        consistent = false;
                        first_mismatch_run = Some(i + 1);
                    }
                } else {
                    baseline = Some(sig.clone());
                }
                signatures.push(sig);
            }

            if !consistent {
                issues.push(DoctorIssue {
                    code: "determinism_audit_mismatch".to_string(),
                    message: format!(
                        "determinism audit mismatch for {} across {} runs (seed={seed})",
                        path.as_path().display(),
                        runs
                    ),
                    hint: Some(
                        "Run `fz run --det --seed <seed>` repeatedly and compare traces/events."
                            .to_string(),
                    ),
                });
            }

            Some(DeterminismAudit {
                scenario: path.as_path().display().to_string(),
                runs,
                seed,
                consistent,
                signatures,
                first_mismatch_run,
            })
        } else {
            None
        }
    } else {
        None
    };

    let ok = issues.is_empty();
    Ok(DoctorReport {
        ok,
        issues,
        nondeterminism_signals: if signals.is_empty() {
            None
        } else {
            Some(signals)
        },
        determinism_audit,
    })
}

fn scenario_run_signature(run: &ScenarioRun) -> String {
    let mut writer = Blake3Writer::default();
    hash_status(&mut writer, run.status);
    hash_memory(&mut writer, run.memory.as_ref());
    hash_findings(&mut writer, &run.findings);
    hash_decisions(&mut writer, &run.decisions.decisions);
    hash_events(&mut writer, &run.events);
    writer.finalize()
}

fn hash_status(writer: &mut Blake3Writer, status: ExitStatus) {
    hash_tag(writer, "status");
    hash_str(
        writer,
        match status {
            ExitStatus::Pass => "pass",
            ExitStatus::Fail => "fail",
            ExitStatus::Error => "error",
            ExitStatus::Timeout => "timeout",
            ExitStatus::Crash => "crash",
        },
    );
}

fn hash_memory(writer: &mut Blake3Writer, memory: Option<&MemoryRunReport>) {
    hash_tag(writer, "memory");
    match memory {
        Some(memory) => {
            hash_bool(writer, true);
            hash_json(writer, &memory.options);
            hash_json(writer, &memory.summary);
            hash_json(writer, &memory.leaks);
            hash_json(writer, &memory.graph);
        }
        None => hash_bool(writer, false),
    }
}

fn hash_findings(writer: &mut Blake3Writer, findings: &[Finding]) {
    hash_tag(writer, "findings");
    hash_len(writer, findings.len());
    for finding in findings {
        hash_json(writer, finding);
    }
}

fn hash_decisions(writer: &mut Blake3Writer, decisions: &[Decision]) {
    hash_tag(writer, "decisions");
    hash_len(writer, decisions.len());
    for decision in decisions {
        hash_json(writer, decision);
    }
}

fn hash_events(writer: &mut Blake3Writer, events: &[TraceEvent]) {
    hash_tag(writer, "events");
    hash_len(writer, events.len());
    for event in events {
        hash_u64(writer, event.time_ms);
        hash_str(writer, &event.name);
        hash_json(writer, &event.fields);
    }
}

fn hash_json<T: serde::Serialize>(writer: &mut Blake3Writer, value: &T) {
    if serde_json::to_writer(&mut *writer, value).is_ok() {
        hash_tag(writer, "json-end");
    }
}

fn hash_tag(writer: &mut Blake3Writer, value: &str) {
    hash_str(writer, value);
}

fn hash_str(writer: &mut Blake3Writer, value: &str) {
    hash_len(writer, value.len());
    let _ = writer.write_all(value.as_bytes());
}

fn hash_len(writer: &mut Blake3Writer, len: usize) {
    let _ = writer.write_all(&(len as u64).to_le_bytes());
}

fn hash_u64(writer: &mut Blake3Writer, value: u64) {
    let _ = writer.write_all(&value.to_le_bytes());
}

fn hash_bool(writer: &mut Blake3Writer, value: bool) {
    let _ = writer.write_all(&[u8::from(value)]);
}

#[derive(Default)]
struct Blake3Writer {
    hasher: blake3::Hasher,
}

impl Blake3Writer {
    fn finalize(self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }
}

impl std::io::Write for Blake3Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
