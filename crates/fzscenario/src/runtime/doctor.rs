use serde::{Deserialize, Serialize};

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
    let payload = ScenarioRunSignatureView {
        status: &run.status,
        memory: run.memory.as_ref(),
        findings: &run.findings,
        decisions: &run.decisions.decisions,
        events: &run.events,
    };
    if payload.serialize(&mut serde_json::Serializer::new(&mut writer)).is_err() {
        return String::new();
    }
    writer.finalize()
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

#[derive(serde::Serialize)]
struct ScenarioRunSignatureView<'a> {
    status: &'a ExitStatus,
    memory: Option<&'a MemoryRunReport>,
    findings: &'a [Finding],
    decisions: &'a [Decision],
    events: &'a [TraceEvent],
}
