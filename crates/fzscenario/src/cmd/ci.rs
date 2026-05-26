use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    ArtifactCommand, Config, FlakeBudget, FozzyError, FozzyResult, ReplayOptions, ReportCommand,
    Reporter, TraceFile, TracePath, artifacts_command, profile_command, replay_trace,
    report_command, verify_trace_file,
};
use crate::{ProfileCaptureLevel, ProfileCommand};

#[derive(Debug, Clone)]
pub struct CiOptions {
    pub trace: PathBuf,
    pub flake_runs: Vec<String>,
    pub flake_budget_pct: Option<FlakeBudget>,
    pub perf_baseline: Option<String>,
    pub max_p99_delta_pct: Option<f64>,
    pub strict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCheck {
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub ok: bool,
    pub checks: Vec<CiCheck>,
}

pub fn ci_command(config: &Config, opt: &CiOptions) -> FozzyResult<CiReport> {
    let report = ci_evaluate(config, opt)?;
    if !report.ok {
        return Err(FozzyError::InvalidArgument(
            "ci gate failed (one or more checks failed)".to_string(),
        ));
    }
    Ok(report)
}

pub fn ci_evaluate(config: &Config, opt: &CiOptions) -> FozzyResult<CiReport> {
    if opt.flake_budget_pct.is_some() && opt.flake_runs.is_empty() {
        return Err(FozzyError::InvalidArgument(
            "--flake-budget requires at least two --flake-run inputs".to_string(),
        ));
    }
    if opt.max_p99_delta_pct.is_some() && opt.perf_baseline.is_none() {
        return Err(FozzyError::InvalidArgument(
            "--max-p99-delta-pct requires --perf-baseline".to_string(),
        ));
    }
    let mut checks = Vec::new();

    let verify = verify_trace_file(&opt.trace)?;
    let strict_integrity_ok =
        verify.checksum_present && verify.checksum_valid && verify.warnings.is_empty();
    checks.push(CiCheck {
        name: "trace_verify".to_string(),
        ok: verify.ok && (!opt.strict || strict_integrity_ok),
        detail: Some(format!(
            "checksum_present={} checksum_valid={} warnings={}",
            verify.checksum_present,
            verify.checksum_valid,
            if verify.warnings.is_empty() {
                "<none>".to_string()
            } else {
                verify.warnings.join("; ")
            }
        )),
    });

    let trace = TraceFile::read_json(&opt.trace)?;
    let replay = replay_trace(
        config,
        TracePath::new(opt.trace.clone()),
        &ReplayOptions {
            step: false,
            until: None,
            dump_events: false,
            profile_capture: ProfileCaptureLevel::Baseline,
            reporter: Reporter::Json,
        },
    )?;
    let expected = if trace.summary.status == crate::ExitStatus::Pass {
        "pass"
    } else {
        "non_pass"
    };
    let got = if replay.summary.status == crate::ExitStatus::Pass {
        "pass"
    } else {
        "non_pass"
    };
    checks.push(CiCheck {
        name: "replay_outcome_class".to_string(),
        ok: expected == got,
        detail: Some(format!("expected={expected} got={got}")),
    });
    if let Some(memory) = trace.memory.as_ref() {
        let leak_ok = if memory.options.fail_on_leak {
            memory.summary.leaked_bytes == 0
        } else if let Some(budget) = memory.options.leak_budget_bytes {
            memory.summary.leaked_bytes <= budget
        } else {
            true
        };
        checks.push(CiCheck {
            name: "memory_policy".to_string(),
            ok: leak_ok,
            detail: Some(format!(
                "leaked_bytes={} leaked_allocs={} fail_on_leak={} leak_budget_bytes={:?}",
                memory.summary.leaked_bytes,
                memory.summary.leaked_allocs,
                memory.options.fail_on_leak,
                memory.options.leak_budget_bytes
            )),
        });
    }

    let zip_path =
        std::env::temp_dir().join(format!("fozzy-ci-export-{}.zip", uuid::Uuid::new_v4()));
    artifacts_command(
        config,
        &ArtifactCommand::Export {
            run: opt.trace.display().to_string(),
            out: zip_path.clone(),
        },
    )?;
    let zip_ok = if zip_path.exists() {
        let file = std::fs::File::open(&zip_path)?;
        let mut zip = zip::ZipArchive::new(file).map_err(|e| FozzyError::Zip(e.to_string()))?;
        for i in 0..zip.len() {
            let mut entry = zip
                .by_index(i)
                .map_err(|e| FozzyError::Zip(e.to_string()))?;
            if entry.is_dir() {
                continue;
            }
            let mut sink = std::io::sink();
            std::io::copy(&mut entry, &mut sink)?;
        }
        true
    } else {
        false
    };
    checks.push(CiCheck {
        name: "artifacts_zip_integrity".to_string(),
        ok: zip_ok,
        detail: Some(zip_path.display().to_string()),
    });
    let _ = std::fs::remove_file(zip_path);

    if !opt.flake_runs.is_empty() {
        if opt.flake_runs.len() < 2 {
            return Err(FozzyError::InvalidArgument(
                "--flake-run requires at least two runs when provided".to_string(),
            ));
        }
        let out = report_command(
            config,
            &ReportCommand::Flaky {
                runs: opt.flake_runs.clone(),
                flake_budget: opt.flake_budget_pct,
            },
        )?;
        let rate = out
            .get("flakeRatePct")
            .and_then(|v| v.as_f64())
            .unwrap_or(100.0);
        checks.push(CiCheck {
            name: "flake_budget".to_string(),
            ok: true,
            detail: Some(format!("flake_rate_pct={rate:.2}")),
        });
    }

    if let (Some(baseline), Some(max_p99_delta_pct)) = (&opt.perf_baseline, opt.max_p99_delta_pct) {
        let diff = profile_command(
            config,
            &ProfileCommand::Diff {
                left: baseline.clone(),
                right: opt.trace.display().to_string(),
                cpu: false,
                heap: false,
                latency: true,
                io: false,
                sched: false,
            },
            true,
        )?;
        let p99_delta_pct = diff
            .get("regressions")
            .and_then(|v| v.as_array())
            .and_then(|rows| {
                rows.iter().find(|row| {
                    row.get("metric")
                        .and_then(|m| m.as_str())
                        .is_some_and(|m| m == "p99_latency_ms")
                })
            })
            .and_then(|row| row.get("deltaPct"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        checks.push(CiCheck {
            name: "perf_p99_budget".to_string(),
            ok: p99_delta_pct <= max_p99_delta_pct,
            detail: Some(format!(
                "baseline={baseline} delta_pct={p99_delta_pct:.4} budget_pct={max_p99_delta_pct:.4}"
            )),
        });
    }

    let ok = checks.iter().all(|c| c.ok);
    Ok(CiReport {
        schema_version: "fozzy.ci_report.v1".to_string(),
        ok,
        checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_command_runs_core_checks() {
        let root = std::env::temp_dir().join(format!("fozzy-ci-cmd-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("mkdir");
        let trace = root.join("trace.fozzy");
        let raw = r#"{
          "format":"fozzy-trace",
          "version":2,
          "engine":{"version":"0.1.0"},
          "mode":"run",
          "scenario_path":null,
          "scenario":{"version":1,"name":"x","steps":[]},
          "decisions":[],
          "events":[],
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r1","seed":1},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          }
        }"#;
        std::fs::write(&trace, raw).expect("write trace");
        let cfg = Config {
            base_dir: root.join(".fozzy"),
            reporter: Reporter::Json,
            proc_backend: crate::ProcBackend::Scripted,
            fs_backend: crate::FsBackend::Virtual,
            http_backend: crate::HttpBackend::Scripted,
            mem_track: false,
            mem_limit_mb: None,
            mem_fail_after: None,
            fail_on_leak: false,
            leak_budget: None,
            mem_artifacts: false,
            profile_heap_alloc_budget: None,
            profile_heap_in_use_budget: None,
            mem_fragmentation_seed: None,
            mem_pressure_wave: None,
        };

        let out = ci_command(
            &cfg,
            &CiOptions {
                trace,
                flake_runs: Vec::new(),
                flake_budget_pct: None,
                perf_baseline: None,
                max_p99_delta_pct: None,
                strict: false,
            },
        )
        .expect("ci command");
        assert!(out.ok);
        assert!(out.checks.iter().any(|c| c.name == "trace_verify"));
        assert!(out.checks.iter().any(|c| c.name == "replay_outcome_class"));
        assert!(
            out.checks
                .iter()
                .any(|c| c.name == "artifacts_zip_integrity")
        );
    }

    #[test]
    fn ci_rejects_budget_without_flake_runs() {
        let root =
            std::env::temp_dir().join(format!("fozzy-ci-cmd-budget-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("mkdir");
        let trace = root.join("trace.fozzy");
        let raw = r#"{
          "format":"fozzy-trace",
          "version":2,
          "engine":{"version":"0.1.0"},
          "mode":"run",
          "scenario_path":null,
          "scenario":{"version":1,"name":"x","steps":[]},
          "decisions":[],
          "events":[],
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r1","seed":1},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          }
        }"#;
        std::fs::write(&trace, raw).expect("write trace");
        let cfg = Config {
            base_dir: root.join(".fozzy"),
            reporter: Reporter::Json,
            proc_backend: crate::ProcBackend::Scripted,
            fs_backend: crate::FsBackend::Virtual,
            http_backend: crate::HttpBackend::Scripted,
            mem_track: false,
            mem_limit_mb: None,
            mem_fail_after: None,
            fail_on_leak: false,
            leak_budget: None,
            mem_artifacts: false,
            profile_heap_alloc_budget: None,
            profile_heap_in_use_budget: None,
            mem_fragmentation_seed: None,
            mem_pressure_wave: None,
        };

        let err = ci_command(
            &cfg,
            &CiOptions {
                trace,
                flake_runs: Vec::new(),
                flake_budget_pct: Some("5".parse().expect("budget")),
                perf_baseline: None,
                max_p99_delta_pct: None,
                strict: false,
            },
        )
        .expect_err("must fail");
        assert!(err.to_string().contains("--flake-budget requires"));
    }
}
