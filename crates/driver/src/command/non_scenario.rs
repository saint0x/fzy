use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use super::{attach_project_root_guidance, NonScenarioPlanRequest, NonScenarioTestPlan};

#[derive(Debug, Clone)]
pub(super) struct HostBackedBridgePlan {
    pub(super) trace_path: PathBuf,
    pub(super) scenario_path: PathBuf,
}

pub(super) fn run_non_scenario_test_plan_with_root_guidance(
    path: &Path,
    request: NonScenarioPlanRequest<'_>,
) -> Result<NonScenarioTestPlan> {
    super::run_non_scenario_test_plan(path, request)
        .map_err(|error| attach_project_root_guidance(path, error))
}

pub(super) fn prepare_host_backed_bridge(
    path: &Path,
    request: NonScenarioPlanRequest<'_>,
    label: &str,
) -> Result<HostBackedBridgePlan> {
    let bridge_root = std::env::temp_dir().join("fz-host-bridge");
    std::fs::create_dir_all(&bridge_root).with_context(|| {
        format!(
            "failed creating host-backends bridge directory: {}",
            bridge_root.display()
        )
    })?;
    let stamp = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let trace_path = bridge_root.join(format!("{label}-{stamp}.trace.fozzy"));
    let plan = run_non_scenario_test_plan_with_root_guidance(
        path,
        NonScenarioPlanRequest {
            deterministic: true,
            strict_verify: request.strict_verify,
            safe_profile: request.safe_profile,
            scheduler: request.scheduler,
            seed: request.seed,
            record: Some(&trace_path),
            rich_artifacts: true,
            filter: request.filter,
        },
    )?;
    let artifacts = plan.artifacts.as_ref().ok_or_else(|| {
        anyhow!(
            "host-backends bridge failed to produce artifacts for {}",
            path.display()
        )
    })?;
    let scenario_path = artifacts.primary_scenario_path.clone().ok_or_else(|| {
        anyhow!(
            "host-backends bridge failed to generate a primary scenario for {}",
            path.display()
        )
    })?;
    Ok(HostBackedBridgePlan {
        trace_path,
        scenario_path,
    })
}
