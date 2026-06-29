use std::path::Path;

use anyhow::Result;

use super::{attach_project_root_guidance, NonScenarioPlanRequest, NonScenarioTestPlan};

pub(super) fn run_non_scenario_test_plan_with_root_guidance(
    path: &Path,
    request: NonScenarioPlanRequest<'_>,
) -> Result<NonScenarioTestPlan> {
    super::run_non_scenario_test_plan(path, request)
        .map_err(|error| attach_project_root_guidance(path, error))
}
