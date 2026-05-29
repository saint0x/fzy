//! `fz usage`: a compact "what to use when" guide for agents and humans.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageDoc {
    pub title: String,
    pub items: Vec<UsageItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageItem {
    pub command: String,
    pub when: String,
    pub how: String,
}

impl UsageDoc {
    pub fn pretty(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("{}\n\n", self.title));
        for item in &self.items {
            out.push_str(&format!("{}:\n", item.command));
            out.push_str(&format!("  when: {}\n", item.when));
            out.push_str(&format!("  how:  {}\n\n", item.how));
        }
        out.trim_end().to_string()
    }
}

pub fn usage_doc() -> UsageDoc {
    UsageDoc {
        title: "FZ CLI usage (install once, then use `fz` for compiler and deterministic validation)"
            .to_string(),
        items: vec![
            UsageItem {
                command: "fz map".to_string(),
                when: "Generate a scenario-suite recommendation map for the current workspace before broad validation.".to_string(),
                how: "fz map suites --root . --scenario-root tests --profile pedantic --json.".to_string(),
            },
            UsageItem {
                command: "fz init".to_string(),
                when: "Start a new project or bootstrap the current directory with compiler and scenario scaffolding.".to_string(),
                how: "fz init . --template rust --with run,fuzz,explore,memory,host --force.".to_string(),
            },
            UsageItem {
                command: "fz test".to_string(),
                when: "Run deterministic scenario validation in CI or locally.".to_string(),
                how: "fz test tests/run.pass.fozzy.json --det --strict-verify --seed 1337 --json.".to_string(),
            },
            UsageItem {
                command: "fz run".to_string(),
                when: "Execute one project or one scenario, optionally recording a deterministic trace.".to_string(),
                how: "fz run tests/run.pass.fozzy.json --det --record artifacts/run.trace.fozzy --json.".to_string(),
            },
            UsageItem {
                command: "fz replay".to_string(),
                when: "Reproduce a failure exactly from a recorded trace, to debug without drift.".to_string(),
                how: "fz replay artifacts/run.trace.fozzy --json.".to_string(),
            },
            UsageItem {
                command: "fz trace verify".to_string(),
                when: "Validate trace integrity/version before replaying or handing artifacts to CI/other teams.".to_string(),
                how: "fz trace verify artifacts/run.trace.fozzy --strict --json.".to_string(),
            },
            UsageItem {
                command: "fz shrink".to_string(),
                when: "Minimize a failing run to the smallest scenario/trace that still triggers the bug.".to_string(),
                how: "fz shrink artifacts/run.trace.fozzy --json.".to_string(),
            },
            UsageItem {
                command: "fz fuzz".to_string(),
                when: "Exercise a scenario with the built-in fuzzing mode.".to_string(),
                how: "fz fuzz tests/example.fozzy.json --json.".to_string(),
            },
            UsageItem {
                command: "fz explore".to_string(),
                when: "Explore scenario behavior and generate explore artifacts.".to_string(),
                how: "fz explore tests/distributed.pass.fozzy.json --json.".to_string(),
            },
            UsageItem {
                command: "fz artifacts".to_string(),
                when: "Inspect the latest generated artifact set.".to_string(),
                how: "fz artifacts ls latest --json.".to_string(),
            },
            UsageItem {
                command: "fz report".to_string(),
                when: "Render the latest run summary in JSON or text.".to_string(),
                how: "fz report show latest --format json --json.".to_string(),
            },
            UsageItem {
                command: "fz ci".to_string(),
                when: "Run the built-in CI trace gate against a recorded trace.".to_string(),
                how: "fz ci artifacts/run.trace.fozzy --json.".to_string(),
            },
            UsageItem {
                command: "fz doctor".to_string(),
                when: "Diagnose environment issues and sources of nondeterminism before trusting replay in CI.".to_string(),
                how: "fz doctor --deep --scenario tests/run.pass.fozzy.json --runs 5 --seed 123 --json.".to_string(),
            },
            UsageItem {
                command: "fz env".to_string(),
                when: "Inspect current capability backends plus install-path health for the active binary.".to_string(),
                how: "fz env --json.".to_string(),
            },
            UsageItem {
                command: "fz version".to_string(),
                when: "Print version/build metadata for bug reports and CI logs.".to_string(),
                how: "fz version --json.".to_string(),
            },
            UsageItem {
                command: "fz schema".to_string(),
                when: "Inspect supported scenario-file variants and step types for authoring and automation.".to_string(),
                how: "fz schema --json (alias: `fz steps --json`).".to_string(),
            },
            UsageItem {
                command: "fz validate".to_string(),
                when: "Validate a scenario file and return deterministic parser/shape diagnostics before running tests.".to_string(),
                how: "fz validate tests/example.fozzy.json --json (supports both steps and distributed variants); non-zero exit indicates parse or validation issues.".to_string(),
            },
        ],
    }
}
