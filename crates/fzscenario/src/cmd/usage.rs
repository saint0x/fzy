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
        title: "FZ CLI usage (start with `fz map suites`, then use the full surface)"
            .to_string(),
        items: vec![
            UsageItem {
                command: "fz map".to_string(),
                when: "Start here: generate a language-agnostic code-topology map (hotspots, service boundaries, granular suite recommendations) before running broad gates.".to_string(),
                how: "fz map suites --root . --scenario-root tests --min-risk 60 --profile pedantic --json (run this first); then use fz map hotspots --root . --min-risk 60 --limit 50 --json and fz map services --root . --json for deeper targeting. `pedantic` is the default profile and biases toward over-specifying granular suite coverage; optionally use `balanced` or `overkill`.".to_string(),
            },
            UsageItem {
                command: "fz full".to_string(),
                when: "Run the complete Fozzy surface-area gate with setup guidance and graceful skip behavior for missing inputs.".to_string(),
                how: "fz full --scenario-root tests --seed 1337 --doctor-runs 5 --fuzz-time 2s --explore-steps 200 --explore-nodes 3 --allow-expected-failures --scenario-filter memory --skip-steps fuzz --required-steps usage,version,test_det,run_record_trace,replay,ci,shrink --require-topology-coverage . --topology-min-risk 60 --topology-profile pedantic. This command exercises init/test/run/fuzz/explore/replay/trace verify/shrink/corpus/artifacts/report/profile/memory/map/doctor/ci/env/version/usage with policy controls for mixed scenario sets and can enforce high-risk topology hotspot coverage. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz gate".to_string(),
                when: "Run a lightweight strict deterministic gate for change-scoped validation before full pre-push coverage.".to_string(),
                how: "fz gate --profile targeted --scenario-root tests --scope gateway,local-bridge --seed 1337 --doctor-runs 5 --json. This runs doctor/test/run+record/trace verify/replay/ci against only matched step scenarios.".to_string(),
            },
            UsageItem {
                command: "fz init".to_string(),
                when: "Start a new project or bootstrap config/artifact directories.".to_string(),
                how: "fz init --template rust --with run,memory,explore,fuzz,host --force (or just `fz init` for all scaffold types by default). Then edit tests/*.fozzy.json inputs/assertions and run `fz full --scenario-root tests --seed 7`.".to_string(),
            },
            UsageItem {
                command: "fz test".to_string(),
                when: "Run a suite of Fozzy scenarios in CI; turn on --det to make failures replayable. This is not a direct shell/cargo/jest runner.".to_string(),
                how: "fz test --det --seed 1337 --record /tmp/test.fz --mem-track --fail-on-leak --leak-budget 0; with multiple scenarios, traces are /tmp/test.1.fozzy, /tmp/test.2.fozzy, etc. Host backends (`--proc-backend host`, `--fs-backend host`, `--http-backend host`) are allowed with `--det`; live host observations are recorded into the trace so replay stays deterministic, even though repeated live host runs can still vary with the environment. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz run".to_string(),
                when: "Run a single scenario one-off while iterating locally or debugging a specific failure.".to_string(),
                how: "fz run tests/example.fozzy.json --det --timeout 2s --json --mem-track --mem-limit-mb 256 --mem-fail-after 10000 --mem-artifacts; in --det mode timeout is enforced on virtual elapsed time. For host execution, use `--proc-backend host`, `--fs-backend host`, `--http-backend host`; in `--det` mode those live observations are captured into the trace for deterministic replay. `http_request` supports `headers` + `expect_headers` assertions. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz replay".to_string(),
                when: "Reproduce a failure exactly from a recorded trace, to debug without drift.".to_string(),
                how: "fz replay .fozzy/runs/<runId>/trace.fz --dump-events --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz trace verify".to_string(),
                when: "Validate trace integrity/version before replaying or handing artifacts to CI/other teams.".to_string(),
                how: "fz trace verify .fozzy/runs/<runId>/trace.fz --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz shrink".to_string(),
                when: "Minimize a failing run to the smallest scenario/trace that still triggers the bug.".to_string(),
                how: "fz shrink trace.fz --minimize all --budget 30s --json (then replay the .min.fz output). Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz fuzz".to_string(),
                when: "Find new bugs automatically by mutating inputs and exploring states; use for robustness/security testing.".to_string(),
                how: "fz fuzz scenario:tests/example.fozzy.json --mode coverage --time 30s --record /tmp/fuzz.fz (targets support fn:<id> and scenario:<path.fozzy.json>; built-in fn targets classify findings as target_behavior/input_invalid). Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz explore".to_string(),
                when: "Test distributed/system scenarios by exploring schedules and injecting faults deterministically.".to_string(),
                how: "fz explore tests/kv.explore.fozzy.json --schedule coverage_guided --faults partition-first-two --checker kv_all_equal:k --nodes 3 --steps 200 --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz corpus".to_string(),
                when: "Manage fuzz corpora: seed inputs, export/import to share failing cases across machines/CI.".to_string(),
                how: "fz corpus add <dir> <file>; fz corpus list <dir>; fz corpus export <dir> --out corpus.zip.".to_string(),
            },
            UsageItem {
                command: "fz artifacts".to_string(),
                when: "List/export run files or diff two runs/traces to quickly see artifact/report/trace drift.".to_string(),
                how: "fz artifacts ls <runId>; fz artifacts diff <left> <right>; fz artifacts export <runId> --out out.zip; fz artifacts pack <runId|trace> --out repro.zip; fz artifacts bundle <runId|trace> --out gate.zip. Aliases (`latest`, `last-pass`, `last-fail`) are supported, but CI should prefer explicit run ids or trace paths when race-sensitive.".to_string(),
            },
            UsageItem {
                command: "fz report".to_string(),
                when: "Render a run summary in a specific format for CI (JUnit) or humans (HTML/pretty).".to_string(),
                how: "fz report show <runId|trace> --format junit; fz report query <runId> --jq '.findings[].title'; fz report flaky <run1> <run2> --flake-budget 5. Aliases (`latest`, `last-pass`, `last-fail`) are supported, but CI should prefer explicit run ids or trace paths when race-sensitive.".to_string(),
            },
            UsageItem {
                command: "fz memory".to_string(),
                when: "Inspect memory-focused diagnostics (graph, leak top-N, run-to-run memory deltas)."
                    .to_string(),
                how: "fz memory top <runId|trace> --limit 20; fz memory diff <left> <right>; fz memory graph <runId|trace> --out memory.graph.export.json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out."
                    .to_string(),
            },
            UsageItem {
                command: "fz profile".to_string(),
                when: "Diagnose regressions with deterministic timeline/heap/latency, capability visibility, and one-shot profile health checks.".to_string(),
                how: "fz run tests/example.fozzy.json --det --profile-capture sampled --record ./trace.fz --json; fz profile env --json; fz profile top <runId|trace> --heap --latency --io --sched --limit 20; fz profile flame <runId|trace> --cpu --format speedscope --out cpu.speedscope.json; fz profile diff <left> <right> --cpu --heap --latency --json; fz profile explain <runId|trace> --diff-with <baseline>; fz profile export <runId|trace> --format otlp --out profile.otlp.json; fz profile shrink <runId|trace> --metric p99_latency --direction increase --minimize all (returns status=no_feasible_shrink_found instead of hard error when contract preservation is impossible); fz profile doctor <runId|trace> --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz ci".to_string(),
                when: "Run a canonical local gate bundle for one trace: verify, replay outcome check, artifacts zip integrity, optional flake budget.".to_string(),
                how: "fz ci .fozzy/runs/<runId>/trace.fz --flake-run <run1> --flake-run <run2> --flake-budget 5 --perf-baseline <baselineRunOrTrace> --max-p99-delta-pct 10 --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz doctor".to_string(),
                when: "Diagnose environment issues and sources of nondeterminism before trusting replay in CI.".to_string(),
                how: "fz doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 123 --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fz env".to_string(),
                when: "Inspect current capability backends and whether they are deterministic.".to_string(),
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
