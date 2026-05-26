//! Project init/scaffolding helpers.

use crate::engine::{InitTemplate, InitTestType};
use crate::{Config, FozzyError, FozzyResult, Scenario};
use std::path::{Path, PathBuf};

pub fn init_project(
    config: &Config,
    config_path: &Path,
    template: &InitTemplate,
    force: bool,
    test_types: &[InitTestType],
) -> FozzyResult<()> {
    let base = &config.base_dir;
    if base.exists() && !force {
        return Err(FozzyError::InvalidArgument(format!(
            "{} already exists (use --force to overwrite)",
            base.display()
        )));
    }

    std::fs::create_dir_all(config.runs_dir())?;
    std::fs::create_dir_all(config.corpora_dir())?;

    // Write a minimal config if it doesn't exist.
    if force || !config_path.exists() {
        let cfg = toml::to_string_pretty(config).map_err(|e| FozzyError::Config(e.to_string()))?;
        std::fs::write(config_path, cfg)?;
    }

    std::fs::create_dir_all("tests")?;

    let selected = normalize_init_test_types(test_types);
    if selected.contains(&InitTestType::Run) {
        write_if_allowed(
            Path::new("tests/example.fozzy.json"),
            &serde_json::to_vec_pretty(&Scenario::example())?,
            force,
        )?;
        write_if_allowed(
            Path::new("tests/run.pass.fozzy.json"),
            br#"{
  "version": 1,
  "name": "run-pass",
  "steps": [
    { "type": "trace_event", "name": "setup" },
    { "type": "assert_eq_int", "a": 1, "b": 1 }
  ]
}"#,
            force,
        )?;
    }
    if selected.contains(&InitTestType::Memory) {
        write_if_allowed(
            Path::new("tests/memory.pass.fozzy.json"),
            br#"{
  "version": 1,
  "name": "memory-pass",
  "steps": [
    { "type": "memory_alloc", "bytes": 128, "key": "buf", "tag": "req" },
    { "type": "memory_assert_in_use_bytes", "equals": 128 },
    { "type": "memory_free", "key": "buf" },
    { "type": "memory_assert_in_use_bytes", "equals": 0 }
  ]
}"#,
            force,
        )?;
    }
    if selected.contains(&InitTestType::Explore) {
        write_if_allowed(
            Path::new("tests/distributed.pass.fozzy.json"),
            br#"{
  "version": 1,
  "name": "distributed-pass",
  "distributed": {
    "node_count": 3,
    "steps": [
      { "type": "client_put", "node": "n0", "key": "k", "value": "v1" },
      { "type": "client_put", "node": "n1", "key": "k", "value": "v1" },
      { "type": "client_put", "node": "n2", "key": "k", "value": "v1" },
      { "type": "tick", "duration": "20ms" }
    ],
    "invariants": [
      { "type": "kv_present_on_all", "key": "k" },
      { "type": "kv_all_equal", "key": "k" }
    ]
  }
}"#,
            force,
        )?;
    }
    if selected.contains(&InitTestType::Host) {
        write_if_allowed(
            Path::new("tests/host.pass.fozzy.json"),
            br#"{
  "version": 1,
  "name": "host-pass",
  "steps": [
    { "type": "fs_write", "path": "tmp/host-smoke.txt", "data": "hello-host" },
    { "type": "fs_read_assert", "path": "tmp/host-smoke.txt", "equals": "hello-host" },
    { "type": "proc_spawn", "cmd": "echo", "args": ["fozzy-host"], "expect_exit": 0, "expect_stdout": "fozzy-host\n" }
  ]
}"#,
            force,
        )?;
    }
    if selected.contains(&InitTestType::Fuzz) {
        let corpus_dir = config.corpora_dir().join("fn-kv");
        std::fs::create_dir_all(&corpus_dir)?;
        write_if_allowed(&corpus_dir.join("seed.bin"), b"fozzy-seed\n", force)?;
    }

    write_if_allowed(
        Path::new("tests/INIT_GUIDE.md"),
        init_guide_markdown(&selected).as_bytes(),
        force,
    )?;

    match template {
        InitTemplate::Minimal => {}
        InitTemplate::Rust => {
            let readme = PathBuf::from("README.md");
            if force || !readme.exists() {
                std::fs::write(
                    &readme,
                    "Fozzy project (Rust template)\n\n- scenarios live in `tests/*.fozzy.json`\n- run: `fz test --det --json`\n",
                )?;
            }
        }
        InitTemplate::Ts => {
            // v0.1 doesn't scaffold npm; it only creates the core config + example scenarios.
        }
    }

    Ok(())
}

fn write_if_allowed(path: &Path, bytes: &[u8], force: bool) -> FozzyResult<()> {
    if path.exists() && !force {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

fn normalize_init_test_types(input: &[InitTestType]) -> Vec<InitTestType> {
    let requested = if input.is_empty() {
        vec![InitTestType::All]
    } else {
        input.to_vec()
    };
    let all = [
        InitTestType::Run,
        InitTestType::Fuzz,
        InitTestType::Explore,
        InitTestType::Memory,
        InitTestType::Host,
    ];
    let mut out: Vec<InitTestType> = Vec::new();
    if requested.contains(&InitTestType::All) {
        out.extend(all);
    } else {
        out.extend(requested);
    }
    out.sort_by_key(|v| match v {
        InitTestType::Run => 0,
        InitTestType::Fuzz => 1,
        InitTestType::Explore => 2,
        InitTestType::Memory => 3,
        InitTestType::Host => 4,
        InitTestType::All => 5,
    });
    out.dedup();
    out.retain(|v| *v != InitTestType::All);
    out
}

fn init_guide_markdown(selected: &[InitTestType]) -> String {
    let mut lines = vec![
        "# Fozzy Init Guide".to_string(),
        "".to_string(),
        "This scaffold is set up to run with strict mode by default.".to_string(),
        "Use `--unsafe` only when intentionally opting out of strict checks.".to_string(),
        "".to_string(),
        "## Recommended first run".to_string(),
        "```bash".to_string(),
        "fz full --scenario-root tests --seed 7".to_string(),
        "```".to_string(),
        "".to_string(),
        "## Targeted commands".to_string(),
    ];
    if selected.contains(&InitTestType::Run) {
        lines.push(
            "- Run deterministic scenarios: `fz test tests/*.fozzy.json --det --json`".to_string(),
        );
    }
    if selected.contains(&InitTestType::Memory) {
        lines.push("- Run memory checks: `fz run tests/memory.pass.fozzy.json --det --mem-track --fail-on-leak --leak-budget 0 --json`".to_string());
    }
    if selected.contains(&InitTestType::Explore) {
        lines.push("- Run distributed explore: `fz explore tests/distributed.pass.fozzy.json --schedule coverage_guided --nodes 3 --steps 200 --json`".to_string());
    }
    if selected.contains(&InitTestType::Fuzz) {
        lines.push("- Run fuzzing: `fz fuzz fn:kv --mode coverage --time 10s --corpus .fozzy/corpora/fn-kv --json`".to_string());
    }
    if selected.contains(&InitTestType::Host) {
        lines.push("- Run host-backed checks: `fz run tests/host.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`".to_string());
    }
    lines.push("".to_string());
    lines.push(
        "Edit the `tests/*.fozzy.json` scenarios with your own inputs and assertions.".to_string(),
    );
    lines.join("\n")
}
