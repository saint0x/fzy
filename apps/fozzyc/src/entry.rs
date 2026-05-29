use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use driver::{cli_output, run as driver_run, Command, CommandFailure, Format};

pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return Ok(());
    }
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
        print_help();
        return Ok(());
    }
    if args.len() == 1 && args[0] == "--version" {
        let output = driver_run(Command::Version, Format::Text)?;
        println!(
            "{}",
            cli_output::normalize_cli_output(Format::Text, &output)
        );
        return Ok(());
    }
    if args.len() >= 2 && matches!(args[1].as_str(), "--help" | "-h") {
        print_help();
        return Ok(());
    }

    let json = args.iter().any(|a| a == "--json");
    let format = if json { Format::Json } else { Format::Text };
    let filtered: Vec<String> = args.into_iter().filter(|a| a != "--json").collect();

    let command = parse_command(&filtered)?;
    let raw_output = match driver_run(command.clone(), format) {
        Ok(output) => output,
        Err(error) => {
            if let Some(command_error) = error.downcast_ref::<CommandFailure>() {
                if !command_error.output.trim().is_empty() {
                    println!(
                        "{}",
                        cli_output::normalize_cli_output(format, &command_error.output)
                    );
                }
                std::process::exit(command_error.exit_code);
            }
            return Err(error);
        }
    };
    let output = cli_output::normalize_cli_output(format, &raw_output);
    println!("{output}");
    if let Some(exit_code) = infer_exit_code(&command, &raw_output, json) {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn infer_exit_code(command: &Command, output: &str, json: bool) -> Option<i32> {
    if json {
        let payload: serde_json::Value = serde_json::from_str(output).ok()?;
        return match command {
            Command::Build { .. } => payload
                .get("status")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|status| status == "error")
                .then_some(1),
            Command::DoctorProject { .. }
            | Command::DevLoop { .. }
            | Command::Lint { .. }
            | Command::Fmt { .. } => payload
                .get("status")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|status| status == "error")
                .then_some(1),
            Command::Run { .. } => payload
                .get("exitCode")
                .and_then(serde_json::Value::as_i64)
                .map(|code| code as i32)
                .filter(|code| *code != 0),
            Command::Check { .. } | Command::Verify { .. } | Command::LspDiagnostics { .. } => {
                let has_error = payload
                    .get("items")
                    .and_then(serde_json::Value::as_array)
                    .map(|items| {
                        items.iter().any(|item| {
                            item.get("severity")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|severity| severity == "Error")
                        })
                    })
                    .or_else(|| {
                        payload
                            .get("diagnostics")
                            .and_then(serde_json::Value::as_array)
                            .map(|items| {
                                items.iter().any(|item| {
                                    item.get("severity")
                                        .and_then(serde_json::Value::as_str)
                                        .is_some_and(|severity| severity == "Error")
                                })
                            })
                    })
                    .unwrap_or_else(|| {
                        payload
                            .get("ok")
                            .and_then(serde_json::Value::as_bool)
                            .is_some_and(|ok| !ok)
                    });
                if has_error {
                    Some(1)
                } else {
                    None
                }
            }
            _ => None,
        };
    }

    match command {
        Command::Run { .. } => output
            .split("exit_code=")
            .nth(1)
            .and_then(|tail| tail.split(';').next())
            .and_then(|raw| raw.trim().parse::<i32>().ok())
            .filter(|code| *code != 0),
        Command::Check { .. } | Command::Verify { .. } | Command::LspDiagnostics { .. } => {
            let errors = output
                .split("errors=")
                .nth(1)
                .and_then(|tail| tail.split_whitespace().next())
                .and_then(|raw| raw.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if errors > 0 || output.contains("ok=false") {
                Some(1)
            } else {
                None
            }
        }
        Command::DoctorProject { .. }
        | Command::DevLoop { .. }
        | Command::Lint { .. }
        | Command::Fmt { .. } => {
            if output.contains("status: error") {
                Some(1)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_command(args: &[String]) -> Result<Command> {
    match args.first().map(String::as_str) {
        Some("init") => {
            let path = command_path_or_cwd(args, 1, &["--template", "--with", "--name"])?;
            let package_name = parse_string_flag(args, "--name")?;
            let template = parse_string_flag(args, "--template")?;
            let with = parse_csv_flag(args, "--with")?;
            let force = has_flag(args, "--force");
            Ok(Command::Init {
                path,
                package_name,
                template,
                with,
                force,
            })
        }
        Some("build") => {
            let path = arg_path_or_cwd(args, 1)?;
            let release = args.iter().any(|a| a == "--release");
            let lib = args.iter().any(|a| a == "--lib");
            let threads = parse_u16_flag(args, "--threads")?;
            let backend = parse_backend_flag(args)?;
            let pgo_generate = has_flag(args, "--pgo-generate");
            let pgo_use = parse_path_flag(args, "--pgo-use")?;
            if pgo_generate && pgo_use.is_some() {
                bail!("--pgo-generate and --pgo-use are mutually exclusive");
            }
            let link_libs = parse_repeated_value_flags(args, &["-l", "--link-lib"])?;
            let link_search = parse_repeated_value_flags(args, &["-L", "--link-search"])?;
            let frameworks = parse_repeated_value_flags(args, &["-framework", "--framework"])?;
            Ok(Command::Build {
                path,
                release,
                lib,
                threads,
                backend,
                pgo_generate,
                pgo_use,
                link_libs,
                link_search,
                frameworks,
            })
        }
        Some("run") => {
            let path = command_path_or_cwd(
                args,
                1,
                &[
                    "--seed",
                    "--record",
                    "--backend",
                    "--max-seconds",
                    "--exit-on-healthcheck",
                    "--smoke-http",
                ],
            )?;
            if has_flag(args, "--strict") {
                bail!("`--strict` was removed; use `--strict-verify`");
            }
            if has_flag(args, "--safe-profile") {
                bail!(
                    "`--safe-profile` was removed; production memory safety is always enabled for `run`"
                );
            }
            let split = args.iter().position(|a| a == "--").unwrap_or(args.len());
            let passthrough = if split < args.len() {
                args[(split + 1)..].to_vec()
            } else {
                Vec::new()
            };
            let deterministic = has_flag(args, "--det");
            let strict_verify = has_flag(args, "--strict-verify");
            let seed = parse_u64_flag(args, "--seed")?;
            let record = parse_path_flag(args, "--record")?;
            let host_backends = has_flag(args, "--host-backends");
            let backend = parse_backend_flag(args)?;
            let max_seconds = parse_u64_flag(args, "--max-seconds")?;
            let exit_on_healthcheck = parse_string_flag(args, "--exit-on-healthcheck")?;
            let smoke_http = parse_string_flag(args, "--smoke-http")?;
            Ok(Command::Run {
                path,
                args: passthrough,
                deterministic,
                strict_verify,
                safe_profile: false,
                seed,
                record,
                host_backends,
                backend,
                max_seconds,
                exit_on_healthcheck,
                smoke_http,
            })
        }
        Some("test") => {
            let path = command_path_or_cwd(
                args,
                1,
                &["--seed", "--record", "--backend", "--sched", "--filter"],
            )?;
            if has_flag(args, "--strict") {
                bail!("`--strict` was removed; use `--strict-verify`");
            }
            if has_flag(args, "--safe-profile") {
                bail!(
                    "`--safe-profile` was removed; production memory safety is always enabled for `test`"
                );
            }
            let deterministic = has_flag(args, "--det");
            let strict_verify = has_flag(args, "--strict-verify");
            let seed = parse_u64_flag(args, "--seed")?;
            let record = parse_path_flag(args, "--record")?;
            let host_backends = has_flag(args, "--host-backends");
            let backend = parse_backend_flag(args)?;
            let scheduler = parse_string_flag(args, "--sched")?;
            let rich_artifacts = has_flag(args, "--rich-artifacts");
            let filter = parse_string_flag(args, "--filter")?;
            Ok(Command::Test {
                path,
                deterministic,
                strict_verify,
                safe_profile: false,
                seed,
                record,
                host_backends,
                backend,
                scheduler,
                rich_artifacts,
                filter,
            })
        }
        Some("fmt") => {
            let check = has_flag(args, "--check");
            let targets = args
                .iter()
                .skip(1)
                .filter(|arg| !arg.starts_with("--"))
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            Ok(Command::Fmt { targets, check })
        }
        Some("check") => Ok(Command::Check {
            path: arg_path_or_cwd(args, 1)?,
        }),
        Some("verify") => Ok(Command::Verify {
            path: arg_path_or_cwd(args, 1)?,
        }),
        Some("lint") => Ok(Command::Lint {
            path: arg_path_or_cwd(args, 1)?,
            tier: parse_string_flag(args, "--tier")?.unwrap_or_else(|| "production".to_string()),
        }),
        Some("explain") => Ok(Command::Explain {
            diag_code: args
                .get(1)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing <diag-code>"))?,
        }),
        Some("doctor") => match args.get(1).map(String::as_str) {
            Some("project") => Ok(Command::DoctorProject {
                path: arg_path_or_cwd(args, 2)?,
                strict: has_flag(args, "--strict"),
            }),
            _ if has_flag(args, "--scenario") => Ok(Command::ScenarioDoctor {
                scenario: parse_path_flag(args, "--scenario")?
                    .ok_or_else(|| anyhow::anyhow!("missing value for --scenario"))?,
                runs: parse_u64_flag(args, "--runs")?,
                seed: parse_u64_flag(args, "--seed")?,
                strict: has_flag(args, "--strict"),
                deep: has_flag(args, "--deep"),
                host_backends: has_flag(args, "--host-backends"),
            }),
            _ => {
                print_help();
                bail!("unknown doctor subcommand")
            }
        },
        Some("devloop") => Ok(Command::DevLoop {
            path: arg_path_or_cwd(args, 1)?,
            backend: parse_backend_flag(args)?,
        }),
        Some("dx-check") => Ok(Command::DxCheck {
            path: arg_path_or_cwd(args, 1)?,
            strict: has_flag(args, "--strict"),
        }),
        Some("spec-check") => Ok(Command::SpecCheck),
        Some("emit-ir") => Ok(Command::EmitIr {
            path: arg_path_or_cwd(args, 1)?,
        }),
        Some("perf") => Ok(Command::Perf {
            artifact: parse_path_flag(args, "--artifact")?,
        }),
        Some("artifacts") => match (
            args.get(1).map(String::as_str),
            args.get(2).map(String::as_str),
        ) {
            (Some("ls"), Some("latest")) => Ok(Command::ArtifactsLsLatest),
            _ => {
                print_help();
                bail!("unknown artifacts subcommand")
            }
        },
        Some("report") => match (
            args.get(1).map(String::as_str),
            args.get(2).map(String::as_str),
        ) {
            (Some("show"), Some("latest")) => Ok(Command::ReportShowLatest {
                output_format: parse_string_flag(args, "--format")?
                    .unwrap_or_else(|| "json".to_string()),
            }),
            _ => {
                print_help();
                bail!("unknown report subcommand")
            }
        },
        Some("stability-dashboard") => Ok(Command::StabilityDashboard),
        Some("parity") => Ok(Command::Parity {
            path: arg_path_or_cwd(args, 1)?,
            seed: parse_u64_flag(args, "--seed")?,
        }),
        Some("equivalence") => Ok(Command::Equivalence {
            path: arg_path_or_cwd(args, 1)?,
            seed: parse_u64_flag(args, "--seed")?,
        }),
        Some("audit") => match args.get(1).map(String::as_str) {
            Some("unsafe") => Ok(Command::AuditUnsafe {
                path: arg_path_or_cwd(args, 2)?,
                workspace: has_flag(args, "--workspace"),
            }),
            _ => {
                print_help();
                bail!("unknown audit subcommand")
            }
        },
        Some("vendor") => Ok(Command::Vendor {
            path: arg_path_or_cwd(args, 1)?,
        }),
        Some("abi-check") => Ok(Command::AbiCheck {
            current: arg_path(args, 1)?,
            baseline: parse_path_flag(args, "--baseline")?
                .ok_or_else(|| anyhow::anyhow!("missing value for --baseline"))?,
        }),
        Some("debug-check") => Ok(Command::DebugCheck {
            path: arg_path_or_cwd(args, 1)?,
        }),
        Some("pgo") => match args.get(1).map(String::as_str) {
            Some("merge") => Ok(Command::PgoMerge {
                path: arg_path_or_cwd(args, 2)?,
                output: parse_path_flag(args, "--out")?,
            }),
            _ => {
                print_help();
                bail!("unknown pgo subcommand")
            }
        },
        Some("lsp") => match args.get(1).map(String::as_str) {
            Some("serve") => Ok(Command::LspServe {
                path: parse_path_flag(args, "--path")?,
            }),
            Some("diagnostics") => Ok(Command::LspDiagnostics {
                path: arg_path_or_cwd(args, 2)?,
            }),
            Some("definition") => Ok(Command::LspDefinition {
                path: arg_path(args, 2)?,
                symbol: args
                    .get(3)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing <symbol>"))?,
            }),
            Some("hover") => Ok(Command::LspHover {
                path: arg_path(args, 2)?,
                symbol: args
                    .get(3)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing <symbol>"))?,
            }),
            Some("rename") => Ok(Command::LspRename {
                path: arg_path(args, 2)?,
                from: args
                    .get(3)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing <from>"))?,
                to: args
                    .get(4)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing <to>"))?,
            }),
            Some("smoke") => Ok(Command::LspSmoke {
                path: arg_path_or_cwd(args, 2)?,
            }),
            _ => {
                print_help();
                bail!("unknown lsp subcommand")
            }
        },
        Some("fuzz") => Ok(Command::Fuzz {
            target: arg_path(args, 1)?,
        }),
        Some("explore") => Ok(Command::Explore {
            target: arg_path(args, 1)?,
        }),
        Some("map") => match args.get(1).map(String::as_str) {
            Some("suites") => Ok(Command::MapSuites {
                root: parse_path_flag(args, "--root")?.unwrap_or_else(|| PathBuf::from(".")),
                scenario_root: parse_path_flag(args, "--scenario-root")?
                    .unwrap_or_else(|| PathBuf::from("tests")),
                profile: parse_string_flag(args, "--profile")?
                    .unwrap_or_else(|| "pedantic".to_string()),
            }),
            _ => {
                print_help();
                bail!("unknown map subcommand")
            }
        },
        Some("usage") => Ok(Command::Usage),
        Some("env") => Ok(Command::Env),
        Some("schema") => Ok(Command::Schema),
        Some("validate") => Ok(Command::Validate {
            scenario: arg_path(args, 1)?,
        }),
        Some("trace") => match args.get(1).map(String::as_str) {
            Some("verify") => Ok(Command::TraceVerify {
                trace: arg_path(args, 2)?,
                strict: has_flag(args, "--strict"),
            }),
            _ => {
                print_help();
                bail!("unknown trace subcommand")
            }
        },
        Some("replay") => Ok(Command::Replay {
            trace: arg_path(args, 1)?,
        }),
        Some("shrink") => Ok(Command::Shrink {
            trace: arg_path(args, 1)?,
        }),
        Some("ci") => Ok(Command::Ci {
            trace: arg_path(args, 1)?,
        }),
        Some("trace-native") => Ok(Command::TraceNative {
            trace: arg_path(args, 1)?,
            output: parse_path_flag(args, "--out")?,
        }),
        Some("headers") => Ok(Command::Headers {
            path: arg_path_or_cwd(args, 1)?,
            output: parse_path_flag(args, "--out")?,
        }),
        Some("rpc") => match args.get(1).map(String::as_str) {
            Some("gen") => Ok(Command::RpcGen {
                path: arg_path_or_cwd(args, 2)?,
                out_dir: parse_path_flag(args, "--out-dir")?,
            }),
            _ => {
                print_help();
                bail!("unknown rpc subcommand")
            }
        },
        Some("doc") => match args.get(1).map(String::as_str) {
            Some("gen") => Ok(Command::DocGen {
                path: arg_path_or_cwd(args, 2)?,
                format: parse_string_flag(args, "--format")?.unwrap_or_else(|| "json".to_string()),
                out: parse_path_flag(args, "--out")?,
                reference: parse_path_flag(args, "--reference")?,
            }),
            _ => {
                print_help();
                bail!("unknown doc subcommand")
            }
        },
        Some("inspect") => match args.get(1).map(String::as_str) {
            Some("surface") => Ok(Command::InspectSurface),
            Some("artifacts") => Ok(Command::InspectArtifacts {
                path: arg_path_or_cwd(args, 2)?,
                release: has_flag(args, "--release"),
                backend: parse_backend_flag(args)?,
            }),
            Some("embedding") => Ok(Command::InspectEmbedding {
                path: arg_path_or_cwd(args, 2)?,
            }),
            _ => {
                print_help();
                bail!("unknown inspect subcommand")
            }
        },
        Some("version") => Ok(Command::Version),
        Some("--version") => Ok(Command::Version),
        _ => {
            print_help();
            bail!("unknown command")
        }
    }
}

fn arg_path(args: &[String], idx: usize) -> Result<PathBuf> {
    let raw = args
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("missing required <path> argument"))?;
    Ok(PathBuf::from(raw))
}

fn arg_path_or_cwd(args: &[String], idx: usize) -> Result<PathBuf> {
    match args.get(idx) {
        None => std::env::current_dir().context("failed to resolve current working directory"),
        Some(raw) if raw.starts_with('-') => {
            std::env::current_dir().context("failed to resolve current working directory")
        }
        Some(raw) => Ok(PathBuf::from(raw)),
    }
}

fn command_path_or_cwd(args: &[String], start_idx: usize, value_flags: &[&str]) -> Result<PathBuf> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let mut idx = start_idx;
    while idx < split {
        let raw = &args[idx];
        if value_flags.iter().any(|flag| raw == flag) {
            idx += 2;
            continue;
        }
        if raw.starts_with('-') {
            idx += 1;
            continue;
        }
        return Ok(PathBuf::from(raw));
    }
    std::env::current_dir().context("failed to resolve current working directory")
}

fn print_help() {
    eprintln!(
        "fz <command> [options]\n\
commands:\n\
  init [path] [--name package] [--template minimal|rust|ts] [--with run,fuzz,explore,memory,host|all] [--force]\n\
  build [path] [--release] [--lib] [--threads N] [--backend llvm|cranelift] [--pgo-generate|--pgo-use file] [-l lib] [-L path] [-framework name]\n\
  run [path] [--det] [--strict-verify] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--max-seconds N] [--exit-on-healthcheck URL] [--smoke-http URL] [-- <args>]\n\
  test [path] [--det] [--strict-verify] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--sched policy] [--filter substring]\n\
  fmt [path ...] [--check]\n\
  check [path]\n\
  verify [path]\n\
  lint [path] [--tier production|pedantic|compat]\n\
  explain <diag-code>\n\
  doctor project [path] [--strict]\n\
  doctor --deep --scenario <scenario> [--runs N] [--seed N] [--strict] [--host-backends]\n\
  devloop [path] [--backend llvm|cranelift]\n\
  dx-check [project] [--strict]\n\
  spec-check\n\
  emit-ir [path]\n\
  perf [--artifact path]\n\
  artifacts ls latest\n\
  report show latest [--format json|text]\n\
  stability-dashboard\n\
  parity [path] [--seed N]\n\
  equivalence [path] [--seed N]\n\
  audit unsafe [path] [--workspace]\n\
  vendor [project]\n\
  abi-check <current.abi.json> --baseline <baseline.abi.json>\n\
  debug-check [path]\n\
  pgo merge [path] [--out file]\n\
  lsp serve [--path workspace]\n\
  lsp diagnostics [path]\n\
  lsp definition <path> <symbol>\n\
  lsp hover <path> <symbol>\n\
  lsp rename <path> <from> <to>\n\
  lsp smoke [path]\n\
  headers [path] [--out path]\n\
  rpc gen [path] [--out-dir dir]\n\
  doc gen [path] [--format json|html|markdown] [--out path] [--reference path]\n\
  inspect surface\n\
  inspect artifacts [path] [--release] [--backend llvm|cranelift]\n\
  inspect embedding [path]\n\
  fuzz <scenario>\n\
  explore <scenario>\n\
  map suites [--root dir] [--scenario-root dir] [--profile pedantic|production|compat]\n\
  usage\n\
  env\n\
  schema\n\
  validate <scenario>\n\
  trace verify <trace> [--strict]\n\
  replay <trace>\n\
  shrink <trace>\n\
  ci <trace>\n\
  trace-native <trace.fozzy> [--out path]\n\
  version|--version\n\
flags:\n\
  --json\n\
  --det\n\
  --strict-verify\n\
  --check\n\
  --deep\n\
  --seed <u64>\n\
  --record <path>\n\
  --host-backends\n\
  --scenario <path>\n\
  --runs <u64>\n\
  --max-seconds <u64>\n\
  --exit-on-healthcheck <http://host:port/path>\n\
  --smoke-http <http://host:port/path>\n\
  --backend <llvm|cranelift>\n\
  --lib\n\
  -l|--link-lib <name> (repeatable)\n\
  -L|--link-search <path> (repeatable)\n\
  -framework|--framework <name> (repeatable)\n\
  --threads <u16>\n\
  --pgo-generate\n\
  --pgo-use <file>\n\
  --sched <fifo|random|coverage_guided>\n\
  --filter <substring>\n\
  --root <path>\n\
  --scenario-root <path>\n\
  --profile <name>\n\
  --rich-artifacts\n\
  --out <path>\n\
  --reference <path>\n\
  --out-dir <dir>\n\
  --tier <production|pedantic|compat>\n\
  --artifact <path>\n\
  --baseline <path>\n\
  --strict"
    );
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn parse_u64_flag(args: &[String], flag: &str) -> Result<Option<u64>> {
    if let Some(index) = args.iter().position(|a| a == flag) {
        let raw = args
            .get(index + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?;
        let value = raw
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("invalid integer for {flag}: {raw}"))?;
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

fn parse_u16_flag(args: &[String], flag: &str) -> Result<Option<u16>> {
    if let Some(index) = args.iter().position(|a| a == flag) {
        let raw = args
            .get(index + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?;
        let value = raw
            .parse::<u16>()
            .map_err(|_| anyhow::anyhow!("invalid integer for {flag}: {raw}"))?;
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

fn parse_string_flag(args: &[String], flag: &str) -> Result<Option<String>> {
    if let Some(index) = args.iter().position(|a| a == flag) {
        let raw = args
            .get(index + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?;
        Ok(Some(raw.clone()))
    } else {
        Ok(None)
    }
}

fn parse_path_flag(args: &[String], flag: &str) -> Result<Option<PathBuf>> {
    if let Some(index) = args.iter().position(|a| a == flag) {
        let raw = args
            .get(index + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?;
        Ok(Some(PathBuf::from(raw)))
    } else {
        Ok(None)
    }
}

fn parse_backend_flag(args: &[String]) -> Result<Option<String>> {
    let Some(value) = parse_string_flag(args, "--backend")? else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "llvm" | "cranelift" => Ok(Some(normalized)),
        _ => bail!("invalid --backend `{value}`; expected `llvm` or `cranelift`"),
    }
}

fn parse_repeated_value_flags(args: &[String], flags: &[&str]) -> Result<Vec<String>> {
    let mut values = Vec::new();
    let mut idx = 0usize;
    while idx < args.len() {
        if flags.iter().any(|flag| args[idx] == *flag) {
            let value = args
                .get(idx + 1)
                .ok_or_else(|| anyhow::anyhow!("missing value for {}", args[idx]))?;
            values.push(value.clone());
            idx += 2;
            continue;
        }
        idx += 1;
    }
    Ok(values)
}

fn parse_csv_flag(args: &[String], flag: &str) -> Result<Vec<String>> {
    let Some(raw) = parse_string_flag(args, flag)? else {
        return Ok(Vec::new());
    };
    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::parse_command;
    use driver::Command;
    use std::path::PathBuf;
    #[test]
    fn parse_command_accepts_long_version_flag_alias() {
        let args = vec!["--version".to_string()];
        let command = parse_command(&args).expect("`--version` should parse");
        assert!(matches!(command, Command::Version));
    }

    #[test]
    fn parse_command_keeps_version_subcommand() {
        let args = vec!["version".to_string()];
        let command = parse_command(&args).expect("`version` should parse");
        assert!(matches!(command, Command::Version));
    }

    #[test]
    fn parse_init_defaults_to_current_directory() {
        let cwd = std::env::current_dir().expect("cwd should resolve");
        let command = parse_command(&["init".to_string()]).expect("init should parse");
        match command {
            Command::Init {
                path,
                package_name,
                template,
                with,
                force,
            } => {
                assert_eq!(path, cwd);
                assert_eq!(package_name, None);
                assert_eq!(template, None);
                assert!(with.is_empty());
                assert!(!force);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_init_accepts_path_template_name_and_with_flags() {
        let command = parse_command(&[
            "init".to_string(),
            "demo-app".to_string(),
            "--name".to_string(),
            "demo_pkg".to_string(),
            "--template".to_string(),
            "rust".to_string(),
            "--with".to_string(),
            "run,memory,host".to_string(),
            "--force".to_string(),
        ])
        .expect("init flags should parse");
        match command {
            Command::Init {
                path,
                package_name,
                template,
                with,
                force,
            } => {
                assert_eq!(path, PathBuf::from("demo-app"));
                assert_eq!(package_name.as_deref(), Some("demo_pkg"));
                assert_eq!(template.as_deref(), Some("rust"));
                assert_eq!(with, vec!["run", "memory", "host"]);
                assert!(force);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_artifacts_and_report_commands() {
        assert!(matches!(
            parse_command(&[
                "artifacts".to_string(),
                "ls".to_string(),
                "latest".to_string()
            ])
            .expect("artifacts latest should parse"),
            Command::ArtifactsLsLatest
        ));
        assert!(matches!(
            parse_command(&[
                "report".to_string(),
                "show".to_string(),
                "latest".to_string(),
                "--format".to_string(),
                "json".to_string()
            ])
            .expect("report latest should parse"),
            Command::ReportShowLatest { .. }
        ));
    }

    #[test]
    fn parse_run_rejects_removed_safe_profile_flag() {
        let args = vec![
            "run".to_string(),
            "main.fzy".to_string(),
            "--safe-profile".to_string(),
        ];
        let err = parse_command(&args).expect_err("safe profile flag must be rejected");
        assert!(err
            .to_string()
            .contains("production memory safety is always enabled"));
    }

    #[test]
    fn parse_test_rejects_removed_safe_profile_flag() {
        let args = vec![
            "test".to_string(),
            "main.fzy".to_string(),
            "--safe-profile".to_string(),
        ];
        let err = parse_command(&args).expect_err("safe profile flag must be rejected");
        assert!(err
            .to_string()
            .contains("production memory safety is always enabled"));
    }

    #[test]
    fn parse_trace_native_command() {
        let args = vec![
            "trace-native".to_string(),
            "artifacts/run.trace.fozzy".to_string(),
            "--out".to_string(),
            "artifacts/run.trace.json".to_string(),
        ];
        let command = parse_command(&args).expect("trace-native should parse");
        assert!(matches!(command, Command::TraceNative { .. }));
    }

    #[test]
    fn parse_map_suites_command() {
        let args = vec![
            "map".to_string(),
            "suites".to_string(),
            "--root".to_string(),
            ".".to_string(),
            "--scenario-root".to_string(),
            "tests".to_string(),
            "--profile".to_string(),
            "pedantic".to_string(),
        ];
        let command = parse_command(&args).expect("map suites should parse");
        assert!(matches!(command, Command::MapSuites { .. }));
    }

    #[test]
    fn parse_scenario_doctor_command() {
        let args = vec![
            "doctor".to_string(),
            "--deep".to_string(),
            "--scenario".to_string(),
            "tests/example.fozzy.json".to_string(),
            "--runs".to_string(),
            "5".to_string(),
            "--seed".to_string(),
            "4242".to_string(),
            "--host-backends".to_string(),
        ];
        let command = parse_command(&args).expect("scenario doctor should parse");
        assert!(matches!(command, Command::ScenarioDoctor { .. }));
    }

    #[test]
    fn parse_usage_env_schema_validate_commands() {
        assert!(matches!(
            parse_command(&["usage".to_string()]).expect("usage should parse"),
            Command::Usage
        ));
        assert!(matches!(
            parse_command(&["env".to_string()]).expect("env should parse"),
            Command::Env
        ));
        assert!(matches!(
            parse_command(&["schema".to_string()]).expect("schema should parse"),
            Command::Schema
        ));
        assert!(matches!(
            parse_command(&[
                "validate".to_string(),
                "tests/example.fozzy.json".to_string()
            ])
            .expect("validate should parse"),
            Command::Validate { .. }
        ));
        assert!(matches!(
            parse_command(&[
                "trace".to_string(),
                "verify".to_string(),
                "artifacts/demo.trace.fozzy".to_string(),
                "--strict".to_string()
            ])
            .expect("trace verify should parse"),
            Command::TraceVerify { .. }
        ));
    }

    #[test]
    fn parse_check_defaults_to_current_directory() {
        let args = vec!["check".to_string()];
        let command = parse_command(&args).expect("check should parse without path");
        let cwd = std::env::current_dir().expect("cwd should resolve");
        match command {
            Command::Check { path } => assert_eq!(path, cwd),
            _ => panic!("expected check command"),
        }
    }

    #[test]
    fn parse_run_defaults_to_current_directory_when_first_arg_is_flag() {
        let args = vec!["run".to_string(), "--det".to_string()];
        let command = parse_command(&args).expect("run should parse without explicit path");
        let cwd = std::env::current_dir().expect("cwd should resolve");
        match command {
            Command::Run {
                path,
                deterministic,
                ..
            } => {
                assert_eq!(path, cwd);
                assert!(deterministic);
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn parse_run_accepts_flag_first_path_style() {
        let args = vec![
            "run".to_string(),
            "--det".to_string(),
            "--seed".to_string(),
            "1337".to_string(),
            "tests/run.pass.fozzy.json".to_string(),
        ];
        let command = parse_command(&args).expect("run should parse flag-first path");
        match command {
            Command::Run {
                path,
                deterministic,
                seed,
                ..
            } => {
                assert_eq!(path, PathBuf::from("tests/run.pass.fozzy.json"));
                assert!(deterministic);
                assert_eq!(seed, Some(1337));
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn parse_test_accepts_flag_first_path_style() {
        let args = vec![
            "test".to_string(),
            "--det".to_string(),
            "--strict-verify".to_string(),
            "tests/example.fozzy.json".to_string(),
        ];
        let command = parse_command(&args).expect("test should parse flag-first path");
        match command {
            Command::Test {
                path,
                deterministic,
                strict_verify,
                ..
            } => {
                assert_eq!(path, PathBuf::from("tests/example.fozzy.json"));
                assert!(deterministic);
                assert!(strict_verify);
            }
            _ => panic!("expected test command"),
        }
    }

    #[test]
    fn parse_lsp_diagnostics_defaults_to_current_directory() {
        let args = vec!["lsp".to_string(), "diagnostics".to_string()];
        let command = parse_command(&args).expect("lsp diagnostics should parse without path");
        let cwd = std::env::current_dir().expect("cwd should resolve");
        match command {
            Command::LspDiagnostics { path } => assert_eq!(path, cwd),
            _ => panic!("expected lsp diagnostics command"),
        }
    }

    #[test]
    fn parse_explain_command() {
        let args = vec!["explain".to_string(), "E-DRV-1234ABCD".to_string()];
        let command = parse_command(&args).expect("explain should parse");
        match command {
            Command::Explain { diag_code } => assert_eq!(diag_code, "E-DRV-1234ABCD"),
            _ => panic!("expected explain command"),
        }
    }

    #[test]
    fn parse_doctor_project_defaults_to_current_directory() {
        let args = vec!["doctor".to_string(), "project".to_string()];
        let command = parse_command(&args).expect("doctor project should parse");
        match command {
            Command::DoctorProject { path, strict } => {
                assert_eq!(path, std::env::current_dir().expect("cwd"));
                assert!(!strict);
            }
            _ => panic!("expected doctor project command"),
        }
    }

    #[test]
    fn parse_devloop_command() {
        let args = vec![
            "devloop".to_string(),
            "examples/minimal_runtime".to_string(),
            "--backend".to_string(),
            "cranelift".to_string(),
        ];
        let command = parse_command(&args).expect("devloop should parse");
        match command {
            Command::DevLoop { path, backend } => {
                assert_eq!(path, PathBuf::from("examples/minimal_runtime"));
                assert_eq!(backend.as_deref(), Some("cranelift"));
            }
            _ => panic!("expected devloop command"),
        }
    }

    #[test]
    fn parse_lint_command_with_tier() {
        let args = vec![
            "lint".to_string(),
            "examples/fullstack".to_string(),
            "--tier".to_string(),
            "pedantic".to_string(),
        ];
        let command = parse_command(&args).expect("lint should parse");
        match command {
            Command::Lint { path, tier } => {
                assert_eq!(path, PathBuf::from("examples/fullstack"));
                assert_eq!(tier, "pedantic");
            }
            _ => panic!("expected lint command"),
        }
    }

    #[test]
    fn parse_perf_command_defaults_to_default_artifact() {
        let args = vec!["perf".to_string()];
        let command = parse_command(&args).expect("perf should parse");
        assert!(matches!(command, Command::Perf { artifact: None }));
    }

    #[test]
    fn parse_stability_dashboard_command() {
        let args = vec!["stability-dashboard".to_string()];
        let command = parse_command(&args).expect("stability dashboard should parse");
        assert!(matches!(command, Command::StabilityDashboard));
    }

    #[test]
    fn parse_build_with_pgo_generate() {
        let args = vec![
            "build".to_string(),
            "examples/fullstack".to_string(),
            "--pgo-generate".to_string(),
            "--backend".to_string(),
            "llvm".to_string(),
        ];
        let command = parse_command(&args).expect("build pgo-generate should parse");
        match command {
            Command::Build {
                path,
                pgo_generate,
                pgo_use,
                backend,
                ..
            } => {
                assert_eq!(path, PathBuf::from("examples/fullstack"));
                assert!(pgo_generate);
                assert!(pgo_use.is_none());
                assert_eq!(backend.as_deref(), Some("llvm"));
            }
            _ => panic!("expected build command"),
        }
    }

    #[test]
    fn parse_build_with_pgo_use() {
        let args = vec![
            "build".to_string(),
            "examples/fullstack".to_string(),
            "--pgo-use".to_string(),
            "artifacts/default.profdata".to_string(),
        ];
        let command = parse_command(&args).expect("build pgo-use should parse");
        match command {
            Command::Build {
                pgo_generate,
                pgo_use,
                ..
            } => {
                assert!(!pgo_generate);
                assert_eq!(pgo_use, Some(PathBuf::from("artifacts/default.profdata")));
            }
            _ => panic!("expected build command"),
        }
    }

    #[test]
    fn parse_build_rejects_pgo_generate_and_pgo_use_together() {
        let args = vec![
            "build".to_string(),
            "examples/fullstack".to_string(),
            "--pgo-generate".to_string(),
            "--pgo-use".to_string(),
            "artifacts/default.profdata".to_string(),
        ];
        let error = parse_command(&args).expect_err("combined pgo flags should fail");
        assert!(error
            .to_string()
            .contains("--pgo-generate and --pgo-use are mutually exclusive"));
    }

    #[test]
    fn parse_pgo_merge_defaults_to_current_directory() {
        let args = vec!["pgo".to_string(), "merge".to_string()];
        let command = parse_command(&args).expect("pgo merge should parse");
        match command {
            Command::PgoMerge { path, output } => {
                assert_eq!(path, std::env::current_dir().expect("cwd"));
                assert!(output.is_none());
            }
            _ => panic!("expected pgo merge command"),
        }
    }

    #[test]
    fn parse_pgo_merge_with_path_and_output() {
        let args = vec![
            "pgo".to_string(),
            "merge".to_string(),
            ".fz/pgo/default".to_string(),
            "--out".to_string(),
            "artifacts/default.profdata".to_string(),
        ];
        let command = parse_command(&args).expect("pgo merge should parse");
        match command {
            Command::PgoMerge { path, output } => {
                assert_eq!(path, PathBuf::from(".fz/pgo/default"));
                assert_eq!(output, Some(PathBuf::from("artifacts/default.profdata")));
            }
            _ => panic!("expected pgo merge command"),
        }
    }
}
