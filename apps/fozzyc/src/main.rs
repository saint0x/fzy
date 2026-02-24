use std::path::PathBuf;

use anyhow::{bail, Result};
use driver::{run, Command, Format};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return Ok(());
    }

    let json = args.iter().any(|a| a == "--json");
    let format = if json { Format::Json } else { Format::Text };
    let filtered: Vec<String> = args.into_iter().filter(|a| a != "--json").collect();

    let command = parse_command(&filtered)?;
    let output = run(command, format)?;
    println!("{output}");
    Ok(())
}

fn parse_command(args: &[String]) -> Result<Command> {
    match args.first().map(String::as_str) {
        Some("init") => {
            let name = args
                .get(1)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing <name>"))?;
            Ok(Command::Init { name })
        }
        Some("build") => {
            let path = arg_path(args, 1)?;
            let release = args.iter().any(|a| a == "--release");
            let threads = parse_u16_flag(args, "--threads")?;
            let backend = parse_backend_flag(args)?;
            Ok(Command::Build {
                path,
                release,
                threads,
                backend,
            })
        }
        Some("run") => {
            let path = arg_path(args, 1)?;
            if has_flag(args, "--strict") {
                bail!("`--strict` was removed; use `--strict-verify` and/or `--safe-profile`");
            }
            let split = args.iter().position(|a| a == "--").unwrap_or(args.len());
            let passthrough = if split < args.len() {
                args[(split + 1)..].to_vec()
            } else {
                Vec::new()
            };
            let deterministic = has_flag(args, "--det");
            let strict_verify = has_flag(args, "--strict-verify");
            let safe_profile = has_flag(args, "--safe-profile");
            let seed = parse_u64_flag(args, "--seed")?;
            let record = parse_path_flag(args, "--record")?;
            let host_backends = has_flag(args, "--host-backends");
            let backend = parse_backend_flag(args)?;
            Ok(Command::Run {
                path,
                args: passthrough,
                deterministic,
                strict_verify,
                safe_profile,
                seed,
                record,
                host_backends,
                backend,
            })
        }
        Some("test") => {
            let path = arg_path(args, 1)?;
            if has_flag(args, "--strict") {
                bail!("`--strict` was removed; use `--strict-verify` and/or `--safe-profile`");
            }
            let deterministic = has_flag(args, "--det");
            let strict_verify = has_flag(args, "--strict-verify");
            let safe_profile = has_flag(args, "--safe-profile");
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
                safe_profile,
                seed,
                record,
                host_backends,
                backend,
                scheduler,
                rich_artifacts,
                filter,
            })
        }
        Some("fmt") => Ok(Command::Fmt {
            path: arg_path(args, 1)?,
        }),
        Some("check") => Ok(Command::Check {
            path: arg_path(args, 1)?,
        }),
        Some("verify") => Ok(Command::Verify {
            path: arg_path(args, 1)?,
        }),
        Some("spec-check") => Ok(Command::SpecCheck),
        Some("emit-ir") => Ok(Command::EmitIr {
            path: arg_path(args, 1)?,
        }),
        Some("parity") => Ok(Command::Parity {
            path: arg_path(args, 1)?,
            seed: parse_u64_flag(args, "--seed")?,
        }),
        Some("equivalence") => Ok(Command::Equivalence {
            path: arg_path(args, 1)?,
            seed: parse_u64_flag(args, "--seed")?,
        }),
        Some("audit") => match args.get(1).map(String::as_str) {
            Some("unsafe") => Ok(Command::AuditUnsafe {
                path: arg_path(args, 2)?,
            }),
            _ => {
                print_help();
                bail!("unknown audit subcommand")
            }
        },
        Some("vendor") => Ok(Command::Vendor {
            path: arg_path(args, 1)?,
        }),
        Some("abi-check") => Ok(Command::AbiCheck {
            current: arg_path(args, 1)?,
            baseline: parse_path_flag(args, "--baseline")?
                .ok_or_else(|| anyhow::anyhow!("missing value for --baseline"))?,
        }),
        Some("debug-check") => Ok(Command::DebugCheck {
            path: arg_path(args, 1)?,
        }),
        Some("lsp") => match args.get(1).map(String::as_str) {
            Some("diagnostics") => Ok(Command::LspDiagnostics {
                path: arg_path(args, 2)?,
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
                path: arg_path(args, 2)?,
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
        Some("replay") => Ok(Command::Replay {
            trace: arg_path(args, 1)?,
        }),
        Some("shrink") => Ok(Command::Shrink {
            trace: arg_path(args, 1)?,
        }),
        Some("ci") => Ok(Command::Ci {
            trace: arg_path(args, 1)?,
        }),
        Some("headers") => Ok(Command::Headers {
            path: arg_path(args, 1)?,
            output: parse_path_flag(args, "--out")?,
        }),
        Some("rpc") => match args.get(1).map(String::as_str) {
            Some("gen") => Ok(Command::RpcGen {
                path: arg_path(args, 2)?,
                out_dir: parse_path_flag(args, "--out-dir")?,
            }),
            _ => {
                print_help();
                bail!("unknown rpc subcommand")
            }
        },
        Some("version") => Ok(Command::Version),
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

fn print_help() {
    eprintln!(
        "fozzyc <command> [options]\n\
commands:\n\
  init <name>\n\
  build <path> [--release] [--threads N] [--backend llvm|cranelift]\n\
  run <path> [--det] [--strict-verify] [--safe-profile] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [-- <args>]\n\
  test <path> [--det] [--strict-verify] [--safe-profile] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--sched policy] [--filter substring]\n\
  fmt <path>\n\
  check <path>\n\
  verify <path>\n\
  spec-check\n\
  emit-ir <path>\n\
  parity <path> [--seed N]\n\
  equivalence <path> [--seed N]\n\
  audit unsafe <path>\n\
  vendor <project>\n\
  abi-check <current.abi.json> --baseline <baseline.abi.json>\n\
  debug-check <path>\n\
  lsp diagnostics <path>\n\
  lsp definition <path> <symbol>\n\
  lsp hover <path> <symbol>\n\
  lsp rename <path> <from> <to>\n\
  lsp smoke <path>\n\
  headers <path> [--out path]\n\
  rpc gen <path> [--out-dir dir]\n\
  fuzz <scenario>\n\
  explore <scenario>\n\
  replay <trace>\n\
  shrink <trace>\n\
  ci <trace>\n\
  version\n\
flags:\n\
  --json\n\
  --det\n\
  --strict-verify\n\
  --safe-profile\n\
  --seed <u64>\n\
  --record <path>\n\
  --host-backends\n\
  --backend <llvm|cranelift>\n\
  --threads <u16>\n\
  --sched <fifo|random|coverage_guided>\n\
  --filter <substring>\n\
  --rich-artifacts\n\
  --out <path>\n\
  --out-dir <dir>\n\
  --baseline <path>"
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
