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
            Ok(Command::Build {
                path,
                release,
                threads,
            })
        }
        Some("run") => {
            let path = arg_path(args, 1)?;
            let split = args.iter().position(|a| a == "--").unwrap_or(args.len());
            let passthrough = if split < args.len() {
                args[(split + 1)..].to_vec()
            } else {
                Vec::new()
            };
            let deterministic = has_flag(args, "--det");
            let strict = has_flag(args, "--strict");
            let seed = parse_u64_flag(args, "--seed")?;
            let record = parse_path_flag(args, "--record")?;
            let host_backends = has_flag(args, "--host-backends");
            Ok(Command::Run {
                path,
                args: passthrough,
                deterministic,
                strict,
                seed,
                record,
                host_backends,
            })
        }
        Some("test") => {
            let path = arg_path(args, 1)?;
            let deterministic = has_flag(args, "--det");
            let strict = has_flag(args, "--strict");
            let seed = parse_u64_flag(args, "--seed")?;
            let record = parse_path_flag(args, "--record")?;
            let host_backends = has_flag(args, "--host-backends");
            let scheduler = parse_string_flag(args, "--sched")?;
            let rich_artifacts = has_flag(args, "--rich-artifacts");
            Ok(Command::Test {
                path,
                deterministic,
                strict,
                seed,
                record,
                host_backends,
                scheduler,
                rich_artifacts,
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
        Some("emit-ir") => Ok(Command::EmitIr {
            path: arg_path(args, 1)?,
        }),
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
  build <path> [--release] [--threads N]\n\
  run <path> [--det] [--strict] [--seed N] [--record path] [--host-backends] [-- <args>]\n\
  test <path> [--det] [--strict] [--seed N] [--record path] [--host-backends] [--sched policy]\n\
  fmt <path>\n\
  check <path>\n\
  verify <path>\n\
  emit-ir <path>\n\
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
  --strict\n\
  --seed <u64>\n\
  --record <path>\n\
  --host-backends\n\
  --threads <u16>\n\
  --sched <fifo|random|coverage_guided>\n\
  --rich-artifacts\n\
  --out <path>\n\
  --out-dir <dir>"
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
