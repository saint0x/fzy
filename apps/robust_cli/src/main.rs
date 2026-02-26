use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use core::{Capability, CapabilitySet};
use stdlib::concurrency::{BoundedChannel, OverflowPolicy};
use stdlib::durability::{acquire_file_lock, fsync_file, write_atomic};
use stdlib::observability::{
    LogField, LogLevel, Logger, Metrics, RedactionPolicy, RuntimeStats, Tracer,
};
use stdlib::process::EnvConfig;
use stdlib::security::{audit_privileged_operation, PrivilegedOperation, Secret};

const C_RESET: &str = "\x1b[0m";
const C_BOLD: &str = "\x1b[1m";
const C_RED: &str = "\x1b[31m";
const C_GREEN: &str = "\x1b[32m";
const C_YELLOW: &str = "\x1b[33m";
const C_BLUE: &str = "\x1b[34m";
const C_CYAN: &str = "\x1b[36m";

fn main() -> Result<()> {
    let cwd = std::env::current_dir().context("failed to read current directory")?;
    let state_dir = cwd.join("examples/robust_cli/.state");
    let state_file = state_dir.join("store.db");
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("failed to create state dir: {}", state_dir.display()))?;

    let env = EnvConfig::from_current_env();
    let channel_capacity = env.parse_usize("ROBUST_CLI_CHANNEL_CAP").unwrap_or(128);

    let mut app = App::new(state_file, channel_capacity)?;
    app.run()
}

struct App {
    store_path: PathBuf,
    store: BTreeMap<String, String>,
    logger: Logger,
    metrics: Metrics,
    tracer: Tracer,
    history: BoundedChannel<String>,
    last_secret: Option<Secret>,
}

impl App {
    fn new(store_path: PathBuf, history_capacity: usize) -> Result<Self> {
        let store = load_store(&store_path)?;
        let mut logger = Logger {
            min_level: LogLevel::Info,
            policy: RedactionPolicy::RedactKnownSecrets,
            ..Logger::default()
        };
        logger.log(
            LogLevel::Info,
            "robust cli initialized",
            Some("boot".to_string()),
            vec![LogField {
                key: "store_path".to_string(),
                value: store_path.display().to_string(),
                redacted: false,
            }],
        );

        Ok(Self {
            store_path,
            store,
            logger,
            metrics: Metrics::new(),
            tracer: Tracer::default(),
            history: BoundedChannel::new(history_capacity.max(8), OverflowPolicy::DropOldest),
            last_secret: None,
        })
    }

    fn run(&mut self) -> Result<()> {
        self.banner();
        self.help();

        let mut line = String::new();
        loop {
            print!("{C_BOLD}{C_BLUE}robust-cli>{C_RESET} ");
            io::stdout().flush().context("failed to flush stdout")?;
            line.clear();

            let bytes = io::stdin()
                .read_line(&mut line)
                .context("failed to read from stdin")?;
            if bytes == 0 {
                println!("{C_YELLOW}EOF received, exiting.{C_RESET}");
                break;
            }

            let input = line.trim();
            if input.is_empty() {
                continue;
            }
            let _ = self.history.send(input.to_string());

            match self.handle(input) {
                Ok(Control::Continue) => {}
                Ok(Control::Exit) => break,
                Err(err) => {
                    self.metrics.inc_counter("cmd.error", 1);
                    println!("{C_RED}error:{C_RESET} {err}");
                }
            }
        }

        Ok(())
    }

    fn handle(&mut self, input: &str) -> Result<Control> {
        let root = self.tracer.start_root(
            "cli.command",
            format!("cmd-{}", self.metrics.counter("cmd.total") + 1),
        );
        self.metrics.inc_counter("cmd.total", 1);

        let mut parts = input.split_whitespace();
        let cmd = parts.next().unwrap_or_default();
        match cmd {
            "help" => self.help(),
            "init" => {
                self.store.clear();
                self.persist()?;
                self.ok("initialized empty store");
            }
            "set" => {
                let key = parts.next().context("usage: set <key> <value>")?;
                let value = parts.collect::<Vec<_>>().join(" ");
                if value.is_empty() {
                    anyhow::bail!("usage: set <key> <value>");
                }
                self.store.insert(key.to_string(), value);
                self.persist()?;
                self.metrics.inc_counter("kv.set", 1);
                self.ok(&format!("set {key}"));
            }
            "get" => {
                let key = parts.next().context("usage: get <key>")?;
                match self.store.get(key) {
                    Some(value) => println!("{C_CYAN}{key}{C_RESET} = {value}"),
                    None => println!("{C_YELLOW}missing key:{C_RESET} {key}"),
                }
            }
            "del" => {
                let key = parts.next().context("usage: del <key>")?;
                let existed = self.store.remove(key).is_some();
                self.persist()?;
                if existed {
                    self.ok(&format!("deleted {key}"));
                } else {
                    println!("{C_YELLOW}key not found:{C_RESET} {key}");
                }
            }
            "list" => {
                if self.store.is_empty() {
                    println!("{C_YELLOW}store is empty{C_RESET}");
                } else {
                    println!("{C_BOLD}{C_CYAN}entries ({}){C_RESET}", self.store.len());
                    for (k, v) in &self.store {
                        println!("  {C_CYAN}{k}{C_RESET} = {v}");
                    }
                }
            }
            "compact" => {
                self.persist()?;
                self.ok("compacted and fsynced store");
            }
            "export" => {
                let target = parts
                    .next()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.store_path.with_extension("export.db"));
                self.export(&target)?;
                self.ok(&format!("exported to {}", target.display()));
            }
            "login" => {
                let token = parts.next().context("usage: login <token>")?;
                self.last_secret = Some(Secret::new(token));
                self.logger.log(
                    LogLevel::Info,
                    "operator login",
                    Some("auth".to_string()),
                    vec![LogField {
                        key: "api_token".to_string(),
                        value: token.to_string(),
                        redacted: false,
                    }],
                );
                self.ok("token captured (redacted in logs)");
            }
            "audit" => self.audit(),
            "stats" => self.stats(),
            "history" => self.print_history(),
            "clear" => {
                print!("\x1b[2J\x1b[H");
                io::stdout().flush().context("failed to flush clear")?;
            }
            "quit" | "exit" => {
                let _child = self.tracer.start_child(&root, "cli.exit");
                self.ok("bye");
                return Ok(Control::Exit);
            }
            _ => {
                println!("{C_YELLOW}unknown command:{C_RESET} {cmd}");
                self.help();
            }
        }

        Ok(Control::Continue)
    }

    fn banner(&self) {
        println!(
            "{C_BOLD}{C_GREEN}Robust CLI Interactive{C_RESET} {C_CYAN}v0{C_RESET}\nstore: {}",
            self.store_path.display()
        );
    }

    fn help(&self) {
        println!("{C_BOLD}commands{C_RESET}");
        println!("  {C_CYAN}help{C_RESET}                    show commands");
        println!("  {C_CYAN}init{C_RESET}                    reset store");
        println!("  {C_CYAN}set <k> <v>{C_RESET}             set key/value");
        println!("  {C_CYAN}get <k>{C_RESET}                 get value");
        println!("  {C_CYAN}del <k>{C_RESET}                 delete key");
        println!("  {C_CYAN}list{C_RESET}                    list all keys");
        println!("  {C_CYAN}compact{C_RESET}                 durable rewrite + fsync");
        println!("  {C_CYAN}export [path]{C_RESET}           export snapshot");
        println!("  {C_CYAN}login <token>{C_RESET}           capture secret (redacted)");
        println!("  {C_CYAN}audit{C_RESET}                   capability audit");
        println!("  {C_CYAN}stats{C_RESET}                   runtime stats + metrics");
        println!("  {C_CYAN}history{C_RESET}                 command history");
        println!("  {C_CYAN}clear{C_RESET}                   clear screen");
        println!("  {C_CYAN}quit{C_RESET}                    exit");
    }

    fn persist(&self) -> Result<()> {
        let _lock = acquire_file_lock(&self.store_path).map_err(|err| {
            anyhow!(
                "failed to acquire lock for {}: {:?}",
                self.store_path.display(),
                err
            )
        })?;
        let serialized = serialize_store(&self.store);
        write_atomic(&self.store_path, serialized.as_bytes())
            .map_err(|err| anyhow!("failed to write {}: {:?}", self.store_path.display(), err))?;
        fsync_file(&self.store_path)
            .map_err(|err| anyhow!("failed to fsync {}: {:?}", self.store_path.display(), err))?;
        Ok(())
    }

    fn export(&self, target: &Path) -> Result<()> {
        let serialized = serialize_store(&self.store);
        write_atomic(target, serialized.as_bytes())
            .map_err(|err| anyhow!("failed to export to {}: {:?}", target.display(), err))?;
        fsync_file(target)
            .map_err(|err| anyhow!("failed to fsync {}: {:?}", target.display(), err))?;
        Ok(())
    }

    fn audit(&self) {
        let mut caps = CapabilitySet::default();
        caps.insert(Capability::FileSystem);
        caps.insert(Capability::Process);

        let checks = [
            (
                "file_write",
                audit_privileged_operation(&caps, PrivilegedOperation::FileWrite, "persist store"),
            ),
            (
                "process_spawn",
                audit_privileged_operation(&caps, PrivilegedOperation::ProcessSpawn, "export hook"),
            ),
            (
                "network_bind",
                audit_privileged_operation(
                    &caps,
                    PrivilegedOperation::NetworkBind,
                    "disabled in cli",
                ),
            ),
        ];

        println!("{C_BOLD}capability audit{C_RESET}");
        for (name, check) in checks {
            let status = if check.allowed {
                format!("{C_GREEN}allowed{C_RESET}")
            } else {
                format!("{C_RED}blocked{C_RESET}")
            };
            println!("  {name:<14} {status} ({})", check.reason);
        }
    }

    fn stats(&self) {
        let runtime = RuntimeStats {
            task_queue_depth: self.history.len(),
            scheduler_lag_ms: 0,
            allocation_pressure_bytes: 0,
            open_file_count: 1,
            open_socket_count: 0,
        };
        println!("{C_BOLD}stats{C_RESET}");
        println!(
            "  commands.total      {}",
            self.metrics.counter("cmd.total")
        );
        println!(
            "  commands.errors     {}",
            self.metrics.counter("cmd.error")
        );
        println!("  kv.set              {}", self.metrics.counter("kv.set"));
        println!("  queue.depth         {}", runtime.task_queue_depth);
        println!(
            "  runtime.health      {}",
            if runtime.healthy() {
                format!("{C_GREEN}healthy{C_RESET}")
            } else {
                format!("{C_RED}degraded{C_RESET}")
            }
        );
    }

    fn print_history(&mut self) {
        println!("{C_BOLD}history{C_RESET}");
        let mut idx = 1usize;
        while let Ok(item) = self.history.recv() {
            println!("  {:>2}. {}", idx, item);
            idx += 1;
        }
    }

    fn ok(&self, msg: &str) {
        println!("{C_GREEN}ok:{C_RESET} {msg}");
    }
}

enum Control {
    Continue,
    Exit,
}

fn load_store(path: &Path) -> Result<BTreeMap<String, String>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    let mut map = BTreeMap::new();
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once('\t') {
            map.insert(unescape(k), unescape(v));
        }
    }
    Ok(map)
}

fn serialize_store(store: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (k, v) in store {
        out.push_str(&escape(k));
        out.push('\t');
        out.push_str(&escape(v));
        out.push('\n');
    }
    out
}

fn escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

fn unescape(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{escape, serialize_store, unescape};

    #[test]
    fn escape_round_trip() {
        let input = "a\\tb\\nc";
        assert_eq!(unescape(&escape(input)), input);
    }

    #[test]
    fn serialize_contains_tab_separated_rows() {
        let mut map = BTreeMap::new();
        map.insert("k1".to_string(), "v1".to_string());
        map.insert("k2".to_string(), "v2".to_string());
        let text = serialize_store(&map);
        assert!(text.contains("k1\tv1\n"));
        assert!(text.contains("k2\tv2\n"));
    }
}
