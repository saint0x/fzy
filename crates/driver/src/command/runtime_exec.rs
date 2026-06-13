fn run_native_binary_with_bounds(
    binary: &Path,
    args: &[String],
    bounds: RunBounds<'_>,
    stream_stdio: bool,
) -> Result<NativeRunOutcome> {
    let mut child = ProcessCommand::new(binary);
    child.args(args);
    if stream_stdio {
        child.stdout(Stdio::inherit());
        child.stderr(Stdio::inherit());
    } else {
        child.stdout(Stdio::piped());
        child.stderr(Stdio::piped());
    }
    let mut child = child
        .spawn()
        .with_context(|| format!("failed to execute native artifact: {}", binary.display()))?;
    let started = Instant::now();
    let mut poll_sleep = Duration::from_millis(5);
    loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("failed waiting for native artifact: {}", binary.display()))?
        {
            let (stdout, stderr) = read_child_output(&mut child)?;
            return Ok(NativeRunOutcome {
                exit_code: status.code().unwrap_or(1),
                stdout,
                stderr,
            });
        }
        if let Some(max) = bounds.max_seconds {
            if started.elapsed() >= Duration::from_secs(max) {
                let _ = child.kill();
                let _ = child.wait();
                let (stdout, mut stderr) = read_child_output(&mut child)?;
                if !stderr.is_empty() {
                    stderr.push('\n');
                }
                stderr.push_str("timed out");
                return Ok(NativeRunOutcome {
                    exit_code: 124,
                    stdout,
                    stderr,
                });
            }
        }
        if let Some(url) = bounds.exit_on_healthcheck {
            if probe_http_ok(url)? {
                let _ = child.kill();
                let _ = child.wait();
                let (stdout, stderr) = read_child_output(&mut child)?;
                return Ok(NativeRunOutcome {
                    exit_code: 0,
                    stdout,
                    stderr,
                });
            }
        }
        if let Some(url) = bounds.smoke_http {
            if probe_http_ok(url)? {
                let _ = child.kill();
                let _ = child.wait();
                let (stdout, stderr) = read_child_output(&mut child)?;
                return Ok(NativeRunOutcome {
                    exit_code: 0,
                    stdout,
                    stderr,
                });
            }
        }
        thread::sleep(poll_sleep);
        if poll_sleep < Duration::from_millis(50) {
            poll_sleep = (poll_sleep * 2).min(Duration::from_millis(50));
        }
    }
}

fn read_child_output(child: &mut std::process::Child) -> Result<(String, String)> {
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_string(&mut stdout)
            .context("failed reading child stdout")?;
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_string(&mut stderr)
            .context("failed reading child stderr")?;
    }
    Ok((stdout, stderr))
}

fn probe_http_ok(url: &str) -> Result<bool> {
    let Some(without_scheme) = url.strip_prefix("http://") else {
        bail!("unsupported URL for smoke/health probe: {url} (only http:// is supported)");
    };
    let (host_port, path) = if let Some((host_port, path)) = without_scheme.split_once('/') {
        (host_port, format!("/{}", path))
    } else {
        (without_scheme, "/".to_string())
    };
    let (host, port) = if let Some((host, port_str)) = host_port.split_once(':') {
        let parsed = port_str
            .parse::<u16>()
            .with_context(|| format!("invalid probe port in URL: {url}"))?;
        (host, parsed)
    } else {
        (host_port, 80u16)
    };
    let connect_addr = format!("{host}:{port}");
    let resolved = connect_addr
        .to_socket_addrs()
        .with_context(|| format!("invalid probe host/port in URL: {url}"))?
        .next();
    let Some(socket_addr) = resolved else {
        return Ok(false);
    };
    let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(500)) {
        Ok(stream) => stream,
        Err(_) => return Ok(false),
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200"))
}

#[cfg(test)]
fn scenario_run_routing(deterministic_requested: bool, host_backends: bool) -> ScenarioRunRouting {
    if deterministic_requested && host_backends {
        return ScenarioRunRouting {
            deterministic_applied: true,
            mode: "host-backed-deterministic-scenario",
            reason: "host-backed deterministic scenario replay enabled",
        };
    }
    if deterministic_requested {
        return ScenarioRunRouting {
            deterministic_applied: true,
            mode: "deterministic-scenario",
            reason: "",
        };
    }
    ScenarioRunRouting {
        deterministic_applied: false,
        mode: "scenario",
        reason: "",
    }
}

fn init_project(
    path: &Path,
    package_name: Option<&str>,
    template: Option<&str>,
    with: &[String],
    force: bool,
) -> Result<()> {
    let root = if path.as_os_str().is_empty() {
        std::env::current_dir().context("failed to resolve current working directory")?
    } else {
        path.to_path_buf()
    };
    let root = if root.is_absolute() {
        root
    } else {
        std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(root)
    };
    let root_name = root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("app");
    let package = normalize_init_package_name(package_name.unwrap_or(root_name));
    if package.is_empty() {
        bail!("project name cannot be empty");
    }

    let template = parse_init_template(template)?;
    let test_types = parse_init_test_types(with)?;
    ensure_init_target_ready(&root, &template, force)?;

    std::fs::create_dir_all(&root)
        .with_context(|| format!("failed creating project root {}", root.display()))?;
    let src = root.join("src");
    std::fs::create_dir_all(&src).context("failed to create src directory")?;

    let config_path = root.join("fozzy.toml");
    let manifest = render_init_manifest(&package);
    write_init_file(&config_path, manifest.as_bytes(), force)
        .context("failed to write fozzy.toml")?;
    write_init_file(
        &src.join("main.fzy"),
        render_init_main(&package).as_bytes(),
        force,
    )
    .context("failed to write src/main.fzy")?;

    let config = fzscenario::Config::default();
    fzscenario::init_project_with_options(
        &config,
        &config_path,
        &template,
        force,
        &test_types,
        fzscenario::InitProjectOptions {
            write_config: false,
        },
    )
    .map_err(|error| anyhow!(error.to_string()))?;

    Ok(())
}

fn parse_init_template(template: Option<&str>) -> Result<fzscenario::InitTemplate> {
    match template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        None => Ok(fzscenario::InitTemplate::Minimal),
        Some("minimal") => Ok(fzscenario::InitTemplate::Minimal),
        Some("rust") => Ok(fzscenario::InitTemplate::Rust),
        Some("ts") => Ok(fzscenario::InitTemplate::Ts),
        Some(other) => bail!("unsupported init template `{other}`; expected minimal, rust, or ts"),
    }
}

fn parse_init_test_types(values: &[String]) -> Result<Vec<fzscenario::InitTestType>> {
    let mut parsed = Vec::new();
    for value in values {
        let normalized = value.trim().to_ascii_lowercase();
        let kind = match normalized.as_str() {
            "run" => fzscenario::InitTestType::Run,
            "fuzz" => fzscenario::InitTestType::Fuzz,
            "explore" => fzscenario::InitTestType::Explore,
            "memory" => fzscenario::InitTestType::Memory,
            "host" => fzscenario::InitTestType::Host,
            "all" => fzscenario::InitTestType::All,
            _ => bail!(
                "unsupported init scaffold kind `{}`; expected run, fuzz, explore, memory, host, or all",
                value
            ),
        };
        parsed.push(kind);
    }
    Ok(parsed)
}

fn normalize_init_package_name(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

fn ensure_init_target_ready(
    root: &Path,
    template: &fzscenario::InitTemplate,
    force: bool,
) -> Result<()> {
    let collisions = init_collision_paths(root, template)
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    if !force && !collisions.is_empty() {
        bail!(
            "init target {} already contains scaffold-managed paths: {} (use --force to overwrite)",
            root.display(),
            collisions
                .iter()
                .map(|path| path
                    .strip_prefix(root)
                    .unwrap_or(path)
                    .display()
                    .to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn init_collision_paths(root: &Path, template: &fzscenario::InitTemplate) -> Vec<PathBuf> {
    let mut paths = vec![
        root.join("fozzy.toml"),
        root.join("src"),
        root.join("tests"),
        root.join(".fozzy"),
    ];
    if matches!(template, fzscenario::InitTemplate::Rust) {
        paths.push(root.join("README.md"));
    }
    paths
}

fn render_init_manifest(package: &str) -> String {
    format!(
        "base_dir = \".fozzy\"\n\n[package]\nname = \"{package}\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"{package}\"\npath = \"src/main.fzy\"\n\n[unsafe]\ncontracts = \"compiler\"\nenforce_dev = false\nenforce_verify = true\nenforce_release = true\ndeny_unsafe_in = []\nallow_unsafe_in = []\n"
    )
}

fn render_init_main(package: &str) -> String {
    format!("fn main() -> i32 {{\n    let _app = \"{package}\"\n    return 0\n}}\n")
}

fn write_init_file(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if path.exists() && !force {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

