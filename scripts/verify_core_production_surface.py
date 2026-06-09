import json
import pathlib
import subprocess
import tempfile
import textwrap


def run_json(repo: pathlib.Path, args: list[str], expect_rc: int = 0) -> dict:
    proc = subprocess.run(
        ["cargo", "run", "-q", "-p", "fz", "--", *args, "--json"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    payload = json.loads(proc.stdout.strip())
    assert proc.returncode == expect_rc, (args, proc.returncode, payload, proc.stderr)
    return payload


def main() -> None:
    repo = pathlib.Path.cwd()
    core = repo / "core"

    verify_payload = run_json(repo, ["verify", str(core)])
    assert verify_payload["errors"] == 0, verify_payload

    build_payload = run_json(repo, ["build", str(core)])
    assert build_payload["status"] == "ok", build_payload

    test_payload = run_json(repo, ["test", str(core), "--det", "--strict-verify"])
    assert test_payload.get("diagnostics", 1) == 0, test_payload
    assert test_payload.get("module") == "lib", test_payload

    consumer_root = pathlib.Path(tempfile.mkdtemp(prefix="fozzylang-core-namespace-consumer-"))
    (consumer_root / "src").mkdir(parents=True, exist_ok=True)
    (consumer_root / "fozzy.toml").write_text(
        textwrap.dedent(
            """\
            [package]
            name="core_consumer"
            version="0.1.0"

            [[target.bin]]
            name="core_consumer"
            path="src/main.fzy"
            """
        ),
        encoding="utf-8",
    )
    (consumer_root / "src/main.fzy").write_text(
        textwrap.dedent(
            """\
            use core.fs;
            use core.security;

            fn main() -> i32 {
                let temp_path = fs.temp_file("core-consumer")
                discard fs.atomic_write(temp_path, " hello ")
                let body = fs.read_file(temp_path)
                discard fs.remove(temp_path)

                if str.trim(body) != "hello" {
                    return 11
                }

                let mac = security.sign_value("key", "value")
                if security.verify_value("key", "value", mac) != 1 {
                    return 13
                }

                if str.starts_with(mac, "") != 1 {
                    return 14
                }

                return 0
            }
            """
        ),
        encoding="utf-8",
    )

    consumer_verify = run_json(repo, ["verify", str(consumer_root)])
    assert consumer_verify["errors"] == 0, consumer_verify

    consumer_build = run_json(repo, ["build", str(consumer_root)])
    assert consumer_build["status"] == "ok", consumer_build

    trace = repo / "artifacts" / "core.consumer.trace.fozzy"
    consumer_run_det = run_json(
        repo,
        ["run", str(consumer_root), "--det", "--seed", "4242", "--record", str(trace)],
    )
    assert consumer_run_det["status"] == "ok", consumer_run_det
    assert consumer_run_det["module"] == "main", consumer_run_det

    trace_verify_payload = run_json(repo, ["trace", "verify", str(trace), "--strict"])
    assert trace_verify_payload["ok"] is True, trace_verify_payload

    replay_payload = run_json(repo, ["replay", str(trace)])
    assert replay_payload["status"] == "pass", replay_payload

    ci_payload = run_json(repo, ["ci", str(trace)])
    assert ci_payload["ok"] is True, ci_payload

    consumer_run = run_json(
        repo,
        [
            "run",
            str(consumer_root),
            "--proc-backend",
            "host",
            "--fs-backend",
            "host",
            "--http-backend",
            "host",
        ],
    )
    assert consumer_run["status"] == "ok", consumer_run
    assert consumer_run["exitCode"] == 0, consumer_run

    print("core-production-surface-ok")


if __name__ == "__main__":
    main()
