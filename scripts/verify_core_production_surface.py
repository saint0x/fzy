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
    assert proc.stdout.strip(), (args, proc.returncode, proc.stderr)
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

    unsafe_audit_payload = run_json(repo, ["audit", "unsafe", str(core)])
    assert unsafe_audit_payload["ok"] is True, unsafe_audit_payload
    assert unsafe_audit_payload["missingContractCount"] == 0, unsafe_audit_payload
    assert unsafe_audit_payload["invalidOwnerIdCount"] == 0, unsafe_audit_payload
    assert unsafe_audit_payload["invalidProofRefCount"] == 0, unsafe_audit_payload
    assert unsafe_audit_payload["unsafeContextViolationCount"] == 0, unsafe_audit_payload
    assert unsafe_audit_payload["riskClassCounts"].get("memory") == 16, unsafe_audit_payload

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
            use core.io;
            use core.log;
            use core.security;
            use core.thread;
            use core.concurrency;

            fn main() -> i32 {
                let temp_path = fs.temp_file("core-consumer")
                discard io.write_text(temp_path, " hello ")
                let body = io.read_text(temp_path)
                discard io.remove(temp_path)

                if str.trim(body) != "hello" {
                    return 11
                }

                let task_ctx = thread.current_context()
                if task_ctx.bound != 0 {
                    return 12
                }

                let queue_policy = concurrency.reject_policy(4)
                let queue = concurrency.snapshot(1, queue_policy)
                if concurrency.depth_after_send(queue, queue_policy) != 2 {
                    return 19
                }
                if concurrency.depth_after_recv(queue) != 0 {
                    return 20
                }

                let signer = security.default_signer()
                let mac = security.sign(signer, "key", "value")
                if security.verify(signer, "key", "value", mac) != 1 {
                    return 13
                }

                if str.starts_with(mac, "v1:") != 1 {
                    return 14
                }

                let session_token = security.opaque_token(18)
                if session_token == "" || str.contains(session_token, "=") == 1 {
                    return 15
                }

                if security.verify(signer, "key", "value", "2b23ec6907c6a352f26ba7d5f2721c8a4f13ec0fcb1607e1043bfc2e3110c170") != 0 {
                    return 17
                }

                let request = log.field(
                    log.field(
                        log.field(log.event(log.LogLevel::Info, "core.consumer"), "request_id", "req-1"),
                        "path",
                        "/health",
                    ),
                    "method",
                    "GET",
                )
                let enriched = log.secret_field(
                    log.field(request, "component", "core_consumer"),
                    "token",
                    "super-secret",
                )
                let emitted = log.emit(
                    log.default_config(),
                    log.with_correlation(enriched, log.correlation("req-1", "trace-1", "span-1")),
                )
                if emitted == 0 {
                    return 18
                }

                return 0
            }
            """
        ),
        encoding="utf-8",
    )

    consumer_verify = run_json(repo, ["verify", str(consumer_root)])
    assert consumer_verify["errors"] == 0, consumer_verify

    trace = repo / "artifacts" / "core.consumer.trace.fozzy"
    consumer_run_det = run_json(
        repo,
        [
            "run",
            str(consumer_root),
            "--det",
            "--strict-verify",
            "--seed",
            "4242",
            "--record",
            str(trace),
        ],
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
            "--strict-verify",
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
