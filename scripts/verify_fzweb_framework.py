#!/usr/bin/env python3
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER_SOURCE = ROOT / "frameworklib" / "fzweb" / "src" / "live_server_main.fzy"


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def parse_json(stdout: str):
    text = stdout.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(text.splitlines()[-1])


def http_request(base_url: str, path: str, method: str = "GET", data: bytes | None = None, headers: dict[str, str] | None = None):
    req = urllib.request.Request(f"{base_url}{path}", data=data, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8"), dict(err.headers)


def wait_healthy(base_url: str, headers: dict[str, str] | None = None):
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            status, body, _ = http_request(base_url, "/healthz", headers=headers)
            if status == 200 and body == "ok":
                return
        except Exception:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"fzweb server did not become healthy on {base_url}")


def reserve_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def start_server(extra_env: dict[str, str] | None = None):
    env = dict(os.environ)
    env["FZWEB_MAX_REQUESTS"] = "256"
    env["FZ_HOST"] = "127.0.0.1"
    port = reserve_port()
    env["FZ_PORT"] = str(port)
    if extra_env:
        env.update(extra_env)
    cmd = [
        "cargo",
        "run",
        "-q",
        "-p",
        "fz",
        "--",
        "run",
        str(SERVER_SOURCE),
        "--host-backends",
        "--json",
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc, f"http://127.0.0.1:{port}"


def stop_server(proc: subprocess.Popen):
    if proc.poll() is None:
        proc.kill()
    try:
        out, err = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate(timeout=5)
    return out, err


def assert_process_alive(proc: subprocess.Popen):
    if proc.poll() is not None:
        out, err = proc.communicate()
        raise RuntimeError(f"fzweb server exited early rc={proc.returncode} stdout={out} stderr={err}")


def verify_public_server():
    proc, base_url = start_server()
    try:
        wait_healthy(base_url)
        assert_process_alive(proc)

        status, body, _ = http_request(base_url, "/readyz")
        assert status == 200 and body == "ready", (status, body)

        status, body, _ = http_request(base_url, "/json")
        assert status == 404, (status, body)

        status, body, _ = http_request(base_url, "/openapi.json")
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("openapi") == "3.1.0", payload

        status, body, _ = http_request(base_url, "/inspect")
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("route") == "inspect", payload

        status, body, _ = http_request(base_url, "/search?q=fzweb&limit=7")
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("query") == "fzweb", payload
        assert payload.get("limit") == "7", payload

        status, body, _ = http_request(base_url, "/static/app.js")
        assert status == 200 and "app.js" in body, (status, body)

        status, body, _ = http_request(base_url, "/v1/echo/saint")
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("name") == "saint", payload

        echo_body = b'{"ok":true}'
        status, body, _ = http_request(
            base_url,
            "/echo",
            method="POST",
            data=echo_body,
            headers={"Content-Type": "application/json"},
        )
        assert status == 200 and body == echo_body.decode("utf-8"), (status, body)

        bind_body = b'{"user":"saint","active":"true"}'
        status, body, _ = http_request(
            base_url,
            "/bind",
            method="POST",
            data=bind_body,
            headers={"Content-Type": "application/json"},
        )
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("user") == "saint", payload
        assert payload.get("active") == "true", payload

        status, body, _ = http_request(
            base_url,
            "/v1/items/abc?version=4",
            method="PUT",
            data=b'{"ok":true}',
            headers={"Content-Type": "application/json"},
        )
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("action") == "updated", payload
        assert payload.get("item_id") == "abc", payload

        status, body, _ = http_request(
            base_url,
            "/v1/items/abc?version=9",
            method="DELETE",
        )
        assert status == 202, (status, body)
        payload = json.loads(body)
        assert payload.get("action") == "deleted", payload

        status, body, _ = http_request(base_url, "/echo")
        assert status == 405, (status, body)

        status, body, _ = http_request(
            base_url,
            "/echo",
            method="POST",
            data=b"bad",
            headers={"Content-Type": "application/json"},
        )
        assert status == 400, (status, body)
        payload = json.loads(body)
        assert payload.get("error") == "invalid_json_body", payload

        status, body, _ = http_request(base_url, "/metrics")
        assert status == 200 and "fzweb_requests_total" in body, (status, body)
    finally:
        stop_server(proc)


def verify_auth_server():
    token = "secret-token"
    proc, base_url = start_server(
        {
            "FZWEB_REQUIRE_AUTH": "true",
            "FZWEB_AUTH_TOKEN": token,
        }
    )
    try:
        wait_healthy(base_url, headers={"Authorization": f"Bearer {token}"})
        assert_process_alive(proc)

        status, body, _ = http_request(base_url, "/inspect")
        assert status == 401, (status, body)

        status, body, _ = http_request(
            base_url,
            "/inspect",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert status == 200, (status, body)
    finally:
        stop_server(proc)


def verify_rate_limit_server():
    proc, base_url = start_server(
        {
            "FZWEB_RATE_CAPACITY": "3",
            "FZWEB_RATE_REFILL_MS": "60000",
        }
    )
    try:
        wait_healthy(base_url)
        assert_process_alive(proc)

        assert http_request(base_url, "/inspect")[0] == 200
        assert http_request(base_url, "/search?q=rate")[0] == 200
        status, body, _ = http_request(base_url, "/inspect")
        assert status == 429, (status, body)
    finally:
        stop_server(proc)


def main() -> int:
    check = run(["cargo", "run", "-q", "-p", "fz", "--", "check", "frameworklib/fzweb", "--json"])
    if check.returncode != 0:
        sys.stderr.write(check.stdout)
        sys.stderr.write(check.stderr)
        return 2
    check_payload = parse_json(check.stdout)
    if int(check_payload.get("errors", 1)) != 0:
        sys.stderr.write("fzweb check reported errors\n")
        return 2

    build = run(
        [
            "cargo",
            "run",
            "-q",
            "-p",
            "fz",
            "--",
            "build",
            "frameworklib/fzweb",
            "--backend",
            "llvm",
            "--release",
            "--json",
        ]
    )
    if build.returncode != 0:
        sys.stderr.write(build.stdout)
        sys.stderr.write(build.stderr)
        return 2
    build_payload = parse_json(build.stdout)
    if build_payload.get("status") != "ok":
        sys.stderr.write("fzweb build status not ok\n")
        return 2

    verify_public_server()
    verify_auth_server()
    verify_rate_limit_server()

    print("fzweb-framework-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
