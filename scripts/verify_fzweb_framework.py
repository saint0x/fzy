#!/usr/bin/env python3
import json
import os
import pathlib
import base64
import hashlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER_SOURCE = ROOT / "frameworklib" / "fzweb" / "src" / "live_server_main.fzy"
STABLE_CARGO = pathlib.Path("/Users/deepsaint/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo")


def cargo_bin() -> str:
    override = os.environ.get("FZWEB_VERIFY_CARGO")
    if override:
        return override
    if STABLE_CARGO.exists():
        return str(STABLE_CARGO)
    return os.environ.get("CARGO", "cargo")


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


def websocket_exchange(base_url: str, path: str, message: str):
    host = "127.0.0.1"
    port = int(base_url.rsplit(":", 1)[1])
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    expected_accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("utf-8")).digest()
    ).decode("utf-8")
    with socket.create_connection((host, port), timeout=3) as sock:
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n\r\n"
        )
        sock.sendall(request.encode("utf-8"))
        response = sock.recv(4096).decode("utf-8", errors="ignore")
        assert response.startswith("HTTP/1.1 101"), response
        assert f"Sec-WebSocket-Accept: {expected_accept}" in response, response

        payload = message.encode("utf-8")
        mask = b"\x01\x02\x03\x04"
        frame = bytearray([0x81, 0x80 | len(payload)])
        frame.extend(mask)
        for idx, byte in enumerate(payload):
            frame.append(byte ^ mask[idx % 4])
        sock.sendall(frame)

        header = sock.recv(2)
        assert header and header[0] == 0x81, header
        length = header[1] & 0x7F
        return sock.recv(length).decode("utf-8")


def wait_healthy(
    base_url: str,
    headers: dict[str, str] | None = None,
    proc: subprocess.Popen | None = None,
):
    deadline = time.time() + 20
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            out, err = proc.communicate()
            raise RuntimeError(
                f"fzweb server exited early rc={proc.returncode} stdout={out} stderr={err}"
            )
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
    port = reserve_port()
    env["FZWEB_BIND"] = f"127.0.0.1:{port}"
    if extra_env:
        env.update(extra_env)
    cmd = [
        cargo_bin(),
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
        wait_healthy(base_url, proc=proc)
        assert_process_alive(proc)

        status, body, headers = http_request(base_url, "/")
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("service") == "fzweb", payload
        assert headers.get("Content-Security-Policy", "").startswith("default-src"), headers

        status, body, _ = http_request(base_url, "/readyz")
        assert status == 200 and body == "ready", (status, body)

        status, body, _ = http_request(base_url, "/openapi.json")
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("openapi") == "3.1.0", payload

        status, body, _ = http_request(base_url, "/version")
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("framework") == "fzweb", payload

        status, body, headers = http_request(base_url, "/cookies/set")
        assert status == 200, (status, body)
        assert "theme=light" in headers.get("Set-Cookie", ""), headers

        status, body, _ = http_request(base_url, "/inspect")
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("route") == "inspect", payload

        status, body, _ = http_request(base_url, "/search?q=fzweb&limit=7")
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("query") == "fzweb", payload
        assert payload.get("limit") == 7, payload

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
        assert status == 200, (status, body)
        assert body == echo_body.decode("utf-8") or '"event":"echo"' in body, body

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
        assert payload.get("active") is True, payload

        login_body = b'{"user":"saint"}'
        status, body, headers = http_request(
            base_url,
            "/session/login?user=saint",
            method="POST",
            data=login_body,
            headers={"Content-Type": "application/json"},
        )
        assert status == 200, (status, body)
        session_cookie = headers.get("Set-Cookie", "")
        assert "fzweb_session=" in session_cookie, headers
        signed_value = session_cookie.split(";", 1)[0]

        status, body, _ = http_request(
            base_url,
            "/session/me",
            headers={"Cookie": signed_value},
        )
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("user") == "saint", payload

        status, body, _ = http_request(base_url, "/v1/items")
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("count") == 2, payload

        status, body, _ = http_request(
            base_url,
            "/v1/items/abc?version=3",
        )
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("item_id") == "abc", payload
        assert payload.get("version") == 3, payload

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
        assert payload.get("version") == 4, payload

        status, body, _ = http_request(
            base_url,
            "/v1/items/abc?version=5",
            method="PATCH",
            data=b'{"status":"patched"}',
            headers={"Content-Type": "application/json"},
        )
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("action") == "patched", payload
        assert payload.get("version") == 5, payload

        status, body, _ = http_request(
            base_url,
            "/v1/items/abc?version=9",
            method="DELETE",
        )
        assert status == 202, (status, body)
        payload = json.loads(body)
        assert payload.get("action") == "deleted", payload

        boundary = "----fzwebboundary"
        multipart_body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="title"\r\n\r\n'
            "hello\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="note.txt"\r\n'
            "Content-Type: text/plain\r\n\r\n"
            "world\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        status, body, _ = http_request(
            base_url,
            "/upload",
            method="POST",
            data=multipart_body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload.get("fields") == 1, payload
        assert payload.get("files") == 1, payload

        status, body, headers = http_request(base_url, "/events")
        assert status == 200, (status, body)
        assert headers.get("Content-Type", "").startswith("text/event-stream"), headers
        assert "event: ready" in body, body

        echo = websocket_exchange(base_url, "/ws", "hello")
        assert echo == "echo:hello", echo

        status, body, _ = http_request(base_url, "/missing")
        assert status == 404, (status, body)

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
        wait_healthy(base_url, proc=proc)
        assert_process_alive(proc)

        status, body, _ = http_request(base_url, "/version")
        assert status == 200, (status, body)

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
            "FZWEB_RATE_CAPACITY": "2",
            "FZWEB_RATE_REFILL_MS": "60000",
        }
    )
    try:
        wait_healthy(base_url, proc=proc)
        assert_process_alive(proc)

        assert http_request(base_url, "/inspect")[0] == 200
        assert http_request(base_url, "/version")[0] == 200
        assert http_request(base_url, "/inspect")[0] == 200
        status, body, _ = http_request(base_url, "/inspect")
        assert status == 429, (status, body)
    finally:
        stop_server(proc)


def main() -> int:
    check = run([cargo_bin(), "run", "-q", "-p", "fz", "--", "check", "frameworklib/fzweb", "--json"])
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
            cargo_bin(),
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
