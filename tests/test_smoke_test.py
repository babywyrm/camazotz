from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "smoke_test.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _start_server(
    require_llm: bool,
    *,
    config_payload: dict[str, object] | None = None,
) -> tuple[ThreadingHTTPServer, dict[str, int]]:
    calls = {"tools_call": 0}

    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, obj: dict, status: int = 200, headers: dict[str, str] | None = None) -> None:
            payload = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if headers:
                for k, v in headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send_json({"ok": True})
                return
            if self.path == "/config":
                if config_payload is None:
                    self._send_json({"detail": "not found"}, status=404)
                    return
                self._send_json(config_payload)
                return
            self._send_json({"detail": "not found"}, status=404)  # pragma: no cover

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/mcp":  # pragma: no cover
                self._send_json({"detail": "not found"}, status=404)
                return

            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode() or "{}")
            method = body.get("method")
            req_id = body.get("id", 1)

            if method == "initialize":
                self._send_json(
                    {"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2024-11-05"}},
                    headers={"mcp-session-id": "session-1"},
                )
                return

            if method == "tools/list":
                self._send_json(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "tools": [
                                {
                                    "name": "config.ask_agent",
                                    "description": "test tool",
                                    "inputSchema": {"type": "object"},
                                }
                            ]
                        },
                    }
                )
                return

            if method == "tools/call":
                calls["tools_call"] += 1
                if not require_llm:
                    self._send_json({"jsonrpc": "2.0", "id": req_id, "error": {"code": -1, "message": "unexpected"}})
                    return
                self._send_json(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": '{"answer":"ok"}'}]},
                    }
                )
                return

            self._send_json(  # pragma: no cover
                {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "unknown method"}}
            )

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", _free_port()), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, calls


def test_mock_server_returns_404_for_config_when_no_payload() -> None:
    server, _ = _start_server(False)
    try:
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}/config"
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            urllib.request.urlopen(url, timeout=2)  # noqa: S310 — test loopback only
        assert excinfo.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_smoke_passes_without_llm_probe() -> None:
    server, calls = _start_server(require_llm=False)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--gateway-url",
                base,
                "--portal-url",
                base,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert calls["tools_call"] == 0
    finally:
        server.shutdown()
        server.server_close()


def test_smoke_passes_with_llm_probe() -> None:
    server, calls = _start_server(require_llm=True)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--gateway-url",
                base,
                "--portal-url",
                base,
                "--require-llm",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert calls["tools_call"] == 1
    finally:
        server.shutdown()
        server.server_close()


def test_smoke_fails_when_llm_probe_errors() -> None:
    server, calls = _start_server(require_llm=False)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--gateway-url",
                base,
                "--portal-url",
                base,
                "--require-llm",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert calls["tools_call"] == 1
    finally:
        server.shutdown()
        server.server_close()


def test_smoke_cli_lists_require_identity_flag() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "--require-identity" in proc.stdout


def test_smoke_passes_with_identity_probe() -> None:
    server, calls = _start_server(
        False,
        config_payload={"difficulty": "medium", "show_tokens": False, "idp_provider": "mock"},
    )
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--gateway-url",
                base,
                "--portal-url",
                base,
                "--require-identity",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert calls["tools_call"] == 0
    finally:
        server.shutdown()
        server.server_close()


def test_smoke_identity_probe_passes_with_zitadel_provider() -> None:
    server, calls = _start_server(
        False,
        config_payload={
            "difficulty": "medium",
            "show_tokens": False,
            "idp_provider": "zitadel",
            "idp_degraded": False,
            "idp_reason": "ok",
        },
    )
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--gateway-url",
                base,
                "--portal-url",
                base,
                "--require-identity",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert calls["tools_call"] == 0
    finally:
        server.shutdown()
        server.server_close()


def test_smoke_identity_probe_passes_when_degraded() -> None:
    server, calls = _start_server(
        False,
        config_payload={
            "difficulty": "medium",
            "show_tokens": False,
            "idp_provider": "zitadel",
            "idp_degraded": True,
            "idp_reason": "zitadel_unreachable",
        },
    )
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--gateway-url",
                base,
                "--portal-url",
                base,
                "--require-identity",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert calls["tools_call"] == 0
    finally:
        server.shutdown()
        server.server_close()


def test_smoke_fails_when_identity_probe_invalid() -> None:
    server, calls = _start_server(False, config_payload={"difficulty": "medium"})
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--gateway-url",
                base,
                "--portal-url",
                base,
                "--require-identity",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert calls["tools_call"] == 0
    finally:
        server.shutdown()
        server.server_close()
