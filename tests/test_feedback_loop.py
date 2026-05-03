"""Unit tests for scripts/feedback_loop.py."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

# Make scripts/ importable without installing
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import feedback_loop as fl
from feedback_loop import (
    ScanSummary,
    _print_diff,
    _resolve_apply_backend,
    _resolve_scanner,
    apply_policy,
    apply_policy_compose,
    generate_policy,
    parse_args,
    run_scan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _args(**kwargs) -> argparse.Namespace:
    """Build a minimal Namespace with sensible defaults."""
    defaults = {
        "scanner": None,
        "apply_backend": None,
        "baseline_url": "http://192.168.1.85:30080/mcp",
        "policed_url": "http://192.168.1.85:30090/mcp",
        "mode": "print",
        "namespace": "camazotz",
        "selector": ["app=brain-gateway"],
        "label": [],
        "policy_name": "test-policy",
        "kubeconfig": None,
        "ssh_host": None,
        "ssh_key": None,
        "wait_seconds": 5,
        "workdir": None,
        "scan_args": "",
        "compose_policy_path": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _fake_scan_report(findings: list[dict]) -> str:
    return json.dumps({"findings": findings})


# ---------------------------------------------------------------------------
# _resolve_scanner
# ---------------------------------------------------------------------------


def test_resolve_scanner_explicit_flag(tmp_path: Path) -> None:
    scanner_bin = tmp_path / "mcpnuke"
    scanner_bin.touch()
    args = _args(scanner=str(scanner_bin))
    assert _resolve_scanner(args) == str(scanner_bin)


def test_resolve_scanner_explicit_flag_missing(tmp_path: Path) -> None:
    args = _args(scanner=str(tmp_path / "nonexistent"))
    with pytest.raises(SystemExit, match="--scanner path not found"):
        _resolve_scanner(args)


def test_resolve_scanner_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner_bin = tmp_path / "mcpnuke"
    scanner_bin.touch()
    monkeypatch.setenv("MCPNUKE_BIN", str(scanner_bin))
    args = _args(scanner=None)
    assert _resolve_scanner(args) == str(scanner_bin)


def test_resolve_scanner_env_var_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MCPNUKE_BIN", str(tmp_path / "gone"))
    args = _args(scanner=None)
    with pytest.raises(SystemExit, match="MCPNUKE_BIN path not found"):
        _resolve_scanner(args)


def test_resolve_scanner_well_known_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MCPNUKE_BIN", raising=False)
    # Patch SCANNER_SEARCH_PATHS so the first candidate exists
    fake_bin = tmp_path / "scan"
    fake_bin.touch()
    monkeypatch.setattr(fl, "SCANNER_SEARCH_PATHS", [str(fake_bin), "/nonexistent"])
    args = _args(scanner=None)
    assert _resolve_scanner(args) == str(fake_bin)


def test_resolve_scanner_which_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCPNUKE_BIN", raising=False)
    monkeypatch.setattr(fl, "SCANNER_SEARCH_PATHS", [])
    monkeypatch.setattr(fl.shutil, "which", lambda name: "/usr/local/bin/mcpnuke")
    args = _args(scanner=None)
    assert _resolve_scanner(args) == "/usr/local/bin/mcpnuke"


def test_resolve_scanner_not_found_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCPNUKE_BIN", raising=False)
    monkeypatch.setattr(fl, "SCANNER_SEARCH_PATHS", [])
    monkeypatch.setattr(fl.shutil, "which", lambda name: None)
    args = _args(scanner=None)
    with pytest.raises(SystemExit, match="mcpnuke not found"):
        _resolve_scanner(args)


# ---------------------------------------------------------------------------
# _resolve_apply_backend
# ---------------------------------------------------------------------------


def test_resolve_apply_backend_explicit_kubectl() -> None:
    args = _args(apply_backend="kubectl", policed_url="http://remote.host/mcp")
    assert _resolve_apply_backend(args) == "kubectl"


def test_resolve_apply_backend_explicit_compose() -> None:
    args = _args(apply_backend="docker-compose", policed_url="http://remote.host/mcp")
    assert _resolve_apply_backend(args) == "docker-compose"


def test_resolve_apply_backend_localhost_auto() -> None:
    args = _args(apply_backend=None, policed_url="http://localhost:9090/mcp")
    assert _resolve_apply_backend(args) == "docker-compose"


def test_resolve_apply_backend_127_auto() -> None:
    args = _args(apply_backend=None, policed_url="http://127.0.0.1:9090/mcp")
    assert _resolve_apply_backend(args) == "docker-compose"


def test_resolve_apply_backend_remote_auto() -> None:
    args = _args(apply_backend=None, policed_url="http://10.0.0.5:9090/mcp")
    assert _resolve_apply_backend(args) == "kubectl"


def test_resolve_apply_backend_falls_back_to_baseline_url() -> None:
    # When policed_url is None, falls back to baseline_url
    args = _args(
        apply_backend=None,
        policed_url=None,
        baseline_url="http://localhost:30080/mcp",
    )
    assert _resolve_apply_backend(args) == "docker-compose"


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------


def test_run_scan_parses_findings(tmp_path: Path) -> None:
    report_file = tmp_path / "report.json"
    findings = [
        {"severity": "HIGH", "check": "auth-bypass"},
        {"severity": "MEDIUM", "check": "info-leak"},
        {"severity": "HIGH", "check": "auth-bypass"},
    ]
    report_file.write_text(_fake_scan_report(findings))

    with patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        summary = run_scan(
            "http://target/mcp",
            report_file,
            extra_args=[],
            scanner="/fake/mcpnuke",
        )

    assert summary.total_findings == 3
    assert summary.by_severity["HIGH"] == 2
    assert summary.by_severity["MEDIUM"] == 1
    assert summary.by_check["auth-bypass"] == 2
    assert summary.target == "http://target/mcp"


def test_run_scan_results_format(tmp_path: Path) -> None:
    """Supports the nested results[] format as well."""
    report_file = tmp_path / "report.json"
    report_file.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "findings": [
                            {"severity": "CRITICAL", "check": "rce"},
                        ]
                    }
                ]
            }
        )
    )
    with patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        summary = run_scan(
            "http://target/mcp",
            report_file,
            extra_args=[],
            scanner="/fake/mcpnuke",
        )
    assert summary.total_findings == 1
    assert summary.by_severity["CRITICAL"] == 1


def test_run_scan_missing_report_raises(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.json"
    with patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        with pytest.raises(SystemExit, match="mcpnuke did not produce"):
            run_scan(
                "http://target/mcp",
                missing_file,
                extra_args=[],
                scanner="/fake/mcpnuke",
            )


# ---------------------------------------------------------------------------
# generate_policy
# ---------------------------------------------------------------------------


def test_generate_policy_writes_file(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("apiVersion: nullfield.io/v1")

    with patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        generate_policy(
            "http://target/mcp",
            out_path=policy_file,
            policy_name="test-pol",
            namespace="default",
            selectors=["app=gw"],
            labels=["env=test"],
            scanner="/fake/mcpnuke",
        )

    # subprocess was called with the right arguments
    cmd_used = mock_run.call_args[0][0]
    assert "/fake/mcpnuke" in cmd_used
    assert "--generate-policy" in cmd_used
    assert "--policy-selector" in cmd_used
    assert "app=gw" in cmd_used


def test_generate_policy_missing_output_raises(tmp_path: Path) -> None:
    missing_output = tmp_path / "no-policy.yaml"
    with patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with pytest.raises(SystemExit, match="mcpnuke did not write"):
            generate_policy(
                "http://target/mcp",
                out_path=missing_output,
                policy_name="p",
                namespace="n",
                selectors=[],
                labels=[],
                scanner="/fake/mcpnuke",
            )


# ---------------------------------------------------------------------------
# apply_policy (kubectl path)
# ---------------------------------------------------------------------------


def test_apply_policy_print_mode(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("kind: NullfieldPolicy\n")
    args = _args(mode="print")
    apply_policy(args, policy_path)
    out = capsys.readouterr().out
    assert "mode=print" in out
    assert "NullfieldPolicy" in out


def test_apply_policy_dry_run(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("kind: NullfieldPolicy\n")
    args = _args(mode="dry-run")

    with patch("feedback_loop._require", return_value="/usr/bin/kubectl"), \
         patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        apply_policy(args, policy_path)

    cmd_used = mock_run.call_args[0][0]
    assert "--dry-run=client" in cmd_used


def test_apply_policy_apply_mode(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("kind: NullfieldPolicy\n")
    args = _args(mode="apply")

    with patch("feedback_loop._require", return_value="/usr/bin/kubectl"), \
         patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        apply_policy(args, policy_path)

    cmd_used = mock_run.call_args[0][0]
    assert "apply" in cmd_used
    assert "--dry-run=client" not in cmd_used


def test_apply_policy_kubectl_fails_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("kind: NullfieldPolicy\n")
    args = _args(mode="apply")

    with patch("feedback_loop._require", return_value="/usr/bin/kubectl"), \
         patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        with pytest.raises(SystemExit, match="kubectl apply failed"):
            apply_policy(args, policy_path)


def test_apply_policy_ssh_host_no_key(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("kind: NullfieldPolicy\n")
    args = _args(mode="apply", ssh_host="root@192.168.1.85", ssh_key=None)

    with patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        apply_policy(args, policy_path)

    cmd_used = mock_run.call_args[0][0]
    assert "ssh" in cmd_used
    assert "root@192.168.1.85" in cmd_used
    assert "-i" not in cmd_used


def test_apply_policy_ssh_host_with_key(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("kind: NullfieldPolicy\n")
    args = _args(
        mode="apply",
        ssh_host="root@192.168.1.85",
        ssh_key="/Users/tms/.ssh/id_ed25519",
    )

    with patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        apply_policy(args, policy_path)

    cmd_used = mock_run.call_args[0][0]
    assert "-i" in cmd_used
    assert "/Users/tms/.ssh/id_ed25519" in cmd_used


# ---------------------------------------------------------------------------
# apply_policy_compose
# ---------------------------------------------------------------------------


def test_apply_policy_compose_print_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("kind: NullfieldPolicy\n")
    compose_dir = tmp_path / "compose" / "nullfield"
    compose_dir.mkdir(parents=True)
    args = _args(mode="print", compose_policy_path=str(compose_dir / "policy.yaml"))
    apply_policy_compose(args, policy_path)
    out = capsys.readouterr().out
    assert "mode=print" in out
    assert "NullfieldPolicy" in out


def test_apply_policy_compose_dry_run(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("kind: NullfieldPolicy\n")
    compose_dir = tmp_path / "compose" / "nullfield"
    compose_dir.mkdir(parents=True)
    dest = compose_dir / "policy.yaml"
    args = _args(mode="dry-run", compose_policy_path=str(dest))
    apply_policy_compose(args, policy_path)
    # File was written
    assert dest.read_text() == "kind: NullfieldPolicy\n"
    out = capsys.readouterr().out
    assert "dry-run" in out


def test_apply_policy_compose_apply_mode(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("kind: NullfieldPolicy\n")
    compose_dir = tmp_path / "compose" / "nullfield"
    compose_dir.mkdir(parents=True)
    dest = compose_dir / "policy.yaml"
    args = _args(mode="apply", compose_policy_path=str(dest))

    with patch("feedback_loop.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        apply_policy_compose(args, policy_path)

    assert dest.read_text() == "kind: NullfieldPolicy\n"
    cmd_used = mock_run.call_args[0][0]
    assert "docker" in cmd_used
    assert "nullfield-controller" in cmd_used


def test_apply_policy_compose_no_path_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("kind: NullfieldPolicy\n")
    # compose_policy_path is None and no compose/nullfield dir in CWD or script parent
    args = _args(mode="apply", compose_policy_path=None)
    with patch.object(Path, "exists", return_value=False):
        with pytest.raises(SystemExit, match="cannot find compose/nullfield/policy.yaml"):
            apply_policy_compose(args, policy_path)


# ---------------------------------------------------------------------------
# _print_diff
# ---------------------------------------------------------------------------


def test_print_diff_decreased(capsys: pytest.CaptureFixture) -> None:
    before = ScanSummary(
        target="http://t/mcp",
        total_findings=10,
        by_severity={"HIGH": 5, "MEDIUM": 5},
        by_check={"auth": 5, "ssrf": 5},
    )
    after = ScanSummary(
        target="http://t/mcp",
        total_findings=4,
        by_severity={"MEDIUM": 4},
        by_check={"ssrf": 4},
    )
    rc = _print_diff(before, after)
    assert rc == 0
    out = capsys.readouterr().out
    assert "decreased" in out
    assert "10 -> 4" in out


def test_print_diff_unchanged(capsys: pytest.CaptureFixture) -> None:
    s = ScanSummary(
        target="http://t/mcp",
        total_findings=5,
        by_severity={"HIGH": 5},
        by_check={"c": 5},
    )
    rc = _print_diff(s, s)
    assert rc == 1
    out = capsys.readouterr().out
    assert "unchanged" in out


def test_print_diff_increased(capsys: pytest.CaptureFixture) -> None:
    before = ScanSummary(
        target="http://t/mcp",
        total_findings=2,
        by_severity={"LOW": 2},
        by_check={"c": 2},
    )
    after = ScanSummary(
        target="http://t/mcp",
        total_findings=5,
        by_severity={"CRITICAL": 5},
        by_check={"c": 2, "new": 3},
    )
    rc = _print_diff(before, after)
    assert rc == 2
    out = capsys.readouterr().out
    assert "INCREASED" in out


def test_print_diff_closed_checks(capsys: pytest.CaptureFixture) -> None:
    before = ScanSummary(
        target="http://t/mcp",
        total_findings=3,
        by_severity={"HIGH": 3},
        by_check={"closed-check": 2, "still-open": 1},
    )
    after = ScanSummary(
        target="http://t/mcp",
        total_findings=1,
        by_severity={"HIGH": 1},
        by_check={"still-open": 1},
    )
    rc = _print_diff(before, after)
    assert rc == 0
    out = capsys.readouterr().out
    assert "closed-check" in out


# ---------------------------------------------------------------------------
# parse_args — new flags
# ---------------------------------------------------------------------------


def test_parse_args_scanner_flag() -> None:
    with patch("sys.argv", ["feedback_loop", "--baseline-url", "http://x/mcp",
                             "--scanner", "/opt/mcpnuke/scan"]):
        args = parse_args()
    assert args.scanner == "/opt/mcpnuke/scan"


def test_parse_args_apply_backend_flag() -> None:
    with patch("sys.argv", ["feedback_loop", "--baseline-url", "http://x/mcp",
                             "--apply-backend", "docker-compose"]):
        args = parse_args()
    assert args.apply_backend == "docker-compose"


def test_parse_args_ssh_key_flag() -> None:
    with patch("sys.argv", ["feedback_loop", "--baseline-url", "http://x/mcp",
                             "--ssh-host", "root@192.168.1.85",
                             "--ssh-key", "/Users/tms/.ssh/id_ed25519"]):
        args = parse_args()
    assert args.ssh_key == "/Users/tms/.ssh/id_ed25519"
    assert args.ssh_host == "root@192.168.1.85"


def test_parse_args_compose_policy_path_flag() -> None:
    with patch("sys.argv", ["feedback_loop", "--baseline-url", "http://x/mcp",
                             "--compose-policy-path", "/opt/compose/nullfield/policy.yaml"]):
        args = parse_args()
    assert args.compose_policy_path == "/opt/compose/nullfield/policy.yaml"


def test_parse_args_defaults() -> None:
    with patch("sys.argv", ["feedback_loop", "--baseline-url", "http://x/mcp"]):
        args = parse_args()
    assert args.scanner is None
    assert args.apply_backend is None
    assert args.ssh_key is None
    assert args.compose_policy_path is None
    assert args.mode == "print"
