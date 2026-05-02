#!/usr/bin/env python3
"""End-to-end agentic feedback loop: scan -> generate-policy -> apply -> re-scan.

This script orchestrates the four-tool round-trip that the camazotz / mcpnuke /
nullfield ecosystem is built around:

    1. Scan a baseline target with mcpnuke and record the finding count.
    2. Have mcpnuke synthesize a NullfieldPolicy CRD from those findings.
    3. Apply the CRD via kubectl (local context or via SSH to a K8s host).
    4. Wait for nullfield's controller to bridge the CRD to a ConfigMap and for
       the sidecar's policy loader to pick it up.
    5. Re-scan against the policed entry point and report the delta.

The whole loop is the demo that proves the ecosystem composes: it is the only
place where mcpnuke (red team), nullfield (arbiter), and camazotz (target) all
participate in one continuous run instead of in isolation.

Three apply modes:

    print     dump the generated policy to stdout, do not apply (default; safe).
    dry-run   render via `kubectl apply --dry-run=client -f -`, do not commit.
    apply     real `kubectl apply -f -`, then re-scan.

Targeting:

    --baseline-url    URL of the bypass / unprotected entry point (e.g.
                      http://192.168.1.85:30080/mcp). Used for the first scan.
    --policed-url     URL of the nullfield-protected entry point (e.g.
                      http://192.168.1.85:30090/mcp). Used for the second scan.
                      In `print` mode only --baseline-url is required.

Operator controls:

    --namespace       Kubernetes namespace (default: camazotz).
    --selector        K=V pod label, repeatable. Defaults to app=brain-gateway
                      which matches the chart's brain-gateway Deployment.
    --policy-name     metadata.name (default: mcpnuke-feedback-loop).
    --kubeconfig      Path to a kubeconfig (default: $KUBECONFIG or ~/.kube/config).
    --ssh-host        If set, kubectl runs as `ssh root@<host> sudo k3s kubectl`
                      instead of locally. Convenient for the NUC reference deploy
                      where the agent on the workstation does not have a local
                      kubeconfig pointing at the cluster.
    --wait-seconds    Seconds to wait between apply and re-scan, to let the CRD
                      controller (default 30s loop) and the sidecar reload pick
                      up the new policy. Default: 45.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ScanSummary:
    target: str
    total_findings: int
    by_severity: dict[str, int]
    by_check: dict[str, int]


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], *, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess, echoing the command for operator visibility."""
    print(f"$ {' '.join(shlex.quote(c) for c in cmd)}", flush=True)
    return subprocess.run(cmd, check=check, **kwargs)


def _require(binary: str) -> str:
    """Resolve a required binary or exit with a clear message."""
    path = shutil.which(binary)
    if not path:
        raise SystemExit(f"feedback_loop: required binary not found on PATH: {binary}")
    return path


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def run_scan(target_url: str, json_out: Path, *, extra_args: list[str]) -> ScanSummary:
    """Run mcpnuke against target_url and parse the JSON report."""
    mcpnuke = _require("mcpnuke")
    cmd = [mcpnuke, "--targets", target_url, "--json", str(json_out)] + extra_args
    _run(cmd, check=False)

    if not json_out.exists():
        raise SystemExit(
            f"feedback_loop: mcpnuke did not produce {json_out}. "
            "The scan may have failed before reporting; re-run mcpnuke manually."
        )

    data = json.loads(json_out.read_text())
    findings = data.get("findings") if isinstance(data, dict) else None
    if findings is None:
        results = data.get("results", []) if isinstance(data, dict) else []
        findings = []
        for r in results:
            findings.extend(r.get("findings", []))

    by_sev: dict[str, int] = {}
    by_check: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "UNKNOWN").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        check = f.get("check") or "unknown"
        by_check[check] = by_check.get(check, 0) + 1

    return ScanSummary(
        target=target_url,
        total_findings=len(findings),
        by_severity=by_sev,
        by_check=by_check,
    )


# ---------------------------------------------------------------------------
# Policy generation
# ---------------------------------------------------------------------------


def generate_policy(
    target_url: str,
    *,
    out_path: Path,
    policy_name: str,
    namespace: str,
    selectors: list[str],
    labels: list[str],
) -> None:
    """Run mcpnuke --generate-policy with selector/label targeting."""
    mcpnuke = _require("mcpnuke")
    cmd = [
        mcpnuke,
        target_url,
        "--no-invoke",
        "--generate-policy",
        str(out_path),
        "--policy-name",
        policy_name,
        "--policy-namespace",
        namespace,
    ]
    for sel in selectors:
        cmd.extend(["--policy-selector", sel])
    for lbl in labels:
        cmd.extend(["--policy-labels", lbl])
    _run(cmd, check=False)
    if not out_path.exists():
        raise SystemExit(
            f"feedback_loop: mcpnuke did not write {out_path}. "
            "Re-run with `--generate-policy` manually to debug."
        )


# ---------------------------------------------------------------------------
# Apply (kubectl, optionally over SSH)
# ---------------------------------------------------------------------------


def _kubectl_cmd(args: argparse.Namespace) -> list[str]:
    """Return the kubectl invocation prefix, possibly tunneled via SSH."""
    if args.ssh_host:
        return ["ssh", args.ssh_host, "sudo", "k3s", "kubectl"]
    cmd = [_require("kubectl")]
    if args.kubeconfig:
        cmd.extend(["--kubeconfig", args.kubeconfig])
    return cmd


def apply_policy(args: argparse.Namespace, policy_path: Path) -> None:
    """Apply the generated CRD via kubectl, honoring dry-run mode."""
    base = _kubectl_cmd(args)

    if args.mode == "print":
        print("\n--- Generated NullfieldPolicy (mode=print, NOT applied) ---")
        print(policy_path.read_text())
        return

    apply_cmd = base + ["apply", "-n", args.namespace, "-f", "-"]
    if args.mode == "dry-run":
        apply_cmd.append("--dry-run=client")

    print(f"\n--- Applying policy ({args.mode}) ---")
    with policy_path.open("rb") as fh:
        result = subprocess.run(apply_cmd, stdin=fh, check=False)
    if result.returncode != 0:
        raise SystemExit(
            f"feedback_loop: kubectl apply failed with exit {result.returncode}. "
            "Verify cluster access and that the NullfieldPolicy CRD is installed."
        )


# ---------------------------------------------------------------------------
# Loop
# ---------------------------------------------------------------------------


def _print_scan(label: str, summary: ScanSummary) -> None:
    print(f"\n=== {label}: {summary.target} ===")
    print(f"  total findings: {summary.total_findings}")
    if summary.by_severity:
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
        ordered = sorted(
            summary.by_severity.items(),
            key=lambda kv: sev_order.index(kv[0]) if kv[0] in sev_order else 99,
        )
        line = ", ".join(f"{sev}={n}" for sev, n in ordered)
        print(f"  by severity:    {line}")


def _print_diff(baseline: ScanSummary, after: ScanSummary) -> int:
    print("\n=== Loop result ===")
    delta = baseline.total_findings - after.total_findings
    direction = "decreased" if delta > 0 else ("increased" if delta < 0 else "unchanged")
    print(
        f"  findings {direction}: "
        f"{baseline.total_findings} -> {after.total_findings} (delta {delta:+d})"
    )

    severities = sorted(set(baseline.by_severity) | set(after.by_severity))
    for sev in severities:
        b = baseline.by_severity.get(sev, 0)
        a = after.by_severity.get(sev, 0)
        if b == a:
            continue
        marker = "down" if a < b else "up"
        print(f"  {sev:<8} {b} -> {a}  ({marker})")

    closed_checks = sorted(c for c in baseline.by_check if c not in after.by_check)
    if closed_checks:
        print("  checks fully closed:")
        for c in closed_checks[:10]:
            print(f"    - {c} (was {baseline.by_check[c]})")
        if len(closed_checks) > 10:
            print(f"    ... and {len(closed_checks) - 10} more")

    if delta > 0:
        print("\nLoop verified: applied policy reduced the attack surface.")
        return 0

    if delta == 0:
        print(
            "\nLoop completed but findings did not move. Likely causes: "
            "selector did not match the target pods, the CRD bridge has not "
            "synced yet (default 30s loop — try a larger --wait-seconds), or "
            "the policy was applied to the wrong namespace."
        )
        return 1

    print(
        "\nLoop completed but findings INCREASED. The applied policy probably "
        "broke the gateway. Check `kubectl logs -l app=brain-gateway -c nullfield`."
    )
    return 2


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--baseline-url",
        required=True,
        help="MCP endpoint to scan as baseline (typically the bypass entry, e.g. "
        "http://192.168.1.85:30080/mcp).",
    )
    p.add_argument(
        "--policed-url",
        help="MCP endpoint to scan after applying the policy (typically the "
        "nullfield-protected entry, e.g. http://192.168.1.85:30090/mcp). "
        "Required for mode=apply.",
    )
    p.add_argument(
        "--mode",
        choices=("print", "dry-run", "apply"),
        default="print",
        help="What to do with the generated policy. Default: print (safe).",
    )
    p.add_argument(
        "--namespace",
        default="camazotz",
        help="Kubernetes namespace for the NullfieldPolicy (default: camazotz).",
    )
    p.add_argument(
        "--selector",
        action="append",
        default=[],
        help="K=V pod label for spec.selector.matchLabels, repeatable. "
        "Defaults to app=brain-gateway when no --selector given.",
    )
    p.add_argument(
        "--label",
        action="append",
        default=[],
        help="K=V metadata label for the policy, repeatable.",
    )
    p.add_argument(
        "--policy-name",
        default="mcpnuke-feedback-loop",
        help="metadata.name for the generated policy "
        "(default: mcpnuke-feedback-loop).",
    )
    p.add_argument(
        "--kubeconfig",
        default=os.environ.get("KUBECONFIG"),
        help="Path to kubeconfig (default: $KUBECONFIG or ~/.kube/config).",
    )
    p.add_argument(
        "--ssh-host",
        help="If set, run kubectl as `ssh <host> sudo k3s kubectl`. Useful for "
        "the NUC reference deploy where the workstation lacks a local kubeconfig.",
    )
    p.add_argument(
        "--wait-seconds",
        type=int,
        default=45,
        help="Seconds to wait between apply and re-scan, to let the CRD "
        "controller (default 30s loop) and sidecar policy loader pick up "
        "the new policy. Default: 45.",
    )
    p.add_argument(
        "--workdir",
        help="Directory for intermediate JSON + YAML artifacts. "
        "Default: a fresh tempdir.",
    )
    p.add_argument(
        "--scan-args",
        default="",
        help="Extra args passed verbatim to the mcpnuke scans (e.g. "
        '"--no-invoke --safe-mode").',
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.mode == "apply" and not args.policed_url:
        raise SystemExit(
            "feedback_loop: --policed-url is required when --mode=apply "
            "(re-scan needs to hit the nullfield-protected entry point)."
        )
    if not args.selector:
        args.selector = ["app=brain-gateway"]

    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="feedback-loop-"))
    workdir.mkdir(parents=True, exist_ok=True)
    print(f"feedback_loop: workdir = {workdir}")

    extra_scan_args = shlex.split(args.scan_args) if args.scan_args else []

    baseline_json = workdir / "baseline.json"
    print("\n[1/5] Baseline scan ...")
    baseline = run_scan(args.baseline_url, baseline_json, extra_args=extra_scan_args)
    _print_scan("Baseline", baseline)

    policy_path = workdir / "policy.yaml"
    print("\n[2/5] Generating policy from baseline findings ...")
    generate_policy(
        args.baseline_url,
        out_path=policy_path,
        policy_name=args.policy_name,
        namespace=args.namespace,
        selectors=args.selector,
        labels=args.label,
    )
    print(f"  policy written to {policy_path} ({policy_path.stat().st_size} bytes)")

    print(f"\n[3/5] Apply (mode={args.mode}) ...")
    apply_policy(args, policy_path)

    if args.mode != "apply":
        print(
            f"\n[4/5] Skipped wait — mode={args.mode} did not commit the policy."
        )
        print("[5/5] Skipped re-scan.")
        print(
            f"\nDone. Generated policy at {policy_path}. "
            "Re-run with --mode=apply to commit and verify the loop."
        )
        return 0

    print(f"\n[4/5] Waiting {args.wait_seconds}s for CRD sync + sidecar reload ...")
    time.sleep(args.wait_seconds)

    after_json = workdir / "after.json"
    print("\n[5/5] Re-scan against policed entry ...")
    after = run_scan(args.policed_url, after_json, extra_args=extra_scan_args)
    _print_scan("After policy", after)

    return _print_diff(baseline, after)


if __name__ == "__main__":
    sys.exit(main())
