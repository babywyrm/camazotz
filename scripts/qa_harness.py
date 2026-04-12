#!/usr/bin/env python3
"""
Camazotz QA Harness — end-to-end scenario validation across guardrail levels.

Fires every registered tool at EZ / MOD / MAX guardrails, validates response
shapes, and reports issues. Designed to be extended as new modules land.

Usage:
    python scripts/qa_harness.py                     # full run against localhost
    python scripts/qa_harness.py --gateway http://host:8080
    python scripts/qa_harness.py --level easy         # single guardrail level
    python scripts/qa_harness.py --module auth_lab    # single module
    python scripts/qa_harness.py --json               # machine-readable output
"""
from __future__ import annotations

import argparse
import json
import sys

try:
    import httpx
except ImportError:
    sys.exit("httpx is required: pip install httpx")

from qa_runner import (
    GUARDRAIL_LABELS,
    GUARDRAIL_LEVELS,
    GatewayClient,
    MODULE_TESTS,
    results_to_dict,
    run_qa,
)


def _print_summary(results_dict: dict) -> int:
    total_issues = results_dict["total_issues"]
    total_levels = results_dict["total_test_points"]
    total_checks = results_dict["total_checks"]
    total_modules = results_dict["total_modules"]

    print(f"\n{'=' * 60}")
    print(f"  SUMMARY: {total_issues} issues across {total_levels} test points ({total_checks} checks)")
    print(f"{'=' * 60}")
    if total_issues:
        for mod in results_dict["modules"]:
            for lr in mod["levels"]:
                for c in lr["checks"]:
                    if not c["passed"]:
                        label = GUARDRAIL_LABELS.get(lr["level"], lr["level"])
                        detail = f" ({c['detail']})" if c["detail"] else ""
                        print(f"  ! [{label}] {mod['name']}: {c['name']}{detail}")
    else:
        print(f"  ALL CLEAR — {total_modules} modules × {len(GUARDRAIL_LEVELS)} guardrail levels")

    return total_issues


def main() -> None:
    parser = argparse.ArgumentParser(description="Camazotz QA Harness — scenario validation across guardrail levels")
    parser.add_argument("--gateway", default="http://localhost:8080", help="Gateway base URL")
    parser.add_argument("--level", choices=GUARDRAIL_LEVELS, help="Test a single guardrail level")
    parser.add_argument("--module", help="Test a single module (e.g. auth_lab)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--timeout", type=float, default=30, help="Per-request timeout in seconds")
    parser.add_argument("--list", action="store_true", dest="list_modules", help="List available modules and exit")
    parser.add_argument("--debug", action="store_true", help="Verbose gateway client logging to stderr")
    args = parser.parse_args()

    if args.list_modules:
        for name in MODULE_TESTS:
            print(f"  {name}")
        return

    gw = GatewayClient(args.gateway, timeout=args.timeout, verbose=args.debug)

    try:
        tools = gw.list_tools()
    except httpx.ConnectError:
        sys.exit(f"Cannot reach gateway at {args.gateway} — is it running?")

    if not args.json:
        print(f"Connected to {args.gateway} — {len(tools)} tools registered", flush=True)

    levels = (args.level,) if args.level else GUARDRAIL_LEVELS
    modules = MODULE_TESTS
    if args.module:
        if args.module not in MODULE_TESTS:
            sys.exit(f"Unknown module '{args.module}'. Use --list to see available modules.")
        modules = {args.module: MODULE_TESTS[args.module]}

    if not args.json:
        print(f"Running {len(modules)} modules × {len(levels)} levels...", flush=True)

    results, idp_status = run_qa(gw, levels=levels, modules=modules, verbose=not args.json)
    rd = results_to_dict(results, idp_status)

    if args.json:
        print(json.dumps(rd, indent=2))
    else:
        _print_summary(rd)

    sys.exit(1 if rd["total_issues"] else 0)


if __name__ == "__main__":
    main()
