"""
qa_runner — reusable QA engine for Camazotz scenario validation.

Used by both the CLI harness (scripts/qa_harness.py) and the Flask
operator panel (frontend/app.py → /operator).
"""
from __future__ import annotations

import time
from dataclasses import asdict
from typing import Callable

from .checks import MODULE_TESTS
from .client import GatewayClient
from .walkthroughs import WALKTHROUGHS, WalkthroughStep
from .types import (
    GUARDRAIL_LABELS,
    GUARDRAIL_LEVELS,
    CheckResult,
    LevelResult,
    ModuleResult,
)

__all__ = [
    "CheckResult",
    "GatewayClient",
    "GUARDRAIL_LABELS",
    "GUARDRAIL_LEVELS",
    "LevelResult",
    "MODULE_TESTS",
    "ModuleResult",
    "WALKTHROUGHS",
    "WalkthroughStep",
    "run_qa",
    "results_to_dict",
]


def run_qa(
    gw: GatewayClient,
    levels: tuple[str, ...] = GUARDRAIL_LEVELS,
    modules: dict[str, Callable] | None = None,
    *,
    verbose: bool = False,
) -> list[ModuleResult]:
    """Execute checks for each module at each guardrail level.

    Args:
        gw: Gateway client pointed at the brain-gateway.
        levels: Guardrail levels to test.
        modules: Subset of MODULE_TESTS to run (default: all).
        verbose: Print progress to stdout (CLI mode).
    """
    import sys

    modules = modules or MODULE_TESTS
    all_results: list[ModuleResult] = []
    total = len(modules)

    for idx, (mod_name, test_fn) in enumerate(modules.items(), 1):
        mr = ModuleResult(module=mod_name)

        if verbose:
            print(f"\n{'=' * 60}", flush=True)
            print(f"  [{idx}/{total}] {mod_name}", flush=True)
            print(f"{'=' * 60}", flush=True)

        for level in levels:
            t0 = time.monotonic()
            try:
                gw.reset()
                time.sleep(0.3)
                gw.set_guardrail(level)
                time.sleep(0.2)

                checks = test_fn(gw, level)
            except Exception as exc:
                checks = [CheckResult(
                    name="module_execution",
                    passed=False,
                    detail=f"uncaught exception: {type(exc).__name__}: {exc}",
                )]
                if verbose:
                    print(f"  ERROR running {mod_name} at {level}: {exc}", file=sys.stderr, flush=True)

            elapsed = round(time.monotonic() - t0, 1)
            lr = LevelResult(level=level, checks=checks)
            mr.levels.append(lr)

            if verbose:
                label = GUARDRAIL_LABELS.get(level, level)
                failed = [c for c in checks if not c.passed]
                status = "PASS" if not failed else "ISSUE"
                suffix = ""
                if failed:
                    suffix = f" — {'; '.join(f'FAIL: {c.name}' for c in failed)}"
                print(f"  [{label:3s}] {status} ({elapsed}s){suffix}", flush=True)

        all_results.append(mr)

    return all_results


def results_to_dict(results: list[ModuleResult]) -> dict:
    """Convert results to a JSON-serializable dict."""
    total_issues = sum(mr.issue_count for mr in results)
    total_checks = sum(len(lr.checks) for mr in results for lr in mr.levels)
    total_levels = sum(len(mr.levels) for mr in results)

    return {
        "total_modules": len(results),
        "total_test_points": total_levels,
        "total_checks": total_checks,
        "total_issues": total_issues,
        "modules": [
            {
                "name": mr.module,
                "issues": mr.issue_count,
                "levels": [
                    {
                        "level": lr.level,
                        "passed": lr.passed,
                        "checks": [asdict(c) for c in lr.checks],
                    }
                    for lr in mr.levels
                ],
            }
            for mr in results
        ],
    }
