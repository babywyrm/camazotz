"""In-memory ring-buffer store for benchmark runs.

Keeps the last BENCH_STORE_SIZE runs (default 20, env-configurable).
Thread-safe. Optionally persists each run to JSON under BENCH_RESULTS_DIR.
"""

from __future__ import annotations

import collections
import json
import os
import threading
from pathlib import Path

from brain_gateway.app.bench.types import BenchmarkRun

_lock = threading.Lock()
_STORE_SIZE = max(1, int(os.environ.get("BENCH_STORE_SIZE", "20")))
_runs: collections.deque[BenchmarkRun] = collections.deque(maxlen=_STORE_SIZE)

_RESULTS_DIR: Path | None = None
_raw = os.environ.get("BENCH_RESULTS_DIR", "")
if _raw:
    _RESULTS_DIR = Path(_raw)
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def save_run(run: BenchmarkRun) -> None:
    """Append *run* to the in-memory buffer and optionally persist to disk."""
    with _lock:
        _runs.append(run)

    if _RESULTS_DIR:
        out = _RESULTS_DIR / f"{run.run_id}.json"
        out.write_text(json.dumps(run.to_dict(), indent=2))


def get_runs(limit: int | None = None) -> list[dict]:
    """Return recent runs newest-first, serialised to dicts."""
    with _lock:
        items = list(reversed(_runs))
    if limit is not None:
        items = items[:limit]
    return [r.to_dict() for r in items]


def get_latest() -> dict | None:
    with _lock:
        if not _runs:
            return None
        return _runs[-1].to_dict()


def clear() -> None:
    with _lock:
        _runs.clear()


def compare_last(n: int = 2) -> list[dict]:
    """Return aggregate summaries for the last *n* runs for quick comparison."""
    with _lock:
        items = list(reversed(_runs))[:n]
    summaries = []
    for r in items:
        summaries.append(
            {
                "run_id": r.run_id,
                "timestamp": r.timestamp,
                "model": r.model,
                "provider": r.provider,
                "total_probes": r.total_probes,
                "passed": r.passed,
                "failed": r.failed,
                "avg_latency_ms": r.avg_latency_ms,
                "injection_resistance_rate": r.injection_resistance_rate,
                "tool_accuracy_rate": r.tool_accuracy_rate,
                "total_input_tokens": r.total_input_tokens,
                "total_output_tokens": r.total_output_tokens,
            }
        )
    return summaries
