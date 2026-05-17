"""Benchmark runner — executes the probe suite against the current brain."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncGenerator

from brain_gateway.app.bench.probes import PROBE_SUITE, Probe
from brain_gateway.app.bench.types import BenchmarkRun, ProbeResult
from brain_gateway.app.brain.provider import BrainProvider


def _run_probe(probe: Probe, provider: BrainProvider) -> ProbeResult:
    t0 = time.monotonic()
    try:
        result = provider.generate(prompt=probe.prompt, system=probe.system)
        latency_ms = int((time.monotonic() - t0) * 1000)
        passed, notes = probe.evaluator(result.text)
        outcome = "pass" if passed else "fail"
        return ProbeResult(
            probe_id=probe.id,
            category=probe.category,
            description=probe.description,
            latency_ms=latency_ms,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            outcome=outcome,
            passed=passed,
            response_preview=result.text[:200],
            notes=notes,
        )
    except Exception as exc:  # noqa: BLE001
        latency_ms = int((time.monotonic() - t0) * 1000)
        return ProbeResult(
            probe_id=probe.id,
            category=probe.category,
            description=probe.description,
            latency_ms=latency_ms,
            input_tokens=0,
            output_tokens=0,
            outcome="error",
            passed=False,
            response_preview="",
            notes=f"error: {exc}",
        )


def run_benchmark(provider: BrainProvider | None = None) -> BenchmarkRun:
    """Run all probes synchronously and return a complete :class:`BenchmarkRun`."""
    if provider is None:
        from brain_gateway.app.brain.factory import get_provider
        provider = get_provider()

    from brain_gateway.app.config import get_brain_provider, get_ollama_host

    run = BenchmarkRun(
        model=getattr(provider, "_model", "") or getattr(provider, "name", ""),
        provider=get_brain_provider(),
        ollama_host=get_ollama_host(),
    )

    for probe in PROBE_SUITE:
        run.probes.append(_run_probe(probe, provider))

    run.summarise()
    return run


async def run_benchmark_stream(
    provider: BrainProvider | None = None,
) -> AsyncGenerator[tuple[str, dict], None]:
    """Async generator — yields ``(event_type, data)`` as each probe completes.

    Events emitted in order::

        run_start   — one, immediately, with run metadata + probe count
        probe_start — one per probe, before inference begins
        probe_done  — one per probe, after inference, with result + running totals
        run_complete — one, at the end, with the full serialised BenchmarkRun

    The run is saved to the store on ``run_complete``.
    Probes run sequentially in a thread pool so the event loop stays responsive.
    """
    if provider is None:
        from brain_gateway.app.brain.factory import get_provider
        provider = get_provider()

    from brain_gateway.app.config import get_brain_provider, get_ollama_host

    run = BenchmarkRun(
        model=getattr(provider, "_model", "") or getattr(provider, "name", ""),
        provider=get_brain_provider(),
        ollama_host=get_ollama_host(),
    )

    yield "run_start", {
        "run_id": run.run_id,
        "timestamp": run.timestamp,
        "model": run.model,
        "provider": run.provider,
        "ollama_host": run.ollama_host,
        "total_probes": len(PROBE_SUITE),
    }

    cumulative_in = 0
    cumulative_out = 0
    t_run_start = time.monotonic()

    for idx, probe in enumerate(PROBE_SUITE):
        yield "probe_start", {
            "index": idx,
            "total": len(PROBE_SUITE),
            "probe_id": probe.id,
            "category": probe.category,
            "description": probe.description,
        }

        result = await asyncio.to_thread(_run_probe, probe, provider)
        run.probes.append(result)
        run.summarise()

        cumulative_in += result.input_tokens
        cumulative_out += result.output_tokens
        elapsed_ms = int((time.monotonic() - t_run_start) * 1000)

        yield "probe_done", {
            **result.to_dict(),
            "index": idx,
            "total": len(PROBE_SUITE),
            "cumulative_in_tokens": cumulative_in,
            "cumulative_out_tokens": cumulative_out,
            "elapsed_ms": elapsed_ms,
            # Running aggregates so the UI can update mid-run
            "run_passed": run.passed,
            "run_failed": run.failed,
            "run_avg_latency_ms": run.avg_latency_ms,
        }

    from brain_gateway.app.bench.store import save_run
    save_run(run)

    yield "run_complete", run.to_dict()
