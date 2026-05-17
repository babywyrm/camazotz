"""Benchmark runner — executes the probe suite against the current brain."""

from __future__ import annotations

import time

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
    """Run all probes and return a complete :class:`BenchmarkRun`.

    *provider* defaults to the current factory-selected brain if ``None``.
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

    for probe in PROBE_SUITE:
        run.probes.append(_run_probe(probe, provider))

    run.summarise()
    return run
