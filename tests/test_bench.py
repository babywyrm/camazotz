"""Tests for the camazotz model-tier benchmark.

Uses a fake brain provider so no real Ollama / cloud calls happen.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from brain_gateway.app.bench.probes import PROBE_SUITE
from brain_gateway.app.bench.runner import run_benchmark, run_benchmark_stream
from brain_gateway.app.bench.store import clear, compare_last, get_latest, get_runs, save_run
from brain_gateway.app.bench.types import BenchmarkRun, ProbeResult
from brain_gateway.app.brain.provider import BrainResult
from brain_gateway.app.main import app


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_provider(response: str = "TOOL:read_secret name=db-password") -> MagicMock:
    """Return a fake BrainProvider whose generate() always returns *response*."""
    prov = MagicMock()
    prov.name = "mock"
    prov._model = "mock-model"
    prov.generate.return_value = BrainResult(
        text=response,
        input_tokens=10,
        output_tokens=20,
        cost_usd=0.0,
        model="mock-model",
    )
    return prov


# ── Unit tests: types ─────────────────────────────────────────────────────────

class TestBenchmarkRunSummarise:
    def test_empty_run(self) -> None:
        run = BenchmarkRun(model="m", provider="local")
        run.summarise()
        assert run.total_probes == 0
        assert run.passed == 0
        assert run.avg_latency_ms == 0.0

    def test_single_pass(self) -> None:
        run = BenchmarkRun(model="m", provider="local")
        run.probes = [
            ProbeResult("p1", "tool_accuracy", "desc", 100, 10, 20, "pass", True, "ok"),
        ]
        run.summarise()
        assert run.total_probes == 1
        assert run.passed == 1
        assert run.failed == 0
        assert run.avg_latency_ms == 100.0
        assert run.tool_accuracy_rate == 1.0

    def test_mixed_injection_probes(self) -> None:
        run = BenchmarkRun(model="m", provider="local")
        run.probes = [
            ProbeResult("i1", "injection", "d", 50, 5, 5, "pass", True, ""),
            ProbeResult("i2", "injection", "d", 50, 5, 5, "fail", False, ""),
            ProbeResult("i3", "injection", "d", 50, 5, 5, "pass", True, ""),
        ]
        run.summarise()
        assert run.injection_resistance_rate == pytest.approx(2 / 3, rel=1e-3)
        assert run.total_input_tokens == 15
        assert run.total_output_tokens == 15

    def test_to_dict_contains_probes(self) -> None:
        run = BenchmarkRun(model="m", provider="local")
        run.probes = [
            ProbeResult("p1", "efficiency", "d", 10, 1, 2, "pass", True, ""),
        ]
        run.summarise()
        d = run.to_dict()
        assert "probes" in d
        assert len(d["probes"]) == 1
        assert d["probes"][0]["probe_id"] == "p1"


# ── Unit tests: probes ────────────────────────────────────────────────────────

class TestProbeDefinitions:
    def test_probe_ids_unique(self) -> None:
        ids = [p.id for p in PROBE_SUITE]
        assert len(ids) == len(set(ids)), "Duplicate probe IDs detected"

    def test_all_probes_have_required_fields(self) -> None:
        for probe in PROBE_SUITE:
            assert probe.id
            assert probe.category in {"tool_accuracy", "injection", "instruction", "efficiency"}
            assert probe.prompt
            assert probe.system
            assert callable(probe.evaluator)

    def test_evaluator_returns_tuple(self) -> None:
        for probe in PROBE_SUITE:
            result = probe.evaluator("some response text")
            assert isinstance(result, tuple)
            assert len(result) == 2
            passed, notes = result
            assert isinstance(passed, bool)
            assert isinstance(notes, str)


# ── Unit tests: runner ────────────────────────────────────────────────────────

class TestRunner:
    def test_run_benchmark_returns_benchmarkrun(self, monkeypatch) -> None:
        prov = _make_provider()
        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        monkeypatch.setenv("CAMAZOTZ_OLLAMA_MODEL", "mock-model")
        run = run_benchmark(prov)
        assert isinstance(run, BenchmarkRun)
        assert run.total_probes == len(PROBE_SUITE)
        assert run.model == "mock-model"

    def test_run_benchmark_calls_generate_for_each_probe(self) -> None:
        prov = _make_provider()
        run = run_benchmark(prov)
        assert prov.generate.call_count == len(PROBE_SUITE)

    def test_run_benchmark_records_latency(self) -> None:
        prov = _make_provider()
        run = run_benchmark(prov)
        for pr in run.probes:
            assert pr.latency_ms >= 0

    def test_run_benchmark_provider_error_becomes_error_outcome(self) -> None:
        prov = MagicMock()
        prov.name = "broken"
        prov._model = ""
        prov.generate.side_effect = RuntimeError("inference backend down")
        run = run_benchmark(prov)
        for pr in run.probes:
            assert pr.outcome == "error"
            assert pr.passed is False
            assert "inference backend down" in pr.notes

    def test_injection_probe_passes_when_model_resists(self) -> None:
        prov = _make_provider("SAFE: this looks like an injection attempt, denied")
        run = run_benchmark(prov)
        injection_results = [p for p in run.probes if p.category == "injection"]
        assert len(injection_results) > 0
        assert run.injection_resistance_rate > 0.0

    def test_tool_accuracy_probe_passes_when_model_calls_right_tool(self) -> None:
        def _smart_generate(prompt: str, system: str = "") -> BrainResult:
            if "cluster_diagnostics" in system:
                text = "TOOL:cluster_diagnostics query=pod health check"
            elif "read_secret" in system:
                text = "TOOL:read_secret name=db-password"
            elif "send_notification" in system:
                text = "TOOL:send_notification channel=#security-ops message=anomaly"
            elif "BLOCKED" in system:
                text = "BLOCKED: that tool is not permitted."
            elif "JSON" in system:
                text = '{"status": "unknown"}'
            else:
                text = "ready"
            return BrainResult(text=text, input_tokens=5, output_tokens=5)

        prov = MagicMock()
        prov.name = "smart"
        prov._model = "smart-model"
        prov.generate.side_effect = _smart_generate
        run = run_benchmark(prov)
        assert run.tool_accuracy_rate == 1.0


# ── Unit tests: store ─────────────────────────────────────────────────────────

class TestStore:
    def setup_method(self) -> None:
        clear()

    def teardown_method(self) -> None:
        clear()

    def _make_run(self, model: str = "test-model") -> BenchmarkRun:
        run = BenchmarkRun(model=model, provider="local")
        run.probes = [
            ProbeResult("p1", "efficiency", "d", 50, 10, 20, "pass", True, ""),
        ]
        run.summarise()
        return run

    def test_save_and_retrieve(self) -> None:
        run = self._make_run()
        save_run(run)
        results = get_runs()
        assert len(results) == 1
        assert results[0]["model"] == "test-model"

    def test_get_latest(self) -> None:
        save_run(self._make_run("first"))
        save_run(self._make_run("second"))
        latest = get_latest()
        assert latest is not None
        assert latest["model"] == "second"

    def test_get_latest_empty(self) -> None:
        assert get_latest() is None

    def test_get_runs_limit(self) -> None:
        for i in range(5):
            save_run(self._make_run(f"model-{i}"))
        assert len(get_runs(limit=3)) == 3

    def test_compare_last(self) -> None:
        save_run(self._make_run("a"))
        save_run(self._make_run("b"))
        save_run(self._make_run("c"))
        cmp = compare_last(n=2)
        assert len(cmp) == 2
        assert cmp[0]["model"] == "c"
        assert cmp[1]["model"] == "b"

    def test_clear(self) -> None:
        save_run(self._make_run())
        clear()
        assert get_runs() == []

    def test_runs_newest_first(self) -> None:
        save_run(self._make_run("old"))
        save_run(self._make_run("new"))
        runs = get_runs()
        assert runs[0]["model"] == "new"
        assert runs[1]["model"] == "old"


# ── Integration tests: API endpoints ─────────────────────────────────────────

class TestBenchAPI:
    def setup_method(self) -> None:
        from brain_gateway.app.bench.store import clear as _clear
        _clear()

    def teardown_method(self) -> None:
        from brain_gateway.app.bench.store import clear as _clear
        _clear()

    def _mock_run_benchmark(self, model: str = "api-model") -> BenchmarkRun:
        run = BenchmarkRun(model=model, provider="local")
        run.probes = [
            ProbeResult("p1", "efficiency", "d", 30, 5, 10, "pass", True, ""),
        ]
        run.summarise()
        return run

    def test_bench_run_returns_200(self, monkeypatch) -> None:
        from unittest.mock import patch
        run = self._mock_run_benchmark()
        with patch("brain_gateway.app.bench.runner.run_benchmark", return_value=run):
            with patch("brain_gateway.app.brain.factory.get_provider", return_value=_make_provider()):
                client = TestClient(app)
                resp = client.post("/bench/run", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "run_id" in data
        assert "model" in data
        assert "probes" in data

    def test_bench_results_empty(self) -> None:
        client = TestClient(app)
        resp = client.get("/bench/results")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["runs"] == []

    def test_bench_latest_404_when_empty(self) -> None:
        client = TestClient(app)
        resp = client.get("/bench/results/latest")
        assert resp.status_code == 404

    def test_bench_results_after_run(self, monkeypatch) -> None:
        from unittest.mock import patch
        run = self._mock_run_benchmark()
        with patch("brain_gateway.app.bench.runner.run_benchmark", return_value=run):
            with patch("brain_gateway.app.brain.factory.get_provider", return_value=_make_provider()):
                client = TestClient(app)
                client.post("/bench/run", json={})
        resp = client.get("/bench/results")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    def test_bench_latest_after_run(self, monkeypatch) -> None:
        from unittest.mock import patch
        run = self._mock_run_benchmark("latest-model")
        with patch("brain_gateway.app.bench.runner.run_benchmark", return_value=run):
            with patch("brain_gateway.app.brain.factory.get_provider", return_value=_make_provider()):
                client = TestClient(app)
                client.post("/bench/run", json={})
        resp = client.get("/bench/results/latest")
        assert resp.status_code == 200
        assert resp.json()["model"] == "latest-model"

    def test_bench_compare(self, monkeypatch) -> None:
        from unittest.mock import patch
        client = TestClient(app)
        for name in ("qwen:1.5b", "qwen:7b"):
            run = self._mock_run_benchmark(name)
            with patch("brain_gateway.app.bench.runner.run_benchmark", return_value=run):
                with patch("brain_gateway.app.brain.factory.get_provider", return_value=_make_provider()):
                    client.post("/bench/run", json={})
        resp = client.get("/bench/compare?n=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["n"] == 2
        models = [r["model"] for r in data["runs"]]
        assert "qwen:7b" in models

    def test_bench_clear(self, monkeypatch) -> None:
        from unittest.mock import patch
        run = self._mock_run_benchmark()
        with patch("brain_gateway.app.bench.runner.run_benchmark", return_value=run):
            with patch("brain_gateway.app.brain.factory.get_provider", return_value=_make_provider()):
                client = TestClient(app)
                client.post("/bench/run", json={})
        resp = client.delete("/bench/results")
        assert resp.status_code == 200
        assert resp.json()["cleared"] is True
        assert client.get("/bench/results").json()["count"] == 0

    def test_bench_results_limit_param(self, monkeypatch) -> None:
        from unittest.mock import patch
        client = TestClient(app)
        for i in range(4):
            run = self._mock_run_benchmark(f"model-{i}")
            with patch("brain_gateway.app.bench.runner.run_benchmark", return_value=run):
                with patch("brain_gateway.app.brain.factory.get_provider", return_value=_make_provider()):
                    client.post("/bench/run", json={})
        resp = client.get("/bench/results?limit=2")
        assert resp.json()["count"] == 2


# ── Unit tests: run_benchmark_stream ────────────────────────────────────────

class TestRunBenchmarkStream:
    """Tests for the async streaming runner."""

    def _collect(self, prov=None, **kwargs):
        """Run the async generator synchronously and collect all (event, data) pairs."""
        import asyncio

        async def _run():
            events = []
            async for event_type, data in run_benchmark_stream(prov, **kwargs):
                events.append((event_type, data))
            return events

        return asyncio.run(_run())

    def test_emits_run_start_first(self, monkeypatch) -> None:
        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        monkeypatch.setenv("CAMAZOTZ_OLLAMA_MODEL", "test-model")
        events = self._collect(_make_provider())
        assert events[0][0] == "run_start"

    def test_emits_run_complete_last(self, monkeypatch) -> None:
        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        events = self._collect(_make_provider())
        assert events[-1][0] == "run_complete"

    def test_emits_probe_start_and_done_per_probe(self, monkeypatch) -> None:
        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        events = self._collect(_make_provider())
        probe_starts = [e for e in events if e[0] == "probe_start"]
        probe_dones = [e for e in events if e[0] == "probe_done"]
        assert len(probe_starts) == len(PROBE_SUITE)
        assert len(probe_dones) == len(PROBE_SUITE)

    def test_run_start_contains_model_and_total(self, monkeypatch) -> None:
        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        monkeypatch.setenv("CAMAZOTZ_OLLAMA_MODEL", "qwen:7b")
        events = self._collect(_make_provider())
        _, d = events[0]
        assert d["total_probes"] == len(PROBE_SUITE)
        assert "run_id" in d
        assert "timestamp" in d

    def test_probe_done_contains_cumulative_tokens(self, monkeypatch) -> None:
        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        events = self._collect(_make_provider())
        dones = [e for e in events if e[0] == "probe_done"]
        # Each probe returns 20 output tokens; cumulative should grow
        tok_series = [d["cumulative_out_tokens"] for _, d in dones]
        assert tok_series[-1] >= tok_series[0]
        assert tok_series[-1] > 0

    def test_run_complete_matches_benchmarkrun_shape(self, monkeypatch) -> None:
        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        events = self._collect(_make_provider())
        _, final = events[-1]
        assert "run_id" in final
        assert "total_probes" in final
        assert "probes" in final
        assert final["total_probes"] == len(PROBE_SUITE)

    def test_probe_done_has_elapsed_ms(self, monkeypatch) -> None:
        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        events = self._collect(_make_provider())
        dones = [d for _, d in events if _ == "probe_done"]
        assert all("elapsed_ms" in d for d in dones)
        assert all(d["elapsed_ms"] >= 0 for d in dones)

    def test_stream_saves_to_store(self, monkeypatch) -> None:
        import asyncio
        from brain_gateway.app.bench.store import clear, get_latest

        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        clear()

        async def _run():
            async for _ in run_benchmark_stream(_make_provider()):
                pass

        asyncio.run(_run())
        assert get_latest() is not None


# ── SSE endpoint: GET /bench/run/stream ──────────────────────────────────────

class TestBenchStreamEndpoint:
    """Smoke-tests for the SSE streaming endpoint via TestClient."""

    def test_stream_endpoint_returns_event_stream(self, monkeypatch) -> None:
        from unittest.mock import AsyncMock, patch

        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        monkeypatch.setenv("CAMAZOTZ_OLLAMA_MODEL", "stream-model")

        prov = _make_provider()

        async def _fake_stream(provider):
            yield "run_start", {"run_id": "x", "model": "stream-model",
                                "provider": "local", "ollama_host": "http://ollama:11434",
                                "total_probes": 1, "timestamp": "2026-01-01T00:00:00"}
            yield "run_complete", {"run_id": "x", "total_probes": 1, "passed": 1,
                                   "failed": 0, "model": "stream-model", "provider": "local",
                                   "ollama_host": "", "probes": [], "avg_latency_ms": 0,
                                   "total_input_tokens": 0, "total_output_tokens": 0,
                                   "injection_resistance_rate": 0, "tool_accuracy_rate": 0,
                                   "timestamp": "2026-01-01T00:00:00"}

        with patch("brain_gateway.app.bench.runner.run_benchmark_stream", side_effect=_fake_stream):
            with patch("brain_gateway.app.brain.factory.get_provider", return_value=prov):
                client = TestClient(app)
                resp = client.get("/bench/run/stream")

        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")

    def test_stream_endpoint_model_override_accepted(self, monkeypatch) -> None:
        """Verify the endpoint does not 422 when ?model= is provided."""
        from unittest.mock import patch

        monkeypatch.setenv("BRAIN_PROVIDER", "local")
        prov = _make_provider()

        async def _fake_stream(provider):
            yield "run_complete", {}
            return

        with patch("brain_gateway.app.bench.runner.run_benchmark_stream", side_effect=_fake_stream):
            with patch("brain_gateway.app.brain.factory.get_provider", return_value=prov):
                with patch("brain_gateway.app.brain.factory.reset_provider"):
                    with patch("brain_gateway.app.config.set_runtime_model"):
                        with patch("brain_gateway.app.config.get_runtime_model", return_value="qwen:7b"):
                            client = TestClient(app)
                            resp = client.get("/bench/run/stream?model=qwen:1.5b")

        assert resp.status_code == 200
