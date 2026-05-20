"""Camazotz Brain Gateway — MCP 2025-03-26 Streamable HTTP transport.

Supports:
  - POST /mcp  → JSON-RPC requests (returns JSON or SSE based on Accept)
  - GET  /mcp  → 405 (no server-initiated messages yet)
  - DELETE /mcp → session termination
  - Notifications (id=None) → 202 Accepted
  - Mcp-Session-Id header for session management
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from brain_gateway.app.config import (
    VALID_BRAIN_PROVIDERS,
    get_available_models,
    get_brain_metadata,
    get_brain_provider,
    get_difficulty,
    get_idp_provider,
    get_ollama_host,
    get_ollama_model,
    is_live_idp,
    reset_brain_config,
    reset_idp_config,
    set_brain_config,
    set_difficulty,
    set_idp_config,
    set_runtime_model,
    show_tokens,
    validate_ollama_host,
    validate_ollama_url,
)
from brain_gateway.app.identity.service import idp_status
from brain_gateway.app.mcp_handlers import handle_rpc
from brain_gateway.app.rate_limit import TokenBucketLimiter
from brain_gateway.app.models import JsonRpcRequest
from brain_gateway.app.modules.registry import get_registry
from brain_gateway.app.observer import get_buffer_info, get_events, get_events_since, get_last_event, record_brain_switch
from brain_gateway.app.scenarios import ScenarioLoader, generate_flags, verify_flag
from brain_gateway.app.session import SessionManager

app = FastAPI(title="Camazotz Brain Gateway")
sessions = SessionManager()
_rate_limiter = TokenBucketLimiter()

IDP_BACKED_LABS: tuple[str, ...] = ("oauth_delegation_lab", "rbac_lab", "revocation_lab")
IDP_BACKED_TOOLS: tuple[str, ...] = (
    "oauth.exchange_token",
    "revocation.revoke_principal",
    "revocation.use_token",
)

_scenario_loader: ScenarioLoader | None = None
_loader_lock = threading.Lock()


def _get_loader() -> ScenarioLoader:
    global _scenario_loader
    with _loader_lock:
        if _scenario_loader is None:
            modules_dir = os.environ.get("CAMAZOTZ_MODULES_DIR", "camazotz_modules")
            _scenario_loader = ScenarioLoader(modules_dir)
            _scenario_loader.load_all()
        return _scenario_loader


@app.post("/mcp")
async def mcp_endpoint(request: Request, payload: JsonRpcRequest) -> Response:
    if payload.id is None:
        return Response(status_code=202)

    client_id = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if not _rate_limiter.allow(client_id, difficulty=get_difficulty()):
        return JSONResponse(
            status_code=429,
            content={"jsonrpc": "2.0", "id": payload.id, "error": {"code": -32000, "message": "Rate limit exceeded"}},
        )

    result = handle_rpc(payload)

    headers: dict[str, str] = {}
    if payload.method == "initialize":
        sid = sessions.create()
        headers["mcp-session-id"] = sid

    accept = request.headers.get("accept", "")
    if "text/event-stream" in accept:
        async def _stream() -> AsyncIterator[dict[str, str]]:
            yield {"event": "message", "data": json.dumps(result)}
        return EventSourceResponse(_stream(), headers=headers)

    return JSONResponse(content=result, headers=headers)


@app.get("/mcp")
async def mcp_sse_listener() -> Response:
    return Response(status_code=405)


@app.delete("/mcp")
async def mcp_delete_session(request: Request) -> Response:
    sid = request.headers.get("mcp-session-id")
    if sid:
        sessions.destroy(sid)
    return Response(status_code=200)


@app.get("/_observer/last-event")
def observer_last_event() -> dict[str, object]:
    """Return the most recent observer event for the dashboard."""
    return get_last_event()


@app.get("/_observer/events")
def observer_events(limit: int | None = None, since: str | None = None) -> dict:
    """Return recent observer events from the ring buffer."""
    if since:
        events = get_events_since(since)
    else:
        events = get_events(limit=limit)
    info = get_buffer_info()
    return {"events": events, **info}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "brain-gateway"}


@app.get("/config")
def get_config() -> dict[str, object]:
    """Return current runtime configuration."""
    status = idp_status()
    brain_meta = get_brain_metadata()
    ollama_host = get_ollama_host()
    config: dict[str, object] = {
        "difficulty": get_difficulty(),
        "show_tokens": show_tokens(),
        "idp_provider": status["idp_provider"],
        "idp_degraded": status["idp_degraded"],
        "idp_reason": status["idp_reason"],
        "idp_backed_labs": list(IDP_BACKED_LABS),
        "idp_backed_tools": list(IDP_BACKED_TOOLS),
        "brain": {
            **brain_meta,
            "ollama_host": ollama_host,
            "ollama_model": get_ollama_model(),
            "available_providers": list(VALID_BRAIN_PROVIDERS),
            "available_models": get_available_models(
                brain_meta["provider"], ollama_host
            ),
        },
    }
    if is_live_idp():
        from brain_gateway.app.identity.service import get_identity_provider as _get_idp

        p = _get_idp()
        if hasattr(p, "issuer_url"):
            config["idp_endpoints"] = {
                "issuer": getattr(p, "issuer_url", "") or "",
                "token": getattr(p, "token_endpoint", "") or "",
                "introspection": getattr(p, "introspection_endpoint", "") or "",
                "revocation": getattr(p, "revocation_endpoint", "") or "",
            }
    return config


class _IdpConfigUpdate(BaseModel):
    provider: str
    issuer_url: str = ""
    token_endpoint: str = ""
    introspection_endpoint: str = ""
    revocation_endpoint: str = ""
    client_id: str = ""
    client_secret: str = ""


class _BrainConfigUpdate(BaseModel):
    provider: str
    ollama_host: str = ""
    ollama_model: str = ""


class _ConfigUpdate(BaseModel):
    difficulty: str | None = None
    model: str | None = None
    idp: _IdpConfigUpdate | None = None
    reset_idp: bool = False
    brain: _BrainConfigUpdate | None = None
    reset_brain: bool = False


@app.put("/config")
def update_config(payload: _ConfigUpdate) -> dict[str, object]:
    """Update runtime difficulty, active brain model, and/or IdP config.

    When the IdP is changed, all lab state is automatically reset to
    prevent stale token/session references from the previous provider.
    """
    from fastapi import HTTPException
    from brain_gateway.app.brain.factory import reset_provider

    if payload.difficulty is not None:
        set_difficulty(payload.difficulty)

    if payload.model is not None:
        if not payload.model.strip():
            raise HTTPException(status_code=400, detail="model must be a non-empty string")
        prev_model = get_brain_metadata().get("model", "")
        set_runtime_model(payload.model)
        reset_provider()
        cur_provider = get_brain_provider()
        record_brain_switch(
            previous_provider=cur_provider, new_provider=cur_provider,
            previous_model=prev_model, new_model=payload.model,
            trigger="api",
        )

    if payload.reset_idp:
        prev_provider = get_idp_provider()
        new_provider = reset_idp_config()
        if new_provider != prev_provider:
            get_registry().reset_all()
            _rate_limiter.reset()
    elif payload.idp is not None:
        prev_provider = get_idp_provider()
        new_provider = set_idp_config(
            provider=payload.idp.provider,
            issuer_url=payload.idp.issuer_url,
            token_endpoint=payload.idp.token_endpoint,
            introspection_endpoint=payload.idp.introspection_endpoint,
            revocation_endpoint=payload.idp.revocation_endpoint,
            client_id=payload.idp.client_id,
            client_secret=payload.idp.client_secret,
        )
        if new_provider != prev_provider:
            get_registry().reset_all()
            _rate_limiter.reset()

    if payload.reset_brain:
        prev_brain = get_brain_provider()
        prev_model = get_brain_metadata().get("model", "")
        new_brain = reset_brain_config()
        reset_provider()
        new_model = get_brain_metadata().get("model", "")
        if new_brain != prev_brain:
            get_registry().reset_all()
            _rate_limiter.reset()
        record_brain_switch(
            previous_provider=prev_brain, new_provider=new_brain,
            previous_model=prev_model, new_model=new_model,
            trigger="api_reset",
        )
    elif payload.brain is not None:
        if payload.brain.provider not in VALID_BRAIN_PROVIDERS:
            raise HTTPException(
                status_code=400,
                detail=f"invalid brain provider: {payload.brain.provider!r}; "
                       f"valid: {', '.join(VALID_BRAIN_PROVIDERS)}",
            )
        if payload.brain.provider == "local":
            host = payload.brain.ollama_host or get_ollama_host()
            url_err = validate_ollama_url(host)
            if url_err:
                raise HTTPException(status_code=400, detail=url_err)
            model = payload.brain.ollama_model or ""
            check = validate_ollama_host(host, model)
            if not check["ok"]:
                raise HTTPException(status_code=422, detail=str(check["error"]))
        prev_brain = get_brain_provider()
        prev_model = get_brain_metadata().get("model", "")
        new_brain = set_brain_config(
            provider=payload.brain.provider,
            ollama_host=payload.brain.ollama_host,
            ollama_model=payload.brain.ollama_model,
        )
        reset_provider()
        new_model = get_brain_metadata().get("model", "")
        if new_brain != prev_brain:
            get_registry().reset_all()
            _rate_limiter.reset()
        record_brain_switch(
            previous_provider=prev_brain, new_provider=new_brain,
            previous_model=prev_model, new_model=new_model,
            ollama_host=payload.brain.ollama_host,
            trigger="api",
        )

    brain_meta = get_brain_metadata()
    ollama_host = get_ollama_host()
    status = idp_status()
    return {
        "difficulty": get_difficulty(),
        "show_tokens": show_tokens(),
        "idp_provider": status["idp_provider"],
        "idp_degraded": status["idp_degraded"],
        "brain": {
            **brain_meta,
            "ollama_host": ollama_host,
            "ollama_model": get_ollama_model(),
            "available_providers": list(VALID_BRAIN_PROVIDERS),
            "available_models": get_available_models(
                brain_meta["provider"], ollama_host
            ),
        },
    }


@app.post("/reset")
def reset_labs() -> dict[str, object]:
    """Reset all lab state and clear the rate limiter."""
    get_registry().reset_all()
    _rate_limiter.reset()
    return {
        "reset": True,
        "tool_lab": "call counter reset to 0",
        "shadow_lab": "webhook registry cleared",
        "relay_lab": "context buffer cleared",
        "comms_lab": "outbox cleared",
    }


@app.get("/api/scenarios")
def list_scenarios() -> list[dict[str, object]]:
    """Return metadata for all loaded scenarios."""
    loader = _get_loader()
    return [
        {
            "threat_id": s.threat_id,
            "title": s.title,
            "difficulty": s.difficulty,
            "category": s.category,
            "description": s.description,
            "objectives": s.objectives,
            "hints": s.hints,
            "tools": s.tools,
            "owasp_mcp": s.owasp_mcp,
            "module_name": s.module_name,
            "agentic": s.agentic,
        }
        for s in loader.all()
    ]


class _FlagSubmission(BaseModel):
    threat_id: str = ""
    flag: str = ""


@app.post("/api/flags/verify")
def verify_submitted_flag(payload: _FlagSubmission) -> dict[str, object]:
    """Validate a submitted canary flag against the expected value."""
    correct = verify_flag(payload.threat_id, payload.flag)
    return {"threat_id": payload.threat_id, "correct": correct}


# ── Benchmarking ─────────────────────────────────────────────────────────────

class _BenchRunRequest(BaseModel):
    """Optional override for a one-off benchmark against a specific model."""

    model: str | None = None  # if set, swap model for this run then restore


@app.get("/bench/run/stream")
async def bench_run_stream(model: str | None = None) -> Response:
    """SSE stream — run all probes and emit one event per probe as it completes.

    Query params:
        model: optional model override for this run only (does not change
               the active brain model for other sessions).

    Event types: ``run_start``, ``probe_start``, ``probe_done``, ``run_complete``.
    """
    from brain_gateway.app.bench.runner import run_benchmark_stream
    from brain_gateway.app.brain.factory import get_provider, reset_provider
    from brain_gateway.app.config import get_runtime_model, set_runtime_model

    original_model: str | None = None
    if model:
        original_model = get_runtime_model()
        set_runtime_model(model)
        reset_provider()

    provider = get_provider()

    async def _events() -> AsyncIterator[dict[str, str]]:
        try:
            async for event_type, data in run_benchmark_stream(provider):
                yield {"event": event_type, "data": json.dumps(data)}
        finally:
            if model:
                set_runtime_model(original_model or "")
                reset_provider()

    return EventSourceResponse(_events())


@app.post("/bench/run")
def bench_run(payload: _BenchRunRequest | None = None) -> dict[str, object]:
    """Run the full probe suite against the current (or requested) brain model.

    Probe results and aggregate stats are stored in the in-memory bench store
    and returned immediately.  Switch the active model first via PUT /config
    or pass ``model`` here for a one-shot run without persisting the change.
    """
    from brain_gateway.app.bench.runner import run_benchmark
    from brain_gateway.app.bench.store import save_run
    from brain_gateway.app.brain.factory import get_provider, reset_provider

    override_model = payload.model if payload else None
    original_model: str | None = None

    if override_model:
        from brain_gateway.app.config import get_runtime_model, set_runtime_model
        original_model = get_runtime_model()
        set_runtime_model(override_model)
        reset_provider()

    try:
        provider = get_provider()
        run = run_benchmark(provider)
    finally:
        if override_model and original_model is not None:
            from brain_gateway.app.config import set_runtime_model
            set_runtime_model(original_model)
            reset_provider()
        elif override_model:
            from brain_gateway.app.config import reset_brain_config
            reset_brain_config()
            reset_provider()

    save_run(run)
    return run.to_dict()


@app.get("/bench/results")
def bench_results(limit: int | None = None) -> dict[str, object]:
    """Return stored benchmark runs, newest first."""
    from brain_gateway.app.bench.store import get_runs
    runs = get_runs(limit=limit)
    return {"count": len(runs), "runs": runs}


@app.get("/bench/results/latest")
def bench_latest() -> dict[str, object]:
    """Return the most recent benchmark run, or 404 if none yet."""
    from fastapi import HTTPException
    from brain_gateway.app.bench.store import get_latest
    run = get_latest()
    if run is None:
        raise HTTPException(status_code=404, detail="No benchmark runs recorded yet")
    return run


@app.get("/bench/compare")
def bench_compare(n: int = 2) -> dict[str, object]:
    """Return aggregate summaries for the last *n* runs for model comparison."""
    from brain_gateway.app.bench.store import compare_last
    summaries = compare_last(n=max(1, n))
    return {"n": len(summaries), "runs": summaries}


@app.post("/bench/quick-check")
def bench_quick_check() -> dict[str, object]:
    """Run one probe per category as a fast sanity check (e.g. after brain switch)."""
    from brain_gateway.app.bench.runner import run_quick_check
    result = run_quick_check()
    return result.to_dict()


@app.delete("/bench/results")
def bench_clear() -> dict[str, object]:
    """Clear the in-memory benchmark run store."""
    from brain_gateway.app.bench.store import clear
    clear()
    return {"cleared": True}
