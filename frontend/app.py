import os
import sys
import time

import httpx
from flask import Flask, render_template, request, jsonify

_scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "scripts")
if os.path.isdir(_scripts_dir) and _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

from qa_runner import (  # noqa: E402
    GUARDRAIL_LEVELS,
    GatewayClient,
    MODULE_TESTS,
    results_to_dict,
    run_qa,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "cztz-dev-key")

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8080")


def _mcp_call(method: str, params: dict | None = None) -> dict:
    """Send a JSON-RPC request to the brain gateway."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or {},
    }
    try:
        resp = httpx.post(f"{GATEWAY_URL}/mcp", json=payload, timeout=30.0)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {"error": {"code": -1, "message": str(exc)}}


def _observer_last() -> dict:
    try:
        resp = httpx.get(f"{GATEWAY_URL}/_observer/last-event", timeout=5.0)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError):
        return {}


@app.route("/")
def index() -> str:
    all_scenarios = _fetch_scenarios()
    tools = set()
    modules = set()
    for s in all_scenarios:
        modules.add(s.get("module_name", ""))
        for t in s.get("tools", []):
            tools.add(t)
    return render_template(
        "index.html",
        scenarios=all_scenarios,
        tool_count=len(tools),
        module_count=len(modules),
    )


@app.route("/playground")
def playground() -> str:
    data = _mcp_call("tools/list")
    tools = data.get("result", {}).get("tools", [])
    return render_template("playground.html", tools=tools)


@app.route("/scenarios")
def scenarios() -> str:
    all_scenarios = _fetch_scenarios()
    all_scenarios.sort(key=lambda s: s.get("threat_id", ""))
    return render_template("scenarios.html", scenarios=all_scenarios)


@app.route("/observer")
def observer() -> str:
    event = _observer_last()
    return render_template("observer.html", last_event=event)


@app.route("/api/tools", methods=["GET"])
def api_tools():
    data = _mcp_call("tools/list")
    return jsonify(data)


@app.route("/api/call", methods=["POST"])
def api_call():
    body = request.get_json(silent=True) or {}
    tool_name = body.get("name", "")
    arguments = body.get("arguments", {})
    if not tool_name:
        return jsonify({"error": "Missing tool name"}), 400
    data = _mcp_call("tools/call", {"name": tool_name, "arguments": arguments})
    return jsonify(data)


@app.route("/api/observer", methods=["GET"])
def api_observer():
    return jsonify(_observer_last())


@app.route("/api/config", methods=["GET"])
def api_config_get():
    try:
        resp = httpx.get(f"{GATEWAY_URL}/config", timeout=5.0)
        resp.raise_for_status()
        return jsonify(resp.json())
    except (httpx.HTTPError, ValueError):
        return jsonify({"difficulty": "medium", "show_tokens": False})


@app.route("/api/config", methods=["PUT"])
def api_config_put():
    body = request.get_json(silent=True) or {}
    try:
        resp = httpx.put(f"{GATEWAY_URL}/config", json=body, timeout=5.0)
        resp.raise_for_status()
        return jsonify(resp.json())
    except (httpx.HTTPError, ValueError):
        return jsonify({"error": "Gateway unreachable"}), 502


@app.route("/api/reset", methods=["POST"])
def api_reset():
    try:
        resp = httpx.post(f"{GATEWAY_URL}/reset", timeout=5.0)
        resp.raise_for_status()
        return jsonify(resp.json())
    except (httpx.HTTPError, ValueError):
        return jsonify({"error": "Gateway unreachable"}), 502


def _fetch_scenarios() -> list[dict]:
    try:
        resp = httpx.get(f"{GATEWAY_URL}/api/scenarios", timeout=10.0)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError):
        return []


@app.route("/challenges")
def challenges():
    scenarios = _fetch_scenarios()
    return render_template("challenges.html", scenarios=scenarios)


@app.route("/challenges/<threat_id>")
def challenge_detail(threat_id: str):
    scenarios = _fetch_scenarios()
    scenario = next((s for s in scenarios if s["threat_id"] == threat_id), None)
    if scenario is None:
        return "Challenge not found", 404
    return render_template("challenge_detail.html", scenario=scenario)


@app.route("/challenges/<threat_id>/verify", methods=["POST"])
def challenge_verify(threat_id: str):
    body = request.get_json(silent=True) or {}
    canary = body.get("canary", "")
    try:
        resp = httpx.post(
            f"{GATEWAY_URL}/api/flags/verify",
            json={"threat_id": threat_id, "flag": canary},
            timeout=5.0,
        )
        resp.raise_for_status()
        return jsonify(resp.json())
    except (httpx.HTTPError, ValueError):
        return jsonify({"correct": False, "error": "Gateway unreachable"}), 502


@app.route("/operator")
def operator():
    return render_template("operator.html", modules=list(MODULE_TESTS.keys()), levels=list(GUARDRAIL_LEVELS))


@app.route("/api/operator/run", methods=["POST"])
def api_operator_run():
    body = request.get_json(silent=True) or {}
    req_modules = body.get("modules")
    req_levels = body.get("levels")

    gw = GatewayClient(base_url=GATEWAY_URL, timeout=30)

    modules = MODULE_TESTS
    if req_modules:
        modules = {k: v for k, v in MODULE_TESTS.items() if k in req_modules}
    levels = tuple(req_levels) if req_levels else GUARDRAIL_LEVELS

    t0 = time.monotonic()
    try:
        results = run_qa(gw, levels=levels, modules=modules)
    except Exception as exc:
        return jsonify({"error": f"QA run failed: {exc}"}), 502
    elapsed = round(time.monotonic() - t0, 1)

    report = results_to_dict(results)
    report["elapsed_seconds"] = elapsed
    return jsonify(report)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "camazotz-portal"})


if __name__ == "__main__":  # pragma: no cover
    app.run(host="0.0.0.0", port=3000, debug=False)
