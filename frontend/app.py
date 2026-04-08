import json
import os
import re
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


def _resolve_prev_refs(arguments: dict, prev_response: dict | None) -> dict:
    """Replace {{prev.<key>}} in argument values with data from previous step response."""
    if not prev_response:
        return dict(arguments)
    resolved = {}
    for k, v in arguments.items():
        if isinstance(v, str) and "{{prev." in v:

            def replacer(m, _prev=prev_response):
                key = m.group(1)
                try:
                    result = _prev.get("result", {})
                    content = result.get("content", [{}])[0].get("text", "{}")
                    parsed = json.loads(content)
                    return str(parsed.get(key, m.group(0)))
                except (json.JSONDecodeError, IndexError, KeyError, AttributeError):
                    return m.group(0)

            resolved[k] = re.sub(r"\{\{prev\.(\w+)\}\}", replacer, v)
        else:
            resolved[k] = v
    return resolved


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
    from threat_map import has_walkthrough

    all_scenarios = _fetch_scenarios()
    all_scenarios.sort(key=lambda s: s.get("threat_id", ""))
    for s in all_scenarios:
        s["has_walkthrough"] = has_walkthrough(s.get("module_name", ""))
    return render_template("scenarios.html", scenarios=all_scenarios)


@app.route("/observer")
def observer() -> str:
    event = _observer_last()
    return render_template("observer.html", last_event=event)


@app.route("/threat-map")
def threat_map() -> str:
    from threat_map import CATEGORY_COLORS, CATEGORY_GROUPS, HEX_ROWS, get_lab_category, has_walkthrough
    from qa_runner.walkthroughs import WALKTHROUGHS

    all_scenarios = _fetch_scenarios()
    scenario_map = {s["module_name"]: s for s in all_scenarios}

    rows = []
    for row_idx, row_labs in enumerate(HEX_ROWS):
        row = []
        for lab_name in row_labs:
            sc = scenario_map.get(lab_name, {})
            cat_name = get_lab_category(lab_name)
            cat_css = CATEGORY_COLORS.get(cat_name, {}).get("css", "")
            row.append({
                "name": lab_name,
                "threat_id": sc.get("threat_id", ""),
                "title": sc.get("title", lab_name.replace("_", " ").title()),
                "description": sc.get("description", ""),
                "category": cat_name,
                "cat_css": cat_css,
                "has_walkthrough": has_walkthrough(lab_name),
                "step_count": len(WALKTHROUGHS.get(lab_name, [])),
            })
        rows.append({"labs": row, "offset": row_idx % 2 == 1})

    return render_template(
        "threat_map.html",
        rows=rows,
        groups=CATEGORY_GROUPS,
        colors=CATEGORY_COLORS,
        total_labs=25,
    )


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


@app.route("/api/observer/events")
def api_observer_events():
    limit = request.args.get("limit", type=int)
    since = request.args.get("since")
    params = {}
    if limit is not None:
        params["limit"] = limit
    if since:
        params["since"] = since
    try:
        resp = httpx.get(f"{GATEWAY_URL}/_observer/events", params=params, timeout=5.0)
        resp.raise_for_status()
        return jsonify(resp.json())
    except (httpx.HTTPError, ValueError):
        return jsonify({"events": [], "buffer_size": 0, "total_recorded": 0})


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
    from threat_map import has_walkthrough

    scenarios = _fetch_scenarios()
    scenario = next((s for s in scenarios if s["threat_id"] == threat_id), None)
    if scenario is None:
        return "Challenge not found", 404
    lab_name = scenario.get("module_name", "")
    return render_template(
        "challenge_detail.html",
        scenario=scenario,
        walkthrough_available=has_walkthrough(lab_name),
        walkthrough_lab=lab_name,
    )


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
    from qa_runner.walkthroughs import WALKTHROUGHS

    scenarios = {s["module_name"]: s for s in _fetch_scenarios()}
    walkthrough_labs = []
    for lab_name, steps in sorted(
        WALKTHROUGHS.items(),
        key=lambda x: scenarios.get(x[0], {}).get("threat_id", ""),
    ):
        sc = scenarios.get(lab_name, {})
        walkthrough_labs.append({
            "lab": lab_name,
            "threat_id": sc.get("threat_id", ""),
            "title": sc.get("title", lab_name),
            "description": sc.get("description", ""),
            "step_count": len(steps),
        })
    return render_template(
        "operator.html",
        modules=list(MODULE_TESTS.keys()),
        levels=list(GUARDRAIL_LEVELS),
        walkthrough_labs=walkthrough_labs,
    )


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


@app.route("/api/operator/walkthrough/labs")
def api_walkthrough_labs():
    from qa_runner.walkthroughs import WALKTHROUGHS

    scenarios = {s["module_name"]: s for s in _fetch_scenarios()}
    labs = []
    for lab_name, steps in sorted(WALKTHROUGHS.items(), key=lambda x: scenarios.get(x[0], {}).get("threat_id", "")):
        sc = scenarios.get(lab_name, {})
        labs.append({
            "lab": lab_name,
            "threat_id": sc.get("threat_id", ""),
            "title": sc.get("title", lab_name),
            "description": sc.get("description", ""),
            "step_count": len(steps),
        })
    return jsonify(labs)


@app.route("/api/operator/walkthrough/step", methods=["POST"])
def api_walkthrough_step():
    from qa_runner.walkthroughs import WALKTHROUGHS

    body = request.get_json(silent=True) or {}
    lab = body.get("lab", "")
    step_idx = body.get("step", 0)

    if lab not in WALKTHROUGHS:
        return jsonify({"error": f"Unknown lab: {lab}"}), 400

    steps = WALKTHROUGHS[lab]
    if not isinstance(step_idx, int) or step_idx < 0 or step_idx >= len(steps):
        return jsonify({"error": f"Step {step_idx} out of range (0-{len(steps)-1})"}), 400

    step = steps[step_idx]
    prev_response = body.get("prev_response")
    resolved_arguments = _resolve_prev_refs(step.arguments, prev_response)

    if step_idx == 0:
        try:
            httpx.put(f"{GATEWAY_URL}/config", json={"difficulty": "medium"}, timeout=5)
            httpx.post(f"{GATEWAY_URL}/reset", timeout=5)
        except httpx.HTTPError:
            pass

    req_params = {"name": step.tool, "arguments": resolved_arguments}
    mcp_request = {"jsonrpc": "2.0", "id": step_idx + 1, "method": "tools/call", "params": req_params}

    try:
        resp = httpx.post(f"{GATEWAY_URL}/mcp", json=mcp_request, timeout=30)
        resp.raise_for_status()
        mcp_response = resp.json()
        status = "error" if "error" in mcp_response else "complete"
    except (httpx.HTTPError, ValueError) as exc:
        mcp_response = {"error": str(exc)}
        status = "error"

    return jsonify({
        "lab": lab,
        "step": step_idx,
        "total_steps": len(steps),
        "title": step.title,
        "narrative": step.narrative,
        "insight": step.insight,
        "request": req_params,
        "response": mcp_response,
        "status": status,
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "camazotz-portal"})


if __name__ == "__main__":  # pragma: no cover
    app.run(host="0.0.0.0", port=3000, debug=False)
