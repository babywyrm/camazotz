import os

import httpx
from flask import Flask, render_template, request, jsonify

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
def index():
    return render_template("index.html")


@app.route("/playground")
def playground():
    data = _mcp_call("tools/list")
    tools = data.get("result", {}).get("tools", [])
    return render_template("playground.html", tools=tools)


@app.route("/scenarios")
def scenarios():
    return render_template("scenarios.html")


@app.route("/observer")
def observer():
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


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "camazotz-portal"})


if __name__ == "__main__":  # pragma: no cover
    app.run(host="0.0.0.0", port=3000, debug=False)
