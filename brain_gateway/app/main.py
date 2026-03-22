from fastapi import FastAPI

from brain_gateway.app.config import get_difficulty, set_difficulty, show_tokens
from brain_gateway.app.mcp_handlers import handle_rpc
from brain_gateway.app.models import JsonRpcRequest
from brain_gateway.app.modules.registry import get_registry
from brain_gateway.app.observer import get_last_event

app = FastAPI(title="Camazotz Brain Gateway")


@app.post("/mcp")
def mcp_endpoint(payload: JsonRpcRequest) -> dict:
    return handle_rpc(payload)


@app.get("/_observer/last-event")
def observer_last_event() -> dict:
    return get_last_event()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "brain-gateway"}


@app.get("/config")
def get_config() -> dict:
    return {
        "difficulty": get_difficulty(),
        "show_tokens": show_tokens(),
    }


@app.put("/config")
def update_config(payload: dict) -> dict:
    if "difficulty" in payload:
        set_difficulty(payload["difficulty"])
    return {
        "difficulty": get_difficulty(),
        "show_tokens": show_tokens(),
    }


@app.post("/reset")
def reset_labs() -> dict:
    get_registry().reset_all()
    return {
        "reset": True,
        "tool_lab": "call counter reset to 0",
        "shadow_lab": "webhook registry cleared",
    }
