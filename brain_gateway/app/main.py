from fastapi import FastAPI

from brain_gateway.app.mcp_handlers import handle_rpc
from brain_gateway.app.models import JsonRpcRequest
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
