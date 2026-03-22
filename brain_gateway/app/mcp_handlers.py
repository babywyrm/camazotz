from brain_gateway.app.models import JsonRpcRequest
from brain_gateway.app.modules.registry import get_registry
from brain_gateway.app.observer import record_event


def handle_rpc(req: JsonRpcRequest) -> dict:
    if req.method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req.id,
            "result": {
                "protocolVersion": "2025-03-26",
                "serverInfo": {"name": "camazotz-brain-gateway", "version": "0.1.0"},
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            },
        }

    registry = get_registry()

    if req.method == "tools/list":
        return {"jsonrpc": "2.0", "id": req.id, "result": {"tools": registry.list_all_tools()}}

    if req.method == "tools/call":
        name = req.params.get("name", "")
        arguments = req.params.get("arguments", {})
        result, module_name = registry.call(name=name, arguments=arguments)
        if result is None or module_name is None:
            return {
                "jsonrpc": "2.0",
                "id": req.id,
                "error": {"code": -32602, "message": f"Unknown tool: {name}"},
            }
        record_event(tool_name=name, module=module_name)
        return {"jsonrpc": "2.0", "id": req.id, "result": result}

    return {
        "jsonrpc": "2.0",
        "id": req.id,
        "error": {"code": -32601, "message": f"Method not found: {req.method}"},
    }
