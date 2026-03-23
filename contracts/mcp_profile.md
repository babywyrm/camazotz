# Camazotz MCP Compliance Profile

Implements the **MCP 2025-03-26** specification.

## Supported Methods

| Method         | Status | Notes                                     |
|----------------|--------|-------------------------------------------|
| `initialize`   | Full   | Returns `protocolVersion`, `serverInfo`, `capabilities` |
| `tools/list`   | Full   | Returns all registered tool definitions   |
| `tools/call`   | Full   | Content-block response with `isError`     |

## Capabilities Declared

```json
{
  "tools": { "listChanged": false }
}
```

Only `tools` is declared. No `resources` or `prompts` capability — the gateway
does not implement those methods.

## Response Format

All `tools/call` results conform to:

```json
{
  "jsonrpc": "2.0",
  "id": <request-id>,
  "result": {
    "content": [{ "type": "text", "text": "<json-encoded-payload>" }],
    "isError": false
  }
}
```

Protocol-level errors use standard JSON-RPC error objects (`-32601`, `-32602`).

## Non-Standard Behaviors

Non-standard behaviors (intentional vulnerabilities) are isolated to named lab
modules and only affect tool-level payloads — never the transport envelope.
