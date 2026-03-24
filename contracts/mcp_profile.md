# Camazotz MCP Compliance Profile

Implements the **MCP 2025-03-26** specification with **Streamable HTTP** transport.

## Transport

| Method | Path | Behavior |
|--------|------|----------|
| POST   | `/mcp` | JSON-RPC requests → `application/json` or `text/event-stream` |
| GET    | `/mcp` | `405 Method Not Allowed` (no server-initiated messages) |
| DELETE | `/mcp` | Session termination via `Mcp-Session-Id` header |

## Supported JSON-RPC Methods

| Method         | Status | Notes                                     |
|----------------|--------|-------------------------------------------|
| `initialize`   | Full   | Returns `protocolVersion`, `serverInfo`, `capabilities`, `Mcp-Session-Id` header |
| `tools/list`   | Full   | Returns all registered tool definitions   |
| `tools/call`   | Full   | Content-block response with `isError`     |
| Notifications  | Full   | Messages with no `id` return `202 Accepted` |

## Capabilities Declared

```json
{
  "tools": { "listChanged": false }
}
```

Only `tools` is declared. No `resources` or `prompts` capability — the gateway
does not implement those methods.

## Session Management

- `initialize` returns an `Mcp-Session-Id` header (UUID v4)
- Clients may include `Mcp-Session-Id` on subsequent requests
- `DELETE /mcp` with the session header terminates the session
- Sessions are not currently enforced — omitting the header is allowed

## Accept Header Negotiation

The POST endpoint respects the `Accept` header:

- `application/json` (default) → standard JSON response
- `text/event-stream` → SSE stream with a single `message` event containing
  the JSON-RPC response

Clients that don't send an `Accept` header get `application/json`.

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
