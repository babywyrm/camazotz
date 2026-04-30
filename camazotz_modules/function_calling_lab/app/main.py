"""Native LLM Function-Calling Identity Erasure lab.

MCP-T35: Lane 2 (Delegated) / Transport E (Native LLM function-calling, non-MCP).

A delegated agent is wired to a model provider's native function-calling API
(OpenAI tools / Anthropic tool_use / Gemini function-calling) instead of MCP.
The model decides which function to invoke and with what arguments.

Threat surface (per ADR 0001 / Transport E):
  1. Prompt injection — user prompt steers the model toward a function call
     the user is not authorized to make
  2. Identity erasure — the function-call envelope carries no end-user
     identity; the provider sees only the agent's API key
  3. Args fidelity — without arg validation, the model's JSON output is
     dispatched verbatim

Difficulty progression:
  easy   — dispatch whatever function the model selected, with whatever args;
           no act_chain check, no arg validation
  medium — args must match a regex shape, but still no act_chain check;
           prompt injection still wins because admin-panel passes the regex
  hard   — act_chain (sub + actor) must be present and the user's scope must
           include the function's required scope before dispatch
"""

from __future__ import annotations

import re
import threading

from camazotz_modules.base import LabModule

# The "function schema" the agent registers with the model provider.  This
# mirrors what an OpenAI tools[] entry or Anthropic tool_use schema looks
# like — it's the contract the model sees when deciding which function to
# call and with what shape of args.
_TOOL_SCHEMAS: list[dict] = [
    {
        "name": "delegate_action",
        "description": "Perform an action on a named target on behalf of the user.",
        "parameters": {
            "type": "object",
            "required": ["target", "action"],
            "properties": {
                "target": {"type": "string", "maxLength": 64},
                "action": {"type": "string", "maxLength": 64},
            },
        },
        "required_scope": "delegate:write",
    },
    {
        "name": "read_status",
        "description": "Read the user's own status.  No elevated scope.",
        "parameters": {
            "type": "object",
            "required": ["user"],
            "properties": {"user": {"type": "string", "maxLength": 64}},
        },
        "required_scope": "user:read",
    },
]
_TOOLS_BY_NAME: dict[str, dict] = {t["name"]: t for t in _TOOL_SCHEMAS}

# Medium-mode arg validators per function.  Models the kind of regex-only
# defense that catches typos and obvious garbage but does NOT defend against
# semantic misuse.
_MEDIUM_VALIDATORS: dict[str, dict[str, re.Pattern[str]]] = {
    "delegate_action": {
        "target": re.compile(r"^[a-zA-Z0-9_-]{1,64}$"),
        "action": re.compile(r"^[a-zA-Z0-9_-]{1,64}$"),
    },
    "read_status": {
        "user": re.compile(r"^[a-zA-Z0-9_-]{1,64}$"),
    },
}

# What admin-panel grants when delegate_action succeeds.  This is the canary —
# its presence in the response data dict means the prompt-injection attack won
# the lab.
_ADMIN_PANEL_PAYLOAD: dict = {
    "admin_panel_token": "cztz-admin-panel-token-leaked-FAKE",
    "users": ["alice", "bob", "admin"],
    "feature_flags": {"debug_mode": True, "bypass_auth": False},
}

# A naive but deterministic "model" — extracts a function-call intent from
# the user prompt.  Real LLMs do this with much more sophistication, but
# the *vulnerability* the lab teaches doesn't depend on model capability:
# even a perfect model will follow a clear instruction in the user prompt
# unless the agent layer above defends against it.
_FN_NAME_RE = re.compile(r"\b(delegate_action|read_status)\b", re.IGNORECASE)
# Match key=value pairs.  Value may include @ . / - _ to allow tests to
# explicitly assert on regex rejections of out-of-shape garbage.
_KV_RE = re.compile(r"\b(target|action|user)=([^\s,)]+)", re.IGNORECASE)


def _extract_intent(user_prompt: str) -> dict:
    """Deterministically extract a function-call intent from a user prompt.

    Models what a real LLM would do — with the inconvenient property that
    a clear instruction in the prompt steers the call.  Tests rely on this
    determinism; a real deployment would call the model provider here.
    """
    fn_match = _FN_NAME_RE.search(user_prompt)
    if not fn_match:
        return {"function": None, "arguments": {}}

    fn = fn_match.group(1).lower()
    args: dict[str, str] = {}
    for kv in _KV_RE.finditer(user_prompt):
        key = kv.group(1).lower()
        # Last value wins if a key appears multiple times.
        args[key] = kv.group(2)

    return {"function": fn, "arguments": args}


class FunctionCallingLab(LabModule):
    name = "function_calling"
    threat_id = "MCP-T35"
    title = "Native Function-Calling Identity Erasure"
    category = "delegation"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._invocation_count = 0

    def tools(self) -> list[dict]:
        return [
            {
                "name": "function_calling.invoke",
                "description": (
                    "Submit a user prompt to the agent.  The model selects a "
                    "function from its registered tools and the agent "
                    "dispatches it.  On hard difficulty the call is rejected "
                    "unless an act_chain is supplied carrying the original "
                    "user's identity and the agent's actor token."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["user_prompt"],
                    "properties": {
                        "user_prompt": {
                            "type": "string",
                            "description": "Natural-language prompt from the user.",
                            "maxLength": 4096,
                        },
                        "act_chain": {
                            "type": "object",
                            "description": (
                                "Optional act-chain envelope.  On hard "
                                "difficulty must contain `sub` (original "
                                "user), `actor` (agent), and `scope` (list "
                                "of granted scopes)."
                            ),
                            "default": {},
                        },
                    },
                },
            },
            {
                "name": "function_calling.show_tool_schema",
                "description": (
                    "Return the function schemas registered with the model "
                    "provider.  Mirrors what OpenAI tools[] / Anthropic "
                    "tool_use exposes to the model."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "function_calling.invoke":
            return self._invoke(arguments)
        if name == "function_calling.show_tool_schema":
            return self._show_schema()
        return None

    def reset(self) -> None:
        with self._lock:
            self._invocation_count = 0

    # -- internals ------------------------------------------------------------

    def _show_schema(self) -> dict:
        return {
            "tools": _TOOL_SCHEMAS,
            "_difficulty": self.difficulty,
        }

    def _invoke(self, arguments: dict) -> dict:
        user_prompt = arguments.get("user_prompt", "")
        act_chain = arguments.get("act_chain") or {}
        difficulty = self.difficulty

        with self._lock:
            self._invocation_count += 1
            invocation_id = self._invocation_count

        # Send the prompt through the LLM for the audit log — even on stub
        # mode this gives operators something to inspect.  The dispatch
        # decision itself uses the deterministic intent extractor below so
        # the lab stays reproducible across providers.
        llm_result = self.ask_llm(user_prompt)
        intent = _extract_intent(user_prompt)

        if not intent["function"]:
            return self.make_response(
                llm_result,
                access="denied",
                reason="model did not select a registered function",
                invocation_id=invocation_id,
                _identity_envelope={
                    "envelope_carries_user_identity": False,
                    "act_chain_supplied": bool(act_chain),
                },
                _difficulty=difficulty,
            )

        fn_name = intent["function"]
        fn_args = intent["arguments"]
        schema = _TOOLS_BY_NAME.get(fn_name)

        if schema is None:
            return self.make_response(
                llm_result,
                access="denied",
                reason=f"function '{fn_name}' is not registered",
                invocation_id=invocation_id,
                _difficulty=difficulty,
            )

        # Medium: regex shape validation.  Catches typos and garbage but
        # does NOT enforce semantic policy.
        if difficulty in ("medium", "hard"):
            validators = _MEDIUM_VALIDATORS.get(fn_name, {})
            for arg_name, pattern in validators.items():
                value = fn_args.get(arg_name, "")
                if not value or not pattern.fullmatch(value):
                    return self.make_response(
                        llm_result,
                        access="denied",
                        reason=(
                            f"argument {arg_name}={value!r} failed shape "
                            f"validation ({pattern.pattern})"
                        ),
                        function=fn_name,
                        arguments=fn_args,
                        invocation_id=invocation_id,
                        _difficulty=difficulty,
                    )

        # Hard: act_chain must be present and carry the right scope.  This
        # is the only tier where end-user identity actually matters at
        # dispatch time — the threat the lab is teaching.
        if difficulty == "hard":
            required_scope = schema.get("required_scope", "")
            chain_sub = act_chain.get("sub", "")
            chain_actor = act_chain.get("actor", "")
            chain_scopes = list(act_chain.get("scope", []))
            if not chain_sub or not chain_actor:
                return self.make_response(
                    llm_result,
                    access="denied",
                    reason=(
                        "hard mode requires act_chain.sub (original user) "
                        "and act_chain.actor (agent) — function-call envelope "
                        "carries no identity by itself"
                    ),
                    function=fn_name,
                    arguments=fn_args,
                    invocation_id=invocation_id,
                    _identity_envelope={
                        "envelope_carries_user_identity": False,
                        "act_chain_supplied": False,
                    },
                    _difficulty=difficulty,
                )
            if required_scope and required_scope not in chain_scopes:
                return self.make_response(
                    llm_result,
                    access="denied",
                    reason=(
                        f"act_chain scopes {chain_scopes} do not include "
                        f"required scope '{required_scope}' for {fn_name}"
                    ),
                    function=fn_name,
                    arguments=fn_args,
                    invocation_id=invocation_id,
                    _identity_envelope={
                        "envelope_carries_user_identity": True,
                        "act_chain_supplied": True,
                        "required_scope": required_scope,
                        "supplied_scopes": chain_scopes,
                    },
                    _difficulty=difficulty,
                )

        # Dispatch.  On easy/medium the data dict reflects exactly what the
        # function returns; on hard the dispatch only happens after the act
        # chain validates.
        data = self._dispatch(fn_name, fn_args)

        return self.make_response(
            llm_result,
            access="granted",
            function=fn_name,
            arguments=fn_args,
            invocation_id=invocation_id,
            data=data,
            _identity_envelope={
                "envelope_carries_user_identity": difficulty == "hard",
                "act_chain_supplied": bool(act_chain),
                "supplied_scopes": list(act_chain.get("scope", [])),
            },
            _difficulty=difficulty,
        )

    def _dispatch(self, fn_name: str, args: dict) -> dict:
        if fn_name == "delegate_action":
            target = args.get("target", "")
            action = args.get("action", "")
            if target == "admin-panel":
                return {**_ADMIN_PANEL_PAYLOAD, "_target": target, "_action": action}
            return {
                "_target": target,
                "_action": action,
                "result": "ok",
            }
        if fn_name == "read_status":
            user = args.get("user", "anonymous")
            return {"user": user, "status": "ok", "last_seen": "2026-04-29T19:48:00Z"}
        return {}
