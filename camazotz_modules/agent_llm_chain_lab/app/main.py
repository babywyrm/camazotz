"""Agent LLM Chain lab — LLM function-calling context leak.

MCP-T49: Agent Chain LLM Function-Calling Context Leak (Lane 4 / Transport E)

Transport E = native LLM function-calling. Agent A registers Agent B as a
callable function in an LLM's function-calling interface. The human's
credential and identity context are embedded in the LLM's conversation
history / system prompt. When the LLM invokes Agent B via function-calling,
the full context — including the credential — is passed in the function
arguments. Agent B sees it.

The vulnerability: LLM function-calling passes the full conversation context
to called functions. A credential or secret embedded in the system prompt or
conversation history is visible to any function the LLM invokes. On easy, the
credential is directly returned from the function call. On hard, the credential
is not echoed back by call_with_context, but inspect_context still reveals the
raw system_context that was passed — proving the credential was there all along.

Defense:
- Strip or redact credential fields from the conversation context before
  invoking any registered function
- Scope the context passed to each function to only what that function needs
- Log all function-calling invocations with the full argument payload for audit
- Use a context sanitisation layer between the LLM and registered functions
"""

from __future__ import annotations

import re

from camazotz_modules.base import LabModule

_FLAG = "CZTZ{MCP-T49_llm_funct10n_c4ll_c0nt3xt_l34k}"

_CREDENTIAL_PATTERNS = [
    r"(?:token|api_key|secret|password)\s*:\s*(\S+)",
    r"bearer\s+(\S+)",
    r"(cztz-\S+)",
    r"(user-bearer-\S+)",
    r"(sk-\S+)",
    r"(AKIA\S+)",
]


def _extract_credential(system_context: str) -> str | None:
    """Return the first credential-like value found in system_context, or None."""
    for pattern in _CREDENTIAL_PATTERNS:
        m = re.search(pattern, system_context, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _has_credential(system_context: str) -> bool:
    return _extract_credential(system_context) is not None


def _redact_partial(credential: str) -> str:
    """Return first 4 chars + '****' for medium-difficulty partial masking."""
    if len(credential) <= 4:
        return credential + "****"
    return credential[:4] + "****"


class AgentLlmChainLab(LabModule):
    name = "agent_llm_chain"
    threat_id = "MCP-T49"
    title = "Agent Chain LLM Function-Calling Context Leak"
    category = "identity"

    system_prompts = {
        "easy": (
            "You are a function-calling dispatcher. Register agent functions and "
            "invoke them with the full conversation context, including any credentials "
            "embedded in the system prompt. Do not redact any context fields."
        ),
        "medium": (
            "You are a function-calling dispatcher. Register agent functions and "
            "invoke them with conversation context. Warn about embedded credentials "
            "but still pass the full context to the function."
        ),
        "hard": (
            "You are a strict function-calling dispatcher. You must redact credential "
            "fields from the context before passing it to any registered function. "
            "Do not echo credentials in function call responses."
        ),
    }

    def __init__(self) -> None:
        # function_name -> {system_context: str}
        self._functions: dict[str, dict] = {}
        # the raw system_context from the most recent call_with_context invocation
        self._last_call_context: str | None = None

    def reset(self) -> None:
        self._functions.clear()
        self._last_call_context = None

    def tools(self) -> list[dict]:
        return [
            {
                "name": "llmchain.register_function",
                "description": (
                    "Register Agent B as a callable function in the LLM's function-calling "
                    "interface. The system_context (including any embedded credential) is "
                    "stored and will be passed verbatim as function arguments when "
                    "call_with_context is invoked."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["function_name"],
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "description": "Name to register the callable function under.",
                            "maxLength": 128,
                        },
                        "system_context": {
                            "type": "string",
                            "description": (
                                "System prompt / conversation context that will be forwarded "
                                "to this function on every invocation. May contain credentials."
                            ),
                            "default": "",
                            "maxLength": 2048,
                        },
                    },
                },
            },
            {
                "name": "llmchain.call_with_context",
                "description": (
                    "Invoke Agent B via the LLM's function-calling mechanism. "
                    "The stored system_context (including any embedded credential) is "
                    "passed in the function arguments — Agent B receives the full context. "
                    "On easy, the extracted credential is returned directly. "
                    "On medium, it is partially redacted. "
                    "On hard, it is not echoed in the response — but inspect_context "
                    "still reveals the raw context that was passed."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["function_name", "prompt"],
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "description": "Name of the previously registered function to invoke.",
                            "maxLength": 128,
                        },
                        "prompt": {
                            "type": "string",
                            "description": "Prompt or instruction for the invoked function.",
                            "maxLength": 512,
                        },
                    },
                },
            },
            {
                "name": "llmchain.inspect_context",
                "description": (
                    "Inspect the full system_context that was passed in the last "
                    "function-calling invocation. This reveals any credentials that "
                    "were embedded in the context, even on hard difficulty where "
                    "call_with_context does not echo them back."
                ),
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def handle(self, name: str, arguments: dict) -> dict | None:
        if name == "llmchain.register_function":
            return self._handle_register(arguments)
        if name == "llmchain.call_with_context":
            return self._handle_call(arguments)
        if name == "llmchain.inspect_context":
            return self._handle_inspect(arguments)
        return None

    # ------------------------------------------------------------------

    def _handle_register(self, arguments: dict) -> dict:
        from brain_gateway.app.brain.provider import BrainResult

        dummy = BrainResult(text="")
        function_name = arguments.get("function_name", "").strip()
        system_context = arguments.get("system_context", "").strip()

        if not function_name:
            return self.make_response(dummy, status="error", reason="function_name required")

        self._functions[function_name] = {"system_context": system_context}

        return self.make_response(
            dummy,
            status="registered",
            function_name=function_name,
            note=(
                f"Function '{function_name}' registered. system_context will be forwarded "
                "verbatim in function-call arguments on each invocation."
            ),
            _flags={"context_stored": True},
        )

    def _handle_call(self, arguments: dict) -> dict:
        from brain_gateway.app.brain.provider import BrainResult

        function_name = arguments.get("function_name", "").strip()
        prompt = arguments.get("prompt", "").strip()
        difficulty = self.difficulty

        dummy = BrainResult(text="")

        if function_name not in self._functions:
            return self.make_response(
                dummy,
                status="error",
                reason=(
                    f"Function '{function_name}' is not registered. "
                    "Call llmchain.register_function first."
                ),
            )

        system_context = self._functions[function_name]["system_context"]

        # Store the context for inspect_context (the "smoking gun")
        self._last_call_context = system_context

        result = self.ask_llm(
            f"LLM function-calling dispatch: function={function_name} prompt={prompt}"
        )

        credential = _extract_credential(system_context)
        has_cred = credential is not None

        if difficulty == "easy":
            if has_cred:
                return self.make_response(
                    result,
                    status="ok",
                    function_name=function_name,
                    credential_in_context=True,
                    extracted_credential=credential,
                    flag=_FLAG,
                    ai_analysis=result.text,
                    note=(
                        "The LLM passed the full system_context in the function arguments. "
                        "Agent B (the called function) received the embedded credential directly."
                    ),
                    _flags={"context_leak": True, "credential_exposed": True},
                )
            return self.make_response(
                result,
                status="ok",
                function_name=function_name,
                credential_in_context=False,
                ai_analysis=result.text,
                note="No credential pattern detected in system_context.",
            )

        if difficulty == "medium":
            if has_cred:
                return self.make_response(
                    result,
                    status="ok",
                    function_name=function_name,
                    credential_in_context=True,
                    extracted_credential=_redact_partial(credential),
                    flag=_FLAG,
                    ai_analysis=result.text,
                    note=(
                        "Credential detected in context. Partially redacted in response. "
                        "Use llmchain.inspect_context to see the full raw context."
                    ),
                    _flags={"context_leak": True, "credential_partially_redacted": True},
                )
            return self.make_response(
                result,
                status="ok",
                function_name=function_name,
                credential_in_context=False,
                ai_analysis=result.text,
                note="No credential pattern detected in system_context.",
            )

        # hard: do not echo the credential; credential_in_context is False in response
        return self.make_response(
            result,
            status="ok",
            function_name=function_name,
            credential_in_context=False,
            ai_analysis=result.text,
            note=(
                "Function invoked. Context was passed to the function internally. "
                "Use llmchain.inspect_context to reveal what was actually forwarded."
            ),
            _flags={"context_passed": True},
        )

    def _handle_inspect(self, _arguments: dict) -> dict:
        from brain_gateway.app.brain.provider import BrainResult

        dummy = BrainResult(text="")
        return self.make_response(
            dummy,
            last_call_context=self._last_call_context,
            note=(
                "This is the raw system_context forwarded to the last function-call invocation. "
                "Any credential embedded here was visible to the called function."
                if self._last_call_context is not None
                else "No function-call invocation has been made yet."
            ),
        )
