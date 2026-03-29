"""Abstract base class for all Camazotz lab modules."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from brain_gateway.app.brain.factory import get_provider
from brain_gateway.app.brain.provider import BrainResult, attach_usage
from brain_gateway.app.config import get_difficulty

if TYPE_CHECKING:
    from brain_gateway.app.brain.provider import BrainProvider


class LabModule(ABC):
    """Base class every lab extends.

    Subclasses set ``name``, ``threat_id``, ``system_prompts`` as class
    attributes and implement ``tools()`` and ``handle()``.  The base class
    provides helpers that eliminate the boilerplate previously duplicated
    across every lab (provider lookup, difficulty-keyed LLM calls, response
    building with automatic usage attachment).
    """

    name: str
    threat_id: str
    system_prompts: dict[str, str] = {}

    title: str = ""
    category: str = ""
    canary_prefix: str = "CZTZ"

    # Back-reference set by the registry after instantiation.
    _registry: Any = None

    # --- abstract contract ---------------------------------------------------

    @abstractmethod
    def tools(self) -> list[dict]:
        """Return MCP tool definitions for this module."""

    @abstractmethod
    def handle(self, name: str, arguments: dict) -> dict | None:
        """Execute a tool call.  Return ``None`` if *name* is not ours."""

    def reset(self) -> None:
        """Clear mutable instance state.  Override in stateful labs."""

    # --- convenience helpers -------------------------------------------------

    @property
    def difficulty(self) -> str:
        return get_difficulty()

    @property
    def provider(self) -> BrainProvider:
        return get_provider()

    def ask_llm(
        self,
        prompt: str,
        *,
        difficulty_key: str | None = None,
        system_override: str | None = None,
    ) -> BrainResult:
        """Call the brain provider with the system prompt for the current difficulty."""
        if system_override:
            system = system_override
        else:
            key = difficulty_key or self.difficulty
            system = self.system_prompts.get(key, next(iter(self.system_prompts.values()), ""))
        return self.provider.generate(prompt=prompt, system=system)

    def make_response(self, result: BrainResult, **data: Any) -> dict:
        """Build a response dict with ``_difficulty`` and optional ``_usage``."""
        response: dict[str, Any] = {**data, "_difficulty": self.difficulty}
        attach_usage(response, result)
        return response
