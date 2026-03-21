from typing import Protocol

from camazotz_modules.auth_lab.app.main import AuthLabModule
from camazotz_modules.context_lab.app.main import ContextLabModule
from camazotz_modules.egress_lab.app.main import EgressLabModule
from camazotz_modules.tool_lab.app.main import ToolLabModule


class ModuleAdapter(Protocol):
    def list_tools(self) -> list[dict]:
        """Return MCP tool definitions for the module."""

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        """Call a module tool if supported."""


def get_registered_modules() -> list[ModuleAdapter]:
    return [AuthLabModule(), ToolLabModule(), ContextLabModule(), EgressLabModule()]


def list_all_tools() -> list[dict]:
    tools: list[dict] = []
    for module in get_registered_modules():
        tools.extend(module.list_tools())
    return tools


def call_tool_by_name(name: str, arguments: dict) -> tuple[dict | None, str | None]:
    for module in get_registered_modules():
        result = module.call_tool(name=name, arguments=arguments)
        if result is not None:
            module_name = module.__class__.__name__
            return result, module_name
    return None, None
