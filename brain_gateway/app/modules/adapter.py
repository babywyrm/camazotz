from typing import Protocol

from camazotz_modules.auth_lab.app.main import AuthLabModule
from camazotz_modules.context_lab.app.main import ContextLabModule
from camazotz_modules.egress_lab.app.main import EgressLabModule
from camazotz_modules.secrets_lab.app.main import SecretsLabModule
from camazotz_modules.shadow_lab.app.main import ShadowLabModule
from camazotz_modules.supply_lab.app.main import SupplyLabModule
from camazotz_modules.tool_lab.app.main import ToolLabModule


class ModuleAdapter(Protocol):
    def list_tools(self) -> list[dict]:
        """Return MCP tool definitions for the module."""

    def call_tool(self, name: str, arguments: dict) -> dict | None:
        """Call a module tool if supported."""


_modules: list[ModuleAdapter] | None = None


def get_registered_modules() -> list[ModuleAdapter]:
    global _modules
    if _modules is None:
        _modules = [
            AuthLabModule(),
            ToolLabModule(),
            ContextLabModule(),
            EgressLabModule(),
            SecretsLabModule(),
            SupplyLabModule(),
            ShadowLabModule(),
        ]
    return _modules


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
