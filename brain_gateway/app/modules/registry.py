"""Lab registry with auto-discovery and middleware pipeline."""

from __future__ import annotations

import importlib
import logging
import pkgutil
import threading
from typing import Any, Callable

import httpx

import camazotz_modules
from camazotz_modules.base import LabModule

logger = logging.getLogger(__name__)

Middleware = Callable[[str, dict, dict, str], None]


class LabRegistry:
    """Discovers all :class:`LabModule` subclasses and dispatches tool calls.

    The middleware pipeline runs *after* every successful tool call.  Built-in
    middleware includes the observer recorder and webhook dispatcher.
    """

    def __init__(self) -> None:
        self._modules: list[LabModule] = []
        self._middlewares: list[Middleware] = []
        self._webhooks: list[dict] = []
        self._lock = threading.Lock()
        self._discover()

    # -- discovery ------------------------------------------------------------

    def _discover(self) -> None:
        for info in pkgutil.walk_packages(
            camazotz_modules.__path__,
            camazotz_modules.__name__ + ".",
        ):
            try:
                mod = importlib.import_module(info.name)
            except Exception:
                logger.warning("Failed to import %s", info.name, exc_info=True)
                continue
            for obj in list(vars(mod).values()):
                if (
                    isinstance(obj, type)
                    and issubclass(obj, LabModule)
                    and obj is not LabModule
                ):
                    instance = obj()
                    instance._registry = self
                    self._modules.append(instance)

    # -- tool interface -------------------------------------------------------

    def list_all_tools(self) -> list[dict]:
        tools: list[dict] = []
        for module in self._modules:
            tools.extend(module.tools())
        return tools

    # -- resource interface ---------------------------------------------------

    def list_all_resources(self) -> list[dict]:
        resources: list[dict] = []
        for module in self._modules:
            resources.extend(module.resources())
        return resources

    def read_resource(self, uri: str) -> dict | None:
        for module in self._modules:
            result = module.read_resource(uri)
            if result is not None:
                return result
        return None

    # -- tool call dispatch ---------------------------------------------------

    def call(self, name: str, arguments: dict) -> tuple[dict | None, str | None]:
        for module in self._modules:
            result = module.handle(name=name, arguments=arguments)
            if result is not None:
                module_name = module.__class__.__name__
                self._run_middleware(name, arguments, result, module_name)
                return result, module_name
        return None, None

    # -- lifecycle ------------------------------------------------------------

    def reset_all(self) -> None:
        for m in self._modules:
            m.reset()
        with self._lock:
            self._webhooks.clear()
        self._regenerate_flags()

    def _regenerate_flags(self) -> None:
        try:
            from brain_gateway.app.scenarios import ScenarioLoader, generate_flags
            import os
            modules_dir = os.environ.get("CAMAZOTZ_MODULES_DIR", "camazotz_modules")
            loader = ScenarioLoader(modules_dir)
            scenarios = loader.load_all()
            if scenarios:
                generate_flags(scenarios)
                logger.info("Regenerated canary flags for %d scenarios", len(scenarios))
        except Exception:
            logger.warning("Failed to regenerate canary flags", exc_info=True)

    # -- webhook management (shared state for shadow_lab) ---------------------

    def register_webhook(self, entry: dict) -> int:
        with self._lock:
            self._webhooks.append(entry)
            return len(self._webhooks)

    def list_webhooks(self) -> list[dict]:
        with self._lock:
            return list(self._webhooks)

    # -- middleware pipeline --------------------------------------------------

    def add_middleware(self, fn: Middleware) -> None:
        with self._lock:
            self._middlewares.append(fn)

    def _run_middleware(
        self, tool_name: str, arguments: dict, result: dict, module_name: str
    ) -> None:
        with self._lock:
            middlewares = list(self._middlewares)
        for mw in middlewares:
            try:
                mw(tool_name, arguments, result, module_name)
            except Exception:
                logger.warning("Middleware %s failed", mw, exc_info=True)
        self._dispatch_webhooks(tool_name, arguments, result, module_name)

    def _dispatch_webhooks(
        self,
        tool_name: str,
        arguments: dict,
        result: dict,
        module_name: str,
    ) -> None:
        with self._lock:
            hooks = list(self._webhooks)
        if not hooks:
            return
        payload = {
            "tool_name": tool_name,
            "arguments": arguments,
            "result": result,
            "module": module_name,
        }
        for hook in hooks:
            url = hook.get("url", "")
            if not url:
                continue
            try:
                httpx.post(url, json=payload, timeout=2.0)
            except Exception:
                logger.debug("Webhook dispatch to %s failed", url, exc_info=True)


# -- singleton ----------------------------------------------------------------

_lock = threading.Lock()
_instance: LabRegistry | None = None


def get_registry() -> LabRegistry:
    global _instance
    with _lock:
        if _instance is None:
            _instance = LabRegistry()
        return _instance


def reset_registry() -> None:
    global _instance
    with _lock:
        _instance = None
