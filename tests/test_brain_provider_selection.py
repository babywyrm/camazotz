from unittest.mock import patch, MagicMock

import httpx

from brain_gateway.app.brain.factory import get_provider, reset_provider
from brain_gateway.app.brain.local_ollama import LocalOllamaProvider
from brain_gateway.app.config import get_ollama_host, get_ollama_model, set_difficulty, reset_difficulty


def test_default_provider_is_cloud(monkeypatch) -> None:
    reset_provider()
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = get_provider()
    assert provider.name == "cloud"
    result = provider.generate("hello")
    assert "[cloud-stub]" in result.text
    assert result.input_tokens == 0
    reset_provider()


def test_local_provider_selected(monkeypatch) -> None:
    reset_provider()
    monkeypatch.setenv("BRAIN_PROVIDER", "local")
    provider = get_provider()
    assert provider.name == "local"
    assert isinstance(provider, LocalOllamaProvider)
    reset_provider()


def test_provider_generate_accepts_system_kwarg(monkeypatch) -> None:
    reset_provider()
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = get_provider()
    result = provider.generate("test", system="custom system")
    assert "[cloud-stub]" in result.text
    reset_provider()


def test_ollama_provider_calls_api(monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://fake-ollama:11434")
    monkeypatch.setenv("CAMAZOTZ_OLLAMA_MODEL", "llama3.2:3b")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "response": "test ollama output",
        "eval_count": 42,
        "prompt_eval_count": 10,
    }
    mock_response.raise_for_status = MagicMock()

    with patch("brain_gateway.app.brain.local_ollama.httpx.post", return_value=mock_response) as mock_post:
        provider = LocalOllamaProvider()
        result = provider.generate("hello world", system="be helpful")

    mock_post.assert_called_once_with(
        "http://fake-ollama:11434/api/generate",
        json={"model": "llama3.2:3b", "prompt": "hello world", "stream": False, "system": "be helpful"},
        timeout=60.0,
    )
    assert result.text == "test ollama output"
    assert result.input_tokens == 10
    assert result.output_tokens == 42
    assert result.cost_usd == 0.0
    assert result.model == "llama3.2:3b"


def test_ollama_provider_without_system(monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://fake-ollama:11434")

    mock_response = MagicMock()
    mock_response.json.return_value = {"response": "no system", "eval_count": 5, "prompt_eval_count": 3}
    mock_response.raise_for_status = MagicMock()

    with patch("brain_gateway.app.brain.local_ollama.httpx.post", return_value=mock_response):
        provider = LocalOllamaProvider()
        result = provider.generate("test prompt")

    assert result.text == "no system"


def test_ollama_provider_unavailable_fallback(monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://fake-ollama:11434")

    with patch("brain_gateway.app.brain.local_ollama.httpx.post", side_effect=httpx.ConnectError("refused")):
        provider = LocalOllamaProvider()
        result = provider.generate("hello")

    assert "[ollama-unavailable]" in result.text
    assert "hello" in result.text


def test_config_ollama_defaults(monkeypatch) -> None:
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("CAMAZOTZ_OLLAMA_MODEL", raising=False)
    assert get_ollama_host() == "http://localhost:11434"
    assert get_ollama_model() == "llama3.2:3b"


def test_config_ollama_overrides(monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://gpu-box:11434")
    monkeypatch.setenv("CAMAZOTZ_OLLAMA_MODEL", "mistral:7b")
    assert get_ollama_host() == "http://gpu-box:11434"
    assert get_ollama_model() == "mistral:7b"


def test_set_difficulty_valid() -> None:
    reset_difficulty()
    assert set_difficulty("hard") == "hard"
    assert set_difficulty("easy") == "easy"
    assert set_difficulty("MEDIUM") == "medium"
    reset_difficulty()


def test_set_difficulty_invalid() -> None:
    reset_difficulty()
    original = set_difficulty("medium")
    result = set_difficulty("nightmare")
    assert result == "medium"
    reset_difficulty()


def test_reset_difficulty(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_DIFFICULTY", raising=False)
    set_difficulty("hard")
    from brain_gateway.app.config import get_difficulty
    assert get_difficulty() == "hard"
    reset_difficulty()
    assert get_difficulty() == "medium"


def test_shared_types_importable() -> None:
    from brain_gateway.app.types import Difficulty, ObserverEvent, UsageInfo
    from brain_gateway.app.models import ToolDefinition
    assert Difficulty.EASY == "easy"
    assert Difficulty.MEDIUM == "medium"
    assert Difficulty.HARD == "hard"
    td: ToolDefinition = {"name": "test", "description": "desc", "inputSchema": {}}
    assert td["name"] == "test"
    oe: ObserverEvent = {"request_id": "r1", "tool_name": "t1", "module": "m1", "timestamp": "ts"}
    assert oe["tool_name"] == "t1"
    ui: UsageInfo = {"input_tokens": 10, "output_tokens": 20, "cost_usd": 0.001, "model": "m"}
    assert ui["cost_usd"] == 0.001


def test_brain_result_usage_dict() -> None:
    from brain_gateway.app.brain.provider import BrainResult
    r = BrainResult(text="hi", input_tokens=10, output_tokens=20, cost_usd=0.00123456789, model="test")
    d = r.usage_dict()
    assert d["input_tokens"] == 10
    assert d["cost_usd"] == 0.001235


def test_cloud_provider_error_handling() -> None:
    from unittest.mock import patch, MagicMock
    from brain_gateway.app.brain.cloud_claude import CloudClaudeProvider

    with patch("brain_gateway.app.brain.cloud_claude.os.getenv", side_effect=lambda k, d="": "sk-fake" if k == "ANTHROPIC_API_KEY" else d):
        with patch("brain_gateway.app.brain.cloud_claude.anthropic.Anthropic") as mock_cls:
            mock_client = MagicMock()
            mock_client.messages.create.side_effect = Exception("API rate limit")
            mock_cls.return_value = mock_client
            provider = CloudClaudeProvider()
            result = provider.generate("test prompt")
    assert "[cloud-error]" in result.text


def test_redact_short_string() -> None:
    from camazotz_modules.secrets_lab.app.main import _redact
    assert _redact("short") == "****"
    assert _redact("ab") == "****"
    assert _redact("") == "****"
    assert _redact("longerthan8chars") == "long****hars"


def test_base_lab_module_abc() -> None:
    from camazotz_modules.base import LabModule
    import pytest
    with pytest.raises(TypeError):
        LabModule()


def test_registry_auto_discovery() -> None:
    from brain_gateway.app.modules.registry import get_registry, reset_registry
    reset_registry()
    registry = get_registry()
    names = {m.name for m in registry._modules}
    assert names == {"audit", "auth", "comms", "config", "context", "egress", "error", "hallucination", "indirect", "notification", "relay", "secrets", "shadow", "supply", "temporal", "tenant", "tool"}
    reset_registry()


def test_registry_reset_all() -> None:
    from brain_gateway.app.modules.registry import get_registry, reset_registry
    reset_registry()
    registry = get_registry()
    registry.register_webhook({"url": "http://test.com", "label": "test"})
    assert len(registry.list_webhooks()) == 1
    registry.reset_all()
    assert len(registry.list_webhooks()) == 0
    reset_registry()


def test_registry_middleware_pipeline() -> None:
    from brain_gateway.app.modules.registry import get_registry, reset_registry
    reset_registry()
    registry = get_registry()
    calls = []
    registry.add_middleware(lambda t, a, r, m: calls.append(t))
    registry.call("context.injectable_summary", {"text": "test"})
    assert "context.injectable_summary" in calls
    reset_registry()


def test_registry_middleware_exception_handling() -> None:
    from brain_gateway.app.modules.registry import get_registry, reset_registry
    reset_registry()
    registry = get_registry()

    def failing_mw(t, a, r, m):
        raise RuntimeError("middleware boom")

    registry.add_middleware(failing_mw)
    result, mod = registry.call("context.injectable_summary", {"text": "test"})
    assert result is not None
    reset_registry()


def test_registry_webhook_dispatch_empty_url() -> None:
    from brain_gateway.app.modules.registry import get_registry, reset_registry
    reset_registry()
    registry = get_registry()
    registry.register_webhook({"url": "", "label": "empty"})
    result, mod = registry.call("context.injectable_summary", {"text": "test"})
    assert result is not None
    reset_registry()


def test_tool_lab_subprocess_failure_fallback() -> None:
    from unittest.mock import patch, MagicMock
    from brain_gateway.app.modules.registry import get_registry, reset_registry
    reset_registry()
    registry = get_registry()

    from brain_gateway.app.config import set_difficulty, reset_difficulty
    set_difficulty("easy")
    for _ in range(7):
        registry.call("tool.mutate_behavior", {})
    with patch("camazotz_modules.tool_lab.app.main.subprocess.run", side_effect=OSError("exec failed")):
        result, _ = registry.call("tool.hidden_exec", {"command": "fail"})
    assert result is not None
    assert result["_real_output"] is False
    assert "simulated output" in result["output"]
    reset_difficulty()
    reset_registry()


def test_supply_lab_real_install_success_path(tmp_path) -> None:
    import os
    from unittest.mock import patch, MagicMock
    from camazotz_modules.supply_lab.app.main import SupplyLab

    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "mod.py").write_text("# dummy")
    (tmp_path / "setup.py").write_text("# setup")

    def fake_run(cmd, **kwargs):
        target = None
        for i, c in enumerate(cmd):
            if c == "--target" and i + 1 < len(cmd):
                target = cmd[i + 1]
        if target:
            os.makedirs(target, exist_ok=True)
            sub = os.path.join(target, "installed_pkg")
            os.makedirs(sub, exist_ok=True)
            with open(os.path.join(sub, "module.py"), "w") as f:
                f.write("# installed")
        m = MagicMock()
        m.returncode = 0
        return m

    with patch("camazotz_modules.supply_lab.app.main.subprocess.run", side_effect=fake_run):
        files = SupplyLab._real_install("requests", "pypi", False)

    assert files is not None
    assert len(files) > 0


def test_supply_lab_real_install_exception_path() -> None:
    from unittest.mock import patch
    from camazotz_modules.supply_lab.app.main import SupplyLab

    with patch("camazotz_modules.supply_lab.app.main.subprocess.run", side_effect=OSError("boom")):
        result = SupplyLab._real_install("requests", "pypi", False)
    assert result is None


def test_registry_discover_handles_bad_module() -> None:
    from unittest.mock import patch
    from brain_gateway.app.modules.registry import LabRegistry
    import pkgutil

    original_walk = pkgutil.walk_packages

    class FakeInfo:
        name = "camazotz_modules.fake_broken_lab"

    def mock_walk(*args, **kwargs):
        yield FakeInfo()
        yield from original_walk(*args, **kwargs)

    with patch("brain_gateway.app.modules.registry.pkgutil.walk_packages", side_effect=mock_walk):
        reg = LabRegistry()
    assert len(reg._modules) >= 7
