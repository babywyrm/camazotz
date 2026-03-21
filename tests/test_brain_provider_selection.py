from brain_gateway.app.brain.factory import get_provider, reset_provider


def test_default_provider_is_cloud(monkeypatch) -> None:
    reset_provider()
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = get_provider()
    assert provider.name == "cloud"
    result = provider.generate("hello")
    assert "[cloud-stub]" in result
    reset_provider()


def test_local_provider_selected(monkeypatch) -> None:
    reset_provider()
    monkeypatch.setenv("BRAIN_PROVIDER", "local")
    provider = get_provider()
    assert provider.name == "local"
    result = provider.generate("hello")
    assert "[local-stub]" in result
    reset_provider()


def test_provider_generate_accepts_system_kwarg(monkeypatch) -> None:
    reset_provider()
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = get_provider()
    result = provider.generate("test", system="custom system")
    assert "[cloud-stub]" in result
    reset_provider()
