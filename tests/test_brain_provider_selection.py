from brain_gateway.app.brain.factory import get_provider


def test_default_provider_is_cloud(monkeypatch) -> None:
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    provider = get_provider()
    assert provider.name == "cloud"
    assert provider.generate("hello") == "[cloud] hello"


def test_local_provider_selected(monkeypatch) -> None:
    monkeypatch.setenv("BRAIN_PROVIDER", "local")
    provider = get_provider()
    assert provider.name == "local"
    assert provider.generate("hello") == "[local] hello"
