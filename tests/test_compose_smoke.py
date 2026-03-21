from pathlib import Path


def test_compose_files_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    assert (root / "compose/docker-compose.yml").exists()
    assert (root / "compose/.env.example").exists()
    assert (root / "compose/profiles/starter.env").exists()
    assert (root / "compose/profiles/weird.env").exists()
    assert (root / "compose/profiles/chaotic.env").exists()


def test_frontend_files_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    assert (root / "frontend/app.py").exists()
    assert (root / "frontend/Dockerfile").exists()
    assert (root / "frontend/requirements.txt").exists()
    assert (root / "frontend/templates/base.html").exists()
    assert (root / "frontend/templates/index.html").exists()
    assert (root / "frontend/templates/playground.html").exists()
    assert (root / "frontend/templates/scenarios.html").exists()
    assert (root / "frontend/templates/observer.html").exists()


def test_observer_sidecar_files_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    assert (root / "compose/observer/main.py").exists()
    assert (root / "compose/observer/Dockerfile").exists()


def test_makefile_exists() -> None:
    root = Path(__file__).resolve().parents[1]
    assert (root / "Makefile").exists()


def test_kube_manifests_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    for name in [
        "namespace.yaml",
        "configmap.yaml",
        "secret.yaml",
        "brain-gateway.yaml",
        "portal.yaml",
        "observer.yaml",
        "ollama.yaml",
        "deploy.sh",
    ]:
        assert (root / "kube" / name).exists(), f"Missing kube/{name}"


def test_helm_chart_exists() -> None:
    root = Path(__file__).resolve().parents[1]
    helm = root / "deploy" / "helm" / "camazotz"
    assert (helm / "Chart.yaml").exists()
    assert (helm / "values.yaml").exists()
    assert (helm / "templates" / "_helpers.tpl").exists()
    for tpl in ["configmap", "secret", "brain-gateway", "portal", "observer", "ollama"]:
        assert (helm / "templates" / f"{tpl}.yaml").exists(), f"Missing template {tpl}.yaml"


def test_compose_generator_exists() -> None:
    root = Path(__file__).resolve().parents[1]
    assert (root / "deploy" / "generate-compose.py").exists()


def test_compose_generator_produces_valid_yaml() -> None:
    import yaml
    root = Path(__file__).resolve().parents[1]
    compose = root / "compose" / "docker-compose.yml"
    data = yaml.safe_load(compose.read_text(encoding="utf-8"))
    assert "services" in data
    assert "brain-gateway" in data["services"]
    assert "portal" in data["services"]
    assert "observer" in data["services"]
    assert "ollama" in data["services"]
