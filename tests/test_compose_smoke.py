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
