from pathlib import Path


def test_compose_files_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    assert (root / "compose/docker-compose.yml").exists()
    assert (root / "compose/.env.example").exists()
    assert (root / "compose/profiles/starter.env").exists()
    assert (root / "compose/profiles/weird.env").exists()
    assert (root / "compose/profiles/chaotic.env").exists()
