from pathlib import Path


def test_mcpvenom_regression_assets_exist() -> None:
    root = Path(__file__).resolve().parents[2]
    assert (root / "tests/regression/baselines/starter.json").exists()
