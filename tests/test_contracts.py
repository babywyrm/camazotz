from pathlib import Path
import json


def test_contract_files_exist_and_parse() -> None:
    root = Path(__file__).resolve().parents[1]
    for rel in [
        "contracts/mcp_profile.md",
        "contracts/module_contract.json",
        "contracts/event_schema.json",
    ]:
        path = root / rel
        assert path.exists(), f"Missing {rel}"
        if path.suffix == ".json":
            json.loads(path.read_text(encoding="utf-8"))
