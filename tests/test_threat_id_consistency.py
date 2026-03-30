"""Every module's Python threat_id must match its scenario.yaml threat_id."""

import importlib
import pkgutil
from pathlib import Path

import yaml
import pytest

import camazotz_modules
from camazotz_modules.base import LabModule


def _discover_modules(importer=importlib.import_module):
    """Yield (module_name, lab_cls, yaml_path) for every lab."""
    pkg_path = Path(camazotz_modules.__file__).parent
    for info in pkgutil.walk_packages([str(pkg_path)], prefix="camazotz_modules."):
        try:
            mod = importer(info.name)
        except Exception:
            continue
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if (
                isinstance(obj, type)
                and issubclass(obj, LabModule)
                and obj is not LabModule
                and hasattr(obj, "threat_id")
            ):
                parts = info.name.split(".")
                lab_dir = parts[1] if len(parts) > 1 else parts[0]
                yaml_path = pkg_path / lab_dir / "scenario.yaml"
                if yaml_path.exists():
                    yield lab_dir, obj, yaml_path


_MODULES = list(_discover_modules())


def test_discover_modules_skips_failed_imports():
    def always_fail(_name):
        raise ImportError("simulated import failure")

    assert list(_discover_modules(always_fail)) == []


@pytest.mark.parametrize(
    "lab_dir,lab_cls,yaml_path",
    _MODULES,
    ids=[t[0] for t in _MODULES],
)
def test_threat_id_matches_yaml(lab_dir, lab_cls, yaml_path):
    with open(yaml_path) as f:
        scenario = yaml.safe_load(f)
    yaml_tid = scenario.get("threat_id", "")
    python_tid = lab_cls.threat_id
    assert python_tid == yaml_tid, (
        f"{lab_dir}: Python threat_id={python_tid!r} != YAML threat_id={yaml_tid!r}"
    )
