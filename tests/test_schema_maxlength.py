"""Every string param in every tool must have a maxLength."""

from brain_gateway.app.modules.registry import LabRegistry


def test_all_string_params_have_maxlength():
    registry = LabRegistry()
    tools = registry.list_all_tools()
    missing = []
    for tool in tools:
        name = tool["name"]
        props = tool.get("inputSchema", {}).get("properties", {})
        for pname, pdef in props.items():
            if pdef.get("type") in (None, "string"):
                if "maxLength" not in pdef:  # pragma: no cover
                    missing.append(f"{tool['name']}.{pname}")
    assert missing == [], f"String params without maxLength: {missing}"
