#!/usr/bin/env python3
"""Generate docker-compose.yml from Helm values.yaml.

Usage:
    python deploy/generate-compose.py
    python deploy/generate-compose.py --values deploy/helm/camazotz/values.yaml --output compose/docker-compose.yml
"""

import argparse
from pathlib import Path

import yaml


def load_values(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def build_compose(v: dict) -> dict:
    cfg = v["config"]
    sec = v["secrets"]
    gw = v["gateway"]
    pt = v["portal"]
    ob = v["observer"]
    ol = v["ollama"]

    def env_line(key: str, val: str, compose_var: str | None = None) -> str:
        if compose_var:
            if val == "":
                return f"{key}=${{{compose_var}:-}}"
            return f"{key}=${{{compose_var}:-{val}}}"
        return f"{key}={val}"

    gateway_env = [
        env_line("BRAIN_PROVIDER", cfg["brainProvider"], "BRAIN_PROVIDER"),
        env_line("AWS_REGION", cfg.get("awsRegion", ""), "AWS_REGION"),
        env_line("AWS_PROFILE", cfg.get("awsProfile", ""), "AWS_PROFILE"),
        env_line("AWS_ACCESS_KEY_ID", cfg.get("awsAccessKeyId", ""), "AWS_ACCESS_KEY_ID"),
        env_line("AWS_SECRET_ACCESS_KEY", cfg.get("awsSecretAccessKey", ""), "AWS_SECRET_ACCESS_KEY"),
        env_line("AWS_SESSION_TOKEN", cfg.get("awsSessionToken", ""), "AWS_SESSION_TOKEN"),
        env_line("ANTHROPIC_API_KEY", sec["anthropicApiKey"], "ANTHROPIC_API_KEY"),
        env_line("CAMAZOTZ_MODEL", cfg["camazotzModel"], "CAMAZOTZ_MODEL"),
        env_line("CAMAZOTZ_BEDROCK_STUB", cfg.get("camazotzBedrockStub", ""), "CAMAZOTZ_BEDROCK_STUB"),
        env_line("CAMAZOTZ_DIFFICULTY", cfg["difficulty"], "CAMAZOTZ_DIFFICULTY"),
        env_line("CAMAZOTZ_SHOW_TOKENS", cfg["showTokens"], "CAMAZOTZ_SHOW_TOKENS"),
        env_line("OLLAMA_HOST", cfg["ollamaHost"], "OLLAMA_HOST"),
        env_line("CAMAZOTZ_OLLAMA_MODEL", cfg["ollamaModel"], "CAMAZOTZ_OLLAMA_MODEL"),
        env_line("CAMAZOTZ_FLAGS_DIR", gw.get("flagsDir", "/opt/camazotz/flags"), "CAMAZOTZ_FLAGS_DIR"),
        env_line(
            "CAMAZOTZ_MODULES_DIR",
            gw.get("modulesDir", "/workspace/camazotz_modules"),
            "CAMAZOTZ_MODULES_DIR",
        ),
        env_line("CAMAZOTZ_IDP_PROVIDER", cfg.get("idpProvider", "mock"), "CAMAZOTZ_IDP_PROVIDER"),
        env_line("CAMAZOTZ_IDP_ISSUER_URL", cfg.get("idpIssuerUrl", ""), "CAMAZOTZ_IDP_ISSUER_URL"),
        env_line("CAMAZOTZ_IDP_TOKEN_ENDPOINT", cfg.get("idpTokenEndpoint", ""), "CAMAZOTZ_IDP_TOKEN_ENDPOINT"),
        env_line(
            "CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT",
            cfg.get("idpIntrospectionEndpoint", ""),
            "CAMAZOTZ_IDP_INTROSPECTION_ENDPOINT",
        ),
        env_line(
            "CAMAZOTZ_IDP_REVOCATION_ENDPOINT",
            cfg.get("idpRevocationEndpoint", ""),
            "CAMAZOTZ_IDP_REVOCATION_ENDPOINT",
        ),
        env_line("CAMAZOTZ_IDP_CLIENT_ID", cfg.get("idpClientId", ""), "CAMAZOTZ_IDP_CLIENT_ID"),
        env_line("CAMAZOTZ_IDP_CLIENT_SECRET", sec.get("idpClientSecret", ""), "CAMAZOTZ_IDP_CLIENT_SECRET"),
    ]

    lab_secrets = v.get("labSecrets", {})
    for key, val in lab_secrets.items():
        gateway_env.append(env_line(f"CZTZ_SECRET_{key}", val))

    portal_env = [
        env_line("GATEWAY_URL", cfg["gatewayUrl"]),
        env_line("FLASK_SECRET", sec["flaskSecret"], "FLASK_SECRET"),
    ]

    observer_env = [
        env_line("GATEWAY_URL", cfg["gatewayUrl"]),
        env_line("OBSERVER_POLL_INTERVAL", cfg["observerPollInterval"], "OBSERVER_POLL_INTERVAL"),
        env_line("LOG_LEVEL", cfg["logLevel"], "LOG_LEVEL"),
    ]

    def healthcheck(port: int, path: str) -> dict:
        return {
            "test": ["CMD-SHELL", f'python3 -c "import urllib.request; urllib.request.urlopen(\'http://localhost:{port}{path}\')"'],
            "interval": "10s",
            "timeout": "5s",
            "retries": 5,
            "start_period": "5s",
        }

    services = {}

    services["portal"] = {
        "build": {"context": pt["build"]["context"], "dockerfile": pt["build"]["dockerfile"]},
        "environment": portal_env,
        "ports": [f"{pt['port']}:{pt['port']}"],
        "depends_on": {"brain-gateway": {"condition": "service_healthy"}},
        "restart": "unless-stopped",
        "healthcheck": healthcheck(pt["port"], pt["healthPath"]),
        "networks": [v["namespace"]],
    }

    services["brain-gateway"] = {
        "build": {"context": gw["build"]["context"], "dockerfile": gw["build"]["dockerfile"]},
        "environment": gateway_env,
        "volumes": [f"camazotz-flags:{gw.get('flagsDir', '/opt/camazotz/flags')}"],
        "ports": [f"{gw['port']}:{gw['port']}"],
        "depends_on": {"ollama": {"condition": "service_started", "required": False}},
        "restart": "unless-stopped",
        "healthcheck": healthcheck(gw["port"], gw["healthPath"]),
        "networks": [v["namespace"]],
    }

    services["observer"] = {
        "build": {"context": ob["build"]["context"], "dockerfile": ob["build"]["dockerfile"]},
        "environment": observer_env,
        "depends_on": {"brain-gateway": {"condition": "service_healthy"}},
        "restart": "unless-stopped",
        "networks": [v["namespace"]],
    }

    services["ollama"] = {
        "image": f"{ol['image']}:{ol['tag']}",
        "ports": [f"{ol['port']}:{ol['port']}"],
        "volumes": ["ollama-models:/root/.ollama"],
        "restart": "unless-stopped",
        "healthcheck": {
            "test": ["CMD-SHELL", f"curl -sf http://localhost:{ol['port']}{ol['healthPath']} || exit 1"],
            "interval": "10s",
            "timeout": "5s",
            "retries": 5,
            "start_period": "15s",
        },
        "profiles": ["local", "full"],
        "networks": [v["namespace"]],
    }

    services["ollama-init"] = {
        "image": f"{ol['image']}:{ol['tag']}",
        "depends_on": {"ollama": {"condition": "service_healthy"}},
        "restart": "no",
        "entrypoint": ["ollama", "pull", f"${{CAMAZOTZ_OLLAMA_MODEL:-{cfg['ollamaModel']}}}"],
        "environment": [f"OLLAMA_HOST=http://ollama:{ol['port']}"],
        "profiles": ["local", "full"],
        "networks": [v["namespace"]],
    }

    return {
        "services": services,
        "networks": {v["namespace"]: {"name": v["namespace"]}},
        "volumes": {"ollama-models": None, "camazotz-flags": None},
    }


def write_compose(data: dict, path: Path) -> None:
    header = "# Auto-generated from deploy/helm/camazotz/values.yaml\n# Regenerate: make compose-gen\n\n"
    body = yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
    path.write_text(header + body, encoding="utf-8")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Generate docker-compose.yml from Helm values")
    parser.add_argument("--values", default=str(root / "deploy/helm/camazotz/values.yaml"))
    parser.add_argument("--output", default=str(root / "compose/docker-compose.yml"))
    args = parser.parse_args()

    values = load_values(Path(args.values))
    compose = build_compose(values)
    write_compose(compose, Path(args.output))
    print(f"Generated {args.output} from {args.values}")


if __name__ == "__main__":
    main()
