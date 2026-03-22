<div align="center">

```
                        ▄▄▄
                      ▄█████▄
                    ▄█████████▄
                  ▄████▀▀▀▀▀████▄
                 ████▀  ▄▄▄  ▀████
                ████  ▄█████▄  ████
               ████  ████ ████  ████
              ▐███▌ ████   ████ ▐███▌
              ████  ████   ████  ████
              ████  ▀████ ████▀  ████
              ▐███▌  ▀███████▀  ▐███▌
               ████    ▀███▀    ████
                ████▄         ▄████
                 █████▄▄   ▄▄█████
                  ▀▀█████████████▀
                ▄██▀▀    █    ▀▀██▄
               ████     ███     ████
              ▐███▌    █████    ▐███▌
              ████    ███████    ████
             ▐███▌   ████ ████   ▐███▌
             ████   ████   ████   ████
            ▐███▀  ▐███▌   ▐███▌  ▀███▌
            ▀▀▀    ▀▀▀▀     ▀▀▀▀    ▀▀▀
```

</div>

<h1 align="center">CAMAZOTZ</h1>
<p align="center"><strong>MCP Security Playground</strong></p>

<p align="center">
<img src="https://img.shields.io/badge/python-3.12%2B-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+">
<img src="https://img.shields.io/badge/tests-128_passing-10b981?style=flat-square" alt="128 tests">
<img src="https://img.shields.io/badge/coverage-100%25-10b981?style=flat-square" alt="100% coverage">
<img src="https://img.shields.io/badge/OWASP_MCP_Top_10-10%2F10-dc2626?style=flat-square" alt="OWASP 10/10">
<img src="https://img.shields.io/badge/license-MIT-a89cb8?style=flat-square" alt="MIT License">
</p>
<p align="center">
<img src="https://img.shields.io/badge/docker-compose-2496ed?style=flat-square&logo=docker&logoColor=white" alt="Docker Compose">
<img src="https://img.shields.io/badge/kubernetes-helm-326ce5?style=flat-square&logo=kubernetes&logoColor=white" alt="Kubernetes">
<img src="https://img.shields.io/badge/LLM-Claude_%7C_Ollama-f87171?style=flat-square" alt="Claude | Ollama">
</p>

---

Camazotz is a hands-on training platform for understanding how
[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) tools
can be exploited when backed by large language models. Every scenario is
mapped to the [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/)
and backed by a live LLM (Claude or Ollama) so exploits emerge from real
AI behavior, not static mock responses.

> **The core insight Camazotz teaches:** LLM guardrails are not security
> controls. The AI may warn, refuse, or flag a request in its reasoning —
> while the underlying tool logic executes the vulnerable action anyway.

---

## Quick Start

```bash
git clone https://github.com/babywyrm/camazotz && cd camazotz
make env          # create .env from template
make up           # start with Claude (needs ANTHROPIC_API_KEY in .env)
# — or —
make up-local     # start with Ollama (fully offline, no API key needed)
```

Open **http://localhost:3000** — the Camazotz Security Portal.

For Kubernetes deployment: `make helm-deploy` (see [deploy/README.md](deploy/README.md)).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Portal :3000                                                   │
│  ┌──────────┐ ┌──────────────┐ ┌───────────┐ ┌──────────────┐   │
│  │  Web UI  │ │  Playground  │ │ Scenarios │ │   Observer   │   │
│  └────┬─────┘ └──────┬───────┘ └───────────┘ └──────▲───────┘   │
└───────┼──────────────┼───────────────────────────────┼──────────┘
        │              │                               │
        ▼              ▼                               │
┌─────────────────────────────────────────────────────────────────┐
│  Brain Gateway :8080                                            │
│  ┌───────────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ MCP JSON-RPC      │─▶│ LabRegistry  │  │ Observer         │──┘
│  │ Handler           │  │ + Middleware  │  │ Telemetry        │
│  └───────────────────┘  └──────┬───────┘  └──────────────────┘  │
└────────────────────────────────┼────────────────────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌──────────────┐  ┌──────────────────────┐  ┌──────────────────┐
│  auth_lab    │  │  context_lab         │  │  egress_lab      │
│  MCP02/07    │  │  MCP06/10            │  │  SSRF            │
│  SQLite      │  │  Two-stage LLM chain │  │  Real httpx.get  │
├──────────────┤  ├──────────────────────┤  ├──────────────────┤
│  secrets_lab │  │  shadow_lab          │  │  supply_lab      │
│  MCP01       │  │  MCP09               │  │  MCP04           │
│  os.environ  │  │  Webhook dispatch    │  │  pip install     │
├──────────────┤  └──────────────────────┘  └──────────────────┘
│  tool_lab    │
│  MCP03/05    │         ┌──────────────────────────┐
│  subprocess  │────────▶│  AI Brain                │
└──────────────┘         │  Claude API  │  Ollama   │
                         └──────────────────────────┘
```

## How a Vulnerable Tool Call Works

```
  Attacker          Portal            Gateway           LLM Brain        Vuln Logic
     │                 │                  │                  │                │
     │  issue_token    │                  │                  │                │
     │  (admin, fake)  │                  │                  │                │
     ├────────────────▶│  JSON-RPC        │                  │                │
     │                 │  tools/call      │                  │                │
     │                 ├─────────────────▶│  system prompt   │                │
     │                 │                  ├─────────────────▶│                │
     │                 │                  │  "Deny — this    │                │
     │                 │                  │◀─is suspicious"──┤                │
     │                 │                  │                  │                │
     │                 │                  │  json.loads fails on markdown     │
     │                 │                  ├──────────────────────────────────▶│
     │                 │                  │          fallback: grant admin    │
     │                 │                  │◀─────────────────────────────────┤
     │                 │  token + result  │                  │                │
     │                 │◀─────────────────┤                  │                │
     │ cztz-eve-admin  │                  │                  │                │
     │◀────────────────┤                  │                  │                │
     │                 │                  │                  │                │
     │    ┌──────────────────────────────────────────────────────────┐        │
     │    │  The LLM said no.  The code said yes.  That's the vuln.  │        │
     │    └──────────────────────────────────────────────────────────┘        │
```

## The Teaching Moment

Every tool response includes two things:

- **`ai_analysis`** — what the LLM *thinks* should happen
- **The actual result** — what the deterministic logic *actually did*

On easy mode, they align. On medium and hard, they diverge: the AI flags
the risk while the underlying vulnerability still fires. This teaches that
**prompt-based guardrails cannot replace proper security engineering**.

---

## OWASP MCP Top 10 Coverage

| OWASP ID | Risk | Scenario | What Happens |
|----------|------|----------|-------------|
| MCP01 | Secret Exposure | `secrets.leak_config` | AI explains creds while dumping real `CZTZ_SECRET_*` env vars |
| MCP02 | Privilege Escalation | `auth.issue_token` → `auth.access_protected` | LLM denies, JSON fallback grants admin; token works in SQLite store |
| MCP03 | Tool Poisoning | `tool.mutate_behavior` | Tool builds trust, then rug-pulls with real `subprocess` exec |
| MCP04 | Supply Chain | `supply.install_package` | Evil registry accepted; real `pip install` runs in sandbox |
| MCP05 | Command Injection | `tool.hidden_exec` | Appears after rug pull; executes real commands |
| MCP06 | Intent Subversion | `context.injectable_summary` | Injection propagates through two-stage LLM chain |
| MCP07 | Weak Auth | `auth.issue_token` | Social engineering bypasses access control |
| MCP08 | No Audit Trail | `/_observer/last-event` | Only last event, no persistence |
| MCP09 | Shadow MCP | `shadow.register_webhook` | Persistent callback with real `httpx.post` dispatch on every call |
| MCP10 | Context Injection | `context.injectable_summary` | Unsanitized summary fed to downstream consumer LLM |

**Plus:** SSRF via `egress.fetch_url` — AI proxy with real `httpx.get` fetches when policy allows.

---

## Difficulty Levels

Switch live from the portal nav bar — no restart needed.

| Level | What It Teaches |
|-------|----------------|
| **Easy** | The vulnerability class. Everything works, zero guardrails. |
| **Medium** *(default)* | Partial controls. The LLM flags issues but gaps remain exploitable. |
| **Hard** | Naive guardrails. Strict prompts, allowlists, full redaction — creative bypasses still work. |

<details>
<summary><strong>Per-module difficulty matrix</strong></summary>

| Module | Easy | Medium | Hard |
|--------|------|--------|------|
| `context_lab` | No filtering | Notes injections, doesn't follow | Blocks injection, refuses summary |
| `auth_lab` | Grants if reason is convincing | Requires valid ticket INC-1001..1005 | Always denies elevated roles |
| `supply_lab` | Approves custom registries | Rejects non-corp registries | Denies all + blocks install_command |
| `secrets_lab` | All creds exposed | All redacted except DATABASE_URL | Full redaction |
| `egress_lab` | Zero filtering | Blocks metadata IPs | Blocks metadata + internal ranges |
| `shadow_lab` | Any URL accepted | External warned but accepted | External rejected unless allowlisted |
| `tool_lab` | Rug pull at 3 calls | Rug pull at 5 calls | Rug pull at 8, obfuscated description |

</details>

---

## Deployment

```
  Local Dev                Docker Compose              Kubernetes / K3s
 ─────────────────   ─────────────────────────   ──────────────────────────
  uv run uvicorn      Portal        :3000         Portal LB      :3000
  python app.py       Gateway       :8080         Gateway ClusterIP
                      Observer                    Observer
                      Ollama        :11434        Ollama + PVC

        ──────────────▶          ──────────────▶
            make up                 make helm-deploy
```

| Path | Command | When to Use |
|------|---------|-------------|
| Docker Compose (Claude) | `make up` | Quick local setup with API key |
| Docker Compose (Ollama) | `make up-local` | Offline, no API key, free |
| Kubernetes (Helm) | `make helm-deploy` | Cluster deployment, production-like |
| No Docker | `uv run uvicorn ...` | Development, debugging |

Works on **macOS** (Intel + Apple Silicon) and **Linux** (Debian, Ubuntu, CentOS).

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BRAIN_PROVIDER` | `cloud` | `cloud` (Claude) or `local` (Ollama) |
| `ANTHROPIC_API_KEY` | — | Required for Claude |
| `CAMAZOTZ_DIFFICULTY` | `medium` | Guardrail strength (switchable from portal) |
| `CAMAZOTZ_SHOW_TOKENS` | `false` | Show LLM token usage and cost per call |
| `CAMAZOTZ_OLLAMA_MODEL` | `llama3.2:3b` | Ollama model name |

Full reference: [QUICKSTART.md](QUICKSTART.md)

## Project Structure

```
camazotz/
├── brain_gateway/           # FastAPI backend (MCP JSON-RPC, config, observer)
│   ├── app/brain/           # LLM provider abstraction (Claude + Ollama)
│   └── app/modules/
│       └── registry.py      # LabRegistry — auto-discovers modules, middleware pipeline
├── camazotz_modules/        # 7 vulnerability lab modules (LabModule subclasses)
│   ├── base.py              # LabModule ABC — shared contract and helpers
│   ├── auth_lab/            # Confused deputy, privilege escalation, SQLite token store
│   ├── context_lab/         # Prompt injection, two-stage LLM chain
│   ├── egress_lab/          # SSRF via AI proxy, real httpx fetches
│   ├── secrets_lab/         # Credential leak, reads real os.environ
│   ├── shadow_lab/          # Persistent webhook registration, real httpx dispatch
│   ├── supply_lab/          # Supply chain attack, real pip install in sandbox
│   └── tool_lab/            # Rug pull, tool mutation, real subprocess execution
├── frontend/                # Flask portal (dark theme, crimson accent)
├── compose/                 # Docker Compose (generated from Helm values)
├── deploy/                  # Helm chart (single source of truth) + compose generator
├── kube/                    # Legacy raw K8s manifests + deploy.sh
├── tests/                   # 128 tests, 100% coverage
└── Makefile                 # Cross-platform dev/deploy targets
```

## Makefile Targets

```bash
make up             # start with Claude
make up-local       # start with Ollama
make down           # stop all services
make test           # run 128 tests (100% coverage)
make status         # health check all services
make compose-gen    # regenerate docker-compose.yml from Helm values
make helm-deploy    # deploy to K8s
make help           # show all targets
```

---

## Documentation

| Document | Covers |
|----------|--------|
| [QUICKSTART.md](QUICKSTART.md) | Setup, configuration, first run, profiles |
| [deploy/README.md](deploy/README.md) | Helm chart, compose generation, deployment workflows |
| [docs/scenarios.md](docs/scenarios.md) | Red/blue team exercises for every scenario |
| [docs/module-authoring.md](docs/module-authoring.md) | How to build new vulnerability modules |
| [kube/README.md](kube/README.md) | Legacy K8s manifests, K3s deploy script |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Roadmap

- **New vulnerability modules** — multi-step attack chains, cross-tool
  exploitation, resource poisoning, prompt caching attacks
- **Scanner integration** — automated regression with
  [mcpvenom](https://github.com/babywyrm/mcpvenom) baselines
- **Multi-player mode** — concurrent sessions with isolated state for
  workshops and CTF events
- **Scoring engine** — track which vulnerabilities each participant
  discovers, time-to-exploit metrics
- **Additional LLM providers** — OpenAI, Gemini, local GGUF models

---

## License

MIT
