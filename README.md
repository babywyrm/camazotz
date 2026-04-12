<h1 align="center">CAMAZOTZ ..beta..</h1>
<p align="center"><strong>MCP Security Playground</strong></p>

<p align="center">
<img src="https://img.shields.io/badge/python-3.12%2B-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+">
<img src="https://img.shields.io/badge/tests-594_passing-10b981?style=flat-square" alt="594 tests">
<img src="https://img.shields.io/badge/coverage-100%25-10b981?style=flat-square" alt="100% coverage">
<img src="https://img.shields.io/badge/modules-25_labs-dc2626?style=flat-square" alt="25 labs">
<img src="https://img.shields.io/badge/Red_Team_Playbook-14%2F14-10b981?style=flat-square" alt="Playbook 14/14">
<img src="https://img.shields.io/badge/license-MIT-a89cb8?style=flat-square" alt="MIT License">
</p>
<p align="center">
<img src="https://img.shields.io/badge/docker-compose-2496ed?style=flat-square&logo=docker&logoColor=white" alt="Docker Compose">
<img src="https://img.shields.io/badge/kubernetes-helm-326ce5?style=flat-square&logo=kubernetes&logoColor=white" alt="Kubernetes">
<img src="https://img.shields.io/badge/LLM-Bedrock_%7C_Claude_API_%7C_Ollama-f87171?style=flat-square" alt="Bedrock | Claude API | Ollama">
</p>

---

Camazotz is a hands-on training platform for understanding how
[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) tools
can be exploited when backed by large language models. Every scenario is
mapped to the [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/)
and backed by a live LLM (Anthropic API or Ollama by default; optional
Amazon Bedrock via `BRAIN_PROVIDER=bedrock`) so exploits emerge from real
AI behavior, not static mock responses.

> **The core insight Camazotz teaches:** LLM guardrails are not security
> controls. The AI may warn, refuse, or flag a request in its reasoning —
> while the underlying tool logic executes the vulnerable action anyway.

---

## Quick Start

```bash
git clone https://github.com/babywyrm/camazotz && cd camazotz
make env          # create .env from template
make up           # start with Claude API (needs ANTHROPIC_API_KEY in .env)
# — or —
make up-local     # start with Ollama (fully offline, no API key needed)
# Optional: BRAIN_PROVIDER=bedrock + AWS region/credentials for Amazon Bedrock
```

Open **http://localhost:3000** — the Camazotz Security Portal.

For Kubernetes deployment: `make helm-deploy` (see [deploy/README.md](deploy/README.md)).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Portal :3000                                                   │
│  ┌──────────┐ ┌──────────────┐ ┌───────────┐ ┌──────────────┐   │
│  │  Web UI  │ │  Playground  │ │ Scenarios │ │ Threat Map   │   │
│  │  + Chall │ │              │ │ + Chall   │ │ + Observer   │   │
│  └────┬─────┘ └──────┬───────┘ └───────────┘ └──────▲───────┘   │
└───────┼──────────────┼───────────────────────────────┼──────────┘
        │              │                               │
        ▼              ▼                               │
┌─────────────────────────────────────────────────────────────────┐
│  Brain Gateway :8080                                            │
│  ┌───────────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ MCP Streamable    │─▶│ LabRegistry  │  │ Observer         │──┘
│  │ HTTP Transport    │  │ + Middleware │  │ Telemetry        │
│  └───────────────────┘  └──────┬───────┘  └──────────────────┘  │
└────────────────────────────────┼────────────────────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌──────────────┐  ┌──────────────────────┐  ┌──────────────────┐
│  auth_lab    │  │  context_lab         │  │  egress_lab      │
│  MCP02/07    │  │  MCP06/10            │  │  SSRF            │
│  MCP-T04     │  │  Two-stage LLM chain │  │  Real httpx.get  │
├──────────────┤  ├──────────────────────┤  ├──────────────────┤
│  secrets_lab │  │  shadow_lab          │  │  supply_lab      │
│  MCP01       │  │  MCP09               │  │  MCP04           │
│  os.environ  │  │  Webhook dispatch    │  │  pip install     │
├──────────────┤  ├──────────────────────┤  ├──────────────────┤
│  tool_lab    │  │  relay_lab           │  │  comms_lab       │
│  MCP03/05    │  │  MCP-T05             │  │  MCP-T12         │
│  subprocess  │  │  Context poisoning   │  │  Exfiltration    │
├──────────────┤  ├──────────────────────┤  ├──────────────────┤
│  indirect_lab│  │  config_lab          │  │ hallucination_lab│
│  MCP-T02     │  │  MCP-T09             │  │  MCP-T10         │
│  Fetched     │  │  Prompt tampering    │  │  Ambiguous input │
│  injection   │  │                      │  │  → prod data loss│
├──────────────┤  ├──────────────────────┤  ├──────────────────┤
│  tenant_lab  │  │  audit_lab           │  │  error_lab       │
│  MCP-T11     │  │  MCP-T13             │  │  MCP-T15         │
│  Memory leak │  │  Log evasion         │  │  Error leaks     │
├──────────────┤  ├──────────────────────┤  ├──────────────────┤
│  temporal_lab│  │  notification_lab    │  │  rbac_lab        │
│  MCP-T16     │  │  MCP-T17             │  │  MCP-T20         │
│  Time-of-use │  │  Notification abuse  │  │  RBAC bypass     │
├──────────────┤  ├──────────────────────┤  ├──────────────────┤
│  oauth_lab   │  │  attribution_lab     │  │  cred_broker_lab │
│  MCP-T21     │  │  MCP-T22             │  │  MCP-T23         │
│  Token replay│  │  Context forgery     │  │  Vault isolation │
├──────────────┤  ├──────────────────────┤  ├──────────────────┤
│  downgrade   │  │  delegation_chain    │  │  revocation_lab  │
│  MCP-T24     │  │  MCP-T25             │  │  MCP-T26         │
│  Pattern A→B │  │  Chain abuse         │  │  Token lifecycle │
├──────────────┤  └──────────────────────┘  └──────────────────┘
│  cost_lab    │
│  MCP-T27     │
│  LLM exhaust │
└──────────────┘
        │                                    ┌──────────────────────────┐
        └───────────────────────────────────▶│  AI Brain                │
                                             │  Bedrock │ API │ Ollama  │
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
     │                 │                  │◀─────────────────-────────────────┤
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

On EZ guardrails, they align. On MOD and MAX, they diverge: the AI flags
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

**Plus cross-tool chain attacks (MCP Red Team Playbook):**

| Playbook ID | Risk | Scenario | What Happens |
|-------------|------|----------|-------------|
| MCP-T04 | Token Audience Bypass | `auth.access_service_b` | Token scoped to service-a replayed against service-b — audience not validated |
| MCP-T05 | Cross-Tool Context Poisoning | `relay.store_context` → `relay.execute_with_context` | Poisoned tool output enters shared context buffer, LLM follows embedded instructions |
| MCP-T02 | Indirect Prompt Injection | `indirect.fetch_and_summarize` | Fetched web content overrides LLM summarization task |
| MCP-T09 | Agent Config Tampering | `config.read_system_prompt` → `config.update_system_prompt` | Attacker modifies system prompt to remove safety guards |
| MCP-T10 | Hallucination-Driven Destruction | `hallucination.execute_plan` | Ambiguous input causes LLM to destroy production data |
| MCP-T11 | Cross-Tenant Memory Leak | `tenant.recall_memory` | No tenant isolation — any caller reads any tenant's data |
| MCP-T12 | Exfiltration via Chaining | `comms.send_message` | Sensitive data from relay context exits through messaging channel — no DLP |
| MCP-T13 | Audit Log Evasion | `audit.perform_action` | All actions attributed to service account, not actual user |

**Plus:** SSRF via `egress.fetch_url` — AI proxy with real `httpx.get` fetches when policy allows.

**Plus agentic platform security labs:**

| Threat ID | Risk | Scenario | What Happens |
|-----------|------|----------|-------------|
| MCP-T20 | RBAC Bypass | `rbac.list_agents` / `rbac.trigger_agent` | Cross-team agent access via prefix matching and group override |
| MCP-T21 | OAuth Token Replay | `oauth.exchange_token` / `oauth.call_downstream` | Refresh token theft and replay across delegation flows |
| MCP-T22 | Attribution Forgery | `attribution.submit_action` | Execution context spoofing — principal and signature manipulation |
| MCP-T23 | Credential Broker Injection | `cred_broker.read_credential` | Cross-team vault access and sidecar config tampering |
| MCP-T24 | Pattern Downgrade | `downgrade.authenticate` | Force agents from OAuth delegation (Pattern A) to weaker service account (Pattern B) |
| MCP-T25 | Delegation Chain Abuse | `delegation.invoke_agent` | Unbounded agent-to-agent invocation depth with principal spoofing |
| MCP-T26 | Token Revocation Gaps | `revocation.use_token` | Cached tokens remain valid after principal revocation |
| MCP-T27 | LLM Cost Exhaustion | `cost.invoke_llm` | Quota bypass and cost misattribution via team spoofing |

---

## Guardrail Levels

The nav bar's **Guardrails** switcher controls how aggressively the LLM
defends each scenario. This is separate from the per-challenge complexity
rating (Easy / Medium / Hard) shown on challenge cards.

| Guardrail | Label | What It Teaches |
|-----------|-------|----------------|
| **EZ** (green) | Minimal defenses | The vulnerability class. Everything works, zero guardrails. |
| **MOD** *(default)* | Partial controls | The LLM flags issues but gaps remain exploitable. |
| **MAX** (red) | Strict guardrails | Strict prompts, allowlists, full redaction — creative bypasses still work. |

> **Note:** Some challenges are pure logic bugs (e.g., `tenant_lab`,
> `audit_lab`) and behave identically at all guardrail levels. The
> challenge detail page indicates whether a scenario is
> **guardrail-sensitive** or a **logic vulnerability**.

> **Gateway limits:** Per-client token-bucket rate limiting applies to
> `POST /mcp`: **EZ** has no cap, **MOD** allows 30 requests/minute, **MAX**
> allows 10/minute. Counters reset when you call **`POST /reset`** (same as
> scenario state reset).

> **Input bounds:** Every MCP tool string argument declares JSON Schema
> **`maxLength`** (256 for identifiers, 1024 for tokens, 2048 for URLs, 4096
> for free-text content). Oversized arguments are rejected at validation time.

<details>
<summary><strong>Per-module guardrail matrix</strong></summary>

| Module | EZ | MOD | MAX |
|--------|------|--------|------|
| `context_lab` | No filtering | Notes injections, doesn't follow | Blocks injection, refuses summary |
| `auth_lab` | Grants if reason is convincing | Requires valid ticket INC-1001..1005 | Always denies elevated roles |
| `supply_lab` | Approves custom registries | Rejects non-corp registries | Denies all + blocks install_command |
| `secrets_lab` | All creds exposed | All redacted except DATABASE_URL | Full redaction |
| `egress_lab` | Zero filtering | Blocks metadata IPs | Blocks metadata + internal ranges |
| `shadow_lab` | Any URL accepted | External warned but accepted | External rejected unless allowlisted |
| `tool_lab` | Rug pull at 3 calls | Rug pull at 5 calls | Rug pull at 8, obfuscated description |
| `indirect_lab` | All fetched content passed through | Notes injection presence | Blocks injection payloads |
| `config_lab` | Prompt updates accepted | Updates accepted with warning | Prompt locked, updates rejected |
| `hallucination_lab` | No environment guards | Prefers staging paths | Never touches production paths |
| `tenant_lab` | No isolation (logic bug) | No isolation (logic bug) | No isolation (logic bug) |
| `audit_lab` | Service account (logic bug) | Service account (logic bug) | Service account (logic bug) |
| `error_lab` | Stack traces exposed | Partial redaction | Generic errors only |
| `temporal_lab` | No time checks | Relaxed windows | Strict time-of-use |
| `notification_lab` | Unrestricted targets | Format validation | Allowlist + rate limit |
| `rbac_lab` | Full bypass | Prefix matching flaw | Strict group checks |
| `oauth_delegation_lab` | Raw token leak | Encoded tokens, any refresh works | Strict token validation |
| `attribution_lab` | Accept any context | Format checks only | HMAC signature required |
| `credential_broker_lab` | Cross-team vault access | Redacted but readable | Denied + scoped |
| `pattern_downgrade_lab` | Client-forced pattern | Capability override trick | Server-side enforcement |
| `delegation_chain_lab` | Unlimited depth | Depth cap, spoofable principal | Chain blocked |
| `revocation_lab` | Cached tokens survive | Refresh revoked, access persists | Immediate revocation |
| `cost_exhaustion_lab` | No quotas | Quotas, but team spoofable | Strict quotas + multiplier blocked |

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
| Docker Compose (Bedrock) | `make up` | Quick local setup with AWS credentials |
| Docker Compose (Ollama) | `make up-local` | Offline, no API key, free |
| Kubernetes (Helm) | `make helm-deploy` | Cluster deployment, production-like |
| No Docker | `uv run uvicorn ...` | Development, debugging |

Works on **macOS** (Intel + Apple Silicon) and **Linux** (Debian, Ubuntu, CentOS).

---

## Challenge Dashboard

Open **http://localhost:3000/challenges** for the PortSwigger-style challenge lab:

- **Grid view** with complexity/category filters and solve tracking
- **Per-challenge pages** with objectives, progressive hints, curl examples,
  and a guardrail-sensitivity indicator (logic bug vs. guardrail-sensitive)
- **Canary flag system** — each scenario plants a unique `CZTZ{...}` flag
- **Self-service verification** — submit flags at `/challenges/<threat_id>/verify`
- **localStorage persistence** — solved state survives browser refresh

Reset all flags: `POST /reset` or click the Reset button in the nav.

### Operator Console

Navigate to **http://localhost:3000/operator** (hidden — no nav link) for:

- **Guided Walkthrough** — pick any of the 25 labs and watch the exploit
  demonstrated step-by-step at medium guardrails. Each step shows a narrative
  explanation, the raw MCP JSON-RPC request/response (expandable), and a
  security insight callout. Auto-play with pause/step controls.
- **QA Dashboard** — batch pass/fail grid across all modules and guardrail
  levels. Useful for validating platform health after deployment.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BRAIN_PROVIDER` | `cloud` | `cloud` (Anthropic API), `bedrock` (Claude on Amazon Bedrock), or `local` (Ollama) |
| `AWS_REGION` | — | Region for Bedrock when `BRAIN_PROVIDER=bedrock` |
| `AWS_PROFILE` | — | Optional named AWS profile (host-only; containers do not read `~/.aws` by default) |
| `AWS_ACCESS_KEY_ID` | — | AWS access key — often required in Docker unless using an IAM role on the host |
| `AWS_SECRET_ACCESS_KEY` | — | AWS secret key — required with access key for static credentials |
| `AWS_SESSION_TOKEN` | — | Session token for temporary credentials (SSO / assume-role) |
| `CAMAZOTZ_MODEL` | — | Model or inference profile id for Bedrock; also used for Anthropic API when set |
| `CAMAZOTZ_BEDROCK_MODEL` | — | Optional override for Bedrock only (takes precedence over `CAMAZOTZ_MODEL`) |
| `CAMAZOTZ_BEDROCK_STUB` | — | Set `1` for offline Bedrock stub (`[bedrock-stub]`) without AWS credentials |
| `ANTHROPIC_API_KEY` | — | Required when `BRAIN_PROVIDER=cloud` |
| `CAMAZOTZ_DIFFICULTY` | `medium` | Guardrail level: EZ / MOD / MAX (switchable from portal) |
| `CAMAZOTZ_SHOW_TOKENS` | `false` | Show LLM token usage and cost per call |
| `CAMAZOTZ_OLLAMA_MODEL` | `llama3.2:3b` | Ollama model name |
| `CAMAZOTZ_IDP_PROVIDER` | `zitadel` (deployment), `mock` (runtime fallback) | Identity mode: `mock` or `zitadel`. In `zitadel` mode, IDP-backed trio labs (`oauth_delegation`, `revocation`, `rbac`) use live HTTP token/introspect/revoke calls with graceful degradation. Falls back to `mock` if ZITADEL config is incomplete. See [docs/identity/overview.md](docs/identity/overview.md). |

### How Bedrock credentials reach the container

```
  Operator                  compose/.env              brain-gateway container        Bedrock
     │                           │                           │                         │
     │  Option 1: .env file      │                           │                         │
     │  AWS_ACCESS_KEY_ID=...    │                           │                         │
     │  AWS_SECRET_ACCESS_KEY=...│                           │                         │
     │──────────────────────────▶│  docker compose reads     │                         │
     │                           │──────────────────────────▶│  boto3.Session()        │
     │                           │                           │──────────────────────────▶
     │                           │                           │  AnthropicBedrock(      │
     │                           │                           │    aws_region=...)      │
     │                           │                           │                         │
     │  Option 2: IAM role       │                           │                         │
     │  (EC2/ECS/EKS)            │  (no keys in .env)        │                         │
     │                           │                           │  boto3 auto-discovers   │
     │                           │                           │──────────────────────────▶
     │                           │                           │                         │
     │  Option 3: Stub mode      │                           │                         │
     │  CAMAZOTZ_BEDROCK_STUB=1  │                           │  returns [bedrock-stub] │
     │                           │                           │  (no AWS calls)         │
```

| Credential method | Where to set | Best for |
|-------------------|-------------|----------|
| `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` in `.env` | `compose/.env` | Local Docker development with IAM user or temporary credentials |
| `aws configure export-credentials --format env` piped to `.env` | Shell → `.env` | SSO/assume-role credentials (short-lived, refresh as needed) |
| IAM instance profile / IRSA / ECS task role | Infrastructure | EC2, EKS, ECS — no keys needed, boto3 auto-discovers |
| `CAMAZOTZ_BEDROCK_STUB=1` | `compose/.env` or shell | Offline testing, CI, demos without AWS |
| No Docker (`uv run uvicorn ...`) | Shell env or `~/.aws` | Local development — boto3 reads `~/.aws/credentials` directly |

> **Important:** `AWS_PROFILE` works for local development without Docker
> (where boto3 reads `~/.aws/config`), but Docker containers don't mount
> your home directory. For Docker, use explicit key/secret or IAM roles.

Example (adjust for your account):

```bash
export AWS_REGION=us-east-1
export AWS_PROFILE=your-named-profile
export CAMAZOTZ_MODEL=<your-bedrock-model-or-inference-profile-id>
```

Full reference: [QUICKSTART.md](QUICKSTART.md)

## Project Structure

```
camazotz/
├── brain_gateway/           # FastAPI backend (MCP JSON-RPC, config, observer)
│   ├── app/brain/           # LLM provider abstraction (Anthropic API, Bedrock, Ollama)
│   └── app/modules/
│       └── registry.py      # LabRegistry — auto-discovers modules, middleware pipeline
├── camazotz_modules/        # 25 vulnerability lab modules (LabModule subclasses)
│   ├── base.py              # LabModule ABC — shared contract and helpers
│   ├── audit_lab/           # Audit log evasion, service account attribution (MCP-T13)
│   ├── auth_lab/            # Confused deputy, privilege escalation, audience bypass
│   ├── attribution_lab/     # Execution context forgery, principal spoofing (MCP-T22)
│   ├── comms_lab/           # Exfiltration via messaging channel (MCP-T12)
│   ├── config_lab/          # Agent config tampering, system prompt modification (MCP-T09)
│   ├── context_lab/         # Prompt injection, two-stage LLM chain
│   ├── cost_exhaustion_lab/ # LLM cost exhaustion, quota bypass (MCP-T27)
│   ├── credential_broker_lab/ # Vault isolation, sidecar tampering (MCP-T23)
│   ├── delegation_chain_lab/  # Agent-to-agent chain abuse (MCP-T25)
│   ├── egress_lab/          # SSRF via AI proxy, real httpx fetches
│   ├── error_lab/           # Error handling leaks (MCP-T15)
│   ├── hallucination_lab/   # Hallucination-driven destruction of prod data (MCP-T10)
│   ├── indirect_lab/        # Indirect prompt injection via fetched content (MCP-T02)
│   ├── notification_lab/    # Notification abuse (MCP-T17)
│   ├── oauth_delegation_lab/  # OAuth token theft and replay (MCP-T21)
│   ├── pattern_downgrade_lab/ # Auth pattern downgrade A→B (MCP-T24)
│   ├── rbac_lab/            # RBAC boundary bypass, cross-team access (MCP-T20)
│   ├── relay_lab/           # Cross-tool context poisoning broker (MCP-T05)
│   ├── revocation_lab/      # Token revocation gaps (MCP-T26)
│   ├── secrets_lab/         # Credential leak, reads real os.environ
│   ├── shadow_lab/          # Persistent webhook registration, real httpx dispatch
│   ├── supply_lab/          # Supply chain attack, real pip install in sandbox
│   ├── temporal_lab/        # Time-of-use vulnerabilities (MCP-T16)
│   ├── tenant_lab/          # Cross-tenant memory leak, no isolation (MCP-T11)
│   └── tool_lab/            # Rug pull, tool mutation, real subprocess execution
├── frontend/                # Flask portal (dark theme, crimson accent)
├── compose/                 # Docker Compose (generated from Helm values)
├── deploy/                  # Helm chart (single source of truth) + compose generator
├── kube/                    # Legacy raw K8s manifests + deploy.sh
├── scripts/
│   ├── qa_harness.py        # CLI entry point for E2E QA
│   └── qa_runner/            # Reusable QA engine (shared by CLI + operator panel)
├── tests/                   # 594 tests, 100% coverage
└── Makefile                 # Cross-platform dev/deploy targets
```

## Makefile Targets

```bash
make up             # start with Claude
make up-local       # start with Ollama
make down           # stop all services
make test           # run 594 tests (100% coverage)
make qa             # E2E QA harness against live gateway
make qa-json        # QA harness with machine-readable JSON output
make smoke-local    # smoke test local Docker Compose target
make smoke-k8s      # smoke test k8s target (K8S_HOST=192.168.1.114)
make smoke-local-llm  # smoke test local + LLM probe
make smoke-k8s-llm    # smoke test k8s + LLM probe
make smoke-local-identity   # local smoke + GET /config idp_provider probe
make smoke-k8s-identity     # k8s smoke + GET /config idp_provider probe
make status         # health check all services
make compose-gen    # regenerate docker-compose.yml from Helm values
make helm-deploy    # deploy to K8s
make help           # show all targets
```

---

## Documentation

| Document | Covers |
|----------|--------|
| [docs/identity/overview.md](docs/identity/overview.md) | Identity architecture: mock vs `zitadel` realism, trust boundaries, smoke probes |
| [docs/identity/configuration.md](docs/identity/configuration.md) | `CAMAZOTZ_IDP_*` env vars, Helm values, lab injection helpers |
| [docs/identity/local-runbook.md](docs/identity/local-runbook.md) | Docker Compose identity mode, commands, troubleshooting |
| [docs/identity/nuc-runbook.md](docs/identity/nuc-runbook.md) | Kubernetes / NUC Helm identity mode, smoke commands, rollback |
| [QUICKSTART.md](QUICKSTART.md) | Setup, configuration, first run, profiles |
| [deploy/README.md](deploy/README.md) | Helm chart, compose generation, deployment workflows |
| [docs/scenarios.md](docs/scenarios.md) | Red/blue team exercises for every scenario |
| [docs/module-authoring.md](docs/module-authoring.md) | How to build new vulnerability modules |
| [kube/README.md](kube/README.md) | Legacy K8s manifests, K3s deploy script |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Roadmap

### Near-term

- **CI/CD pipeline** — GitHub Actions running `pytest` + `make smoke-local`
  on every PR; nightly `smoke-local-llm` with Claude key as secret
- **EZ/MAX walkthrough guardrails** — extend guided walkthroughs beyond
  medium to show how the same exploit changes across all three levels
- **Progress dashboard** — server-side solve tracking with per-user state

### Medium-term

- **mcpnuke integration** — automated
  [mcpnuke](https://github.com/babywyrm/mcpnuke) scan → walkthrough
  correlation; regression baselines per release
- **Workshop mode** — timed walkthroughs with completion tracking for
  instructor-led sessions and CTF events
- **Behavioral validation** — observer detects exploit patterns automatically
- **Additional lab modules** — pending ongoing MCP security research

### Longer-term

- **Multi-player mode** — concurrent sessions with isolated state
- **Scoring engine** — track which vulnerabilities each participant
  discovers, time-to-exploit metrics
- **Additional LLM providers** — OpenAI, Gemini, local GGUF models

### Completed (recent)

- **Threat Map** — `/threat-map` page with 7 category groups, 25 lab
  cards, localStorage-based progress tracking, and contextual walkthrough
  links from challenges and scenarios
- **Observer signal tiers** — `signal_tier`, `reason_code`, tighter
  confused-deputy detection, signal filter in Enhanced tab
- **QA checks for all 25 labs** — 25/25 labs covered in QA harness
- **Operator Console** — guided walkthroughs for all 25 labs at medium
  guardrails with telemetry strip

---

## License

MIT
