# Kubernetes identity runbook

This runbook assumes a Camazotz deployment via **Helm** (`deploy/helm/camazotz`), consistent with `make helm-deploy` / `make helm-deploy-local`. Adjust namespace and release name if you use custom flags.

## Defaults

- **`scripts/smoke_test.py --target k8s`** uses **`http://<K8S_HOST>:30080`** for the gateway and **`http://<K8S_HOST>:3000`** for the portal (see `SmokeTarget` in `scripts/smoke_test.py`). Map these ports on your node or load balancer to match your chart.
- `K8S_HOST` is required — no default. Set it for every smoke invocation (e.g. `K8S_HOST=10.0.0.5 make smoke-k8s`).

## Mock mode

Set `config.idpProvider: mock` if you need deterministic mode. No extra identity secrets required.

Deploy (example):

```bash
make helm-deploy
# or with Ollama:
make helm-deploy-local
```

Smoke **without** LLM (identity probe only hits `/config`):

```bash
K8S_HOST=<your-node-ip> make smoke-k8s-identity
```

Smoke **with** LLM (needs working brain provider from cluster):

```bash
K8S_HOST=<your-node-ip> make smoke-k8s-llm
```

`K8S_HOST` is required — there is no default. The script fails loudly
with guidance if you forget. This is deliberate: the repo is public, so
we refuse to ship a network default that would target a stranger's
infrastructure.

### Verify Agentic Lanes view

After every `helm upgrade` / rollout, confirm the lane view is live:

```bash
K8S_HOST=<your-node-ip> make smoke-k8s-lanes
# -> PASS lanes probe (/lanes renders)
# -> PASS lanes probe (/api/lanes schema=v1, 5 lanes, 32 labs mapped)
```

Or by hand:

```bash
curl -s http://<your-node-ip>:3000/api/lanes | python3 -m json.tool | head -20
# schema v1, five lanes, coverage gaps (the teaching artifact)
```

Browser check: `http://<your-node-ip>:3000/lanes`. The Threat Map at
`http://<your-node-ip>:3000/threat-map` must remain byte-identical — a
spec invariant; any regression there is a deploy blocker.

## ZITADEL realism mode (cluster)

**ZITADEL Console** (from cluster node): `http://localhost:8080/ui/console` or via NodePort if exposed.

For the full identity guide, see [guide.md](guide.md).

1. Edit **`deploy/helm/camazotz/values.yaml`** (or use `--set` / a values overlay):

   ```yaml
   config:
     idpProvider: zitadel
     idpIssuerUrl: "https://your-instance.example/..."
     idpTokenEndpoint: "https://your-instance.example/oauth/v2/token"
     idpIntrospectionEndpoint: "https://your-instance.example/oauth/v2/introspect"
     idpRevocationEndpoint: "https://your-instance.example/oauth/v2/revoke"
     idpClientId: "your-client-id"
   secrets:
     idpClientSecret: "your-client-secret"
   ```

2. Upgrade the release:

   ```bash
   helm upgrade --install camazotz deploy/helm/camazotz --namespace camazotz --create-namespace
   ```

3. Wait for pods ready, then:

   ```bash
   K8S_HOST=<your-node-ip> make smoke-k8s-identity
   curl -s http://<your-node-ip>:30080/config   # expect idp_provider zitadel (if using default smoke NodePort)
   ```

**Scope note:** Cluster deployment includes self-hosted `zitadel` + `zitadel-postgres` with full live HTTP OAuth/OIDC integration. The gateway performs real token exchange, introspection, and revocation calls against ZITADEL when `idpProvider: zitadel` is configured and the instance is reachable. If ZITADEL becomes unreachable, the gateway gracefully degrades to mock mode.

Fallback behavior:

- If `idpProvider: zitadel` but `idpTokenEndpoint` is empty, runtime falls back to `mock`.

## Lab env vars on Kubernetes

To mirror local `CAMAZOTZ_LAB_IDENTITY_*` injection, add equivalent env entries to the gateway deployment template or values if your fork exposes them (not all keys may be in stock `values.yaml`). Tests use these for `oauth_delegation_lab` / `rbac_lab` realism; coordinate with your chart customizations.

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|----------------|------------|
| `smoke-k8s-identity` connection refused | Wrong `K8S_HOST`, NodePort, or firewall | `kubectl get svc -n camazotz`, verify portal/gateway exposure |
| `/config` shows `mock` in cluster | `idpProvider` not updated or old pod | `helm get values camazotz -n camazotz`, rollout restart |
| Secret not mounted | `secrets.idpClientSecret` empty in chart | Set in values or external secret operator |
| `_idp_degraded: true` in tool responses | ZITADEL unreachable from cluster | Check ZITADEL pod: `kubectl -n camazotz exec deploy/zitadel -- /app/zitadel ready`; trio falls back to mock gracefully |
| `make smoke-k8s-llm` fails | Brain provider credentials missing in cluster | Set `secrets.anthropicApiKey` or Bedrock/AWS env per [deploy/README.md](../../deploy/README.md) |
| `ask_agent` returns `[cloud-stub] …` text | `ANTHROPIC_API_KEY` secret value is empty (key exists but zero bytes) | Patch and restart: see "Sync Anthropic key from local .env to NUC" below |

## Sync Anthropic key from local .env to NUC

`CloudClaudeProvider` falls back to a stub responder when `ANTHROPIC_API_KEY`
is empty. The secret can exist with zero bytes (e.g. when an earlier `kubectl
apply` carried no value), so the gateway boots cleanly but every LLM call
silently degrades. `make smoke-k8s-llm` still passes against the stub —
detect the gap by inspecting `ask_agent` output for the `[cloud-stub]`
prefix.

To sync the key from your local `compose/.env` to the NUC and restart:

```bash
KEY=$(grep "^ANTHROPIC_API_KEY=" compose/.env | cut -d= -f2)
ssh root@$K8S_HOST "sudo k3s kubectl -n camazotz patch secret camazotz-secrets \
  --type=json \
  -p='[{\"op\":\"replace\",\"path\":\"/data/ANTHROPIC_API_KEY\",\"value\":\"$(echo -n "$KEY" | base64)\"}]' \
  && sudo k3s kubectl -n camazotz rollout restart deploy/brain-gateway \
  && sudo k3s kubectl -n camazotz rollout status deploy/brain-gateway --timeout=60s"
```

Confirm with `make smoke-k8s-llm` — successful Claude responses will not
carry the `[cloud-stub]` prefix. The same key powers `mcpnuke --claude`
on the operator side, which fails loudly if the env var is unset rather
than degrading silently — keep both in sync.

## Rollback

```bash
helm rollback camazotz -n camazotz
# or set config.idpProvider back to mock and upgrade
```

## Command reference

| Command | Purpose |
|---------|---------|
| `make smoke-k8s-identity` | K8s smoke + `GET /config` identity probe (requires `K8S_HOST`) |
| `make smoke-k8s-llm` | K8s smoke + LLM probe (requires `K8S_HOST`) |
| `make smoke-k8s-lanes` | K8s smoke + `/lanes` and `/api/lanes` probe (requires `K8S_HOST`) |
| `make helm-template` | Render manifests locally for review |

See [configuration.md](configuration.md) and [deploy/README.md](../../deploy/README.md).
