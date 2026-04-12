# NUC / Kubernetes identity runbook

This runbook assumes a Camazotz deployment via **Helm** (`deploy/helm/camazotz`), consistent with `make helm-deploy` / `make helm-deploy-local`. Adjust namespace and release name if you use custom flags.

## Defaults

- **`scripts/smoke_test.py --target k8s`** uses **`http://<K8S_HOST>:30080`** for the gateway and **`http://<K8S_HOST>:3000`** for the portal (see `SmokeTarget` in `scripts/smoke_test.py`). Map these ports on your node or load balancer to match your chart.
- Default smoke host: **`192.168.1.114`** (override per site).

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
make smoke-k8s-identity
# or explicit host:
make smoke-k8s-identity K8S_HOST=10.0.0.5
```

Smoke **with** LLM (needs working brain provider from cluster):

```bash
make smoke-k8s-llm
make smoke-k8s-llm K8S_HOST=10.0.0.5
```

## ZITADEL realism mode (cluster)

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
   make smoke-k8s-identity K8S_HOST=<your-node-ip>
   curl -s http://<your-node-ip>:30080/config   # expect idp_provider zitadel (if using default smoke NodePort)
   ```

**Scope note:** As on local Docker, cluster deployment now includes self-hosted `zitadel` + `zitadel-postgres`, but full live HTTP OAuth/OIDC integration inside gateway flows is still in progress. Current behavior combines deployed IdP infrastructure, provider selection, and realism hooks.

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

## Rollback

```bash
helm rollback camazotz -n camazotz
# or set config.idpProvider back to mock and upgrade
```

## Command reference

| Command | Purpose |
|---------|---------|
| `make smoke-k8s-identity` | K8s smoke + `GET /config` identity probe |
| `make smoke-k8s-llm` | K8s smoke + LLM probe |
| `make helm-template` | Render manifests locally for review |

See [configuration.md](configuration.md) and [deploy/README.md](../../deploy/README.md).
