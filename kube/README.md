# Kubernetes Deployment (Raw Manifests)

> **Prefer the Helm chart** at `deploy/helm/camazotz/` for new deployments.
> See [deploy/README.md](../deploy/README.md) for the unified workflow.
>
> These raw manifests and `deploy.sh` remain useful for quick K3s deploys
> where Helm isn't installed.

## Prerequisites

- K3s (or any K8s cluster with `local-path` StorageClass)
- Docker (for building images on the node)
- `kubectl` access to the cluster

## Quick Deploy

From the target node with the repo cloned to `/opt/camazotz`:

```bash
bash /opt/camazotz/kube/deploy.sh
```

This builds images, imports them into K3s containerd, and applies all manifests.

## Manual Deploy

```bash
# Build images
sudo docker build -t camazotz/brain-gateway:latest -f compose/Dockerfile .
sudo docker build -t camazotz/portal:latest -f frontend/Dockerfile frontend/
sudo docker build -t camazotz/observer:latest -f compose/observer/Dockerfile compose/observer/

# Import into K3s
sudo docker save camazotz/brain-gateway:latest | sudo k3s ctr images import -
sudo docker save camazotz/portal:latest | sudo k3s ctr images import -
sudo docker save camazotz/observer:latest | sudo k3s ctr images import -

# Apply manifests
sudo k3s kubectl apply -f kube/namespace.yaml
sudo k3s kubectl apply -f kube/configmap.yaml
sudo k3s kubectl apply -f kube/secret.yaml
sudo k3s kubectl apply -f kube/brain-gateway.yaml
sudo k3s kubectl apply -f kube/portal.yaml
sudo k3s kubectl apply -f kube/observer.yaml
```

## Set the API Key

```bash
sudo k3s kubectl -n camazotz create secret generic camazotz-secrets \
  --from-literal=ANTHROPIC_API_KEY=sk-ant-... \
  --from-literal=FLASK_SECRET=cztz-k8s-secret \
  --dry-run=client -o yaml | sudo k3s kubectl apply -f -
sudo k3s kubectl -n camazotz rollout restart deployment/brain-gateway
```

## Deploy Ollama (Optional)

```bash
sudo k3s kubectl apply -f kube/ollama.yaml
# Wait for pod, then pull the model:
sudo k3s kubectl -n camazotz exec deploy/ollama -- ollama pull llama3.2:3b
# Update configmap to use local provider:
sudo k3s kubectl -n camazotz patch configmap camazotz-config \
  -p '{"data":{"BRAIN_PROVIDER":"local"}}'
sudo k3s kubectl -n camazotz rollout restart deployment/brain-gateway
```

## Services

| Service | Type | Port | Access |
|---------|------|------|--------|
| portal | LoadBalancer | 3000 | External — the branded web UI |
| brain-gateway | ClusterIP | 8080 | Internal — MCP Streamable HTTP API |
| ollama | ClusterIP | 11434 | Internal — local LLM (optional) |

## Manifests

| File | Resource |
|------|----------|
| `namespace.yaml` | `camazotz` namespace |
| `configmap.yaml` | Non-secret configuration |
| `secret.yaml` | API keys and secrets |
| `brain-gateway.yaml` | Gateway deployment + ClusterIP service |
| `portal.yaml` | Portal deployment + LoadBalancer service |
| `observer.yaml` | Observer sidecar deployment |
| `ollama.yaml` | Ollama deployment + PVC + ClusterIP service |
| `deploy.sh` | Automated build + import + apply script |

## Teardown

```bash
sudo k3s kubectl delete namespace camazotz
```
