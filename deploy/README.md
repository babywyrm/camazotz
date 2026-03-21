# Deployment & Configuration

Camazotz uses a **Helm chart as the single source of truth** for all
deployment configuration. Docker Compose is a generated artifact derived
from the same Helm values.

## Architecture

```
deploy/
  helm/camazotz/
    values.yaml         <-- single source of truth
    Chart.yaml
    templates/*.yaml    <-- K8s resource templates
  generate-compose.py   <-- reads values.yaml, writes docker-compose.yml

compose/
  docker-compose.yml    <-- GENERATED (do not edit directly)
  Dockerfile            <-- brain-gateway image (shared by both paths)
  observer/             <-- observer image (shared by both paths)

frontend/
  Dockerfile            <-- portal image (shared by both paths)
```

## Developer workflow: I changed a scenario

When you modify module code (add a tool, change a lab, etc.):

### Docker Compose (local dev)

```bash
# 1. Make your code changes
# 2. Run tests
make test

# 3. Rebuild and restart
make down && make up
```

No config changes needed — Compose rebuilds images from source.

### Kubernetes (NUC / cluster)

```bash
# 1. Make your code changes
# 2. Run tests locally
make test

# 3. On the target node, pull changes and rebuild images
cd /opt/camazotz && git pull
sudo docker build -t camazotz/brain-gateway:latest -f compose/Dockerfile .
sudo docker build -t camazotz/portal:latest -f frontend/Dockerfile frontend/
sudo docker build -t camazotz/observer:latest -f compose/observer/Dockerfile compose/observer/

# 4. Import into K3s
sudo docker save camazotz/brain-gateway:latest | sudo k3s ctr images import -
sudo docker save camazotz/portal:latest | sudo k3s ctr images import -
sudo docker save camazotz/observer:latest | sudo k3s ctr images import -

# 5. Restart deployments to pick up new images
sudo k3s kubectl -n camazotz rollout restart deployment/brain-gateway
sudo k3s kubectl -n camazotz rollout restart deployment/portal
sudo k3s kubectl -n camazotz rollout restart deployment/observer
```

Or use the deploy script which does steps 3-5:

```bash
bash /opt/camazotz/kube/deploy.sh
```

## Developer workflow: I changed deployment config

When you modify ports, env vars, resource limits, add a new service, etc.:

### 1. Edit the Helm values (the source of truth)

```bash
# Edit deploy/helm/camazotz/values.yaml
```

### 2. Regenerate Docker Compose

```bash
make compose-gen
```

This reads `values.yaml` and writes `compose/docker-compose.yml`.

### 3. Deploy

**Docker Compose:**

```bash
make down && make up
```

**Kubernetes (Helm):**

```bash
make helm-deploy
# Or with Ollama:
make helm-deploy-local
```

**Kubernetes (NUC, no local Helm):**

```bash
# Copy updated chart to NUC, then:
sudo helm upgrade --install camazotz /opt/camazotz/deploy/helm/camazotz \
  --namespace camazotz \
  --set secrets.anthropicApiKey=sk-ant-...
```

## Developer workflow: I added a new module

1. Create the module under `camazotz_modules/your_lab/`
2. Register it in `brain_gateway/app/modules/adapter.py`
3. Add tests, verify 100% coverage
4. If the module needs new env vars:
   - Add them to `deploy/helm/camazotz/values.yaml` under `config:`
   - Add them to the ConfigMap template if needed
   - Run `make compose-gen` to update docker-compose.yml
5. If the module needs a new container (rare):
   - Add a new section in `values.yaml`
   - Create a Helm template in `deploy/helm/camazotz/templates/`
   - Run `make compose-gen` to update docker-compose.yml
6. Deploy using either path above

## Makefile targets

| Target | What it does |
|--------|-------------|
| `make compose-gen` | Regenerate docker-compose.yml from Helm values |
| `make helm-template` | Render Helm templates to stdout (dry-run) |
| `make helm-deploy` | Deploy to K8s via Helm (cloud mode) |
| `make helm-deploy-local` | Deploy to K8s with Ollama enabled |
| `make up` | Start Docker Compose (cloud mode) |
| `make up-local` | Start Docker Compose with Ollama |
| `make down` | Stop all services |
| `make test` | Run pytest with 100% coverage |

## Key principle

**Never edit `compose/docker-compose.yml` directly.** It is a generated
file. All deployment configuration lives in `deploy/helm/camazotz/values.yaml`.
The Dockerfiles and application code are shared by both deployment paths.
