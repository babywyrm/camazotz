#!/usr/bin/env bash
set -euo pipefail

# Camazotz K8s deploy script for K3s
# Run on the target node: bash /opt/camazotz/kube/deploy.sh

REPO_DIR="/opt/camazotz"
KUBE_DIR="${REPO_DIR}/kube"
K="sudo k3s kubectl"
NS="camazotz"

echo "=== Camazotz K8s Deploy ==="
echo "  repo: ${REPO_DIR}"
echo "  node: $(hostname)"
echo ""

cd "${REPO_DIR}"

# Build container images with Docker
echo "[1/5] Building container images..."
sudo docker build -t camazotz/brain-gateway:latest -f compose/Dockerfile .
sudo docker build -t camazotz/portal:latest -f frontend/Dockerfile .
sudo docker build -t camazotz/observer:latest -f compose/observer/Dockerfile compose/observer/

# Import images into K3s containerd
echo "[2/5] Importing images into K3s..."
sudo docker save camazotz/brain-gateway:latest | sudo k3s ctr images import -
sudo docker save camazotz/portal:latest | sudo k3s ctr images import -
sudo docker save camazotz/observer:latest | sudo k3s ctr images import -

# Apply manifests
echo "[3/5] Applying K8s manifests..."
$K apply -f "${KUBE_DIR}/namespace.yaml"
$K apply -f "${KUBE_DIR}/configmap.yaml"
$K apply -f "${KUBE_DIR}/secret.yaml"
$K apply -f "${KUBE_DIR}/zitadel-postgres.yaml"
$K apply -f "${KUBE_DIR}/zitadel.yaml"
$K apply -f "${KUBE_DIR}/brain-gateway.yaml"
$K apply -f "${KUBE_DIR}/portal.yaml"
$K apply -f "${KUBE_DIR}/observer.yaml"

echo "[4/6] Waiting for zitadel to be ready..."
$K -n "${NS}" rollout status deployment/zitadel-postgres --timeout=120s
$K -n "${NS}" rollout status deployment/zitadel --timeout=180s

echo "[5/6] Waiting for brain-gateway to be ready..."
$K -n "${NS}" rollout status deployment/brain-gateway --timeout=60s

echo "[6/6] Waiting for portal to be ready..."
$K -n "${NS}" rollout status deployment/portal --timeout=60s

echo ""
echo "=== Deploy complete ==="
$K -n "${NS}" get pods -o wide
echo ""
$K -n "${NS}" get svc
echo ""

PORTAL_IP=$($K -n "${NS}" get svc portal -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
echo "  Portal: http://${PORTAL_IP}"
echo "  Gateway: ClusterIP (internal to cluster)"
echo ""
echo "To deploy Ollama (optional):"
echo "  $K apply -f ${KUBE_DIR}/ollama.yaml"
echo "  $K -n ${NS} exec deploy/ollama -- ollama pull llama3.2:3b"
echo ""
echo "To configure Bedrock (default):"
echo "  $K -n ${NS} patch configmap camazotz-config \\"
echo "    -p '{\"data\":{\"AWS_REGION\":\"us-east-1\",\"CAMAZOTZ_MODEL\":\"<your-model-id>\"}}'"
echo "  $K -n ${NS} rollout restart deployment/brain-gateway"
echo ""
echo "For direct Anthropic API (BRAIN_PROVIDER=cloud):"
echo "  $K -n ${NS} create secret generic camazotz-secrets \\"
echo "    --from-literal=ANTHROPIC_API_KEY=sk-ant-... \\"
echo "    --from-literal=FLASK_SECRET=cztz-k8s-secret \\"
echo "    --dry-run=client -o yaml | $K apply -f -"
echo "  $K -n ${NS} rollout restart deployment/brain-gateway"
