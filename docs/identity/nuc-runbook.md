# NUC / Kubernetes Identity Runbook

## Prerequisites

- Helm 3+, `kubectl` configured for your cluster
- ZITADEL project created with a service account / machine user
- Client ID and Client Secret available

## Deploy in mock mode (default)

```bash
helm upgrade --install camazotz deploy/helm/camazotz \
  --namespace camazotz --create-namespace
```

Verify:
```bash
curl -s http://<K8S_HOST>:30080/config | jq .idp_provider
# → "mock"
```

## Deploy in ZITADEL realism mode

```bash
helm upgrade --install camazotz deploy/helm/camazotz \
  --namespace camazotz --create-namespace \
  --set config.idpProvider=zitadel \
  --set config.idpIssuerUrl=https://my-project.zitadel.cloud \
  --set config.idpTokenEndpoint=https://my-project.zitadel.cloud/oauth/v2/token \
  --set config.idpIntrospectionEndpoint=https://my-project.zitadel.cloud/oauth/v2/introspect \
  --set config.idpRevocationEndpoint=https://my-project.zitadel.cloud/oauth/v2/revoke \
  --set secrets.idpClientId=<your-client-id> \
  --set secrets.idpClientSecret=<your-client-secret>
```

## Run the identity smoke check

```bash
make smoke-k8s-identity K8S_HOST=<your-nuc-ip>
```

Expected output:
```
PASS gateway /health
PASS portal /health
PASS gateway initialize
PASS gateway tools/list (N tools)
PASS llm probe (config.ask_agent)
PASS identity probe (idp_provider=zitadel)
SMOKE OK
```

## Verify the deployment

```bash
kubectl get pods -n camazotz
kubectl logs -n camazotz -l app=brain-gateway --tail=50
curl -s http://<K8S_HOST>:30080/config | jq .idp_provider
```

## Rotate credentials

```bash
kubectl create secret generic camazotz-secrets \
  --namespace camazotz \
  --from-literal=CAMAZOTZ_IDP_CLIENT_ID=<new-id> \
  --from-literal=CAMAZOTZ_IDP_CLIENT_SECRET=<new-secret> \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/brain-gateway -n camazotz
```

## Troubleshooting

**`idp_provider` shows `mock` on cluster:**
- Confirm `config.idpProvider` is set in Helm values
- Check: `kubectl describe configmap camazotz-config -n camazotz | grep IDP`

**Token exchange failures in labs:**
- Confirm ZITADEL endpoints are reachable from within the cluster
- Check: `kubectl exec -n camazotz deploy/brain-gateway -- curl -s $CAMAZOTZ_IDP_TOKEN_ENDPOINT`

**`CAMAZOTZ_IDP_CLIENT_SECRET` not found:**
- Verify the secret was created: `kubectl get secret camazotz-secrets -n camazotz`
- Re-deploy with `--set secrets.idpClientSecret=<value>`
