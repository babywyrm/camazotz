# Teleport Integration for Camazotz

Teleport provides machine identity and zero-trust access for agents interacting
with the camazotz MCP server. Agents authenticate via short-lived X.509
certificates instead of static API keys or long-lived tokens.

## What's Deployed

| Component | Namespace | Purpose |
|---|---|---|
| `teleport-cluster-auth` | teleport | Auth service — issues certs, manages roles, stores state |
| `teleport-cluster-proxy` | teleport | Proxy service — TLS termination, protocol routing |
| `tbot` | teleport | Machine Identity agent — produces short-lived K8s kubeconfig |
| `teleport-app-agent` | teleport | App Access agent — proxies camazotz-mcp through Teleport |

## Agent Access Patterns

### Kubernetes Access (Phase 1)

Agents use tbot-generated kubeconfig with short-lived certs (1h TTL,
auto-renewed every 20 min) to access K8s resources through Teleport RBAC.

```text
Agent → tbot kubeconfig → Teleport Proxy → K8s API
                          (RBAC: agent-readonly)
```

The `tbot-kube` secret contains a kubeconfig that any pod can mount.
Access is scoped by the `agent-readonly` Teleport role which maps to the
K8s `view` ClusterRole via a ClusterRoleBinding.

### MCP Access (Phase 2)

The `teleport-app-agent` registers `camazotz-mcp` as a Teleport
application. Agents with the `agent-mcp` role can access the MCP server
through Teleport's App Access, with per-tool RBAC:

```text
Agent → tsh mcp connect → Teleport Proxy → App Agent → brain-gateway:8080
                           (RBAC: agent-mcp, tools: cost.*, audit.*, etc.)
```

The `agent-mcp` role restricts which MCP tools are accessible:
- `cost.*` — cost and usage checking
- `audit.*` — audit log access
- `attribution.*` — execution attribution
- `identity.*` — identity inspection

## Teleport Roles

### agent-readonly

```yaml
kind: role
version: v7
metadata:
  name: agent-readonly
spec:
  allow:
    kubernetes_groups: ["view"]
    kubernetes_labels: {"*": "*"}
    kubernetes_resources:
      - kind: pod
        namespace: "*"
        verbs: ["get", "list", "watch"]
      - kind: service
        namespace: "*"
        verbs: ["get", "list"]
      - kind: configmap
        namespace: "*"
        verbs: ["get", "list"]
      - kind: namespace
        verbs: ["get", "list"]
```

### agent-mcp

```yaml
kind: role
version: v7
metadata:
  name: agent-mcp
spec:
  allow:
    app_labels:
      type: mcp
    mcp:
      tools:
        - "cost.*"
        - "audit.*"
        - "attribution.*"
        - "identity.*"
```

## Setup Notes

### Self-Signed Cert Trust

The Teleport proxy generates a self-signed cert on startup with SANs
for `teleport.local` and the pod hostname. For the app agent to connect
via the proxy tunnel:

1. `teleport.local` must resolve to the proxy ClusterIP inside the cluster
   (added via CoreDNS hosts block)
2. `teleport.local` must resolve to 192.168.1.85 on the host
   (added via /etc/hosts)
3. The proxy's self-signed cert must be mounted into the app agent as
   `SSL_CERT_FILE` so Go's TLS client trusts it

### Extracting the Proxy Cert

```bash
PROXY_IP=$(kubectl -n teleport get svc teleport-cluster -o jsonpath="{.spec.clusterIP}")
echo | openssl s_client -connect $PROXY_IP:443 -servername teleport.local 2>/dev/null \
  | openssl x509 > proxy-cert.pem
kubectl -n teleport create configmap teleport-proxy-ca --from-file=ca.crt=proxy-cert.pem
```

### CoreDNS Entry

The teleport.local hostname is added to CoreDNS via a hosts block in the
Corefile:

```
hosts /etc/coredns/NodeHosts {
    10.43.148.101 teleport.local
    ttl 60
    reload 15s
    fallthrough
}
```

### Join Method

Both tbot and the app agent use the `kubernetes` join method with
in-cluster token validation. The auth service validates the pod's
ServiceAccount JWT against the K8s API.

## Testing with mcpnuke

mcpnuke includes Teleport-aware security checks:

```bash
mcpnuke --targets http://192.168.1.85:30080/mcp --fast --no-invoke --verbose
```

Teleport checks:
- `teleport_proxy_discovery` — finds proxy, reports version and auth config
- `teleport_cert_validation` — flags self-signed certs
- `teleport_app_enumeration` — tests unauthenticated app list access
- `tbot_credential_exposure` — checks if tbot secrets are over-shared
- `teleport_bot_overprivilege` — flags excessive bot RBAC

Teleport lab exploit chains (requires `--invoke`):
- `teleport_lab_bot_theft` — stolen tbot cert replay chain
- `teleport_lab_role_escalation` — self-escalation via MCP tool
- `teleport_lab_cert_replay` — expired cert replay in grace window

## Limitations

- Self-signed certs require the `SSL_CERT_FILE` workaround for the app agent
- The proxy cert changes when the proxy pod restarts — the configmap must be
  updated (extract + recreate). A cert-manager-issued cert would avoid this.
- Teleport Community Edition does not support access requests — role changes
  are static. Enterprise adds just-in-time access request workflows.
- `tsh mcp connect` requires the Teleport proxy to be reachable from the
  client machine. On a local network, add `teleport.local` to `/etc/hosts`
  pointing to the NUC IP.
