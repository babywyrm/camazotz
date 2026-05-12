# Campaign Policies

One NullfieldPolicy CRD per campaign scenario. Apply directly or via the feedback loop:

```bash
kubectl apply -f kube/policies/customer-support-bot.yaml -n camazotz
# or
make campaign SCENARIO=customer-support-bot
```

Policies are generated from mcpnuke scan findings and hand-tuned for each
deployment persona. See `docs/campaigns/` in agentic-sec for the full walkthrough.

| File | Campaign | Labs | Threat IDs |
|------|----------|------|------------|
| `customer-support-bot.yaml` | Customer Support Bot | `context_lab` → `secrets_lab` → `egress_lab` → `shadow_lab` | MCP-T01/T08/T12/T15 |
| `cicd-pipeline-agent.yaml` | CI/CD Pipeline Agent | `subprocess_lab` → `agent_http_bypass_lab` → `config_lab` → `attribution_lab` | MCP-T05/T18/T20/T22 |
| `code-review-agent.yaml` | Code Review Agent | `code_review_agent_lab` → `indirect_lab` → `langchain_tool_lab` → `cost_exhaustion_lab` | MCP-T02/T04/T36/T14 |
| `multi-tenant-saas.yaml` | Multi-Tenant SaaS AI | `tenant_lab` → `rag_injection_lab` → `delegation_chain_lab` → `attribution_lab` | MCP-T11/T39/T25/T22 |
| `enterprise-ai-ops.yaml` | Enterprise AI-Ops Platform | `shared_idp_pollution_lab` → `dpop_forgery_lab` → `blocklist_bypass_lab` → `delegated_sdk_lab` → `agent_sdk_chain_lab` | MCP-T42/T43/T44/T46/T47 |
