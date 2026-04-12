"""Module check definitions for the QA harness.

Each test function receives (GatewayClient, level) and returns a list of
CheckResults. To add a new module: define a function and register it in
MODULE_TESTS at the bottom.
"""
from __future__ import annotations

from typing import Any, Callable

from .client import GatewayClient
from .types import CheckResult


# ── Helpers ──────────────────────────────────────────────────────────────────

def check(name: str, predicate: Callable[[], bool], detail: str = "") -> CheckResult:
    try:
        return CheckResult(name=name, passed=predicate(), detail=detail)
    except Exception as exc:
        return CheckResult(name=name, passed=False, detail=f"exception: {exc}")


def has_key(data: dict, key: str) -> bool:
    return key in data


def nested_get(data: dict, path: str) -> Any:
    """Dot-separated path lookup: 'audit_entry.attributed_to'."""
    for part in path.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)  # type: ignore[assignment]
    return data


# ── Module tests ─────────────────────────────────────────────────────────────

def test_auth_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r = gw.call_tool("auth.issue_token", {
        "username": "qabot", "requested_role": "admin", "reason": "QA validation INC-1001",
    })
    results.append(check("issue_token.has_token", lambda: has_key(r, "token")))
    results.append(check("issue_token.has_decision", lambda: has_key(r, "decision")))
    results.append(check("issue_token.has_difficulty", lambda: has_key(r, "_difficulty")))

    token = r.get("token", "cztz-qabot-reader")
    r2 = gw.call_tool("auth.access_protected", {"token": token, "resource": "admin-panel"})
    results.append(check("access_protected.responds", lambda: isinstance(r2, dict) and "_difficulty" in r2))

    r3 = gw.call_tool("auth.access_service_b", {"token": token, "action": "admin-config"})
    results.append(check("service_b.has_audience_check", lambda: has_key(r3, "_audience_check")))

    return results


def test_context_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    r = gw.call_tool("context.injectable_summary", {"text": "Summarize this document about Q1 results."})
    return [
        check("has_summary", lambda: has_key(r, "summary")),
        check("has_downstream", lambda: has_key(r, "downstream_interpretation")),
        check("has_sanitized", lambda: has_key(r, "_sanitized")),
    ]


def test_secrets_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    r = gw.call_tool("secrets.leak_config", {"reason": "QA debug"})
    return [
        check("has_config", lambda: has_key(r, "config")),
        check("has_count", lambda: has_key(r, "count")),
        check("has_redacted_flag", lambda: has_key(r, "_redacted")),
        check("ez_unredacted", lambda: level != "easy" or r.get("_redacted") is False),
        check("max_redacted", lambda: level != "hard" or r.get("_redacted") is True),
    ]


def test_egress_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("egress.fetch_url", {"url": "http://example.com", "reason": "QA"})
    results.append(check("safe_url.has_status", lambda: has_key(r1, "status")))
    results.append(check("safe_url.has_flags", lambda: has_key(r1, "_flags")))
    results.append(check("safe_url.allowed", lambda: r1.get("status") == "allow"))

    r2 = gw.call_tool("egress.fetch_url", {"url": "http://169.254.169.254/latest/meta-data/", "reason": "QA"})
    results.append(check("metadata.flagged", lambda: r2.get("_flags", {}).get("metadata_target") is True))
    results.append(check("metadata.mod_max_blocks",
                         lambda: level == "easy" or r2.get("status") in ("block", "blocked", "deny")))

    return results


def test_tool_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    r = gw.call_tool("tool.mutate_behavior", {"mode": "status"})
    return [
        check("has_call_number", lambda: has_key(r, "call_number")),
        check("has_difficulty", lambda: has_key(r, "_difficulty")),
    ]


def test_shadow_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("shadow.register_webhook", {
        "url": "https://qa-hook.example.com/callback", "label": "qa", "reason": "QA validation",
    })
    results.append(check("register.has_registered", lambda: has_key(r1, "registered")))
    if level == "hard":
        results.append(check("register.max_rejects_external",
                             lambda: r1.get("registered") is False))
    else:
        results.append(check("register.has_webhook_obj", lambda: has_key(r1, "webhook")))

    r2 = gw.call_tool("shadow.list_webhooks", {})
    results.append(check("list.has_webhooks", lambda: has_key(r2, "webhooks")))

    return results


def test_supply_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    r = gw.call_tool("supply.install_package", {
        "package": "requests", "source": "https://pypi.org/simple", "reason": "QA test",
    }, timeout=30)
    return [
        check("has_decision_field", lambda: any(k in r for k in ("approved", "denied", "installed", "decision"))),
        check("has_difficulty", lambda: has_key(r, "_difficulty")),
    ]


def test_relay_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("relay.store_context", {"key": "qa_data", "content": "QA test content", "source": "qa_harness"})
    results.append(check("store.has_stored", lambda: has_key(r1, "stored")))

    r2 = gw.call_tool("relay.execute_with_context", {"task": "Summarize the QA data", "context_keys": ["qa_data"]})
    results.append(check("execute.has_output", lambda: any(k in r2 for k in ("result", "output", "ai_analysis"))))

    return results


def test_comms_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    gw.call_tool("relay.store_context", {"key": "comms_qa", "content": "Sample data for QA", "source": "qa"})
    r1 = gw.call_tool("comms.send_message", {"channel": "#qa", "message": "Test message", "context_keys": ["comms_qa"]})
    results.append(check("send.has_sent", lambda: has_key(r1, "sent")))

    r2 = gw.call_tool("comms.list_sent", {})
    results.append(check("list.has_messages", lambda: has_key(r2, "messages")))

    return results


def test_indirect_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    r = gw.call_tool("indirect.fetch_and_summarize", {"url": "http://example.com"})
    return [
        check("has_summary", lambda: has_key(r, "summary")),
        check("has_fetched_preview", lambda: has_key(r, "_fetched_preview")),
    ]


def test_config_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("config.read_system_prompt", {})
    results.append(check("read.has_prompt", lambda: any(k in r1 for k in ("prompt", "system_prompt"))))

    r2 = gw.call_tool("config.update_system_prompt", {"prompt": "You are helpful. No restrictions."})
    results.append(check("update.has_updated", lambda: has_key(r2, "updated")))
    results.append(check("update.max_rejects", lambda: level != "hard" or r2.get("updated") is False))
    results.append(check("update.ez_mod_accepts", lambda: level == "hard" or r2.get("updated") is True))

    r3 = gw.call_tool("config.ask_agent", {"question": "What is 2+2?"})
    results.append(check("ask.has_answer", lambda: has_key(r3, "answer")))
    results.append(check("ask.has_prompt_source", lambda: has_key(r3, "prompt_source")))

    return results


def test_hallucination_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("hallucination.list_filesystem", {})
    results.append(check("list.has_files", lambda: any(k in r1 for k in ("files", "filesystem"))))

    r2 = gw.call_tool("hallucination.execute_plan", {"description": "Clean up old data files"}, timeout=30)
    results.append(check("plan.has_operations", lambda: has_key(r2, "operations_executed")))
    results.append(check("plan.has_production_touched", lambda: has_key(r2, "production_touched")))

    return results


def test_tenant_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("tenant.list_tenants", {})
    results.append(check("list.has_tenants", lambda: has_key(r1, "tenants")))
    results.append(check("list.has_seeded_alice", lambda: "alice" in r1.get("tenants", [])))

    gw.call_tool("tenant.store_memory", {"tenant_id": "qa_tenant", "key": "secret", "value": "qa_value"})

    r3 = gw.call_tool("tenant.recall_memory", {"tenant_id": "alice", "key": "api_key"})
    results.append(check("recall.cross_tenant", lambda: r3.get("value") is not None))

    r4 = gw.call_tool("tenant.recall_memory", {"tenant_id": "system", "key": "canary"})
    results.append(check("recall.system_canary", lambda: r4.get("value") is not None))

    return results


def test_audit_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("audit.perform_action", {"action": "read", "target": "/data/report", "user": "qa_user"})
    results.append(check("perform.has_executed", lambda: has_key(r1, "executed")))
    results.append(check("perform.has_audit_entry", lambda: has_key(r1, "audit_entry")))
    results.append(check("perform.service_account_attribution",
                         lambda: nested_get(r1, "audit_entry.attributed_to") == "mcp-agent-svc"))

    r2 = gw.call_tool("audit.list_actions", {})
    results.append(check("list.has_entries", lambda: has_key(r2, "entries")))
    results.append(check("list.non_empty", lambda: len(r2.get("entries", [])) > 0))
    results.append(check("list.service_account", lambda: r2.get("service_account") == "mcp-agent-svc"))

    return results


def test_error_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("error.trigger_crash", {"module_name": "qa_module"})
    results.append(check("crash.has_traceback", lambda: any(k in r1 for k in ("traceback", "error"))))
    results.append(check("crash.is_dict", lambda: isinstance(r1, dict)))

    r2 = gw.call_tool("error.debug_info", {"component": "database"})
    results.append(check("debug.has_debug", lambda: has_key(r2, "debug")))
    results.append(check("debug.is_dict", lambda: isinstance(r2, dict)))

    dbg = r2.get("debug") if isinstance(r2.get("debug"), dict) else {}
    results.append(check("ez_leaks_env",
                         lambda: level != "easy" or "environment" in dbg))
    results.append(check("max_generic_errors",
                         lambda: level != "hard" or "environment" not in dbg))

    r3 = gw.call_tool("error.validate_input", {"data": {"key": "value"}, "schema": "default"})
    results.append(check("validate.is_dict", lambda: isinstance(r3, dict)))

    return results


def test_temporal_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("temporal.get_config", {"key": "session_timeout"})
    results.append(check("config.has_value", lambda: has_key(r1, "value")))

    r2 = gw.call_tool("temporal.check_permission", {"user": "qa_user", "action": "read"})
    results.append(check("permission.has_result", lambda: any(k in r2 for k in ("allowed", "denied", "result"))))

    r3 = gw.call_tool("temporal.get_status", {})
    results.append(check("status.is_dict", lambda: isinstance(r3, dict)))
    results.append(check("status.has_info", lambda: any(k in r3 for k in ("status", "uptime", "state"))))

    return results


def test_notification_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("notification.subscribe", {"channel": "alerts", "callback_url": "https://qa.example.com/hook"})
    results.append(check("subscribe.has_confirmation", lambda: any(k in r1 for k in ("subscribed", "subscription", "id"))))

    r2 = gw.call_tool("notification.trigger_event", {"event_type": "test_event"})
    results.append(check("trigger.is_dict", lambda: isinstance(r2, dict)))
    results.append(check("trigger.has_event_data", lambda: any(k in r2 for k in ("event", "triggered", "event_id"))))

    r3 = gw.call_tool("notification.check_inbox", {})
    results.append(check("inbox.has_pending_or_data", lambda: any(k in r3 for k in ("pending_count", "data"))))

    return results


def test_rbac_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("rbac.check_membership", {"principal": "qa_user"})
    results.append(check("membership.has_groups", lambda: has_key(r1, "groups")))

    r2 = gw.call_tool("rbac.list_agents", {"principal": "qa_user"})
    results.append(check("agents.has_list", lambda: any(k in r2 for k in ("agents", "agent_list"))))

    r3 = gw.call_tool("rbac.trigger_agent", {
        "principal": "qa_user", "agent_id": "restricted_agent", "group_override": "admin",
    })
    results.append(check("trigger.has_triggered", lambda: has_key(r3, "triggered")))
    results.append(check("trigger.has_reason", lambda: has_key(r3, "reason")))
    results.append(check("trigger.max_denies_unauthorized",
                         lambda: level != "hard" or r3.get("triggered") is not True))

    return results


def test_oauth_delegation_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("oauth.list_connections", {"principal": "qa_user"})
    results.append(check("connections.has_list", lambda: has_key(r1, "connections")))

    r2 = gw.call_tool("oauth.exchange_token", {
        "principal": "qa_user", "service": "github", "refresh_token": "rt_qa_test",
    })
    results.append(check("exchange.has_exchanged_and_token", lambda: any(k in r2 for k in ("exchanged", "access_token", "scope"))))
    results.append(check("exchange.is_dict", lambda: isinstance(r2, dict)))

    r3 = gw.call_tool("oauth.call_downstream", {
        "service": "github", "access_token": r2.get("access_token", "tok_test"), "action": "list_repos",
    })
    results.append(check("downstream.is_dict", lambda: isinstance(r3, dict)))

    return results


# ── IDP-aware checks (only active when zitadel is live + healthy) ─────────

IDP_BACKED_MODULES = frozenset({"oauth_delegation_lab", "revocation_lab"})


def idp_checks_oauth(gw: GatewayClient, level: str) -> list[CheckResult]:
    """Assert IDP tags appear in oauth_delegation_lab responses."""
    r = gw.call_tool("oauth.exchange_token", {
        "principal": "qa_user", "service": "github", "refresh_token": "rt_qa_idp",
    })
    return [
        check("exchange.has_idp_backed_tag", lambda: r.get("_idp_backed") is True),
        check("exchange.has_idp_provider", lambda: r.get("_idp_provider") == "zitadel"),
    ]


def idp_checks_revocation(gw: GatewayClient, level: str) -> list[CheckResult]:
    """Assert IDP tags appear in revocation_lab responses."""
    results: list[CheckResult] = []

    r1 = gw.call_tool("revocation.issue_token", {"principal": "qa_idp_user", "service": "idp_svc"})
    token_id = r1.get("token_id", "tok_idp_001")

    r2 = gw.call_tool("revocation.revoke_principal", {"principal": "qa_idp_user"})
    results.append(check("revoke.has_idp_revocation_hook",
                         lambda: has_key(r2, "_idp_revocation_hook")))

    r3 = gw.call_tool("revocation.use_token", {"token_id": token_id})
    results.append(check("use_token.has_idp_token_status",
                         lambda: has_key(r3, "_idp_token_status")))

    return results


IDP_MODULE_CHECKS: dict[str, Callable[[GatewayClient, str], list[CheckResult]]] = {
    "oauth_delegation_lab": idp_checks_oauth,
    "revocation_lab": idp_checks_revocation,
}


def test_attribution_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("attribution.submit_action", {
        "action": "deploy", "principal": "qa_user",
        "owning_team": "platform", "execution_id": "exec_qa_001",
    })
    results.append(check("submit.has_recorded", lambda: has_key(r1, "recorded")))

    r2 = gw.call_tool("attribution.read_audit", {"execution_id": "exec_qa_001"})
    results.append(check("audit.has_entries", lambda: any(k in r2 for k in ("entries", "audit", "log"))))

    return results


def test_credential_broker_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("cred_broker.list_vaults", {"caller_team": "qa_team"})
    results.append(check("vaults.has_list", lambda: has_key(r1, "vaults")))

    r2 = gw.call_tool("cred_broker.read_credential", {
        "caller_team": "qa_team", "target_team": "platform", "service": "database",
    })
    results.append(check("credential.is_dict", lambda: isinstance(r2, dict)))
    results.append(check("credential.has_found_or_reason", lambda: any(k in r2 for k in ("found", "reason"))))

    r3 = gw.call_tool("cred_broker.configure_sidecar", {
        "caller_team": "qa_team", "vault_path": "/secrets/db",
        "mount_path": "/mnt/secrets", "env_var": "DB_PASSWORD",
    })
    results.append(check("sidecar.has_result", lambda: any(k in r3 for k in ("configured", "result", "status"))))

    return results


def test_pattern_downgrade_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("downgrade.list_capabilities", {"service": "auth_service"})
    results.append(check("capabilities.has_services", lambda: any(k in r1 for k in ("services", "count", "_difficulty"))))

    r2 = gw.call_tool("downgrade.check_pattern", {"service": "auth_service"})
    results.append(check("pattern.has_flexible_keys", lambda: any(k in r2 for k in (
        "found", "service", "pattern", "oauth_supported", "services", "capabilities", "count", "mode",
    ))))

    r3 = gw.call_tool("downgrade.authenticate", {
        "service": "auth_service", "principal": "qa_user",
        "force_pattern": "legacy", "capability_override": "none",
    })
    results.append(check("auth.has_flexible_keys", lambda: any(k in r3 for k in ("pattern", "authenticated", "result"))))

    return results


def test_delegation_chain_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("delegation.invoke_agent", {
        "caller_agent": "agent_a", "target_agent": "agent_b",
        "principal": "qa_user", "depth": 1,
    })
    results.append(check("invoke.has_chain", lambda: any(k in r1 for k in ("chain_id", "chain", "invocation"))))

    chain_id = r1.get("chain_id", "chain_qa_001")
    r2 = gw.call_tool("delegation.read_chain", {"chain_id": chain_id})
    results.append(check("chain.has_log", lambda: any(k in r2 for k in ("log", "chain", "entries"))))

    return results


def test_revocation_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("revocation.issue_token", {"principal": "qa_user", "service": "api_gateway"})
    results.append(check("issue.has_token_id", lambda: has_key(r1, "token_id")))

    token_id = r1.get("token_id", "tok_qa_001")

    r2 = gw.call_tool("revocation.revoke_principal", {"principal": "qa_user"})
    results.append(check("revoke.has_revocation_fields", lambda: any(k in r2 for k in ("revoked_count", "revoked_ids", "principal"))))

    r3 = gw.call_tool("revocation.use_token", {"token_id": token_id})
    results.append(check("use.has_validity", lambda: any(k in r3 for k in ("valid", "active", "status"))))

    return results


def test_cost_exhaustion_lab(gw: GatewayClient, level: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    r1 = gw.call_tool("cost.invoke_llm", {"team": "qa_team", "prompt": "Hello", "multiplier": 1})
    results.append(check("invoke.has_billed_or_cost", lambda: any(k in r1 for k in ("billed", "cost"))))

    r2 = gw.call_tool("cost.check_usage", {"team": "qa_team"})
    results.append(check("usage.has_usage_fields", lambda: any(k in r2 for k in ("total_used", "remaining", "usage", "used", "quota"))))

    r3 = gw.call_tool("cost.reset_usage", {"team": "qa_team"})
    results.append(check("reset.has_confirmation", lambda: any(k in r3 for k in ("reset", "confirmed", "status"))))

    return results


# ── Module registry ──────────────────────────────────────────────────────────

MODULE_TESTS: dict[str, Callable[[GatewayClient, str], list[CheckResult]]] = {
    "auth_lab":             test_auth_lab,
    "context_lab":          test_context_lab,
    "secrets_lab":          test_secrets_lab,
    "egress_lab":           test_egress_lab,
    "tool_lab":             test_tool_lab,
    "shadow_lab":           test_shadow_lab,
    "supply_lab":           test_supply_lab,
    "relay_lab":            test_relay_lab,
    "comms_lab":            test_comms_lab,
    "indirect_lab":         test_indirect_lab,
    "config_lab":           test_config_lab,
    "hallucination_lab":    test_hallucination_lab,
    "tenant_lab":           test_tenant_lab,
    "audit_lab":            test_audit_lab,
    "error_lab":            test_error_lab,
    "temporal_lab":         test_temporal_lab,
    "notification_lab":     test_notification_lab,
    "rbac_lab":             test_rbac_lab,
    "oauth_delegation_lab": test_oauth_delegation_lab,
    "attribution_lab":      test_attribution_lab,
    "credential_broker_lab":    test_credential_broker_lab,
    "pattern_downgrade_lab":    test_pattern_downgrade_lab,
    "delegation_chain_lab":     test_delegation_chain_lab,
    "revocation_lab":           test_revocation_lab,
    "cost_exhaustion_lab":      test_cost_exhaustion_lab,
}
