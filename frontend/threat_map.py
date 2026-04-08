"""Category taxonomy and helpers for the Threat Map page."""

from __future__ import annotations

CATEGORY_GROUPS: list[dict] = [
    {
        "name": "Identity & Access",
        "blurb": (
            "Can an attacker trick the AI into issuing credentials or escalating "
            "privileges? These labs explore confused-deputy token issuance, RBAC "
            "bypass, and delegation abuse."
        ),
        "labs": ["auth_lab", "rbac_lab", "oauth_delegation_lab", "credential_broker_lab"],
    },
    {
        "name": "Data & Secrets",
        "blurb": (
            "What happens when the AI leaks sensitive data it should protect? "
            "Prompt injection, context poisoning, and SSRF via AI proxy."
        ),
        "labs": ["secrets_lab", "context_lab", "egress_lab"],
    },
    {
        "name": "Tool & Supply Chain",
        "blurb": (
            "Tools are the AI's hands. These labs show what happens when tool "
            "behavior mutates, supply chains are poisoned, or security patterns "
            "are downgraded at runtime."
        ),
        "labs": ["tool_lab", "supply_lab", "pattern_downgrade_lab"],
    },
    {
        "name": "Delegation & Trust",
        "blurb": (
            "When AI delegates to other agents or services, trust boundaries "
            "blur. Explore relay attacks, delegation chain abuse, attribution "
            "confusion, and revocation failures."
        ),
        "labs": ["relay_lab", "delegation_chain_lab", "attribution_lab", "revocation_lab"],
    },
    {
        "name": "Observation & Evasion",
        "blurb": (
            "Attackers who can persist undetected win. These labs cover shadow "
            "webhook registration, covert channels, audit evasion, and "
            "notification manipulation."
        ),
        "labs": ["shadow_lab", "comms_lab", "audit_lab", "notification_lab"],
    },
    {
        "name": "AI Behavior",
        "blurb": (
            "The AI itself is an attack surface. Hallucinated tools, indirect "
            "prompt injection, configuration tampering, and cost exhaustion "
            "attacks exploit the model's reasoning."
        ),
        "labs": ["hallucination_lab", "indirect_lab", "config_lab", "cost_exhaustion_lab"],
    },
    {
        "name": "Isolation",
        "blurb": (
            "Shared infrastructure means shared risk. Multi-tenant data leaks, "
            "error-based information disclosure, and temporal race conditions."
        ),
        "labs": ["tenant_lab", "error_lab", "temporal_lab"],
    },
]

HEX_ROWS: list[list[str]] = [
    ["auth_lab", "rbac_lab", "oauth_delegation_lab", "credential_broker_lab", "secrets_lab"],
    ["context_lab", "egress_lab", "tool_lab", "supply_lab", "pattern_downgrade_lab"],
    ["relay_lab", "delegation_chain_lab", "attribution_lab", "revocation_lab", "shadow_lab"],
    ["comms_lab", "audit_lab", "notification_lab", "hallucination_lab", "indirect_lab"],
    ["config_lab", "cost_exhaustion_lab", "tenant_lab", "error_lab", "temporal_lab"],
]

CATEGORY_COLORS: dict[str, dict[str, str]] = {
    "Identity & Access": {"primary": "#7c3aed", "dark": "#4c1d95", "css": "identity"},
    "Data & Secrets": {"primary": "#2563eb", "dark": "#1e3a8a", "css": "data"},
    "Tool & Supply Chain": {"primary": "#d97706", "dark": "#92400e", "css": "tool"},
    "Delegation & Trust": {"primary": "#059669", "dark": "#064e3b", "css": "delegation"},
    "Observation & Evasion": {"primary": "#dc2626", "dark": "#7f1d1d", "css": "observation"},
    "AI Behavior": {"primary": "#0891b2", "dark": "#164e63", "css": "ai"},
    "Isolation": {"primary": "#6b7280", "dark": "#374151", "css": "isolation"},
}

_LAB_TO_CATEGORY: dict[str, str] = {}
for _g in CATEGORY_GROUPS:
    for _lab in _g["labs"]:
        _LAB_TO_CATEGORY[_lab] = _g["name"]


def get_lab_category(lab_name: str) -> str:
    """Return the display category name for a lab, or empty string if unknown."""
    return _LAB_TO_CATEGORY.get(lab_name, "")


def has_walkthrough(lab_name: str) -> bool:
    """Return True if a guided walkthrough exists for the given lab."""
    from qa_runner.walkthroughs import WALKTHROUGHS
    return lab_name in WALKTHROUGHS
