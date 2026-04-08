# Threat Map & Contextual Walkthrough Links — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Threat Map page and contextual walkthrough links so learners can visualise the 25-lab landscape, track progress, and discover walkthroughs when stuck.

**Architecture:** New `/threat-map` route in Flask frontend serving a Jinja2 template. Category grouping logic lives in a small Python helper (`frontend/threat_map.py`). Walkthrough availability is a thin wrapper around the existing `WALKTHROUGHS` dict. Challenge detail and scenario templates get conditional walkthrough link blocks. All progress is `localStorage`-based (client-side).

**Tech Stack:** Flask, Jinja2, vanilla JS, existing CSS variable system, pytest + 100% coverage.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `frontend/threat_map.py` | Create | Category taxonomy, grouping helper, teaching blurbs |
| `frontend/templates/threat_map.html` | Create | Threat Map page template |
| `frontend/templates/base.html` | Modify (line ~170) | Add "Threat Map" to nav |
| `frontend/app.py` | Modify | Add `GET /threat-map` route |
| `frontend/templates/challenge_detail.html` | Modify | Add walkthrough callout after hints |
| `frontend/templates/scenarios.html` | Modify | Add walkthrough pill to scenario cards |
| `tests/test_threat_map.py` | Create | Tests for grouping helper, route, template assertions |
| `tests/test_frontend_routes.py` | Modify | Add walkthrough link tests for challenge detail + scenarios |

---

### Task 1: Category grouping helper

**Files:**
- Create: `frontend/threat_map.py`
- Test: `tests/test_threat_map.py`

- [ ] **Step 1: Write failing test for category grouping**

```python
# tests/test_threat_map.py
import importlib
import sys

import pytest


@pytest.fixture()
def threat_map_mod():
    frontend_dir = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "frontend")
    if frontend_dir not in sys.path:
        sys.path.insert(0, frontend_dir)
    sys.modules.pop("threat_map", None)
    mod = importlib.import_module("threat_map")
    yield mod
    sys.path.remove(frontend_dir)
    sys.modules.pop("threat_map", None)


def test_all_25_labs_are_grouped(threat_map_mod):
    groups = threat_map_mod.CATEGORY_GROUPS
    all_labs = []
    for g in groups:
        all_labs.extend(g["labs"])
    assert len(all_labs) == 25
    assert len(set(all_labs)) == 25


def test_each_group_has_required_fields(threat_map_mod):
    for g in threat_map_mod.CATEGORY_GROUPS:
        assert "name" in g
        assert "blurb" in g
        assert "labs" in g
        assert len(g["labs"]) >= 1
        assert len(g["blurb"]) > 10


def test_has_walkthrough_true(threat_map_mod):
    assert threat_map_mod.has_walkthrough("auth_lab") is True


def test_has_walkthrough_false(threat_map_mod):
    assert threat_map_mod.has_walkthrough("nonexistent_lab") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_threat_map.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'threat_map'`

- [ ] **Step 3: Write minimal implementation**

```python
# frontend/threat_map.py
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


def has_walkthrough(lab_name: str) -> bool:
    """Return True if a guided walkthrough exists for the given lab."""
    from qa_runner.walkthroughs import WALKTHROUGHS
    return lab_name in WALKTHROUGHS
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_threat_map.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```
feat(threat-map): category grouping helper with taxonomy and walkthrough lookup
```

---

### Task 2: Flask route for Threat Map

**Files:**
- Modify: `frontend/app.py`
- Test: `tests/test_threat_map.py`

- [ ] **Step 1: Write failing test for the route**

Append to `tests/test_threat_map.py`:

```python
@pytest.fixture()
def frontend_client():
    frontend_dir = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "frontend")
    if frontend_dir not in sys.path:
        sys.path.insert(0, frontend_dir)
    sys.modules.pop("app", None)
    mod = importlib.import_module("app")
    mod.app.config["TESTING"] = True
    with mod.app.test_client() as client:
        yield client, mod
    sys.path.remove(frontend_dir)
    sys.modules.pop("app", None)


def test_threat_map_route_returns_200(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    assert resp.status_code == 200


def test_threat_map_has_all_25_cards(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert html.count('data-lab="') == 25


def test_threat_map_has_progress_bar(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert "of 25" in html


def test_threat_map_has_category_groups(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert "Identity &amp; Access" in html
    assert "AI Behavior" in html
    assert "Isolation" in html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_threat_map.py::test_threat_map_route_returns_200 -v`
Expected: FAIL — 404

- [ ] **Step 3: Add route to `frontend/app.py`**

Add after the `/observer` route (around line 112):

```python
@app.route("/threat-map")
def threat_map() -> str:
    from threat_map import CATEGORY_GROUPS, has_walkthrough
    from qa_runner.walkthroughs import WALKTHROUGHS

    all_scenarios = _fetch_scenarios()
    scenario_map = {s["module_name"]: s for s in all_scenarios}

    groups = []
    for group in CATEGORY_GROUPS:
        labs = []
        for lab_name in group["labs"]:
            sc = scenario_map.get(lab_name, {})
            labs.append({
                "name": lab_name,
                "threat_id": sc.get("threat_id", ""),
                "title": sc.get("title", lab_name.replace("_", " ").title()),
                "description": sc.get("description", ""),
                "category": sc.get("category", ""),
                "has_walkthrough": has_walkthrough(lab_name),
                "step_count": len(WALKTHROUGHS.get(lab_name, [])),
            })
        groups.append({
            "name": group["name"],
            "blurb": group["blurb"],
            "labs": labs,
        })

    return render_template("threat_map.html", groups=groups, total_labs=25)
```

- [ ] **Step 4: Create minimal `frontend/templates/threat_map.html`** (placeholder that passes tests — full styling in Task 3)

```html
{% extends "base.html" %}
{% block title %}Threat Map — Camazotz{% endblock %}

{% block content %}
<div class="container section">
  <div style="text-align:center;padding:2rem 0">
    <h1>Threat Map</h1>
    <p>0 of 25 labs completed</p>
  </div>
  {% for group in groups %}
  <h2>{{ group.name }}</h2>
  <p>{{ group.blurb }}</p>
  <div>
    {% for lab in group.labs %}
    <div data-lab="{{ lab.name }}" data-tid="{{ lab.threat_id }}">
      <span>{{ lab.threat_id }}</span>
      <span>{{ lab.title }}</span>
      {% if lab.has_walkthrough %}
      <a href="/operator#walkthrough/{{ lab.name }}">Walkthrough</a>
      {% endif %}
    </div>
    {% endfor %}
  </div>
  {% endfor %}
</div>
{% endblock %}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_threat_map.py -v`
Expected: 8 passed

- [ ] **Step 6: Commit**

```
feat(threat-map): /threat-map route with category groups and lab cards
```

---

### Task 3: Threat Map template — full styling and client-side progress

**Files:**
- Modify: `frontend/templates/threat_map.html`

- [ ] **Step 1: Replace the placeholder template with the full styled version**

The template should:
- Extend `base.html`.
- Include `extra_css` block with styles for: `.tm-header`, `.tm-progress`, `.tm-progress-bar`, `.tm-chips`, `.tm-group`, `.tm-group-header`, `.tm-group-blurb`, `.tm-cards` (flex row), `.tm-card` (compact card with threat ID badge, title, description, solve check, walkthrough icon), `.tm-reset-btn`.
- Card structure: `data-lab`, `data-tid` attributes. Threat ID badge uses `.badge.badge-accent`. Solve check uses `.solved-check` (hidden by default). Walkthrough link only rendered when `lab.has_walkthrough`.
- Include `extra_js` block with JS that:
  - Reads `cztz_solved_<tid>` from `localStorage` for each card.
  - Shows/hides `.solved-check` per card.
  - Counts solved labs per group and overall, updates summary bar and chips.
  - `resetProgress()` function: clears all `cztz_solved_*` keys, calls `fetch('/api/reset', {method:'POST'})`, refreshes counts.

(Full HTML is implementation detail — the card design should match `.challenge-card` from `challenges.html`, and group headers should match `.sc-section h2` from `scenarios.html`.)

- [ ] **Step 2: Run full test suite**

Run: `uv run pytest tests/test_threat_map.py -v`
Expected: 8 passed

- [ ] **Step 3: Commit**

```
feat(threat-map): styled template with progress tracking and reset
```

---

### Task 4: Add Threat Map to navigation

**Files:**
- Modify: `frontend/templates/base.html` (line ~170)
- Test: `tests/test_threat_map.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_threat_map.py`:

```python
def test_threat_map_in_nav(frontend_client):
    client, _ = frontend_client
    resp = client.get("/")
    html = resp.data.decode()
    assert 'href="/threat-map"' in html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_threat_map.py::test_threat_map_in_nav -v`
Expected: FAIL

- [ ] **Step 3: Add nav link in `base.html`**

In `frontend/templates/base.html`, after the Challenges link (line 170) and before the Observer link (line 171), add:

```html
      <a href="/threat-map" class="{% if request.path == '/threat-map' %}active{% endif %}">Threat Map</a>
```

So the nav order becomes: Home, Playground, Scenarios, Challenges, **Threat Map**, Observer, Guardrails, Reset.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_threat_map.py::test_threat_map_in_nav -v`
Expected: PASS

- [ ] **Step 5: Commit**

```
feat(threat-map): add Threat Map to main navigation
```

---

### Task 5: Walkthrough link on Challenge Detail page

**Files:**
- Modify: `frontend/templates/challenge_detail.html`
- Modify: `frontend/app.py` (pass `has_walkthrough` to template context)
- Test: `tests/test_frontend_routes.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_frontend_routes.py`:

```python
def test_challenge_detail_has_walkthrough_link(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/challenges/MCP-T01")
    html = resp.data.decode()
    assert "Watch the walkthrough" in html or "walkthrough" in html.lower()


def test_challenge_detail_no_walkthrough_for_unknown(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/challenges/MCP-T01")
    html = resp.data.decode()
    assert '/operator#walkthrough/' in html
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_frontend_routes.py::test_challenge_detail_has_walkthrough_link -v`
Expected: FAIL

- [ ] **Step 3: Modify `frontend/app.py` `challenge_detail()` to pass walkthrough info**

In the `challenge_detail` route, add:

```python
@app.route("/challenges/<threat_id>")
def challenge_detail(threat_id: str):
    from threat_map import has_walkthrough

    scenarios = _fetch_scenarios()
    scenario = next((s for s in scenarios if s["threat_id"] == threat_id), None)
    if scenario is None:
        return "Challenge not found", 404
    lab_name = scenario.get("module_name", "")
    return render_template(
        "challenge_detail.html",
        scenario=scenario,
        walkthrough_available=has_walkthrough(lab_name),
        walkthrough_lab=lab_name,
    )
```

- [ ] **Step 4: Add walkthrough callout to `challenge_detail.html`**

After the hints section (after the closing `</div>` of the hint-accordion section, around line 141), add:

```html
  {% if walkthrough_available %}
  <div class="detail-section">
    <div style="background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.18);border-left:3px solid rgba(251,191,36,.6);border-radius:0 8px 8px 0;padding:1rem 1.2rem;display:flex;align-items:center;gap:.8rem">
      <span style="font-size:1.3rem">&#9654;</span>
      <div>
        <div style="font-weight:700;font-size:.88rem;margin-bottom:.2rem">Stuck? Watch the walkthrough</div>
        <div style="font-size:.8rem;color:var(--text2)">Step through this exploit with guided narrative and security insights.</div>
      </div>
      <a href="/operator#walkthrough/{{ walkthrough_lab }}" style="margin-left:auto;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:.45rem 1rem;font-size:.8rem;font-weight:600;color:var(--text);text-decoration:none;white-space:nowrap;transition:all .2s">View Walkthrough</a>
    </div>
  </div>
  {% endif %}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_frontend_routes.py -v`
Expected: all passed

- [ ] **Step 6: Commit**

```
feat(walkthrough-links): contextual walkthrough callout on challenge detail page
```

---

### Task 6: Walkthrough pill on Scenario cards

**Files:**
- Modify: `frontend/templates/scenarios.html`
- Modify: `frontend/app.py` (pass walkthrough availability to scenarios)
- Test: `tests/test_frontend_routes.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_frontend_routes.py`:

```python
def test_scenarios_page_has_walkthrough_pills(frontend_client) -> None:
    client, _ = frontend_client
    resp = client.get("/scenarios")
    html = resp.data.decode()
    assert "walkthrough" in html.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_frontend_routes.py::test_scenarios_page_has_walkthrough_pills -v`
Expected: FAIL

- [ ] **Step 3: Modify `frontend/app.py` `scenarios()` to annotate walkthrough availability**

```python
@app.route("/scenarios")
def scenarios() -> str:
    from threat_map import has_walkthrough

    all_scenarios = _fetch_scenarios()
    all_scenarios.sort(key=lambda s: s.get("threat_id", ""))
    for s in all_scenarios:
        s["has_walkthrough"] = has_walkthrough(s.get("module_name", ""))
    return render_template("scenarios.html", scenarios=all_scenarios)
```

- [ ] **Step 4: Add walkthrough pill to `scenarios.html` scenario cards**

Inside each `.scenario-card`, after the `.scenario-meta` div, add:

```html
      {% if s.has_walkthrough %}
      <a href="/operator#walkthrough/{{ s.module_name }}" style="display:inline-flex;align-items:center;gap:.3rem;font-size:.72rem;font-weight:600;color:var(--orange);text-decoration:none;margin-top:.3rem;transition:color .2s">&#9654; Walkthrough</a>
      {% endif %}
```

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_frontend_routes.py -v`
Expected: all passed

- [ ] **Step 6: Commit**

```
feat(walkthrough-links): walkthrough pill on scenario cards
```

---

### Task 7: Full test suite and coverage

**Files:**
- All test files

- [ ] **Step 1: Run the full test suite**

Run: `uv run pytest -q`
Expected: all tests pass, 100% coverage

- [ ] **Step 2: Fix any coverage gaps**

If `frontend/threat_map.py` or new route branches are not fully covered, add targeted tests to `tests/test_threat_map.py`.

- [ ] **Step 3: Commit any coverage fixes**

```
test: coverage for threat map and walkthrough links
```

---

### Task 8: Deploy and verify

**Files:** None (operational)

- [ ] **Step 1: Rebuild local Docker Compose**

Run: `make down && make up`

- [ ] **Step 2: Verify locally**

Open `http://localhost:3000/threat-map` — confirm page loads with 7 category groups, 25 lab cards, progress bar, and walkthrough links.

Open a challenge detail page — confirm walkthrough callout appears below hints.

Open scenarios page — confirm walkthrough pills appear.

- [ ] **Step 3: Sync and deploy to NUC**

```bash
rsync -avz -e "ssh -i ~/HTB/Artifice/OG_id_ed25519" --exclude='.venv' --exclude='__pycache__' --exclude='.git/' /Users/tms/camazotz/ root@192.168.1.114:/opt/camazotz/
ssh -i ~/HTB/Artifice/OG_id_ed25519 root@192.168.1.114 'cd /opt/camazotz && bash kube/deploy.sh'
ssh -i ~/HTB/Artifice/OG_id_ed25519 root@192.168.1.114 'sudo k3s kubectl -n camazotz rollout restart deployment/brain-gateway deployment/portal deployment/observer'
```

- [ ] **Step 4: Verify on NUC**

Run: `uv run python scripts/smoke_test.py --target k8s --k8s-host 192.168.1.114 --require-llm`

Open `http://192.168.1.114:3000/threat-map` — confirm page loads correctly.

- [ ] **Step 5: Commit (if any deploy fixes needed)**

```
fix: deploy adjustments for threat map
```
