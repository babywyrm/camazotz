# Threat Map v2 — Hex Territory Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the card-grid Threat Map with a hex honeycomb territory view, fix broken walkthrough deep-links, and add 3-state engagement tracking.

**Architecture:** Rewrite `threat_map.html` template with CSS hex grid. Add `HEX_ROWS` and `CATEGORY_COLORS` to `threat_map.py`. Fix Operator hash routing to parse `walkthrough/<lab_name>`. Add `cztz_viewed_*` localStorage writes in `enterLab()`. Flask route unchanged.

**Tech Stack:** Flask/Jinja2, CSS clip-path hexagons, vanilla JS, localStorage, pytest 100% coverage.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `frontend/threat_map.py` | Modify | Add `HEX_ROWS`, `CATEGORY_COLORS`, `get_lab_category()` |
| `frontend/templates/threat_map.html` | Rewrite | Hex honeycomb with flyout, 3-state progress, reset |
| `frontend/templates/operator.html` | Modify | Deep-link hash parsing + `cztz_viewed_*` in `enterLab()` |
| `frontend/app.py` | Modify | Pass `CATEGORY_COLORS` and row data to template |
| `tests/test_threat_map.py` | Modify | Hex-specific assertions |
| `tests/test_operator.py` | Modify | Deep-link hash test |

---

### Task 1: Add hex layout metadata to `threat_map.py`

**Files:**
- Modify: `frontend/threat_map.py`
- Test: `tests/test_threat_map.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_threat_map.py`:

```python
def test_hex_rows_total_25(threat_map_mod):
    rows = threat_map_mod.HEX_ROWS
    total = sum(len(r) for r in rows)
    assert total == 25
    assert len(rows) == 5


def test_hex_rows_all_labs_present(threat_map_mod):
    all_from_rows = [lab for row in threat_map_mod.HEX_ROWS for lab in row]
    all_from_groups = [lab for g in threat_map_mod.CATEGORY_GROUPS for lab in g["labs"]]
    assert sorted(all_from_rows) == sorted(all_from_groups)


def test_category_colors_cover_all_groups(threat_map_mod):
    for g in threat_map_mod.CATEGORY_GROUPS:
        assert g["name"] in threat_map_mod.CATEGORY_COLORS


def test_get_lab_category(threat_map_mod):
    assert threat_map_mod.get_lab_category("auth_lab") == "Identity & Access"
    assert threat_map_mod.get_lab_category("egress_lab") == "Data & Secrets"
    assert threat_map_mod.get_lab_category("nonexistent") == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_threat_map.py -v -k "hex_rows or category_colors or get_lab_category"`
Expected: FAIL — `AttributeError: module 'threat_map' has no attribute 'HEX_ROWS'`

- [ ] **Step 3: Add data structures to `frontend/threat_map.py`**

Append after `CATEGORY_GROUPS` (before `has_walkthrough`):

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_threat_map.py -v`
Expected: all pass

- [ ] **Step 5: Commit**

```
feat(threat-map): hex layout metadata — row assignments, category colors, lab-to-category lookup
```

---

### Task 2: Fix Operator deep-links and add viewed state

**Files:**
- Modify: `frontend/templates/operator.html`
- Test: `tests/test_operator.py`

- [ ] **Step 1: Write failing test for deep-link parsing**

Add to `tests/test_operator.py`:

```python
def test_operator_deeplink_hash_parsing(frontend_client):
    client, _ = frontend_client
    resp = client.get("/operator")
    html = resp.data.decode()
    assert "walkthrough/" in html
    assert "enterLab(" in html


def test_operator_writes_viewed_state(frontend_client):
    client, _ = frontend_client
    resp = client.get("/operator")
    html = resp.data.decode()
    assert "cztz_viewed_" in html
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_operator.py::test_operator_deeplink_hash_parsing tests/test_operator.py::test_operator_writes_viewed_state -v`
Expected: at least `test_operator_writes_viewed_state` FAIL (no `cztz_viewed_` string in current template)

- [ ] **Step 3: Fix hash routing in `operator.html`**

In `frontend/templates/operator.html`, replace the init IIFE (around line 300-304):

```javascript
(function(){
  var hash=location.hash.replace('#','');
  if(hash==='qa'||hash==='walkthrough') switchTab(hash);
  else switchTab('walkthrough');
})();
```

With:

```javascript
(function(){
  var hash=location.hash.replace('#','');
  if(hash==='qa'){
    switchTab('qa');
  } else if(hash.indexOf('walkthrough/')===0){
    var labName=hash.split('/')[1];
    switchTab('walkthrough');
    if(labName) enterLab(labName);
  } else {
    switchTab('walkthrough');
  }
})();
```

- [ ] **Step 4: Add `cztz_viewed_*` write in `enterLab()`**

In the `enterLab` function (around line 391-418), add after `if(!_currentLabData)return;`:

```javascript
  var _tid=_currentLabData.threat_id;
  if(_tid) localStorage.setItem('cztz_viewed_'+_tid,'true');
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_operator.py -v`
Expected: all pass

- [ ] **Step 6: Commit**

```
fix(operator): deep-link hash routing for walkthrough/<lab> and viewed state tracking
```

---

### Task 3: Rewrite Threat Map template as hex honeycomb

**Files:**
- Modify: `frontend/app.py` (pass extra data to template)
- Rewrite: `frontend/templates/threat_map.html`
- Modify: `tests/test_threat_map.py`

- [ ] **Step 1: Update failing test assertions for hex elements**

Replace `test_threat_map_has_all_25_cards` and `test_threat_map_has_category_groups` in `tests/test_threat_map.py`:

```python
def test_threat_map_has_all_25_hexes(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert html.count('class="hex ') == 25
    assert html.count('data-lab="') == 25


def test_threat_map_has_category_colors(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    for css_class in ["identity", "data", "tool", "delegation", "observation", "ai", "isolation"]:
        assert f"hex {css_class}" in html


def test_threat_map_has_flyout_structure(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert "hex-flyout" in html


def test_threat_map_tracks_viewed_state(frontend_client):
    client, _ = frontend_client
    resp = client.get("/threat-map")
    html = resp.data.decode()
    assert "cztz_viewed_" in html
    assert "cztz_solved_" in html
```

Remove the old `test_threat_map_has_all_25_cards` and `test_threat_map_has_category_groups` functions.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_threat_map.py -v`
Expected: new hex tests FAIL

- [ ] **Step 3: Update `frontend/app.py` route to pass hex data**

Replace the `threat_map` route with:

```python
@app.route("/threat-map")
def threat_map() -> str:
    from threat_map import CATEGORY_COLORS, CATEGORY_GROUPS, HEX_ROWS, get_lab_category, has_walkthrough
    from qa_runner.walkthroughs import WALKTHROUGHS

    all_scenarios = _fetch_scenarios()
    scenario_map = {s["module_name"]: s for s in all_scenarios}

    rows = []
    for row_idx, row_labs in enumerate(HEX_ROWS):
        row = []
        for lab_name in row_labs:
            sc = scenario_map.get(lab_name, {})
            cat_name = get_lab_category(lab_name)
            cat_css = CATEGORY_COLORS.get(cat_name, {}).get("css", "")
            row.append({
                "name": lab_name,
                "threat_id": sc.get("threat_id", ""),
                "title": sc.get("title", lab_name.replace("_", " ").title()),
                "description": sc.get("description", ""),
                "category": cat_name,
                "cat_css": cat_css,
                "has_walkthrough": has_walkthrough(lab_name),
                "step_count": len(WALKTHROUGHS.get(lab_name, [])),
            })
        rows.append({"labs": row, "offset": row_idx % 2 == 1})

    groups = []
    for group in CATEGORY_GROUPS:
        groups.append({"name": group["name"], "blurb": group["blurb"], "labs": group["labs"]})

    return render_template(
        "threat_map.html",
        rows=rows,
        groups=groups,
        colors=CATEGORY_COLORS,
        total_labs=25,
    )
```

- [ ] **Step 4: Rewrite `frontend/templates/threat_map.html`**

Full rewrite with hex honeycomb layout. The template must:
- Use CSS `clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)` for hexes
- Hex size ~72×82px
- Each hex: `class="hex <cat_css>"`, `data-lab="<name>"`, `data-tid="<threat_id>"`
- Category color gradients from `CATEGORY_COLORS`
- 3-state CSS: `.hex.untouched` (opacity 0.35), `.hex.viewed` (opacity 0.7, amber shadow), `.hex.solved` (opacity 1.0, green shadow)
- Flyout panel (`hex-flyout`) with title, description, state badge, Challenge + Walkthrough buttons
- Summary bar: engaged count + solved count + progress bar + color legend + state legend
- Reset button clearing both `cztz_viewed_*` and `cztz_solved_*`
- JS reads localStorage for both key patterns, applies state classes, counts for summary

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_threat_map.py -v`
Expected: all pass

- [ ] **Step 6: Commit**

```
feat(threat-map): hex honeycomb territory layout with 3-state engagement and flyout
```

---

### Task 4: Full test suite and coverage

**Files:**
- All test files

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest -q`
Expected: all pass, 100% coverage

- [ ] **Step 2: Fix any coverage gaps**

If new branches in `threat_map.py` or `app.py` are uncovered, add targeted tests.

- [ ] **Step 3: Commit any fixes**

```
test: coverage for hex threat map and operator deep-links
```

---

### Task 5: Deploy and verify

**Files:** None (operational)

- [ ] **Step 1: Rebuild local Docker Compose**

Run: `make down && make up`

- [ ] **Step 2: Verify locally**

Open `http://localhost:3000/threat-map` — confirm hex honeycomb renders with 25 hexes, category colors, flyout on click, walkthrough links work.

Open `http://localhost:3000/operator#walkthrough/auth_lab` — confirm it deep-links directly into auth_lab player (not the picker).

- [ ] **Step 3: Sync and deploy to NUC**

```bash
rsync -avz -e "ssh -i ~/HTB/Artifice/OG_id_ed25519" --exclude='.venv' --exclude='__pycache__' --exclude='.git/' /Users/tms/camazotz/ root@192.168.1.114:/opt/camazotz/
ssh -i ~/HTB/Artifice/OG_id_ed25519 root@192.168.1.114 'cd /opt/camazotz && bash kube/deploy.sh'
ssh -i ~/HTB/Artifice/OG_id_ed25519 root@192.168.1.114 'sudo k3s kubectl -n camazotz rollout restart deployment/brain-gateway deployment/portal deployment/observer'
```

- [ ] **Step 4: Verify on NUC**

Open `http://192.168.1.114:3000/threat-map` — confirm hex layout.

Open `http://192.168.1.114:3000/operator#walkthrough/auth_lab` — confirm deep-link.

Run: `uv run python scripts/smoke_test.py --target k8s --k8s-host 192.168.1.114 --require-llm`

- [ ] **Step 5: Commit any deploy fixes**

```
fix: deploy adjustments for hex threat map
```
