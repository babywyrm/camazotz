# Threat Map v2 — Hex Territory Redesign

**Date:** 2026-04-08
**Status:** Approved
**Replaces:** 2026-04-08-threat-map-and-walkthrough-links-design.md (visual layer only — route, taxonomy, and walkthrough links remain)

## Problems Solved

1. **Walkthrough deep-links are broken.** `/operator#walkthrough/auth_lab` lands on the generic lab picker because the Operator JS only checks for `hash === 'walkthrough'`, never parsing the lab name suffix.
2. **Progress tracking is misleading.** The page reads `cztz_solved_*` (flag captures only) but most learners engage via walkthroughs long before capturing flags. The map shows 0/25 for active learners.
3. **The "map" is just a card grid.** Category-grouped cards are a reorganized Challenges page. It doesn't feel like a landscape or territory.

## Design

### Hex Territory Layout

The `/threat-map` page is rebuilt with a honeycomb of hexagonal tiles. Each of the 25 labs is one hex. Hexes are arranged in a 5-column honeycomb (5 rows, alternating offset) and color-coded by threat category.

**Hex size:** ~72×82px — large enough for threat ID + short lab name without squinting.

**Category colors (CSS gradients):**

| Category | Primary | Dark |
|----------|---------|------|
| Identity & Access | `#7c3aed` | `#4c1d95` |
| Data & Secrets | `#2563eb` | `#1e3a8a` |
| Tool & Supply Chain | `#d97706` | `#92400e` |
| Delegation & Trust | `#059669` | `#064e3b` |
| Observation & Evasion | `#dc2626` | `#7f1d1d` |
| AI Behavior | `#0891b2` | `#164e63` |
| Isolation | `#6b7280` | `#374151` |

**Honeycomb row assignments (5 per row):**

| Row | Hexes |
|-----|-------|
| 1 | auth, rbac, oauth_delegation, credential_broker, secrets |
| 2 (offset) | context, egress, tool, supply, pattern_downgrade |
| 3 | relay, delegation_chain, attribution, revocation, shadow |
| 4 (offset) | comms, audit, notification, hallucination, indirect |
| 5 | config, cost_exhaustion, tenant, error, temporal |

### 3-State Engagement Model

Each hex has one of three visual states driven by localStorage:

| State | localStorage key | Visual |
|-------|-----------------|--------|
| `untouched` | neither key present | 35% opacity, no glow |
| `viewed` | `cztz_viewed_<threat_id>` = `"true"` | 70% opacity, amber box-shadow |
| `solved` | `cztz_solved_<threat_id>` = `"true"` | 100% opacity, green box-shadow |

`solved` takes precedence over `viewed` (if both are set, show `solved`).

**Setting `viewed`:** The Operator walkthrough player writes `cztz_viewed_<threat_id>` to localStorage inside `enterLab()`. The `_walkthroughLabs` data already contains `threat_id` per lab.

**Setting `solved`:** Unchanged — the challenge detail page writes `cztz_solved_<threat_id>` on successful flag submission (already works).

### Hex Click Interaction

Clicking a hex opens a **flyout panel** positioned below the hex:
- Lab title and one-line description
- Threat ID badge
- Current state badge (untouched / viewed / solved)
- Two action buttons:
  - **"Challenge"** → `/challenges/<threat_id>`
  - **"Walkthrough"** → `/operator#walkthrough/<lab_name>` (deep-link)
- Clicking another hex or clicking outside closes the flyout

### Summary Bar

Top of page, above the honeycomb:
- "X of 25 engaged" (count of labs that are `viewed` or `solved`)
- "Y flags captured" (count of `solved` only)
- Horizontal progress bar showing engaged percentage
- Color legend for the 7 categories
- State legend: ○ untouched, ◐ viewed, ● solved

### Deep-Link Fix (Operator)

The Operator init JS (`operator.html`) is updated:

**Current (broken):**
```javascript
var hash = location.hash.replace('#', '');
if (hash === 'qa' || hash === 'walkthrough') switchTab(hash);
else switchTab('walkthrough');
```

**Fixed:**
```javascript
var hash = location.hash.replace('#', '');
if (hash === 'qa') {
  switchTab('qa');
} else if (hash.indexOf('walkthrough/') === 0) {
  var labName = hash.split('/')[1];
  switchTab('walkthrough');
  if (labName) enterLab(labName);
} else {
  switchTab('walkthrough');
}
```

This makes `/operator#walkthrough/auth_lab` immediately open the auth_lab walkthrough player.

### Reset

The "Reset Progress" button on the threat map clears both key patterns:
- All `cztz_solved_*` keys
- All `cztz_viewed_*` keys
- Calls `POST /api/reset` to clear gateway state

## Files Changed

| File | Action | What |
|------|--------|------|
| `frontend/templates/threat_map.html` | Rewrite | Hex honeycomb layout replaces card grid |
| `frontend/templates/operator.html` | Modify | Hash deep-link parsing + `cztz_viewed_*` write in `enterLab()` |
| `frontend/threat_map.py` | Modify | Add `HEX_ROWS` (list of 5 lists assigning labs to rows), `CATEGORY_COLORS` (dict mapping category name to primary/dark color pair) |
| `tests/test_threat_map.py` | Modify | Update assertions for hex elements |
| `tests/test_operator.py` | Modify | Add deep-link hash parsing test |

## Files Unchanged

- `frontend/app.py` — route stays the same, data passed to template unchanged
- `frontend/templates/base.html` — nav link already present
- `frontend/templates/challenge_detail.html` — walkthrough callout already present
- `frontend/templates/scenarios.html` — walkthrough pill already present
- `frontend/threat_map.py` CATEGORY_GROUPS — taxonomy and blurbs unchanged

## Testing

- Hex count: rendered HTML contains 25 elements with hex class and `data-lab` attribute
- Category colors: each hex has a category CSS class
- Progress states: template JS reads both `cztz_viewed_*` and `cztz_solved_*`
- Flyout: hexes have `data-lab` and `data-tid` for JS interaction
- Deep-link: operator template contains `walkthrough/` hash parsing with `enterLab()` call
- Viewed state write: operator template writes `cztz_viewed_` in `enterLab()`
- Reset: button clears both `cztz_solved_*` and `cztz_viewed_*` patterns
- Summary bar: renders engaged count and solved count
- Coverage: 100% maintained

## Out of Scope

- Server-side progress storage
- Dedicated mobile hex layout (CSS handles reasonable breakpoints)
- Animated state transitions
- Hex drag/rearrange

## Exit Criteria

- Hex honeycomb renders 25 labs with category colors and 3-state engagement glow
- Clicking a hex opens flyout with working challenge + walkthrough links
- `/operator#walkthrough/auth_lab` deep-links directly into auth_lab player
- Opening a walkthrough marks the lab as `viewed` on the threat map
- All tests pass at 100% coverage
- Deployed and verified on local Compose and NUC k3s
