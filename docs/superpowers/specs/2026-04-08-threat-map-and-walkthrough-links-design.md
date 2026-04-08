# Threat Map & Contextual Walkthrough Links

**Date:** 2026-04-08
**Status:** Approved

## Goal

Make Camazotz a living, breathing teachable resource for three audiences
(security professionals, developers, workshop students) by adding:

1. A **Threat Map** page that visualises the 25-lab landscape with progress tracking.
2. **Contextual walkthrough links** that bridge challenges, scenarios, and the map
   into the (still hidden) Operator walkthrough player.

## Audience

- Security professionals doing self-study on MCP/agentic risks.
- Developers building with AI tools who need to understand failure modes.
- Students in workshops/CTFs who need structured guidance and a sense of completion.

The design layers information so each audience can engage at the depth they want.

## Feature 1: Threat Map Page

### Route and navigation

- `GET /threat-map` — new page, added to the main nav between "Challenges" and
  "Observer" (label: **Threat Map**).

### Data source

No new backend data model. The page assembles its content from:

- Lab module class attributes (`name`, `threat_id`, `title`, `category`) via the
  existing gateway tools/list or scenario loader.
- Walkthrough registry (`WALKTHROUGHS` from `qa_runner.walkthroughs`) for step counts
  and walkthrough availability.
- `localStorage` for challenge solve status (same key pattern as the Challenges page).

### Layout

**Summary bar** (top of page):
- "X of 25 labs completed" progress indicator.
- Category breakdown chips (e.g. "SSRF 0/2", "Identity 1/4") showing per-group
  completion.

**Category groups** (body):
- Labs are grouped under ~7 display categories (see taxonomy below).
- Each group has a heading and a 1-2 sentence teaching blurb that orients learners
  to the risk area.
- Within each group, labs are displayed as a horizontal row of compact cards.

**Lab card** (compact):
- Threat ID badge (e.g. `MCP-T06`).
- Lab title.
- One-line description.
- Guardrail sensitivity hint (which levels are vulnerable vs. protected).
- Solve status badge (green checkmark from localStorage, or empty circle).
- Walkthrough link icon (only if a walkthrough exists for this lab in `WALKTHROUGHS`).
  Links to `/operator#walkthrough/<lab_name>`.

### Category taxonomy

Labs are consolidated from their per-module `category` attribute into ~7 display
groups so the map is scannable rather than 25 groups of 1:

| Display Group          | Labs                                                    |
|------------------------|---------------------------------------------------------|
| Identity & Access      | auth_lab, rbac_lab, oauth_delegation_lab, credential_broker_lab |
| Data & Secrets         | secrets_lab, context_lab, egress_lab                    |
| Tool & Supply Chain    | tool_lab, supply_lab, pattern_downgrade_lab              |
| Delegation & Trust     | relay_lab, delegation_chain_lab, attribution_lab, revocation_lab |
| Observation & Evasion  | shadow_lab, comms_lab, audit_lab, notification_lab       |
| AI Behavior            | hallucination_lab, indirect_lab, config_lab, cost_exhaustion_lab |
| Isolation              | tenant_lab, error_lab, temporal_lab                     |

Each group heading includes a short teaching blurb, e.g.:

> **Identity & Access:** Can an attacker trick the AI into issuing credentials or
> escalating privileges? These labs explore confused-deputy token issuance, RBAC
> bypass, and delegation abuse.

### Solve status and progress

- Solve status is read from `localStorage` using the same key pattern the Challenges
  page already writes: `cztz_solved_<threat_id>` (value `"true"` when solved).
- The summary bar aggregates counts per group and overall.
- No server-side progress storage in this iteration.

### Reset

- A "Reset Progress" button on the page clears all `localStorage` solve keys.
- Optionally also hits `POST /api/reset` to clear gateway state (same as the
  existing nav Reset button).

## Feature 2: Contextual Walkthrough Links

### Where they appear

**Challenge detail page** (`challenge_detail.html`):
- A "Stuck? Watch the walkthrough" callout card below the hints section.
- Styled as a visible but non-intrusive card (amber/accent border, consistent with
  the existing insight callout pattern).
- Links to `/operator#walkthrough/<lab_name>`.

**Scenario cards** (`scenarios.html`):
- Each scenario with a matching walkthrough gets a small "Walkthrough" pill/link
  next to the existing hint toggle.
- Same deep-link pattern.

**Threat Map cards** (new page):
- Each lab card with a walkthrough gets a walkthrough link icon.
- The Threat Map becomes a navigation hub connecting to challenges, scenarios, and
  walkthroughs.

### Matching logic

- A walkthrough link renders only when the lab exists in `WALKTHROUGHS`.
- Challenge/scenario pages already know the `threat_id` and lab name; matching is a
  simple dict lookup.
- If no walkthrough exists for a lab, no link renders — no broken promises.

### Operator stays hidden

- The `/operator` route is NOT added to the main nav.
- Users reach it only through contextual bridges (challenge detail, scenario cards,
  threat map cards) or by knowing the URL directly.
- The Operator JS already handles `#walkthrough/<lab>` hash routing via `enterLab()`.

## Visual style

- Matches the existing dark theme and CSS variable system.
- Cards reuse the design language of the Challenges grid and Operator lab picker.
- Category group headers use the same style as Observer tab headers.
- Progress bar uses the `--accent` color variable.
- Walkthrough link callouts use the existing insight callout pattern (amber border).

## Testing

- **`GET /threat-map` route:** returns 200, renders template with nav link.
- **Card count:** template contains 25 lab cards.
- **Category grouping logic:** unit test that all 25 labs map to exactly the defined
  groups with no orphans.
- **Summary bar:** progress indicator renders with correct "0 of 25" default.
- **Walkthrough link availability:** helper function returns True only for labs in
  `WALKTHROUGHS`.
- **Challenge detail walkthrough link:** renders when walkthrough exists, absent when
  it does not.
- **Scenario walkthrough pill:** renders conditionally.
- **Reset clears localStorage keys:** covered by template assertion (button present)
  plus integration behaviour (JS-level, not unit-testable server-side).
- Coverage: maintain 100%.

## Out of scope (this iteration)

- Server-side progress storage or user accounts.
- EZ/MAX walkthrough parity (medium only, as today).
- Interactive dependency graph (Approach 2 from brainstorm).
- Scoring engine or timed workshop mode.
- Unhiding the Operator in the nav.

## Exit criteria

- Threat Map page is live, in nav, shows all 25 labs grouped by category with solve
  badges and walkthrough links.
- Challenge detail and scenario pages surface walkthrough links for labs that have
  walkthroughs.
- All tests pass at 100% coverage.
- Both local Compose and NUC k3s deployments updated and verified.
