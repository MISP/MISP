# Analyst Dashboard — Session handoff (2026-05-31 — TRACK KICK-OFF: mini-PRD created; AD-W1 trending engine fully DECIDED, AD-01..04)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD (deviation/companion to
  `dashboard-prd.md`). §3 = 9-widget roster (status per widget); §5 =
  per-widget detail; §6 = **AD-NN** decision log.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (planning; no code; PRD+handoff committed as kick-off)
- Created `analyst-dashboard-prd.md` (skeleton + roster + three-jobs framing).
- **AD-W1 (the trending engine) fully decided — AD-01..04.**
- Build order: **W1 → W7 → W6 → (W2/W3/W4) → W5 → W8 → W9**. **Next = W7.**

## Why this track (three analyst jobs)
The analyst board today is 5 v1-era widgets (TrendingAttributes/Tags, two
WorldMaps, RecentSightings) — all aggregate trends/maps, **no "what changed
since last login" surface**. This track delivers three jobs; every widget
must serve one:
1. **What's new** — event-stream rework (W6) + new-data stats (W7).
2. **What's rising** — parametrised trending engine (W1) + its dimensions
   (CVEs W2, threat actors W3, attack techniques W4) + ATT&CK heatmap (W5).
3. **What affects me** — overlap-with-my-org (W8); targeting-my-country/sector
   (a W7 metric).

**Recomposing the analyst `template.json` is the USER's job** — we build /
improve widgets; the user arranges the board.

## AD-W1 — the trending engine (DECIDED; reuse these facts verbatim)
- **One parametrised `Trending` widget** (AD-01), not N near-identical
  classes. `dimension` config; per-dimension hooks: counting strategy, label
  resolver, drill-down link builder. Dimensions: galaxy namespaces
  (threat-actor, attack-pattern, **+ free** malware/tool/sector), attribute
  types (CVE/vulnerability).
- **New render kind = ranked-row list** (AD-01): per row = label · inline
  volume bar · count · `▲/▼` delta badge (sparkline = later polish). **NOT
  BarChart** (can't carry the per-row badge). **Must add a glyph to
  `render-thumbs.mjs`** (CLAUDE.md rule).
- **Counting = distinct events containing the value, each event = 1** (AD-02).
  Union event-tag ∪ attribute/object-tag ∪ attribute-value →
  `COUNT(DISTINCT event_id)`. Off `EventTag`/`AttributeTag`/`Attribute`
  (connector tables; no event hydration). `AttributeTag.event_id` exists → no
  join needed. Resists per-org reporting process-noise (scanner dumping 10k
  identical CVEs = 1).
- **Momentum = floored-% delta vs prior equal window** (AD-03): volume-ranked
  list + per-row delta badge. Item must clear a configurable min
  current-window count before "rising" is flagged. **No spike detection**
  (cost; deferred).
- **Cache/ACL = per-org, lazy-loaded, all data** (AD-04): org = MISP's ACL
  atom → `cache_scope` by org (same-org users share visibility); site-admins =
  separate no-ACL bucket; NOT background-precomputed (cross-org leakage); NOT
  per-user; source = all events incl. unpublished; trending caches ~15–30
  min/org.

## Track-wide principle (carry to every widget)
**ACL-scoped aggregate widgets cache PER-ORG** (AD-04 generalises): never a
single shared blob, never per-user (org is the atom), site-admins bucketed
separately, lazy-loaded not background-precomputed. Freshness per-widget
(trending 15–30 min/org; event-stream near-live).

## Open per-widget circle-backs (carry — first-pass answers in PRD §5)
- **W7 (new-data stats) — NEXT.** `StatGrid` + per-org-cached deltas vs prior
  equal window. Starter metrics (user): new events, attribute count, events
  targeting my org's country/sector, new events published by my org. **Pin:**
  "new" = created (`timestamp`) vs published vs first-seen; exact targeting
  match (country and/or sector).
- **W2 (CVEs):** counting beyond event-tags is "trickier than it sounds" —
  user has ideas + **existing APIs**; **grill at W2**. Link-out via
  **`MISP.cveurl`** (default `https://cve.circl.lu`, ID embedded, e.g.
  `…/vuln/CVE-2026-10186`); covers CVE / GCVE / GitHub advisory. CVEs appear
  as tags **and** (much more prevalent) `vulnerability` attribute values.
- **W3 (threat actors):** attribute/object-level galaxy tags (not just
  EventTag); cluster resolution (name/synonyms/icon vs raw tag string).
- **W4 (techniques):** keep DISTINCT from the heatmap — ranked list + momentum
  vs the spatial matrix view.
- **W5 (ATT&CK heatmap):** existing `AttackWidget` (`render=Attack`,
  `restSearch 'attack'`); filters are manual — decide whether to wire it to
  the global `time_window`.
- **W6 (event stream):** data layer is good (rich canonical filters,
  toolbar-bulk-editable); rework the **visual** only — detailed **cards**,
  inline filter/scope/exclude controls, eye-catching. Undecided: **grouped
  digest vs ticker** — explore at W6. Near-live refresh (cheap).
- **W8 (overlap-with-my-org):** define "overlap" (correlations vs
  attribute-value intersection), cost, ACL. High value, tricky.
- **W9 (sightings):** likely **look-and-feel rework only** — sighting engine
  is slow and unused by some communities, so don't over-invest in a live "are
  my IOCs sighted?" engine.

## Conventions (carry)
- **AD-NN** decision numbering (this track), cross-linked to parent `DD-NN`.
- **Per-org cache** for ACL aggregates (above).
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + one
  new render kind = pure additions; touching existing widgets needs sign-off.
- **Sequential** ([[feedback_sequential_implementation]]): one widget at a
  time.
- **Commit per task; never `git add -A`; explicit `git add` +
  `git status --short`; sign (`%G?`=U).**
- **chgrp www-data** every edited web-served/app file incl. docs.
- New render kind ⇒ glyph in `render-thumbs.mjs` (CLAUDE.md).
- User wants **rigorous pushback + genuine forks via AskUserQuestion**, and to
  **re-verify rather than defend** when a premise is questioned.

## Live test instance (shared with the main track)
- `http://localhost:5007/dashboards` (302 w/o session, 200 with). Admin
  user 1 `admin@admin.test` / `Password12345`, Overmind theme. Cookie jar
  `/tmp/cj_stat.txt` (re-mint via [[reference-misp-login-dance]] if it 302s).
- DB `mysql -u misp -pPassword1234 misp`; Redis `redis-cli -n 13` (data),
  db0 sessions. Branch: `dashboards` — **no separate track branch** (user,
  2026-05-31: building both tracks solo; shipping dashboard v2 + the analyst
  widgets/defaults together in the next release).

## Quick-start for next session
1. Read this + `analyst-dashboard-prd.md` (§3 roster, §5 AD-W1, §6 AD-01..04).
2. **W1 is fully decided.** Next tracked widget is **W7 (new-data stats)** —
   pin the 4 metrics + the "new" definition, spec the per-org-cached deltas.
   (Or start *building* W1 engine-first if the user prefers — confirm.)
3. **Housekeeping (resolved 2026-05-31):** PRD + this handoff committed as the
   track kick-off; **no separate branch** — both tracks ride `dashboards` and
   ship together in the next release.
4. Watch context; refresh this handoff before wrapping.
