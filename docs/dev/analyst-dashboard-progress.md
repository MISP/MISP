# Analyst Dashboard — Implementation Progress Tracker

**Source of truth for what's spec'd, what's built, what's next.** A fresh
session picks up the work by reading [`analyst-dashboard-prd.md`](analyst-dashboard-prd.md)
for the spec (roster §3, per-widget detail §5, **AD-NN** decision log §6) and
**this file** for state. This is the analyst-track sibling of
[`dashboard-progress.md`](dashboard-progress.md); the two tracks share the
`dashboards` branch and ship together (see [`analyst-dashboard-handoff.md`](analyst-dashboard-handoff.md)).

## How to use this file

- This track works in two stages: **spec** (discuss → decide → record an
  AD-NN; widget row reaches `DECIDED` in PRD §3) then **build** (the task
  checklist below). We are currently **spec-first**: speccing widgets ahead
  of writing any code, by the user's choice.
- Tasks are checked off **one at a time** as they complete — no batching, no
  pre-checking. **One task = one commit** (see `feedback_commit_per_task`).
  Stage only the files the task touched plus this tracker — never `git add -A`.
  Commit format:

  ```
  new: [analyst-dashboard] <short imperative summary>

  Closes <Wn build task / spec task> as it appears in this file.
  ```

  `new:` additions, `chg:` changes/refactors, `fix:` bug fixes (CLAUDE.md).
- Build phases run **strictly sequentially** (`feedback_sequential_implementation`);
  research/lookups may parallelise, code writing never.
- On task close, append a **Done note** (1–3 lines: what was done, paths
  touched, any surprise). Done note + commit hash = the audit trail.
- Blocked task → mark `[~]` + a `Blocked by:` line; don't check or commit it.
- **Additive-only** (`feedback_additive_only_posture`): new widgets + the one
  new render kind = pure additions; touching an existing widget needs sign-off.

## Live test instance

`http://localhost:5007/dashboards` — admin user 1 `admin@admin.test` /
`Password12345`, Overmind theme. DB `mysql -u misp -pPassword1234 misp`;
Redis `redis-cli -n 13` (data), db0 sessions. Full recipe in the handoff.

## Status legend

- `[ ]` not started
- `[~]` in progress / blocked (one at a time max)
- `[x]` done (Done note + commit hash follows)

## Spec status (mirrors PRD §3 roster)

| ID | Widget | Spec | Build |
|----|--------|------|-------|
| AD-W1 | Trending engine (parametrised) | `DECIDED` (AD-01..04) | `[ ]` not started — **first build unit** |
| AD-W2 | Trending vulnerabilities (dim of W1) | `DECIDED` (AD-09) | `[ ]` not started |
| AD-W3 | Trending threat actors (dim of W1) | `DECIDED` (AD-10) | `[ ]` not started |
| AD-W4 | Trending attack techniques (dim of W1) | `DECIDED` (AD-11) | `[ ]` not started |
| AD-W5 | ATT&CK matrix heatmap (existing) | `DECIDED` (AD-12) | `[ ]` not started |
| AD-W6 | Event-stream rework | `DECIDED` (AD-08) | `[ ]` not started |
| AD-W7 | New-data stats (StatGrid + deltas) | `DECIDED` (AD-05..07) | `[ ]` not started |
| AD-W8 | Overlap-with-my-org | `DECIDED` (AD-13) | `[ ]` not started |
| AD-W9 | Sightings rework | `DEFERRED` | — look-and-feel only; revisit post-build |

## Spec log (this track's planning tasks)

- [x] **Track kick-off** — mini-PRD + handoff created; AD-W1 fully decided
  (AD-01..04). *(commit `e0453e3e0`)*
- [x] **AD-W7 spec → DECIDED** — anchor (AD-05), aggregate-count ACL
  relaxation (AD-06), full W7 spec (AD-07). Resolved AD-W1's deferred window
  anchor en route. Split this progress tracker out.
- [x] **AD-W6 spec → DECIDED** — flat detailed cards (Fork A); read-only,
  filters via existing toolbar bulk-edit (Fork B); additive subclass
  `EventStreamCardsWidget` + new `EventCards` render kind. (AD-08.)
- [x] **AD-W2 spec → DECIDED** — Trending Vulnerabilities: all `vulnerability`
  IDs (CVE/GCVE/GHSA), distinct-event count **ACL-scoped** (the watch-out;
  AD-06 skip-ACL applies only to scale-counts, never value-rankings), cveurl
  link-out (default corrected to `vulnerability.circl.lu/vuln/`). (AD-09.)
- [x] **AD-W3 spec → DECIDED** — Trending threat actors: `threat-actor` galaxy
  only (sidesteps cross-galaxy identity merge); distinct-event count over
  EventTag ∪ AttributeTag, **ACL-scoped** (note: `AttributeTag::countForTags`
  skips ACL — unusable as-is); per-cluster resolved label (value+icon+synonyms),
  link to /galaxy_clusters/view/<id>. (AD-10.)
- [x] **AD-W4 spec → DECIDED** — Trending attack techniques: `mitre-attack-
  pattern` (Enterprise) only; reuses W3's ACL-correct count with the tag-id set
  grouped by **parent technique** (sub-techniques roll up); DISTINCT from W5
  (ranked list + momentum vs spatial matrix). (AD-11.)
- [x] **AD-W5 spec → DECIDED** — wire AttackWidget to the global `time_window`
  canonical **in-place** (first additive-only sign-off granted); map it into
  the restSearch 'attack' timestamp filter; manual filters preserved. (AD-12.)
- [x] **AD-W8 spec → DECIDED** — Overlap-with-my-org: correlation-based (reuse
  `getRelatedEventIds` — ACL-correct + engine-agnostic), reference set =
  events my org created (`orgc_id`); window-anchored build (no org_id scan, no
  schema change); render = reuse W6 EventCards + overlap badge. (AD-13.)
- [ ] **AD-W9** — DEFERRED (look-and-feel-only rework of `RecentSightingsWidget`;
  sighting engine slow/unused by some — revisit after the render kinds exist).
  No spec needed now; the roster is otherwise fully DECIDED.

**✅ SPEC PHASE COMPLETE (2026-06-01)** — W1–W8 all DECIDED (AD-01..13); W9
deferred. The work is now BUILD, starting at Phase B1 (W1 engine). Confirm with
the user before starting (they may recompose the analyst `template.json` first).

## Build backlog (ordered by confirmed build order)

Build order: **W1 → W7 → W6 → (W2/W3/W4) → W5 → W8 → W9**. Engine first
(W2/W3/W4 are its dimensions); stats next (cheapest standalone win); then
event-stream; dimensions; heatmap wiring; the hard/soft pair last. No build
task starts until the user moves the track out of spec-first mode.

### Phase B1 — AD-W1 Trending engine (on deck; fully DECIDED)

- [ ] New render kind **`Trending`** — `Trending.ctp` ranked-row list (label ·
  inline volume bar · count · `▲/▼` delta badge). Token-driven CSS, no inline
  styles (mirror `StatGrid.ctp`).
- [ ] Glyph for `Trending` in `render-thumbs.mjs` (**CLAUDE.md rule** — new
  render kind ⇒ glyph): `thumbTrending()` + REGISTRY entry.
- [ ] `TrendingWidget` class — `dimension` config + per-dimension hooks
  (counting strategy, label resolver, drill-down link builder).
- [ ] Counting (AD-02): `COUNT(DISTINCT event_id)` over event-tag ∪
  attribute-tag ∪ attribute-value, off `EventTag`/`AttributeTag`/`Attribute`
  (no event hydration; `AttributeTag.event_id` confirmed present).
- [ ] Momentum (AD-03): floored-% delta vs prior equal window; configurable
  min current-window count before "rising" is flagged.
- [ ] Cache/ACL (AD-04): per-org `cache_scope`, site-admin no-ACL bucket,
  lazy-load on render, ~15–30 min/org, source = all events incl. unpublished.
- [ ] Visual verification on the live instance (real render path, not a
  hand-built payload — see `project_dashboard_ctp_payload_passthrough`).

### Phase B2 — AD-W7 New-data stats (DECIDED; build-deferred)

- [ ] `NewDataStatsWidget` (`render = 'StatGrid'`) — 4 metrics, `value` =
  window count, `change` = delta vs prior equal window (AD-07).
- [ ] Metrics 1–2 global counts (no ACL, AD-06); metric 3 targeting waterfall
  (config → org meta → org-name ccTLD → N/A); metric 4 `orgc_id`+`published`.
- [ ] ccTLD→country resolver from `country.json` (`meta.tld`/`ISO`).
- [ ] Cache split (AD-06): global / `(country,sector)` / `orgc_id` keys.
- [ ] Visual verification on the live instance.

### Phase B3 — AD-W6 Event-stream rework (DECIDED; build-deferred)

- [ ] New render kind **`EventCards`** — `EventCards.ctp` flat reverse-chron
  cards (threat dot · org · relative time · #id · info · tag chips · attr
  count) from the `fetchEvent` payload. Token-driven CSS, no inline styles;
  reuse `Index.ctp`'s tag-chip colour + contrast helper.
- [ ] Glyph for `EventCards` in `render-thumbs.mjs` (stacked-cards shape;
  **CLAUDE.md rule**): `thumbEventCards()` + REGISTRY entry.
- [ ] `EventStreamCardsWidget extends EventStreamWidget` — override `$render` =
  `EventCards`, `$title`, `$description`; inherit the canonical-filter data
  layer + `$schema` verbatim (toolbar-bulk-editable). `handler()` untouched.
- [ ] Read-only confirm: no in-body controls; filters via toolbar bulk-edit.
  Near-live (`autoRefreshDelay = 5` inherited); no cache (per-user ACL'd
  `fetchEvent`).
- [ ] Visual verification on the live instance (real render path).

### Phase B4 — AD-W2 Trending Vulnerabilities dimension (DECIDED; needs B1 engine)

*A `dimension` config + per-dimension hooks on the built W1 engine — not a new
widget. Depends on Phase B1.*

- [ ] `vulnerability` dimension config: counting = `COUNT(DISTINCT event_id)`
  over `type='vulnerability' AND deleted=0` grouped by `value1` (attribute-value
  arm only; tag arms empty for CVEs).
- [ ] **ACL-correct count** (primary risk): constrain to the org's visible
  event set (reuse `Attribute` ACL conditions; no event hydration); cache
  per-org (AD-04); site-admin no-ACL bucket.
- [ ] Window anchor `Attribute.timestamp` (AD-05); momentum AD-03.
- [ ] Label resolver = identifier verbatim; link builder = `MISP.cveurl` +
  value (`{cveurl}{value}`).
- [ ] Visual verification on the live instance.

### Phase B5 — AD-W3 Trending Threat Actors dimension (DECIDED; needs B1 engine)

*A `dimension` config + hooks on the built W1 engine. Depends on Phase B1.*

- [ ] `threat-actor` dimension config: tag-id set = `tags WHERE is_galaxy=1 AND
  name LIKE 'misp-galaxy:threat-actor="%'`.
- [ ] **ACL-correct union-distinct count** (primary risk): `COUNT(DISTINCT
  event_id)` over EventTag ∪ AttributeTag for those tag_ids, ACL-scoped to the
  org's visible events — do NOT reuse `AttributeTag::countForTags` (skips ACL,
  counts occurrences). Cache per-org; site-admin no-ACL bucket.
- [ ] Anchors per AD-05 (event-tag→Event.timestamp, attr-tag→Attribute.timestamp);
  momentum AD-03.
- [ ] Label resolver: bulk-resolve top-N clusters → value + Galaxy.icon +
  synonyms (avoid N+1). Link builder = /galaxy_clusters/view/<id>.
- [ ] Visual verification on the live instance.

### Phase B6 — AD-W4 Trending Attack Techniques dimension (DECIDED; needs B1 engine)

*A `dimension` config on the W1 engine, reusing W3's count machinery. Depends
on B1 (and shares B5's ACL-correct union-distinct count).*

- [ ] `mitre-attack-pattern` dimension config: tag-id set = Enterprise
  attack-pattern cluster tags, **grouped by parent technique** (sub-technique
  external_id `T1566.001` → parent `T1566`, ".NNN" stripped).
- [ ] ACL-correct distinct-event count at the parent-technique level (reuse the
  B5 union-distinct count); cache per-org.
- [ ] Anchors AD-05; momentum AD-03.
- [ ] Label resolver: parent cluster `value` + `external_id` + Galaxy.icon
  (`map`), bulk-resolved; link = /galaxy_clusters/view/<parent_id>.
- [ ] Visual verification + confirm DISTINCT from the W5 heatmap on the board.

### Phase B7 — AD-W5 ATT&CK heatmap time_window wiring (DECIDED; in-place edit)

*Touches existing `AttackWidget` — additive-only sign-off granted (AD-12).*

- [ ] Add `time_window` canonical to `AttackWidget::$schema` (currently `[]`).
- [ ] In `handler()`, map `time_window` → restSearch 'attack' `timestamp`
  filter (reuse the in-tree translation; `-1` ⇒ no bound); merge without
  clobbering manual `attackGalaxy`/`published`.
- [ ] Confirm cache key includes the window; verify toolbar bulk-edit drives it.
- [ ] Visual verification on the live instance (heatmap re-scopes with board).

### Phase B8 — AD-W8 Overlap-with-my-org (DECIDED; needs B1 + B3 EventCards)

*New widget; reuses the W6 `EventCards` render. Depends on B3 (EventCards).*

- [ ] `OverlapWithMyOrgWidget` (`render = 'EventCards'`): candidate set =
  ACL-visible window events (`Event.timestamp` in window), capped top-N recent
  (`log()` if capped).
- [ ] For each candidate, `Correlation->getRelatedEventIds($user, id, sgids)`;
  keep iff a related event's `orgc_id` = my org. Overlap strength = # of my-org
  events it correlates to; rank desc then recency.
- [ ] EventCards + "overlaps N of your events" badge; per-org cache (AD-04).
- [ ] Verify across correlation engines (Default at minimum; note OnDemand path
  is reused for free via getRelatedEventIds).
- [ ] Visual verification on the live instance.

*(W9 deferred — look-and-feel-only reskin of RecentSightingsWidget, after the
render kinds land.)*

## Discovered work

*(none yet — file here with introduces-what / why / where-it-goes notes.)*
