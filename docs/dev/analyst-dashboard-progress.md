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
| AD-W1 | Trending engine (parametrised) | `DECIDED` (AD-01..04) | `[x]` **BUILT** (Phase B1; vulnerability dim live) |
| AD-W2 | Trending vulnerabilities (dim of W1) | `DECIDED` (AD-09) | `[ ]` not started |
| AD-W3 | Trending threat actors (dim of W1) | `DECIDED` (AD-10) | `[ ]` not started |
| AD-W4 | Trending attack techniques (dim of W1) | `DECIDED` (AD-11) | `[ ]` not started |
| AD-W5 | ATT&CK matrix heatmap (existing) | `DECIDED` (AD-12) | `[ ]` not started |
| AD-W6 | Event-stream rework | `DECIDED` (AD-08) | `[x]` **BUILT** (Phase B3; EventCards render kind + subclass live) |
| AD-W7 | New-data stats (StatGrid + deltas) | `DECIDED` (AD-05..07) | `[x]` **BUILT** (Phase B2; 4 metrics live) |
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

- [x] New render kind **`Trending`** — `Trending.ctp` ranked-row list (label ·
  inline volume bar · count · `▲/▼` delta badge). Token-driven CSS, no inline
  styles (mirror `StatGrid.ctp`).
  *Done:* added `app/View/Elements/dashboard/Widgets/Trending.ctp` (flat
  row-list contract: `label`/`count`/`delta`/`badge`/`drilldown`/`title` —
  bare handler return is the row list, no `{data:}` wrapper, like StatGrid)
  + a token-driven `.misp-trending-*` block in `dashboard.default.css`. Bar
  width is the only inline value, carried as the `--misp-trending-fill`
  custom property (data-driven, same posture as `Index.ctp`'s tag chips);
  delta badge mirrors `.misp-stat-delta`. Galaxy-icon slot deferred to W3/W4
  (additive). Verified: `parallel-lint` clean, CSS braces balance.
- [x] Glyph for `Trending` in `render-thumbs.mjs` (**CLAUDE.md rule** — new
  render kind ⇒ glyph): `thumbTrending()` + REGISTRY entry.
  *Done:* added `thumbTrending()` (decreasing-width horizontal bars + a small
  up-arrow = "ranked + rising", distinct from SimpleList/BarChart) and
  registered it under `Trending:` in `REGISTRY`. `node --check` clean.
- [x] `TrendingWidget` class — `dimension` config + per-dimension hooks
  (counting strategy, label resolver, drill-down link builder).
  *Done (with B1.4 — one commit; a class without its count is
  non-functional):* `app/Lib/Dashboard/TrendingWidget.php`. `render='Trending'`,
  `dimension` is a plain config key (no `select` canonical type exists; one
  would touch the adapter → deferred), defaulted in `handler()`. `dimensions()`
  registry → per-dimension `count`/`labels` hook methods (a new dimension =
  additive entry + methods). Orchestration: parse window → count → arsort →
  top-N → resolve labels → flat rows for `Trending.ctp`. Runs **live/uncached**
  (cache is B1.6).
- [x] Counting (AD-02): `COUNT(DISTINCT event_id)` over event-tag ∪
  attribute-tag ∪ attribute-value, off `EventTag`/`AttributeTag`/`Attribute`
  (no event hydration; `AttributeTag.event_id` confirmed present).
  *Done:* built the ACL-correct distinct-event **mechanism** + the first arm
  (attribute-value, for the `vulnerability` dimension): candidate event ids
  from in-window rows → `aclVisibleEventIds()` (reuses
  `Event::createEventConditions($user)`; site-admin → all) → `COUNT(DISTINCT
  Attribute.event_id)` grouped by `value1`. Window-bounded both ends so no
  unbounded IN list. SQL validated on the dev DB (270 vuln attrs / 138
  distinct events; CVE-2017-11882 tops at 13). The **tag arms** (EventTag ∪
  AttributeTag) arrive with their galaxy dimensions in B5/B6 — additive count
  hooks on the same mechanism; do NOT reuse `*Tag::countForTags` (occurrence
  count + AttributeTag skips ACL — AD-10).
- [x] Momentum (AD-03): floored-% delta vs prior equal window; configurable
  min current-window count before "rising" is flagged.
  *Done:* count hook now takes explicit `[start, end]` bounds so `handler()`
  counts the current window `[now-w, now]` AND the non-overlapping prior
  window `[now-2w, now-w]` via the same hook. Per row (only if
  `count >= min_count`, default 3): `prior<=0` → `NEW` badge; else
  `delta = floor((cur-prior)/prior*100)` → ▲/▼ (0 → no badge). All-time
  (`-1`) → no prior window → no momentum. Added `min_count` to params/schema.
  Lint clean.
- [x] Cache/ACL (AD-04): per-org `cache_scope`, site-admin no-ACL bucket,
  lazy-load on render, ~15–30 min/org, source = all events incl. unpublished.
  *Done (user signed off Option A, 2026-06-01):* added an `'org'` scope to
  `WidgetCache` (additive — `user`/`global` untouched): key segment
  `o<org_id>:`, site admins → shared `sa:` no-ACL bucket, `remember()` fails
  safe to a live compute without a bucket. `TrendingWidget` declares
  `cache_scope='org'` + `cache_duration=1200` (20 min). Extended
  `WidgetCacheTest` with 6 org-scope cases (per-org sharing, org isolation,
  `sa:` separation, fail-safe) — **19 tests / 31 assertions green**.
- [x] Visual verification on the live instance (real render path, not a
  hand-built payload — see `project_dashboard_ctp_payload_passthrough`).
  *Done:* rendered `TrendingWidget` through the **real pipeline**
  (renderWidget → CanonicalTypeAdapter → WidgetCache `org`/`sa:` bucket →
  handler → render_widget.ctp → Trending.ctp). REST path (`time_window=-1`)
  matched the SQL exactly (CVE-2017-11882=13, …). A 4y split window
  (`1460d`, min_count=3) exercised momentum: CVE-2015-5465 ▲500% (6 vs 1),
  CVE-2017-11882 ▼58% (3 vs 7), CVE-2022-30190/42475 `NEW` (3 vs 0),
  count≤2 rows correctly badge-less. Web-UI HTML render produced correct
  `.misp-trending-*` markup (bar widths 100/50/33/17%); headless screenshot
  against the real CSS confirmed the styled visual (coloured ▲/▼/NEW badges,
  fill bars). **Phase B1 (W1 trending engine) COMPLETE.**

### Phase B2 — AD-W7 New-data stats (DECIDED; building)

*B2.1–B2.4 built as one commit — `NewDataStatsWidget` is one indivisible
additive class (the metrics, their scoping, the resolver and the per-metric
cache are woven through one file; a partial split isn't independently
meaningful), mirroring the B1.3+B1.4 combination. Four done-notes below.*

- [x] `NewDataStatsWidget` (`render = 'StatGrid'`) — 4 metrics, `value` =
  window count, `change` = delta vs prior equal window (AD-07).
  *Done:* `app/Lib/Dashboard/NewDataStatsWidget.php`. `render='StatGrid'`,
  `time_window` canonical (default `P7D`, AD-12) parsed exactly like
  `TrendingWidget` (adapter `P7D`→`7d`→seconds). Current window `[now-w, now]`
  + prior `[now-2w, now-w]` (AD-03); all-time (`-1`) → no prior → no delta.
  `deltaRow()` returns `title`/`icon`/`value`/`change`(+`drilldown`); StatGrid
  renders >0 ▲, <0 ▼, 0 = no badge. No new render kind, no glyph.
- [x] Metrics 1–2 global counts (no ACL, AD-06); metric 3 targeting waterfall
  (config → org meta → org-name ccTLD → N/A); metric 4 `orgc_id`+`published`.
  *Done:* m1 `COUNT(Event)` `Event.timestamp` window (global); m2
  `COUNT(Attribute)` `Attribute.timestamp` window `deleted=0` (global); m3
  `COUNT(DISTINCT Event.id)` over `EventTag` for the resolved country∪sector
  tag-ids, `Event.timestamp` window, **N/A when neither axis resolves**
  (resolved-but-untagged = a genuine 0); m4 `COUNT(Event)` `orgc_id`=me +
  `published=1` + `publish_timestamp` window (AD-05 exception — own-org publish
  is a genuine local act). Drilldowns relative + DD-03-safe (events/attributes
  index with `searchtimestamp`/`searchpublishtimestamp`/`searchorg`/`searchtag`).
- [x] ccTLD→country resolver from `country.json` (`meta.tld`/`ISO`).
  *Done:* reads `country.json`/`sector.json` `values` live (self-contained per
  AD-07; no DB/galaxy-import dependency for the mapping, unlike
  `AttributeGeoMapWidget`'s DB path), memoised. Country waterfall: config →
  `org.nationality` (value/ISO/ISO3, case-folded) → org-name ccTLD (`.lu`→
  cluster value) → null. Sector waterfall: config → `org.sector` → null.
  Explicit config overrides win even for non-cluster values. Bad/missing file
  degrades to the next tier.
- [x] Cache split (AD-06): global / `(country,sector)` / `orgc_id` keys.
  *Done:* **per-metric in-handler Redis cache, NOT the WidgetCache `org`
  scope** — these counts aren't ACL-scoped (AD-06), and the `org` scope's
  site-admin `sa:` no-ACL bucket would wrongly share metric 3/4 across
  different-org site admins. m1/m2 keyed global (one compute per instance,
  shared across orgs), m3 by `(country,sector)`, m4 by `o<orgc_id>`; keys
  carry the window **length** not the drifting `now`, so hits work within the
  ~5 min TTL (DD-19 posture). Degrades to live when Redis is absent.
- [x] Visual verification on the live instance.
  *Done:* rendered through the **real pipeline** (renderWidget →
  CanonicalTypeAdapter → handler → render_widget.ctp → StatGrid.ctp). REST
  path matched the DB **exactly** for all four metrics: all-time events=6088,
  attributes(deleted=0)=1,919,285, published-by-org1=51, targeting (config
  `luxembourg`/`Bank`)=6 (= DB union distinct). A 4y split window (`1460d`)
  exercised the prior-window delta — events ▼660 (2243 vs 2903), attributes
  ▲22,185 (875,378 vs 853,193, exact once `now` synchronised), published ▲41
  (46 vs 5), targeting ▲4 (5 vs 1). Org-1 has no nationality/sector →
  metric 3 correctly **N/A** without overrides. Web-UI HTML produced correct
  `.misp-stat-*` markup (calendar/tag/shield/building glyphs, ▲/▼ badges,
  relative DD-03-safe drilldowns). Redis held the expected per-metric keys:
  `events`/`attributes` global, `published:…:o1`, windowed by length not
  `now`. **Phase B2 (W7 new-data stats) COMPLETE.**

### Phase B3 — AD-W6 Event-stream rework (DECIDED; building)

- [x] New render kind **`EventCards`** — `EventCards.ctp` flat reverse-chron
  cards (threat dot · org · relative time · #id · info · tag chips · attr
  count) from the `fetchEvent` payload. Token-driven CSS, no inline styles;
  reuse `Index.ctp`'s tag-chip colour + contrast helper.
  *Done:* added `app/View/Elements/dashboard/Widgets/EventCards.ctp` (reads
  the inherited `{data:[...]}` payload; **ignores `fields`** — Index column
  concept) + a `.misp-eventcards-*` block in `dashboard.default.css`. Threat
  dot+label derived from `Event.threat_level_id` (no ThreatLevel-association
  dependency); dot colour maps MISP's threat palette through semantic tokens
  (High→danger, Medium→info, Low→success, Undefined→muted) so it stays
  theme-independent. Relative time + 160-char info truncation + tag-chip cap
  (5 + "+N more") are in-template helpers; reuses `Index.ctp`'s
  `_idxContrastColour` (guard-defined identically so the card renders
  standalone). Only inline value = data-driven chip colours (same posture as
  Index chips). `php -l` clean, CSS braces balance (498/498). All consumed
  paths confirmed against a live `EventStreamWidget` payload.
- [x] Glyph for `EventCards` in `render-thumbs.mjs` (stacked-cards shape;
  **CLAUDE.md rule**): `thumbEventCards()` + REGISTRY entry.
  *Done:* added `thumbEventCards()` — a vertical stack of 3 receding
  rounded cards, each with a small threat-dot + a short info line (evokes
  the flat card stream; distinct from SimpleList's bare rows and StatGrid's
  2×2 grid) — and registered it under `EventCards:` in `REGISTRY`.
  `node --check` clean.
- [x] `EventStreamCardsWidget extends EventStreamWidget` — override `$render` =
  `EventCards`, `$title`, `$description`; inherit the canonical-filter data
  layer + `$schema` verbatim (toolbar-bulk-editable). `handler()` untouched.
  *Done:* `app/Lib/Dashboard/EventStreamCardsWidget.php` —
  `require_once 'EventStreamWidget.php'` (same precedent as
  `OrgsContributorLastMonthWidget`; resolves via the calling script's own
  dir) + a 4-line subclass overriding only `$render`/`$title`
  (`Event Card Stream`)/`$description`. Runtime check: `render=EventCards`,
  inherits `handler()`, all 9 `params`, the 5-canonical `schema`
  (threat_level/analysis/sharing_group/galaxy_cluster/orgs), `category=events`.
  Lint clean.
- [x] Read-only confirm: no in-body controls; filters via toolbar bulk-edit.
  Near-live (`autoRefreshDelay = 5` inherited); no cache (per-user ACL'd
  `fetchEvent`).
  *Done (confirmed by design — same commit as the subclass):* the inherited
  `autoRefreshDelay=5` and `cacheLifetime=false` carry over, and the subclass
  declares **no** `cache_duration`/`cache_scope`, so `WidgetCache::remember`
  runs `handler()` live (per-user ACL'd `fetchEvent`, never per-org cached).
  `EventCards.ctp` renders static markup only — no forms/inputs/JS controls —
  so filtering stays on the dashboard toolbar canonical bulk-edit (AD-08
  Fork B). Verified via runtime property dump (`cacheLifetime=false`, no
  `cache_duration` prop).
- [x] Visual verification on the live instance (real render path).
  *Done:* verified through the **real pipeline** in 3 layers. (1) REST
  `renderWidget` → `renderer:EventCards` + the inherited `{data,fields}`
  payload; the inherited `threat_level=[2]` filter correctly narrowed to
  only Medium events through the subclass. (2) Web-UI POST + session →
  real `EventCards.ctp` HTML, no PHP warnings: 4 cards with the correct
  threat dots (tl 4→undefined, 2→medium, 3→low), `·`-separated org/time
  (relative + ISO tooltip), right-aligned `#id` links to
  `/events/view/<id>`, data-driven tag chips with **correct contrast**
  (`tlp:amber` #FFC000→dark text, dark tags→white via `_idxContrastColour`),
  `1 attr`/`15 attrs` singular/plural, and a 0-tag card cleanly showing
  only the count. (3) Headless-chromium screenshot against the real CSS
  confirmed the styled visual. Dev data has no event with >5 tags or long
  info, so the **"+N more" overflow** (5 chips + "+2 more") and **160-char
  info truncation** branches were covered by a focused renderer harness
  (presentation logic only — the handler passthrough is proven by layers
  1–2). Folded a 1-line CSS polish: `row3` `align-items: center`→`flex-start`
  so the attr count anchors to the first tag line instead of floating at the
  vertical centre when chips wrap. **Phase B3 (W6 event-stream rework)
  COMPLETE.**

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

- **[RESOLVED — B1.6, Option A, user signed off 2026-06-01]** `WidgetCache`
  gained an additive `'org'` scope; `TrendingWidget` uses it. *(Original
  finding below kept for the audit trail.)* **`WidgetCache` has no `'org'`
  scope — AD-04 per-org cache needs a 2nd additive-only touch of existing
  code (SIGN-OFF, lands at B1.6).**
  *Introduces:* `WidgetCache::scope()`/`key()` recognise only `'user'`
  (keys `u<id>:`) and `'global'` (config-only) — see
  `app/Lib/Dashboard/Tools/WidgetCache.php:162`. *Why it matters:* AD-04
  locks the trending cache **per-org** ("never per-user; org is the atom;
  site-admins a separate no-ACL bucket"). The faithful implementation adds
  an `'org'` scope (key segment `o<org_id>:`, site-admin → `sa:` bucket) —
  a small additive branch in existing platform code, parallel to the AD-12
  AttackWidget sign-off; it improves caching for all widgets. The fallback
  is `cache_scope='user'` (ACL-correct, fully additive, but duplicates
  compute/storage for same-org users — contradicts AD-04's letter). *Where:*
  decide at **B1.6**; B1.3–B1.5 run the engine live (uncached) so this never
  blocks them.
- **Dev-DB vulnerability data is stale vs the box clock — affects B1.7
  verification.** Box clock = 2026-06-01; newest `vulnerability` attr =
  2025-05-25 (~372d ago), oldest 2014. So finite 30d/365d windows render
  "No data"; the 138 distinct events all sit in a single ~11y band ending
  ~1y ago. *For B1.7:* verify the volume path with `time_window=-1` (all-time,
  full ranked list, no momentum badges by design), and verify **momentum**
  either with a large split window (e.g. ~2000d → two non-empty halves) or by
  touching a few attrs' timestamps into a recent current/prior window. Not a
  code bug.
