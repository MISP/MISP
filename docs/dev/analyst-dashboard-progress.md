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
| AD-W2 | Trending vulnerabilities (dim of W1) | `DECIDED` (AD-09) | `[x]` **BUILT** (Phase B4; engine from B1 + cveurl drilldown) |
| AD-W3 | Trending threat actors (dim of W1) | `DECIDED` (AD-10) | `[ ]` not started |
| AD-W4 | Trending attack techniques (dim of W1) | `DECIDED` (AD-11) | `[x]` **BUILT** (Phase B6; W3 count re-pointed + parent roll-up) |
| AD-W5 | ATT&CK matrix heatmap (existing) | `DECIDED (REDESIGN)` (AD-15) | `[x]` **BUILT** (Phase B7, 2026-06-02) — renderer redesign: hide inactive · labeled cells · technique/sub-technique aggregation + `<details>` unfold · √-scaled red ramp + legend · AD-12 time_window folded in; verified live (light + midnight) |
| AD-W6 | Event-stream rework | `DECIDED` (AD-08) | `[x]` **BUILT** (Phase B3; EventCards render kind + subclass live) |
| AD-W7 | New-data stats (StatGrid + deltas) | `DECIDED` (AD-05..07) | `[x]` **BUILT** (Phase B2; 4 metrics live) |
| AD-W8 | Overlap-with-my-org | `DECIDED` (AD-13, AD-14) | `[x]` **BUILT** (Phase B8; correlation-anchored, EventCards + overlap badge, `exclude_own_org` setting) |
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
- [x] **AD-W5 spec → REDESIGN (supersedes AD-12)** — user reviewed the shipped
  static heatmap and chose "redesign the renderer": (1) hide inactive, (2)
  larger labeled cells, (3) technique/sub-technique aggregation w/ click-to-
  unfold (parent heat = SUM), (4) single red ramp + legend, (5) AD-12
  `time_window` folded in. **Renderer-only** (data layer untouched);
  renderer-rewrite + AttackWidget edit signed off. (AD-15; B7 un-parked.)
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

Build order: **W1 ✅ → W7 ✅ → W6 ✅ → W2 ✅ → W3 ✅ → W4 ✅ → W8 ✅ → W5 ✅ (B7
redesign) → W9**. Engine first (W2/W3/W4 are its dimensions); stats next; then
event-stream; dimensions; the affects-me pair; **W5 reordered to last-but-W9**
after the heatmap was parked then reopened as a renderer redesign (AD-15,
2026-06-02; see Phase B7) — **now BUILT**. Only **W9 (DEFERRED)** remains.

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

- [x] `vulnerability` dimension config: counting = `COUNT(DISTINCT event_id)`
  over `type='vulnerability' AND deleted=0` grouped by `value1` (attribute-value
  arm only; tag arms empty for CVEs).
  *Done (covered by B1.4):* `countVulnerability()` + the `dimensions()` entry
  shipped with the W1 engine — exactly this query. No new work in B4.
- [x] **ACL-correct count** (primary risk): constrain to the org's visible
  event set (reuse `Attribute` ACL conditions; no event hydration); cache
  per-org (AD-04); site-admin no-ACL bucket.
  *Done (covered by B1.4 + B1.6):* `aclVisibleEventIds()` scopes the count;
  the per-org `WidgetCache` `org` scope + `sa:` bucket are on the widget. No
  new work in B4.
- [x] Window anchor `Attribute.timestamp` (AD-05); momentum AD-03.
  *Done (covered by B1.4 + B1.5):* `countVulnerability` is `Attribute.timestamp`
  window-bounded; `handler()` computes the prior-window delta. No new work in B4.
- [x] Label resolver = identifier verbatim; link builder = `MISP.cveurl` +
  value (`{cveurl}{value}`).
  *Done:* label resolver (identifier verbatim) shipped in B1; the **link
  builder is the actual B4 work** — `labelsVulnerability()` now sets
  `'drilldown' => DashboardURLValidator::cveBaseUrl() . $value` (mirrors
  `value_field.ctp:94`, no separator). `cveBaseUrl()` is the shared resolver
  the relaxed DD-03 gate allowlists, so the external link survives rather than
  being dropped (see the B4 Discovered-work entry — DD-03 relaxation, user
  signed off). Unit-probed: `CVE-2017-11882` → `http://cve.circl.lu/cve/CVE-2017-11882`,
  admitted by the validator.
- [x] Visual verification on the live instance.
  *Done:* verified the cveurl drilldown through the **real render path**
  (flushed the per-org cache first; vuln data is ~372 d stale so used
  `time_window=-1` all-time, like B1.7). (1) REST `renderWidget` →
  `renderer:Trending`, every row carries
  `drilldown=http://cve.circl.lu/cve/<CVE>` (the configured `MISP.cveurl`);
  counts unchanged from B1.7 (CVE-2017-11882=13, CVE-2012-0158=11, …). (2)
  Web-UI POST + session → all 5 rows render as **`<a class="misp-trending-row"
  href="http://cve.circl.lu/cve/…">`** (0 fell back to `<div>`), i.e. the
  relaxed DD-03 gate **admitted** every external link end-to-end — the exact
  failure mode the relaxation fixes. No PHP warnings. No screenshot: `Trending`
  is not a new render kind (visually proven in B1.7); only the `href` changed,
  confirmed in the markup. **Phase B4 (W2 trending vulnerabilities) COMPLETE.**

### Phase B5 — AD-W3 Trending Threat Actors dimension (BUILT + verified 2026-06-02)

*A `dimension` config + hooks on the built W1 engine. Depends on Phase B1.*

- [x] `threat-actor` dimension config: tag-id set = `tags WHERE is_galaxy=1 AND
  name LIKE 'misp-galaxy:threat-actor="%'`.
  **Done:** `dimensions()` gains a `threat-actor` entry (→ `countThreatActor` /
  `labelsThreatActor`); `threatActorTagIds()` is the tag-id query. Row key = the
  **tag_id** (not a cluster id) so the count is immune to tag_name→cluster being
  non-1:1 (see label note). 118 such tags on the dev box.
- [x] **ACL-correct union-distinct count** (primary risk): `COUNT(DISTINCT
  event_id)` over EventTag ∪ AttributeTag for those tag_ids, ACL-scoped to the
  org's visible events — do NOT reuse `AttributeTag::countForTags` (skips ACL,
  counts occurrences). Cache per-org; site-admin no-ACL bucket.
  **Done:** `countThreatActor()` gathers in-window `(tag_id, event_id)` pairs
  from both arms, ACL-filters the union of candidate events via the SAME
  `aclVisibleEventIds()` the vulnerability arm uses (AD-09), then counts
  distinct events per tag over the visible subset — a per-tag event **set**
  unions the two arms so a doubly-tagged event counts once. Per-org cache is
  inherited from the widget (`cache_scope='org'`). Live counts match a raw-SQL
  probe exactly (Sofacy 47, Lazarus 29, Turla 19, Anunak 12, TA505 11…).
- [x] Anchors per AD-05 (event-tag→Event.timestamp, attr-tag→Attribute.timestamp);
  momentum AD-03.
  **Done:** the event-tag arm joins `events` and bounds on `Event.timestamp`;
  the attribute-tag arm joins `attributes` (+`deleted=0`) and bounds on
  `Attribute.timestamp`. Momentum is the engine's existing AD-03 path (prior
  equal window via a second count call); `-1`/all-time has none, as designed.
- [x] Label resolver: bulk-resolve top-N clusters → value + Galaxy.icon +
  synonyms (avoid N+1). Link builder = /galaxy_clusters/view/<id>.
  **Done:** `labelsThreatActor()` = 2 bulk queries (cluster value+icon via
  `galaxy_clusters.tag_name=tags.name`+`galaxies`; synonyms via
  `galaxy_elements`). **80/118 tag_names map to >1 cluster row** (local forks /
  duplicate imports) → `clusterOutranks()` picks one deterministically (default
  desc, version desc, id desc). Synonyms deduped (duplicate imports doubled
  them). `Trending.ctp` gains an optional leading **galaxy icon** (FontAwesome
  helper → `fas fa-user-secret`) + `.misp-trending-icon` token CSS — the W3/W4
  extension the renderer's header anticipated. Orphan tags (no cluster row, e.g.
  Hafnium/COVELLITE) fall back to the bare actor name, no link/icon.
- [x] Visual verification on the live instance.
  **Done:** REST `renderWidget` (dimension=threat-actor, `time_window=-1`) =
  counts above; web-UI POST+session render = **8 `<a>` rows** (icon +
  `href="/galaxy_clusters/view/<id>"`, DD-03 admits the relative link with no
  relaxation) + **2 plain `<div>` rows** (orphan fallback), no PHP warnings.
  Appended to user 1's dashboard as `w_12` (TrendingWidget, threat-actor,
  `time_window=-1`; backup `/tmp/dash_backup.json`), smoke-tested.
  **Phase B5 (W3 trending threat actors) COMPLETE.**

### Phase B6 — AD-W4 Trending Attack Techniques dimension (BUILT + verified 2026-06-02)

*A `dimension` config on the W1 engine, reusing W3's count machinery. Depends
on B1 (and shares B5's ACL-correct union-distinct count).*

- [x] `mitre-attack-pattern` dimension config: tag-id set = Enterprise
  attack-pattern cluster tags, **grouped by parent technique** (sub-technique
  external_id `T1566.001` → parent `T1566`, ".NNN" stripped).
  **Done:** `dimensions()` gains a `mitre-attack-pattern` entry (→
  `countAttackPattern` / `labelsAttackPattern`); `attackPatternTagBuckets()` is
  the tag set (`is_galaxy=1 AND name LIKE 'misp-galaxy:mitre-attack-pattern="%'`
  — galaxy type `mitre-attack-pattern`, the Enterprise matrix; mobile/ICS/ATLAS/
  pre/cmtmf are separate namespaces, excluded) + the `tag_id → parentId` roll-up
  map. **Build deviation from AD-11's *suggested* mechanism (which it left "open
  at build"):** the technique id is parsed from the tag **NAME** (`… - T1566.001`
  → strip `.NNN` → `T1566`), NOT the `galaxy_elements` `external_id` element —
  that element is unreliable on real data (`Capture Camera - T1512` carries
  `external_id=APP-19`, a legacy Mobile id; rows are also duplicated). 440/452
  tags parse a `T<id>`; the 12 that don't are 5 tactic `TA00NN` tags + 7
  deprecated un-suffixed names — not techniques, correctly dropped. DECIDED spec
  (scope, parent roll-up, reuse W3 count) unchanged. Helpers unit-tested
  (sub-technique roll-up, tactic rejection, dashes-in-value).
- [x] ACL-correct distinct-event count at the parent-technique level (reuse the
  B5 union-distinct count); cache per-org.
  **Done:** `countThreatActor` refactored into a shared
  `countDistinctEventsByTag($user,$start,$end,$tagIds,$bucketMap=null)` — the
  same gather-pairs → `aclVisibleEventIds()` → per-bucket event-**set** logic,
  but the final map keys by `$bucketMap[tag_id]` when a map is given (W4 parent
  roll-up) else the tag_id itself (W3, behaviour preserved). `countAttackPattern`
  delegates with the parent bucket map, so an event tagged with both a technique
  and its sub-technique counts **once** for the parent. Per-org cache inherited
  from the widget (`cache_scope='org'`). Matches the raw-SQL ground truth
  (verified at B6.5).
- [x] Anchors AD-05; momentum AD-03.
  **Done:** inherited from the shared counter (event-tag arm bounds on
  `Event.timestamp`, attribute-tag arm on `Attribute.timestamp`+`deleted=0`) and
  the engine's existing AD-03 prior-window path — no W4-specific work.
- [x] Label resolver: parent cluster `value` + `external_id` + Galaxy.icon
  (`map`), bulk-resolved; link = /galaxy_clusters/view/<parent_id>.
  **Done:** `labelsAttackPattern()` resolves each top-N parent id → its parent
  cluster via `galaxy_clusters.tag_name LIKE '% - T<id>"'` (one OR'd query; the
  closing-quote anchor pins to the exact parent, never a `.NNN` sub-technique).
  Label = `value (external_id)` ("Phishing (T1566)") via `attackLabel()`, icon =
  `Galaxy.icon` (`map`) into the W3 `Trending.ctp` icon slot (reused, no glyph),
  link `/galaxy_clusters/view/<parent_cluster_id>` (relative → DD-03 admits, no
  relaxation). Non-1:1 tag→cluster deduped via the existing `clusterOutranks()`;
  parent resolves even when only sub-techniques are tagged (it is its own
  cluster); orphan parent falls back to the bare technique id. Matched by
  `tag_name` (not a `tags` row) since only ~⅓ of clusters have one.
- [x] Visual verification + confirm DISTINCT from the W5 heatmap on the board.
  **Done:** flushed the per-org `misp:trending_cache:*` bucket, verified through
  the **real render path** (site-admin → ACL opens to all events, so the output
  must equal a raw-SQL ground truth). (1) REST `renderWidget`
  (dimension=mitre-attack-pattern, `time_window=-1`): all top-12 parent counts
  match the SQL exactly — T1190=696, T1095=580, **T1566=101** (the roll-up:
  distinct-event union of Phishing T1566=68 ∪ Spearphishing-Attachment
  T1566.001=36 ∪ Spearphishing-Link T1566.002=34), T1094=80, T1059=63, …; labels
  `Name (Txxxx)`, `icon=map`, drilldown to the correct parent cluster ids
  (T1190→135240, T1566→136176). (2) Web-UI POST+session render = **15 `<a>` rows
  / 0 `<div>` fallbacks** (every parent resolved a cluster; relative
  `/galaxy_clusters/view/<id>` links all DD-03-admitted, no relaxation), 15
  `fas fa-map` glyphs via the reused W3 `Trending.ctp` icon slot, bar fills
  proportional (100% / 83.3%), no PHP warnings. (3) Momentum exercised on a
  `1460d` split window — confirms the **string-keyed** prior-window lookup
  (W4 keys are `T1566`, not ints): Phishing ▲34% (58 vs 43), Exploit
  Public-Facing App ▼97% (26 vs 670), Command&Scripting ▼43%, … all correct
  floored %. **DISTINCT from W5** confirmed: W4 `render='Trending'` (ranked
  top-N + momentum), W5 `AttackWidget` `render='Attack'` (spatial matrix) — no
  code overlap. Appended to user 1's dashboard as `w_14` (TrendingWidget,
  mitre-attack-pattern, `time_window=-1`; backup `/tmp/dash_backup.json`),
  read-back verified (14 tiles, all 3 Trending dimensions present).
  **Phase B6 (W4 trending attack techniques) COMPLETE.**

### Phase B7 — AD-W5 ATT&CK heatmap REDESIGN (✅ UN-PARKED 2026-06-02; spec AD-15)

> **✅ UN-PARKED — spec locked (AD-15, 2026-06-02).** The user briefed the
> concrete dissatisfaction and chose **"redesign the renderer."** Both forks
> resolved: **fold in AD-12 `time_window`**; **parent heat = SUM of counts**
> (renderer-only). **Scope = renderer + `AttackWidget` only; the data layer
> (`AttackExport`, `Galaxy::getMatrix`) stays UNTOUCHED.** Sign-off granted for
> the `Attack.ctp` rewrite + `AttackWidget.php` edit (beyond additive-only).
> Full spec: PRD §5 AD-W5 + AD-15.

*Renderer redesign: rewrites `Attack.ctp` (existing) + dashboard CSS (default +
midnight) + small unfold JS; edits `AttackWidget.php` (time_window only).
User-signed-off (beyond additive). Read-only posture deviated for click-to-unfold
(progressive disclosure of own data — user-requested). `Attack` is an existing
render kind ⇒ no new glyph (confirm the existing one).*

- [x] **`AttackWidget.php` — `time_window` wiring (AD-12/AD-15 pt5).** Add the
  `time_window` canonical to `$schema` (currently `[]`); map it → restSearch
  'attack' `timestamp` filter (reuse the in-tree translation; `-1` ⇒ no bound);
  merge without clobbering manual `attackGalaxy`/`published`; cache key includes
  the window. *(The only data-side touch; everything else is the renderer.)*
  *Done:* added the `time_window` canonical (`'type'=>'time_window'`,
  `default => -1` = all-time, so existing instances are unaffected) +
  `resolveTimeWindow()` (mirrors `AttributeGeoMapWidget::resolveSince`; "Nd"
  string OR seconds int → epoch lower bound; ≤0/-1 → null = no bound). `handler()`
  now drives `filters['timestamp']` from the window (OVERRIDES a manual
  `filters.timestamp` only when a finite window is set; -1 preserves it). Lint
  clean. **Verified live (REST render path):** `"30d"`→0 (no recent attack-tagged
  events on the stale corpus), `"3650d"`→696 = all-time, `100000000`s (~3.17y)→21
  (intermediate, monotonic; proves the seconds-int form), `-1`/none→696 (schema
  default injected); manual future-range `filters.timestamp` w/o window → 0
  (preserved, not clobbered); empty config → null ("No filter configured",
  original behaviour). **No cache concern:** AttackWidget declares legacy
  `cacheLifetime` not `cache_duration`, so `WidgetCache::remember` is a
  pass-through → runs live; the window always drives.
- [x] **`Attack.ctp` — technique/sub-technique aggregation (AD-15 pt3).** Group
  each tactic column's cells by parent T-ID off `external_id` (`^T\d+$` =
  technique; `^T\d+\.\d+$` = sub-technique → parent = strip `.\d+`). Parent cell
  = rolled-up group; **parent heat = SUM** of own + sub event-counts. Orphan
  sub-technique (no parent cell in column) → synthesise header from the parent
  T-ID. Non-`T####` id (43 legacy clusters) → standalone top-level group.
  *Done (with the steps below — one renderer rewrite):* pass-0 builds a global
  parent-name map (resolves the 7/195 orphan subs to real names, e.g.
  T1574→"Hijack Execution Flow"); pass-1 groups per column, SUM aggregate,
  active subs sorted desc, groups sorted by aggregate desc. Non-T ids fall to a
  standalone leaf group. Label = strip trailing " - <external_id>" suffix
  (authoritative; never mangles — replaced the blind `removeTrailing` strip).
- [x] **`Attack.ctp` — hide inactive (AD-15 pt1).** Render only groups whose
  aggregate score > 0; drop tactic columns with no active group. *Done:* groups
  with agg ≤ 0 skipped; columns with no surviving group skipped; empty-matrix
  guard message added. Verified live: 15 active columns (of 16+), inactive
  techniques absent.
- [x] **`Attack.ctp` + CSS — larger labeled cells (AD-15 pt2).** Each cell shows
  technique name + T-ID + count, readable without hover (wall-display usable);
  replaces the 8px hover-only bars. Token-driven CSS (default + midnight).
  *Done:* flex cells (name 2-line clamp · T-ID · bold count), 168px columns,
  active-group count badge in the header. All chrome token-driven.
- [x] **`Attack.ctp` + CSS — single red gradient + legend (AD-15 pt4).** Drop the
  export's multi-hue `colours`; shade each cell in-renderer from
  `score / max-parent-score` on a single-hue red ramp; render a small
  legend/scale. *Done:* HSL(h=0) ramp, **√-scaled** + normalised to the global
  max aggregate (the hit distribution is heavily skewed — max 696 vs median <10
  — so a linear ramp would wash out the mid-range); per-cell luminance-picked
  text colour (opaque ⇒ theme-independent); legend bar gradient sampled from the
  exact same ramp at 5 stops, min 0 / max = global aggregate.
- [x] **Unfold (AD-15 pt3) — native `<details>`/`<summary>`, NO JS.** Parents
  with active subs render as `<details>` (summary = parent cell + rotating
  caret; sub-cells inside, hidden until opened). Multi-widget-safe, accessible,
  and keeps the read-only posture deviation minimal (HTML disclosure, not
  scripting). *Supersedes the "unfold JS" step — no JS file touched.*
- [x] Confirm `time_window` cache key + toolbar bulk-edit drives the heatmap.
  *Done:* AttackWidget runs live in v2 (legacy `cacheLifetime`, not
  `cache_duration` → `WidgetCache` pass-through), so the window always drives;
  no stale-cache concern (verified in step 1).
- [x] Visual verification on the live instance (real render path): inactive
  hidden, labels readable, parent cells fold/unfold, red ramp + legend, re-scopes
  with the board. *Done:* (a) deterministic synthetic harness (aggregation/
  hide-inactive/orphan-fallback/labels/legend all asserted); (b) real 34MB
  payload rendered offline — 15 cols, 84 `<details>`, 168 leaf + 190 sub cells,
  0 un-stripped labels; (c) **real web-UI POST render = byte-identical
  (172692 B, http 200)** → the live pipeline delivers `$data` to `Attack.ctp`;
  (d) snap-chromium screenshots **light + midnight** confirm legend, red ramp,
  readable labels, and unfolded sub-techniques on both themes.
- [x] **User 1 test dashboard (standing pref) — verified in place.** AttackWidget
  is **already** on the board as `w_8` (dedupe by class → no append). It renders
  the redesigned heatmap live (64 techniques on its config). **Finding (not a
  bug):** `w_8`'s config carries `time_window:"-1"` **and** a stale manual
  `filters.timestamp:["2023-01-01","2023-03-31"]` (the old AttackWidget
  placeholder's dates) — per the documented rule, `-1` preserves the manual
  timestamp, so `w_8` is scoped to Q1 2023. Left as-is (board config is the
  user's to arrange); flagged so they can clear the stale timestamp for the
  full all-time view if wanted.

**Phase B7 (AD-W5 ATT&CK heatmap REDESIGN) COMPLETE + verified.** Renderer-only
(Attack.ctp + CSS) + the one AttackWidget.php time_window add; data layer
untouched. The roster is now fully BUILT except **W9 (DEFERRED)**.

### Phase B8 — AD-W8 Overlap-with-my-org (DECIDED; needs B1 + B3 EventCards)

*New widget; reuses the W6 `EventCards` render. Depends on B3 (EventCards).*

- [x] `OverlapWithMyOrgWidget` (`render = 'EventCards'`): candidate set =
  ACL-visible window events (`Event.timestamp` in window), capped top-N recent
  (`log()` if capped). *Done: new class; fetch top-200 by `Event.timestamp
  DESC` then window-filter (= top-N recent in-window, dense or sparse);
  `CANDIDATE_CAP=200`; `CakeLog::write('info', …)` when the fetch hits the cap
  (no existing widget `log()` idiom — MISP log is the honest channel).*
- [x] For each candidate, `Correlation->getRelatedEventIds($user, id, sgids)`;
  keep iff a related event's `orgc_id` = my org. Overlap strength = # of my-org
  events it correlates to; rank desc then recency. *Done: `sgids` via
  `SharingGroup->authorizedIds`; self-id filtered; one batched
  `Event->find('list', [id, orgc_id])` over all related ids; `usort` strength
  desc → `Event.timestamp` desc. **AD-14:** `exclude_own_org` config (default
  true) drops my-own-org candidates for a pure external "affects-me" signal.*
- [x] EventCards + "overlaps N of your events" badge; per-org cache (AD-04).
  *Done: additive per-record `_analyst_overlap` payload key →
  `EventCards.ctp` renders the badge only when present (W6 stream unaffected) +
  `.misp-eventcards-overlap` token pill in `dashboard.default.css` (mirrors
  `.misp-trending-delta`); `cache_scope='org'`, `cache_duration=1200`.*
- [x] Verify across correlation engines (Default at minimum; note OnDemand path
  is reused for free via getRelatedEventIds). *Done: live REST + web-UI HTML on
  the **Default** engine (configured) — `exclude_own_org` false→44 / true→25
  events, orgc=1 (admin's org) correctly excluded, strengths 1/2/5 ranked
  correctly, 25/25 cards badged. Engine-agnostic by construction: all three
  behaviours implement `fetchRelatedEventIds`.*
- [x] Visual verification on the live instance. *Done: snap-chromium screenshot
  of the rendered `.ctp` through `dashboard.default.css` — accent badge pill
  renders inline (threat dot · org · time · **overlaps N** · #id). Appended to
  user 1's dashboard as `w_15` (backup `/tmp/dash_backup.json`; 15 tiles).*

### Phase B9 — widget settings canonization (NEXT; user-requested 2026-06-02)

> **Goal (user):** the new free-form settings I added this track live only in
> `$params` (raw "advanced" config JSON). Promote the ones that should be
> first-class UI controls into `$schema` with a proper scalar type so the
> **configure form's typed-fields tier** renders a real control — e.g.
> `exclude_own_org` should be a **checkbox**, not an advanced JSON key.
>
> **Key finding (makes this trivial + additive):** `configure.module.mjs`
> ALREADY renders the scalar types `string` / `int` / `bool` / `enum` as native
> controls (`bool` → checkbox `misp-field-checkbox`; `enum` → `<select>` honouring
> `enum`/`enum_labels`; `int` → number). `WidgetSchema` whitelists all four
> (`int`/`bool`/`enum` + `string`). So each item below is a **pure `$schema`
> addition — NO platform/JS change.** (The old "no `select` type → deferred" note
> was about the *toolbar* tier; `TOOLBAR_ELIGIBLE_TYPES` excludes scalars, but the
> *configure form* renders them — and that's the "settings part" the user means.)

- [x] **`OverlapWithMyOrgWidget` — `exclude_own_org` → `bool`.** Add to `$schema`:
  `['type'=>'bool','default'=>true,'help'=>…]`. Keep the `$params` text (it
  becomes the field help). Verify the configure-form checkbox posts a value the
  existing `parseBool()` read-back accepts (check `data-type='bool'` readback).
  *Done:* added the `exclude_own_org` `bool` schema entry (`default=>true`, help
  carried from `$params`); `$params` text + `$placeholder` key kept. PHP harness
  proved the full round-trip: `WidgetSchema::validate` = well-formed;
  `CanonicalTypeAdapter::translate([])` injects `exclude_own_org=true` (matches
  `parseBool`'s own true default → no behaviour change for existing instances)
  and passes a user-set `false` through unchanged (no scalar switch case);
  `parseBool` reflection accepts every wire form (true/false, "true"/"false",
  "0"→false, 1→true, null→default). `exclude_own_org` is now schema-handled, so
  the configure form's `handledKeys` filters it out of the Advanced tier — the
  placeholder key renders ONCE as the typed checkbox, not duplicated. Lint
  clean. Browser-screenshot proof deferred to the B9 verification task (item 6).
- [x] **`TrendingWidget` — `dimension` → `enum`.** Add to `$schema`:
  `['type'=>'enum','enum'=>['vulnerability','threat-actor','mitre-attack-pattern'],
  'enum_labels'=>{…},'default'=>'vulnerability']`. Keep the enum list in sync with
  the `dimensions()` registry (note the duplication; consider deriving). This is
  the one the prior handoff wrongly deferred as "needs a new canonical type".
  *Done:* added the `dimension` `enum` schema entry (3 values + `enum_labels` +
  `default=>'vulnerability'`); `$params` text + `$placeholder` key kept. PHP
  harness proved: `WidgetSchema::validate` well-formed; **enum values EXACTLY
  match the `dimensions()` registry keys** (reflection-compared — no drift) and
  every value carries an `enum_label`; `CanonicalTypeAdapter` injects
  `vulnerability` when absent and passes a chosen value through; the handler's
  dimension-selection (`!empty && isset(registry[...])`) picks the
  default-injected value, a chosen value, and falls back to `vulnerability` for
  a bogus value. `dimension` is now schema-handled → filtered from the Advanced
  tier (renders once as the `<select>`). Lint clean. The enum<->registry
  duplication is documented in a code comment (deriving deferred — would need a
  public dimensions() accessor; not worth a refactor for 3 stable values).
  Browser screenshot deferred to the B9 verification task (item 6).
- [ ] **`NewDataStatsWidget` — `country` / `sector` → `string`.** Optional
  free-text overrides → `['type'=>'string','default'=>'','help'=>…]` each, so they
  render as labelled text inputs instead of advanced JSON.
- [ ] **`AttackWidget` — `filters` stays advanced.** A freeform restSearch filter
  dict has no scalar type; it legitimately stays in the raw/advanced tier.
  `time_window` already canonized (B7). No change — just confirm/note.
- [ ] **Cross-check the whole track for leftover `$params`-only knobs** that
  should be typed (sweep every analyst widget); confirm a key present in BOTH
  `$params` and `$schema` renders ONCE (typed control), not duplicated (the
  proven `time_window` pattern — verify, don't assume).
- [ ] **Verify** each via the real configure-form render (open the widget config
  UI / inspect the rendered form, or the configure.module.mjs path) — checkbox /
  dropdown / number appear; defaults inject via `CanonicalTypeAdapter`; the
  handler still reads the posted value. Screenshot the configure form for proof.
- [ ] Additive posture holds — these are `$schema` additions only; **if** the
  sweep turns up a setting whose ideal control needs a NEW canonical type or a
  configure-form JS change, that's a platform touch → **stop and get sign-off**.

*(W9 deferred — look-and-feel-only reskin of RecentSightingsWidget, after the
render kinds land.)*

## Discovered work

- **[RESOLVED — B4, user signed off 2026-06-02]** AD-09's external **cveurl
  link-out collides with the dashboard's own DD-03 URL-safety contract.**
  *Finding:* `DashboardURLValidator::validate()` (used by `Trending.ctp` to
  gate `drilldown`) rejects every off-host absolute URL — and `MISP.cveurl`
  (`http://cve.circl.lu/cve/` on this box; default
  `https://vulnerability.circl.lu/vuln/`) is external — so a literal AD-09
  `{cveurl}{value}` drilldown would be **silently dropped** and the row would
  render as plain text. Never hit in B1.7 because the link was deferred to B4.
  *Fork surfaced (AskUserQuestion):* (1) internal event-search drilldown
  (additive, amends AD-09), (2) **relax DD-03 to allowlist the configured
  cveurl host** (honours AD-09, touches platform code), (3) both. **User chose
  (2).** *Resolution:* `DashboardURLValidator` now allowlists the trusted CVE
  base alongside `MISP.baseurl` — a shared `cveBaseUrl()` resolver
  (`MISP.cveurl` ?: documented default) feeds BOTH the gate's allowlist and
  the widget's link builder so the emitted URL and the gate that admits it
  can't drift; arbitrary off-host links are still dropped (scheme+host+port
  match required). Test suite extended to **29 tests / 42 assertions green**
  (all original DD-03 cases preserved + cveurl host/scheme/port, off-host
  still rejected, default-trust, `cveBaseUrl`).

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
