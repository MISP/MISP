# Analyst Dashboard — mini-PRD

> A **deviation/companion** to `dashboard-prd.md`, scoped to the analyst
> persona's widget surface. The parent PRD owns the dashboard *platform*
> (layout engine, gallery, templates, render kinds, theming, DD-01..DD-51).
> This doc owns the **analyst widget roster** — what an analyst needs to
> see and the widgets that deliver it. Where the two conflict, the parent
> PRD's platform decisions win; this doc only adds widgets + the analyst
> default layout.

## 0. Status & how to use this doc

- **Started:** 2026-05-31. Intended to span ~a dozen sessions.
- **Mode:** discuss → decide → record. We work the roster **one widget at
  a time** (sequential; see `feedback_sequential_implementation`). No code
  is written until a widget's row is `DECIDED` and its detail section is
  filled.
- **Decision numbering:** `AD-NN` (Analyst Dashboard), local to this doc,
  cross-linked to parent `DD-NN` where relevant. *(proposed — confirm)*
- **Recomposing the analyst `template.json` is the USER's job**, not ours
  (user, 2026-05-31). We build/improve widgets; the user arranges the board.
- **Companion progress tracker:** TBD — likely split out an
  `analyst-dashboard-progress.md` once implementation starts (matches the
  parent's PRD+progress split + `feedback_session_continuity`). *(confirm)*

## 1. The gap this dashboard closes

Today's analyst `template.json` is five v1-era widgets (TrendingAttributes,
TrendingTags, two WorldMaps, RecentSightings/SimpleList) — all **aggregate
trends and maps**. Against the persona's stated need — *"an at-a-glance view
of what changed since they were last here"* (parent PRD §3, J1) — there is
**no recent-activity surface at all**, no momentum signal, and no
"affects me" lens. This dashboard fixes that.

## 2. Persona: the three analyst jobs

The analyst (parent PRD §3: *"logs in daily, wants an at-a-glance view of
what changed"*) has three distinct jobs. Every widget here must serve one:

1. **What's new** — the incoming feed + a volume pulse. *(event-stream
   rework, new-data stats)*
2. **What's rising** — not just volume, but *momentum*: what is spiking
   right now. *(parametrised trending engine)*
3. **What affects me** — intel that overlaps my org's data, or targets my
   country/sector. *(overlap widget, targeting metrics)*

## 3. Widget roster

Status: `DISCUSSING` (forks open) · `DECIDED` (spec locked, ready to build) ·
`BUILT` · `DEFERRED`.

| ID | Widget | Job | Status | Headline open question |
|----|--------|-----|--------|------------------------|
| AD-W1 | **Trending engine** (parametrised) | rising | DECIDED | engine/counting/momentum/cache locked (AD-01..04); per-dimension specifics → W2/W3 |
| AD-W2 | Trending vulnerabilities (dim of W1) | rising | DECIDED | spec locked (AD-09): vuln-attr distinct-event count, **ACL-scoped**; cveurl link-out; all CVE/GCVE/GHSA |
| AD-W3 | Trending threat actors (dim of W1) | rising | DECIDED | spec locked (AD-10): `threat-actor` galaxy only; event∪attr-tag distinct-event count, **ACL-scoped**; per-cluster label |
| AD-W4 | Trending attack techniques (dim of W1) | rising | DECIDED | spec locked (AD-11): `mitre-attack-pattern`, parent roll-up; reuses W3 ACL count; distinct from W5 |
| AD-W5 | ATT&CK matrix heatmap (existing `AttackWidget`) | rising | **DECIDED (REDESIGN)** | renderer redesign locked (AD-15): hide inactive · labeled cells · technique/sub-technique aggregation w/ click-to-unfold · single red ramp + legend; + AD-12 `time_window` folded in. Renderer-only; data layer untouched |
| AD-W6 | **Event-stream rework** | new | DECIDED | spec locked (AD-08): additive subclass + new read-only `EventCards` render; flat cards; toolbar-driven filters |
| AD-W7 | **New-data stats** (StatGrid + deltas) | new | **BUILT** (Phase B2) | spec locked (AD-05..07): `timestamp` anchor · 4 metrics · targeting waterfall · global-count ACL relaxation |
| AD-W8 | Overlap-with-my-org (correlation) | affects-me | **BUILT** (B8) | AD-13 + AD-14: correlation-anchored (`getRelatedEventIds`), my-org-created ref set, window-anchored; reuses W6 EventCards + overlap badge; `exclude_own_org` setting (default true) |
| AD-W9 | Sightings rework (`RecentSightingsWidget`) | affects-me | **DECLINED** (AD-16) | dropped: the sighting ACL is a shitshow (widget-level `perm_site_admin` gate vs `Sighting->restSearch` user-scoping), engine slow / unused by some — not worth the untangling. Existing sightings widgets left as-is; analyst surface is complete at W1–W8 |
| AD-W10 | **Recent Event Reports** (feed) | new | DECIDED | spec locked (AD-18): N newest visible Event Reports via `fetchReports`, reverse-chron, `FeedList` render; recency = `EventReport.timestamp` |
| AD-W11 | **Recent Analyst Data** (feed) | new | DECIDED | spec locked (AD-19, re-scoped): newest visible **Notes + Opinions** (any target type, target type **shown**), `buildConditions` ACL, `modified` recency, `FeedList` render. No my-org-events filter (drops the IN-list trap) |
| AD-W12 | **Recently Added Galaxy Clusters** (feed) | new | DECIDED | spec locked (AD-20): N newest **local** clusters (`default=0`) via `fetchGalaxyClusters`, recency = `version` (add-or-update), `FeedList` render + Galaxy.icon |

> **⤳ TRACK REOPENED (2026-06-02).** After the W1–W8 surface shipped, the user
> requested **three new feed-style widgets** — W10 (new reports), W11 (analyst
> data visible to me), W12 (new local galaxy clusters) — all serving job 1
> ("what's new"), all on a single **new shared render kind `FeedList`** (AD-17;
> the user explicitly opened "new UI" as in-scope). Pure additions (new widget
> classes + one new render template/CSS/glyph; no existing widget or handler
> touched). AD-W9 stays DECLINED. Decision log resumes at **AD-17**.

## 4. Cross-cutting decisions (first-pass; detail to follow)

- **"Trending" = volume AND momentum** (user, 2026-05-31). The existing
  TrendingTags/TrendingAttributes compute *top-N-by-frequency in a window*
  only — no momentum. The analyst engine must add a **rising/uptick** signal
  alongside traditional volume. *(math + representation: see AD-W1, open.)*
- **One parametrised `Trending` widget**, not N near-identical classes
  (user accepted my idea-1, 2026-05-31). Dimensions are config: galaxy
  namespaces (threat-actor, attack-pattern, **+ free: malware, tool,
  sector**), attribute types (CVE/vulnerability), etc. Per-dimension hooks:
  counting strategy, label resolver, drill-down/link builder. *(Tension to
  resolve: the CVE "focused widget" + the galaxy attribute-level counting
  must fit as dimension hooks, not fork the class — see AD-W1/W2.)*
- **Deltas vs previous equivalent window** are wanted wherever we show a
  number (new-data stats explicitly; trending momentum) (user liked,
  2026-05-31).
- **Aggregate widgets cache per-org, lazy-loaded** (AD-04). Org is MISP's ACL
  atom (same-org users see the same events), so ACL-scoped aggregates key
  their cache by org — never a single cross-org blob (leakage), never per-user
  (org is the atom), never background-precomputed; site-admins get a separate
  no-ACL bucket. Freshness is per-widget (trending ~15–30 min/org; event
  stream near-live). Applies track-wide (W1, W7, W8…).

## 5. Per-widget detail

*(Filled as each row reaches `DECIDED`. Stubs capture first-pass answers +
the explicit "circle back" flags from 2026-05-31.)*

### AD-W1 — Trending engine  `DECIDED`

**Locked (2026-05-31):**
- **One parametrised `Trending` widget** (AD-01). Dimensions are config:
  galaxy namespaces (threat-actor, attack-pattern, + free malware/tool/
  sector), attribute types (CVE/vulnerability). Per-dimension hooks:
  counting strategy, label resolver, drill-down link builder.
- **New render kind — a ranked-row list** (AD-01): per row = label · inline
  volume bar · count · `▲/▼` delta badge (sparkline = later polish). Needs a
  glyph in `render-thumbs.mjs` (CLAUDE.md). NOT BarChart — it can't carry the
  per-row delta badge cleanly. (Fork 1 = (b) volume-list + badge; toggle /
  dual-panel / sparkline-as-default rejected as too busy.)
- **Counting metric = distinct events containing the value** (AD-02), each
  event capped at 1 regardless of internal multiplicity. Union across sources
  (event tag ∪ attribute/object tag ∪ attribute value), then
  `COUNT(DISTINCT event_id)`. Off the narrow indexed connector tables
  (`EventTag`, `AttributeTag`) + `Attribute`, not by hydrating events (user's
  "cheat"). Deliberately diverges from `TrendingAttributes`' raw occurrence
  count; resists per-org reporting process-noise.
- **Momentum (AD-03)** = volume-ranked list + per-row delta badge vs the
  **immediately-preceding equal-length window** (same baseline as AD-W7).
  Eligibility: **floored % change** — an item must clear a configurable
  minimum current-window distinct-event count before it can be flagged
  rising (kills `1→4 = +300%` noise), then rank/annotate by % vs prior
  window. **No spike detection** (cost; deferred).

- **Data-path / cache (AD-04)** = lazy-load on render, cache **per-org**
  (org = MISP's ACL atom; same-org users share event visibility), site-admins
  in a separate no-ACL bucket. **Not** background-precomputed (cross-org
  leakage) and **not** per-user (org is the atom). Source = **all events**,
  incl. unpublished (orgs collaborate pre-publication; publication only gates
  cross-community sync). Freshness is per-widget: trending caches ~15–30
  min/org (event stream stays near-live — W6). `AttributeTag` carries
  `event_id`, so distinct-event counting at attribute-tag level needs no join
  to `Attribute`.

**Deferred to per-dimension specs (W2/W3):**
- **Window anchor** — **RESOLVED by AD-05**: `Event.timestamp` (last-modified),
  track-wide. Attribute-level sources (attribute-tag / attribute-value) test
  `Attribute.timestamp` analogously. (`publish_timestamp` rejected — tracks
  propagation-to-this-instance, not newness; see AD-05.)
- **CVE counting specifics** (W2) + galaxy attribute-level specifics (W3).

### AD-W2 — Trending Vulnerabilities  `DECIDED`

**Locked (2026-05-31):** The first concrete **dimension** of the W1 engine.
Scope = **all `vulnerability` attribute identifiers** (CVE / GCVE / GHSA — one
identifier-agnostic attribute type; Fork: "all vulnerability IDs"). Title
"Trending Vulnerabilities".

- **Counting strategy hook** = `COUNT(DISTINCT event_id)` over
  `attributes WHERE type='vulnerability' AND deleted=0`, grouped by `value1`.
  For this dimension the AD-02 union collapses to the **attribute-value arm
  only** — CVEs are *not* tags/taxonomy (research: stored exclusively as
  `vulnerability` values; the `branded-vulnerability` galaxy is not a CVE
  index), so the event-tag / attribute-tag arms are empty. Cheaply indexable:
  `attributes` has indexes on `type`, `value1(255)`, `event_id`.
- **⚠ ACL is the watch-out (user, 2026-05-31).** Trending ranks *which values*
  are rising — that reveals content, so the count **must be ACL-scoped to the
  viewer's org's visible events** (per AD-04: trending is per-org-cached *and*
  ACL-scoped). This is the boundary with AD-06: AD-06's "skip ACL" covers
  *scale*-counts (how many — W7) which leak nothing; a *value-ranking* (which
  ones) must NOT be a global count. So the AD-02 narrow-table "cheat" still
  applies, but the count is constrained to the org's visible event set (event +
  attribute distribution / sharing-group ACL), then cached per-org.
  **Primary build risk** = a lightweight ACL-correct count path (reuse MISP's
  attribute ACL condition builder; avoid full event hydration). Site-admins =
  the no-ACL bucket (AD-04).
- **Window anchor** = `Attribute.timestamp` (AD-05, attribute-level source): a
  value is "in window" if a `vulnerability` attribute carrying it has
  `Attribute.timestamp` in window; distinct events among those = the count.
- **Momentum** = AD-03 (floored-% delta vs prior equal window; configurable
  min current-window distinct-event count before "rising" flags).
- **Label resolver hook** = the identifier verbatim (`CVE-…` / `GCVE-…` /
  `GHSA-…`); no cluster resolution needed (these are attribute values, not
  galaxy clusters — contrast W3).
- **Drill-down link builder hook** = `Configure::read('MISP.cveurl')` then the
  identifier appended **directly, no separator** (`{cveurl}{value}` —
  `value_field.ctp:93`). **Correction to the first-pass note:** the in-tree
  default is `https://vulnerability.circl.lu/vuln/` (`Server.php:5859`,
  `config.default.php:41`) — *not* `cve.circl.lu` — and `cveurl` already
  includes the trailing path, so the URL is e.g.
  `https://vulnerability.circl.lu/vuln/CVE-2026-10186`. Users run their own
  lookup instance (this dev box overrides to `cve.circl.lu/cve/`). A sibling
  `MISP.cweurl` exists for `weakness`/CWE — out of scope for W2.

**Open at build (not blocking spec):** the exact lightweight ACL-count query
(reuse `Attribute` ACL conditions vs a per-org visible-event-id set); whether
to segment the label by identifier prefix (CVE vs GCVE vs GHSA).

### AD-W3 — Trending Threat Actors  `DECIDED`

**Locked (2026-06-01):** The second **dimension** of the W1 engine. Scope =
**native `threat-actor` galaxy only** (Fork: chosen over the actor-galaxy union
— a single galaxy means each actor is ~one cluster, so it sidesteps the
no-canonical-UUID cross-galaxy identity-merge problem).

- **Counting strategy hook** = `COUNT(DISTINCT event_id)` over the **union of
  `EventTag` ∪ `AttributeTag`** rows whose `tag_id` ∈ the threat-actor cluster
  tag-id set, deduped to distinct events. This is AD-02's **tag arms** (both
  event- and attribute/object-level — the handoff's "not just EventTag"),
  contrast W2's value arm. The tag-id set = `tags WHERE is_galaxy=1 AND name
  LIKE 'misp-galaxy:threat-actor="%'`; clusters join via
  `galaxy_clusters.tag_name = tags.name`. Indexes present (`event_tags.tag_id`,
  `attribute_tags.tag_id` + `event_id`, `galaxy_clusters.tag_name`).
- **⚠ ACL (AD-09 reinforced — concrete on the tag arms).** The in-tree
  `AttributeTag::countForTags()` **skips ACL** ("ignored for performance") and
  counts *occurrences*, not distinct events — so it is **unusable as-is**.
  `EventTag::countForTags()` ACL-checks (via `createEventConditions`) but is
  still per-tag occurrence. W3 therefore needs a **custom ACL-correct,
  distinct-event count over the union**, cached per-org (AD-04); site-admins =
  no-ACL bucket. (Same primary build risk as AD-09.)
- **Window anchor** (AD-05, per-source): event-tag arm tests `Event.timestamp`
  in window; attribute-tag arm tests `Attribute.timestamp` in window. A cluster
  is "in window" if any such occurrence falls in the window; distinct events
  among those = the count.
- **Momentum** = AD-03 (floored-% delta vs prior equal window).
- **Label resolver hook** (the crux for a galaxy dimension) = resolve cluster
  tag → `GalaxyCluster.value` (display name) + `Galaxy.icon` (join `Galaxy`;
  e.g. `user-secret`) + synonyms (`GalaxyElement` `key='synonyms'`, shown on
  hover). **Per-cluster, no merge** (Fork chosen) — same-actor-across-galaxies
  is moot at single-galaxy scope; synonym/relation merge deferred. Resolve the
  top-N clusters' value/icon/synonyms in **one bulk query** (avoid N+1).
- **Drill-down link builder hook** = `/galaxy_clusters/view/<cluster_id>`
  (in-app cluster view; accepts id or uuid).

**Open at build (not blocking spec):** the exact ACL-correct union-distinct
count query; the bulk label-resolution query shape.

### AD-W4 — Trending Attack Techniques  `DECIDED`

**Locked (2026-06-01):** The third **dimension** of the W1 engine; reuses W3's
galaxy machinery (a different galaxy type). Scope = **`mitre-attack-pattern`
(Enterprise) only** (mirrors W3's "native galaxy only"; mobile / ICS / ATLAS /
cmtmf excluded — say so to widen).

- **Counting strategy hook** = **engine-native, reusing W3's ACL-correct
  `COUNT(DISTINCT event_id)`** over `EventTag` ∪ `AttributeTag` for the
  technique tag-id set, cached per-org — but the tag-id set is **grouped by
  parent technique**: each sub-technique (`external_id` `T1566.001`) folds into
  its parent (`T1566`, ".NNN" stripped). Distinct-event is taken at the parent
  level (an event tagged with both `T1566` and `T1566.001` counts once, per
  AD-02). A parent bucket exists even if only sub-techniques are tagged.
- **Sub-technique roll-up** (Fork chosen over counting them separately):
  fewer rows, aggregated signal, cleaner "which technique is trending".
- **Window anchor** AD-05 (event-tag→`Event.timestamp`,
  attribute-tag→`Attribute.timestamp`); **momentum** AD-03.
- **Label resolver hook** = the **parent** cluster `value` + `external_id`
  (e.g. "Phishing (T1566)") + `Galaxy.icon` (`map`); bulk-resolved (avoid N+1).
- **Drill-down link builder hook** = `/galaxy_clusters/view/<parent_cluster_id>`.
- **DISTINCT from W5** (the heatmap): W4 = a ranked top-N list + momentum badges
  wired to the global window; W5 = the spatial ATT&CK **matrix** heatmap
  (`AttackWidget`, `render=Attack`, `restSearch 'attack'`, manual filters). Two
  different views of the same data — confirmed distinct, no overlap to resolve.
- **Counting-path note:** engine-native chosen for consistency with W2/W3. The
  `attack` restSearch returnFormat that W5 uses is ACL-correct and was
  considered, but it's a *parallel* counting path and would need verifying it
  counts distinct events (AD-02) — held as a build-time alternative, not the
  default.

**Open at build (not blocking spec):** the parent roll-up mapping (sub-technique
tag_ids → parent `external_id`/cluster); confirm the parent label resolves from
the parent cluster record even when only sub-techniques are tagged.

### AD-W5 — ATT&CK matrix heatmap  `DECIDED (REDESIGN)`

**⤳ REDESIGN (2026-06-02, AD-15) — supersedes the static thin-bar renderer.**
The user reviewed the shipped v2 `Attack.ctp` (thin 8px **unlabeled** bars, all
techniques incl. no-hits shown, multi-hue gradient, hover-only) and reworked the
brief. **Appetite = redesign the renderer** (not a reskin). **Renderer-only**:
`Attack.ctp` + dashboard CSS (default + midnight) + a small unfold JS; the data
layer (`AttackExport`, `Galaxy::getMatrix`) stays **untouched** — the
`tabs`+`scores` payload, with `external_id` already stamped on every cell, carries
everything the redesign needs. Five locked points:

1. **Hide inactive techniques** — render only technique groups whose aggregate
   score > 0; tactic columns with no active group are hidden entirely (kills the
   muted-bar noise; the board's "what's hot" signal only).
2. **Larger, labeled cells** — each cell shows the technique name + T-ID + count,
   **readable without hover** (must work on a static wall display). Replaces the
   8px hover-only bars.
3. **Technique / sub-technique aggregation** — the shipped renderer flatly mixes
   them. *(CONFIRMED from live galaxy data: 526 sub-techniques all carry
   `kill_chain`, so they land in `tabs` intermixed with the 673 techniques in the
   same tactic columns.)* Group per tactic column by **parent T-ID** off
   `external_id` (`^T\d+$` = technique; `^T\d+\.\d+$` = sub-technique, parent =
   strip the `.\d+`). The parent cell shows the rolled-up aggregate; **click
   unfolds its sub-techniques on demand** (progressive disclosure). Parent heat =
   **SUM** of own + sub-technique event-counts (AD-15 fork; renderer-only;
   overcounts events hitting multiple sub-techniques of one parent — acceptable
   for a relative density ramp; "broader family coverage = hotter" reads right).
4. **Single red gradient + legend** — drop the export's multi-hue
   `ColourGradientTool` colours; compute each cell's shade in-renderer from
   `score / max-parent-score` on a single-hue red ramp; render a small
   legend/scale so intensity is interpretable.
5. **`time_window` wiring (AD-12, REAFFIRMED 2026-06-02)** — folded into this
   pass: add the `time_window` canonical to `AttackWidget::$schema`, map it to the
   restSearch 'attack' `timestamp` filter (`-1` ⇒ no bound), cache key includes
   the window. So the heatmap re-scopes with the board's toolbar like every other
   analyst widget. This is the only `AttackWidget.php` change.

**⚠ Sign-off (user, 2026-06-02).** The redesign **rewrites `Attack.ctp`**
(existing code, originally from the main dashboard-v2 track) + adds CSS/JS + edits
`AttackWidget.php` — beyond additive-only ([[feedback_additive_only_posture]]).
The user signed off **both** ("redesign the renderer" + "fold in `time_window`").
**Scope boundary: renderer + `AttackWidget` only — the data layer stays
untouched** (the "true distinct-event parent count" option was offered and
**declined** in favour of the renderer-only SUM). The platform **read-only render
posture is deviated** for the click-to-unfold — that's progressive disclosure of
the widget's *own* data, NOT a filter/scope action, and is explicitly
user-requested.

**Open at build (not blocking spec):**
- **Orphan sub-technique** — a sub-technique present in a column whose parent
  technique cell is absent (parent mapped to a different tactic, or parent lacks
  `kill_chain`): synthesise a group header from the parent T-ID (name fallback =
  the T-ID itself).
- **Non-`T####` `external_id`** — 43 clusters carry a non-T id
  (legacy/pre-attack): treat each as its own standalone top-level group (no
  sub-folding).
- A technique mapped to multiple tactics appears in multiple columns (existing
  matrix behaviour); aggregation is **per-column**.
- Unfold JS must **scope to the widget container** (multi-widget dashboard pages).
- `Attack` is an **existing** render kind → no new glyph needed (the CLAUDE.md
  glyph rule is for NEW kinds only); confirm the `Attack` glyph already exists in
  `render-thumbs.mjs`.
- Exact `time_window`→restSearch `timestamp` mapping (does 'attack' accept the
  relative "30d" form directly? reuse `TrendingAttributesWidget` /
  `CanonicalTypeAdapter`); confirm the `time_window` merge doesn't clobber the
  manual `attackGalaxy` / `published` filters.

---

**⚠ SUPERSEDED by the 2026-06-02 redesign above — kept for the audit trail.**

**Locked (2026-06-01):** The existing `AttackWidget` (`render=Attack`,
`restSearch 'attack'`, manual `filters`, `cacheLifetime=1200`). It is the only
analyst widget **not** on the `time_window` canonical (`$schema=[]`).

- **Decision = wire to the global `time_window`, in-place** (Fork: over a thin
  subclass or keep-as-is). Add a `time_window` canonical to AttackWidget's
  `$schema` and map it into the restSearch 'attack' `timestamp` filter (~a few
  lines), so the heatmap re-scopes with the board and becomes
  toolbar-bulk-editable like every other analyst widget — and AttackWidget
  improves for **all** dashboards, not just the analyst board.
- **⚠ Additive-only sign-off (user, 2026-06-01).** This is the track's **first
  change that touches existing code** beyond ACL/routes/composer
  ([[feedback_additive_only_posture]]). The user explicitly signed off: it's a
  small config/schema-class addition (one `$schema` entry + a few lines of
  filter mapping), **not** a rewrite. `handler()`'s existing manual `filters`
  (`attackGalaxy`, `published`) are preserved; only the `timestamp` portion is
  driven by `time_window`.
- **Mapping**: `time_window` ("30d" / seconds / `-1`=all) → the restSearch
  `timestamp` filter (reuse the in-tree translation —
  `TrendingAttributesWidget` / `CanonicalTypeAdapter`); `-1` ⇒ no timestamp
  bound. Cache key must include the window value (automatic once it's config).
- **Scope**: only `time_window` wired this pass. The orgs / tags / etc.
  canonicals could be wired into the restSearch filters later — out of scope here.
- **Confirms** the global window = the `time_window` canonical: W1 (trending
  engine) and W7 (new-data stats) should likewise declare `time_window` so the
  toolbar drives the whole board uniformly.

**Open at build (not blocking spec):** exact `time_window`→restSearch timestamp
mapping (does `attack` accept the relative "30d" form directly?); confirm the
manual `filters` + `time_window` merge doesn't clobber `attackGalaxy`.

### AD-W6 — Event-stream rework  `DECIDED`

**Locked (2026-05-31):** A **new widget** + a **new read-only render kind**,
both pure additions — `EventStreamWidget` is left untouched
([[feedback_additive_only_posture]]).

- **Approach (additive):** `EventStreamCardsWidget extends EventStreamWidget`
  (subclassing is an in-tree pattern — `OrgsUsing*` / `OrgsContributorLastMonth`
  extend `OrgsContributorsGeneric`; `Dashboard::loadWidget` loads by filename).
  It inherits the **entire proven data layer** verbatim: all canonical filters
  (`tags`, `orgs` w/ `match_via` + per-entry negate, `published`,
  `threat_level`, `analysis`, `sharing_group`, `galaxy_cluster`) and their
  `$schema` → **toolbar-bulk-editable for free**. Overrides only `$title`,
  `$render`, `$description`; `handler()` unchanged.
- **Layout = flat detailed cards** (Fork A: flat chosen over grouped-digest
  and ticker). Reverse-chronological; near-live (`autoRefreshDelay = 5`
  inherited). *Ticker rejected* — motion/accessibility, least detail per card,
  and the 5 s auto-refresh already reads as "live". *Grouped-digest deferred*
  — flat is the first cut; recency bucketing can come later.
- **New render kind = `EventCards`** (event-specific, like `UserList` /
  `QueueList`). Consumes the inherited `{data}` payload (full `fetchEvent`
  records) directly; the `fields` column list is an `Index`-render concept and
  is **ignored** by the card template (cards have a curated anatomy). **Needs a
  glyph** in `render-thumbs.mjs` — stacked-cards shape (CLAUDE.md rule).
- **Card anatomy** (per the accepted mockup): row 1 = threat-level dot
  (coloured by `threat_level_id`: High / Med / Low / Undefined) + threat label
  · `Orgc.name` · **relative time** (from `Event.timestamp`, consistent with
  AD-05's "what changed" anchor) · `#id` (link to `/events/view/<id>`); row 2
  = `Event.info` (truncated); row 3 = tag chips (coloured, capped + "+N more")
  + attribute-count badge (`Event.attribute_count` — confirmed present in
  `fetchEvent` metadata, no extra query). Token-driven CSS, no inline styles
  (mirror `Index.ctp` / `StatGrid.ctp`); reuse `Index.ctp`'s tag-chip colour +
  contrast helper.
- **Inline controls = reuse the toolbar bulk-edit** (Fork B): cards stay
  **read-only**, preserving the platform's deliberate read-only render posture
  (`Index.ctp`: "read-only widget surface"). Filter / scope / exclude is driven
  by the existing dashboard toolbar canonical bulk-edit — no in-body
  interactivity, so W6 stays inside the analyst-track charter (add widgets, not
  platform changes). In-body click-to-filter chips were considered and held
  back as a parent-PRD platform change.
- **Cache/ACL = none / near-live.** Unlike the aggregate widgets (AD-04), this
  is a **per-user ACL'd** view — `fetchEvent($user, …)` enforces ACL per caller
  — so it is neither per-org-cached nor a global count; it re-fetches live
  every `autoRefreshDelay`. (The one analyst widget that is genuinely per-user,
  not aggregate.)

**Open at build (not blocking spec):** final widget / render-kind names;
tag-chip cap N; info truncation length; relative-time formatting; the
stacked-cards glyph.

### AD-W7 — New-data stats  `DECIDED`

**Locked (2026-05-31):** Render = `StatGrid` (data contract from
`UsageDataWidget`: rows of `title`/`icon`/`value`/`change`/`drilldown`;
`change` is an int → `▲/▼` badge). Each card's `value` = the metric's count
in the **current window**; `change` = **delta vs the immediately-preceding
equal-length window** (`current − prior`; negative ⇒ ▼) — shares AD-W1's
prior-window baseline (AD-03). Window anchor = **`Event.timestamp`** (AD-05).

**The four metrics:**
1. **New events** — `COUNT(Event)` with `Event.timestamp` in window. *Global
   count, no ACL filter* (AD-06).
2. **New attributes** — `COUNT(Attribute)` with `Attribute.timestamp` in
   window, `deleted = 0`. Global count, no ACL filter (AD-06). (Metric 2 is
   *new attributes in window*, not corpus size.)
3. **Events targeting my org's country/sector** — distinct events in window
   carrying `misp-galaxy:country="<c>"` ∪ `misp-galaxy:sector="<s>"`, with
   `<c>`/`<s>` resolved by the **targeting waterfall** (below). Shows **N/A**
   (not `0`) when neither resolves. Cached by the resolved `(country, sector)`
   tuple + window.
4. **New events published by my org** — `Event.orgc_id = <my org>` AND
   `published = 1` AND `publish_timestamp` in window. Anchored on
   `publish_timestamp` **here only**: for an org's *own* events that stamp is
   a genuine local publish act, so the sync-propagation unreliability that
   rules `publish_timestamp` out elsewhere (AD-05) does not apply. Cached
   per-`orgc_id` + window.

**Targeting waterfall (metric 3) — resolve country `<c>` and sector `<s>`
independently; first hit wins:**
- **Country `<c>`:** (1) explicit widget config → (2) `org.nationality`
  case-folded to a `country.json` cluster `value` (fallback: `meta.ISO`/
  `ISO3`) → (3) the org **name's ccTLD** matched to `country.json`
  `meta.tld` (e.g. `post.lu` → `.lu` → cluster `value` "luxembourg") →
  (4) none.
- **Sector `<s>`:** (1) explicit widget config → (2) `org.sector` case-folded
  to a `sector.json` cluster `value` → (3) none. (No TLD path — a TLD yields
  a country, never a sector.)
- ccTLD→country is **self-contained**: `country.json`'s 252 clusters each
  carry `meta.tld` + `meta.ISO`/`ISO3` + a lowercase `value`; no external
  list needed.
- A **widget config option** to set country/sector explicitly **overrides all
  heuristics** (some communities enforce org meta; many don't set it — don't
  take the dev instance, where most orgs are blank, as ground truth).

**Cache/ACL (AD-06 applied):** metrics 1–2 = global counts (no ACL filter),
global+window cache key; metric 3 = `(country, sector)`+window key; metric 4 =
`orgc_id`+window key. Nothing is ACL-filtered, so AD-04's site-admin no-ACL
bucket is **moot** here. Lazy-loaded on render; freshness modest (counts are
cheap — propose ~5 min, confirm at build).

**Window source:** widget takes a `time_window` param (the proven
`start_date`/`end_date` `date_range` pattern from `UsageDataWidget`); if/when
the platform exposes a global `time_window` control, inherit it. Default
window length **flagged for build** (propose 7d).

**Open at build (not blocking spec):** exact default window; `~5 min`
freshness; metric drilldown URLs (events-index filtered by window + metric);
whether the `country.json` lookup is a build-time prebuilt map or read live.

### AD-W8 — Overlap-with-my-org  `DECIDED`

**Locked (2026-06-01):** The "affects me" payoff widget — "what's new that I
should *care* about". Surfaces NEW window events (`Event.timestamp` in window,
ACL-visible) that **correlate with events my org created**.

- **Overlap definition = correlation-based** (Fork: over raw attribute-value
  intersection). Reuse `Correlation->getRelatedEventIds($user, $eventId,
  $sgids)` — it is **ACL-correct AND engine-agnostic** (works under
  Default / NoAcl / OnDemand engines), and inherits correlation's denoising
  (over-correlating values + correlation_exclusions already stripped) and its
  fuzzy matches (ssdeep / CIDR). Rejected raw value-intersection: expensive
  (value joins, no reusable index), redundant (correlations *are* value matches
  + more), and would force re-implementing ACL + denoising.
- **Reference set = events my org created** (`Event.orgc_id` = my org) (Fork:
  over "events my org can see" — the broader set is close to "has any
  correlation at all", which dilutes the "affects ME" signal).
- **⚠ Build approach (forced by research, not a fork).** Do NOT scan
  `default_correlations` by `org_id`: it has **no `org_id`/timestamp index**,
  its `org_id` is the *visibility* org **not the creator** (`orgc_id` isn't on
  correlations), and the OnDemand engine has no table at all. Instead **anchor
  on the bounded window-event set** (what the analyst cares about anyway): for
  each window event, call `getRelatedEventIds`, keep it iff a related event's
  `orgc_id` = my org. Cost scales with the window, not the correlation table;
  no schema change; engine-safe; correlation lookups are `event_id`/`1_event_id`
  indexed.
- **Render = reuse the W6 `EventCards` kind** with an **"overlaps N of your
  events" badge** (overlap strength = # of my-org events the candidate
  correlates to). Ranked by overlap strength desc, then recency. (Confirm at
  build.)
- **ACL / cache:** ACL inherited from `getRelatedEventIds` + the per-`$user`
  window-event fetch; **per-org cache** (AD-04). **Cost guard:** cap the
  candidate window-event set (top-N most recent) before the per-event related
  lookups; **`log()` if capped** (no silent truncation).
- **Window anchor** = `Event.timestamp` (AD-05) on the candidate (new) events.

**Open at build (not blocking spec):** overlap-strength metric (distinct
my-org events vs # correlating attributes); candidate cap N; whether to
drill-down to *which* of my events overlap; the badge's exact text.

### AD-W9 — Sightings rework — **DECLINED (AD-16)**
First-pass (user): "definitely rework, but **maybe just a look-and-feel
rework**" — the sighting engine is slow and some communities don't use it,
so don't over-invest in a live "are my IOCs sighted?" engine.
**Resolution (2026-06-02, AD-16):** at W9 spec time the recon surfaced that both
sightings widgets (`RecentSightingsWidget`, `ThresholdSightingsWidget`) are
**`perm_site_admin`-gated** via `checkPermissions()`, while `Sighting->restSearch`
is itself user-ACL-aware — an analyst rework would mean untangling that gate-vs-
ACL conflict. The user reviewed the finding and **declined the rework** ("the ACL
for that is indeed a shitshow"). W9 is **dropped from the roster**; the existing
sightings widgets are left exactly as-is. The analyst widget surface is
**complete at W1–W8**.

### Shared render kind — `FeedList`  `DECIDED` (AD-17)

A **new read-only render kind** serving all three of W10/W11/W12 (the user
chose it over reusing Index/SimpleList — see AD-17). Output shape = a
**reverse-chronological feed of "recently added" items**, each row:

```
[icon]  TITLE                                  → (whole row links if drilldown)
        org · relative-time · context     [chip] [chip]
        "optional snippet / subtitle, truncated"
```

- **Payload contract** = a **flat list of row dicts** (bare handler return, no
  `{data:}` wrapper — same posture as `Trending.ctp` / `StatGrid.ctp`). Per row
  (all optional except `title`):
  - `title` (string, **required**) — primary line.
  - `icon` (string) — FontAwesome name, rendered via the FontAwesome helper
    (reuse the `Trending.ctp` icon slot pattern).
  - `org` (string) — author/owner org name → first meta segment.
  - `timestamp` (int, epoch) — rendered as relative time ("5w ago") in the
    meta line (template computes; tooltip = ISO).
  - `context` (string) — a context descriptor in the meta line (e.g.
    "Event #1842", "on Attribute").
  - `chips` (string[]) — small muted pills (e.g. analyst-data type / target
    object type / galaxy type). The W11 "show the target object type"
    requirement rides here.
  - `subtitle` (string) — snippet / secondary text, template-truncated.
  - `drilldown` (string) — makes the whole row a link (shows the `→` affordance);
    **DD-03-gated** via `DashboardURLValidator` exactly like `Trending.ctp`.
- **Token-driven CSS, no inline styles** (mirror `EventCards.ctp` /
  `StatGrid.ctp`); reuse existing semantic tokens so the global midnight overlay
  themes it for free (no overlay edit — [[project_misp_dark_theme_sequencing]]).
- **New render kind ⇒ a glyph** in `render-thumbs.mjs` (CLAUDE.md rule):
  `thumbFeedList()` — a stack of feed rows (leading dot/icon + a title line + a
  shorter meta line), distinct from `EventCards` (receding cards), `SimpleList`
  (bare rows), `StatGrid` (2×2 grid).
- **Shared widget settings** (all three): `limit` (int, default 10 — the feed is
  **N-newest-bounded**, so it always shows content regardless of corpus age) and
  `time_window` (the track-wide canonical, default **`-1` = no time filter**;
  set it to scope the feed to a recent window). Read-only (no in-body controls);
  filters/scope ride the toolbar like the rest of the track.

### AD-W10 — Recent Event Reports  `DECIDED`

**Locked (2026-06-02):** A new widget (`RecentEventReportsWidget`,
`render=FeedList`) listing the **N newest Event Reports visible to the viewer**,
reverse-chronological. Serves job 1 ("what's new").

- **Fetch** = `EventReport->fetchReports($user, ['conditions' => ['EventReport.deleted' => 0
  (+ optional `EventReport.timestamp >=` when a finite `time_window` is set)],
  'order' => ['EventReport.timestamp' => 'DESC'], 'limit' => N])`. ACL is **inside
  `fetchReports` → `buildACLConditions($user)`** (reuses `Event::createEventConditions`
  + the report's own distribution / sharing-group; site-admin sees all) — clean,
  not a W9 trap. `contain` the parent `Event` + `Orgc` for the org/event display.
- **Recency anchor** = `EventReport.timestamp` (epoch; set on create, bumped on
  edit → honestly "recently created or updated").
- **Row mapping** → `icon` = a report/document glyph (`file-text-o`-ish);
  `title` = `EventReport.name`; `subtitle` = a stripped/truncated `content`
  snippet; `org` = `Orgc.name`; `timestamp` = `EventReport.timestamp`; `context`
  = "Event #<event_id>"; `drilldown` = `/eventReports/view/<id>` (relative →
  DD-03 admits, no relaxation).
- **No per-org cache** — like W6 this is a per-user ACL'd fetch (`fetchReports`
  enforces ACL per caller); it re-fetches live. (Cheap: indexed `timestamp` +
  `LIMIT N`.)

**Open at build (not blocking spec):** the exact content-snippet strip/length;
whether the card links to the report (`/eventReports/view`) or the parent event
(chosen: the report — it's the "new thing"); the report glyph name.

### AD-W11 — Recent Analyst Data  `DECIDED`

**Locked (2026-06-02) — RE-SCOPED from the original "on my org's events" brief.**
The user dropped the my-org-events filter (it would need a child-UUID `IN` list
— a feasibility/perf risk, W9-adjacent) in favour of the simpler, strictly safe
**"newest analyst data the current user can view."** New widget
(`RecentAnalystDataWidget`, `render=FeedList`).

- **Scope** = **Notes + Opinions only** (Relationships dropped — they're
  object-to-object structural links, not commentary, and sparse), **any target
  object type** (Event / Attribute / Object / GalaxyCluster / …), with the
  **target object type shown on every row** (user's explicit requirement).
- **Fetch** = two ACL'd queries — `Note` and `Opinion` — each
  `find('all', ['conditions' => $Model->buildConditions($user) (+ optional
  `modified >=` window), 'order' => ['modified' => 'DESC'], 'limit' => N,
  'contain' => ['Org','Orgc']])`, then **merge + sort by `modified` DESC + take
  top N** in PHP. `buildConditions` (`AnalystData` base) applies org_uuid +
  distribution + sharing-group ACL; site-admin sees all. **No event-UUID
  pre-filter, no transitive child mapping** — the re-scope's whole point.
- **Recency anchor** = `modified` (datetime; the base recency field).
- **Row mapping** → `icon` = type glyph (Note → `sticky-note`/`comment`,
  Opinion → `balance-scale`/`thumbs`); `title` = the note text (Note) or the
  opinion `comment` (Opinion), stripped/truncated; `subtitle` = for Opinion, the
  `opinion` value (0–100) rendered (e.g. "Opinion: 76/100"); `chips` = the
  **target `object_type`** label (+ the analyst-data type Note/Opinion if not in
  the icon); `org` = `Orgc.name`; `timestamp` = `modified`; `drilldown` =
  best-effort to the target (Event → `/events/view/<id>` resolved from
  `object_uuid`; GalaxyCluster → `/galaxy_clusters/view`; else the analyst-data
  item view or no link), DD-03-gated.
- **Permission gate** — confirm at build whether viewing requires
  `perm_analyst_data` (the recon flagged it as the analyst-data perm) or whether
  the distribution ACL (`buildConditions`) suffices; gate the widget only if
  required.
- **No per-org cache** — per-user ACL'd fetch, re-fetched live.

**Open at build (not blocking spec):** the exact per-target-type drilldown
resolution (which types get a link vs a bare type chip); the Opinion-value
rendering; whether to resolve Event `object_uuid` → id for the link in one bulk
query; the `perm_analyst_data` gate question above.

### AD-W12 — Recently Added Galaxy Clusters  `DECIDED`

**Locked (2026-06-02):** A new widget (`RecentGalaxyClustersWidget`,
`render=FeedList`) listing the **N newest LOCAL galaxy clusters** (`default=0`)
visible to the viewer, reverse-chronological. Serves job 1 ("what's new").

- **Population = local clusters only (`default=0`)** (user fork): the shipped
  `default=1` clusters (63k on the dev box) are bulk-imported with batch
  `version` dates, so including them would flood the feed with "new" clusters on
  every sync/import — noise. `default=0` (locally created / forked) is the
  genuinely user-"added" set.
- **Fetch** = `GalaxyCluster->fetchGalaxyClusters($user, ['conditions' =>
  ['GalaxyCluster.default' => 0, 'GalaxyCluster.deleted' => 0 (+ optional
  `GalaxyCluster.version >=` window)], 'order' => ['GalaxyCluster.version' =>
  'DESC'], 'limit' => N], $full=false)` with the parent `Galaxy` joined for
  `icon`/`type` (the `TrendingWidget` threat-actor label hook already does this
  join — reuse the pattern). ACL is inside `fetchGalaxyClusters →
  buildConditions` (org / distribution / sharing-group + parent-galaxy access).
- **Recency anchor** = `version` (epoch — the **only** timestamp on the table;
  set on create **and** edit, so the widget is honestly "recently added or
  updated"; label the time accordingly). A few legacy rows carry `version≈0` →
  they sort to the bottom and a finite window drops them.
- **Row mapping** → `icon` = `Galaxy.icon` (FA, via the helper); `title` =
  `GalaxyCluster.value`; `subtitle` = the galaxy name + (optional) a short
  `description` snippet; `chips` = the galaxy `type` (e.g. "threat-actor");
  `org` = `Orgc.name`; `timestamp` = `version`; `drilldown` =
  `/galaxy_clusters/view/<id>` (relative → DD-03 admits).
- **No per-org cache** — per-user ACL'd fetch, re-fetched live.

**Open at build (not blocking spec):** whether to expose an optional
`galaxy_type` filter (deferred — keep v1 minimal); the description-snippet
length; confirming `fetchGalaxyClusters` returns `Galaxy.icon`/`Orgc.name` at
`$full=false` (else bump to a targeted contain/join).

## 6. Decision log (AD-NN)

**AD-01 — 2026-05-31 — One parametrised `Trending` widget + a new
ranked-row render kind.** Refs: idea-1 (user-accepted), parent DD-45
(render-kind family), CLAUDE.md glyph rule, `feedback_additive_only_posture`.
Instead of 3–4 near-identical `Trending{CVEs,ThreatActors,Techniques}`
classes, one `Trending` widget takes a `dimension` config; CVEs / actors /
techniques (+ free malware / tool / sector) are dimensions with per-dimension
hooks (counting strategy, label resolver, link builder). Render is a NEW kind
— a ranked-row list (label · inline bar · count · delta badge · optional
sparkline) — because BarChart can't carry the per-row delta badge; a glyph
goes in `render-thumbs.mjs`. Additive (new widget + new render kind; no
existing widget touched). Fork 1 = (b); Fork 1b confirmed the new render kind.

**AD-02 — 2026-05-31 — Counting metric = distinct events containing the
value (each event = 1).** Refs: AD-01, user spec. The trend metric is
`COUNT(DISTINCT event_id)` per value — an event with thousands of identical
occurrences counts once — to resist per-org reporting process-noise. Sources
unioned then deduped to events: event tag (`EventTag`) ∪ attribute/object tag
(`AttributeTag`) ∪ attribute value (`Attribute`, e.g. `vulnerability` type).
Computed off the narrow indexed connector tables, not by hydrating events
(user's "cheat"). Deliberately diverges from `TrendingAttributesWidget`'s raw
`count(value1)`.

**AD-03 — 2026-05-31 — Momentum = floored-% delta vs prior equal window; no
spike detection.** Refs: AD-01/02, AD-W7 (shared baseline), user cost
constraint. Each row shows volume rank + a `▲/▼` movement badge = % change of
its distinct-event count vs the immediately-preceding equal-length window.
Eligibility floor: a configurable minimum current-window count before
"rising" is flagged (kills small-N % noise). Spike detection (current vs
trailing mean+kσ) explicitly deferred — needs bucketing + history, and
lookups are already cost-sensitive at community scale.

**AD-04 — 2026-05-31 — Aggregate widgets cache per-org (the ACL atom),
lazy-loaded, never background-shared; source = all events, not
published-only.** Refs: AD-01/02/03, parent DD-20/21 (per-widget cache), user
ACL spec. MISP's ACL atom is the **organisation** — two users in the same org
see the same events — so ACL-scoped aggregate widgets cache with `cache_scope`
keyed by **org**: correct AND shared across the org's users, vs a single
background-computed blob (would leak across orgs) or per-user (needless
duplication). **Site admins** = a separate no-ACL bucket (they see
everything). Data is **lazy-loaded on render + cached**, not precomputed by a
background job. **Freshness is per-widget:** cheap live widgets (event stream,
W6) refresh every few seconds; heavy aggregates (trending) cache ~15–30
min/org. Source set is **all events, not published-only** — orgs actively
collaborate on unpublished events; publication only governs cross-community
sync, so trending must not be blind to pre-publication data. Confirmed:
`AttributeTag` carries `event_id` (not only `attribute_id`), so distinct-event
counting at attribute-tag level is a single narrow indexed lookup, no join to
`Attribute`.

**AD-05 — 2026-05-31 — Window anchor = `Event.timestamp` (last-modified),
track-wide.** Refs: AD-W1 deferred anchor, AD-W7, parent PRD J1, user domain
note. The timestamp that puts an event "in the window" is `Event.timestamp`
(last change), **not** `publish_timestamp`: (a) any edit forces a republish so
the two move together for locally-edited events, but (b) `publish_timestamp`
records propagation **to this instance** — a fresh sync connection pulling a
peer's historic dataset stamps the whole batch at sync time, so it is
unreliable as a "newness" signal; (c) `Event.timestamp` is indexed, matches
"what changed since I was last here" (J1), and includes unpublished events
(AD-04). Attribute-level sources test `Attribute.timestamp` analogously.
*Exception:* AD-W7 metric 4 ("published by my org") uses `publish_timestamp`,
because for an org's **own** events that stamp is a genuine local publish act,
not a sync import. (`first_seen` rejected — sparse attribute-level nanosecond
field, not an event anchor.)

**AD-06 — 2026-05-31 — Aggregate count metrics may skip ACL filtering (global
counts acceptable); only org-contextual metrics are org-scoped.** Refs:
refines AD-04; user ("generally for aggregate information we're ok with
that"). A pure scale-count ("N new attributes this window") exposes no
specific intel, so it need not be ACL-filtered — query it globally
(`timestamp > x`) and cache under a global+window key. This **refines AD-04**:
"ACL-scoped aggregate widgets cache per-org" still holds for genuinely
ACL-scoped aggregates, but pure counts aren't ACL-scoped at all → for them
both the per-org cache **and** the site-admin no-ACL bucket are moot.
Org-**contextual** metrics (targeting my org, published by my org) stay keyed
by their org context (resolved country/sector tuple; `orgc_id`), not by ACL.

**AD-07 — 2026-05-31 — AD-W7 (new-data stats) DECIDED.** Refs: AD-05/06, AD-03
(shared prior-window delta baseline), `UsageDataWidget` (StatGrid contract).
Four `StatGrid` metrics; each `value` = current-window count, `change` = delta
vs the prior equal window: (1) new events (`Event.timestamp` in window,
global), (2) new attributes (`Attribute.timestamp` in window, `deleted=0`,
global), (3) events targeting my org's country/sector (distinct events
carrying `misp-galaxy:country=` ∪ `misp-galaxy:sector=`, resolved via the
**targeting waterfall**: explicit widget config → org `nationality`/`sector` →
org-name ccTLD (country only) → N/A; ccTLD→country resolved self-contained
from `country.json` `meta.tld`/`ISO`), (4) new events published by my org
(`orgc_id`=me, `published=1`, `publish_timestamp` in window). A widget option
to set country/sector overrides all targeting heuristics. Cache split per
AD-06. Full spec in §5. Build is deferred — the track stays in spec mode; next
spec target is W6, while the first *build* unit remains W1 (engine-first).

**AD-08 — 2026-05-31 — AD-W6 (event-stream rework) DECIDED.** Refs: AD-04
(cache contrast), the parent read-only render posture (`Index.ctp`), user
Fork A (flat cards) + Fork B (toolbar bulk-edit). A pure-additive
`EventStreamCardsWidget extends EventStreamWidget` (in-tree subclassing
precedent: `OrgsUsing*` extend `OrgsContributorsGeneric`) inherits the whole
canonical-filter data layer (toolbar-bulk-editable) and overrides only
`$render` / `$title` / `$description`. New **read-only** render kind
`EventCards` (+ glyph) lays out flat reverse-chron cards straight from the
`fetchEvent` payload: threat dot · `Orgc.name` · relative time (`Event.timestamp`,
per AD-05) · `#id` · `Event.info` · tag chips · attr count (`Event.attribute_count`,
confirmed in `fetchEvent` metadata). Filter / scope / exclude stays on the
existing toolbar bulk-edit — cards are read-only, preserving the platform
posture and the analyst-track "add widgets, not platform changes" charter. No
cache: `fetchEvent` is per-user ACL'd and near-live (5 s), so AD-04's per-org
aggregate cache does not apply. Ticker rejected (motion/accessibility;
redundant with auto-refresh); grouped-digest deferred (flat is the first cut).

**AD-09 — 2026-05-31 — AD-W2 (Trending Vulnerabilities) DECIDED; trending
counts are ACL-scoped, not global.** Refs: AD-01/02/03/04 (engine), AD-05
(anchor), AD-06 (the contrast), user ACL watch-out + "all vulnerability IDs".
The first W1 dimension. Scope = all `vulnerability` attribute identifiers
(CVE/GCVE/GHSA — one identifier-agnostic type; research confirmed no separate
gcve/ghsa type). Counting = `COUNT(DISTINCT event_id)` over
`type='vulnerability' AND deleted=0` grouped by `value1` — the AD-02 union
collapses to the attribute-value arm (CVEs aren't tags). **Key clarification
the user flagged: trending value-rankings MUST be ACL-scoped** to the org's
visible events (AD-04 per-org cache), unlike AD-06's global scale-counts —
surfacing *which* values are rising reveals content. The narrow-table count
still applies but is constrained to the visible event set; primary build risk =
a lightweight ACL-correct count path (reuse `Attribute` ACL conditions, no
event hydration). Window anchor `Attribute.timestamp` (AD-05); momentum AD-03;
label = identifier verbatim; link-out = `MISP.cveurl` + value (`{cveurl}{value}`,
default corrected to `https://vulnerability.circl.lu/vuln/`, sibling `cweurl`
out of scope). Generalises to the engine: **AD-06 (skip ACL) applies only to
scale-counts, never to value-rankings (AD-04).**

**AD-10 — 2026-06-01 — AD-W3 (Trending Threat Actors) DECIDED.** Refs:
AD-01/02/03/04/05 (engine/anchor), AD-09 (ACL), user Forks (threat-actor only;
per-cluster label). Second W1 dimension. Scope = native `threat-actor` galaxy
only (chosen over the actor-galaxy union — sidesteps the no-canonical-UUID
cross-galaxy identity-merge problem). Counting = `COUNT(DISTINCT event_id)`
over `EventTag` ∪ `AttributeTag` for the threat-actor cluster tag-id set
(AD-02's tag arms — event AND attribute/object level; contrast W2's value arm);
indexes present. **ACL reinforced (AD-09):** the in-tree
`AttributeTag::countForTags()` skips ACL and counts occurrences, so it's
unusable as-is — W3 needs a custom ACL-correct distinct-event count over the
union, cached per-org. Anchors per AD-05 (event-tag→`Event.timestamp`,
attribute-tag→`Attribute.timestamp`); momentum AD-03. Label resolver =
`GalaxyCluster.value` + `Galaxy.icon` + synonyms-on-hover (per-cluster, no
merge; merge deferred), resolved bulk to avoid N+1. Link-out =
`/galaxy_clusters/view/<id>`.

**AD-11 — 2026-06-01 — AD-W4 (Trending Attack Techniques) DECIDED.** Refs:
AD-10 (reuses W3 galaxy machinery), AD-01/02/03/04/05, AD-09 (ACL), W5
distinctness, user Fork (roll up sub-techniques). Third W1 dimension. Scope =
`mitre-attack-pattern` (Enterprise) only (mirrors W3's native-galaxy-only).
Counting = engine-native reuse of W3's ACL-correct distinct-event count over
`EventTag` ∪ `AttributeTag`, with the tag-id set **grouped by parent
technique**: each sub-technique (`T1566.001`) folds into its parent (`T1566`,
".NNN" stripped); distinct-event taken at parent level. Anchors AD-05; momentum
AD-03. Label = parent cluster `value` + `external_id` + `Galaxy.icon` (`map`);
link = `/galaxy_clusters/view/<parent_id>`; bulk-resolved. **DISTINCT from W5:**
W4 = ranked top-N + momentum wired to the global window; W5 = the spatial ATT&CK
matrix heatmap (`AttackWidget`, `restSearch 'attack'`, manual filters).
Counting-path: engine-native chosen for consistency; the `attack` restSearch
returnFormat (what W5 uses) noted as a build-time alternative (ACL-correct but a
parallel path needing AD-02 distinct-event verification).

**AD-12 — 2026-06-01 — AD-W5 (ATT&CK heatmap) DECIDED: wire to global
`time_window` in-place; first additive-only sign-off.** Refs: existing
`AttackWidget`, the `time_window` canonical (PewPew / GeoMap / Trending*
precedent), user sign-off. AttackWidget is the only analyst widget not on the
`time_window` canonical (`$schema=[]`). Decision: add the `time_window`
canonical to its `$schema` and map it into the restSearch 'attack' `timestamp`
filter (~a few lines), so the heatmap re-scopes with the board and becomes
toolbar-bulk-editable like every other analyst widget. **This touches existing
code beyond ACL/routes/composer — the track's FIRST such change — and the user
explicitly signed off ([[feedback_additive_only_posture]]); it's a small
config/schema-class change, not a rewrite.** Existing manual `filters`
(`attackGalaxy` / `published`) preserved; only the timestamp portion is driven
by `time_window`; cache key includes the window (automatic as config). Only
`time_window` wired this pass (orgs/tags out of scope). Confirms the global
window = the `time_window` canonical → W1 and W7 should also declare it.

**AD-13 — 2026-06-01 — AD-W8 (Overlap-with-my-org) DECIDED.** Refs: AD-04
(cache), AD-05 (anchor), AD-09 (ACL pattern), correlation-engine research, user
Forks (correlation-based; my-org-created). The "affects me" payoff widget:
surfaces NEW window events (`Event.timestamp` in window, ACL-visible) that
correlate with events my org **created** (`orgc_id`). Definition =
correlation-based — reuse `Correlation->getRelatedEventIds($user, …)`, which is
ACL-correct AND engine-agnostic (Default/NoAcl/OnDemand) and inherits
correlation denoising + fuzzy matches. Reference set = `Event.orgc_id` = my org.
**Build approach (forced by research): anchor on the bounded window-event set +
per-event `getRelatedEventIds`, keep those whose related events are
my-org-created** — sidesteps `default_correlations`' missing `org_id`/timestamp
index, the `org_id`=visibility-not-creator gap, and the OnDemand no-table case;
no schema change. Render = reuse the W6 `EventCards` kind with an "overlaps N of
your events" badge, ranked by overlap strength. Per-org cache (AD-04). Cost
guard = cap candidate window events (top-N recent), `log()` if capped. Rejected
raw attribute-value intersection (expensive, redundant, re-implements ACL).

**AD-14 — 2026-06-02 — AD-W8 `exclude_own_org` setting (build refinement).**
Refs: AD-13, user fork ("can you make it a setting?"). The locked AD-W8
candidate set is *every* ACL-visible window event; only the *related* set is
restricted to my-org-created. That admits a self-referential case — my org's
own new event surfacing because it correlates with my org's older events —
which dilutes the "external affects-me" signal the widget is for. Rather than
hard-pick exclude-vs-keep, exposed it as a boolean config **`exclude_own_org`
(default `true`)**: true drops candidates whose `orgc_id` is my org (pure
external signal); false honours the literal AD-13 candidate-set definition.
Default true because the widget's framing ("what just landed that affects me")
is external situational awareness. Built into `OverlapWithMyOrgWidget`
(`$params` doc + lenient bool coercion); verified live (false→44 / true→25
candidates on the dev corpus, admin org 1 correctly dropped).

**AD-15 — 2026-06-02 — AD-W5 (ATT&CK heatmap) REDESIGN; supersedes the static
thin-bar renderer; AD-12 `time_window` reaffirmed + folded in.** Refs: AD-12
(parked; sign-off was void), the shipped v2 `Attack.ctp` (main dashboard-v2
track, commit `01feda2b0`), user rework brief + appetite ("redesign the
renderer"), live galaxy-data feasibility check. The user was dissatisfied with
the shipped static heatmap; the concrete brief is **renderer-only** (`Attack.ctp`
+ dashboard CSS + small unfold JS — data layer `AttackExport`/`Galaxy::getMatrix`
**untouched**, since the `tabs`+`scores`+per-cell `external_id` payload already
suffices): **(1)** hide inactive (zero-score) techniques and empty tactic
columns; **(2)** larger **labeled** cells (name + T-ID + count, readable without
hover — wall-display usable); **(3)** **technique/sub-technique aggregation** —
the shipped renderer flatly mixes them (confirmed: all 526 sub-techniques carry
`kill_chain` → intermixed with the 673 techniques in tabs); group per tactic
column by parent T-ID off `external_id` (`^T\d+$` technique / `^T\d+\.\d+$`
sub-technique → strip `.\d+`); parent cell = rolled-up aggregate, **click unfolds
sub-techniques on demand**; **parent heat = SUM of own + sub counts** (fork:
sum/max/true-distinct → user chose SUM, renderer-only, overcount-tolerant);
**(4)** **single red gradient + legend** (drop the export's multi-hue
`ColourGradientTool`; shade in-renderer from `score/max-parent-score`); **(5)**
**fold in AD-12** — wire the `time_window` canonical into `AttackWidget::$schema`
+ restSearch `timestamp` (the only `AttackWidget.php` change). **Sign-off (user):
renderer rewrite + `AttackWidget` edit are beyond additive-only and explicitly
approved; data layer is the scope boundary (true-distinct-count declined). The
read-only render posture is deviated for the click-to-unfold — progressive
disclosure of the widget's own data, not a filter/scope action, user-requested.**
B7 is **UN-PARKED** with this spec.

**AD-16 — 2026-06-02 — AD-W9 (Sightings rework) DECLINED; roster closes at
W1–W8.** Refs: PRD §3 AD-W9 row, the W9 spec-time recon (this session). At W9
spec time the recon found both sightings widgets (`RecentSightingsWidget`,
`ThresholdSightingsWidget`) gate on `perm_site_admin` in `checkPermissions()`,
while `Sighting->restSearch($user, …)` already user-scopes results — so an
analyst-facing rework would require reconciling a widget-level site-admin gate
against `restSearch`'s per-user ACL (on top of the known engine slowness / patchy
community use the first-pass steer already flagged). The user reviewed the
finding and **declined**: "let's not touch the sighting one, the ACL for that is
indeed a shitshow." **Decision:** W9 is dropped from the roster — no analyst
sightings widget is built, and the existing `RecentSightingsWidget` /
`ThresholdSightingsWidget` are left unchanged. The analyst widget surface is
**COMPLETE at W1–W8** (all built + verified through Phases B1–B9). No further
build phase; the track is done barring user-requested follow-ups.

**AD-17 — 2026-06-02 — TRACK REOPENED: three new feed widgets (W10/W11/W12) on
one new shared render kind `FeedList`.** Refs: user request (this session),
CLAUDE.md glyph rule, [[feedback_additive_only_posture]], the AskUserQuestion
render fork. After W1–W8 shipped, the user asked for three "what's new" widgets —
new reports, analyst data they can see, new galaxy clusters — and explicitly put
"new UI" in scope. All three are the **same output shape**: a reverse-chron feed
of recently-added items (icon · title · org·time·context meta · optional snippet ·
optional chips). The existing render kinds don't fit cleanly (SimpleList too thin;
Index a dense table; EventCards event-specific), so the **user chose a new shared
`FeedList` render kind** over reuse — one new render template + CSS block + one
gallery glyph, serving all three cohesively (more economical and consistent than
three mismatched reuses). **Pure additive:** three new widget classes + the new
render kind; **no existing widget or handler is touched** (CSS-append +
render-thumbs glyph are the established additive track patterns from B1/B3/B8). All
three are **per-user ACL'd live fetches** (no per-org cache — like W6) and
**N-newest-bounded** (`limit`, default 10) with an optional `time_window` filter
(default `-1`). Full contract in §5 "Shared render kind — `FeedList`".

**AD-18 — 2026-06-02 — AD-W10 (Recent Event Reports) DECIDED.** Refs: AD-17
(FeedList), EventReport recon. `RecentEventReportsWidget` (`render=FeedList`)
lists the N newest visible Event Reports, reverse-chron by `EventReport.timestamp`.
Fetch via `EventReport->fetchReports($user, …)` whose `buildACLConditions` reuses
`Event::createEventConditions` + the report distribution/SG (clean ACL, not a W9
trap); `deleted=0`; optional `timestamp` window bound. Row = report glyph · name ·
content snippet · `Orgc.name` · relative time · "Event #<id>" context · drilldown
`/eventReports/view/<id>` (DD-03-admitted relative link). No cache (per-user
ACL'd, cheap indexed `LIMIT N`). Full spec §5 AD-W10.

**AD-19 — 2026-06-02 — AD-W11 (Recent Analyst Data) DECIDED — RE-SCOPED.** Refs:
AD-17, AnalystData recon, user re-scope. The original brief ("analyst data on my
org's events") would need a child-UUID `IN` list to catch notes on attributes/
objects inside my events — a feasibility/perf risk the user flagged ("I am indeed
worried about the child UUID in list"). The user **re-scoped to "the newest analyst
data the current user can view"** — no my-org filter, **Notes + Opinions only**
(Relationships dropped as structural/sparse), **any target object type with the
target type displayed**. Fetch = two ACL'd queries (`Note`, `Opinion`) via
`AnalystData::buildConditions($user)` (org_uuid + distribution + SG), ordered by
`modified` DESC, merged + top-N in PHP. This is **strictly simpler and safer** than
the original (one of the rare cases where the re-scope removes risk rather than
adding it). Row = type glyph · note text / opinion comment · target-type chip ·
`Orgc.name` · relative `modified` · best-effort target drilldown. Confirm the
`perm_analyst_data` view gate at build. No cache. Full spec §5 AD-W11.

**AD-20 — 2026-06-02 — AD-W12 (Recently Added Galaxy Clusters) DECIDED.** Refs:
AD-17, GalaxyCluster recon, user fork (local only). `RecentGalaxyClustersWidget`
(`render=FeedList`) lists the N newest **local** clusters (`default=0`) visible to
the viewer, reverse-chron by `version`. **Local-only** because the 63k shipped
(`default=1`) clusters carry batch import `version` dates → including them would
flood the feed on every sync (user chose local). `version` is the only timestamp
(set on create AND edit) → labeled "added or updated". Fetch via
`GalaxyCluster->fetchGalaxyClusters($user, …)` (`buildConditions` ACL + parent-
galaxy access), parent `Galaxy` joined for `icon`/`type` (reuse the TrendingWidget
threat-actor join). Row = `Galaxy.icon` · `value` · galaxy name/type chip ·
`Orgc.name` · relative `version` · drilldown `/galaxy_clusters/view/<id>`. No
cache. Full spec §5 AD-W12.

## 7. Open meta-questions (resolve early)

1. ~~`AD-NN` numbering vs continuing parent `DD-NN`?~~ **RESOLVED**
   (2026-05-31): `AD-NN`, in use through AD-07, cross-linked to parent
   `DD-NN`.
2. ~~Split an `analyst-dashboard-progress.md` now?~~ **RESOLVED**
   (2026-05-31): split now → [`analyst-dashboard-progress.md`](analyst-dashboard-progress.md)
   is the task tracker (mirrors the parent PRD+progress split).
3. ~~Build order — confirm.~~ **RESOLVED** (2026-05-31): confirmed
   **W1 → W7 → W6 → (W2/W3/W4) → W5 → W8 → W9**. Note we are **speccing
   ahead of building** (user chose to keep planning): spec order has run
   W1 then W7; next spec target = **W6**. The first *build* unit remains
   **W1** (engine-first, since W2/W3/W4 are its dimensions).
