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
| AD-W5 | ATT&CK matrix heatmap (existing `AttackWidget`) | rising | DISCUSSING | wire to global `time_window`? else keep as-is |
| AD-W6 | **Event-stream rework** | new | DECIDED | spec locked (AD-08): additive subclass + new read-only `EventCards` render; flat cards; toolbar-driven filters |
| AD-W7 | **New-data stats** (StatGrid + deltas) | new | DECIDED | spec locked (AD-05..07): `timestamp` anchor · 4 metrics · targeting waterfall · global-count ACL relaxation |
| AD-W8 | Overlap-with-my-org (correlation) | affects-me | DISCUSSING | feasibility/cost; what "overlap" means |
| AD-W9 | Sightings rework (`RecentSightingsWidget`) | affects-me | DEFERRED | look-and-feel only? (sighting engine is slow / unused by some) |

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

### AD-W8 — Overlap-with-my-org
First-pass (user): "REALLY good but a bit tricky" — explore. Intent: intel
in the window that **correlates with the viewer's own org data**. The real
answer to "what's new that I should *care* about". **Open:** definition of
overlap (correlations? attribute-value intersection?), cost, ACL.

### AD-W9 — Sightings rework
First-pass (user): "definitely rework, but **maybe just a look-and-feel
rework**" — the sighting engine is slow and some communities don't use it,
so don't over-invest in a live "are my IOCs sighted?" engine. Discuss scope
at W9 time.

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
