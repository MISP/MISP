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
| AD-W2 | Trending CVEs (dimension of W1) | rising | DISCUSSING | counting beyond event-tags; `MISP.cveurl` link-out |
| AD-W3 | Trending threat actors (dim of W1) | rising | DISCUSSING | attribute/object-level galaxy tags; cluster resolution |
| AD-W4 | Trending attack techniques (dim of W1) | rising | DISCUSSING | distinctness from the ATT&CK heatmap |
| AD-W5 | ATT&CK matrix heatmap (existing `AttackWidget`) | rising | DISCUSSING | wire to global `time_window`? else keep as-is |
| AD-W6 | **Event-stream rework** | new | DISCUSSING | cards vs ticker vs grouped digest; data layer kept |
| AD-W7 | **New-data stats** (StatGrid + deltas) | new | DISCUSSING | "new" definition; the four metrics; delta baseline |
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
- **Window anchor** — which timestamp puts an event "in the window"
  (`Event.timestamp` vs `Attribute.timestamp` vs `publish_timestamp`).
- **CVE counting specifics** (W2) + galaxy attribute-level specifics (W3).

### AD-W2 — Trending CVEs
First-pass (user): a **focused** widget; each CVE / GCVE / GitHub-advisory
identifier links out to the canonical vulnerability-lookup URL via
**`MISP.cveurl`** (default `https://cve.circl.lu`, identifier embedded, e.g.
`https://cve.circl.lu/vuln/CVE-2026-10186`) — it is a vulnerability-lookup
instance and users may run their own, not CIRCL's. **Circle back (user
flagged):** counting CVEs beyond event-tags is "trickier than it sounds" —
user has ideas + *existing APIs* for this use-case; **grill at W2 time.**

### AD-W6 — Event-stream rework
First-pass (user): keep the (good) canonical filters; rework the *visual* —
"a few more detailed **cards**", easy inline controls for filtering / scope /
exclusions, **visually easy to read and eye-catching**. Undecided between
**grouped digest** and **ticker**; explore both at W6 time.

### AD-W7 — New-data stats
First-pass (user) — the four starter metrics: **new events**, **attribute
count**, **events targeting your org's country/sector**, **new events
published by your org**. Render: `StatGrid`. **Deltas vs previous equivalent
window** (user: "GREAT"). **Open:** "new" = created (`timestamp`) vs
published vs first-seen; exact targeting match (country and/or sector).

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

## 7. Open meta-questions (resolve early)

1. `AD-NN` numbering vs continuing parent `DD-NN`? *(proposed: AD-NN.)*
2. Split an `analyst-dashboard-progress.md` now, or keep roster-as-tracker
   in §3 until implementation starts?
3. Build order — proposed: **W1 → W7 → W6 → (W2/W3/W4) → W5 → W8 → W9**
   (engine first since W2/W3/W4 are its dimensions; stats next as the
   cheapest standalone win; event-stream; then dimensions; heatmap wiring;
   the two hard/soft ones last). *(confirm.)*
