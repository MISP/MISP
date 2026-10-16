# PRD: Pivot Explorer — leveraging Pivotick on `/events/view2`

**Status:** **COMPLETE** (2026-10-01) — the Pivotick integration is feature-complete. Decisions
settled against v1.6.0 (D1–D4, D5′, D6–D13; D5 withdrawn), then revised for v2 on 2026-09-23 (§5,
*Rulings after the v2 bump*). **Every §9 task is built** (2026-09-23). §8's still-owed checks were
closed by a live pass on 2026-10-01; §11's open questions are parked until analyst or community
feedback asks for them; what is left is polish, listed in §12. State lives in
[`pivot-explorer-v16-progress.md`](pivot-explorer-v16-progress.md).

**Owner:** Sami Mokaddem (Claude-assisted)
**Created:** 2026-08-28
**Grilled:** 2026-08-28 → 2026-08-31 — see §5 for what was settled and what changed as a result
**Working dir:** /home/sami/git/MISP
**Branch:** `pivotick-v2`, off `worktree-pivotick-v16` (which holds the v1.6.0 work)
**Library:** Pivotick v2.0.1+, built from `develop` at `f598444` (`app/webroot/js/pivotick.iife.js`,
`app/webroot/css/pivotick.css`). Written against v1.6.0; the file name keeps `v16` so links hold.

---

## 1. Summary

Pivotick v1.6.0 closes three of the four library gaps that were blocking the Pivot Explorer:
**edges now come in kinds that can be styled and switched off**, **nodes carry rim badges**, and
**the legend keys several dimensions at once**. A data dock, a real panel lifecycle, async
content renderers and a full set of before-write hooks landed alongside them.

The review that produced this revision changed the framing. The graph is **not a renderer for an
event** — it is an **exploration surface seeded by the event's authored relationships and grown
on demand**. Three consequences drive the whole design:

1. **One implementation, not two.** Editing and exploring are modes of one graph, not two
   graphs. Whether you may write is decided by *what you clicked*, not which page you are on
   (D8).
2. **The graph has resolution levels**, and the seed takes the highest that fits a 1,500-node
   budget: correlated-event proxies, then authored relationships (uncapped — bounded in practice
   at 2,362 edges), then relationship-less objects as containment-only clusters (D5′, D10, D12).
   A behemoth event is not a special case; it is an event that only affords the lower levels.
3. **Per-attribute correlations load on demand** (D9) — the most numerous relationship by far, and
   the aggregate that replaces them at low resolution (`RelatedEvent`) is already in the payload.
4. **Five edge kinds on two dimensions** (D1): how an edge came to exist (`kind` — reference,
   analyst assertion, correlation, feed, server) and what it asserts (`relationship_type`, ~143
   values). Feed and server correlations bring `feed`/`server` nodes onto the canvas.

The one library gap that did **not** close is lazy cluster expansion (`childrenProvider` /
`onBeforeNodeExpansion`), which is what expandable correlated events need. §4 scopes that out
and §11 keeps it on the list. It is still open in v2, but v2's **pivots** — fetch, stage, choose
what lands — reach most of what it was wanted for; §3.7.

## 2. Background & Motivation

### 2.1 Two activities, one graph

Two distinct things an analyst does with a graph:

- **Curation** — "this file dropped that payload, which contacted that C2." Authoring structure
  while building an event. Single-event, precise, infrequent.
- **Exploration** — "I have this hash; what else touches it?" Iterative, crosses event
  boundaries, unbounded, frequent.

The tempting conclusion is two graphs, one editable and one read-only. **Rejected** (D8), because
the most valuable output of an exploration session is a cross-event assertion — *this event is
attributed-to that actor* — and a two-graph split puts the write capability in the graph that
structurally cannot reach the nodes worth writing about: the single-event editor has no foreign
nodes, and the read-only explorer has no write.

Pivotick already models this correctly: v1.6.0 reserved `explore` and `enrich` as coming-soon
rail modes beside Select / Create / View — v2 retired those slots for `addRailMode`, which lets a
consumer register the mode itself, and ships a Pivot mode built through that same door — and
`editors.{nodeEditor,nodeCreator,deletion,edgeEditor}.enabled` (`:640-693`) removes write
affordances rather than vetoing them. The library's own roadmap says *modes*, not *graphs*.

### 2.2 Three kinds of write, not one

"Read-only" conflates three things with three different gates. This taxonomy is the backbone of
the gating model in §6.6:

| Kind | Examples | Persists? | Gate |
|---|---|---|---|
| **View write** | pivot in a node, hide, expand, re-layout, ephemeral enrichment, save a layout | no (except saved layouts) | `perm_auth` for `modules/queryEnrichment`; `perm_add` for `eventGraph add` |
| **Structural write** | object reference CRUD; enrichment persisted into the event; delete attribute/object | yes | `perm_add` **+ event edit rights** |
| **Assertional write** | note, opinion, analyst relationship | yes | `perm_add` + `perm_analyst_data`, **no ownership of the target** |

The third row is the important one: `ACLComponent.php:23` gates `analystData add` on role
permissions alone. Any user holding them may annotate **anything they can see**, including
another organisation's event. That is the entire design of analyst data, and any surface that
confines writing to "the event you own" throws that capability away.

Note also that ephemeral enrichment (`modules/queryEnrichment`, `perm_auth` —
`ACLComponent.php:581`) is available to a user who cannot edit the event at all, whereas
persisting enrichment into the event (`events/queryEnrichment`, `perm_add` — `:405`) is not.

## 3. Current State (evidence)

### 3.1 What the Pivot Explorer builds today

`event_pivot_explorer.ctp` is now 117 lines — markup, the editor CSS, and the `data-pe-*`
config attributes on `#pe-card`. All behaviour lives in `app/webroot/js/pivot-explorer.js`
(936 lines), loaded by the element's `assetLoader` call beside `pivotick.iife`. **Bare
`:NNN` references in this section and in §6 point into that module.** It fetches
`/events/view/{id}.json` and builds:

| Element | Source | Notes |
|---|---|---|
| Object nodes | `ev.Object` | Only objects `computeConnectivity()` finds connected |
| Attribute nodes | `obj.Attribute` | Nested as cluster **children** of their object (`:317-329`) |
| Event-level attribute nodes | `ev.Attribute` | Only when an object reference points at them (`:299-305`) |
| Edges | `obj.ObjectReference` | The **only** edge kind; label = `relationship_type` |
| Editor tray | `UI.extraPanels` | Unconnected attributes/objects as draggable chips |

Node style is keyed on kind via `nodeStyleMap` — event = green hexagon, object = blue square,
attribute = orange circle (`:386-391`) — with `iconClass` carrying the misp-iconify glyph,
`imagePath` carrying attachment thumbnails, and `styleCb` spending `strokeColor`/`strokeWidth`
on the pending-reference ring (`:414-419`). Every styling channel is committed.

### 3.2 What v1.6.0 adds that this graph can use

| Capability | API | Verified at |
|---|---|---|
| Edge kinds | `render.edgeTypeAccessor`, `render.edgeStyleMap` | `RendererOptions.ts:178,197` |
| Relationship layers | `UI.filter.edgeFacets`; `{ key: 'kind' }` is complete | CHANGELOG §*Edges come in kinds* |
| Layer toggle without moving the graph | link force gates on `Edge.visibleIgnoringLayer` | idem |
| Rim badges | `NodeStyle.badges`, `callbacks.onBadgeClick` | `RendererOptions.ts:438` |
| Multi-dimension legend | `UI.legend: { position, sections: [...] }`, `scope: 'edge'` | `GraphUI.ts:53` |
| Orphan control | `UI.filter.hideDisconnected` + View flyout switch | CHANGELOG §*Nodes with nothing left attached* |
| Data dock | `UI.table`, `UI.dock`, `UIManager.addDockTab()` | CHANGELOG §*The dock holds more than the table* |
| Before-write hooks | `onBeforeEdgeCreate`, `onBeforeDelete`, `isValidConnection`, … | CHANGELOG §*Every user write goes through a hook* |
| Write-affordance removal | `editors.{nodeEditor,nodeCreator,deletion,edgeEditor}.enabled` | `GraphUI.ts:640-693` |
| Reserved rail modes | `UI.modeRail: { explore, enrich }` (disabled "SOON") — **removed in v2**, see §3.7 | `GraphUI.ts:134-142` |
| Panel lifecycle | `ExtraPanel` re-invoked per selection; `id`/`order`/`reactive` | CHANGELOG §*Sidebar panels* |
| Async content | every content hook may return a `Promise`; `RenderContext{signal}` | CHANGELOG §*Content renderers* |

**Not available**, and relied on by nothing here: a declarative initial filter value.
`FilterOptions` is `{ facets, excludeKeys, edgeFacets, hideDisconnected }` and `FilterFacet` is
`{ key, label, type, options, matchMode, accessor, predicate, order }` — neither carries an
opening value, so "open with this layer switched off" is only reachable imperatively via
`queryEngine.setEdgeFilter()` *after* construction, which forfeits v1.6.0's "filters apply
before the first layout" guarantee. This is what killed the default-hidden design (D9) and is
logged as a library ask in §11.

### 3.3 Upgrade compatibility audit (v1.4.0 → v1.6.0) — already performed

MISP shipped a bundle dated 2026-07-23, i.e. **~v1.4.0** (v1.4.0 tagged 07-21, v1.5.0 07-29).
v1.5.0 carries two breaking sections. Audit result: **the existing integration is unaffected.**

- Uses none of the removed/renamed API: no `UI.selectionMenu`, `graphControls`, `graphToolbar`,
  `graphNaviation`.
- The extra panel's `render` returns an **HTMLElement** (`pivot-explorer.js:889`), so the
  1.5.0 "a `string` never
  renders as markup" change does not bite. Its `innerHTML` writes are all to its own DOM.
- `graph.on('edgeAdd', …)` (`pivot-explorer.js:894`) and `simulation.d3LinkDistance` still exist.
  (The `edgeAdd` write path did not survive v2 — §3.7.)
- v1.6.0's breaking changes are confined to physics presets. As the code stands, the graph
  **configures** `d3LinkDistance: 200` (`pivot-explorer.js:441-442`), so physics stays
  `'manual'` — auto declines
  to take over a graph that tuned any knob it drives, and layout is unchanged by the upgrade
  alone. **D7 then deliberately opts into `'auto'`.**
- Bundle verified: `node --check` passes, the `window.Pivotick` footer is present, and the
  deployed file is byte-identical (md5 `140ead0d…`) to a fresh `vite build` of the `v1.6.0` tag.

One **user-visible** change to communicate, not fix: 1.5.0 replaced full-mode chrome with the B3
mode rail and removed the `e` "Edit Graph" toggle in favour of **Create mode**. The comment that
still described "pivotick's Edit ▸ Add edge tool" has been refreshed accordingly
(`pivot-explorer.js:526-529`) — the second half of task 1.

### 3.4 MISP data already available

- **Analyst data is already on the wire.** `/events/view/{id}.json` takes the REST path, which
  sets `includeAnalystData = true` unconditionally (`EventsController.php:1787`). Attributes,
  objects and event reports carry flat `Note` / `Opinion` / `Relationship` arrays plus flattened
  child notes/opinions, and `RelationshipInbound` wherever something points at the element
  (task 41).
- **`RelatedEvent` is already on the wire** — `includeEventCorrelations` defaults true
  (`Event.php:2953-2954`), with `id, uuid, info, date, threat_level_id, analysis, published,
  distribution, org_id, orgc_id` + `Org`/`Orgc`.
- **`RelatedAttribute` is not**, for REST: `includeGranularCorrelations` is set only when
  `!_isRest()` or the named param is present (`EventsController.php:1858-1862`). Under D9 this
  is a **feature**, not a gap — see §6.7.
- ✅ **Inbound analyst relationships on attributes/objects** (task 41). The bulk path
  (`attachAnalystDataBulk`) did not add `RelationshipInbound`, and the event level's, computed
  by `afterFind`, was dropped by `JSONConverterTool::convert`. Both now arrive, each carrying its
  source element in `related_object`, read with the viewer's access.
- **Saved graph layouts already exist** — `EventGraphController` + `EventGraph` model, ACL
  `view: *`, `add: perm_add`, `delete: perm_modify` (`ACLComponent.php:1105-1110`). The legacy
  event graph used this via `quickSaveNetworkHistory`.

### 3.5 Measured shape of the data (dev instance, 4,167 events with attributes)

Everything below is a live measurement, and it is what the seed rule (D5′) is built on.

**Event size:**

| Attributes/event | Events |
|---|---|
| ≤50 | 1,377 |
| 51–500 | 1,984 |
| 501–5k | 714 |
| 5k–50k | 89 |
| >50k | 3 |

**Six largest events:**

| Event | Attributes | Objects | Live refs | Correlations |
|---|---|---|---|---|
| 4116 | 369,822 | 28,410 | **0** | 5,629 |
| 4134 | 58,146 | 4,617 | 0 | — |
| 4176 | 51,620 | 11,064 | 0 | — |
| 4114 | 31,495 | 0 | 0 | — |
| 2561 | 27,495 | 0 | 0 | — |
| 1195 | 20,970 | 4,724 | 2,362 | 350 |

**Relationship density:**

- Object references: **11,330** live, across 69,957 objects. Only **345 of 4,167 events (8%)
  have any object reference at all**; of those, 315 have ≤50 and the maximum in one event is
  2,362.
- Analyst relationships: 120 rows instance-wide (largely synthetic test data — a deployment
  using analyst data heavily would differ; the object-reference figures would not).
- Correlations: **336,221** rows. Event 4116 alone has 5,629.
- 80% of all attributes (2.2M of 2.8M) are **event-level**, not inside an object.

**Payload size — the unbudgeted cost.** `/events/view/{id}.json` returns the whole event, and the
Pivot Explorer fetches it today:

| Event | Attribute JSON (conservative) |
|---|---|
| 4116 | **~81 MB** |
| 1195 | ~5.5 MB |

That is attributes alone, before 28,410 objects, tags, analyst data or feed correlations — so
event 4116's view is on the order of a **100 MB download**. The seed budget (D12) caps the canvas
at 1,500 nodes while still transferring 370,000 attributes to get there, and no client-side
paging can fix a payload that has already arrived. See **D13**.

**Two conclusions drawn from this:**

1. **The authored relationship set is small and safe to always show.** 2,362 edges worst case.
2. **For ~92% of events, correlations are the only relationship there is.** Today's
   reference-only rule therefore renders an **empty canvas** for most large events —
   `computeConnectivity()` finds nothing connected, so `buildGraphData` emits nothing. Four of
   the six largest events render blank today. That is not an edge case; it is the norm.

### 3.6 Gap statement

The graph draws one relation kind out of at least four, gives no indication that an element
carries analyst data, names one of its encodings, cannot say which event a node belongs to, and
renders nothing at all for the majority of large events — while the data for most of it is
already in the response it fetches, and the library now has the channels to show it.

### 3.7 Upgrade to Pivotick v2 (v1.6.0 → `develop` `d220446`) — performed 2026-09-23

Built from a clean export of pivotick `develop` at `d220446` (v2.0.1 plus 29 unreleased commits:
zoom-dependent node drawings, a legibility gate on labels). The IIFE still carries everything,
the simulation worker included — it starts from a `blob:` URL, which MISP's CSP already allows
(`worker-src blob:`, `AppController.php:891`). `node --check` passes; md5 `1183ba8c…`.

**What the upgrade broke, and what was done about it:**

- **Drawing an edge.** v2 records every hand-drawn edge in `graph.history` the moment it lands.
  The v1.6 flow let the edge land, then saved or removed it from an `edgeAdd` listener — so a
  refused, cancelled or failed save left an undo row for an edge that no longer existed, and a
  saved one undid as though it had never been written. **Fixed:** the save moved into
  `onBeforeEdgeCreate`, which resolves only after the POST, accepting with `persisted: true` or
  refusing; `isValidConnection` marks a non-object source invalid during the gesture. This pulls
  the *mechanism* of task 10 forward; its `possibleKinds()`, `promptData()` picker and
  `editors.*.enabled` gating are still task 10.
- **Labels on open.** `render.minLabelFontSize` (default 9 CSS px) hides a label too small to
  read. The graph opens fitted, and on the harness fixture the fit is zoom 0.62, so a 12 px label
  renders at 7.4 px: **nothing on the canvas is named until the analyst zooms in.** Library
  behaviour working as designed; left at the default pending a decision (below).
- Nothing else. Every option and call `pivot-explorer.js` makes still exists with the same
  shape; `UI.modeRail` and `onNodeExpansion`, the two removed APIs, were never used.

**Verified in a headless browser**, against the real bundle and `pivot-explorer.js` with a stubbed
`fetch` (not the dev server — it was serving another tree): the graph renders with no console
error; L0/L1/L2 seed as the unit suite says; both edge kinds draw in their D1 colours; a tray
chip drops in pinned and pending; and the four edge gestures behave — non-object source (no
picker, no edge, no history), cancelled picker (nothing), refused save (POST sent, no edge, no
history), accepted save (edge tagged `object-reference`, one `create` history row,
`persisted: true`). This discharges the rendering half of task 1b; it does not replace §8.1 on
the real instance with real events.

**What v2 adds that this plan should decide about** — each touched a settled decision. Answered
2026-09-23; the rulings are in §5 (*Rulings after the v2 bump*):

| v2 feature | Touches | The question |
|---|---|---|
| **Pivots** (`graph.pivots`): `summarize` advertises a count, a cap *refuses* rather than truncates, results are staged in a Review tab until committed | D9, task 5, §4 non-goals | Should the on-demand correlation fetch be a pivot on the event node rather than a bespoke layer? The refusal-with-a-count gate is D9's cap, already built. |
| Pivots on a correlated-event proxy, with container rows that ingest whole | §4 *Lazy expansion* non-goal, D12 L0 | Does "expand a related event" stop being out of scope? |
| `ctx.addPivot` / enrichment as a pivot, with `save` writing results back | §4 *Enrichment* non-goal, §2.2 view vs structural write | `modules/queryEnrichment` is a pivot's `fetch`; persisting it is its `save`. Still out of scope? |
| `graph.history` + `persisted` on `onBeforeDelete` (a persisted deletion is *sealed*, never undone) | D6, task 10c | D6 deletes edges behind a confirm; under v2 that deletion is permanently un-undoable in the history menu, which is the honest outcome — confirm the confirm is still wanted on top. |
| `pivotMarkUnsaved` / `pvt-node-unsaved` | D2's removal of the pending ring | The tray still paints its own pending ring (`styleCb`). v2 has a library marker for exactly this state, but only for pivot-created nodes. |
| `addRailMode`, `UI.*.enabled` switches (`UI.history`, `UI.editors.edgeCreator`, …) | D8, task 10 | A read-only user can still draw local edges today (the editor hooks attach only when `canEdit`). v2's `editors.edgeCreator.enabled: false` removes the tool outright. |
| `NodeStyle.tiers` / `focusTier` (dot → chip → card by rendered size) | D10/D12 budget, L2 | Could L2 objects draw as dots past a threshold rather than being skipped above 1,500 nodes? |
| `render.minLabelFontSize` | the open-unlabelled finding above | Keep the 9 px default, lower it, or open at a zoom where labels read? |

**Answers:** correlations → a pivot (R1); related events → a pivot, with the rim badge carrying
its candidates (R2); enrichment → deferred to its own pass (R3); a persisted deletion → allowed,
and it says it cannot be undone before it happens (R4); read-only users → no write affordance of
any kind (R5, done); labels → Pivotick's default (R6). The unsaved-marker and tiers rows fold
into P0 and are decided where their tasks land.

## 4. Goals / Non-Goals

### Goals

1. Draw object references, analyst relationships and feed correlations as **distinct, switchable
   edge layers** (all three already in the payload), fetch per-attribute correlations **on
   demand**, and add `relationship_type` as a second, orthogonal edge filter (D1).
2. Indicate analyst data (note count, endorsed/disputed) with **rim badges**, detail in a
   selection-reactive sidebar panel.
3. Name every encoding in a **sectioned legend** that doubles as the layer control.
4. Show **event provenance** — which nodes belong to the event being viewed and which do not.
5. Replace the bespoke editor tray with a **dock pane** listing the whole event, since the graph
   now seeds small and the dock is the route to everything else.
6. Move edge creation onto **`onBeforeEdgeCreate` + `isValidConnection`**, and gate write
   affordances with **`editors.*.enabled`** per the taxonomy in §2.2.
7. Never render a silently empty canvas: an event with no authored relationships says so and
   offers the correlation fetch.

### Non-Goals

- **A second entry point (pivot route).** The component is to be *parameterised* for it (seed +
  default mode) but the route is not built here. See §11.
- ~~**Lazy expansion of correlated events.**~~ **Back in scope as a pivot (R2).** In-place
  expansion still needs `childrenProvider`, which v2 did not ship either; a related event is
  instead *pivoted on*, and what it brings back is staged and chosen like any other pivot.
- **Writing notes and opinions from the graph.** Read-only — they are displayed (badge + panel)
  but not authored here. Analyst **relationships** *are* written (D2b): they are the assertion an
  exploration produces, and D8 turns on being able to record one. Notes and opinions are a form
  problem rather than a graph problem, and the existing `analystData/add` UI already solves it.
- **Enrichment from the graph** (either variety) — **deferred, not dropped (R3).** It is the pass
  after everything else here runs, and it will be pivots too: `modules/queryEnrichment` as a
  pivot's `fetch`, persisting as its `save`. The taxonomy in §2.2 is what gates the two.
- **Backend aggregation of objects.** A behemoth's L2 is *skipped*, not summarised. The
  correlation aggregate already exists (`RelatedEvent`), and feed correlations already degrade to a
  count past 10,000 hits (D1); the object one does not exist, and building it is new endpoint work.
  See §11.
- **Analyst-data threads.** Flat list in the sidebar panel; no nested renderer.
- Relationship targets outside the graph's node universe (Galaxy, Organisation, SharingGroup).
- Retiring the legacy `/events/view_graph`, or touching `EventGraphTool` / `getEventGraph*`.

## 5. Design Decisions

### Rulings after the v2 bump (2026-09-23)

These revise the decisions below where they conflict; each names what it overrides.

#### P0 — Nothing custom where Pivotick already does it ✅ RULED

The governing rule for everything that follows. If the library has the feature — a gate, a
picker, a staging area, a badge, a confirmation, a marker — MISP configures it rather than
building its own. MISP's code is data (turning the event into nodes and edges), persistence
(the writes to MISP) and configuration. Where the library falls short, the fix is a request in
`~/git/pivotick/prd/`, not glue here.

It reaches further than R1–R6. Custom pieces now standing, each to be replaced when its task
lands: the relationship picker (→ `ctx.promptData`, task 10), the tray and its drag-and-drop
(→ the dock, task 9 — see §11 for whether that is an origin-less pivot), the pending ring
(→ removed, D2), the correlation layer and its cap (→ R1).

#### R1 — Correlations are a pivot ✅ RULED (revises D9, §6.7, task 5)

D9's intent stands: nothing about correlations is in the opening payload. What changes is the
*mechanism*. Instead of a bespoke control, a bespoke layer and a client-side cap, correlations
are a pivot registered through `pivots`: `appliesTo` the event's attributes and objects,
`fetch` returning the correlated elements and their `correlation` edges, `maxCandidates` as
D9's cap. The library then owns what D9 had to design: the count before the fetch, narrowing,
a refusal that names the number instead of truncating, the Review tab where results wait until
chosen, provenance, and undo of an ingest. **No `save`** — correlations are derived, so the
results are never counted unsaved.

**The count source — built, as the first slice of D13.** `summarize` needs a cheap count, and
`/events/view/{id}.json` has none: `RelatedAttribute` is absent from REST by default (§3.4) and
`RelatedEvent` carries no per-event counts. `GET /events/correlationCounts/{id}.json` (`7f0b6d041`) answers it:
`{ total, attributes: {uuid: n}, objects: {uuid: n}, events: {id: n}, limit }`, from the same
ACL'd correlations as the event view's `RelatedAttribute`, with the event's own side limited to
attributes the user can see. Fetched once per graph; `summarize` reads it for the origin it is
handed. Measured in `graph-endpoint-prd` §7. **`fetch`** posts to
`/events/correlatedAttributes/{id}.json` (`attribute_uuids`), which returns exactly the pairs the
count counted, as `{ pairs, events }`: `events` holds, once per correlated event, what its card
draws — the index row (org, date, publish time, distribution, attribute and object counts), its
tags and its galaxy clusters — fetched the way the events index does, never the event's content.
Results come back as one container per correlated event, keyed `event:<uuid>` like
any event node so ingest merges them into one already drawn, plus a `correlation` edge per pair. `maxCandidates` is
1,500 — the D12 canvas budget, for the same legibility reason.

**The count is on the rim too (task 15).** Each of this event's attributes and objects declares
its count as the pivot's potential, `node.setPotential('correlations', n)` — a declared,
never-queried badge, opening Pivot mode on that element. It is declared
once the counts arrive, and again on every node as it lands (an element-pivot ingest, the event's
own side a correlation run brings along), before the render that follows. An object's badge is its
own count, which already covers its attributes; the attributes wear theirs once it is expanded.
The badge says what the pivot *would* bring, and stays after a run has brought it.

**Taking them back off (task 12).** Undo takes back the newest run; everything the correlation
pivot brought, over any number of runs, comes off through the canvas menu's *Remove fetched
correlations* — `graph.removeBySource('correlations')`, which
deletes only what nothing else vouches for, so the seed and whatever the element pivot put there
stay. The entry shows only while something fetched is on the canvas. The removal is a history
entry since Pivotick `f598444` (§11.13, task 0d), so Undo puts it back, and the notice says so.

It changes a number this PRD leaned on: **event 4116 has 708 correlations to offer, not
5,629.** 5,629 is the raw table; the event view's correlation list — and so anything a pivot can
fetch — leaves out correlation-exclusion and over-correlating values. Still well past a sane
`maxCandidates`, so the gate is still load-bearing.

#### R2 — Related events are a pivot, and the badge shows what they would bring ✗ WITHDRAWN by R7

*Kept for the record: with no correlated-event nodes on the canvas there is nothing to pivot on.*

A correlated-event proxy (L0) is a pivot origin. Pivoting on it fetches the elements of that
event which correlate with this one, staged for triage like R1's. The node carries the count as
**declared potential** — `node.setPotential('related-event', n)` draws a rim badge, and clicking
it opens Pivot mode on that pivot. Declared, never queried: the library will not call a provider
to draw a badge. `n` is the `events` entry of R1's count response. A related event reached only
through excluded or over-correlating values counts 0 and wears no badge — 11 of event 4116's 89
— which is honest: the pivot would bring nothing back from it.

#### R3 — Enrichment is its own later pass ✅ RULED

Out of this PRD's delivery. When it comes it is a pivot (`fetch` = `modules/queryEnrichment`,
`save` = persisting into the event), gated by §2.2's view/structural split.

#### R4 — A persisted deletion says it cannot be undone ✅ RULED (amends D6)

v2 seals a deletion written through to MISP: its history row is chipped **locked** and undo
passes over it, because restoring it would put back something MISP no longer has. That is
right, so it stays — and the analyst is told *before* the click, in D6's `ctx.confirm()`:
`variant: 'danger'`, a confirm label that names the action, and a body saying it deletes the
relationship in MISP and cannot be undone from the graph. `onBeforeDelete` returns
`persisted: true` on what it wrote, which is what makes the history lock it.

#### R5 — Read-only users get no write affordance ✅ RULED, DONE (`5a5770d9c`)

A user who cannot edit the event is offered nothing that would reach MISP:
`editors.{nodeEditor, nodeCreator, edgeCreator, edgeEditor, deletion}.enabled: false`, and no
editor hooks or tray. Notes, hiding and layout stay, being canvas-only. When analyst
relationships become writable (task 10b), a user with `perm_analyst_data` gets `edgeCreator`
back for that kind alone (D8). **Done in 10b:** `perm_add` and `perm_analyst_data` — the
`analystData/add` ACL — give back `edgeCreator` and `deletion`, and the hooks.

#### R6 — Labels follow Pivotick's legibility default ✅ RULED

`render.minLabelFontSize` stays at the library's 9 px. The graph may open with labels hidden and
names appear as the analyst zooms in.

#### R7 — Correlated events leave the canvas; an event node is a relationship endpoint ✅ RULED, DONE (2026-09-24) (withdraws R2 and D12's L0, revises D1, D11, §6.4, task 3b)

The canvas no longer opens on this event with a spoke to every event it correlates with. That
star (86 spokes on 4116) repeated what the event's Correlation tab already lists, in a worse form:
the layout carries no meaning, an event-to-event edge does not say *which* value is shared, and
the hub took the layout over from the authored structure only this graph can show. Correlations
are now attribute to attribute only, fetched on demand through R1's pivot; the other event
appears solely as the container holding the attribute it shares.

- **No L0.** `RelatedEvent` is no longer read. The seed is L1 + L2 (D12); the statement reads
  `Seeded L1+L2 · …`.
- **An event node is drawn only as an analyst relationship's endpoint**, and counts toward L1:
  this event, when one of its attributes or objects points at it or when it has an outbound
  relationship of its own (`Event.Relationship`, now walked); another event, drawn as a leaf from
  the record the payload attaches to the relationship (`related_object.Event`,
  `Relationship::getRelatedElement` → `fetchSimpleEvent`). That record carries no `Orgc`, so the
  card shows the date alone. A target the viewer cannot see comes back with an empty
  `related_object` and is counted as *not drawable*, like any other undrawable target.
- **Gone:** the `event-correlation` edge kind (style, legend name, filter), the related-event
  pivot and its rim badge (R2). The server side is unchanged: `correlationCounts` still returns
  `events`, which the statement now uses — `708 correlations with 78 events available` on 4116 —
  and `correlatedAttributes` keeps its `event_ids` filter.
- **D11 fires more often, by design.** A large event with correlations but no references or
  relationships (4116) now opens empty, saying so, pointing at Event elements, and adding that
  correlations are fetched from the elements put on the canvas.

Checked live on the dev instance: 3989 (an attribute `similar-to` event 4182) draws 4182 alone,
with one analyst edge and no spokes; 4182 (an attribute `related-to` itself) draws its own node;
1545's event→event relationship targets an event this instance does not hold and is counted not
drawable; 4116 opens on the empty state.

#### R8 — No node expands ✅ RULED, DONE (2026-09-24), on trial

`render.enableNodeExpansion: false`. Pivotick has no per-node form of the switch, so it applies to
every node: an object stays a closed box over its attributes, and so does the container a
correlation run fills. It removes the chevron and the Enter shortcut, and an expanded node draws
no cluster; the library's *Expand Node* menu entry is hidden regardless. Nodes keep their
children, so the data, the element pivot and the correlation fetch are unchanged — but a
correlation edge into an attribute ends on the closed box holding it. Taken as a trial, to revert
if that cost shows; locking only some nodes would need a per-node predicate upstream.

### All settled in review (2026-08-28 → 2026-08-31)

#### D8 — One implementation; writes gated by what you clicked ✅ SETTLED

One graph component, not two. Whether a write is offered is decided by the element under the
cursor and the user's permissions, **not** by which page is open:

- **Object references** are offered only where there is a single-event context to attach them to,
  and only on nodes belonging to that event (`scope === 'self'`).
- **Notes, opinions and analyst relationships** are offered on any element, anywhere, because
  `ACLComponent.php:23` gates them on role permissions alone.

Rejected: two graphs (one editable/event-scoped, one read-only/exploratory). The cross-event
assertion — the most valuable product of exploration — is available in neither half of that
split. Exploring and editing become **modes** — in v2, rail modes registered with `addRailMode`
beside the library's own Pivot mode.

#### D5′ — Authored relationships are always seeded, uncapped ✅ SETTLED (supersedes D5)

The elements participating in an **object reference** or an **analyst relationship** are always
seeded, with no node budget. Justified by §3.5: 2,362 edges worst case, 315 of 345
reference-having events under 50.

This is **L1** of D12's resolution levels — L0 (correlated-event proxies) sits below it and is
also always present; L2 (relationship-less objects) sits above it and *is* budgeted, per D10.
"Uncapped" applies to L1 alone.

**D5 as originally written is withdrawn.** It proposed building every attribute and object into
the graph and hiding orphans with `hideDisconnected`. On event 4116 that is ~398,000 nodes
constructed before anything is hidden. `hideDisconnected` survives as a **user-facing switch**
(it is on the View flyout of every graph regardless), not as a load strategy.

#### D9 — Correlations load on demand, not hidden-by-default ✅ SETTLED (mechanism revised by R1)

Correlations are **absent from the opening payload**. A control fetches them; the cap applies at
fetch time.

Rejected: shipping correlations and switching the layer off by default. Three reasons, all
concrete:

1. **A layer-hidden edge still shapes the layout** — the link force deliberately gates on
   `Edge.visibleIgnoringLayer` so that toggling doesn't reshuffle. Event 4116 would open laid out
   by 5,629 invisible edges.
2. **Orphan flood** — a foreign node whose only edge is a hidden correlation has no visible
   edge; thousands of disconnected dots unless `hideDisconnected` is forced on.
3. **No declarative way to do it** (§3.2): it takes a post-construction
   `queryEngine.setEdgeFilter()`, so the correlations reach the first layout and are then
   hidden — losing the "filters apply before the first layout" guarantee.

On-demand loading delivers what default-hidden was for (uncluttered opening, correlations one
click away) while making the first paint *cheaper*, and it turns the 92% empty case into a
designed first step rather than a defect.

#### D12 — Resolution levels: the seed takes the highest level that fits the budget ✅ SETTLED (L0 withdrawn by R7)

> **R7 (2026-09-24):** L0 is gone — correlated events are not drawn, and an event node is an
> analyst relationship's endpoint, charged to L1. The seed is L1 + L2. The L0 row and the
> paragraphs built on it below are kept as the reasoning that was revised.

The graph has four resolution levels. The seed takes the highest that fits a **single node budget
of 1,500** (pivotick's own detail threshold — past it the minimap stops resolving per-node style
and reads as a density map), and the same budget caps D9's correlation fetch.

| Level | Content | Source | Worst case observed | Cost |
|---|---|---|---|---|
| **L0** | event + correlated-event proxy nodes | `RelatedEvent` | **86 nodes** (event 4116) | free, already in payload |
| **L1** | authored relationships — object references + analyst relationships | inline | 2,362 edges (event 1195) | free, already in payload |
| **L2** | objects and event-level attributes with no relationship that a feed or server hits (since 2026-09-30; before, every relationship-less object) | inline | budget-capped (D10) | free, already in payload |
| **L3** | per-attribute correlations | `RelatedAttribute` | fetch-capped (D9) | one extra request |

**Why this matters:** a behemoth event is no longer a special case needing an apology. Event 4116
(369,822 attributes, 0 references, 5,629 correlations) affords L0 + L1 — 86 nodes saying *this
event touches 86 others* — and is told that L2 does not fit. That is a useful graph, not a
message.

**The correlation aggregate already exists.** Event 4116's 5,629 correlations collapse to 86
distinct related events, and `RelatedEvent` — that exact aggregate — is already loaded by default
(`Event.php:2953-2954`). So backend aggregation for the dimension that actually explodes
(336,221 correlation rows vs 11,330 references) costs nothing and is available today.

**L0 needs an edge to exist** (settled 2026-08-31, task 3b). The event node is drawn only when
something connects to it — a correlated-event proxy, or an analyst relationship pointing at the
event. Otherwise D11 could never fire: a bare hexagon on every event would make L0 permanently
non-empty, and "L0, L1 and L2 are all empty" unreachable. It would also be a floating dot, which is
the failure D5 was withdrawn for. Identity is the header's job (D2c), not a node's.

**What is *not* aggregated:** objects. There is no existing "28,410 objects → 12,000 file, 8,000
url" roll-up, and building one is real endpoint work. D10's ceiling means Phase 1 does not need
it — objects above the budget simply are not drawn and the dock lists them. Logged in §11.

#### D10 — Objects with no relationship: seeded below a budget ✅ SETTLED

**(c)** — objects with no relationship are seeded as containment-only clusters up to the 1,500-node
budget (L2 in D12); above it the seed stops at L0+L1. Justified by the distribution across the
350 events that have objects but no references:

| Nodes if seeded (objects + attribute children) | Events | Total nodes |
|---|---|---|
| ≤100 | 306 | 6,786 |
| 101–1k | 36 | 8,880 |
| 1k–5k | 5 | 11,772 |
| **>5k** | **3** | **523,677** |

342 of 350 events cost under 1,000 nodes; three events account for half a million. A single
threshold separates them with almost nothing in between.

**All-or-nothing, not greedy** (settled 2026-08-31, task 3c). L2 is admitted whole or not at all —
"above it the seed stops at L0+L1" is a statement about the *level*, not about individual objects.
A greedy fill to the budget would draw an arbitrary 40 of event 4116's 28,410 objects, and no
honest statement could explain which 40 or why; the analyst would read a fragment as a sample. The
cost is computed before anything is built: each object costs 1 + its live children, so 750
two-attribute objects cost 2,250, not 750.

**Event-level attributes are never seeded without a relationship**, and the asymmetry is
principled rather than convenient: an object is a cluster with a template type and named
children, so "12 file objects and 3 url objects" conveys the event's composition at a glance. A
bare event-level attribute has no structure — drawn with no relationship it is an isolated dot
conveying strictly less than the dock's table row, which has the width to show the value the
canvas shortens to fit its node. The asymmetry is also load-bearing: 80% of all attributes are
event-level, so seeding those means seeding the whole event again.

> **Governing principle:** the graph draws things with **structure or relationships**; the table
> draws things that are **just values**.

**Amended 2026-09-30:** a feed or server hit counts as a relationship: the edge to its source is
drawn. L2 therefore takes an event-level attribute a feed or server hits, at one node each,
alongside the objects a hit reaches, and leaves out an object nothing links. Whatever carries no
link, object or attribute, is left to the element pivot.

#### D11 — The empty-graph case is explicit ✅ SETTLED (consequence of D5′ + D9 + D12)

An event with genuinely nothing to draw at any resolution level opens with a statement and an
action, not a blank canvas: *"No relationships in this event — 5,629 correlations available"* plus
a button. This replaces today's silent blank, which four of the six largest events produce.

Note that D12 **demotes this message considerably**: it now fires only when L0, L1 and L2 are all
empty, rather than whenever the event is large. A behemoth gets L0's aggregated view instead.

> **Built (task 4, 2026-09-23), with a different action.** The correlation count in the example
> cannot appear: correlations imply related events, and related events put L0 on the canvas. The
> message names what is missing and points at the *Event elements* pivot (task 9) instead. It is
> Pivotick's `UI.emptyState` card (added upstream on MISP's request), with MISP's words.
>
> **R7 (2026-09-24):** with L0 gone, correlations no longer keep a large event off this card —
> 4116 now opens on it. The title reads *Nothing in this event is linked yet*, and the body adds
> that correlations are fetched from the elements on the canvas.

#### D1 — Two edge dimensions, six kinds, plus feed/server nodes ✅ SETTLED

Edges carry **two orthogonal dimensions**, because "show me only analyst relationships" and "show
me only `communicates-with`" are different questions:

| Dimension | Meaning | Values | Control |
|---|---|---|---|
| `kind` | how the edge came to exist | 6 | `multiselect` edge facet + legend section (the layer switch) |
| `relationship_type` | what it asserts | ~143 | `text`/`regex` edge facet |

`relationship_type` is deliberately **not** a `multiselect`: object references alone use 143
distinct values (`analysed-with` 6,968, then a long tail through `opened`, `includes`,
`communicates-with`, `child-of`, `calls`). A 143-row dropdown is unusable, and the library already
concedes the pattern — its table row filters switch from a dropdown to a text box past 50 distinct
values. A pattern box ("everything `-of$`") is the usable form.

**Built (task 5c), now Pivotick's own `regex` facet (task 14).** Types are free text — the dev
instance carries `Characterized_By` beside `dropped-by` — so `by` must find both, and a `regex`
facet compiles case-insensitively; `matchMode: 'partial'` is a case-sensitive `includes`. 5c
first shipped a hand-written case-blind `predicate`; task 14 dropped it for the library's box,
which also validates the pattern before applying it. A plain word still reads as a substring;
the cost is that `.` and brackets are pattern syntax. The value lives in `data.relationship_type` on every object-reference and analyst-relationship edge,
seeded or drawn, next to the `label` that displays it. Derived kinds (`event-correlation`,
`correlation`, later `feed-correlation`) assert nothing and carry no such field, so any typed
filter hides them — asking "what asserts `-by`" is asking about authored edges.

**The six `kind` values:**

| `kind` | Source | In payload? |
|---|---|---|
| `object-reference` | `obj.ObjectReference` | yes |
| `analyst-relationship` | `.Relationship[]` + `.RelationshipInbound[]` | yes |
| ~~`event-correlation`~~ | ~~`RelatedEvent`~~ — **removed by R7**: correlations are attribute to attribute only | — |
| `correlation` | `RelatedAttribute` | **no** — on demand (D9) |
| `feed-correlation` | `attribute.Feed[]` | **yes, free** (`includeFeedCorrelations = 1` unconditionally, `EventsController.php:1857`) |
| `server-correlation` | `attribute.Server[]` | yes — the fetch asks for `includeServerCorrelations:1` (REST defaults it to 0); the model still withholds it from whoever may not see it (task 41) |

**`event-correlation` is not folded into `correlation`** (settled 2026-08-31, task 3b; the kind
itself is gone since R7), and the split is load-bearing.
Both are correlation-derived, but they are different granularities of the same fact: event 4116
has **86** `event-correlation` edges and **5,629** `correlation` edges saying the same thing at
attribute resolution. One `kind` for both would break two things at once — the layer switch could
no longer keep the cheap aggregate while hiding the expensive detail, which is the entire point of
D12's resolution levels; and the `correlation` layer would appear populated the moment the graph
opens, contradicting D9's promise that correlations are absent until fetched. Palette: `#6fbe80`
dashed, the green of the event nodes it joins.

**Inbound analyst relationships share the `analyst-relationship` kind.** The graph is
`isDirected: true`, so the arrowhead already carries which way the assertion points; a separate
layer would double the vocabulary to say what the arrow says. The "another org asserted this about
my data" signal is carried in the sidebar panel instead.

**A relationship's far end in another event is drawn** (task 41), in either direction. The far end
is the target of an outbound relationship and the source of an inbound one, and MISP attaches it
in `related_object`, read with the viewer's access. Another event is its card, as before. Another
event's attribute or object lands free and closed beside its event's card, joined by `in-event`:
the payload names the element, not the rest of its object. It is charged to L1 with its card. A
far end the viewer cannot read, or a tombstone, is not drawable, and nothing says it was there.
A relationship inside this event arrives from both ends and draws once.

**Two new node types: `feed` and `server`.** Reversing an earlier recommendation to exclude them —
the exclusion rested on a misreading. The `$isSiteAdmin` guard at `Event.php:3374` is on the
**ShadowAttribute** branch; the Attribute path (`:3398`) has no such check. The real gate is a
dedicated role permission, **`perm_view_feed_correlations`** (`Feed.php:521-522`), so ordinary
users do see these correlations and they belong on the canvas.

They are also cheap. `attachFeedCorrelations` attaches per-attribute hits to
`attribute['Feed'][]` / `attribute['Server'][]` **and** a deduplicated source map to
`event['Feed'][id]` / `event['Server'][id]` — so it is one node per feed or server, not one per
correlation, exactly as `RelatedEvent` is for events.

Three constraints the implementation must honour (§7 carries the edge cases):

- **A built-in degraded mode already exists.** Past 10,000 hits without `overrideLimit`, the
  sources are dropped and you get `attribute['FeedHit'] = true` plus `event['FeedCount']`
  (`Feed.php:604-611`). This is precisely the backend aggregation pattern requested for objects —
  already implemented here. The graph must render both shapes.
- **Server fields are restricted.** A non-site-admin outside the host org sees only `id` and
  `name` on a `Server` source (`Feed.php:613-620`), and server event-UUID hits are withheld
  entirely (`:648-652`).
- Containment stays **nesting**, not an edge. `tag`/`galaxy` edges remain out of scope.

#### D2 — Channel allocation; the "pending" state is removed ✅ SETTLED

A node can only look so many ways, and v1.6.0 took one of the channels MISP was using. Selection
now draws on the node's **rim** ("keeps its own `color` and takes the selection colour on its
rim"), where highlight already lived — so the rim has four claimants, two of them library-owned
and overriding: selection, highlight, MISP's pending-reference ring, and MISP's image-node frame.

**Final allocation:**

| What it says | Channel |
|---|---|
| what kind of thing it is (attribute / object / event) | the node's drawing — `misp-pivot-nodes.js` |
| what kind of thing it is (feed / server) | fill `color`, `shape`, `size` |
| which attribute or object type | the drawing's glyph (misp-iconify, from the webfont) |
| how much it says | `tiers` — S at rest, M chip from zoom 1 — and `focusTier` (below) |
| attachment preview | `imagePath` |
| **an analyst has commented here** | **one folded badge** — count as `text`, colour as sentiment |
| from another event | **undecided — see D2c** |
| selected / hovered | **rim — left entirely to the library** |

✅ **Node drawings (2026-09-24).** Attribute, object and event nodes draw the chosen set from
`prd/pivot-node-designs/` (`summary.md`, *The chosen set*), vendored as the generated
`app/webroot/js/misp-pivot-nodes.js` with its icon font `webroot/webfonts/misp-iconify.woff2`.
`mispNodeStyles()` composes the module's three sizes into one style per element: the S
drawing is the base, the 140×44 M chip is the only zoom tier, and the richest drawing — XL
for events and objects, M otherwise — is the `focusTier`. XL is kept out of `tiers` so every
element shares one footprint (`layoutSize` 70, half the chip) and one threshold: the whole
canvas swaps to chips at zoom 1. The explorer's own badges replace the module's on every
drawing, and the Element legend rows declare the entity hues, since a drawn node leaves
`color` transparent. The event card reads `orgc`, `publish_timestamp`, the counts,
`distribution`, and the galaxy/tag context that `eventNodeData()` now carries; a
`RelatedEvent` proxy or a correlation hit has none of the context, and the card omits the row.
An object leads with its template's highest `ui-priority` relation:
`ObjectTemplate::uiPrioritiesForEvent()` resolves it for the templates the viewer's visible
objects use (exact version, else the newest installed), the element hands it over as
`data-pe-ui-priorities`, and `objectChildData()` puts `ui_priority` on each child. A zero
priority is left out, so ordering falls back to `to_ids`, then template order.

**Provenance is binary** wherever it is drawn. There are four ways to be foreign — extended
event, correlated event, feed, server — but feed, server and event-proxy nodes already announce
themselves through node *type* (own shape and fill). The only ambiguous node is an attribute or
object that looks identical to this event's but is not, so the cue need only say mine / not-mine.

The *channel* for it is **not** settled — an earlier revision of this document recorded
saturation as decided, which over-read the review. It is now D2c.

**Notes and opinions fold into one badge.** They are the same message to an analyst — *somebody
has commented on this* — and one badge carries both: the note count as its text, endorsed /
disputed / neutral as its colour. This matters because only **two** badge corners are free on an
expandable node (both East corners are reserved for the expand affordance) and object nodes are
expandable.

**The "pending / not yet saved" state is removed entirely**, and its `styleCb` ring
(`:414-419`) is deleted. Rationale: putting an attribute on the canvas is a **view write** in
§2.2's taxonomy — the attribute was always in the event, and showing it changes nothing in MISP.
Only the edge is a save. The old pending ring existed because the previous design treated a
dragged-in node as half-created; it never was.

Two things fall out for free:

- **A bug in today's code disappears.** The pending ring is invisible whenever the node is
  selected — and a freshly dropped node is selected on drop, which is exactly when "unsaved"
  matters. Deleting the concept removes the collision rather than working around it.
- **The badge budget drops to one**, comfortable even on expandable nodes.

#### D2b — Which link kind a drawn edge becomes ✅ SETTLED

Drawing an edge can mean two different writes, and the constraints do **not** always pick one.

- An object reference's **source is always an object**: `ObjectReferencesController::add()`
  resolves it strictly in the `Object` table (`Object.uuid`/`Object.id`, `deleted = 0`) and throws
  `Invalid object.` otherwise. Its *target* may be an attribute (`referenced_type 0`) or an object
  (`1`). It is intra-event by construction.
- An analyst relationship's endpoints may be any of `AnalystData::valid_targets` — Attribute,
  Event, EventReport, GalaxyCluster, Galaxy, Object, Note, Opinion, Relationship, Organisation,
  SharingGroup — and **not** Feed or Server.

| Source → Target | Possible link |
|---|---|
| object → object/attribute, **same event** | **either kind — ambiguous** |
| attribute → anything | analyst relationship only (an attribute cannot be a reference source) |
| anything → node in another event | analyst relationship only |
| anything → feed / server | **nothing** — not a valid analyst target either |

Only the first row is undecidable from the endpoints, and it is the most common gesture on this
page.

**Resolution: narrow first, ask only when genuinely ambiguous.** One function answers "what could
this edge be", from the endpoints *and* the user's rights:

```js
function possibleKinds(source, target) {
    const s = source.getData?.() || {}, t = target.getData?.() || {};
    const kinds = [];
    // an object reference's source is ALWAYS an object, and it is intra-event
    if (canEdit && s.type === 'object'
        && (t.type === 'object' || t.type === 'attribute')
        && s.scope === 'self' && t.scope === 'self') {
        kinds.push('object-reference');
    }
    // feed/server are not in AnalystData::valid_targets
    if (permAnalystData && t.type !== 'feed' && t.type !== 'server') {
        kinds.push('analyst-relationship');
    }
    return kinds;
}
```

| `possibleKinds()` | Behaviour |
|---|---|
| 0 | `isValidConnection` returns `false` — the target is marked invalid live during the drag, and `onBeforeEdgeCreate` is never consulted |
| 1 | no link-type question; the form asks only for the relationship type |
| 2 | the form carries a **pre-filled link type**, defaulted to `object-reference` |

The extra field therefore appears only where both writes are genuinely available — which for a
user without event edit rights is **never**. This cannot produce an impossible write (unlike
"always an object reference"), does not make identical gestures mean different things for
different users (unlike inferring from rights alone), and does not hide the decision in rail-mode
state.

**The two kinds do not share a vocabulary**, which decides the form's shape:

- **Object references** draw on `object_relationships` — **262 rows** on the dev instance, so it
  is populated and authoritative. The module's hardcoded 25-entry fallback is deleted (task 10);
  the list comes from `/objectRelationships/index.json`, and a failed fetch leaves free text.
- **Analyst relationships** take free text (`relationship_type varchar(255)`, no vocabulary).

So the relationship-type field depends on the chosen link type, which the declarative
`promptData({ fields })` form cannot express. The two-kind case needs `promptData`'s custom
variant (`render` + `getValues`); the one-kind case can stay declarative.

**Built otherwise (task 10b), under P0:** both cases stay declarative. An analyst relationship's
type is free text, so a name picked from the reference vocabulary is equally valid for it; the
two-kind form is the one-kind form with a *Link type* select in front, defaulting to
`object-reference`. No custom form markup.

**How it is shared (task 19).** An analyst relationship also asks what MISP's own *Add
Relationship* form asks beyond its type: **distribution** (levels 0–4, named as MISP names them —
the model refuses 5), **sharing group** (the user's usable ones, `fetchAllAuthorised(…, 'name', 1)`,
read only at level 4 and required there) and **authors** (blank lets MISP fill in the user's
email, shown as the placeholder). The default level is `MISP.default_analyst_data_distribution`,
else `MISP.default_event_distribution` as that form shows. The element computes all of it for a
user with analyst rights and hands it over as `data-pe-analyst-sharing`. When the analyst kind is
the only one, the questions join the one form; when both kinds are possible, a second form, *Share
the relationship*, follows once the analyst kind is chosen and the first form's button reads
*Next*. Pivotick's form has no field that depends on another, so that second form is how a
reference is spared the sharing questions, and the sharing group is listed whatever the level.

**A latent stored-XSS is removed on the way.** The current picker builds its `<option>` list by
string concatenation into `innerHTML` (`:847-850`). It is fed from the hardcoded 25-entry array
today, so nothing is exploitable — but `object_relationships` contains a row literally named
`<script>alert('name')</script>`, so wiring the real vocabulary into that builder would introduce
stored XSS. `ctx.promptData()` removes the sink, and v1.5.0's rule that a consumer `string`
renders as text rather than markup means the library will not reintroduce it.

`isValidConnection` **rejects feed and server nodes as targets outright** — no persistable edge
can point at them.

#### D3 — Two legend sections; provenance is not one of them ✅ SETTLED

**Two** sections, not three:

| Section | Keys on | Rows |
|---|---|---|
| `Element` | the `render.nodeTypeAccessor` dimension (neither `key` nor `entries`) | 5 — attribute, object, event, feed, server |
| `Relationship` | `scope: 'edge'`, `key: 'kind'` | 5 — the D1 kinds |

Sections AND together, so "attributes, correlated" is expressible. The `Relationship` section
names the same key as the `edgeFacets` declaration, so panel and legend are two views of one
filter, and it is the affordance that switches the correlation layer on once D9's fetch has run.

**Provenance is deliberately excluded.** The legend is *descriptive* — it samples the colour the
renderer resolved and reports it. Provenance is not encoded in colour (D2c), so any provenance
section would have to invent swatches that appear nowhere on the canvas, and the library warns
about exactly this case. A legend row that disagrees with the canvas is worse than no row.

Provenance filtering instead lives in the **filter panel** as an ordinary `scope` node facet — a
checkbox, which is the right control for a dimension with no colour. Nothing is lost: a facet
there filters exactly as a legend row would.

Rejected alternative worth recording: swatches showing the same hue at two saturations, so the
swatch demonstrates the encoding. It only tells the truth for one node kind — a saturated and
desaturated orange keys it to attributes, while objects are blue and feeds different again.

Corner: **the library's default**, not a declared one (✅ task 7). In `full` mode Pivotick now
docks the legend in the right column, stacked above the minimap, because the left column belongs to
the mode rail and its panels — so the `bottom-left` this section first proposed would now fight
the rail.

#### D2c — Provenance has no canvas encoding ✅ SETTLED

Foreign nodes are **not** dimmed, tinted or otherwise marked. Provenance lives in the sidebar
panel, the dock table's column, and the `scope` filter facet (D3) — nothing on the canvas.

**Rationale, and it is the important part:** fading is not a neutral cue, it encodes a *judgment*
that this event is the subject. An analyst may legitimately pivot outward and make the foreign
material the focus — following a correlation into a campaign, treating this event as one exhibit
among several — and a baked-in fade fights that the whole way. A filter facet is symmetric: it
isolates `self` or `foreign` with equal ease, and lets the analyst declare what the subject is
instead of the renderer assuming it.

Rejected: **(a)** fading (asymmetric, per above) and **(c)** foreign variants of each node type
(`attribute (other event)`, …), which would make provenance legend-describable but multiplies the
type space and makes the `Element` section do two jobs.

**Consequence — the chrome becomes the only "you are here".** With no canvas encoding, nothing
inside the graph says which event seeded it. That is tolerable on `/events/view2`, where the
surrounding page identifies the event, but not once the same component is mounted from a pivot
route (§11) with no event page around it. So the component carries its own header — the card
header, since `UI.mainHeader` is the sidebar's per-selection title and Pivotick has no graph-level
slot (✅ task 8):

```
Event 1234 · <info> · <orgc> · <date>
seeded L0+L1 · 86 nodes · L2 skipped (28,410 objects not shown) · 5,629 correlations available
```

The second line is not decoration: D11 and D12 both *require* the graph to state which resolution
levels it seeded and what it left out, and this is where that statement lives.

#### D4 — "Unlinked attributes" becomes search + a server-paged table ✅ SETTLED

> **Built as a pivot (task 9, 2026-09-23).** Under P0 the pane is Pivotick's own: an origin-less
> pivot whose `text` facet is the search box and whose Review tab is the paged table; ingest puts
> elements on the canvas, with undo. Paging stays in the browser until D13, because the whole
> payload is already there. The tray and its drag-and-drop are gone.

Today's sidebar panel titled **"Unlinked attributes"** (`:887`) lists every attribute and object
not on the canvas as draggable chips. It is doing two jobs, and they scale differently:

- *getting one specific element onto the canvas* — has to live inside the graph, and is the only
  thing the panel uniquely provides;
- *browsing the event's contents* — which the event page's own attribute table already does
  properly, with paging, sorting and filtering.

**Resolution:** the pane keeps a **search box at every size** — type `evil.com`, get a handful of
matches, click to add to the canvas — and adapts its listing to the event:

| Event size | Listing |
|---|---|
| short / medium | the full list, as today |
| large | a **server-paged, sortable** table |

Search is bounded by construction and works identically on a 20-attribute event and a
370,000-attribute one, which is what makes it the primitive rather than the list.

**The listing is server-backed, not paged in the browser.** MISP already provides it twice:
`EventsController::viewEventAttributes($id, $all)` (ACL `*`, `ACLComponent.php:441`) — the
endpoint the event page's own table uses — and `AttributesController::index()`, which accepts
`page`, `limit`, `sort`, `direction` alongside `value`/`type`/`category`/`uuid` filters
(`:104`). Neither needs building.

The library's own table goes in the drawer beside it and shows **what is in the graph** — a small
set after the seed rule — with its `Visibility` column explaining what is hidden and why. The two
panes have different scopes on purpose: yours is the event, the library's is the canvas.

Rejected: leaving the panel in the sidebar (a narrow column for long attribute values, and it
splits two differently-scoped lists across two places), and deleting it outright in favour of the
page's table (which would remove the only in-graph route to adding an element).

It mounts via `UIManager.addDockTab()` — a wide horizontal region suits long attribute values far
better than a narrow sidebar column — and the sidebar keeps the analyst-data panel (§6.2).

**Why this is load-bearing rather than cosmetic:** the graph now seeds on relationships and a
budget, so for the ~92% of events with no authored relationship, and for every event above 1,500
nodes, this pane is the *only* in-graph route to the event's contents.

#### D13 — A dedicated seed endpoint, in its own PRD ✅ SETTLED

Exposed by §3.5's payload measurement: every budget in this document caps something *downstream*
— D12 the canvas, D9 the correlation fetch, D4 the listing — while the opening fetch stays
unbounded. `/events/view/4116.json` is ~100 MB and the graph draws 86 nodes from it. Once D4's
pane is server-paged, **nothing in the design needs the full payload in memory**.

**Resolution: build a dedicated graph endpoint returning `{nodes, edges, meta}`** — the server
knows which elements carry relationships and can answer in kilobytes what now costs 100 MB. It
also collapses two other items: the dedicated correlation endpoint (§11) and the client-side
graph construction that is the bulk of `pivot-explorer.js`.

**Deferred to its own document:** [`pivot-explorer-graph-endpoint-prd.md`](../../prd/pivot-explorer-graph-endpoint-prd.md).
It is a new endpoint with its own ACL, sharing-group filtering and test surface, whereas every
other decision here is implementable against the existing payload. So this PRD ships against
`/events/view/{id}.json` unchanged, and **knowingly accepts that large events stay slow to
open** until the endpoint lands.

Rejected: named parameters to trim `fetchEvent` — it grows an already-large option surface for a
partial win, and would still ship the whole event's tags and analyst data.

#### D6 — Deletion removes relationships, never elements ✅ SETTLED (amended by R4)

D6's original content — `onBeforeEdgeCreate`, `isValidConnection`, `editors.*.enabled` — was
absorbed into **D2b** with more detail. What remained was the one unexamined part of the write
path, and the riskiest: deletion. Pivotick puts Delete in the bulk-action row **directly beside
Hide**, and the two mean entirely different things.

**Resolution:**

- **Deleting an edge deletes the underlying relationship** — the object reference or the analyst
  relationship — which is the exact inverse of what D2b creates.
- **Deleting a node is not offered.** `editors.deletion.enabled` is a single flag and cannot
  distinguish nodes from edges, so node deletes are **vetoed in `onBeforeDelete`** with an
  explanation.
- **Every edge deletion goes behind `ctx.confirm()`**, naming the specific relationship.
- **Built (task 10c):** a soft delete by the reference's uuid, which every object-reference edge
  carries. An edge MISP cannot find again, or would refuse to delete — a correlation, an
  analyst relationship of another org (task 10b: `canEditAnalystData` is creator org or site
  admin) — is spared from the decision, not deleted and not a veto. An analyst relationship is
  hard-deleted, as MISP's own views do. Notes are canvas-only and pass through.

Rationale for refusing node deletion:

- Remove-from-canvas is already **Hide**. Two adjacent buttons where one is reversible and the
  other soft-deletes event data is an accident waiting to happen.
- Deleting an attribute that is a cluster child *inside* an object is a different operation from
  deleting the object; `cascadingEdges` makes that ambiguity visible rather than resolving it.
- MISP's event view already deletes attributes properly, with context and confirmation. The graph
  does not need to be a second, worse place to do something destructive.

`DeleteContext` gives `{ nodes, edges, notes, cascadingEdges, origin, confirm }`, with `edges` and
`cascadingEdges` guaranteed not to overlap — so each deletion can be persisted exactly once. With
node deletion vetoed, `cascadingEdges` is always empty here.

#### D7 — Physics opts into `'auto'` ✅ SETTLED (revises the original recommendation)

Keep `d3LinkDistance: 200` **and** add `physics: 'auto'`.

The original D7 said stay manual so that "layout does not change under this release". **D12
invalidated that reasoning:** the seed rule means the canvas is 86 nodes, or 20, or 1,500
containment-only clusters depending on the event, so layout was never going to stay unchanged, and
one hand-tuned link distance cannot suit that range. Auto re-tunes from node count, node sizes and
canvas size and keeps doing so as the graph changes — precisely the variability D12 introduced.

Setting both is explicitly legal: the explicit d3 values **seed the opening frame** and auto takes
over from there. So the first paint is the layout that exists today, and it adapts afterwards
rather than staying tuned for a graph shape that no longer occurs.

Note this supersedes the §3.3 audit line that inferred physics would stay `'manual'` — that was
true of the code as it stands, not of the code this PRD produces.

## 6. Detailed Design

### 6.1 Relationship layers and the seed rule (D1, D5′)

`buildGraphData` produces three edge kinds at load and a fourth on demand:

```js
// object references — existing, now tagged
edges.push({ from: objId, to: refId,
             data: { kind: 'object-reference', label: rel } });

// analyst relationships — from attr/obj .Relationship[] (+ .RelationshipInbound[])
edges.push({ from: srcId, to: dstId,
             data: { kind: 'analyst-relationship', label: r.relationship_type,
                     authors: r.authors, orgc: r.orgc_uuid } });

// L0's correlation aggregate — one edge per RelatedEvent, no assertion to label
edges.push({ from: 'event:' + ev.uuid, to: 'event:' + related.uuid,
             data: { kind: 'event-correlation', label: '' } });

// correlations — added later, by §6.7's second request
```

Seed membership follows D12's resolution levels, taking the highest that fits the 1,500-node
budget:

```
L0  if edged    event node + one proxy node per RelatedEvent
L1  always      elements participating in an object reference or analyst relationship
                (+ the attribute children of any object node, as today)
L2  if it fits  objects and event-level attributes with no relationship that a feed
                or server hits, their hit the only edge; anything nothing links is
                left to the element pivot (2026-09-30: event 4466 drew 81 kit
                endpoints with no edge at all)
L3  on demand   per-attribute correlations (§6.7)
```

`computeConnectivity()` generalises from "a reference touches it" to "any authored relationship
touches it", and now resolves `event:` endpoints too, so an analyst relationship may target this
event or one of its correlated neighbours. `computeSeed()` sits above it and owns the level
arithmetic: it costs L0 and L1, then admits L2 whole or not at all (D10). L2 adds an event-level
attribute only for a feed or server hit — see D10's governing principle and its amendment.

**One seed, two readers.** `computeSeed()` is what the canvas builder and the editor tray both
consult, so the invariant that every live element is on the canvas *or* in the tray — never both,
never neither — survives L2 moving most objects from the second to the first. On an event whose L2
does not fit, the tray is again the only route to those objects (D4).

The graph states the outcome (§7, D12): *"Seeded L0+L1 · 4 nodes · L2 skipped (28,410 objects not
shown) · 3 relationships not drawable"*. It renders into `#pe-resolution` in the card; task 8 moves
it under the event-identity line of the header D2c calls for. A seed that took **no** level still
owes the skip clause — an event whose only content is relationship-less objects draws nothing and
must say why rather than fall silent.

Feed and server correlations add two node types and two more kinds (D1). Source nodes come from
the deduplicated `event['Feed']` / `event['Server']` maps — one node per source — and the edges
from each attribute's `Feed[]` / `Server[]` hits. As built (task 5b):

```js
// The map is keyed by source id in PHP but arrives as a JSON list, so it is
// re-indexed by each record's own id — by position, feed 1 reads feed 2's name.
known[String(src.id)] = src;

// Per-attribute hit, event-level and object children alike. Source → attribute:
// pivotick draws a stand-in for an edge *into* a collapsed object's child, and
// none for an edge out of one (§7).
if (!nodeSet[attrId]) { feedHitsHidden++; return; }       // never pulls an element in
addNode(srcId, { id: srcId, data: sourceNodeData(type, known[hit.id] || hit) });
addEdge(srcId, attrId, '', 'feed-correlation');           // or 'server-correlation'
```

**A feed hit never seeds an element.** It is a derived correlation, not an authored relationship,
so it joins neither L1 nor the budget arithmetic: edges draw from elements the seed already took,
a source node appears with its first drawable hit, and the rest are stated — *"69 feed hits on
elements not shown"*. The element pivot still offers those elements; one it brings in arrives
without its feed edges, as it arrives without its references. Source nodes are few (one per feed,
88 at most on the dev instance) and are counted in the node total but not in the budget.

A feed is drawn by misp-pivot-nodes (2026-09-24), as the event family's value-only feed hit —
the feed *is* the node. At rest it is `event-s-ring` with the feed mark in the hexagon and the
dotted ring; zoomed in it is `event-m-authority` for a source: the feed mark in the 20px
authority slot, the feed name on line 1, the provider (else the URL's host) on line 2, the dotted
teal rail, and no preview triangle since nothing on the node opens the feed. It has no XL, so
its focus card is that chip. The entity lives in `prd/pivot-node-designs/renderers/` like the
others. A server is drawn the same way (task 42), as the event family's remote hit: the server
mark in the hexagon inside the dashed ring at rest, and the same authority chip with the server
mark in the slot, the server name, then the provider or the URL's host. It wears its own hue,
magenta `#D0539F` (the palette's `server` family); the purple it had as a triangle sat 25° from
the galaxy violet and read as a cluster. The `server-correlation` edges take the same hue.

A source node's data carries the label, provider, format and URL where MISP sends them,
`feed_events` for a MISP-format feed, and `scope: 'foreign'`: provenance stays binary (D2), and a
value the Provenance facet does not offer would hide the node under either choice. It has no
`name` key, which the Object facet reads. A restricted `Server` source carries only id and name;
its chip's second line then reads *MISP Server*.

**A MISP-format feed opens onto its events (the `feed-events` pivot).** Each hit on an attribute
names the feed events its value is in (`event_uuids`); a feed listed once per lookup batch is merged
by id, so the node and its badge count every event. The feed wears that count as the pivot's
potential. Running it posts the uuids to `POST /feeds/manifestEvents.json`
(`{feeds: {id: [uuid]}}`), which reads the manifest the instance already holds — a local feed's own
file, a remote feed's cached `misp_feed_<id>_manifest.cache.gz` — and never requests one; gated like
`previewIndex` (`__canViewFeed`), capped at 1,500 uuids. Each event lands as a cached-feed event
card, `feed-event:<feed id>:<uuid>`: info, date, org and tags from the manifest, galaxy tags
resolved to the user's visible clusters, `_provenance: 'feed'` and the feed as `source`. A
`feed-event` edge joins it to its feed and a `feed-correlation` edge to each of this event's
attributes it holds, one not drawn yet coming along. A remote feed without a cached manifest lands
uuid-only cards. *Preview in feed* opens `feeds/previewEvent`. The manifest carries no counts or
distribution, so the card's footer names the feed instead.

**Server correlations are requested** (task 41). The code is the feed code on `ev.Server`. The
event is fetched as `/events/view/{id}/includeServerCorrelations:1.json`, which the event view
itself asks for by default; REST alone defaults it to 0. `Event::fetchEvent` still drops it for a
user who is neither site admin nor in the host org, unless
`MISP.show_server_correlations_for_all_users` is set. For them the layer is simply absent.

Options:

```js
render: {
    edgeTypeAccessor: e => e.getData()?.kind,
    edgeStyleMap: {
        'object-reference':     { strokeColor: '#428bca' },
        'analyst-relationship': { strokeColor: '#f39a1f', dashed: true },
        'event-correlation':    { strokeColor: '#6fbe80', dashed: true },
        'correlation':          { strokeColor: '#888', dashed: true },
        'feed-correlation':     { strokeColor: '#D4A017', dashed: true },  // palette().feed.core
        'server-correlation':   { strokeColor: '#D0539F', dashed: true },  // palette().server.core
    },
},
UI: { filter: { edgeFacets: [
    { key: 'kind',              label: 'Relationship', type: 'multiselect' },
    { key: 'relationship_type', label: 'Asserts',      type: 'regex' },   // case-blind
]}},
```

An analyst relationship whose `related_object_uuid` does not resolve to a node is **skipped** —
`getRelatedElement()` returns `[]` for an unresolvable target, and `addEdge` already refuses an
edge with a missing endpoint (`:277`). Count the skips and report them in the panel (§7).

### 6.2 Analyst-data badges and panel

Notes and opinions fold into **one** badge (D2): the count as its text, the sentiment as its
colour.

```js
badges: node => {
    const a = node.getData()?.analyst;
    if (!a || !a.count) return [];              // [] is how a node says it wears none
    return [{
        position: 'nw',
        text:  String(a.count),                 // >3 chars renders as 99+
        color: a.mood === 'disputed' ? '#b94a48'
             : a.mood === 'endorsed' ? '#6fbe80' : '#999',
        title: a.count + ' notes/opinions — ' + a.mood,
    }];
}
```

`'nw'` deliberately: on an expandable node **both East corners are reserved** for the expand
affordance (north-east collapsed, south-east expanded), and object nodes are expandable. Folding
the two facts into one badge leaves the second free corner genuinely spare.

Badges do not aggregate children, so an object's count must walk `node.children` in the `badges`
function if it should include its attributes (§7).

Opinion → `disputed` uses the existing bands (`opinion_scale.ctp:11`): mean `< 41` disputed,
`> 60` endorsed, else neutral. Dev-instance opinion values are strongly bimodal (13 in 0–30 vs
30 in 70–100), so a two-state signal reflects real usage better than a gradient.

Detail goes in a selection-reactive `ExtraPanel` — v1.6.0 re-invokes `render` per selection with
the selected `Node`, which is what makes this panel possible. Content is already in the payload,
so no fetch; a later thread fetch may return a `Promise` and `ctx.signal` cancels a superseded
one. `callbacks.onBadgeClick` selects the node and opens the panel — a badge with no `onClick`
lets its click fall through, so declaring one is required for interactivity.

**The sidebar around it (task 17).** The panel's title follows the selection — *Notes &
opinions (5)* — through the same selection-reactive `title` a panel's `render` has. The
Properties panel above it is declared (`UI.propertiesPanel.nodePropertiesMap` /
`edgePropertiesMap`) instead of listing every data key under its own name: an attribute reads
Value, Type, Category, Object relation, IDS flag, Comment, Event (*This event* or *Event N*),
the degraded feed flag and UUID; an object Template, Meta-category, Event, UUID; an event Info,
Date, Organisation, Event ID, UUID; a feed or server Provider, URL, Format, Events and its ID; an
edge the kind of link by name, what it asserts, its authors and UUID. Blank fields are left out.
The header keeps the library's default mapping, `label` over `description`, which is already
MISP's.

### 6.3 Sectioned legend (D3)

```js
UI: {
    legend: {
        sections: [
            { title: 'Element' },                                  // nodeTypeAccessor dimension
            { title: 'Relationship', scope: 'edge', key: 'kind' },
        ],
    },
    filter: {
        facets: [                                                            // D3, task 8
            { key: 'scope', label: 'Provenance', type: 'multiselect',
              options: [{ label: 'This event', value: 'self' }, { label: 'Other events', value: 'foreign' }] },
            // Declaring any node facet replaces derivation, so the rest are declared too,
            // options read off the live graph: Element (type), Category, Attribute type,
            // Object (name), IDS flag (boolean), Value (regex).
        ],
        edgeFacets: [
            { key: 'kind',              label: 'Relationship', type: 'multiselect' },
            { key: 'relationship_type', label: 'Asserts',      type: 'regex' },
        ],
    },
}
```

Two sections, not three — provenance is a filter-panel facet rather than a legend section (D3),
because the legend can only sample colour and provenance is not encoded in colour.

Exactly one section may omit both `key` and `entries` (the `nodeTypeAccessor` dimension); a second
is dropped with a warning. The `Relationship` section names the same key as the `edgeFacets`
declaration, so panel and legend become two views of one filter — and it is the affordance that
turns the correlation layer on after §6.7 has fetched it. (`LegendEntry`, if ever declared
explicitly, requires `id` and `color`; `label` defaults to a prettified `id`.)

### 6.4 Event provenance and correlated events (D2)

Every node gains `data.scope` (`'self'` | `'foreign'`) and `data.event_uuid`, derived from the
`event_id` each attribute/object already carries. It drives the `scope` **filter facet**, the
sidebar panel and the dock's column — and **nothing on the canvas** (D2c). With the pending ring
also deleted (D2), `styleCb` has no remaining job on this page and the rim belongs entirely to the
library.

**Since R7, correlated events are not drawn;** another event appears only as an analyst
relationship's target (from `related_object.Event`) or as the container a correlation run fills.
Either is a **leaf node** of type `event`, labelled from `info`/`date`/`org`. It is **not** an
expandable container in this phase (§4); double-click navigates to that event's own `view2`.
✅ Built in task 3b, navigation included: `callbacks.onNodeDbclick` sends the analyst to
`/events/view2/{id}` for any `event` node but the one the graph was seeded from. ✅ Task 8 gave
them `data.scope: 'foreign'` and the header.

**The node menu (task 18)** makes that discoverable without navigating away. MISP appends three
entries after the library's own, *Pivot ▸* among them (Pivotick's, one click per applicable pivot):
*Open its event* on a related event or on an attribute or object a pivot brought from another
event, *Browse feed* on a feed (`/feeds/previewIndex/{id}`, which every role may read — a feed's
`view` is host-org only), and *Copy value* on an attribute, confirmed through the notifier. The two
pages open in a new tab, so the canvas survives; double-click still navigates in place. None is
gated on edit rights: none writes. This event's own elements get no *open* entry — their MISP view
redirects to the page the analyst is on.

✅ **Built in task 8.** Every node carries `scope`, `event_id` (for an attribute or object, the
event it belongs to) and `event_uuid` where the payload knows it — extension events are listed
without one. Pivot results carry it too: a correlated attribute is foreign with its event's id and
uuid, this event's side of the pair self.

Extended events (`extended:1` merges foreign attributes/objects into the same arrays, provenance
in `Event.extensionEvents`) are `scope: 'foreign'` and, unlike correlated events, are real nodes
with real edges. Whether they get a container enclosure is deferred (§11).

### 6.5 Editor tray → dock pane (D4)

`createEditor()` keeps its inventory logic and chip DOM; only the mount changes:

```js
var handle = _graph.UIManager.addDockTab({
    label: 'Event elements', order: 10,
    render:  function () { return panelEl || buildPanel(); },
    toolbar: function () { return buildFilterInput(); },
});
```

`render` is called once, lazily, on first activation, so the pane keeps its scroll position;
`handle.refresh()` re-renders after a chip is staged. Under D5′ the dock is **load-bearing, not
a convenience**: the graph seeds on relationships, so for most events the dock is the only route
to the event's contents. `UI.table` gives a second pane whose `Visibility` column explains where
every element stands — the honest version of what the tray approximated.

The relationship picker overlay is **removed** in favour of `ctx.promptData()` (§6.6).

### 6.6 Write path and the gating model (D6, D8)

```js
editors: {                       // affordance removal, not veto
    edgeEditor:  { enabled: canEdit || permAnalystData },
    nodeCreator: { enabled: canEdit },
    deletion:    { enabled: canEdit },
},
callbacks: {
    // (source: Node | Note, target: Node) => boolean — runs on every pointer move.
    // Cheap: property lookups only. Zero possible kinds ⇒ the target reads invalid.
    isValidConnection: (source, target) => possibleKinds(source, target).length > 0,

    // (context: EdgeCreateContext) => EdgeCreateDecision | Promise<…>  — ONE argument
    onBeforeEdgeCreate: async (ctx) => {
        if (ctx.kind !== 'edge') return true;               // note-links pass through
        const kinds = possibleKinds(ctx.source, ctx.target);
        if (!kinds.length) return false;

        // one kind: declarative form, no link-type question
        // two kinds: custom form, because the vocabulary depends on the choice (D2b)
        const values = kinds.length === 1
            ? await ctx.promptData({ fields: fieldsFor(kinds[0]) })
            : await ctx.promptData({ render: renderLinkTypeForm, getValues });
        if (!values) return false;                          // cancelled → veto

        const kind = values.kind || kinds[0];
        const ok = kind === 'object-reference'
            ? await persistObjectReference(ctx.source, ctx.target, values.relationship_type)
            : await persistAnalystRelationship(ctx.source, ctx.target, values.relationship_type);
        return ok ? { accept: true, data: { kind, label: values.relationship_type } } : false;
    },

    // (context: DeleteContext) => DeleteDecision | Promise<…>            (D6)
    // { nodes, edges, notes, cascadingEdges, origin, confirm }
    onBeforeDelete: async (ctx) => {
        if (ctx.nodes.length) {
            notify('Hide takes one off the canvas; the event view deletes it from MISP.');
            return false;                          // node deletion is never offered (D6)
        }
        const refs = ctx.edges.filter(isDeletable);    // object-reference with a uuid
        if (!refs.length) return ctx.edges.length ? { accept: true, edges: [] } : true;  // notes
        if (!await ctx.confirm({ variant: 'danger', confirmLabel: 'Delete in MISP',
                                 body: confirmBody(refs) })) return false;   // R4
        const done = await deleteReferences(refs);     // soft delete, by uuid
        return done.length ? { accept: true, edges: done, persisted: true } : false;
    },
}
```

Physics (D7) — the explicit value seeds the opening frame, auto adapts from there:

```js
simulation: { physics: 'auto', d3LinkDistance: 200 }
```

Four notes:

- **`ctx.promptData()` replaces the bespoke relationship picker**, and removes a latent
  stored-XSS sink on the way — see D2b. `ctx.promptLabel()` is the one-field variant. Net code
  deletion.
- **`isValidConnection` is the single gate**, driven by `possibleKinds()` (D2b). It turns the
  legacy Event Graph's after-the-fact refusal — `can_be_referenced()`'s *"Cannot reference a node
  not belonging in this event"* (`event-graph.js:1684`) — into a cursor state during the drag, and
  it covers the feed/server rejection at the same time. `onBeforeEdgeCreate` is not consulted for
  a target it rejects.
- **`edgeEditor` stays enabled for a user with only `perm_analyst_data`.** They cannot create
  object references, but they can assert analyst relationships (D8), so removing the affordance
  wholesale on `!canEdit` would deny the write MISP permits.
- Programmatic mutation never invokes these hooks, so putting a node on the canvas from the dock
  (`graph.addNode`) is unaffected — and under D2 that is a pure view write with nothing to save.

### 6.7 Payload: two requests (D9)

**Request 1 (load)** — `/events/view/{id}.json`, unchanged. Already carries analyst data and
`RelatedEvent`. Notably it must **not** gain `includeGranularCorrelations:1`: under D9 the
absence of `RelatedAttribute` from the REST default is exactly what is wanted.

**Request 2 (on demand)** — `/events/view/{id}.json/includeGranularCorrelations:1` when the user
asks for correlations, taking `RelatedAttribute` from the response and discarding the rest. Cap
applied here, before nodes are built.

Refetching the whole event to obtain one key is wasteful; a dedicated
`/events/correlations/{id}.json` returning only `RelatedAttribute` is the clean version and is
logged in §11. Reusing the existing named parameter first keeps this phase free of controller
changes.

Two smaller items:

- **Annotation counts** are derived client-side in `attributeNodeData()` / `objectNodeData()`
  from the inline `Note`/`Opinion` arrays. No endpoint work.
- ✅ **Inbound analyst relationships** are attached by `attachAnalystDataBulk` (task 41): one
  query per chunk of 1,000 uuids on the indexed `related_object_uuid`, and the key only where
  something points at the element.

## 7. Edge Cases

- **The 92% case.** ✅ Handled by task 3c. Most events have no authored relationship, so L1 is
  empty and the seed rests on L0 + L2. For the 306 events costing ≤100 nodes that is a complete picture of the event's
  composition; D11's message now fires only when L0, L1 and L2 are all empty.
- **Event 4116.** 369,822 attributes, 28,410 objects, 0 references, 5,629 correlations. L1 empty,
  L2 does not fit (523,677 nodes across the three monsters), so it seeds at **L0: 86
  correlated-event proxies**. The graph must say that L2 was skipped and why, or the analyst reads
  86 nodes as the whole event. ✅ Built in tasks 3b/3c; the statement is `#pe-resolution`. The
  arithmetic is unit-tested at the boundary (1,500 fits, 1,501 skips whole) rather than against
  the live event, which the opening payload makes too slow to iterate on.
- **The L2/`hideDisconnected` collision.** A containment-only cluster parent has no edges, so
  `hideDisconnected` treats it as disconnected and flipping *Hide unconnected* blanks an
  L2-seeded canvas. The library deliberately leaves a cluster's *interior* alone but not its
  parent. Not a blocker — but the switch's label and D11's message must both speak about
  **relationships**, not about content, or the behaviour reads as a bug.
- **The dock on a huge event.** Resolved by D4: the pane pages server-side via
  `viewEventAttributes` / `attributes/index` rather than listing an in-memory 398,000 rows.
- **`hideDisconnected` after a correlation fetch.** Turning the correlation layer back off
  strands the foreign nodes it brought in. The View flyout switch is the user's remedy; we should
  not force it on, since it moves the graph.
- **`reapply()` and manual hides.** Re-deriving visibility undoes `graph.hideNode()`. Any code we
  write that hides a node must use `queryEngine.excludeNode()` instead.
- **Badge capacity.** Four on a plain node, two on an expandable one. Object nodes are
  expandable; child aggregation would want three.
- **Unresolvable analyst-relationship targets** — skipped (§6.1); surface a count so a dropped
  assertion is visible rather than silently absent.
- **Deleted records.** `isDeleted()` tombstones attributes/objects/references; analyst data has
  no `deleted` flag, so an analyst relationship can point at a soft-deleted attribute. Treat as
  unresolvable.
- **Cluster stand-in edges** are deduped by node pair and can speak for several kinds; the
  library keeps them alive while any represented edge passes the filter. Nothing to do, but a
  stand-in's style may not match any single layer.
- **Edges out of a nested child** were never drawn under Pivotick `1296966`: a collapsed object
  got a stand-in for an edge into one of its attributes but nothing for an edge out of one, so an
  analyst relationship from an object's attribute to anything outside that object was hidden.
  Fixed upstream — edges across clusters are drawn from one projection (`a0a4c9a`,
  `pivotick/prd/cluster-edge-projection.md`) — and bundled in task 0d. Feed edges still run
  source → attribute, the direction chosen around the defect; nothing needs them flipped.
- **Feed correlations in degraded mode.** Past 10,000 hits without `overrideLimit` the sources are
  dropped and the payload carries only `attribute['FeedHit'] = true` and `event['FeedCount']`
  (`Feed.php:604-611`). There is nothing to draw an edge *to* — no feed node exists. Render this as
  a **badge** on the attribute ("in a feed") rather than an edge, and say so at the graph level
  from `FeedCount`. Both shapes must be handled; a big event will hit this. **Built (5b):** an `sw`
  badge (`fa-rss`, the feed cyan) on each flagged attribute, off the analyst badge's `nw` corner,
  and *"16246 feed hits, too many to name their feeds"* in the statement. Like the analyst badge
  it does not roll up, so on event 1195 — every flagged attribute inside a collapsed object — it
  shows only once an object is expanded.
- **Server fields are restricted.** Non-site-admin users outside the host org get only `id` and
  `name` on a `Server` source (`Feed.php:613-620`), so a server node's label is all there is —
  no tooltip detail, no URL. Server event-UUID hits are withheld entirely (`:648-652`).
- ✅ **Server correlations are requested with the event** (task 41), not on demand: they cost
  what feed correlations cost, which the payload already pays. Past 10,000 hits MISP degrades
  them the feed way, flagging `FeedHit`, so on such an event a server hit wears the feed badge.
- **Self-referencing analyst relationship** — `Relationship::beforeValidate` rejects
  `object_uuid == related_object_uuid`; guard anyway.

## 8. Test Plan

Manual, on `/events/view2/{id}` against the dev instance (75 notes, 43 opinions, 120 analyst
relationships, and the events in §3.5 as fixtures). Each item says what checked it — the
progress file's §2 ledger has the detail — or what is **still owed**. The tray and the dock pane
that items 1 and 9 first described were retired by task 9's element pivot (§11.7); the items now
test what replaced them.

**2026-10-01:** the owner exercised the explorer live and found nothing broken or odd. That pass
closes the **still owed** items below; they stay listed as what it covered.

1. ✅ **Upgrade regression** — graph renders, objects expand, the element pivot puts an element on
   the canvas, an edge can be created and persists across a reload (1b, 9).
2. Event 1195 (2,362 refs): ✅ seeds with the authored spine (1b); ✅ layers toggle independently
   (7, on 2014). **Still owed:** layout, selection and camera measured unchanged across a toggle.
3. ✅ The empty canvas: D11's card on 184 (4). Event 4116 (0 refs, 5,629 correlations) is never
   empty — its related events seed L0 — so it tests the caps instead: the element pivot is refused
   past 1,500 candidates, and related-event pulls land and undo cleanly (5, 9).
4. ✅ References *and* analyst relationships drawn as two layers on one event (10b, 2014).
5. ✅ Badges only on elements with analyst data; clicking one opens the panel (6).
   **Still owed:** that clicking the node's shape beside the badge still selects it.
6. Legend: ✅ the Relationship section drives the panel's layer filter and stays in sync (7).
   It has two sections, not three — provenance is a facet, not a legend section. **Still owed:**
   sections folding independently; two sections filtering together.
7. Provenance: ✅ the `scope` facet isolates each set, and the header states which event seeded
   the graph (8). **Still owed:** an `extended:1` event's foreign nodes looking identical to local
   ones — the explorer fetches without `extended:1`, so none have been seen; a correlated-event
   proxy navigating on double-click (unit-tested only).
8. Write gating: ✅ read-only users get no write affordance at all (R5); ✅ a persisted edge survives
   a reload (1b, 10). **Still owed:** an invalid target marked during the drag; a vetoed edge
   leaving nothing behind.
8b. ✅ Deletion (D6): an edge's delete confirms, names the relationship and survives a reload; a
   node's is refused with the Hide explanation (10c). **Still owed:** the bulk-action and
   context-menu delete buttons clicked live, and a mixed node-and-edge selection refused whole
   there (both route through the tested `requestDelete`).
8c. ✅ Physics (D7): 2014's opening frame is today's; 1195 re-tunes to an even disc (11).
   **Still owed:** a 1,500-node L2 seed checked for spacing.
9. Element pivot, which replaced the dock pane: ✅ lists what the canvas lacks, search narrows it,
   ingest and undo (9). **Still owed:** the Review tab's scroll position surviving a tab switch.
10. ✅ An event with no analyst data draws no badge and no panel (6, 2014).
11. ✅ Edge types: the Asserts box keeps what matches, case-blind, and hides correlations (5c).
12. ✅ Feeds: one node per feed, edges matching the payload, the degraded badge and total (5b).
    **Still owed:** a foreign org's analyst relationship seen spared by a delete; a note on the
    event node itself — no event at hand had either.

## 9. Implementation Plan (sequential, one commit per task)

| # | Task | Depends on |
|---|---|---|
| 0 | ✅ Bundle to v1.6.0 + compatibility audit | — |
| 0b | ✅ Bundle to v2 (`develop` `d220446`) + audit; edge save moved onto `onBeforeEdgeCreate` (§3.7) | 0 |
| 0d | ✅ Bundle to `develop` `f598444`: edges out of nested children drawn (§11.12), `removeBySource` in Undo (§11.13); the removal notice says Undo puts it back | 0b |
| 1 | Regression pass on the existing graph under v2 (§8.1); refresh the stale Edit▸Add-edge comment | 0b |
| 2 | ✅ Tag object-reference edges with `kind`; add `edgeTypeAccessor`/`edgeStyleMap`/`edgeFacets` (one layer) | 1 |
| 3 | ✅ Generalise `computeConnectivity()` to any authored relationship; add analyst-relationship edges as a second layer (L1, D5′) | 2 |
| 3b | ✅ L0: event node + `RelatedEvent` proxy nodes (free, already in payload) — withdrawn by R7 (task 20) | 2 |
| 3c | ✅ L2: budget-capped containment-only objects, with a "skipped, N not shown" statement (D10, D12) | 3, 3b |
| 4 | ✅ D11 empty-state message, pointing at the element pivot (an empty seed has no correlations) | 3c, 9 |
| 5e | ✅ Count source: `/events/correlationCounts/{id}.json` (R1, first slice of D13) | — |
| 5f | ✅ Fetch path: `POST /events/correlatedAttributes/{id}.json` — the pairs 5e counts, narrowed by `attribute_uuids` or `event_ids` | 5e |
| 5 | ✅ correlations as a pivot — `appliesTo` / `summarize` from 5e / `fetch` from 5f / `maxCandidates` 1,500, no `save` (R1) | 5e, 5f, pivotick fix |
| 5d | ✅ related-event pivot on L0 proxies + declared potential as the rim badge (R2) — withdrawn by R7 (task 20) | 3b, 5e, 5f, pivotick fix |
| 5b | `feed`/`server` node types + `feed-correlation` layer (free in payload), incl. the `FeedHit` degraded shape (D1) | 2 |
| 5c | `relationship_type` text facet as the second edge dimension (D1) | 2 |
| 6 | ✅ Analyst-data badges + selection-reactive sidebar panel | 1 |
| 7 | ✅ Sectioned legend — `Element` on `nodeTypeAccessor`, `Relationship` on edge `kind`; library-default corner | 3, 5, 6 |
| 8 | ✅ `data.scope` facet + header (event identity + resolution statement) + correlated-event proxy nodes (D2c). The whole node-facet set is declared, since declaring one replaces derivation | 5 |
| 9 | ✅ "Unlinked attributes" → an origin-less pivot, *Event elements*: search + element/category facets, the Review tab as the paged list, ingest as putting on the canvas (D4 under P0, §11.7) | 1 |
| 10 | ✅ `possibleKinds()`; replace the `innerHTML` picker with `ctx.promptData`; delete the pending ring (D2, D2b, P0). Hooks landed in 0b, read-only gating in R5. Ownership comes from the payload, so 8 was not needed | 1 |
| 10b | ✅ Analyst-relationship persistence (`analystData/add`) as the second write target (D2b); `edgeCreator` for `perm_analyst_data` alone (R5). Deletion too, by creator org, as 10c's inverse | 10 |
| 10c | ✅ `onBeforeDelete`: edge deletion behind a `danger` `ctx.confirm()` saying it cannot be undone, returning `persisted: true`; node deletion vetoed (D6, R4). A soft delete by the reference's uuid; correlations and analyst relationships are spared | 10 |
| 11 | ✅ `simulation.physics: 'auto'` alongside `d3LinkDistance: 200` (D7) | 1 |

**P0 sweep (2026-09-23).** A read of Pivotick `develop` against what the explorer uses found
library features it rebuilt by hand or left unused. One commit each:

| # | Task | Depends on |
|---|---|---|
| 12 | ✅ Remove what the correlation pivots brought, through `graph.removeBySource`, from the canvas menu (R1) | 5, 5d |
| 13 | ✅ Labels carry the whole value; the canvas's `textTruncate` shortens them, not a 42-character cut | — |
| 14 | ✅ The Asserts box is Pivotick's `regex` facet, case-blind, instead of MISP's own predicate (5c) | 5c |
| 15 | ✅ Correlated attributes and objects declare their correlation count as rim potential, like related events (R1, R2) | 5, 5d |
| 16 | ✅ Drop `compact()`: Pivotick skips null data values everywhere it scans (since `4d71efb`), so node and edge data pass as the payload has them | 8 |
| 17 | ✅ The sidebar's Properties declared under MISP's names; the analyst panel's title counts the selection's notes (§6.2). Its lifecycle was the library's already | 6 |
| 19 | ✅ Analyst relationships ask distribution, sharing group and authors, as MISP's own form does (D2b) | 10b |
| 18 | ✅ Node context menu: open its event or feed in a new tab, copy an attribute's value; *Pivot ▸* is the library's (§6.4) | — |
| 20 | ✅ R7: no correlated-event nodes, no `event-correlation` edges, no related-event pivot; an event node is an analyst relationship's endpoint (event-level `Relationship` walked, other events from `related_object.Event`); the statement names the events correlations reach | 3b, 5d |

Tasks 2, 6, 9 and 10 are mutually independent. Tasks 5 and 5d are built on 5e and 5f; their
`correlation` edges needed a Pivotick fix (`pivotick/prd/misp/pivot-edges-to-children.md`). 4
follows 9, whose pivot its message points at. Both upstream requests landed in Pivotick `develop` `1296966` (bundled in MISP as `d7a179e9c`); the two defects that left open (§11.12, §11.13) were fixed in `f598444`, bundled as task 0d. Enrichment (R3) is not a task here.

**✅ Done (prerequisite, not a task above).** The inline JS is extracted out of the `.ctp` into
`app/webroot/js/pivot-explorer.js`, leaving the element at 117 lines of markup + CSS + config.
The move was behaviour-preserving: the 745 lines of graph and editor logic are byte-identical,
and only the five PHP interpolation points changed shape. Config now arrives via `data-pe-*`
attributes on `#pe-card` (`event-id`, `baseurl`, `can-edit`, and the two translated error
strings), read in a new `boot()` that waits for `DOMContentLoaded` because `assetLoader`
emits the `<script>` ahead of the element's own markup.

Two follow-ups this exposes, neither blocking: the editor's ~15 UI strings (`Filter…`,
`Add relationship`, `Cancel`, `Save`, …) were hardcoded English in the `.ctp` and still are
in the module — they want the same `data-pe-*` treatment to become translatable; and the
`<style>` block (78 lines, still inline under `if ($canEdit)`) is the same extraction again
for CSS.

## 10. Files Touched

| File | Change |
|---|---|
| `app/webroot/js/pivotick.iife.js` | ✅ replaced (v1.6.0, then v2 at `d220446`, then `1296966`, then `f598444`) |
| `app/webroot/css/pivotick.css` | ✅ replaced (v1.6.0, then v2 at `d220446`, then `1296966`; byte-identical at `f598444`) |
| `app/View/Themed/Overmind/Elements/Events/View/event_pivot_explorer.ctp` | ✅ trimmed to markup + CSS + `data-pe-*` config (858 → 117 lines); ✅ `#pe-resolution` line added (task 3c); ✅ `#pe-header` with `#pe-identity` above it (task 8) |
| `app/webroot/js/pivot-explorer.js` | ✅ new — all behaviour, extracted from the `.ctp`; all of §6.1–§6.7 lands here |
| `tests/js/pivot-explorer-graph.test.js` | ✅ new — zero-dependency unit suite over the seed and the graph builder |
| `app/Controller/EventsController.php`, `app/Controller/Component/ACLComponent.php` | ✅ `correlationCounts` (5e) and `correlatedAttributes` (5f, POST) actions + ACL entries (`*`) |
| `app/View/Themed/Overmind/Elements/Events/View/event_pivot_explorer.ctp` | ✅ edit rights from `$this->Acl->canModifyEvent($data)` — view2 sets no `mayModify` |
| `app/Model/Event.php` | ✅ `getCorrelationCounts()` (task 5e), `getCorrelatedAttributes()` (task 5f) |
| `app/Lib/Tools/CorrelationCountTool.php`, `app/Test/CorrelationCountToolTest.php` | ✅ new — the aggregation, and its unit test (task 5e) |
| `app/Model/Behavior/AnalystDataParentBehavior.php`, `app/Model/Relationship.php` | ✅ `RelationshipInbound` in the bulk path (task 41) |
| `app/Lib/Tools/JSONConverterTool.php` | ✅ keeps an event's and an object's `RelationshipInbound` (task 41) |
| `docs/dev/pivot-explorer-v16-prd.md` | this document |

No schema change in Phase 1. One new endpoint, `correlationCounts` (task 5e), as the first slice
of D13.

## 11. Open Questions / Phase 2

**Parked 2026-10-01.** The explorer works as wanted today; the open items below (1, 2, 3, 5, 8
and 13's two-Undo remainder) wait for feedback from analysts or the community rather than being
decided ahead of it.

1. **Object aggregation** (backend). The one dimension with no existing roll-up: "28,410 objects
   → 12,000 file, 8,000 url" as aggregate nodes, so a behemoth's L2 degrades to a summary instead
   of being skipped. Correlations already have their aggregate for free (`RelatedEvent`, D12);
   objects do not. This is the natural successor to D10's ceiling and needs a new endpoint.
2. **Lazy expansion.** `childrenProvider` / a fired `onBeforeNodeExpansion` is the one library
   PRD from the set that did not ship (`prd/misp/async-children-provider.md`, still *Proposed*).
   R2 made the related-event pivot the stand-in (5d): a proxy does not expand in place, but its
   pivot brings its elements in. **Open:** whether in-place expansion is still wanted on top.
3. **Declarative initial filter value** (library ask). `FilterOptions`/`FilterFacet` carry no
   opening value (§3.2). Not needed under D9, but any future default-off layer needs it, and it
   would let a filter apply before the first layout as v1.6.0 intends.
4. ✅ **A dedicated correlation endpoint** — built as two, not folded into D13's graph endpoint:
   `GET /events/correlationCounts/{id}.json` (5e) for what a pivot would bring, and
   `POST /events/correlatedAttributes/{id}.json` (5f) for the pairs. Nothing refetches the event.
5. **The pivot entry point** — a route seeding the same component from one indicator, defaulting
   to Explore. §4 keeps it out of scope; the seed/mode parameterisation is designed for it.
6. **Analyst-data and enrichment write paths.** ✅ Analyst relationships are written and deleted
   from the graph (10b). Notes and opinions stay read-only (§4). ✅ Enrichment shipped as its own
   pass (R3): [`pivot-explorer-enrichment-prd.md`](pivot-explorer-enrichment-prd.md).
7. ✅ **Dock paging** — answered by task 9 as proposed here. Under P0, the answer: the unlinked-element
   list becomes an **origin-less pivot** (`origin: 'none'`) whose Review tab *is* the searchable,
   filterable, paged table, and whose ingest *is* putting elements on the canvas — which retires
   the tray, its drag-and-drop and D4's bespoke pane in one move.
8. **Extended-event enclosure** — does a foreign event get a container, and can object clusters
   nest inside it three levels deep (event → object → attribute)?
9. ✅ **Badge aggregation** — neither (task 6): an object's badge is the object's own; its attributes wear theirs.
10. ✅ **Physics `'auto'`** — shipped (11): skipped inside its deadband on 2014, re-tuning 1195 to
    rest in 7–10 s. The timings were taken on a loaded machine, so no before/after figure is
    recorded.
11. ✅ **`RelatedAttribute` cost** — never paid: correlations come from 5e/5f's endpoints, measured
    on 1195 and 4116 before task 5 shipped, not from `RelatedAttribute` in the event payload.
12. ✅ **Edges out of a nested child** — a Pivotick defect (§7), fixed upstream (`a0a4c9a`, superseding
    `pivotick/prd/misp/edges-out-of-children.md`) and bundled in 0d. An analyst relationship from an
    object's attribute to anything outside that object is drawn.
13. ✅ **`removeBySource` is in Undo** — a Pivotick defect (`pivotick/prd/misp/remove-by-source-history.md`),
    fixed in `a5ebbfc` and bundled in 0d. Task 12's removal is a history entry; Undo restores what
    left and who vouched for it, and the notice says so. **Open:** one removal is two entries, one
    per correlation pivot, because `removeBySource` takes a single source and `history.group`
    coalesces only visibility changes — so a full restore takes two Undos.

## 12. Backlog (after completion, 2026-10-01)

Polish that does not hold the feature open. None of it blocks shipping; each item is picked up
when the library change lands or someone asks for it.

| Item | Waits on | Source |
|---|---|---|
| **Tag pivots past 200.** The summary says at most 200; the endpoint's `total` already carries the real number. | pivotick `prd/pivot-summary-window.md` (Proposed) | tag-pivots PRD, T8 |
| **Select by id.** `selectElement(s)` take Node/Edge objects; selecting by id, reveal and the resolution result are not built. | pivotick `prd/misp/selection-api-by-identity.md` §4.1–4.4 | upstream |
| **Sidebar panel order.** MISP's extra panels render below pivotick's neighbours panel. Cosmetic. | MISP or pivotick | sidebar PRD §5.4 |
| **Groups do not mix origins.** A group can hold both MISP elements and enrichment results; a `scope` key on groups would keep them apart. No code. | MISP | enrichment PRD; `prd/pivot-enrichment/candidates/b-mark/NOTES.md` |

Not in this backlog, because they are separate projects: the `/events/graph/{id}.json` endpoint
([`pivot-explorer-graph-endpoint`](../../prd/pivot-explorer-graph-endpoint-prd.md), parked
2026-09-29) and the intelligence graph (`prd/intelligence-graph/`, stopped after phase 0). §11's
parked questions stay in §11.
