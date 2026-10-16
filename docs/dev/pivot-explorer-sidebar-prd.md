# PRD: A sidebar that completes the node

**Status:** Contract built 2026-09-29 (§5.1); wired 2026-09-29 (§5.4) and checked live.
**Owner:** Sami Mokaddem (Claude-assisted)
**Parent:** [`pivot-explorer-v16-prd.md`](pivot-explorer-v16-prd.md).
**Depends on:** the persona branch's context priority (§4), merged into `personas-pivotick` on 2026-09-29.

---

## 1. Why

A node's card is a glance: an event card shows its title, org, date and a few tags; an attribute
card its value, type and marks. The sidebar is where the analyst reads the rest, and today it
does not do that job.

- **It is a flat list of fields.** `nodeProperties` (`pivot-explorer.js`) returns name/value rows
  per entity: *Info, Date, Organisation, Tags, Galaxy clusters, Event ID, UUID* for an event.
  Nothing is ranked, grouped or explained, and some of it (ids, uuids) is what the analyst
  needs least.
- **It says less than the card in places.** The event card draws threat level, analysis,
  distribution and counts; the sidebar lists none of them.
- **Context is missing.** Nothing says what the node's tags and clusters mean, which feeds or
  servers saw it, how widely it correlates, who sighted it, or which of its context matters to
  *this* analyst.
- **A multi-selection cannot show what nodes share.** Pivotick aggregates each property across
  the selection, with counts and keep/exclude chips, but MISP joins all tags into one string
  (`Tags: a, b, c`), so shared tags never add up.

The goal: for every kind of node, the sidebar shows **everything on the card, plus the context
and other information an analyst needs to decide what to do next, in the order that matters**.

## 2. Requirements

### 2.1 Per entity

Each entity's sidebar holds what its card shows, then its context. The lists are what must be
*reachable*; which is shown first and how is the exploration's question (§5).

| Entity | On the card (must repeat) | Context to add |
|---|---|---|
| **Event** (this one, another, a feed's) | info, org, date, threat level, analysis, distribution, published, attribute/object counts, provenance | tags and clusters, grouped by taxonomy and galaxy; analyst data; correlation summary (how many events share values with it); feeds and servers that hold it; extends / extended by; reports; a link out to its own page |
| **Object** | template name, meta-category, top attributes | all its attributes, ranked by template priority, with their marks; references in and out; tags, clusters and warninglist hits rolled up from its attributes; correlation count per attribute |
| **Attribute** | value, type, IDS flag, marks (warninglist, tags, analyst, feed) | category, comment, first/last seen; tags and clusters; warninglists by name and category; feed and server hits; correlation count; sightings; the object and event it belongs to |
| **Tag** | name, colour | taxonomy, predicate and value descriptions (numerical value where the taxonomy has one) |
| **Galaxy cluster** | value, galaxy | description, synonyms, meta (country, refs, …), relation count |
| **Feed / server** | name, provider | URL, format, how many of the canvas's attributes it holds |
| **Edge** | kind, relationship type | comment, provenance, whether it is authored (deletable) or derived |

### 2.2 Multi-selection

Selecting several nodes answers **what do they share**: tags, clusters, orgs, and later shared
values, each with how many of the selection carry it, using pivotick's aggregated table and
its keep/exclude filter. Every multi-valued field is emitted as one entry per value.

### 2.3 Rules

- **Nothing hints at records the viewer cannot see.** No counts or caveats about invisible
  events, attributes or orgs. A count is of what the viewer can read.
- **Lazy beyond the payload.** What the node data carries renders at once; anything that needs
  a request (sightings, cluster meta, correlation summary) loads in the panel with pivotick's
  async render and its abort signal, never on every selection of the whole canvas.
- **Both themes, sidebar width.** The panel is pivotick's sidebar column; designs work at its
  width, in light and dark.
- **One grammar across entities.** An analyst learns the layout once.

## 3. What pivotick offers

The sidebar is pivotick's; MISP fills it through hooks, all of which receive a node, an edge,
an array of either (a multi-selection) or `null`, and may return a promise (with a
`RenderContext` whose `signal` aborts a superseded render):

| Hook | Place |
|---|---|
| `UI.mainHeader.render` | the header above everything |
| `UI.propertiesPanel.render` / `nodePropertiesMap` | the properties body; `nodePropertiesMap` rows feed the multi-selection aggregation |
| `UI.neighborsPanel.render` | the neighbours list |
| `UI.extraPanels[]` | ordered, optionally reactive, extra panels (MISP's analyst panel is one) |

A design that needs something these cannot do is written up for pivotick, not built around.

**Two gaps, found while building the contract**, both written up in pivotick's `prd/misp/`:

- A custom `propertiesPanel.render` also receives multi-selections, and the aggregated table
  with its keep/exclude chips is then gone (`Properties.ts:175`). So a designed single-node view
  and §2.2's aggregate cannot share the properties panel until `render` can return `undefined`
  to hand a selection back to the default: `properties-render-default-fallback.md`.
- The aggregate assumes one value per property. With one `Tag` row per tag it counts right,
  but keep/exclude reads only a node's first `Tag` row, and a multi-valued property's bar
  overflows: `aggregated-keep-exclude-multi-valued.md`.

**Both landed upstream on 2026-09-29** (pivotick `24da317`, `025b6b8`). A
`propertiesPanel.render` that returns `undefined` hands the selection to the default panel,
so the single-node view owns the properties body and a multi-selection gets pivotick's
aggregated table from `propertyRows`; one `Tag` row per tag now counts and filters right.
MISP vendors pivotick, so wiring starts by taking a bundle that carries both.

## 4. Context priority

The persona work (`worktree-personas`, not merged: 493 commits ahead of `develop` on
2026-09-27) orders context by the analyst's profile. Its rules are in
`prd/personas/02-context-priority.md` and `04-label-surfaces.md`.

- **What it covers: taxonomies and galaxies only.** A profile's
  `parameters.context.{taxonomies|galaxies}.{pinned|preferred|demoted}` lists taxonomy
  namespaces and galaxy types. Order is pinned, preferred, unlisted (count order kept), demoted.
  Nothing is hidden (D40); an instance-disabled taxonomy beats a pin (D41); the instance's
  highlighted tags outrank a pin (D53). Pinned `tlp` / `PAP` lead with the most restrictive label.
  Individual clusters, warninglists, feeds and orgs are **not** in it.
- **Which profile:** `AnalystProfile::resolveFor($user)`, nearest scope wins: user, then org, then
  instance, then the shipped `default-v1`, which declares nothing, so pages look as today.
- **The call:** `ValueLabelPriority::planFor($profile)` normalises a profile into
  `[scope][tier] => keys`, and `order($groups, $plan, $scope)` sorts groups carrying a `key`,
  adding `priority`. They are pure functions: no user, no query. The event page already passes
  the plan to its views (`labelPlan`, `EventsController.php:1767` on that branch), which order
  the tag and galaxy columns of event and attribute rows. There is no per-event or per-object
  equivalent of the value page's `ValueIntelligence::forContext`, and missing pins are only drawn on
  the value page (D54).

**What the sidebar takes from it.** Tags are grouped by taxonomy namespace and clusters by
galaxy type, and those groups are ordered by the active plan. The explorer receives the plan as
the event page does (a `data-pe-*` attribute or the seed payload) and applies the same order
in the view-model. Whether the sidebar also shows missing pins is a question for the
exploration, since D54 keeps them on the value page for now.

**What it does not decide.** The order of everything else (warninglists, feeds, correlations,
sightings, analyst data, the entity's own fields) is not in the profile. The exploration
proposes a fixed order for it, one per entity.

**The dependency is met.** `personas-pivotick` carries both branches. `EventsController`'s
`__eventViewCommon` sets `labelPlan`, but **`view2` does not run it** (found while wiring: the
explorer received an empty plan for a viewer whose profile pins three taxonomies), so the
explorer element resolves the plan itself when none was handed down, and passes it with its
other `data-pe-*` attributes. The
contract's view-models take the plan as input and are tested and dumped with the shipped
`incident-response-v1` (pins `tlp, PAP, admiralty-scale`, prefers `threat-actor,
mitre-intrusion-set, …`). The ordering is a JS port of `ValueLabelPriority`, checked against
the PHP class itself, so the sidebar and the event page cannot rank labels two ways.

Missing pins need the instance's enabled taxonomies and galaxies (D41: a disabled taxonomy
beats a pin). The view-model computes them only when it is given that list, and leaves them
`null` otherwise.

## 5. Phases

### 5.1 Contract

No templates. Built and checked before any design starts:

- **A view-model per entity**, built from node data plus the lazy reads above, with the
  priority order of §4 applied. One function per entity, unit-tested.
- **Fixtures**: the view-models dumped as JSON from real events on the dev instance, covering
  the hard cases: an event with many galaxies (4242), a warninglisted attribute (4074's
  `8.8.8.8`), an object with many attributes, a foreign event card and a feed's card (1562,
  2014), a tag and a cluster node (1525), an authored and a derived edge, a multi-selection of
  three events sharing tags.
- **A page frame**: a static page that renders a candidate sidebar at the real width, in both
  themes, from the fixtures, with an `?only=<fixture>` filter so headless Chrome can capture
  each case.

#### What was built (2026-09-29)

**Most of the context is already in the page.** The explorer's `/events/view/{id}.json` carries
the sightings of every attribute, full galaxy clusters (description, synonyms, meta,
relations), each attribute's feeds and servers, first/last seen, threat level, analysis,
reports, related events and all analyst data; the node data just dropped it. So a view-model
reads this event's own elements from the payload, and only reads lazily what the payload
cannot say:

| Read | Request | For |
|---|---|---|
| `taxonomies` | `POST /tags/search/0/1.json` `{tag: [...]}` | what a tag means: taxonomy, predicate and value text, numerical value |
| `warninglists` | `GET /warninglists/index/id:3‖7.json` | a warninglist's description and type |
| `extended_by` | `POST /events/restSearch` `{eventsExtendingUuid, metadata}` | the events extending this one |
| `record` | `POST /attributes/restSearch` or `/events/restSearch` by uuid | another event's attribute or event, which arrives slim |
| `cluster_tag`, `cluster` | `/tags/search`, then `GET /galaxy_clusters/view/{uuid}.json` | a cluster node the payload does not hold |

`attributes/restSearch` needed `_csrfTokenHeaderOnly` for a session POST, like the explorer's
other endpoints; the rest already pass.

- **The view-models:** `app/webroot/js/pivot-sidebar-model.js`, `MispPivotSidebar.build(input, env)`.
  No DOM and no fetch: a read is declared as `vm.lazy[key] = {state, request}`; the caller
  fetches it, stores the answer in `env.lazy[key]` (`false` when it failed) and builds again.
  One grammar for every entity: `title`, `subtitle`, `provenance`, `card` (what the node draws),
  `facts`, `labels` (tag groups by taxonomy, cluster groups by galaxy, in plan order, plus
  `missing`), `warninglists`, `sources`, `correlations`, `sightings`, `analyst`, `relations`,
  `children` (an object's attributes, ranked by the template), `links`. `propertyRows()` gives
  pivotick one row per value for the multi-selection aggregate.
- **Correlation counts:** the caller's `env.correlations(type, uuid)` must answer 0 for this
  event's own elements that `correlationCounts` leaves out, and `null` only for what was never
  asked. The view-model reads `null` as *not known*.
- **Tests:** `tests/js/pivot-sidebar-model.test.js` (priority rules, PHP parity with
  `PHP_BIN` set, every entity, lazy states, the multi-selection).
- **Fixtures:** `prd/pivot-sidebar/fixtures/`, 14 view-models dumped by `dump-fixtures.mjs` from
  the dev instance with every lazy read performed: this event (4242, and 1525 for galaxies),
  a warninglisted IDS attribute (4074's `8.8.8.8`), an attribute with 9 sightings from 3 orgs
  (46), an object with 26 attributes (1191), another event's card and attribute (from 2014's
  correlations), a feed, a tag and a cluster (4208), a galaxy tag with no cluster behind it, an
  authored and a derived edge, and three correlated events. 4242 has no event-level galaxies,
  so 1525 stands in for that case.
- **The page frame:** `prd/pivot-sidebar/frame.html?candidate=<name>&only=<ids>&theme=light|dark&lazy=pending|failed`
  draws a candidate into pivotick's own sidebar containers at the measured 340px, both
  themes side by side, with the event page's stylesheets. `capture.mjs <name>` screenshots
  every fixture and fails on a render error or anything wider than the column. A candidate is
  `candidates/<name>/render.js` filling `slots.header`, `slots.properties` and `slots.extras`,
  the three hooks of §3; `baseline` is a raw dump that proves the frame.

### 5.2 Exploration

Three candidates, each built **cold by its own agent** from a written brief, so they are
independent designs rather than three passes of one hand. The brief gives the reading list
(this PRD, the fixtures, the page frame, the node designs in `prd/pivot-node-designs`), a
do-not list (no invented data, no fields outside the view-model, no library changes), the
build and capture commands, and one assigned direction:

- **A. The card, continued.** The header redraws the node's card at sidebar width; sections
  follow in a fixed order (context, links, activity), each collapsible.
- **B. Priority first.** A short ranked list of what matters about this node for this analyst
  (§4) leads; the full detail follows below a fold.
- **C. Questions.** Sections named after what the analyst is deciding: *Is it noise?*, *Who
  else has it?*, *What is it tied to?*, *What do we know?*

Each covers every fixture. Deliverables are local files under `prd/pivot-sidebar/`, with
screenshots per fixture and theme.

#### What came back (2026-09-29)

The brief is `prd/pivot-sidebar/brief.md`. All three candidates cover all 14 fixtures and pass
`capture.mjs` in the ready, pending and failed states (28 of 28 each). Each has a `NOTES.md`
next to its `render.js`; `compare.html?only=<fixture>&theme=&lazy=` draws the three side by side.

| | A. `a-card` | B. `b-priority` | C. `c-questions` |
|---|---|---|---|
| First screen | the node's card, complete, at full width | identity, then a ranked *Notice* list | the card, then four question headings each with its answer |
| Rest | Context, Links, Activity, Record, each collapsible, same four for every entity | one fold, *Everything else*, opened at a section by chips | the evidence under each question; Record folded last |
| Best on | event-galaxies, object-many: the card grows into the record | the warninglisted and sighted attributes; event-galaxies | the warninglisted and sighted attributes; multi-events ("1 label on all 3 · 4 on some") |
| Weak on | tag, cluster-bare, edges: all card, empty rows | object-many, tag, cluster, feed, edges: the list turns into a fact list or "nothing stands out" | tag, feed, edges: one or two questions, sparse; events have no noise question |
| Missing pins | drawn, as a quiet closing line | events only: attributes inherit their event's handling | drawn, under *What do we know?* |
| Single view mounts in | header + one extra panel; properties hidden | header + properties | header + properties |

The ranking rule B defines is fixed across entities: noise (false-positive warninglist,
disputed), caution (other warninglists, FP/expiration sightings, unpublished), handling
(pinned tlp/PAP, most restrictive first), other pinned then preferred context, reach
(sightings, correlations, feeds), state (edge kind, analyst data, reports).

**Found on the way, beyond the candidates:**

- **Icons draw as solid squares on the event page.** The Overmind layout loads both
  `misp-iconify.css` (the mask build, 64 icons) and `misp-iconify-font.css`, and both define
  `.misp-icon`; the mask sheet paints the box in `currentColor`, so every icon it has no mask
  for (galaxy, object, attribute-type glyphs) is a filled square. A and B hit it independently.
- **pivotick's header lays its child out as a flex row.** A and C both override it; a header
  that takes a plain block would make that unnecessary.
- **The frame keeps a lazy read's data when it flips it to pending**, so a foreign node's
  card still shows fields that came from the read. The view-model does not say which fields a
  read supplied; wiring needs that to draw a real pending state.
- **View-model gaps all three name:** correlations, related events and cluster relations are
  bare counts with nothing to open; analyst items carry an org uuid but no name; sightings have
  no per-org split by type. A also wants the org uuid on the card (monogram colour), C an
  event-level count of noisy attributes, B the profile's name.

### 5.3 Pick

**Picked 2026-09-29: B, priority first**, for every single node, and C's multi-selection.
It is built as `prd/pivot-sidebar/candidates/picked/`, generated from the two candidates by
its `build-picked.py`, and passes all three capture runs.

| Case | From | Change |
|---|---|---|
| Event | B | **Threat level and analysis dropped** everywhere (strip and Record): they are deprecated. **Tags carry no description**, in the notices or the fold; a pinned handling group keeps "Strictest of n", clusters keep their line. |
| Attribute, object | B | none |
| Edge | B | the two ends drawn as C draws them: the entity's icon, a quiet wash of its hue with a thin bar, the kind as a small word on the right |
| Multi-selection | C | *What do they share?* (n/total with bars) and *Who made them?* in an extra panel; pivotick's own aggregated table in the properties body (§3) |

**"Pinned" is the analyst profile's, checked.** Every `priority` in the view-model comes from
`order(…, env.plan, …)`, and `env.plan` is `planFor(profile)`, the profile's
`parameters.context`; the fixtures use `incident-response-v1`. The taxonomies' highlighted
flag is never read.

**Why B.** It answers what to notice first, and is strongest where the analyst has to stop:
a warninglisted IDS attribute, a sighted one, an event's handling labels. For a
multi-selection there is no single node to rank for; the question is what is shared, which
C's headings answer directly.

**Carried into wiring from the exploration:** the pending state must hide what a lazy read
supplies, so the view-model has to say which fields came from which read; B's notice list is
thin on nodes without signals (tag, feed, edges), which its fold opening by default on small
detail partly offsets; the event page's clashing `.misp-icon` stylesheets (§5.2).

### 5.4 Wiring

The picked design is built into `pivot-explorer.js` on the contract's view-models, through the
§3 hooks, and checked live on the fixture events.

#### What was built (2026-09-29)

- **pivotick** updated to `025b6b8` (the two fixes of §3), built from a clean export of that
  commit.
- **The view:** `app/webroot/js/pivot-sidebar-view.js` and `app/webroot/css/pivot-sidebar.css`,
  ported from `candidates/picked` with the frame-only parts removed; the port matches the
  candidate pixel for pixel on every fixture and lazy state. From here the MISP files are the
  source. `MispPivotSidebarView.header(vm, jump)`, `.detail(vm)` → `{el, reveal}`,
  `.shared(vm)`.
- **The hooks** (`pivot-explorer.js`, *sidebar*): `mainHeader.render` draws the header,
  `propertiesPanel.render` the detail for one element and `undefined` for several, so
  pivotick's aggregate draws from `nodePropertiesMap` = the model's `propertyRows`; an extra
  panel `pe-shared` carries C's shared labels and orgs, hidden by CSS for anything else. The
  analyst panel stays, after it.
- **One session per selection:** the three hooks share one view-model; its lazy reads run
  once, are cached by request for later selections, and redraw the drawn elements in place
  when they land. Retry drops the failed answers and reads again. The session is aborted when
  the selection moves on. Correlation counts arriving later redraw it too; a foreign uuid that
  was asked and left out of the answer now reads 0, not *unknown*.
- **The element** passes `data-pe-label-plan` and `data-pe-permitted` (the plan's pinned keys
  the instance enables, asked as the value page asks them).
- **View-model additions:** a tag or cluster node gives its own row to the aggregate (they gave
  only `Element`); an attribute a card slice brought carries a `Matched` fact, the one field of
  the old flat list the model did not have.
- **The header does not shrink:** pivotick's sidebar is a fixed-height column whose header may
  shrink, which clipped the notice list over the fold; `flex-shrink: 0` lets the column scroll.
- **Tests:** the explorer suite now loads the model and view; the old flat-property tests
  became tests of the hooks (rows per value, `undefined` for a multi-selection, the shared
  panel's scope). 694 and 75 pass.

**Checked live** on the dev instance, as `admin` with *Incident Response & Investigation*
selected, on 11 of the fixture cases in both themes: every lazy read answers 200, nothing
overflows, no page error. The foreign event leads with `tlp:white` (strictest of 2) and *No PAP
label*; the multi-selection's aggregate counts `tlp:white` 3/3. With the reads forced to 500
the failed state draws its Retry buttons, and Retry recovers.

**Open:**

- *Resolved 2026-09-29:* the neighbour graph was crowded: pivotick's ego graph copied the
  canvas's zoom tiers, so neighbours became M cards and the root its XL card, and its fit zoomed
  to 3×. pivotick `1444032` (vendored) adds `neighborsPanel.graph.{render, layout}` and a fit that
  stops at `maxZoom`; the explorer passes the plain S drawings (no tiers, no focus card, no pivot
  badges, labels kept) and `maxZoom: 1`. Checked live on the foreign event (1 neighbour) and a
  cluster (73), both themes.
- *Resolved 2026-09-29:* with nothing selected the header was empty, then read `null`; pivotick
  `b43dcd3` (vendored) lets a header `render` return `undefined` for the default count, and
  renders `null` as nothing.
- Extra panels sit below pivotick's neighbours panel, so the shared labels come after the
  neighbour graph rather than right under the aggregate.
- The event page's two `.misp-icon` stylesheets (§5.2) are unchanged; the view uses only
  `misp-simple` icons, which the mask build has.

## 6. Out of scope

- Editing from the sidebar (tags, analyst data): the existing MISP forms do that.
- Shared *values* across a multi-selection: needs a server read, a later step.
- Saving a selection or a graph as a collection: parked, scope open.
