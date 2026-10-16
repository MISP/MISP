# Pivot Explorer (Pivotick v2) — Implementation Progress

Delivery tracker for [`pivot-explorer-v16-prd.md`](pivot-explorer-v16-prd.md).
**Task definitions live in the PRD (§9); this file tracks only state.** Update it in the
same pass as the code, not in a catch-up sweep.

- **Branch:** `pivotick-v2`, off `worktree-pivotick-v16` (the v1.6.0 work)
- **Library:** Pivotick v2 — `90931b5` (`develop`, with the context-menu order commit `1eec3f0` merged back in). PRD §3.7
- **Last updated:** 2026-09-30
- **Status:** every task done — the §9 plan, the P0 sweep (12–18), 19–33, 35–44 and bundle bumps 0–0p · §3.7 answered 2026-09-23 (PRD §5 *Rulings*, P0 + R1–R8)
- **Tests:** `node tests/js/pivot-explorer-graph.test.js` — 723 assertions, no dependencies

`✅` done · `🔜` next · `⏸` blocked · `⬚` not started

---

## 1. Tasks

One commit per task, per PRD §9. `E` and `T` are prerequisites, not numbered PRD tasks;
task 1 is split into `1a`/`1b` because only one half needs the dev server.

| # | Task | Status | Depends on | Commit / note |
|---|---|---|---|---|
| 0 | Bundle to v1.6.0 + compatibility audit | ✅ | — | `e02a24710` (2026-08-28) |
| 0b | Bundle to v2 + audit; edge save onto `onBeforeEdgeCreate` + `isValidConnection` | ✅ | 0 | `3c4d1f0b1` bundle, `9ed240f92` write path (2026-09-23) — see §2 |
| 0c | Bundle to `develop` `1296966`: pivot edges to children, `UI.emptyState` | ✅ | 0b | `d7a179e9c` (2026-09-23), built from a clean export — the checkout's own `dist/` differed |
| 0d | Bundle to `develop` `f598444`: edges out of nested children, `removeBySource` in Undo | ✅ | 0c | 2026-09-24, built from a clean export; the CSS came out byte-identical. The removal notice now says Undo puts it back. See §2 |
| 0e | Bundle to `05fe810` (`worktree-collapsed-cue`, one commit on `develop` `95cc681`): the dashed collapsed cue follows `enableNodeExpansion` | ✅ | 0d, R8 | 2026-09-24, built from a clean export, not yet merged into `develop` upstream. Live on 3989: no node carries `pvt-node-expandable`, objects draw their own outline (`#8A7A73`, 1.5px) undashed; the only dashes left are the feeds' dotted provenance rings |
| 0f | Bundle to `develop` `c6f11be` + `05fe810`: `focusTierYieldsAt` | ✅ | 0e | 2026-09-24, built from a clean export of `c6f11be` with `05fe810` applied, which `develop` still lacks; the CSS came out byte-identical. Entities without their own XL design (all but events and objects) set it to 0. Live on 2014: at rest an attribute and an object both show their hover drawing; at chip zoom (`data-pvt-tier="0"`) the attribute shows none and the object still shows its XL card |
| 0g | Bundle to `develop` `c47d7fe` + `05fe810`: rim badges show only while Pivot mode is open (`pivotRimBadgeVisible`, default `'pivot-mode'`) | ✅ | 0f | 2026-09-25, built from a clean export of `c47d7fe` with `05fe810` applied, which `develop` still lacks; the CSS came out byte-identical. The explorer keeps the default. Live on 3989: at rest no `.pvt-node-badge` (the previous bundle drew 14, all pivot badges: 12 Correlations, 2 Feed events); opening Pivot mode brings the same 14 back |
| 0h | Bundle to `develop` `53b51fc` + `05fe810`: the Pivot panel offers Fetch & ingest beside Fetch | ✅ | 0g | 2026-09-25, built from a clean export of `53b51fc` with `05fe810` applied, which `develop` still lacks; the CSS changes with it (`.pvt-pivot-ingest-button`). Live on 3989: the panel shows the button (100×26) beside Fetch; scoped to a feed through its Feed events rim badge, it lands the feed's 3 events without triage (119 → 122 nodes) |
| 0i | Bundle to `develop` `790226d` + `05fe810`: a menu row declared without a `variant` defaults to `outline-primary`, so it highlights on hover | ✅ | 0h | 2026-09-25, built from a clean export of `790226d` with `05fe810` applied, which `develop` still lacks; the CSS came out byte-identical. Live on 2014: *Copy value* on an attribute carries `pvt-action-item-outline-primary` and hovers to the same `rgb(235, 46, 83)` as *Pivot* and the other built-in rows; before, it had no hover state |
| 0j | Bundle to `develop` `8db49e9` + `05fe810`: a badge is sized by its node's short side, so a wide card no longer dwarfs it | ✅ | 0i | 2026-09-25, built from a clean export of `8db49e9` with `05fe810` applied, which `develop` still lacks; the CSS came out byte-identical. Live on 780, rim badges forced on: on the 140×44 event and attribute cards a badge is 19.8 px tall, 45% of the card, down from 28 px (64%) |
| 0k | Bundle to `develop` `21c2aa9` + `05fe810`: `textMaxWidth` caps a node label at a width; S labels cut at 220 units (`S_LABEL_MAX_WIDTH`) instead of drawn in full | ✅ | 0j | 2026-09-27, built from a clean export of `21c2aa9` with `05fe810` applied; the CSS came out byte-identical. Live on 1340: widest S label 218.6 units, an md5 whole, a sha256 middle-elided; on 1810 a 22,184-character YARA rule draws 196 units wide |
| 0l | Bundle to `develop` `89a92dc`, plain `develop` at last (`05fe810` merged as `28295c8`): a narrowing facet honours `default` (`0cae434`); `Edge.clone()` keeps the provenance ledger, so `getEdges()` reports an edge's real sources | ✅ | 0k | 2026-09-28, built from a clean export of `89a92dc`; the CSS came out byte-identical. Suite 645/645. Live, admin, served bundle md5 `d0ce8038…`: on 752 *Event elements* opens with *Attribute* ticked and *Tag* not, breakdown `16 Attributes` (was `16 Attributes · 3 Tags`), a plain browse lands the 16 attributes; on 2014 after a correlations run all 79 edges read the same sources through `getEdges()` as through `getMutableEdges()`, correlation edges as `correlations`; no node carries `pvt-node-expandable`. No console error |
| 0m | Bundle to `develop` `625fe52`: graph simplification (`prd/graph-simplification.md`) — view-only groups from the neighbour, chain, few-links and k-core rules, a Simplify rail mode, groups opened in place, landing groups, groups made by hand. MISP declares no `UI.simplify`, so `full` mode offers the built-in rules switched off | ✅ | 0l | 2026-09-29, built from a clean export of `625fe52`; the CSS changed this time (238 → 249 KB), the IIFE 937 → 1,006 KB, the worker still inlined. Suite 645/645. Live, admin, bundle swapped in over HTTP (the server serves another tree): on 2014 the rail shows *Simplify* with the four rules off; the neighbour rule at size 2 folds 2 nodes into 1 group and `getNodes()` still returns all 8; on 1340 all 18 nodes draw and the rule finds nothing to fold. Only console errors are 404s on `/events/correlationCounts`, absent from the served tree |
| 0n | Bundle to `develop` `cda9895`: `pivotIngestGrouped` (every landing grouped, Review offers *Ingest loose*), `UI.tooltip.enabled` per kind or predicate, a right-click inside a selection acts on it (`menuSelection`), Del hides the selection, the header count follows the data | ✅ | 0m | 2026-09-29, built from a clean export of `cda9895`; the CSS changed (249 KB), the IIFE 1,006 → 1,011 KB. Suite 645/645. Used by the groups PRD ([`pivot-explorer-graph-simplification-prd.md`](pivot-explorer-graph-simplification-prd.md)), whose S4 carries the live check |
| 0o | Bundle to `develop` `bd5d913`: `UI.simplify.typeOf` / `colorOf` for every rule and group colour, `groupStyle(info, base)` and `GroupInfo.landing`, a portaled tooltip's header keeps a forced dark theme | ✅ | 0n | 2026-09-29, built from a clean export of `bd5d913`; the IIFE 1,011 → 1,012 KB. Suite 681/681. Closes the groups PRD's L3–L5 (live check there, S5) |
| 0p | Bundle to `1eec3f0` (branch `worktree-tooltip-enabled-per-kind`, `develop` `bd5d913` plus one commit): node, group and selection menus read *Pivot ▸*, the group entries, the rest with the app's own, the delete last; the canvas menu's *Release pinned nodes* (`prd/misp/context-menu-order.md`) | ✅ | 0o | 2026-09-29, built from a clean export of `1eec3f0`; the IIFE 1,012 KB, CSS unchanged. Suite 696/696. Live on 2014: an attribute's menu reads Pivot · Select Neighbors · Hide Children · Connect to… · Inspect Properties · Copy value · Delete Node; a group's Pivot · Open group · Select members · View members in table · Select Neighbors · Delete members; a selection's Pivot · Group selected nodes · Select Neighbors · Delete Selected |
| E | Extract inline JS out of the `.ctp` into `webroot/js/pivot-explorer.js` | ✅ | 0 | `edc6a0caa` (2026-08-31) |
| T | Graph-builder unit tests, `tests/js/pivot-explorer-graph.test.js` | ✅ | E | Not a PRD task; possible only once E made the builder loadable outside a browser |
| 1a | Refresh the stale `Edit ▸ Add edge` comment | ✅ | 0 | Comment only, nothing to verify |
| 1b | Regression pass under v2 (§8.1) | ✅ | 0b | 2026-09-23 on the dev instance — see §2. Found and fixed: the editor was never offered on view2 (`608229a2b`) |
| 2 | Tag object-reference edges with `kind`; add `edgeTypeAccessor` / `edgeStyleMap` / `edgeFacets` (one layer) | ✅ | 1 | Built ahead of the 1b gate, deliberately. Edge stroke becomes explicit blue — see §2 |
| 3 | Generalise `computeConnectivity()` to any authored relationship; analyst-relationship edges as a second layer (L1, D5′) | ✅ | 2 | Also fixed a pre-existing seeding bug — see §2 |
| 3b | L0: event node + `RelatedEvent` proxy nodes (free, already in payload) | ✅ | 2 | `7ab4f859f` (2026-08-31), shared with 3c — see §2 |
| 3c | L2: budget-capped containment-only objects + "skipped, N not shown" statement (D10, D12) | ✅ | 3, 3b | `7ab4f859f` (2026-08-31). **Changes what most events draw** — see §2 |
| 4 | D11 empty-state message | ✅ | 3c, 9 | `ace970f01`, then `aceab26ae` onto Pivotick's `UI.emptyState` — points at the element pivot, not the correlation pivot: an empty seed has no correlations to offer. See §2 |
| 5e | Count source — `GET /events/correlationCounts/{id}.json` (R1, first slice of D13) | ✅ | — | `7f0b6d041` (2026-09-23) — see §2 |
| 5f | Fetch path — `POST /events/correlatedAttributes/{id}.json` (`attribute_uuids` / `event_ids`) | ✅ | 5e | `261e06772` — pairs match 5e's counts exactly, per attribute and per event. Since 2026-09-24 it also returns each correlated event's card metadata (`events`), so a pivoted event card draws its org, counts, tags and clusters, not only its title |
| 5 | Correlations as a pivot — `appliesTo` / `summarize` from 5e / `fetch` / `maxCandidates`, no `save` (R1) | ✅ | 5e, 5f, 0c | `65b782926`; edges land since `1296966` — see §2 |
| 5d | Related-event pivot on L0 proxies + declared potential as the rim badge (R2) | ✅ | 3b, 5e, 5f, 0c | `65b782926`. Badge counts match 5e on every related event; edges land since `1296966` |
| 5b | `feed` / `server` node types + `feed-correlation` layer, incl. the `FeedHit` degraded shape (D1) | ✅ | 2 | 2026-09-23 — a hit never seeds an element; edges run source → attribute, around a library gap filed upstream. See §2. 2026-09-24: a MISP-format feed pivots onto its events (`feed-events`, `POST /feeds/manifestEvents.json`), drawn as cached-feed event cards from the held manifest. Live, admin: 1489's CIRCL OSINT Feed → 2 cards with org, tags and clusters; event 1's Threatfox → 9 (the merged count; the payload lists the feed twice), Botvrij uuid-only (no cached manifest) |
| 5c | `relationship_type` text facet as the second edge dimension (D1) | ✅ | 2 | 2026-09-23 — case-blind through the facet's `predicate`, not `matchMode: 'partial'`; since task 14 the library's `regex` facet. See §2 |
| 6 | Analyst-data badges + selection-reactive sidebar panel | ✅ | 1 | 2026-09-23 — see §2. Answers PRD §11.9: no aggregation |
| 7 | Sectioned legend | ✅ | 3, 5, 6 | `dcbf0abc3` (2026-09-23) — configuration only; the corner is the library's default, not D3's `bottom-left`. See §2 |
| 8 | `data.scope` facet + header (event identity + resolution statement) + correlated-event proxy nodes (D2c) | ✅ | 5 | `da35afec2` (2026-09-23) — declares the whole node-facet set, not `scope` alone: declaring any facet replaces derivation. Header in the card, not `UI.mainHeader`. See §2. **Header withdrawn 2026-09-25** (owner): the identity line repeated the page title and the resolution line spoke in level names; it goes with the builder's `stats` |
| 9 | "Unlinked attributes" → dock pane: search box + full list, server-paged table above a size threshold (D4); library `UI.table` as a second pane | ✅ | 1 | 2026-09-23 — built as PRD §11.7's origin-less pivot, not a bespoke pane (P0). See §2 |
| R5 | Read-only users: every persistence editor off, no editor hooks, no tray | ✅ | 0b | `5a5770d9c` (2026-09-23) — verified in the harness for both roles |
| 10 | `possibleKinds()`; `ctx.promptData` replaces the `innerHTML` picker; delete the pending ring (D2, D2b, P0) | ✅ | 1 | 2026-09-23 — see §2. Did not need 8: ownership is read off the payload, not a `scope` field. Needed the vocabulary endpoint fixed first (`e39908012`) |
| 10b | Analyst-relationship persistence (`analystData/add`) as the second write target (D2b); `edgeCreator` for `perm_analyst_data` alone (R5) | ✅ | 10 | `fc954861f` (2026-09-23) — plus deletion by creator org; the two-kind form stays declarative (P0). See §2 |
| 10c | `onBeforeDelete`: edge deletion behind a `danger` `ctx.confirm()` saying it cannot be undone, `persisted: true`; node deletion vetoed (D6, R4) | ✅ | 10 | `b2b969730` (2026-09-23) — a soft delete by the reference's uuid, which every object-reference edge now carries; correlations and analyst relationships are spared, not refused. See §2 |
| 11 | `simulation.physics: 'auto'` alongside `d3LinkDistance: 200` (D7) | ✅ | 1 | `5d44f7811` (2026-09-23) — the link distance alone had pinned physics to `'manual'`. See §2 |
| 12 | Remove what the correlation pivots brought (`removeBySource`) | ✅ | 5, 5d | 2026-09-23 — canvas menu; in Undo since 0d (the library gap is fixed upstream). See §2 |
| 13 | Full-value labels, truncated by the canvas (`textTruncate`) | ✅ | — | 2026-09-23 — only MISP's own delete confirm still bounds a name. See §2 |
| 14 | Asserts as Pivotick's `regex` facet | ✅ | 5c | 2026-09-23 — MISP's `assertsMatches` predicate deleted. See §2 |
| 15 | Correlation count as declared rim potential on attributes and objects | ✅ | 5, 5d | 2026-09-23 — one `declarePotential` for both pivots, on the counts and on every `nodeAdd`. See §2 |
| 16 | Drop `compact()` if dead | ✅ | 8 | 2026-09-23 — dead: the crash it guarded is gone upstream (`4d71efb`). See §2 |
| 17 | Declared sidebar properties; the analyst panel's title counts the selection | ✅ | 6 | 2026-09-23 — the lifecycle half was moot: `UI.extraPanels` is already the library's reactive panel. See §2 |
| 19 | Analyst relationships: distribution, sharing group, authors | ✅ | 10b | 2026-09-24 — requested after the sweep. A second form when both kinds are possible. See §2 |
| 18 | Node context menu: open in MISP, copy value | ✅ | — | 2026-09-23 — three entries after the library's; *Pivot ▸* needed nothing. See §2 |
| 20 | R7: correlated events off the canvas; an event node is an analyst relationship's endpoint | ✅ | 3b, 5d | 2026-09-24 — withdraws 3b's proxies and 5d. See §2 |
| 21 | Events, objects and attributes draw the `prd/pivot-node-designs` set (`misp-pivot-nodes.js`): S at rest, M chip by zoom tier, XL on focus | ✅ | — | `76b613a40` (2026-09-24), with the `95cc681` bundle (`5c4de0731`, svgIcon keeps `dominant-baseline`) and the harness loading the module (`5d5568aba`) |
| 22 | Object nodes lead with their template's ui-priority attribute | ✅ | 21 | `58d4ed7e5` (2026-09-24) |
| 23 | R8: no node can be expanded; the collapsed cue follows `enableNodeExpansion` | ✅ | 21 | `41f14c00e`, bundle 0e (2026-09-24) |
| 24 | A feed draws as the event family's authority card, in its own amber hue | ✅ | 21, 5b | `41c4d0944`, `2ac3ed2e7` (2026-09-24) |
| 25 | Quieter chrome: sidebar starts collapsed, no Pivotick tooltip, no hover drawing on a chip-only node once chips show (`focusTierYieldsAt`) | ✅ | 21, 0f | `c7d08a85a`, `c580de81e`, `cbb44d760` (2026-09-24) |
| 26 | Layout spaced for a 45-unit footprint; the chip tier engages at zoom 0.8 and labels show from 8 px | ✅ | 21 | `bb99c7d37` (2026-09-24), `c02d7c41f` (2026-09-25) — live on 2014: labels from zoom 0.67, chips from 0.81 |
| 27 | Event cards: a correlated event draws its org, counts, tags and clusters (5f returns `events`); the chip is teal, title full width, size instead of threat level | ✅ | 21, 5f | `0b631d133`, `f2e12b917`, `609307444` (2026-09-24) |
| 28 | A MISP-format feed pivots onto its events (`feed-events`), from its cached manifest | ✅ | 5b | `d9f293c84` (2026-09-24) |
| 29 | Header withdrawn (owner): identity line and resolution statement removed, with the builder's `stats` | ✅ | 8 | `c1905d9c5` (2026-09-25) — a skipped L2 is now said only by the empty state and the element pivot |
| 30 | Tags and galaxy clusters: attributes and events carry `tags` / `clusters` (a cluster keyed by its tag), shown in the sidebar and as a `se` tag badge on attributes; a **Tags & clusters** pivot brings one node per tag or cluster, joined to every carrier on the canvas (an object through its attributes), as the `tag` edge kind | ✅ | 21 | 2026-09-25 — live on 2014 (1 tag, badge, 1 edge) and 4242 (4 tags + 4 ATT&CK clusters, 280 edges over 35 objects). Reaching other events from a tag is the next pass |
| 31 | From a tag or cluster node: **Events with this tag** (`POST /events/taggedEvents/{id}.json`, newest 200 by `timestamp`, all of them or any, each card saying per tag whether the event or one of its attributes carries it) and **Related clusters** (`GET /galaxy_clusters/relatedClusters/{id}.json`, outbound, targets resolved by id), as the `cluster-relation` edge kind | ✅ | 30 | 2026-09-25, [`pivot-explorer-tag-pivots-prd.md`](pivot-explorer-tag-pivots-prd.md) §7 — live on 4242 (4 ATT&CK clusters → 21 events, 84 `via attribute` edges) and 1525 (APT28 → 4 `similar` clusters, one merged). `tlp:white` 0.36 s, the heaviest attribute tag 2.2 s. The summary says at most 200 until the library can state a larger total |
| 32 | **Correlations** on a selection holding more than one correlating attribute offers an *Attribute* multiselect, each option its own count, so one attribute of a closed object can be asked for alone. The total follows the picks; with none ticked every attribute is asked for, counted or not | ✅ | 5 | 2026-09-25 — live on 1562: the passive-dns object's two `rdata` attributes are listed with 1 each, and ticking one takes the total from 2 to 1 |
| 33 | Warninglist hits: an attribute carries its `warnings` (the payload already asks for them), in MISP's field names; the M card draws MISP's triangle in its free top-right corner (red for a false positive, orange for a known identifier); the sidebar lists them; the filter has *On a warninglist* | ✅ | 30 | 2026-09-25 — live on 4074: `8.8.8.8` wears the red triangle, titled `Likely false positive — List of known IPv4 public DNS resolvers`. The look is the one CHANNELS.md already set, moved from the rim into the card |
| 34 | Another event's contents: **Event contents** | withdrawn | 33 | 2026-09-27, replaced by task 36: a correlation lands in its object, and *Around this object* goes further. The pivot read `/events/view/{id}.json` and landed what the canvas lacked inside the card |
| 35 | One-click pivots (a context-menu row, a single-pivot rim badge) land up to 25 new candidates without Review (`pivotQuickIngestLimit`); more go to Review. The Pivot panel keeps Fetch and Fetch & ingest | ✅ | 5 | 2026-09-27 — live on 1562: one-click Correlations on the passive-dns object lands directly (36 → 38 nodes), nothing staged |
| 36 | A correlation lands in its object (closed, with its live attributes) or free, beside its event's empty card, joined by the `in-event` edge kind; *Around this object*, on another event's object, lands the objects one reference away in its event (`GET /objects/surroundings/{uuid}.json`) | ✅ | 5, 35 | 2026-09-27, [`pivot-explorer-correlated-object-prd.md`](pivot-explorer-correlated-object-prd.md) §9 — live on 752: 4 objects, 6 free attributes, one card for 1052, 10 `in-event` edges; *Around this object* on 2473 lands 2 reports and 2 references, undone cleanly |
| 37 | Another event's card: **Its attributes**, **Its IDS indicators**, **Its network indicators** (`POST /events/cardElements/{id}.json`, counted in landing units, leaving out what is drawn) and **More correlations with this event**, each landing in its object with an `in-event` edge | ✅ | 36 | 2026-09-27, [`pivot-explorer-event-expansions-prd.md`](pivot-explorer-event-expansions-prd.md) §10 — live on 752→1052: IDS 120 then 0, network 37, more correlations 9 then 0 |
| 38 | Legend quick filter **Provenance**: *This event* (its card, its attributes and objects, and the tag and cluster nodes it carries on itself or a live attribute) and *Elsewhere* (other events, their elements, feeds and servers, tags only they carry) | ✅ | 30 | 2026-09-27 — live on 752 with 1052's correlations and tags landed: 19 / 30; *Elsewhere* off keeps the 16 attributes and 3 tags |
| 39 | **Event elements** offers the event's tags and galaxy clusters (on itself or a live attribute): *Element* is a multiselect, attributes and objects by default (`default`, drawn once pivotick ships [`prd/pivot-facet-default.md`]); a tag lands alone, or joined to a drawn carrier | ✅ | 9, 38 | 2026-09-28 — live on 752: a plain browse lands the 16 attributes; *Tags* lands 3, `tlp:white` alone and 2 joined to their attribute; `tlp:white` offers *Events with this tag*. Since bundle 0l the boxes read *Attribute* ticked, *Tag* not, and the breakdown `16 Attributes` |
| 40 | **Correlations** from any drawn attribute or object: another event's elements are counted as they land (one `POST /events/correlationCounts/{id}.json` per landing, `attribute_uuids`), wear their count on the rim, and pivot like this event's own; an object by its drawn children. What correlates back into this event is left out, and a pair already drawn the other way is not drawn again | ✅ | 36 | 2026-09-29 — live on 2014: from `1.1.1.1`, 7 other events' copies each wear *8*; Correlations from event 16's lands 8 edges (9 → 17), no reverse duplicate, undone cleanly. The committed build offered nothing on them |
| 41 | Analyst relationships reaching another event's attribute or object, in either direction: `RelationshipInbound` in the bulk analyst-data path and kept at event level by the JSON converter; the far end lands free and closed beside its event's card (`in-event`). The event is fetched with `includeServerCorrelations:1`, so the `server-correlation` layer fills for whoever MISP lets see it | ✅ | 5b, 36 | 2026-09-29 — live on 4345, 1, 4182, 4074 (§2) |
| 42 | A server draws as the feed does, not as a triangle: the event family's remote hit at rest (server mark in the hexagon, dashed ring) and the authority chip zoomed in (server mark, name, provider or host), in its own magenta family (`#D0539F`), which its `server-correlation` edges and legend row share | ✅ | 24, 41 | 2026-09-30 — `misp-pivot-nodes` gains a `server` palette family and entity (feed and server built by one `sourceEntity`). Live on 4345 (§2) |
| 43 | A feed's edges (`feed-correlation`, `feed-event`) take the feed's amber (`palette().feed.core`); the canvas fills the window below its top, down to its card's edge, refitted on resize, never under 480 px (was 72vh) | ✅ | 42 | 2026-09-30 — live on 4345 and 2014 (§2) |
| 44 | A stand-in edge into a closed object's child dashes like the edges it stands for (`6, 4`), not pivotick's `3`: one rule in `pivot-explorer.css` at the library's own specificity, so its forecast dash still wins | ✅ | 43 | 2026-09-30 — live on 2014 and 4345 (§2). Interim: showing *lands on a hidden child* some other way is not decided |
| 45 | **Tags & clusters** declares no rim potential: a carrier no longer wears its tag and cluster count on the canvas; the pivot still applies to it | ✅ | 30 | 2026-09-30 |
| 46 | L2 draws only an object a feed or server hits; an object nothing links (no reference, relationship or hit) is left to *Event elements*, and the empty state names hits among the links | ✅ | 3c, 28 | 2026-09-30 — live on 4466: the 81 `http-request` objects (the kit's admin endpoints, no reference, correlation or hit) leave the canvas and are the 81 objects *Event elements* offers; 108 objects stay, each with its feed edge |
| 47 | L2 also draws an event-level attribute a feed or server hits, one node each against the budget, as it draws an object a hit reaches (D10 amended) | ✅ | 46 | 2026-09-30 — live on 4345: `secure-pay.com`, `backup-service.local`, `secure-book.com` and `update-software-service.com` join the canvas on their server hit alone; 2014's `1.1.1.1` unchanged (a reference already drew it) |

### Critical path

```
0 ✅ ─ E ✅ ─ T ✅
         └──── 1b ✅ ─┬─ 2 ✅ ─┬─ 3 ✅ ─┬─ 3c ✅ ─ 5 ✅ ─ 8 ✅
                       │        │        │  5e ✅ 5f ✅ ┘
                       │        ├─ 3b ✅ ── 5d ✅
                       │        ├─ 5b ✅
                       │        └─ 5c ✅
                       ├─ 6 ✅ ─────── 7 ✅
                       ├─ 9 ✅ ── 4 ✅
                       ├─ 10 ✅ ─┬─ 10b ✅
                       │         └─ 10c ✅
                       └─ 11 ✅
```

Every task is done. Task 4 moved off the correlation chain
onto 9 (see §2), and 10 off 8.

---

## 2. Verification ledger

What has actually been checked, and how. Manual test-plan items are PRD §8.

| Scope | Verified | Method | Still owed |
|---|---|---|---|
| v1.6.0 bundle (task 0) | ✅ | `node --check`; `window.Pivotick` footer present; byte-identical (md5 `140ead0d…`) to a fresh `vite build` of the `v1.6.0` tag | Browser regression = §8.1 |
| Extraction (E) — PHP side | ✅ | Stub-harness render, 3 cases: `data-pe-*` populate, `"` in `$baseurl` escapes to `&quot;`, no `<script>` left, `<style>` still gated on `$canEdit`; `php -l` clean | — |
| Extraction (E) — JS side | ✅ | `node --check`; no PHP tags remain; `diff` proves the 745 logic lines byte-identical; stubbed-DOM harness **24/24** (boot timing, lazy tab activation, `_initialized` guard, URL assembly, error-as-text, `canEdit` gating) | **Browser check — folded into §8.1** |
| Graph builder — connectivity, nesting, tombstones, edge dedupe, `compact()`, truncation, image detection, tray/canvas invariant | ✅ | `tests/js/pivot-explorer-graph.test.js`, zero-dependency plain node — 27 cases when this row was written, 48 now | Nothing — this layer no longer needs the server |
| Task 2 — `kind` tagging, `edgeTypeAccessor`, `edgeStyleMap`, `edgeFacets` | ✅ data + config | Same suite: every edge tagged, accessor resolves it, and the invariant that each emitted kind is a styled kind | **The grey→blue stroke change is visual — §8.1** |
| Task 3 — generalised seeding, analyst-relationship layer | ✅ data + config | Same suite: D5′ seeding from a relationship alone, target-type gating, tombstones on both kinds, provenance on the edge, skip cases | **Dashed-orange rendering of the new layer — §8.1** |
| Task 3b — L0 nodes, `event-correlation` edges, `Event` as a relationship target | ✅ data + config | Same suite: proxy per `RelatedEvent`, dedupe, no self-proxy, the edge-gate on the event node, `Event`-typed analyst targets resolving to both the event and its neighbours, label/description/`event_id` shape, and `onNodeDbclick` navigating only for a foreign `event` node | **The green hexagons and dashed-green edges are visual — §8.1**; §8.7's double-click check |
| Task 3c — the budget, L2 clusters, the resolution statement | ✅ data + config | Same suite: the boundary (1,500 fits, 1,501 skips whole), cost counted with children and without tombstones, L2 never seeding a bare attribute, the tray losing exactly the objects L2 drew, and the statement's own text in eight states | **How the statement reads in the card — §8.1**; the `hideDisconnected` collision (§7) is still unexercised |
| v2 bundle + write path (task 0b) | ✅ | Clean `npm run build` of `d220446`, `node --check`, md5 `1183ba8c…`; every option/call `pivot-explorer.js` makes checked against `dist/types`; suite 170/170; **headless Chromium harness** — real bundle + real `pivot-explorer.js`, stubbed `fetch`, hand-built fixture (L0 pair, one reference, one L2 object, one tray attribute): renders with no console error, L0+L1+L2 seeded, both edge colours, tray drop pinned + pending, four edge gestures each checked for picker / POST / edge / history | §8.1 on the real instance with events 1195 and 4116 |
| Count endpoint (task 5e) | ✅ model + aggregation | `php -l` on every file; `CorrelationCountToolTest` 3/3 under the container's PHPUnit; the method body run from a check shell against the live models for two users × two events — counts, timings, sizes, the 404, and agreement with `RelatedEvent` (graph-endpoint PRD §7) | **The HTTP route itself** — JSON extension, ACL entry, 404 — needs the dev server on this branch |
| Real instance, v2 (task 1b) | ✅ | Playwright, logged in, dev server on `pivotick-v2`. `correlationCounts` over HTTP: admin 1195 → 350 / 18 events, 4116 → 708 / 78; org 9 admin 1195 → 346 / 15, 4116 → 404 — identical to the check shell. Pivot Explorer: 1195 opens in 4.7 s, layout settles in ~17 s (4,743 top-level nodes, 2,362 references); 4116 opens in 21 s (L0 only, 90 nodes — the D13 payload); 2014 in 0.4 s. No console error from the explorer. Edit rights: admin → editor, plain org-1 User on an org-9 event → read-only. A drawn reference on 2014 POSTs 200, lands as `object-reference`, records `persisted: true`, survives a reload — then deleted (`objectReferences/delete/11378/1`) | Glyphs: see below |
| Drawn edges (task 10) | ✅ | Suite 225/225 (9 new: editor gating per role, the ownership gate on both ends, refusal before any form, vocabulary sorted/defaulted/fetched once, the POST and the persisted decision, custom beats list, blank and cancel save nothing, a refused save, the free-text fallback retrying); 7 targeted mutants, 7 caught. Live, admin, event 2014, through Pivotick's click-connect: the form is Pivotick's themed modal with 262 relationships defaulting to `related-to`, the `<script>` row rendered as text (no `<script>` element in the modal); a list choice and a typed one both POST, land as `object-reference` with the typed label, no console error — references 11379/11380, then hard-deleted | The perm-only analyst kind is 10b |
| Element pivot (task 9) | ✅ | Suite 250/250 (6 new cases: shape, what is offered, search scope, narrowing and summary = fetch, the form's facets and counts, cache invalidation; the tray tests now read the pivot's offer, and the invariant holds against it); 13 targeted mutants, 13 caught. Live, admin, through `graph.pivots` and the real panel/Review tab: 2014 offers its 1 unlinked attribute, ingest puts it on the canvas (29 → 30) and the offer drops to 0, undo takes both back. 4116 offers 28,410 objects (every attribute is inside one); unnarrowed the run is **refused on the cap** (28,410 > 1,500); `80.66.83.162` finds 5 in 197 ms on the first search (search text built then), stages in 70 ms, ingests 5, undo restores. No console error | A read-only user was not driven live — the pivot is declared regardless of edit rights, which the suite checks |
| Analyst data (task 6) | ✅ | Suite 279/279 (7 new cases: count with replies and without relationships, mood from the element's own opinions, the four band edges, no fields or badge without data, no roll-up onto an object, the panel only where there is data, its entries as text with replies indented, the empty and multi-selection states, the badge click); 13 targeted mutants, 13 caught — three only after the fixture gained a relationship, a 55 and a 0-valued reply, one more after the band edges were added. Live, admin: 3838's object wears one `nw` badge, *1 note or opinion — disputed*, interactive; clicking it shows the panel with *Strongly disagree (10/100) · ORGNAME_6879 · 2026-07-14 · Clearly a FP*. 16's two noted URLs are event-level and unlinked, so not drawn; ingesting `circl.lu` through the element pivot brings one with a *3* badge and three notes in the panel. 2014 (no analyst data) has no panel and no `nw` badge. No console error | Notes on the event node were not seen live — no event with an event-level note also has a related event |
| Empty canvas (task 4) | ✅ | Now Pivotick's `UI.emptyState` card, MISP supplying the words. Suite 294/294 (6 cases: the statement and its counts without tombstones, the action, the over-budget case beside the resolution line, a bare event with no action, the emptied-by-hand wording from `initial: false`, text not markup; showing and hiding is the library's and tested there); 8 targeted mutants, 8 caught. Live, admin: 184 opens on the library's card — *Nothing in this event is related yet … Its 1 attribute is listed under Event elements* — the button opens the Pivot panel, ingesting removes the card (0 → 1 node), undo brings it back saying *The canvas is empty*; 2014 shows none. No console error | — |
| Pivots (tasks 5, 5d, 5f) | ✅ | Suite 192/192 (8 new: declaration, cap, no `save`, `appliesTo` before/after counts, never this event, fetch bodies, container shape, stable edge ids, this event's side brought along). Live, admin, via `graph.pivots`: `correlatedAttributes` pairs = counts on 1195 (350), 4116 (708), one attribute, one event, and for the org 9 admin (346); Pivot rail button present; `related-event` potential on 23/23 related events of 2014 and 78/89 of 4116 (the other 11 have no count), each equal to 5e; a related-event run ingests its attributes into the proxy (2014: 4, 4116: 33) and undo takes them back | **Edges, re-run on `1296966`:** every pair lands, both ends on canvas, undo clean — 2014 related-event 1 → 1; 4116 related-event × 5 events 29 → 29 (this event's side arriving as top-level nodes, L2 being skipped); 1195 correlations × 20 origins 57 → 57. No console error |
| Provenance, facets, header (task 8) | ✅ | Suite 321/321 (11 new cases: provenance on every seeded kind, an extension-event element known by id alone, a record with no `event_id`, pivot results on both sides, the element pivot's nodes and children, the declared facet set and Provenance's worded options, options read off the live graph, the identity line and its tooltip as text, a sparse identity, the correlation clause arriving with the counts and absent at zero); 13 targeted mutants, 13 caught. Live, admin: 2014's header reads *Event 2014 · Test · ADMIN · 2025-11-16* over *Seeded L0+L1+L2 · 41 nodes · 35 correlations available*; 23 proxies `foreign`, the event and its 17 elements `self`; a related-event run brings an attribute in as `foreign` with that event's id and uuid; the filter panel shows exactly the seven declared facets, Provenance offering *This event* / *Other events*; filtering to `self` leaves 6 visible top-level nodes, to `foreign` 23, reset restores all. 4116: *Seeded L0 · 90 nodes · L2 skipped (28410 objects not shown) · 708 correlations available* — 708 equal to 5e; same filter behaviour (6 / 89). No console error | Extension events were not seen live: the explorer fetches the event without `extended:1`, so today every payload element is `self` |
| Sectioned legend (task 7) | ✅ | Suite 326/326 (1 new case: two sections, Element on `nodeTypeAccessor` with no key, Relationship on edges by `kind`, the same key as the layer facet, no provenance section); 4 targeted mutants, 4 caught. Live, admin, 2014: one card in the right column above the minimap — *Element*: event 24 · attribute 1 · object 4; *Relationship*: event-correlation 23 (dashed green line swatch) · object-reference 2 (solid blue). Clicking *event-correlation* hides those 23 edges by setting `edge:kind` = `[object-reference]` — the panel's own layer filter — and leaves the nodes; clicking again clears it. No console error | Found a library defect: four icons in `icons.ts` carry mangled SVG, which puts `< path d = … />` text into the section headers' `textContent` — invisible, filed as `pivotick/prd/misp/mangled-inline-icons.md` |
| Deletion (task 10c) | ✅ | Suite 351/351 (9 new cases: the uuid on seeded and drawn edges, the node veto and its notice, the danger confirm's title/label/body, the soft-delete POST by uuid, cancel, narrowing to what MISP deleted with its message on the refusal, all-refused vetoing, spared correlation / analyst / uuid-less edges, notes alone, no hook for a read-only viewer); 14 targeted mutants, 14 caught. Live, admin, 2014, through `graph.editing.requestDelete` and the real modal: a throwaway reference sent as `saveReference` sends it returns its uuid, and after a reload the edge carries it; a node delete is vetoed with *Elements are not deleted here*; the edge's confirm is Pivotick's modal — *This deletes the relationship in MISP: domain-ip → pe-10c-probe → geolocation. It cannot be undone from the graph.* — with a red *Delete in MISP*; confirming removes the edge (26 → 25), the history row is `sealed`/`persisted` and undo passes over it; MISP holds the reference as `deleted: true`. Then hard-deleted. No console error from the explorer | The bulk-action and context-menu buttons were not clicked — both route through `requestDelete`, which was |
| Analyst relationships (task 10b) | ✅ | Suite 386/386 (9 new cases: the uuid on seeded analyst edges; analyst rights alone give back edge tool, delete and hooks; which pairs are valid — across events, from and to event nodes, never to itself, a type MISP cannot name or a uuid-less node; the link-type question only with two kinds, defaulting to the reference; the POST addressed by MISP type and the edge landing with MISP's uuid/orgc/authors; the chosen kind deciding the write, an unoffered one falling back; a refused save; deletion by creator org, site admin, and neither role deleting the other's kind; a mixed selection split across both endpoints); 26 targeted mutants, 26 caught. Live, through Pivotick's click-connect and the real modals: **admin, 2014** — object → object offers *Link type* (Object reference / Analyst relationship), choosing the analyst kind POSTs `analystData/add/Relationship/{uuid}/Object.json` and the edge carries MISP's uuid, org and author; attribute → related-event proxy asks no link type and saves `related_object_type: Event`; both deleted behind the confirm, sealed, view 200 → 404. **orgadmin, org 9's 803** (analyst, cannot edit the event) — card `can-edit 0 / can-analyst 1`, edge tool and delete present, object → object asks no link type, saves under the user's org, deletes. **user, 803** (no analyst permission) — no editor, no hooks. No console error from the explorer. Probe relationships, their blocklist rows and orgadmin's temporary `ui_theme` row removed after | Another org's relationship being spared was not seen live — no event with a foreign-org relationship was at hand; the suite covers it |
| Physics (task 11) | ✅ | Suite 352/352 (1 new case: both options passed). Live, admin, via `graph.simulation`: auto is on for both events. 2014 (29 top-level nodes): auto's pass lands inside its deadband and is skipped, so the opening layout is today's, at rest on open. 1195 (4,743): auto re-tunes — repulsion 25, link distance 184, friction 62 — and is near rest (alpha 0.01) 7–10 s after the tab opens, an even disc with the related events at the centre. No console error | Timings were taken under load ~2.5 on a shared machine, so they are not compared with 1b's ~17 s settle |
| Asserts facet (task 5c) | ✅ | Suite 394/394 (2 new cases: the facet's declaration and its case-blind substring predicate, `relationship_type` on every authored edge including the `related-to` default, none on derived edges; four pinned decisions and the facet list updated); 10 targeted mutants, 10 caught. Live, admin, through the real filter panel (*Asserts* box, `Shift+K`): 1215 — `contain` keeps the 3 `contains` and 1 `contained-within`, pill *21 edges hidden*, 4 edge groups drawn; `-BY` keeps the lone `downloaded-by`. 1086 — `by` finds `Characterized_By` (1 of 70). 2014 — `relat` keeps both references and hides the 23 correlations; `geo` hides all 25. 1195 — `-with` keeps all 2,362 `analysed-with`. Reset restores every edge each time. No console error | The panel applies typed text on a debounce: a reading taken ~1.5 s after typing caught a stale count (24) |
| Feed and server sources (task 5b) | ✅ | Suite 431/431 (10 new cases: one node per feed joined to drawn attributes, event-level and children; the node reading the event's record not the attribute's copy; the source list read by id whether a list or keyed; a hit never seeding an element, and stated; a feed seen only off-canvas drawing no node; deleted attributes; the degraded badge, its corner beside the analyst one, and the total; a server with only id and name; a feed and a server sharing an id; styles, glyphs, provenance; no pivot, no drawn edge and no deletion reaching a source); 20 targeted mutants, 20 caught — two only after the fixes below. Live, admin: **2014** — CIRCL OSINT (19 feed events), Threatfox (3), Botvrij (1) as triangles, 9 feed edges, exactly the payload's; legend *feed 3* / *feed-correlation 9*. Expanding an object with four hits swaps its 3 stand-ins (one per feed) for the 4 real edges. **1086** — 270 drawn + *69 feed hits on elements not shown* = the payload's 339. **1195** — degraded (`FeedCount` 16,246): no source node, *16246 feed hits, too many to name their feeds*; expanding an object draws an `sw` badge on each of its 3 flagged attributes with the tooltip. No console error | Found live, fixed before commit: `event.Feed` arrives as a list, so indexing by key named every feed after its neighbour; and edges out of a collapsed child never draw (PRD §7), which the source → attribute direction avoids. Analyst relationships from a child attribute are still hidden by that gap — upstream |
| Asserts as a regex facet (task 14) | ✅ | Suite 428/428 (the 5c case now pins the declaration — `type: 'regex'`, no predicate — and drops the four assertions on MISP's matcher, whose behaviour is the library's to test). Live, admin, through the real *Asserts* box: every 5c reading repeats — 1215 `contain` keeps 3 `contains` + 1 `contained-within`, `-BY` the lone `downloaded-by`; 1086 `by` finds `Characterized_By`; 2014 `relat` keeps both references and hides the 23 correlations. New with the pattern: `^contain` keeps the same four; `(` is refused by the panel and hides nothing. Reset restores every edge. No console error | — |
| Full-value labels (task 13) | ✅ | Suite 431/431 (the 42-character case becomes *a label is the whole value* for attribute, object, event and related event, with the canvas left its default `textTruncate`; a new case pins the delete confirm bounding an 80-character name itself); 2 targeted mutants, 2 caught. Live, admin: **1215** — 31 nodes carry labels over 42 characters, the longest 128; at zoom the canvas draws the related event's 115-character title as `OSINT - Malwa….v1`, the sidebar clamps it to two lines with an ellipsis, and Properties shows it whole. **489** — the element pivot's Review tab lists a 2,514-character YARA rule as `rule APT30_Generic_H { meta: de…`, clipped like the Value column beside it. No console error | The library's middle ellipsis keeps a title's tail (`….v1`), where the old cut kept only its head — its call, not ours |
| `compact()` removed (task 16) | ✅ | **Why it was dead:** it guarded the filter's auto-derivation calling `.length` on a null; since Pivotick `4d71efb` that derivation, the table's columns and the Review tab's all go through `collectDataAttributes`, which skips null and undefined — and MISP declares its node facets anyway. **Live, before removing it:** the real page served a copy with `compact()` and the edge null-dropping disabled; on 1215 (8 nodes carrying `object_relation: null`), 3838 (2) and 2014 (1) the filter panel and a facet, the table, the sidebar and tooltip on a null-carrying node, the search box and the element pivot's Review tab ran with no error, and the sidebar listed the same fields as the served build — nulls are not shown. **After:** the same sweep on the served build, same result. Suite 429/429: the eight assertions that pinned *key absent* now pin the value as the payload has it (`null`), or a falsy one where a badge or style reads it | No live event carries a null analyst-relationship author or org, so null edge fields were exercised only by the suite |
| Correlation potential (task 15) | ✅ | Suite 439/439 (2 new cases: every counted element declares — an object its own count, a child attribute its own, a related event as R2, never this event, nothing at zero, one render; and an element landing later declares on arrival while a correlated attribute from elsewhere declares nothing). The stub graph gained live nodes carrying potential: until now R2's declaration ran against a stub whose nodes had no `getData`, threw inside the counts' `catch`, and went untested. 4 targeted mutants, 4 caught. Live, admin, each declaration checked against `correlationCounts`: **2014** — 6 elements declare (4 attributes, 2 objects), 0 mismatches, 3 correlation badges drawn beside the 23 related-event ones; clicking one opens Pivot mode on it, *Correlations ~9*. **1215** — 1 and 6. **1195** — 262 elements declare (the rest of the 400 counted are not drawn), 0 mismatches, 88 badges drawn; a related-event run lands 113 nodes, 35 of them this event's own counted attributes, each wearing its count. No console error | The rim is busier on a correlation-heavy event (1195: 88 + 18 badges at the opening zoom) — the library's per-pivot shape, one badge per node here |
| Sidebar properties and panel title (task 17) | ✅ | **Scoped down on reading the library:** the analyst panel already runs on Pivotick's panel lifecycle — `UI.extraPanels` panels are selection-reactive by default, so `addPanel({ reactive })` would change nothing. What was custom-by-omission was the Properties panel, which listed every data key under its own name (`attr-type`, `scope`, `event_uuid`, `analyst_mood`, `imageUrl` …). Suite 451/451 (4 new cases: an attribute's fields event-level and as a child, blanks left out, a foreign one by event id; object, event, feed, a name-only server and an unknown type; an edge by kind name, every derived kind named; the title with and without a count, and for nothing or a multi-selection). 4 targeted mutants, 4 caught. Live, admin: **3838** — an attribute's Properties read *Value 194.78.89.250 · Type ip-src · Category Payload delivery · IDS flag Yes · Comment … · Event This event · UUID …* (7 fields); the noted object's panel is titled *Notes & opinions (1)*; a reference edge shows 3 fields. **2014** — attribute 6, object 4, event 5, feed 5, edge 3 fields, as declared. No console error | The panel's own entries keep their inline styling: Pivotick has no notes-list widget to hand them to |
| Node context menu (task 18) | ✅ | Suite 464/464 (5 new cases: the three entries and their order, no topbar and no other scope touched; *Open its event* for a related event and for a foreign attribute or object, never this event, a source, nothing or a multi-selection, opening `view2` in a new tab without an opener; *Browse feed* on feeds only, to `previewIndex`; *Copy value* only where there is a value, copying it whole with a shortened notice; a refused and an absent clipboard each saying so). The sandbox gained `window.open` and a configurable `navigator`. 4 targeted mutants, 4 caught. Live, admin, 2014, by right-click on the real nodes: a related event's menu lists *Pivot ▸* then the library's entries, then *Open its event*, which opens `/events/view2/4454` in a new tab and leaves the explorer on 2014; *Pivot ▸* offers *Correlations with this event ~1* and *Open pivot panel…*, and its row lands the correlated attribute (44 → 45) as a *Correlations with this event* history row; a feed's menu ends in *Browse feed*, opening `/feeds/previewIndex/1` (*Feeds - MISP*); an attribute's *Copy value* puts `1.1.1.1` on the clipboard, with its notice. No console error | A read-only viewer was not driven live; none of the three is gated, which the suite checks by declaration |
| Removing fetched correlations (task 12) | ✅ | **Probed first:** on 2014 a related-event run lands 6 nodes and 6 edges and `removeBySource('related-event')` takes exactly those, but records no history row — the run's row stays, the next Undo does nothing visible and Redo re-lands the run. The docs say otherwise; filed as `pivotick/prd/misp/remove-by-source-history.md`. Suite 473/473 (2 new cases: offered only once a correlation pivot has brought something; both pivots removed through the library, an element the element pivot also vouches for kept, the seed untouched, the notice's counts and its *not in Undo*, nothing offered after). The stub graph gained provenance on nodes and edges and the library's removal rule. 3 targeted mutants, 3 caught. Live, admin, 2014, by right-click on empty canvas: before any run the canvas menu has no entry; after a related-event run, a correlations run and an element-pivot ingest (44 → 58 nodes, 13 correlation links) it offers *Remove fetched correlations*; clicking it removes 13 elements and 13 links, back to 45 — the seed and the ingested element — with *13 elements and 13 links off the canvas. This is not in Undo; Pivot fetches them again.*; the entry is gone after. No console error | — (closed 2026-09-28: `a5ebbfc` records the removal; see bundle `f598444`) |
| Bundle `f598444` (0d) | ✅ | Built from `git archive f598444`, not the checkout's `dist/`; the bundle carries `a5ebbfc`'s history row (`Nothing left the canvas`) where `1296966` does not. Tier probe on it: a card tier over an `svgIcon` base draws the card with no `null` (7/7 nodes, hover card 280×150). Suite 489/489 with the notice reworded. **Live, admin, served bundle checked to be `f598444`:** on 2014, a related-event run and a correlations run (44 → 57 nodes, 13 correlation links), then *Remove fetched correlations* → 44, the notice ending *Undo puts them back.*; the history gains two `removal` rows, one per pivot, so one Undo restores the related-event half (50 nodes, 6 links) and a second the rest; Redo takes them off again. On 3989, analyst relationship 133 (`similar-to`, from an attribute inside object `c693e9af…` to event 4182) is drawn from the object while it is closed and from the attribute once it is open; the same page on the `1296966` bundle draws it in neither state. No console error | — (closed 2026-09-28: task 20 left one correlation pivot, so *Remove fetched correlations* is one `removeBySource` call, one `removal` row, one Undo — `pivot-explorer.js` `removeFetchedCorrelations()`) |
| Analyst sharing (task 19) | ✅ | `php -l` on the element. Suite 489/489 (5 new cases: the levels, groups, default and author placeholder offered; no group field without groups; with two kinds a reference asks once and saves no sharing while the analyst kind asks a second form, saves as answered with authors trimmed, and cancelling it saves nothing; level 4 refused without a group before any POST and with a warning, a group dropped at any other level; unreadable options falling back to level 1 and saying so) and two updated 10b cases; 5 targeted mutants, 5 caught. Live, admin, 2014, through the real modals: the card carries the five levels, 11 sharing groups by name, default 1 and the admin's email; object → object asks *Link type* first (*Next*), then *Share the relationship* — distribution 4, group 3, author `probe@admin.test` are what MISP saved; level 4 without a group posts nothing and warns *No sharing group*; attribute → related event asks all of it in one form, and MISP saved level 0 with the author left to it (`admin@admin.test`). Probes deleted, their blocklist rows removed. No console error | Another org's user was not driven live — its sharing groups differ, which the element computes per user |
| Suite harness | ✅ | Since `76b613a40` every case threw — the module stops at its lib-missing guard without `window.MispPivotNodes`. The harness now loads the real `misp-pivot-nodes.js` (plus `insertBefore`/`head` on the DOM stub); three expectations followed the node designs it shipped (icon inside the style entry, Element legend entries declared, event hue). 488/488 before task 20 | — |
| Correlated events off the canvas (task 20, R7) | ✅ | Suite 490/490: the L0 block rewritten as event-node cases — `RelatedEvent` draws nothing; another event labelled from its attached record, foreign, a leaf; this event drawn for a relationship into it or out of it (`Event.Relationship`); an invisible or mismatched `related_object` counted not drawable; one event drawn and charged once for two relationships; no uuid, no endpoint; double-click unchanged. One pivot left, removal through it alone, the statement's `with N events`, singular included. Live, admin, dev server on this worktree, capturing the options handed to Pivotick: 3989 draws 4182 once, joined by its `similar-to` edge, legend *event 1* and no event-correlation row; 4182 draws itself for its attribute's `related-to`, its two undrawable ones checked in the DB (a GalaxyCluster; an attribute of 4074); 1545's event→event target does not exist here, counted; 4116 opens on the empty card, *708 correlations with 78 events available*. No console error | A lesser user with a relationship into an event they cannot see was not driven live; the unit case covers the empty `related_object` it gets |
| Correlations from any drawn attribute (task 40) | ✅ | `php -l` on both files. Suite 696/696 (5 new cases: another event's attribute and object counted on arrival in one request, an object by its children, this event's own left out, asked once; a failed count asked again; the pivot applying once counted, summed, each option named from its node; a foreign object fetching by its drawn children; a pair drawn the other way, in the landing or on the canvas, not drawn again); 10 targeted mutants, 10 caught. Live, admin, 2014, dev server on this worktree: one-click Correlations from `1.1.1.1` lands 18 nodes and 9 correlation edges; one counts POST for 12 uuids; each of the 7 foreign `1.1.1.1` then wears *correlations 8* and the pivot applies; run from event 16's it lands 8 correlation edges and no node (every other copy is already drawn), 0 reverse duplicates; undo restores 26 nodes / 9 edges, then 8 / 0. The same run on the committed build finds no foreign node the pivot applies to | Found live: `Graph.getNode`/`getEdge` return a `structuredClone`, which throws on a node or edge carrying a closure; every drawn-check now uses `getMutableNode`/`getMutableEdge`. A lesser user was not driven live — sources go through `fetchAttributesSimple` and pairs through the correlation engine's ACL, as for this event's own. `e.target.closest is not a function` is logged on both builds |
| Inbound relationships and server correlations (task 41) | ✅ | `php -l` on the three PHP files. Suite 716/716 (7 new cases: an inbound source from another event beside its card, deletable by its uuid; an outbound target in another event's object, closed; the event as an inbound target; a relationship inside this event seen from both ends drawn once; an unreadable, mismatched, tombstoned or event-less far end not drawn; two foreign elements and an event endpoint sharing one card; the fetch asking for server correlations). Live, dev server on this worktree: admin 4345 — `8.8.8.8` from 3888 → `deadnxuyla.ru`, 43 `server-correlation` edges from *Training Main*; 1 — 4074's `8.8.8.8` → the `domain-ip` object; 4182 — 3 analyst edges, the same-event one once, 3989's source beside its card; 4074 — out to event 1's object, in from event 4182. `user@admin.test` on 4345 and 4182: the same inbound edges, no server correlations | No live case of a far end the viewer cannot read; the unit case covers it. The event view's own rows (`row_attribute.ctp`, `row_object.ctp`) read `RelationshipInbound` too, and now get it |
| Server nodes drawn (task 42) | ✅ | Suite 719/719 (the triangle assertion replaced: a server is composed at rest and a 140×44 chip; at rest a `#D0539F` hexagon in a `3 3` dashed ring; the chip names the server and its provider in that hue; the edge kind takes it too). The rebuilt bundle differs from the shipped one only by the server family and entity. Live, admin, dev server on this worktree: 4345 — one server node, *Training Main*, 43 `server-correlation` edges, drawn magenta with the dashed ring, no triangle; focused, the chip reads *Training Main* · `training.misp-co…`; legend *server 1* in the new hue. No console error | A restricted source (id and name only) was not driven live; its chip's second line falls back to *MISP Server* |
| Feed edge hue and fitted canvas (task 43) | ✅ | Suite 723/723 (the two feed kinds in the feed hue; fitted when shown, refitted on resize, clamped at 480 px, against a stubbed layout). Live, admin: 4345 at a 1000 px window — canvas 737 px (was 720), card bottom 984 + its 16 px margin = the window's edge; resized to 1300, 1037 px. 2014 at 800 — 537 px, then 837 at 1100; its 9 `feed-correlation` edges stroke `#D4A017`, none cyan. No console error | The degraded-hit badge keeps the cyan `FEED_COLOR` |
| Stand-in dash (task 44) | ✅ | CSS only, no suite case. Live, admin, computed `stroke-dasharray` per drawn path: 2014 — feed 2 real + 5 stand-in, server 1 real + 4 stand-in, all `6px, 4px` (stand-ins were `3px`); the 2 object references stay solid. 4345 — 13 server stand-ins and the analyst one at `6px, 4px` | The legend swatch still draws its own `3 2` (pivotick's `EdgeSwatch`) |
| Everything else | ⬚ | — | PRD §8.2–§8.10 |

**Task 2 has one visible consequence.** Pivotick's default edge stroke is grey
(`var(--pvt-edge-stroke, #999)`); D1 allocates `#428bca` to `object-reference`, and every
edge on the canvas today is one — so all edges go grey→blue. That is the settled palette
(task 3 adds orange for analyst relationships), not a regression, but it is a rendering
change no harness can confirm. Everything else about task 2 is data and config, and tested.

**Task 3 fixed a pre-existing seeding bug, found by its own new test.** The source of a
relationship was seeded *before* the target was checked, so an element whose only link
dangled — pointing at another event, a tombstone, or an element type the canvas does not
draw — arrived on the canvas alone with no edge, which is exactly what the connectivity
rule exists to prevent. Both kinds now resolve the far end first (`exists()`), and such an
element stays in the tray where it can be dragged in deliberately. **This changes existing
behaviour for dangling object references**, in the direction the rule always intended.

The task-2 dedupe-key gap is **closed**: a second kind makes `kind`-in-the-key observable,
and that mutant is now caught.

**Task 3c changes what most events draw, and it is the largest behaviour change of the set.**
Under D10(c) every live object is now on the canvas — as an L1 spine member if a relationship
touches it, otherwise as an L2 containment-only cluster — so long as the whole L2 set fits the
1,500-node budget. Two consequences worth stating plainly:

- **The tray keeps only event-level attributes.** Objects used to be its bulk; below the budget
  they are all on the canvas instead, and the tray/canvas invariant moves them out of it. Above
  the budget they all come back, which is D4's "the dock is load-bearing" case arriving for real.
- **Twelve existing tests changed expectations**, and none of them weakened. They were pinning
  pre-L2 canvas membership; the seeding rule they were really about (L1 vs nothing) is now
  observable through the resolution statement, which names the levels, and through a new companion
  test that pushes L2 past the budget so the pure L1 rule is visible on its own. That companion
  carries the exact assertion task 3 shipped.

**Two decisions the PRD had left open, now settled in it** (§D1, §D10, §D12):

1. **`event-correlation` is a sixth `kind`**, not `correlation`. Event 4116 has 86 of one and
   5,629 of the other saying the same thing at different resolutions; one kind for both would stop
   the layer switch keeping the cheap aggregate while hiding the expensive detail, and would make
   the `correlation` layer look populated before D9's fetch ever runs.
2. **The event node is drawn only when something connects to it.** A bare hexagon on every event
   would make L0 permanently non-empty and put D11's "nothing to draw" message (task 4) out of
   reach — it would also be exactly the floating dot D5 was withdrawn over.

**Why 3b and 3c share one commit**, against the one-commit-per-task rule. `computeSeed()` costs L0
before it can judge whether L2 fits, so the budget arithmetic spans both tasks. Splitting would
have meant committing an intermediate L0-only helper that the next commit deletes — noise, not
history. The two tasks were built and tested together as "finish task 3".

**The new work is mutation-tested to the same standard.** Twenty-six further mutants aimed at
tasks 3b and 3c — the budget gate and its off-by-one, object cost with and without children,
tombstoned children, L0's own budget charge, the tray filter, the event-node edge gate, the L0
edge kind, `Event` target resolution in three places, and every clause of the statement —
**26 caught, 0 escaped**, for 59 over the suite's life. Two needed a second pass: a duplicate
`RelatedEvent` turned out to be invisible in the graph itself (`addNode`/`addEdge` dedupe it) and
observable only as a node the budget paid for and the canvas never drew, so the dedupe test now
asserts the statement; and "draw proxies without the event node" proved to be an *equivalent*
mutant — proxies are non-empty only when the event node is seeded — replaced by one that breaks
the coupling at its source.

The graph-builder suite is **mutation-tested**: seventeen targeted breaks — ten — dropped tombstone guard, removed connectivity gate, removed edge-existence check, disabled dedupe, kept nulls, disabled truncation, broken image regex, unreferenced attributes admitted, dropped `related-to` fallback, nested deleted children — plus task 2's kind dimension and task 3's seeding, target-type
gating, relationship walking and tombstone handling. **33 mutants, 33 caught, none
escaping.** Three of them were only caught after mutation testing exposed fixtures that
were passing by luck: a target type rescued by a uuid that happened not to exist, an
event-level attribute never used as a relationship *source*, and a deleted link between
two elements both on the canvas for other reasons. So a green run means something.

**The extraction has never been opened in a browser.** Harnesses covered the config
plumbing and boot order, not rendering. §8.1's five interactions — graph renders, objects
expand, chips drag in, an edge is created, it persists — cover the bundle bump *and* the
file split in one sitting, which is why task 1b is doing double duty.

---

**Task 0b's write-path change is the only code the v2 bump needed.** v2 records a hand-drawn
edge in `graph.history` when it lands; the v1.6 `edgeAdd` listener saved or removed it *after*
that, so a refused save left an undo row for a vanished edge and a saved one undid as unsaved.
The edge now lands only once `objectReferences/add` succeeds, marked `persisted: true`. Verified
by gesture in the harness, not by the unit suite — the editor has no unit tests.

**The label floor is 8 px** (2026-09-25, the owner's call): `render.minLabelFontSize` was the
library's 9 px, which hid every label at the harness fixture's opening fit (zoom 0.62). The chip
tier also engages at zoom 0.8 rather than 1 (`CHIP_FROM_ZOOM`). Live on 2014: labels from zoom
0.67, chips from 0.81.

**What the live pass turned up:**

- **The editor was never offered on `/events/view2`** — `view2()` sets no `mayModify`, which the
  element read, so `canEdit` was always false, for a site admin on their own event too. The
  element now asks `$this->Acl->canModifyEvent($data)`, as `event_attachments.ctp` and its other
  siblings already do. Pre-dates the v2 work (`4061b1b8c`).
- **No misp-iconify glyph on any node.** The icon class resolves and `misp-iconify.css` loads, but
  Pivotick draws no icon element. **Not pursued:** node rendering is to be replaced by another
  renderer once the functional work is done (owner's call, 2026-09-23).
- **`/events/view2` exists only under the Overmind theme** — a user on the default theme gets
  *View file "Events/view2.ctp" is missing*. Only users 1 and 2 are on Overmind here, which is
  why no non-admin editor could be exercised live; the rule is the siblings' own.
- **Pre-existing page error, not ours:** `mispOvermind.js:2489` listens for `mouseenter` in the
  capture phase on `document` and calls `e.target.closest` unguarded, so the pointer entering the
  page throws `e.target.closest is not a function` (`a6a06665f`).
- **Side effect of the save test:** event 2014's timestamp moved to 2026-09-23 13:35; the
  reference itself is gone.

**Task 8 — what was decided while building it.**

- **The filter panel declares seven node facets, not one.** Declaring any node facet replaces
  Pivotick's derivation from every data key, so `scope` alone would have emptied the panel of
  everything else. The set is the one MISP's own library request asked for
  (`pivotick/prd/misp/declarative-filter-facets.md`): Provenance, Element, Category, Attribute
  type, Object, IDS flag, Value (regex). Select options are read off the live graph each time the
  panel rebuilds, children included. **Visible change:** the panel no longer offers the raw keys it
  used to derive — `uuid`, `label`, `description`, `imageUrl`, `event_uuid` and the like.
- **The header is the card's, not `UI.mainHeader`.** `mainHeader` is the sidebar's per-selection
  title; Pivotick has no graph-level title slot, and on `/events/view2` the card header is chrome
  MISP already owns. Nothing for upstream.
- **Provenance keys on `event_id`, `event_uuid` where known.** `extensionEvents` carries no uuid, so
  an extension element has `event_id` and `scope: 'foreign'` but no `event_uuid`. An attribute or
  object now carries `event_id` meaning *the event it belongs to*; on an `event` node it is still
  that event's own id — the same question asked of a different kind.
- **The correlation total joins the resolution line once the counts arrive**, and is absent at 0.

**Task 10 — what was decided while building it.**

- **Node creation, node editing and edge editing are off for everyone**, editors included. None of
  them writes anything to MISP: a created node would be a phantom, and an edited label would
  disagree with the saved reference. Drawing an edge and deleting stay for editors (deletion's
  MISP backing is 10c, below).
- **"Is this one of this event's elements" is answered from the payload**, not from task 8's
  `scope` field: a node is own if its uuid is a live attribute or object of the event. That is
  what made 10 independent of 8. A correlated attribute a pivot brings in fails it, so it can
  never be referenced.
- **The vocabulary is `object_relationships`**, from `/objectRelationships/index.json`, fetched on
  the first drawn edge and cached. That endpoint returned a 500 for every user — it checked a
  REST payload only CRUD actions set — and is fixed on its own (`e39908012`). The hardcoded
  25-entry list is deleted; if the fetch fails, the form is a single free-text field and the next
  edge asks again.
- **The form is declarative**: a select (defaulting to `related-to`) and a free-text field, the
  typed value winning. Pivotick has no combobox, so a list plus a text field is the closest
  honest shape. Only one kind is ever possible until 10b, so there is no link-type question.

**Task 10c — what was decided while building it.**

- **Every object-reference edge carries the reference's `uuid`.** Seeded ones take it from the
  payload; a drawn one from the `ObjectReference` the add call returns, which it previously
  ignored. Without it a drawn edge could not be deleted until the page was reloaded.
- **A soft delete**, `POST /objectReferences/delete/{uuid}.json` with no hard flag — what the event
  view does, and what lets the deletion reach synced instances.
- **Only an edge MISP can find again is deleted**: kind `object-reference` with a uuid. Correlations
  are derived, and analyst relationships have no write path until 10b, so both are *spared* —
  narrowed out of the decision with an info notice — rather than vetoing the whole gesture. A
  selection of nothing deletable still lets its notes go, without a confirm.
- **Notes pass straight through.** The §6.6 sketch returned `false` when no edge was named, which
  would have made canvas notes undeletable.
- **The decision narrows to what MISP deleted**, and is `persisted: true`; each refusal is reported
  with MISP's own message. If every delete fails, the gesture is vetoed and nothing leaves.
- **A node in the selection vetoes the whole gesture**, with a warning naming Hide and the event
  view — the PRD's rule, kept whole rather than silently deleting only the edges alongside it.

**Task 10b — what was decided while building it.**

- **Analyst rights are `perm_add` and `perm_analyst_data`**, the `analystData/add` ACL entry,
  read in the element and passed as `data-pe-can-analyst`, with the user's org uuid and
  site-admin flag. Either right alone now builds the editor.
- **Any two elements MISP can name** — attribute, object or event, with a uuid, not the same one
  — may be joined, this event's or another's (D8). Feed and server nodes do not exist yet (5b);
  they fail the same type test.
- **The two-kind form stays declarative** (P0), where PRD D2b had planned a custom form: a
  *Link type* select defaulting to the reference, in front of the same relationship fields. An
  analyst relationship's type is free text, so a vocabulary name is valid for it too.
- **Deletion came with it**, as 10c's inverse: an analyst edge is offered for deletion only
  where MISP's `canEditAnalystData` would allow it — the user's own org, or a site admin — so a
  confirm is never followed by a refusal. It is a hard delete, as MISP's own views do, which
  also blocklists the uuid. An editor without analyst rights cannot delete one; an analyst-only
  user cannot delete a reference.
- **The four writes share one `post()`** instead of four copies of the same request and error
  handling.

**Task 9 — the tray became a pivot.** P0 settled what PRD §11.7 had left as a candidate: Pivotick
already has a searchable, filterable, paged table with a commit step (a pivot's Review tab), so the
event's elements are an **origin-less pivot**, *Event elements*, and ingesting is putting them on
the canvas. What that changed:

- **The tray, its drag-and-drop, the drop ghost and all of the element's CSS are deleted.** Elements
  no longer land where they were dropped; the library places them.
- **Undo now covers it.** A tray drop was a programmatic `addNode`, outside the history (§4 below);
  an ingest is a history row.
- **Every viewer gets it, read-only users included.** Putting an element on the canvas writes
  nothing (D2), so there was never a reason to reserve it for editors; the tray was editor-only
  only because it lived in the editor.
- **What it offers is what the canvas lacks**: live event-level attributes and whole objects not
  drawn, read off the live graph, so it tracks ingests, undos and pivots. Summaries are dropped on
  every `nodeAdd` / `nodeRemove`, since the library caches them until told.
- **The form**: a search box (value, type, category and comment; an object answers for its live
  attributes, since it is what gets ingested), then *Element* and *Category* selects with counts.
  `maxCandidates` is the 1,500 budget, so an unnarrowed 28,410-object event is refused with its
  number — D4's "search is the primitive", enforced by the library.
- **Not server-paged.** D4 asked for server paging above a size threshold, but the whole event is
  already in memory (D13 is not built), so paging from the server would fetch again what the page
  holds. When D13 lands, `fetch` is the one place to change. The Review tab pages at 100 rows.
- **The library's `UI.table`** was already the dock's first tab; nothing to add.
- **Not exercised:** an own attribute the correlation pivot brought in on its own (a child of an
  object L2 skipped), followed by ingesting that object here. The ids would collide; Pivotick
  skips an id already on canvas, but whether that holds for a container's children is untested.

**Task 6 — what was decided while building it.**

- **The count is everything said about the element**: its notes and opinions, and the notes and
  opinions left on those. Relationships are not counted; they are edges.
- **The colour is the element's own opinions only.** An opinion on a note is about the note. The
  bands are `opinion_scale.ctp`'s: under 41 disputed, over 60 endorsed, else neutral; notes alone
  are grey like neutral.
- **No aggregation (PRD §11.9: "neither").** An object's badge counts the object's own analyst data;
  its attributes wear theirs. Summing would count the same note twice once the object is expanded,
  and would leave no badge meaning "this element".
- **The node carries two flat fields**, `analyst_count` and `analyst_mood`, absent when there is
  nothing — so a node without analyst data is byte-for-byte what it was, and the fields become
  filter facets for free.
- **The panel is registered only when the event has analyst data somewhere** (§8.10), and shows the
  selected element's notes and opinions as text, replies a step in. The badge carries its own
  `onClick` — select the node, open the sidebar — so the library's related-event potential badges
  keep theirs.

**Task 4 — the message points at the elements, not at correlations.** D11 wrote the message as
*"No relationships in this event — 5,629 correlations available"*. That cannot occur: the
correlation counts are a subset of `RelatedEvent`, and any related event puts L0 on the canvas, so
a seed that drew nothing has no correlation to offer. What an empty canvas does hold is unrelated
attributes, and objects L2 could not fit — exactly what the element pivot lists. So the statement
names what is missing, counts what is there, and its one action opens *Event elements*. Two cases
say something else: an event with no content at all (no action), and a canvas the analyst emptied
by hand (*The canvas is empty*, since "nothing is related" is only true of the seed).

Pivotick had no empty-canvas state, so this first shipped as MISP's own box over its own stage
(`ace970f01`). Requested upstream (`pivotick/prd/misp/empty-canvas-state.md`), landed as
`UI.emptyState` in `1296966`, and the box, its markup and its style are gone (`aceab26ae`): the
statement is the card's `render`, and `initial` is what separates the seed's wording from the
emptied-by-hand one.

**Tasks 5 and 5d were blocked on Pivotick, not on MISP — fixed upstream in `1296966`.** What follows
is the diagnosis as it stood. `PivotManager.ingest()` lands a carried
edge only when an endpoint is a *top-level* node the run landed: descendants of a new container are
not counted, and children merged into a container already on canvas are merged after the edges
are decided. Both pivots return their results as containers (the related event holding its
correlated attributes), so every `correlation` edge is dropped. Written up for a Pivotick session:
`~/git/pivotick/prd/misp/pivot-edges-to-children.md`. No MISP workaround, per P0.

**Event 4116 offers the correlation pivot nothing to start from** — every correlated attribute is
inside an object, and L2 is skipped. Correct, and it is task 9's dock pane that will reach them.

## 3. Blockers

**Task 1b needs the dev server, which is not ours to point.** misp-track selects which tree
`misp-core` serves; on 2026-08-31 it was serving `attribute-value-page-brief` for a parallel
job. **The user owns that switch** — read `~/git/misp-docker-2.5/.misp-track.state` to see
the current selection and ask; never repoint it.

Credentials for the authenticated `/events/view2/{id}` render are available.

**The harness did part of it (2026-09-23)**: rendering, seeding, both edge kinds, the tray drop
and the edge gestures under v2. What still needs the real instance is real payloads (1195, 4116),
the misp-iconify glyphs (the harness loads no font), the CSP-served worker, and the saved
reference surviving a reload.

**What 1b now owes has grown.** Beyond the bundle bump and the file split, an unopened browser has
never seen: the grey→blue edge stroke (task 2), the dashed-orange analyst layer (task 3), the green
event hexagons and their dashed-green aggregate edges (3b), L2's containment clusters on an
ordinary event, and the `#pe-resolution` line in the card header (3c). All of it is tested as data
and config; none of it is tested as pixels.

Fixture events, per PRD §8: **1195** (2,362 refs — the authored-spine seed case) and
**4116** (0 refs, 5,629 correlations — the D11 empty-state and cap case).

---

## 4. Not scheduled

Real work, deliberately outside PRD §9. Listed so it is not rediscovered as a surprise.

- **Hardcoded English UI strings** in `pivot-explorer.js` — the pivots' labels and facet labels
  (`'Event elements'`, `'Search'`, `'Element'`, `'Category'`, `'Correlations'`, …), the
  relationship form's (`'Add relationship'`, `'Relationship type'`, `'Or a custom one'`), the
  notifier messages, and the five fragments `resolutionStatement()` assembles (`'Seeded '`,
  `' node(s)'`, `'L2 skipped (N objects not shown)'`, `'N relationships not drawable'`).
  Untranslatable as they stand. Pivotick has no consumer-facing i18n (no `setLocale` /
  `translations`), so anything MISP writes stays MISP's to translate. Tasks 9 and 10 deleted the
  tray's and the picker's strings, and added about as many in the library's forms. The statement
  is the one group with a natural home already: task 8 moves it into the header, and `data-pe-*`
  is the established route for a translated string — though a sentence with counts and plurals
  wants more than one attribute.

- **Group a large landing by type** — a run that lands many nodes arrives as one group per type with its count ("12 IPs from event B"), which opens onto them, in place of a closed event card. Parked 2026-09-27: it is property grouping applied to one run, so it waits on pivotick grouping and collapsing nodes by a property to coarsen the graph, still to be specified upstream. **Done 2026-09-29** in [`pivot-explorer-graph-simplification-prd.md`](pivot-explorer-graph-simplification-prd.md): every pivot landing arrives grouped by MISP's own kind, 5 or more to a group.
- **Dedicated graph endpoint (D13)** — deferred to
  [`pivot-explorer-graph-endpoint-prd.md`](../../prd/pivot-explorer-graph-endpoint-prd.md). Until it
  lands, this PRD knowingly ships against `/events/view/{id}.json`, so large events stay
  slow to open (~100 MB for event 4116 to draw 86 nodes).
- **Phase 2 open questions** — object aggregation, lazy expansion via `childrenProvider`,
  declarative initial filter value. PRD §11.
