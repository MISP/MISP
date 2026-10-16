# PRD: Groups in the Pivot Explorer — landings, rules and the group card

**Status:** Built and live-checked 2026-09-29 (S1–S5), every library prerequisite (§4 L1–L5) bundled.
**Owner:** Sami Mokaddem (Claude-assisted)
**Parent:** [`pivot-explorer-v16-prd.md`](pivot-explorer-v16-prd.md). Unparks *Group a large
landing by type* ([progress](pivot-explorer-v16-progress.md) §Parked).
**Library:** Pivotick `develop` at `625fe52` (bundle bump 0m). Its
`prd/graph-simplification.md` is the reference for every D-number below.

---

## 1. Why

Two events sharing 3 TTPs and 40 IPs draw 43 nodes and 86 edges, when what the analyst reads
is "they share 3 TTPs and 40 IPs". A pivot that returns 40 IPs scatters 40 dots round its
origin, when the answer was "40 came back". Pivotick now folds nodes into view-only groups
(D1: `getNodes()`, the table, undo and saving see real nodes only). MISP ships the bundle but
declares nothing, so today:

- **The Simplify rail mode offers the built-in rules switched off** (D23), at the library's
  defaults, grouping on `elementOf`. The neighbour rule would put an `ip-dst` and a `domain`
  in one "attribute" group.
- ***Ingest in a group* is offered in Review** (D102) and lands "12 × attribute", for the same
  reason.
- **A one-click pivot** (a context-menu row, a rim badge) lands up to 25 new rows
  (`pivotQuickIngestLimit`) loose, and nothing can ask for a group.
- **A group draws as the library's ringed disc** (D36), in none of the node designs' hues, and
  its tooltip never shows: MISP runs with `tooltip.enabled: false`.

## 2. What the analyst sees

- **Every pivot landing arrives grouped**, one card per kind, off the node it was run on:
  *9 × ip-dst*, *3 × Attack Pattern*. This holds for a one-click run and for Review, whose main
  button lands grouped, with *Ingest loose* beside it.
- **Fewer than 5 of a kind land loose.** Two tags from *Tags & clusters* stay two tags.
- **Opening a card** puts its members back on the canvas in place (D19). Undo takes the
  landing away, group included (D105).
- **A card looks like MISP**: at rest, the library's ring in the entity's hue; zoomed in, a
  stacked MISP chip. Hovering it shows the library's group tooltip: the breakdown, what it
  hangs off, the open hint, and the first three values.
- **Nodes and edges still have no tooltip.**
- **The Simplify mode lists six rules**, only *Pivot landings* on, so an event opens exactly as
  it does today.

## 3. Decisions

| # | Question | Decision |
|---|---|---|
| G1 | Do one-click landings land grouped? | **Yes, every one.** The smallest group (G3) keeps a small answer loose. Rejected: a per-pivot switch (one more setting per pivot to keep right), and never (a one-click *Event elements* browse lands its attributes with no edges, and no structural rule folds an unlinked node, D43) |
| G2 | And Review? | **Grouped by default too.** With the option on, Review's main button (*Ingest selected*, and *Ingest all n*) lands grouped, and a second button, *Ingest loose*, lands as today. One rule for the analyst: pivot results arrive grouped. Library change §4 L1 |
| G3 | How a run is flagged | **By the library, from one graph option, `pivotIngestGrouped: true`** (§4 L1). Not from `onBeforeIngest`: in `PivotManager.ingest()` the set's `runId` moves on before the hook runs (`PivotManager.ts:829-830`), and `IngestContext` carries no `runId` |
| G4 | Smallest group | **5 for every rule that has one:** `landings` (library default 2), `neighbours`, `chains`. Degree and k-core have no smallest group (D74); a community of one stays a node (D82) |
| G5 | What "the same kind" means | **The entity plus MISP's exact type**, in one `mispTypeOf(node)` passed as every rule's `typeOf` (§3.1). `ip-src` and `ip-dst` stay apart: the key is the value the *Attribute type* filter shows, and there is no family table to maintain. Not by changing `render.nodeTypeAccessor`: `nodeStyleMap`, the legend's *Element* section and the facets key on `elementOf` |
| G6 | Several origins | **One card per kind, not per origin.** The landings key is run + type (`rules.ts:35`), so a pivot on 3 attributes returning 9 `ip-dst` gives one *9 × ip-dst* card, with a folded line to each origin. Library behaviour, accepted |
| G7 | How a type is named | **`N × name`**, readable names: the attribute type (`9 × ip-dst`), the object template (`12 × file`), the galaxy's name (`3 × Attack Pattern`), the tag namespace (`4 × tlp`), the element (`6 × event`). `typeLabel` in `UI.simplify` |
| G8 | Which rules MISP lists, in order | **`landings`, `neighbours`, `chains`, `degree`, `kcore`, `communities`.** `landings` is declared so its smallest group is preset (D103). Communities (Leiden) is declared for large correlation webs, where the structural rules find little to fold. No custom rule |
| G9 | Which start on | **Only `landings`.** Switching `neighbours` on would change what every event opens on, which is the seed's call (v16 D12), not this PRD's. Each rule is one click away in the rail |
| G10 | How a group looks | **The library's ringed disc at rest, a MISP chip zoomed in, no hover card.** At rest (S) the ring is coloured with the entity's `core`; from zoom 0.8 (M) a stacked 140 × 44 chip carries the count and G7's name. No XL focus tier: the tooltip (G12) does that job. §3.2 |
| G11 | A group of mixed kinds | **Neutral card, split ring.** Grey MISP surface; the ring is split by share in each **entity's** hue, so two attribute types read as one green arc and the chip's breakdown (`4 ip-dst · 2 domain · 1 event`) tells them apart. Made by degree, k-core, communities and by hand |
| G12 | Where a group explains itself | **The library's group tooltip, on for groups only.** It already carries the breakdown, the anchors, the open hint and the search match count; `tooltip.renderGroupExtra` adds the first three members' values and *+N more*. Nodes and edges keep no tooltip. Needs `tooltip.enabled` per kind (§4 L2) |
| G13 | The open group's chip | **G7's label**, through `render.groupOutline`. The rule stays in the chip's hover text (D92) |
| G14 | Groups made by hand (P11) | **Offered as the library ships them, for the session only.** Saving them with the canvas waits on pivot persistence, which MISP does not have yet |

### 3.1 The type function

`mispTypeOf(node)` lives in `pivot-explorer.js`, exported for the graph-builder tests. The
prefix keeps entities apart: an attribute and an object that are both named `url` never share
a group (D4).

| Element (`elementOf`) | Key | Name (G7) |
|---|---|---|
| attribute | `attribute:` + `data['attr-type']` | the type: `ip-dst` |
| object | `object:` + `data.name` (template) | the template: `file` |
| cluster | `cluster:` + `data.galaxy_type` | `data.galaxy_name`, else the type |
| taxonomy (tag) | `tag:` + namespace (before the first `:`, else the whole name) | the namespace |
| event, feed, server, image | the element alone | `event`, `feed`, `server`, `image` |

An attribute inside an object is a child of a closed container and never on the main canvas,
so no rule sees it (D24). A correlation that lands objects therefore lands
`object:<template>` groups (correlated-object C4): *40 × ip-port*, not 40 attributes.

`typeLabel(type, count)` receives the key, drops the prefix and looks the name up. The
galaxy's name is read from the first member, since the key carries only the type.

### 3.2 The group card

The card follows the node-design grammar
([`prd/pivot-node-designs/summary.md`](../../prd/pivot-node-designs/summary.md)): hue means
entity, and each element draws S at rest and an M chip from zoom 0.8.

- **S (rest):** the library's ringed disc (D36), coloured with the entity's `core` from
  `MispPivotNodes.palette()`, the count on the disc. The ring is what says "group" at every
  zoom, so it is kept, not redrawn. `layoutSize` follows the library's radius (D37), not
  `LAYOUT_SIZE`.
- **M (chip, 140 × 44):** the entity's chip frame with the count as the lead and G7's name as
  the kicker, and a stacked edge (a second, offset rim) that no single element's chip has.
- **No XL:** hovering shows the tooltip (G12), not a larger card.
- **Mixed (G11):** `surface` / `line` frame, the split ring at S, the breakdown on the chip.
- **By hand:** the title replaces the kicker (D111).
- **Badges:** none. A group has no warninglist hit or IDS flag of its own, and every corner
  stays free for the library's search arc (D86).

The drawings are a new entity, `group`, in `prd/pivot-node-designs/entities/`, drawn in the
gallery beside the element cards and built into `misp-pivot-nodes.js` by
`build-renderers.py`. `groupStyle` in the explorer picks the entity's tiers, as
`mispNodeStyles()` does for elements.

## 4. Library prerequisites

Each is written up in `~/git/pivotick/prd/` for its own session. Neither is worked round in
MISP.

| # | What | PRD | Needed by |
|---|---|---|---|
| L1 | `pivotIngestGrouped: true`: every landing (a one-click run, Review's *Ingest selected* and *Ingest all n*) is flagged with `groupLanding` before it lands, and Review's second button becomes *Ingest loose* | `pivot-ingest-grouped.md` | G1–G3 (S2) |
| L2 | `tooltip.enabled` also takes `{ nodes, edges, groups }` or `(element) => boolean` | `tooltip-enabled-per-kind.md` | G12 (S3c) |
| L3 | `UI.simplify.typeOf` and `UI.simplify.colorOf` for every rule and every group colour. Today only `landings`, `neighbours` and `chains` read a rule's `typeOf` (`Simplification.ts:806-808`), so degree, k-core, communities and hand-made groups count parts by element (`6 × attribute, 9 × object`), and `typeColor` never matches a MISP key. A drawn MISP node's resolved colour is transparent, so a mixed group's split ring, the open wash and the tooltip's chips draw in nothing. Found wiring S1, 2026-09-29 | `simplify-host-type-and-colour.md` | G7, G11 |
| L5 | `render.groupStyle(info, base)`, so a host extends the default tiers instead of replacing them (today MISP's chip tier drops the count-on-disc tier); `GroupInfo.landing = { runId, pivotId, pivotLabel }`, so the chip's second line can name the pivot without parsing the internal run id. Found wiring S3c-2, 2026-09-29 | `group-style-base-and-landing-pivot.md` | G10 |
| L4 | A portaled tooltip's header takes the light theme under `UI.theme: 'dark'`: the dark map leaves `pvt-sidebar-mainpanelheader-bg` `unset`, which inherits `:root`'s light `#fafafa`, under white text. Found live on 1017, 2026-09-29 | `portal-theme-inherited-light-header.md` | G12 |

## 5. Tasks

One commit per task.

| # | Task | Depends on |
|---|---|---|
| S1 | `UI.simplify` in `graphOptions()`: G8's rules with G4's `minSize`, G9's `enabled`, `mispTypeOf` as every rule's `typeOf`, `typeLabel`. Unit tests for `mispTypeOf` and `typeLabel` in `tests/js/pivot-explorer-graph.test.js` | — |
| S2 | Bundle bump with L1; `pivotIngestGrouped: true` | S1, L1 |
| S3a | The group card's contract (§3.2): what S and M each say, sizes, mixed and titled variants, recorded here | — |
| S3b | Competing prototypes of the `group` entity in `prd/pivot-node-designs`, in the gallery beside each hue's element cards, S and M, single, mixed and titled | S3a |
| S3c-1 | The ring at rest in the members' entity hue (`groupStyle` → `color`); tooltips on for groups only, with `renderGroupExtra` listing the first three values | S1, L2 |
| S3c-2 | The chosen chip built into `misp-pivot-nodes.js`, returned as `groupStyle`'s M tier; `groupOutline` | S3b, S3c-1 |
| S4 | Live check (§7); the progress doc's parked item moved to done | S1–S3c |
| S5 | Close L3–L5: `UI.simplify.typeOf` / `colorOf` in place of per-rule `typeOf` and the style's `color`; the chip tier appended to `base.tiers`; the chip names `info.landing.pivotLabel`; a group spaced like an element (`layoutSize` 45) | S4, L3–L5 |

## 6. Scope

**In:** MISP's rules, types, labels, look and tooltip for every group the library makes, and
grouped landings by default.

**Out:**
- Saving groups, pull-outs or open state with the canvas (D21). Waits on pivot persistence.
- Any custom rule (by `to_ids`, by owning org). Declare one once an analyst asks for it.
- Tooltips on nodes and edges: they stay off.
- Grouping inside an object: attributes are children of a closed container (D24).

## 7. Acceptance

On the dev instance, as admin and as one of the lesser readers:

1. **One-click, many of one kind:** *Event elements* from the event card on 752 lands one
   group per attribute type with 5 or more members, the rest loose, the groups off the card.
   Undo removes the groups with the nodes.
2. **One-click, few:** *Tags & clusters* on a single attribute lands its tags loose.
3. **Review:** *Ingest selected* and *Ingest all n* land grouped; *Ingest loose* lands as today.
4. **Types kept apart:** a correlations run that lands objects of two templates (pick the event
   from the dev DB) lands one group per template, never one "object" group; `ip-src` and
   `ip-dst` never share a group.
5. **Several origins:** a pivot on several selected attributes gives one card per kind, with a
   line to each origin.
6. **Rules:** the Simplify mode lists G8's rules in order, only *Pivot landings* on, every
   stepper that has one starting at 5. Switching *Same neighbours* on folds nothing under 5,
   and `getNodes()` still returns every node.
7. **Look:** a group at rest and zoomed in matches the chosen prototype in its entity hue; a
   mixed group is neutral with a split ring.
8. **Tooltip:** hovering a group shows the breakdown, the anchors and the first three values;
   hovering a node or an edge shows nothing. No console error.
9. **Suite:** `node tests/js/pivot-explorer-graph.test.js` green.

## 8. State

| # | State |
|---|---|
| G1–G14 | Decided 2026-09-29 |
| L1, L2 | Built upstream (`a3a95c9`, `cda9895`), bundled 2026-09-29 (progress 0n) |
| L3, L4, L5 | Built upstream (`09f133b`, `1ab3387`, `30c9833`), bundled 2026-09-29 (progress 0o) |
| S1 | ✅ `e4632498d`. Live on 1017: the Simplify mode lists the six rules in order, only *Pivot landings* on, steppers at 5 |
| S2 | ✅ `71af31888`. Live on 1017: a one-click *Event elements* lands 25 as one *12 × ip-dst* group and 13 loose nodes (3 md5 stay loose); undo clears it; Review reads *Ingest selected · Ingest loose · Ingest all 25* and its main button lands grouped. On 752 nothing reaches 5, so nothing folds |
| S3a | ✅ The contract: a `group` entity in the design harness, the `GROUPS` samples (seven real landings, view-model in their header) and `prd/pivot-node-designs/group-brief.md` |
| S3b | ✅ Three cold prototypes in `prd/pivot-node-designs/entities/group-{deck,tally,peek}.js`, Group tab of the gallery. **Deck chosen 2026-09-29**: the members' own M chip with two rims behind it |
| S3c-1 | ✅ Live on 1017: the ring draws in attribute green; hovering the group shows its tooltip (label, rule, open hint, three IPs, *+9 more*), hovering a node shows none. The header is unreadable until L4 |
| S3c-2 | ✅ `R.group.M` in `renderers/10-renderers.js`, `MispPivotNodes.groupCard(view)`; `groupStyle` adds the chip tier from 2 × r × 0.8 rendered px, the zoom an element chip engages at; `groupOutline` names the open group by its label. Live on 1017: at zoom 1.39 and 1.95 the group draws *12 × ip-dst · Pivot landings* as a green deck among the attribute chips. Until L5 the second line is the rule's name, not the pivot's, and the disc's count tier is replaced. The layout still spaces a group for its ring, not its 140-wide chip |
| S4 | ✅ 2026-09-29, the dev instance serving this branch. On 2014, as admin and as `user@admin.test`: *Correlations* from the 3 nodes it applies to stages 56, Review's main button lands them as *23 × event*, *12 × ip-dst*, *5 × domain-ip* and *5 × paloalto-threat-event*, never two templates in one group, each group linked to every origin it came from (64 nodes, 23 on the canvas; the reader 61 and 20); *Tags & clusters* on one attribute lands its one tag loose. §7's items 1–3 and 6–8 as S1–S3c above; 1288 folds nothing on *Event elements*, correctly, since its objects are already seeded. Suite 677/677, no console error |
| S5 | ✅ 2026-09-29, live on 2014 with bundle `bd5d913`: every landing group carries `landing.pivotLabel` "Correlations" and its chip reads *12 × ip-dst · Correlations*; the tooltip header is transparent under white ink, its *Linked to* chips in entity hues; at zoom 1.53, 9 cards and no group overlapping another card; *Few links* labels by MISP kind (*1 × asn*, *2 × feed*), each part in its entity's colour. Suite 681/681, no console error |
