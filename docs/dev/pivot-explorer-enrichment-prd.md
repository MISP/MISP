# PRD: Enrichment from the graph

**Status:** **COMPLETE** (2026-10-01); leftover polish is in the parent PRD's backlog
([§12](pivot-explorer-v16-prd.md#12-backlog-after-completion-2026-10-01)). Contract 2026-09-30 — §4 grilled and ruled (E1–E13, plus H1–H3 the grilling
added); phase B done, look B picked (§5.4); phase C wired and accepted (§7). Saving (E8): ruled and wired 2026-09-30, prompt and context menu 2026-10-01 (§10); S9 left as is for now (§10.8).
**Owner:** Sami Mokaddem (Claude-assisted)
**Created:** 2026-09-30
**Parent:** [`pivot-explorer-v16-prd.md`](pivot-explorer-v16-prd.md), which ruled enrichment its own
later pass (R3: "a pivot — `fetch` = the module query, `save` = persisting into the event").
**Reuses:** the Value Intelligence's enrichment engine
([`../../prd/value-intelligence-live/28-enrichment.md`](../../prd/value-intelligence-live/28-enrichment.md),
[`13-auto-run.md`](../../prd/analyst-profile/13-auto-run.md)) and pivotick's pivot interface
(`~/git/pivotick/prd/pivot-enrichment-interface.md`, complete).

---

## 1. Why

An analyst on the Pivot Explorer can already walk outwards through MISP's own data:
correlations, another event's contents, tags, clusters, feeds. What they cannot do is ask the
outside world. To learn what `8.8.8.8` resolves to, who registered `deadnxuyla.ru`, or what
passive DNS knows, they leave the graph for the Value Intelligence's Enrichment tab. That tab answers
in a table, and nothing it finds can join the picture they were building.

Both halves already exist:

- **MISP** has an enrichment engine that picks the modules a value is eligible for, runs one,
  normalises what comes back into attributes and objects, marks which returned values MISP
  already holds, and stores the answer per organisation so it is not asked twice. It is the
  Value Intelligence's, and it renders HTML only.
- **Pivotick** has the whole pivot flow: offer, count, narrow, fetch, triage in Review, ingest,
  undo, and a `save` hook with a ledger of unsaved results.

This PRD joins them: one more pivot, offered on every explorer host, whose results land on the
canvas like any other pivot's.

### State

| Part | Status | Note |
|---|---|---|
| Contract (§4 ruled, §5 frozen) | ✅ | grilled 2026-09-30 |
| Non-enrichment deny-list, `ModuleRole` (§5.1) | ✅ | `000690b9f`; `enrichment.roles` overrides it, raw profile JSON only — the profile editor has no control for it yet |
| JSON endpoints on `ValuesController` (§5.1) | ✅ | `000690b9f` |
| ACL entries | ✅ | `perm_add` + `theming_enabled` for all three (E11) |
| *Enrich* pivot in the shared kit (§5.2) | ✅ | `231c7b8c6`; both hosts, `canEnrich` from the same ACL |
| Landing, `enrichment` edge kind, `scope: 'module'` (§5.3–§5.4) | ✅ | `231c7b8c6`; the value page has the legend section but no Provenance *facet* — its filter is the legend's |
| Run toast (§5.5) | ✅ | |
| Sidebar: provenance, notice, known-only links (E13) | ✅ | `5cccb6836` |
| Prototypes: result node look + edge (§8, phase B) | ✅ | B picked (§5.4); two pivotick asks shipped (`e2537f0`, vendored `b9ff699ec`), one declined |
| Unit tests, acceptance (§7) | ✅ | explorer 765/0, sidebar model 87/0, neighbourhood 29/0; §7 below |
| Save into the event (§10) | ✅ | context-menu saves, the relationship prompt, no panel Save — wired and accepted (§10.7); S9 left as is (§10.8) |

## 2. What the analyst sees

Select an attribute node — or, on the value page, a value node — and open *Pivot ▸*. A new entry,
**Enrich**, is offered when at least one expansion module accepts the node's type and the viewer
may run modules. A Read Only user never sees it.

The pivot panel has one control, **Module**: every eligible module, each labelled with what the
organisation already knows about it for this value — `circl_passivedns — 3 h ago` with its
result count, `whois — timed out yesterday`, or the bare name if it has never been asked. The
modules the analyst profile ticks, and those with a fresh stored answer, start ticked. The
analyst adjusts the ticks and presses Fetch.

A module whose stored answer is fresh answers at once, from the store. The others are asked, five
at a time. What comes back goes to Review:

- **Objects** a module returned (a `passive-dns` record, a `dns-record`) as closed object nodes
  with their attributes.
- **Attributes** it returned (an IP, a domain) as attribute nodes; a legacy module's bare values
  the same way, marked as untyped by the module.
- Each joined to the node it was run on by an **enrichment** edge labelled with the module.
- A returned value MISP already holds says so on the node, and in the sidebar its value opens
  the value's profile.

A single toast says what did not come back: a module that answered with nothing, one that
errored, one that timed out, an answer cut to 200 of its results.

Ingest lands the ticked rows; undo takes them away, like any pivot. The Provenance legend gains
**From enrichment**, so everything the outside world said can be hidden at once. The results are
the canvas's only: nothing is written into MISP. The stored answer, though, is the
organisation's, so the Value Intelligence's Enrichment tab shows the same run afterwards.

## 3. What the engine gives, and what it does not

Measured from the code on 2026-09-30. `VP` is `app/Model/ValueIntelligence.php`.

**It is scoped to a value and a type, not to an attribute.** `enrichmentRun(user, value, module,
type, mode)` (VP:14918) takes no attribute id. For a `misp_standard` module it sends the reader's
*first* visible attribute holding that value and type (`enrichmentOccurrence`, VP:15265), not
necessarily the one clicked, and it sends no object or event context. A `simplified` module gets
`{type: value}`. The same lookup is what keeps a user from enriching a value they cannot see.

**It picks modules by the value's types.** `enrichmentCatalogue` (VP:14182) unions, over every
type the value is held as, the enabled expansion and hover modules that accept it
(`enrichmentEligible`, VP:14843, over `Module::getEnabledModules`: the service switch, the
per-module switch, the per-org restriction). Every call is a round trip to the module server.
Each row carries `name`, `kinds`, the types, the output `format`, a description, `locality`, and
the latest stored answer. `can_run` is `perm_add` (VP:14241). **Nothing filters out modules that
are not enrichment** — sample submitters, uploaders, document transforms — so the Value
Profile's tab offers them today.

**It stores every answer, per organisation.** Table `value_enrichment_runs`, unique on
`(org_id, sha256(value), module, type)`, upserted: state, when, how long it took, the counts, and
the shaped result. `mode=auto` serves a fresh stored answer (`max_age_hours`, default 24) and asks
only when there is none; `mode=stored` never asks; anything else always asks. A `running` row is
the in-flight lock. Failures are stored too.

**It runs synchronously, one module per request.** Timeout `Plugin.Enrichment_timeout`, 10 s by
default. The Value Intelligence caps itself at 5 parallel requests and closes the session first so they
overlap.

**It normalises the answer** (`enrichmentShape`, VP:15340) into:

| Key | Holds |
|---|---|
| `state` | `ok` · `silent` (answered with nothing) · `error` (the module said it cannot) · `refused` (MISP's trigger declined) · `unreachable` · `timeout` · `ineligible` · … |
| `attributes[]` | `{type, value, category, comment, to_ids, correlates, known}` |
| `objects[]` | `{name, meta_category, description, comment, attributes[{relation, type, value, …, known}]}` |
| `elements[]` | a legacy module's flat `{types[], value, known}`, with no structure |
| `total`, `shown`, `capped` | 200 results at most per answer, the true total kept |

**A `misp_standard` answer echoes the attribute it was asked about** in `attributes[]` — every
recorded answer on the dev instance does (`8.8.8.8` as `ip-dst` comes back in circl_passivedns',
mmdb_lookup's and ipasn's). Landed as-is it would draw a loose duplicate of the origin; §5.3 drops
it. On that instance every real result is therefore an **object**: no enabled module returns a
loose attribute or a legacy element.

`known` (`enrichmentKnown`, VP:15487) is one ACL-scoped prevalence probe over the returned values
that MISP correlates on, leaving out the value asked about. It is recomputed on every read, never
stored.

**It writes nothing into events.** Write-back exists elsewhere: `EventsController::
handleModuleResults($id)` takes resolved MISP-format JSON for an event the user can modify.

**Legacy output is shrinking, not gone.** misp-modules' `modules-answering-in-objects` branch
(18 commits over `main` at `953bd2b6`, unmerged) moves 15 flattening modules to `misp_standard`
— dns, reversedns, geoip_*, securitytrails, urlscan, hibp, vulners, … On its tip 39 non-hover
expansion modules still answer `simplified`; 15 of those are real enrichment (apifreaks,
apiosintds, backscatter_io, domaintools, eupi, intel471, iprep, mwdb, otx, passivetotal,
threatcrowd, threatfox, threatminer, vulndb, and whois by choice), the other 24 are not
enrichment at all (E7).

## 4. Decisions — ruled 2026-09-30

| # | Question | Ruling |
|---|---|---|
| H1 | **Which hosts, and where the endpoints live.** | **Value-scoped JSON on `ValuesController`**, beside the `viewEnrichment*` actions; the pivot is in the shared kit. The event page and the value page (attribute *and* `value` nodes) get *Enrich* now, the Intelligence Graph when it lands. The engine is value-scoped, so an event id would only tie the feature to one host. |
| H2 | **How a node learns it is eligible.** `appliesTo` must be synchronous; the catalogue costs a module-server call per request. | **Two reads.** A type → modules map fetched once per page decides eligibility, by the **node's own type** (a value node: each type it is held as). The stored answers are read in `summarize`, for the origin only. The graph does not union the value's other types the way the Value Intelligence does: the node *is* that type. |
| H4 | **Objects and their attributes** (feedback, 2026-09-30). A closed object's attributes are not nodes one can select. | **The object offers *Enrich*** when an attribute has a module. An **Attribute** facet lists its eligible attributes (`relation: value`) and starts with its **lead** one — template priority, then `to_ids` — so a one-click run is one attribute's worth. Results join the object; the edge reads `module · relation`. The 25-pair cap still holds. `72785ed1d`. The context menu offers each attribute as a choice, *Pivot ▸ Enrich ▸ `ip: 8.8.8.8`* — declared as `menuChoices` (`448c05425`), live since pivotick `ce07c9a` (vendored `42b2959e2`), which also redraws the Module list the moment an Attribute is (un)ticked. |
| H5 | **An unknown count** (feedback). Before a module has answered, the menu's `~0` reads as "nothing out there". | **Unknown is drawn as nothing** — pivotick `a0c260e` (`total: null`). The total is known only when every picked module has a stored answer for the value; a failed one counts 0 (`d6f3ad134`). A run now invalidates the cached summary, so a count read before it is re-read after (`72785ed1d`). |
| E1 | **One pivot or many.** | **One *Enrich* pivot, a `multiselect` Module facet.** Pivotick's facet option is `{label, value, count}`, so the stored state is a label suffix (`— 3 h ago`, `— timed out yesterday`) and the count is the stored total. **Pre-ticked:** the profile's `ticked` and `auto` modules, and every module with a fresh stored answer (it costs nothing). The pivot's `total` is the stored totals of the ticked modules; a never-asked module adds 0. |
| E2 | **Which modules.** | **Expansion only.** A module that is hover *and* expansion stays, run as expansion; hover-only and cortex modules are out. |
| E3 | **Value or attribute.** | **Value-scoped** (follows from H1), which buys the per-org store and answers shared with the Value Intelligence. Object-input modules stay out. |
| E4 | **Where results sit, and what they are.** | **Attribute: `enr:<type>:<value>`**, one node shared across modules, origins and runs, each module adding its own edge. **Object: `enr-obj:<module>:<hash>`**, the hash over its name and sorted `(relation, type, value)` triples, so identical records collapse, reruns keep their ids and two origins never collide. Its attributes are its own children, `<object id>:<relation>:<value>`, never shared `enr:` nodes. A result is never merged into a MISP attribute or value node; `known` says the value is in MISP. |
| E5 | **Provenance.** | **`scope: 'module'`, labelled *From enrichment*.** The Provenance legend and facet appear whenever a module result is on the canvas, even on a host that turns provenance off: *This event · Elsewhere · From enrichment* on the event page, *In MISP · From enrichment* on the value page. |
| E6 | **What did not come back.** | **One `graph.notifier.warning` per run**, listing each module that gave nothing and why, and each capped answer. A run where no module answered throws with their reasons. No pivotick change: the notifier is already the explorer's, and the stored failure shows in the facet label next time. |
| E7 | **Legacy text modules, and modules that are not enrichment.** | **A legacy element lands as its first listed type**, flagged untyped by the module, with its other types in the sidebar; an ip-src/ip-dst duplicate against a typed module's answer is accepted. **A shipped deny-list, `ModuleRole`**, removes the modules that are not enrichment — submitters and uploaders (they send a sample out, with side effects), document transforms, query builders and validators — with a profile override like `ModuleLocality`'s. The Value Intelligence's tab honours it too. |
| E8 | **Saving into the event.** | **Not this pass** at first; taken up and ruled 2026-09-30 in §10 (S1–S8). The value page has no event to save into, so it declares no `save`. |
| E9 | **Potential.** | **No rim badge for enrichment**, stored answer or not. |
| E10 | **Many origins.** | **5 calls in flight; at most 25 asked pairs** (node × module) per run, stored answers not counted. Over it, `fetch` refuses **before any call**, with the number, the limit and the way out. `maxCandidates: NODE_BUDGET` as every other pivot. |
| E11 | **Readers who may not run modules.** | **No `perm_add`, no *Enrich*** — `appliesTo` returns nothing and the endpoints refuse. Among the shipped roles only *Read Only* lacks it, and a role's permission tier 0 is what clears it (`Role.php:52`, `:80`). |
| E12 | **The analyst profile's declarations.** | **`ticked` and `auto` pre-tick; `never` removes the module from the facet.** Nothing runs without a press on the graph. |
| E13 | **A result that is known.** | **Its sidebar value links to `/values/view/<b64>`** (new tab) and is a hover-card trigger (`MISP.value_hover_card`), as an object attribute's value is — **only when `known`**. Unknown values get neither. A *Where this is in MISP* pivot stays out. |

## 5. Design

### 5.1 Server

**`app/Lib/Tools/ModuleRole.php`** — a shipped list of modules that are not enrichment, in
`ModuleLocality`'s style, with the analyst profile able to override it per module.
`enrichmentEligible` drops them, so the Value Intelligence and the graph agree.

Three JSON actions on `ValuesController`, ACL `perm_add` (E11), each resolving through the
engine with no new engine code:

- `GET /values/enrichmentTypes.json` → `{types: {<type>: [module names]}, modules: {<name>:
  {format, description}}, profile: {ticked: {<type>: [names]}, never: {<type>: [names]}}}`.
  Expansion modules only (E2), `ModuleRole` applied (E7), `auto` folded into `ticked` (E12). One
  `getEnabledModules` per page.
- `POST /values/enrichmentStored.json` with `{items: [{value, type}]}` → for each item, per module,
  the stored answer's `state`, `ran_at`, `total`, and whether it is fresh. A store read only.
  Items the user holds no visible attribute for come back empty, as if never asked.
- `POST /values/enrichmentRun.json` with `{value, type, module, mode}` → the shaped answer (§3).
  `session_write_close()` first, as the Value Intelligence does. The value must be one the user can
  see under that type (`enrichmentOccurrence`), or the answer is `ineligible`.

### 5.2 The pivot

```js
{
    id: 'enrich', label: 'Enrich',
    appliesTo: nodes => canRun ? nodes.filter(n => typesOf(n).some(t => typeMap[t])) : [],
    summarize: async (nodes, narrowing) => /* enrichmentStored for the origin */ ({
        total: /* stored totals of the ticked modules */,
        facets: [{ key: 'module', label: 'Module', type: 'multiselect',
                   options: /* eligible, minus `never`; label = name + stored-state suffix,
                               count = stored total */,
                   default: /* profile ticked/auto + fresh stored */ }]
    }),
    fetch: (nodes, narrowing, ctx) => /* refuse over 25 asked pairs; else pairs 5 at a time,
                                         ctx.signal forwarded; one toast for what did not come */
    maxCandidates: NODE_BUDGET
}
```

In the shared kit, so both hosts list it. `typesOf(n)` is the attribute's type, or every type a
value node is held as. No `save` (E8), no `autoIngest`, no `setPotential` (E9).

### 5.3 Landing

| Result | Lands as | Joined by |
|---|---|---|
| `attributes[]` | attribute node `enr:<type>:<value>` — **except the echo** of the origin's own value and type, which is dropped | `enrichment` edge from the origin, label = module |
| `objects[]` | closed object node `enr-obj:<module>:<hash>`, its attributes as its own children | `enrichment` edge from the origin |
| `elements[]` | attribute node `enr:<first type>:<value>`, flagged untyped | `enrichment` edge from the origin |

The node data carries `scope: 'module'`, the module name, `known`, the other candidate types of an
untyped element, and whether the answer came from the store and how old it is. The sidebar shows
them; a `known` value is a profile link and a hover-card trigger (E13).

### 5.4 Look

**Picked in phase B (2026-09-30): candidate B, a mark on the node**
(`prd/pivot-enrichment/candidates/b-mark/`).

- **The node** is drawn by `misp-pivot-nodes` exactly as MISP's own attribute or object, and wears
  **one pivotick badge at `ne`**: a white `fa-wand-magic-sparkles` (the icon MISP's UI already
  puts on enrichment) on a disc of MISP's `--bs-enrichment` hue, lightened to read on the canvas
  — `#6A6396` light, `#8C84B5` dark. Same mark on every result of every kind. `ne` because none of
  the explorer's badges (analyst `nw`, feed hit `sw`, tags `se`) can land on a result, and edges
  from the origin arrive from the upper left and cover `nw` at S.
- **Its `title`**: *From enrichment — <modules>*, *Not in MISP: a module said this*, plus
  *Untyped* and *Stored answer, N h ago* when the data says so.
- **A group** (Simplify) wears the mark only when every member is a result. The explorer's group
  key gains `scope`, so a group never mixes MISP records with results.
- **The `enrichment` edge**: solid, 1.25 px, the same violet, labelled with the module. Solid
  because dashes already mean correlation, feed, server and tag.
- **The legend**: *From enrichment* takes the violet, *In MISP* a neutral grey.

**Against v16 D2c** ("from another event" gets no canvas encoding): the mark does not fade, tint or
restyle the node, so D2c's objection — a cue that judges the subject — does not apply; it states a
fact about the data, that MISP does not hold it. Phase B drew D2c's own answer (candidate A, the
edge alone) beside it: it fails whenever the edge is not drawn — the `enrichment` legend row
toggled off, focus mode, a result dragged away — and the results become MISP's nodes.

**Library asks** (pivotick, `prd/misp/`), both shipped in `e2537f0` and vendored in MISP:
`focus-tier-keeps-badges.md` — the hover/selection card now wears the node's badges;
`legend-entry-icon.md` — a legend entry takes a `badge`, so *From enrichment* shows the mark
itself. `badge-screen-size-floor.md` (the mark is a 3 px dot at zoom 0.5) was **declined**: the
mark stays in world units.

**Wiring gotcha:** a legend section whose `entries` function returns `[]` makes pivotick derive
entries of its own (the Element list, repeated). The value page's Provenance section must return
its two entries whenever it is shown, not an empty list before results land.

### 5.5 What did not come back

One toast per run (E6). The states that are not results: `silent` → "answered with nothing";
`error` → the module's message; `timeout`, `unreachable` → as the Value Intelligence words them;
`refused` → "MISP's enrichment workflow declined the query"; a `capped` answer → "*module*: 200
of 1,374 shown". The refusal over the pair cap reads: "30 module queries would be sent; 25 at most per
run — untick modules or select fewer nodes." Nothing a user may not see is counted or hinted at.

### 5.6 Cost

A module is asked at most once per value, type and organisation within the freshness window,
whoever asks, from the graph or the Value Intelligence. Each ask holds one PHP worker for up to the
timeout; 5 at once is what the Value Intelligence already accepts. The module server is asked for its
module list once per page, not once per node.

### 5.7 Saving (later pass — taken up in §10)

When E8 is taken up: `save` builds the MISP-format JSON of the ingested nodes still unsaved and
posts it to `handleModuleResults` for this event — event-page host only, only where the origin
attribute is this event's own and the user can modify it. The library's ledger then counts and
offers them.

## 6. Out of scope

- A *Where this is in MISP* pivot (E13). Writing results into an event is §10.
- Hover-only and cortex modules (E2), object-input modules (E3), per-query module options
  (`userConfig`): no expansion module declares one, and letting a reader set `meta.config` is a
  credential leak.
- Auto-running modules on the graph (E12), enrichment potential badges (E9).
- Enrichment of events, objects as a whole, tags or clusters.

## 7. Acceptance

Against the dev instance, logged in, dev server on this worktree:

1. On an event with an IP attribute, *Enrich* is offered on it and not on an object or event node;
   on the value page it is offered on the value node.
2. The Module facet lists only expansion modules that accept the type — no submitter, uploader or
   transform — each with its stored state, and starts with the profile's and the fresh ones ticked.
3. A run with two modules, one answering and one not, lands the first's results joined by
   `enrichment` edges, and one toast says why the second did not.
4. Running the same module again inside the freshness window answers from the store, without
   asking the module server.
5. The Value Intelligence's Enrichment tab for that value shows the graph's run.
6. A Read Only user is not offered *Enrich*, and `enrichmentRun.json` refuses them.
7. Undo takes the landed results away; the stored answer stays.
8. A legacy module's elements land as untyped attributes; none is dropped.
9. The same record returned from two origins lands as one object node with two edges.
10. Asking more than 25 pairs is refused before any module is called.
11. *From enrichment* in the Provenance legend hides every result, on both hosts.

**Run 2026-09-30** on the dev instance (this worktree served), event 46 and the value page of
`8.8.8.8`, light and dark:

| # | Result |
|---|---|
| 1 | ✅ live on both hosts; object and event nodes refused by `appliesTo` (unit) |
| 2 | ✅ `enrichmentTypes` offers ipasn, whois, mmdb_lookup, circl_passivedns for `ip-dst`, no transform; labels `ipasn — 9 days ago (2)`, `whois — failed 16 days ago`. The admin's profile ticks three, so they start ticked though none was fresh |
| 3 | ✅ ipasn + mmdb_lookup landed 5 objects and 5 edges; one toast: *whois: Whois local instance address is missing* |
| 4 | ✅ the second run read ipasn from the store (`mode: stored`); the sidebar said *Stored answer, just now* |
| 5 | ✅ the graph's run rewrote the organisation's rows in `value_enrichment_runs`, which the tab reads |
| 6 | ✅ at the ACL (no Read Only user on the instance): `perm_add=0` is refused all three endpoints, the tab stays readable; both hosts take `canEnrich` from that same answer |
| 7 | ✅ value page: 23 result nodes, 0 after undo; the store keeps them |
| 8 | unit only — no enabled module answers in the legacy format |
| 9 | ✅ unit (one mmdb record for two origins: one node, two edges) |
| 10 | ✅ unit (27 asked pairs refused, no call made) |
| 11 | the entry is present on both hosts, with the mark; the value page's section appears only once results land. Toggling it was not exercised — it is pivotick's legend filter over the entry's predicate |

## 8. Phases

- **A — Contract.** ✅ Grilled 2026-09-30; rulings in §4, JSON frozen in §5.1.
- **B — Prototypes.** ✅ B picked 2026-09-30 (§5.4). One round, three cold-built candidates for the result node's *From
  enrichment* look and the `enrichment` edge — **A** the edge alone (D2c-consistent), **B** a mark
  on the node, **C** a drawing of its own. Kit in `prd/pivot-enrichment/` (`brief.md`, `frame.html`,
  `capture.mjs`): the value page's full graph on `8.8.8.8` with the real vendored stack, and a
  fixture-backed *Enrich* pivot (`enrich-baseline.js`, §5.2–§5.3 as ruled) run on the centre from
  answers recorded through `forEnrichmentRun(mode=stored)` — mmdb_lookup, ipasn, whois (error),
  and circl_passivedns (199 objects, 200 of 1,376) as the stress case. Kept local. The facet and
  toast wording are settled here, not prototyped.
- **C — Wiring.** ✅ 2026-09-30. `ModuleRole`, the endpoints, the pivot, the sidebar, tests,
  acceptance (§7).

## 9. Files (expected)

| File | Change |
|---|---|
| `app/Lib/Tools/ModuleRole.php` | new: the non-enrichment deny-list (E7) |
| `app/Model/ValueIntelligence.php` | `enrichmentEligible` drops `ModuleRole`'s modules; array forms for the three actions |
| `app/Controller/ValuesController.php`, `app/Controller/Component/ACLComponent.php` | `enrichmentTypes`, `enrichmentStored`, `enrichmentRun` + ACL |
| `app/webroot/js/pivot-explorer.js` | the pivot in the kit, landing, `enrichment` kind and style, `scope: 'module'` legend and facet, the result badge in `nodeBadges` and on groups, `scope` in the Simplify group key |
| `app/webroot/js/value-neighbourhood.js` | list the pivot; the provenance legend when module results exist |
| `app/webroot/js/pivot-sidebar-model.js` | module, stored age, untyped types, `known` links |
| `tests/js/pivot-explorer-graph.test.js` | the pivot, ids, landing |

## 10. Saving into the event (E8)

### 10.1 What the analyst sees (proposed)

On the event page, for a viewer who may modify the event, the Enrich pivot's results can be
saved. Right-click one and pick **Save this element**, or select several and pick **Save
selection**; the pivot panel offers no Save (S7). Save writes them into this event: an object
result becomes a MISP object, a loose result a MISP attribute, each tied back to what it was run
on where MISP can say so. A toast reports *Saved 12* or *Saved 9 of 12 — Retry*, and why.

A saved result stops claiming *Not in MISP*: it is this event's now. Undo after a save takes it
off the canvas only; the event keeps it. The value page, and a viewer who may not modify the
event, see no Save and no unsaved count — the results stay the canvas's only, as today.

### 10.2 Measured 2026-09-30

- **Pivotick has the whole door** (`~/git/pivotick/prd/pivot-persistence.md`, built): `save` on
  the definition, a per-element ledger, `unsavedCount`, a panel/pane Save, partial outcomes with
  Retry, `canonicalIds` so a re-run dedups against what was saved, `pivotMarkUnsaved`. Vendored
  in MISP. **Savability is per pivot**, not per run (`PivotManager.savable`): every run of a
  pivot that declares `save` is enrolled.
- **`handleModuleResults` does not fit.** It goes through `processModuleResultsDataRouter`,
  which queues a background job when `MISP.background_jobs` is on and answers "queued"; either
  way the answer is a flash string, with no per-element outcome and no ids.
- **`processModuleResultsData` fits, called synchronously.** It keeps the client's `uuid`s, so
  the graph can mint them and know every canonical id up front; an attribute the event already
  holds (same type and value) fails as a duplicate and the model finds the existing one.
- **The stored answer is not writable as it is.** `enrichmentObject` keeps name, meta-category,
  description, comment and attributes; it drops `template_uuid` / `template_version`, which
  `MispObject` requires on create, and the module's `ObjectReference`s and `uuid`s.
- **Graph ids of MISP records** are `attr:<uuid>` and `obj:<uuid>`; the event page's `canEdit`
  is `Acl->canModifyEvent`, and `isOwnElement` says whether a node is this event's.
- **A reference starts from an object.** A loose attribute can be referenced, but cannot
  reference anything.

### 10.3 Decisions — ruled 2026-09-30

S3, S4, S6 and S7 were put to the owner; S1, S2, S5 and S8 stand as proposed.

| # | Question | Ruling |
|---|---|---|
| S1 | **Server path.** | **A new synchronous JSON action, `POST /events/saveEnrichment/<id>.json`**, ACL `perm_add` + `canModifyEvent` (as `handleModuleResults`). Takes MISP-format `Attribute[]` / `Object[]` / references with client uuids; resolves each object's template by name; calls `processModuleResultsData` (never the router); answers per uuid: `saved`, `existing` (with the uuid already in the event) or `failed` with a reason. |
| S2 | **Where it is declared.** | `save` only when the host has an event and `canEdit`; otherwise the pivot has none and nothing is counted (P5). `autoSave: false`. |
| S3 | **An origin that is not this event's** (a correlated attribute of another event). | **Saved into this event unattached** — no reference, the comment names the origin value. Otherwise those runs count as unsaved forever, since savability is per pivot. |
| S4 | **The link to the origin.** | **Asked on Save, `related-to` picked by default** — one prompt per save, the relationship list the reference editor offers. Result object → origin (attribute or object): an object reference on the result object. Origin object → loose result: a reference on the origin object. Loose origin → loose result: none is possible; the comment carries it. The `enrichment` edge is reported saved in every case. Cancelling the prompt writes nothing. |
| S5 | **Fields.** | Distribution: the instance's attribute default, as module results get today. `to_ids`, category and comment from the module; an empty comment becomes `Enrichment: <module> on <origin value>`. No prompt. |
| S6 | **After a save.** | `canonicalIds`: `enr:*` → `attr:<uuid>`, `enr-obj:*` → `obj:<uuid>`; a duplicate aliases to the attribute already there. **A saved result becomes a plain MISP node**: its data gains the uuid and this event's scope, and loses `module` scope, so the *From enrichment* mark, the Provenance entry and the sidebar's enrichment block no longer apply. The `enrichment` edge keeps its label. The event index learns the new uuids, so the reference editor can start from a saved object. |
| S7 | **The affordance.** | **The context menu only** (re-ruled 2026-10-01): *Save this element* in the node menu, *Save selection* in the library's selection menu, each offered when what it names holds a savable, unsaved result. **Not the pivot interface**: the panel's and the triage pane's Save write a whole run or provider with no way to pick, so they are not offered (library ask `save-controls-off.md`). `pivotMarkUnsaved` off — the enrichment mark already sets results apart. |
| S8 | **Undo.** | Canvas-only after a save (pivotick P13); nothing is deleted from the event. |

### 10.4 Library asks

In `~/git/pivotick/prd/misp/`:

- `save-a-selection.md` — `graph.pivots.save({ elements })` writes only the named elements
  (their children and edges with them) and leaves the rest of each run pending. **Shipped in
  `a1e22d0`** (2026-10-01). Both menu entries call it with only the unsaved results they name,
  `{ interactive: true }`, so the relationship prompt opens. Several selected nodes get the
  library's own selection menu, not the node menu, so *Save selection* is a `menuSelection` entry.
- `save-controls-off.md` (2026-10-01) — `pivotSaveControls: false`, so the panel and the pane
  draw no unsaved count and no Save while the ledger and `save(...)` keep working. **Shipped in
  `592a357`** and set by the explorer.
- `save-context-prompt.md` — `PivotSaveContext.promptData`, the modal edge creation already
  has, and a cancel outcome that is not a failure. **Shipped in `73f7673`** (2026-10-01): a save
  nobody clicked gets `null` at once, so `graph.pivots.save()` from the console needs
  `{ interactive: true }` to be asked.

**S4 as built.** The prompt — *Save to this event*, the editor's own relationship fields
(`relationshipFields`, now shared with it), `related-to` preselected, a custom one winning —
opens only when the save would write a reference; an unattached save (S3, loose → loose) asks
nothing. An empty answer is `related-to`. Cancel returns `{ cancelled: true }`: nothing is
posted, the run stays pending, no toast.

### 10.5 Phases

| Phase | Status | Note |
|---|---|---|
| D1 — endpoint `saveEnrichment` + ACL (S1) | ✅ | `perm_add` + `theming_enabled`, `canModifyEvent` in the action, CSRF by header |
| D2 — `save` on the Enrich pivot, panel Save (S2–S6, S8) | ✅ | |
| D3 — relationship prompt (S4) | ✅ | 2026-10-01, on pivotick `73f7673` (vendored) |
| D4 — *Save this element* / *Save selection* in the context menu (S7) | ✅ | 2026-10-01, on pivotick `a1e22d0` (vendored) |
| D6 — no Save on the pivot panel or triage pane (S7) | ✅ | 2026-10-01, `pivotSaveControls: false` on pivotick `592a357` (develop, vendored) |
| D5 — tests, acceptance | ✅ | explorer 802/0 (5 new); §10.7 |

### 10.6 As built

- **`POST /events/saveEnrichment/<id>.json`** takes `{Attribute[], Object[] (each with
  ObjectReference[]), ObjectReference[]}` and answers `{results: {<sent uuid>: {state, uuid}},
  message}`, `state` ∈ `saved` · `existing` · `failed`. Only `uuid, type, category, value, to_ids,
  comment` (and `object_relation` inside an object) are read; distribution is the instance default.
- **The template** is the active one named like the object, latest version; none → `failed`.
- **What counts as written is read back** from the database by uuid, not trusted from the
  import's counters. `processModuleResultsData` gained an optional `&$outcome` (`recovered`,
  `failed`) for the attribute an event already holds.
- **A saved object is not written twice.** `processModuleResultsData`'s own match compares raw
  values and misses a normalised one (`last-seen` stored as `…T08:00:00.000000+0000`, sent as
  `…T08:00:00`), which wrote duplicates on a second save. The endpoint asks
  `MispObject::duplicateObjectUuid` (new, over the existing `checkForDuplicateObjects`) first,
  after filling each attribute's default category so the hashes compare like with like; a match
  is `existing`, and gains this origin's reference if it lacks it.
- **Client.** The graph mints v4 uuids (`getRandomValues`), so every canonical id is known up
  front: `obj:<uuid>`, `attr:<uuid>`, or the uuid the event already holds. An adopted node gets
  `scope: 'self'` and loses its module fields, the event index learns it, and handing the graph
  its own nodes back (`graph.updateData`) makes the legend recount.
- **An object's attributes are saved with it**, never alone: a child failing validation does not
  keep the object unsaved in the ledger; the toast carries the server's message.

### 10.7 Acceptance — run 2026-09-30

On event 46 (`ip-dst 8.8.8.8`, its own), dev server on this worktree, `ipasn` from the store:

| # | Check | Result |
|---|---|---|
| 1 | After ingest the panel shows *10 unsaved · Save* | ✅ |
| 2 | Save writes 2 `asn` objects (template v6, distribution 5, comment *Enrichment: ipasn on 8.8.8.8*), their 6 attributes, 2 `related-to` references to the origin | ✅ read back from the database |
| 3 | Toast *Saved 8 nodes and 2 edges*; nothing pending; the nodes draw as plain MISP objects; the legend recounts | ✅ |
| 4 | A second save from a fresh page answers `existing` for both, aliases to the first uuids, writes no object and no reference | ✅ (after the fix above) |
| 5 | Not savable without `canEdit`, nor on the value page (no event) | ✅ unit |
| 6 | Foreign origin unattached; origin object → loose result reference; a failure stays unsaved | ✅ unit |
| 9 | 2026-10-01: after ingesting ipasn's results the panel shows no unsaved line and no Save, the pane only *2 ingested*; the ledger still counts 8 nodes, 2 edges, and *Save this element* is offered | ✅ live; unit 818/0 |
| 8 | 2026-10-01: of 5 results (ipasn + mmdb_lookup), *Save this element* writes one object; *Save selection* on two others writes those two; 9 nodes, 2 edges stay pending; each reference `related-to` | ✅ live; unit 817/0 |
| 7 | 2026-10-01: Save opens *Save to this event* with `related-to` preselected; Cancel posts nothing and leaves 8 nodes, 2 edges pending; a custom `announced-by` is written on both references | ✅ live; unit 811/0 |

The objects were removed afterwards; the event stays unpublished, as a save leaves it.

### 10.8 Left as is

- **S9 — a saved result and the event's own copy of it.** On a fresh page the event's own copy of a
  saved object is drawn from the event, and Enrich lands its result beside it (E4: a result is
  never merged into a MISP node). A save then answers `existing`, and the canvas holds two nodes
  for one MISP object. Either a result the event already holds lands as that MISP node, or it is
  left out of the fetch. **Ruled 2026-10-01: left as is for now** — two nodes for one object
  is acceptable; revisit if analysts report it.
