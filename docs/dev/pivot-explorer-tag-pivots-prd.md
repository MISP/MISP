# PRD: From a tag or cluster to the rest of the instance

**Status:** BUILT 2026-09-25 — decided in review the same day; T7–T9 settled while building (§3).
**Owner:** Sami Mokaddem (Claude-assisted)
**Created:** 2026-09-25
**Parent:** [`pivot-explorer-v16-prd.md`](pivot-explorer-v16-prd.md). Builds on task 30 in
[`pivot-explorer-v16-progress.md`](pivot-explorer-v16-progress.md).

---

## 1. Why

Task 30 made tags and galaxy clusters visible in the Pivot Explorer. Attributes and events carry
them, the sidebar lists them, and the **Tags & clusters** pivot draws one node per tag or cluster,
joined to every element on the canvas that carries it.

Those nodes are dead ends today. An analyst looking at `APT28` on the canvas cannot ask the two
questions it invites:

- **Where else does this appear?** Which other events carry the tag or cluster.
- **What is it related to?** Which clusters the galaxy says it `uses`, is `similar` to, is a
  `subtechnique-of`, and so on.

This PRD adds one pivot for each.

### State

| Part | Status | Note |
|---|---|---|
| `POST /events/taggedEvents/{id}.json` | ✅ | `Event::taggedEventCards()`; per-event `matched` (T7) |
| `GET /galaxy_clusters/relatedClusters/{id}.json` | ✅ | `GalaxyCluster::outboundRelations()` |
| ACL entries | ✅ | `findMissingFunctionNames` empty on both controllers |
| *Events with this tag* pivot | ✅ | summarize and fetch share one request |
| *Related clusters* pivot, `cluster-relation` edge kind | ✅ | |
| Unit tests | ✅ | 545 assertions |
| PHP access tests | — | `app/Test` holds only tool tests, no endpoint pattern; access checked live instead (§7) |
| Full total in the summary (T8) | ⏸ | library gap, `~/git/pivotick/prd/pivot-summary-window.md` |
| Acceptance (§7) | ✅ | 3's full total is in the response, not yet on screen (T8) |

## 2. What the analyst sees

Select a tag or cluster node and open *Pivot ▸*:

- **Events with this tag** — on tag and cluster nodes. Other events land as event cards (the same
  card the correlation and feed pivots draw), each joined to the tag node it carries. When the
  event carries the tag only through one of its attributes, the edge says `via attribute`.
- **Related clusters** — on cluster nodes only. The clusters this cluster's galaxy points at land
  as cluster nodes, each edge labelled with the relation (`uses`, `similar`, …) and pointing away
  from the selected cluster.

Whatever any pivot lands is also joined to the tag and cluster nodes already on the canvas that it
carries, and a tag or cluster node that lands is joined to every carrier already drawn. The order
things reached the canvas in does not decide their links (T10).

Neither pivot is offered on attributes, objects or events directly. The path is always
element → *Tags & clusters* → tag node → one of these, so every event or cluster that lands has
the tag or cluster node it came from to attach to.

## 3. Decisions

Settled in review on 2026-09-25.

| # | Question | Decision |
|---|---|---|
| T1 | What lands from a tag or cluster | **Other events, as cards.** Not the tagged attributes inside them: from a card, the correlation and element pivots go deeper. |
| T2 | A tag on thousands of events (`tlp:white`) | **Newest 200 by `timestamp`**, the total stated in the summary, rows ticked in Review. No run is refused and no namespace is excluded. |
| T3 | Cluster relations: which direction | **Outbound only** — the relations stored on the selected cluster. See §6.2 for what that leaves out. |
| T4 | Several tag nodes selected | **Intersection by default** — events carrying all of them — with **union** as a narrowing option. One tag behaves the same either way. |
| T5 | Where the pivots are offered | **Only on tag and cluster nodes.** |
| T6 | Event-level vs attribute-level carrier | **Label only the attribute case** (`via attribute`); a directly tagged event draws a plain edge. |
| T7 | Who decides event- vs attribute-level (built) | **The server**, per event and tag, in `matched`. The card's `Tag` list cannot: `attachClustersToEventIndex(…, true)` moves every visible cluster's tag out of it, so a directly tagged cluster would read `via attribute`. It also makes union one request instead of one per tag. |
| T8 | A total beyond the 200 (built) | **The summary says at most 200**; the endpoint's `total` keeps the real number. The library judges `maxCandidates` on the summary's `total` and has nowhere else to put a count, so 4,812 would refuse the run T2 promises. Showing both waits on the library. |
| T9 | A cluster reached through another event's card (built) | **The card's clusters carry `tag_name` and `uuid`**, so they key and pivot like any other cluster node. |
| T10 | A carrier landing after its tag is drawn (built) | **Every pivot's result gains the tag edges to drawn nodes**, both ways. Each is a carried edge, so it lands with its node and is undone with it. Before this, an event landing after its tag node stayed unjoined. |

## 4. Pivot 1 — Events with this tag

### 4.1 Endpoint

`POST /events/taggedEvents/{id}.json`, where `{id}` is the event the explorer is open on.

```json
{ "tags": ["misp-galaxy:threat-actor=\"APT28\"", "tlp:amber"], "mode": "and" }
```

Response — `events` is a list, newest first:

```json
{
  "total": 4812,
  "events": [
    { "id": "812", "uuid": "…", "info": "…", "Orgc": {…}, "Tag": [ … ], "Galaxy": [ … ], …,
      "matched": { "misp-galaxy:threat-actor=\"APT28\"": "event", "tlp:amber": "attribute" } }
  ]
}
```

- **Matching.** For each tag name, the event ids from `event_tags` ∪ `attribute_tags` (live
  attributes in live objects). `mode: "and"` intersects the per-tag sets, `"or"` unions them.
  Unknown tag names match nothing, which under `and` means no events. `matched` names, per
  event, each asked-for tag it carries: `event` when the event carries it, else `attribute`.
- **Access.** Only events the user may see, via `Event::createEventConditions()`, the same as
  every other explorer endpoint; only attributes they may see count as a match
  (`MispAttribute::buildConditions()`), and only tags they may use (`Tag::createConditions()`).
  The event `{id}` itself is left out.
- **Order and cap.** `ORDER BY Event.timestamp DESC LIMIT 200`. `total` counts every event that
  matched and is visible, before the cap.
- **Cards.** Built by the existing `Event::correlatedEventCards()`, so the card is identical to a
  correlated event's. Its `Tag` list lacks visible cluster tags, hence `matched` (T7); its
  `Galaxy` clusters now carry `tag_name` and `uuid` (T9).
- **Why not `/events/index`.** Its `tags` filter unions event and attribute tags only in OR mode;
  its AND branch reads `event_tags` alone, so it cannot answer T4's default.

**Cost, measured 2026-09-25** (admin, machine at load 3.7): `tlp:white` (3,622 events) 0.36 s;
`tlp:clear` 1.6 s; `exe`, the instance's heaviest attribute tag (425,561 attribute tags over
267 events), 2.2 s; `exe` ∧ `tlp:white` 1.7 s. The time goes on reading attribute tags, not on
intersecting, so intersecting in SQL would not help. A hub attribute tag is where to look if
it matters.

### 4.2 Client

- **`appliesTo`** — tag and cluster nodes. A cluster queries by its `tag_name`, a tag by its
  `name`.
- **`summarize`** — calls the endpoint and returns `{ total }`, capped at 200 (T8), plus one
  narrowing facet: `mode`, *Match*, a select of *All of them* or *Any of them*, shown only
  when more than one node is selected. Left unset, it means all of them.
- **`fetch`** — the same call; the last question's promise is kept, so summarize then fetch
  is one request. Each event lands as `event:<uuid>` with `eventNodeData(card)`; one already
  on the canvas merges by id. For each selected tag node the event carries per `matched`, one
  edge `event → tag node`, kind `tag`, with the Tags & clusters pivot's edge id:
  - label `''` when `matched` says `event`;
  - label `via attribute` when it says `attribute`.
- Union is one request like intersection: `matched` lists only the tags each event carries.
- `maxCandidates` is the canvas budget like every other pivot, no `save`, no rim potential.
  The count needs a request, and declared potential is never queried (v16 task 15).

## 5. Pivot 2 — Related clusters

### 5.1 Endpoint

`GET /galaxy_clusters/relatedClusters/{uuid}.json` — outbound relations of one cluster.

```json
{
  "relations": [
    { "relation": "similar",
      "cluster": { "id": "47753", "uuid": "…", "value": "APT28 - G0007",
                   "type": "mitre-intrusion-set", "galaxy_name": "MITRE ATT&CK Groups",
                   "tag_name": "misp-galaxy:mitre-intrusion-set=\"APT28 - G0007\"" } }
  ]
}
```

What the existing code does and does not give:

- `/galaxy_clusters/view/{id}.json` returns `GalaxyClusterRelation` **without** the target
  cluster. Only the HTML `viewRelations` attaches targets, through
  `GalaxyCluster::attachClusterToRelations()`, one fetch per relation.
- **Target uuids are not unique.** APT28's `similar` target *APT28 - G0007* has one uuid shared by
  four MITRE galaxies (enterprise, mobile, pre-attack, intrusion-set). Resolving by uuid, as
  `attachClusterToRelations()` does, picks one of them arbitrarily. Resolve by
  `referenced_galaxy_cluster_id`, which names exactly one, in a single batched fetch.
- **Access.** The source cluster through `fetchIfAuthorized($user, $uuid, 'view')`. Each relation
  is kept only if the user may see the relation (its distribution) and its target cluster.
  `fetchGalaxyClusters($user, …)` applies the cluster side.
- A relation whose target is not on this instance (id 0, or a galaxy not installed) is dropped,
  as is one whose target is deleted.
- **Duplicate sources.** The dev instance holds the threat-actor *APT28* twice (72579, 72580),
  same uuid, same tag. `fetchIfAuthorized` by uuid picks one; both carry the same four
  relations, so it does not show.

### 5.2 Client

- **`appliesTo`** — cluster nodes with a `uuid`. Clusters parsed from a bare tag name have none
  (task 30). The endpoint could also accept a `tag_name`, but only once a real case needs it.
- **`summarize`** — `{ total: relations.length }`, one request per cluster, kept for the
  session. The counts are small (APT28's threat-actor cluster: 4; its intrusion set: 124 of
  125 stored), so no cap beyond the canvas budget.
- **`fetch`** — each target lands as `cluster:<tag_name>`, so it merges with a cluster node the
  Tags & clusters pivot already drew. One edge per relation, `selected → target`, kind
  `cluster-relation`, label the relation type. A relation onto the selected node's own tag
  draws nothing.
- A new edge kind, `cluster-relation`: its own entry in `edgeStyleMap`, `KIND_LABELS`
  (*Galaxy relation*) and the Relationship legend. Solid, in the galaxy hue, since it is an
  authored assertion rather than a derived one.

## 6. Scope

### 6.1 In

The two endpoints and the two pivots above, their ACL entries (check with
`findMissingFunctionNames`), unit tests in `tests/js/pivot-explorer-graph.test.js`, and a PHP
test for each endpoint's access rules if the suite has a pattern for it.

### 6.2 Out, knowingly

- **Inbound cluster relations (T3).** MISP stores a relation once, on the cluster whose galaxy
  declared it. Measured on the dev instance: `parent-of`/`child-of` are fully mirrored, `similar`
  mostly (3,605 of 5,059), `uses` almost never (566 of 19,247). So from a technique or malware
  cluster, *who uses it* is nearly always inbound and this pass will not show it. If that is
  needed, draw each inbound relation as stored (arrow from the declaring cluster, never an
  invented `used-by`), behind T2's cap.
- **The tagged attributes themselves (T1).** Reached from the event card with existing pivots.
- **A pivot straight from an element (T5).**
- **Excluding namespaces** such as `tlp:*` or `pap:*` (T2). The count in the summary does that job.
- **Tagging or untagging from the canvas.** Deleting a `tag` edge stays canvas-only (task 30).

## 7. Acceptance

1. On event 4242, selecting the `mitre-attack-pattern` cluster nodes and running *Events with
   this tag* lands only events carrying all of them. Switching to *Any of them* lands the union,
   with one edge per tag each event actually carries.
2. An event matched only through an attribute draws its edge labelled `via attribute`; a directly
   tagged one draws it unlabelled.
3. `tlp:white` (or the instance's most used tag) states its full total, lands at most 200 events,
   newest `timestamp` first. Its request time on the dev instance is measured and recorded in the
   tracker.
4. The open event never lands as its own card.
5. *Related clusters* on APT28 (threat-actor) lands its visible `similar` targets, each resolved
   to the right galaxy, merged with any cluster node already on the canvas.
6. A reader who cannot see an event or cluster never receives it, and no count includes it.
   Check with one of the lesser dev readers.
7. Unit suite green; tracker row added in the same commit as the code.

### Results, 2026-09-25

1. ✅ On 4242, the four `mitre-attack-pattern` clusters under *All of them* land 21 events,
   the count SQL gives, each with 4 edges. *Any of them* lands the same 21: those events carry
   all four.
2. ✅ All 84 of those edges read `via attribute`: on 4242's clusters every match is on an
   attribute. The event-level case is in the unit suite, and live in `matched` for
   `tlp:white`, where 199 of the 200 returned cards say `event`.
3. ✅ in the response, ⏸ on screen: `tlp:white` returns `total` 3,623 and 200 cards, newest
   `timestamp` first, in 0.36 s. The panel shows ~200 (T8).
4. ✅ 4242 is in none of the results.
5. ✅ From APT28 (threat-actor) on 1525's canvas: four `similar` targets, *APT28 – G0007* in
   `mitre-intrusion-set` out of the four galaxies sharing its uuid, merged with the node
   already drawn (3 ingested, 1 already on canvas). The APT28 node was put on the canvas by
   hand: 1525 carries it on the event, which the canvas does not draw, and 1525 is not among
   the newest 200 of any tag another event shares with it.
6. ✅ `orgadmin@circl.lu` gets 1,760 of admin's 3,623 on `tlp:white`. Counting by
   distribution alone gives 1,761; the extra one is 1563, shared with a sharing group that
   org is not in.
7. ✅ 540 assertions.
