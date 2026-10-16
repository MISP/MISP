# PRD: Another event's card brings in part of that event, by kind

**Status:** Built 2026-09-27, live-checked on the dev DB. See §9 and §10.
**Owner:** Sami Mokaddem (Claude-assisted)
**Parent:** [`pivot-explorer-v16-prd.md`](pivot-explorer-v16-prd.md). Follows
[`pivot-explorer-correlated-object-prd.md`](pivot-explorer-correlated-object-prd.md), which
withdrew *Event contents* (its C5) and named the three expansions in its §6.

---

## 1. Why

Another event's card (B) reaches the canvas from a correlation, a tag or an analyst
relationship. Once there, the only pivot on it is *Tags & clusters*, and only if it carries
tags. The analyst who wants to know more about B has two routes left: its correlations, one
object at a time with *Around this object*, or leaving the canvas for B's own page.

*Event contents* used to fill that gap. It was withdrawn because it landed B wholesale: on
4120 that is 18,037 attributes. The card should instead answer the narrow questions an
analyst actually asks of another event:

- **What infrastructure does it name?** Its IP addresses, domains, URLs.
- **What does it say to block?** Its IDS-flagged attributes.
- **Where else does it touch my event?** The rest of its correlations with this event, not
  only the ones already followed.

Each is a small, typed slice of B, landed the way a correlation lands (in its object when it
has one), so the canvas stays readable.

## 2. What the analyst sees

On another MISP event's card (not this event's, not a feed's), the node menu and the Pivot
panel offer four pivots. Each advertises its count before running:

- **Its attributes:** B's attributes, narrowed by a form (search, IDS only, type, category).
- **Its IDS indicators:** the same form, limited to attributes flagged `to_ids`. A shortcut.
- **Its network indicators:** the same form, limited to the network types (§3 N1). A shortcut.
- **More correlations with this event:** every pair between this event and B, including the
  ones already on the canvas, which land again as no-ops.

What lands follows the correlated-object rules: an attribute inside an object brings that
object, closed, with its live attributes; an attribute with no object lands free; each is
joined to B's card by an `in-event` edge. Up to 25 new candidates land directly (task 35),
more go to Review, and more than 1,500 are refused until narrowed.

## 3. Decisions

| # | Question | Decision | Open |
|---|---|---|---|
| N1 | Which attributes are "network" | **Decided 2026-09-27.** An attribute whose type is on the list, in any category but *External analysis*, **or** one of the listed template fields whatever its type. See §3.1 | — |
| N2 | Presets or one pivot | **Decided 2026-09-27: both.** One *Its attributes* pivot with the full form, and *Its IDS indicators* / *Its network indicators* as shortcuts. Pivotick has no preset narrowing (a menu row is one pivot definition, and `quickPivot` always runs with `{}`), so each shortcut is its own pivot over the shared form, with its slice fixed. *More correlations* stays separate: another source, its count already known | — |
| N3 | The form, and what its options count | **Decided 2026-09-27.** Fields per pivot in §3.2. A facet option counts **matching attributes** (*ip-dst (40)*); the total counts **new landing units** and is the only number that gates the cap | — |
| N4 | What an object brings | **Decided 2026-09-27: all its live attributes**, as for a correlation (correlated-object C4), so an object is the same node whichever pivot brought it. Each child that matched carries a mark naming the pivot (`matched: ['ids']`), shown in the sidebar as *Matched: IDS indicators*; data only, no new drawing | — |
| N5 | What a count counts | **Decided 2026-09-27: new landing units.** Objects plus free attributes, leaving out those already on the canvas: the client sends the uuids of B's objects and attributes it holds (`exclude`), and the server leaves them out of the count and the fetch alike. Pivotick gates the cap on the count and the 25 quick limit on new rows, so the number read before a click is what the click adds, and a re-run says 0 | — |
| N6 | "With this event" or "with my canvas" | **Decided 2026-09-27: this event.** The canvas is anchored on it; correlating a third event's nodes with B is the general "correlate from a foreign node" tool, which nothing offers yet (§7 Out) | — |
| N7 | Selection of several cards | **Decided 2026-09-27: each card answers for itself and the counts add up.** One request per card, in parallel, for the count and for the fetch; what lands joins its own card; the cap applies to the sum and the shared form narrows every card at once. A per-card filter in the form is parked until the sum is refused often | — |
| N7b | What *More correlations* counts | **Decided 2026-09-27: new landing units, counted in the browser.** `summarize` fetches this event's pairs with B (`correlatedAttributes`, `event_ids: [B]`), builds the landing with `correlationResult` and counts the rows not on the canvas; the result is kept so the run lands it without a second request. No server change. The existing *Correlations* pivot keeps counting pairs | — |
| N8 | Feed event cards | **Decided 2026-09-27: out.** MISP keeps no copy of a feed event: `Feed::downloadEventFromFeed` pulls it from the feed's source on every read, so a count would download the whole event first, fail with the feed, and pull a 4120-sized event only to refuse it. The card keeps *Tags & clusters*. A local copy kept when *Feed events* lands the card is the route to revisit, in its own PRD | — |

### 3.1 Network indicators

**Types:** `ip-src`, `ip-dst`, `ip-src|port`, `ip-dst|port`, `domain`, `domain|ip`, `hostname`,
`hostname|port`, `url`, `uri`, `onion-address`. **Excluded category:** *External analysis*.

**Template fields,** matched by object template name and `object_relation` whatever the type,
because their templates store addresses as `text`:

| Template | Fields |
|---|---|
| `passive-dns` | `rrname`, `rdata` |
| `passive-dns-dnsdbflex` | `rrname` |
| `attacker-infra` | `beacon_host`, `hostname`, `http_url` |
| `shadowserver-beacon-ttl-report` | `hostname` |
| `shadowserver-beacon-url-overlap` | `hostname`, `url` |
| `intelmq_event` | `source.reverse_dns`, `destination.reverse_dns` |

`rdata` can hold a TXT record rather than an address; accepted as noise.

**Why category alone would miss them:** in the dev DB 196,149 `url` and 67,139 `domain`
attributes are filed under *Payload delivery*, and *Network activity* also holds user-agents,
ports and fingerprints. The ~10k *External analysis* URLs are mostly links to write-ups.

**Left out on purpose,** from a scan of the 373 shipped templates: `link` fields (always
references: blog posts, VirusTotal permalinks); `tsk-web-*` domains (what a victim browsed);
`cs-beacon-config` `http-url` (a path); `url`'s `domain_without_tld` and `subdomain` (fragments
of its `domain`); postal addresses and entry-point addresses.

**Where it lives:** one file, `app/Lib/Tools/PivotExplorer/NetworkIndicators.php`, three
constant arrays (types, excluded categories, template fields) and one method that turns them
into find conditions. The count, the fetch and the type facet all read it; the client never
carries the list. Adding a field is one line there.

### 3.2 The form

| Pivot | Search | IDS only | Type | Category |
|---|---|---|---|---|
| *Its attributes* | yes | yes | B's types | yes |
| *Its IDS indicators* | yes | fixed on | B's types among its IDS attributes | yes |
| *Its network indicators* | yes | yes | the network types B has | yes |

The search matches an attribute's value and comment and, inside an object, the object's name
and the attribute's `object_relation`. `value1`/`value2` are case-insensitive; the comment is
`utf8mb3_bin`, so that side is lower-cased on both ends. Bounded by `event_id`, it is an indexed
read even on 4120. The count mode returns `by_type` and `by_category` beside the total.

## 4. Scale

Measured on the dev DB, 2026-09-27 (live attributes; *free* = outside any object):

| Event | Attributes | IDS | Network activity | IP types | Free | Objects |
|---|---|---|---|---|---|---|
| 752 | 16 | 11 | 5 | 1 | 16 | 0 |
| 1052 | 431 | 219 | 38 | 7 | 73 | 121 |
| 1562 | 34 | 6 | 5 | 0 | 4 | 4 |
| 4242 | 35 | 35 | 35 | 35 | 0 | 34 |
| 4120 | 18,037 | 9,971 | 18,037 | 18,037 | 18,037 | 0 |

On a feed-sized event like 4120 all three slices except correlations are the whole event, so
the count must be computed server-side without fetching the records, and the cap stays the
only thing between the analyst and 18,000 nodes. Grouping a large landing by type is parked
until pivotick groups nodes by property (correlated-object §6).

## 5. Endpoint

**Network and IDS.** A new read, counted and fetched in one shape:

`POST /events/cardElements/{id}.json`
```
{ "slice": "all" | "network" | "ids", "q": "<search>", "types": [...], "category": "<category>",
  "ids": true|false (absent: either), "exclude": [uuid, ...], "count": true|false }
```
- `count: true` returns `{ total, by_type: { type: n }, by_category: { category: n } }`, with
  no records, for `summarize`: `total` in new landing units, the maps in matching attributes.
  Each map ignores its own narrowing (`by_type` leaves out `types`, `by_category` leaves out
  `category`), so a ticked type does not empty the list it was ticked from. `ids` is ignored on
  the `ids` slice.
- `count: false` returns `{ attributes: [...], objects: { uuid: {...} }, matched: [uuid, ...],
  event: {...}, ui_priorities: {...} }`: free attributes as the event payload shapes them, objects
  as `MispObject::fetchGraphObjects` does, B's card as `correlatedEventCards` does. `matched`
  names the attributes that matched, which is where the client reads the N4 mark from; free
  attributes and object children share one shaping, `MispObject::graphAttributes`.
- Access: B must pass `fetchSimpleEvent` for the user; attributes go through
  `fetchAttributes`, objects through `fetchGraphObjects`. An object the user cannot read does
  not land, and neither do its attributes (as observed in the correlated-object live check).
- Capped server-side at the canvas budget (1,500 landing units) so a refused run cannot be
  forced by a direct call: the fetch counts first and answers 400 above it.
- ACL entry for the action (`findMissingFunctionNames` stays empty).

**More correlations.** No new endpoint. `POST /events/correlatedAttributes/{this}.json` with
`event_ids: [B.id]` and no `attribute_uuids`, landed by the existing `correlationResult`, whose
new rows are the count (N7b). `_counts.events[B.id]` still decides whether the pivot applies.

## 6. Client

- `otherEventCard(node)`: a node whose `type` is `event`, whose `event_id` is not this
  event's, and which is not a feed's (`_provenance !== 'feed'`). The same test *Event
  contents* used.
- Three pivots over one builder (`cardElementsPivot('all' | 'ids' | 'network')`): `summarize` asks for
  the count, `fetch` for the records, both cached per card, slice and narrowing, and a failed
  request is not kept.
- The landing reuses `landing()`, `eventCardNode`, `foreignObjectNode` and `inEventEdge`,
  so a network indicator and a correlated attribute from the same object merge into one node.
- *More correlations* is a thin pivot over `fetchCorrelated({ event_ids: [id] })`, one request
  per card, whose `summarize` counts the new rows of the landing it builds and keeps it for
  `fetch` (N7b).
- Summaries are invalidated on node add/remove, like *Event elements* and *Around this object*.
- Tag and cluster joins (task 30's rule) apply to what lands, as for every pivot.

## 7. Scope

**In:** the three pivots, the `cardElements` endpoint with its count mode, the ACL entry, unit
tests, a live check.

**Out:**
- Feed event cards (N8): no local copy of a feed event to count or read.
- Grouping a large landing by type or by object.
- Opening the card to show B inside it (R8 keeps cards closed).
- Correlations between B and nodes of a third event on the canvas (N6): the general
  "correlate from a foreign node" tool, for its own PRD.
- Reports, sightings and analyst data of B.

## 8. Acceptance

Figures from the dev DB, 2026-09-27, as the admin, with nothing of B on the canvas but its card.

1. **IDS.** On 1052's card, reached from 752: *Its IDS indicators* offers **120** (219 matching
   attributes in 120 objects and free attributes). Run from the Pivot panel, it lands them,
   each joined to the card by `in-event`, and each matching child carries *Matched: IDS
   indicators*. Run again, it offers 0.
2. **Network, types.** On the same card *Its network indicators* offers **37** (38 attributes);
   its type facet lists only network types, each with its attribute count.
3. **Network, template fields.** On 4455's card, reached from 44 by one correlation, *Its
   network indicators* offers **4**: the 2 holders of network types and the 2 `passive-dns`
   objects, which land with their `rrname` and `rdata` marked.
4. **Exclude.** After *Correlations* from 752 has landed 1052's four `file` objects, *Its IDS
   indicators* on 1052's card offers the IDS holders less those already drawn, and lands
   nothing twice.
5. **Cap.** On 4120's card, *Its IDS indicators* (9,971) and *Its network indicators* (18,037)
   are refused; searching `104.21` brings both below 1,500 and they run.
6. **More correlations.** On 1052's card after one object was followed from 752, the row offers
   the remaining landing units (10 in all, less what is drawn), lands them with this event's
   side, and then offers 0.
7. **Several cards.** 1052 and 4455 selected together: each shortcut offers the sum and lands
   each card's own, joined to its own card.
8. **Access.** As `orgadmin@circl.lu` (org 9), with one of 1052's IDS-holding objects set to
   distribution 0 for the run and restored after: *Its IDS indicators* offers one fewer, the
   object does not land, and the count agrees with what lands.
9. **Not offered:** on this event's own node, on a feed event's card, on an attribute or object.
10. Unit tests cover the four pivots, the count/fetch split, `exclude`, the matched mark, the
    cache, and the summed selection; `findMissingFunctionNames` stays empty.

## 9. State

| # | Piece | Status | Note |
|---|---|---|---|
| 0 | Grilling session on §3 | ✅ | 2026-09-27: N1–N8 and N7b decided, §8 pinned to dev-DB fixtures |
| 1 | `cardElements` endpoint: count mode, fetch mode, `exclude`, server-side cap, ACL entry | ✅ | `Event::cardElementCounts` / `cardElements`, one query builder; the search escapes `%` and `_` |
| 2 | *Its attributes*, *Its IDS indicators*, *Its network indicators* pivots | ✅ | Form: *Search* text, *IDS only* boolean (true / false / unset, as pivotick draws a boolean), *Type* multiselect, *Category* select. Request cache keyed by card and body, dropped on node add/remove |
| 3 | *More correlations with this event* pivot | ✅ | Counts B's holders the landing would draw. Once they are all drawn it offers 0 but a run can still stage correlation edges between drawn nodes (13 on 1052), which Review shows as edge rows |
| 4 | Unit tests | ✅ | 10 tests in `tests/js/pivot-explorer-graph.test.js` (625 pass) |
| 5 | Live check (§8) | ✅ | §10, all ten |

`✅` done · `🔜` next · `⏸` blocked · `⬚` not started

## 10. Live check, 2026-09-27

On the dev DB as the admin unless said otherwise, through the endpoint and through the real
page (752's Pivot Explorer, pivots driven on the live Pivotick instance).

| # | Result |
|---|---|
| 1 | 1052's card: *Its IDS indicators* offers **120** (219 attributes). Staged, ingested: 307 nodes, 219 children marked, 121 holders joined to the card by `in-event`, sidebar reads *Matched: IDS indicators*. Offers **0** afterwards |
| 2 | *Its network indicators* offers **37** (38 attributes); type facet: domain 12, hostname 4, ip-dst 7, url 15 |
| 3 | 4455: **4**, the 2 `passive-dns` objects landing with all 7 attributes each, `rrname` and `rdata` in `matched`. Their `text` type shows in the type facet |
| 4 | Count = landed on 11 slice/narrowing cases (752, 1052, 1562, 4242, 4455, 4120); excluding half of what landed halves the count with no overlap, excluding all of it gives 0 |
| 5 | 4120: IDS 9,971, network 18,037; `104.21` brings network to 940. An unnarrowed fetch answers 400 in 0.6 s |
| 6 | After one 752→1052 correlation was followed, *More correlations* offers **9** (10 less 1), and 0 after landing |
| 7 | 1052 and 4455 selected together on 752's canvas. No event correlates with both and no tag joins them, so 1052's card came from a real correlation and 4455's was added through `Graph.addNode` from the explorer's own card data. Each count is the sum of the two alone: attributes 193 + 4 = 197, IDS 120 + 0, network 37 + 4 = 41, network narrowed to `domain` 12 + 2 = 14, search `google` 0 + 3 = 3; the type facet sums too (domain 14, ip-dst 9). One request per card for each count and for the fetch. Landing network together: 37 `in-event` edges to 1052's card, 4 to 4455's, none crossing cards; 4455's `rrname`, `rdata`, `domain`, `ip` marked *network*; both then offer 0 |
| 8 | `orgadmin@circl.lu`, object 2410 at distribution 0 for the run (restored to 5): **119**, 119 landed, the object absent, `matched` 217 |
| 9 | Not offered on this event's elements; feed cards and elements covered by unit test |
| 10 | `events/queryACL/findMissingFunctionNames` does not list `cardElements` |

Search is case-insensitive on value and comment (`COMMAND AND CONTROL` and lower case both 5 on
1052).
