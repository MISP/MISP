# PRD: A correlation lands in its object, and the object's surroundings are one pivot away

**Status:** Built 2026-09-27. See §8.
**Owner:** Sami Mokaddem (Claude-assisted)
**Parent:** [`pivot-explorer-v16-prd.md`](pivot-explorer-v16-prd.md). Changes the landing of
task 5's *Correlations* pivot; supersedes task 34's *Event contents* as the way into another
event.

---

## 1. Why

Following a correlation, the analyst asks three things in order: is the other event about the
same thing, what does it know around the shared value, and where does that lead. None of them
is "show me all of event B".

Today a correlation run puts B's attribute inside B's event card. With R8 the card is a closed
box, so the correlation edge ends on it and says nothing about *where* in B the value sits.
The only way further into B is *Event contents*, which lands B's records wholesale inside the
same closed card: tens of thousands on a large event, and nothing visible until the card can
open.

What surrounds a shared value in MISP is its **object**: the `domain-ip`, `file` or `url` it
belongs to, and the objects that object references or is referenced by. That is small, already
structured, and drawn the same way as this event's own objects.

## 2. What the analyst sees

- **A correlation lands in its object.** When B's correlated attribute belongs to an object,
  the run brings that object as a free node, a closed box like this event's objects, with the
  attribute inside it. The correlation edge ends on the object. A correlated attribute with no
  object lands as a free attribute node.
- **B's card is context, beside it.** The card is drawn once per event, holds nothing, and is
  joined to each of B's objects or attributes on the canvas by a thin `in-event` edge. It stays
  the place for B's event-level pivots (tags, and the typed expansions of a later PRD).
- **Around this object** is a pivot on any of B's objects on the canvas. It lands, within B,
  the objects this one references and the objects that reference it, with their reference
  edges. It is one step, and it lands directly when small (task 35's one-click limit).

## 3. Decisions

| # | Question | Decision |
|---|---|---|
| C1 | Where a correlated attribute lands | **Inside its object** when it has one; otherwise **free**. Never inside the event card. |
| C2 | What joins it to its event | An **`in-event`** edge kind, from the object (or free attribute) to the card: thin, grey, undirected-looking, on its own layer so the filter can hide it. |
| C3 | How far *Around this object* reaches | **One step of object references, both directions, within B.** Further is another run from what landed. |
| C4 | What the object brings | **All of its live attributes the user can see**, as today's own objects do. |
| C5 | *Event contents* | **Withdrawn** once this lands. The typed expansions of the event card replace it ([`pivot-explorer-event-expansions-prd.md`](pivot-explorer-event-expansions-prd.md), built 2026-09-27). |
| C6 | This event's side of a pair | Unchanged: it lands where this event's elements land. |

## 4. Endpoint

`POST /events/correlatedAttributes/{id}.json` already returns, per pair, `Object: {uuid, name}`
(`Event::getCorrelatedAttributes`, `Event.php:952`). Extend it to return, once per object, the
object as `Event::fetchEvent` would shape it (template, meta-category, live attributes the user
may read), in a top-level `objects` map keyed by uuid, beside the existing `events` map.

*Around this object* needs a new read:
`GET /objects/surroundings/{uuid}.json` → `{ objects: [...], references: [...] }`. It returns the
objects one reference away from the given one in its own event, both directions, and the
references between them, in the same object shape, filtered by the user's access as every
object read is. It needs an ACL entry (`findMissingFunctionNames` stays empty).

## 5. Client

- `correlationResult` builds, per pair, the object node (`objectNodeData` + `objectChildData`
  children) from `payload.objects` when the pair has an object, else a free attribute node; one
  card per event from `payload.events`; an `in-event` edge per object or free attribute.
- The *Around this object* pivot applies to object nodes whose `scope` is `foreign`, fetches
  `surroundings`, and returns the objects with their children and the reference edges (kind
  `object-reference`, as today), plus `in-event` edges to the card.
- Tag and cluster joins (task 30's rule) apply to everything that lands, as for every pivot.

## 6. Scope

**In:** the landing change (C1, C2), the endpoint extension, the surroundings endpoint and pivot,
withdrawing *Event contents* (C5).

**Out:**
- The event card's typed expansions (*its IPs*, *its IDS indicators*, *what else correlates with
  my canvas*): their own PRD, [`pivot-explorer-event-expansions-prd.md`](pivot-explorer-event-expansions-prd.md).
- Grouping a large landing by type: parked until pivotick groups nodes by property.
- More than one step of references per run.

## 7. Acceptance

1. On an event whose correlation partner holds the shared value inside an object (to be picked
   from the dev DB when building), *Correlations* lands that object with the attribute inside it
   and the correlation edge ending on it. The partner's card sits beside it, joined by one
   `in-event` edge, with no children.
2. A correlated attribute with no object lands free, with its own `in-event` edge.
3. Two correlations into the same object of B land one object, and one `in-event` edge.
4. *Around this object* on that object lands its referenced and referencing objects in 4120
   with their reference edges, directly when 25 or fewer, and undo removes them.
5. A user who cannot read B's object sees the correlated attribute free rather than an object
   they may not see, and *Around this object* returns nothing they may not read.
6. The unit tests cover the landing shapes and the new pivot; the PHP endpoint is checked live
   for access as the tag pivots were.

## 8. State

| # | Piece | Status | Note |
|---|---|---|---|
| 1 | `MispObject::fetchGraphObjects`: readable live objects with their readable attributes, tags (local ones only for the owning org) and warninglist hits | ✅ | |
| 2 | `ObjectTemplate::uiPrioritiesFor`: template ranks for any objects, split out of `uiPrioritiesForEvent` | ✅ | Needed for C4: a foreign object leads with its template's attribute like this event's do |
| 3 | `correlatedAttributes` returns `objects` (keyed by uuid) and `ui_priorities`; a pair's `Object` is null when the user cannot read it | ✅ | The object's name no longer leaks through the pair |
| 4 | `GET /objects/surroundings/{uuid}.json` + ACL entry | ✅ | Returns `{objects, references, event, ui_priorities}`: `event` is the card, so the neighbours can be joined to it even when it left the canvas. References are object-to-object only, and only between objects the user may read. A malformed uuid is a 404 |
| 5 | Client landing (C1, C2), `in-event` edge kind | ✅ | `in-event`: `#6c737d`, 1 px, no arrowhead (`markerEnd: 'none'`), in the Relationship filter. A pair's attribute is put inside its object even when the object's payload lacks it |
| 6 | *Around this object* pivot | ✅ | Pivot id `object-surroundings`, read once per object. A reference it lands is another event's, so Delete spares it: a reference is deletable only from this event's own object |
| 7 | *Event contents* withdrawn (C5) | ✅ | |
| 8 | Unit tests | ✅ | 575 assertions (569 before) |
| 9 | Live check on the dev instance (acceptance 1–5) | ✅ | See §9 |

`✅` done · `🔜` next · `⏸` blocked

## 9. Live check, 2026-09-27

Event **752** correlates 14 times into **1052**: 6 attributes outside any object, and 8 inside
four `file` objects (2473 and 2485 three times each).

- **1–3.** *Correlations* on everything correlating (12 elements) lands the four objects once
  each, closed, with their 3 attributes ranked by their own template; one card for 1052 with
  no children; the 6 free attributes; 10 `in-event` edges (4 objects + 6 attributes). 8 of the
  14 correlation edges end inside an object.
- **4.** *Around this object* on 2473 (`2c61724f…`) offers 2, and a one-click run lands the two
  `virustotal-report` objects with their two `analysed-with` references (39 → 47 nodes,
  24 → 28 edges); undo returns to 39 and 24.
- **5.** As `orgadmin@circl.lu` (org 9; 1052 is org 1's), with 2485 and 2508 set to
  distribution 0 for the run and restored after: 2485 does not land, and neither do its three
  correlated attributes (11 correlations instead of 14). MISP's attribute read already
  withholds an unreadable object's attributes, so they don't land free, as this PRD assumed;
  they don't land at all. The client's free fallback stays, for a pair whose object is missing
  from `objects`. *Around this object* on 2473 returns only 2474 and its one reference.
- `GET /objects/queryACL/findMissingFunctionNames` is `[]` as admin.
