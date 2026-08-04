# PRD: Event Index Mass Tagging & Mass Galaxy Cluster Assignment (MISP)

**Status:** DRAFT — awaiting review/sign-off on §5 decisions
**Owner:** iglocska (Claude-assisted)
**Created:** 2026-06-12
**Working dir:** /var/www/MISP7
**Branch (planned):** `feature-event-index-mass-actions` off `2.5`

---

## 1. Summary

The event index allows multi-selecting events, but the only mass actions are
**delete** and **export**. This PRD adds two more:

1. **Mass tag** — attach one or more tags to all selected events in one
   operation, with a user-chosen **preference** of global or local.
2. **Mass galaxy cluster assignment** — attach one or more galaxy clusters
   to all selected events in one operation, same global/local preference.

The global/local choice is a *preference*, not a hard mode: when the
preference is **global** but the user cannot modify a given event (not the
owner org, not site admin), the attach for that event is **auto-downgraded
to a local tag/cluster** — enforced in the backend per event, never trusted
from the client.

No true bulk endpoint exists for either *on events*. However, the **attribute**
world already has the exact pattern we need (`'selected'` target + JSON ID
list flowing through the generic picker), so the design is: extend the two
existing endpoints to accept `'selected'` + an `event_ids` list, mirroring the
attribute precedent, and add four toolbar buttons to the event index that are
near copies of the ones on the attribute toolbar.

---

## 2. Background & Motivation

Analysts triaging the event index routinely need to classify a batch of
events the same way (e.g. tag a wave of phishing events with
`tlp:amber` + a campaign tag, or attach a threat-actor cluster to all events
of an incident). Today this requires opening every event individually —
N×(open, click, pick, submit). The multi-select machinery, permission
plumbing, picker UI, and even the bulk persistence loops all already exist;
they are just not wired up for events on the index page.

---

## 3. Current State (evidence)

### 3.1 Event index multi-select machinery

- Row checkboxes: `app/View/Elements/Events/eventIndexTable.ctp:45` —
  `<input class="select" type="checkbox" data-id="<?= $eventId ?>"
  data-can-modify="...">`; select-all checkbox at line 5.
- Toolbar: `app/View/Events/index.ctp:88-103` — `multi-delete-button` /
  `multi-export-button` entries, hidden by default (`class` =>
  `'hidden mass-delete'` / `'hidden mass-export'`), rendered via
  `genericElements/ListTopBar/element_simple.ctp` which supports `data-*`
  attributes and `requirement` gating.
- Visibility toggle: `listCheckboxesCheckedEventIndex()`
  (`app/webroot/js/misp.js:1022-1035`) shows/hides the `.mass-*` buttons on
  checkbox change.
- ID collection: `multiSelectDeleteEvents()` (`misp.js:1047`) gathers
  `data-id` of `.select:checked`, JSON-stringifies.
- Global popover launcher: `misp.js:5231` — delegated click handler for any
  element with `data-popover-popup="<url>"`.

### 3.2 Tagging endpoints

- `EventsController::addTag($id, $tag_id)`
  (`app/Controller/EventsController.php:4999-5175`): **single event**,
  multiple tags (JSON list, `collection_N` tag-collection expansion). GET
  renders the form `app/View/Events/add_tag.ctp`; POST validates per tag
  (visibility via `Tag::createConditions()`, dedup, taxonomy exclusivity via
  `Taxonomy::checkIfNewTagIsAllowedByTaxonomy()`, `local_only` constraint),
  saves `EventTag`, logs, and `unpublishEvent()`s on non-local tags. The
  function is single-event-shaped from line 5010 (immediate event lookup,
  bails with "Invalid event." otherwise).
- `AttributesController::addTag($id, $tag_id)`
  (`AttributesController.php:2647-2839`): **the precedent** — accepts
  `$id === 'selected'` + `Attribute.attribute_ids` JSON list; outer loop over
  attributes, inner loop over tags; per-attribute `__canModifyTag()`; tags
  validated once up front; batch `touch` at the end; returns
  success/fail counts.
- Picker chain (events): `ajaxTags.ctp:40,50` launches
  `/tags/selectTaxonomy/{id}` (or `/tags/selectTaxonomy/local:1/{id}`) →
  `selectTaxonomy($id, $scope)` (`TagsController.php:374-417`) threads `$id`
  through **without validating it** → `selectTag()` → generic picker submits
  via `quickSubmitTagForm(selected_tag_ids, addData)` (`misp.js:728-758`),
  which POSTs to `/events/addTag/{addData.id}`.
- `quickSubmitAttributeTagForm` (`misp.js:760-798`) already shows the
  `'selected'` JS branch we need to replicate: fills the hidden
  `#AttributeAttributeIds` field with `getSelected()` and reloads the index
  on success.
- Attribute toolbar precedent: `eventattributetoolbar.ctp:84,93` — two
  buttons with `data-popover-popup` =
  `/tags/selectTaxonomy/selected/attribute` and
  `/tags/selectTaxonomy/local:1/selected/attribute`.

### 3.3 Galaxy cluster endpoints

- `GalaxiesController::attachMultipleClusters($target_id, $target_type)`
  (`GalaxiesController.php:558-631`): **already bulk-shaped** — multiple
  clusters × multiple targets. `$target_id === 'selected'` is supported but
  hard-wired to `Galaxy.attribute_ids`. Per-target `ACL->canModifyTag()`,
  then `Galaxy::attachCluster()` per (cluster, target) pair. Permission
  failure currently **throws ForbiddenException mid-loop** (aborts the rest).
- `Galaxy::attachCluster()` (`app/Model/Galaxy.php:795-850`): cluster attach
  is tag-based under the hood — `Tag::captureTag(..., $force = true)` (so no
  `perm_tag_editor` needed for the galaxy tag to be created), dedup check,
  `EventTag` save, `touch()` (unpublish) on non-local, log entry. Throws
  `MethodNotAllowedException` if a `local_only` cluster is attached
  non-locally.
- Picker chain: `selectGalaxyNamespace($target_id, $target_type)`
  (`GalaxiesController.php:405-439`) threads `target_id` through without
  validation → `selectGalaxy()` → `selectCluster()` → generic picker submits
  via `quickSubmitGalaxyForm(cluster_ids, additionalData)`
  (`misp.js:4610-4656`), which POSTs to
  `/galaxies/attachMultipleClusters/{target_id}/{scope}/local:{local}` and
  already handles `target_id === 'selected'` (fills `#GalaxyAttributeIds`,
  `location.reload()` on success).
- Attribute toolbar precedent: `eventattributetoolbar.ctp:103,113` —
  `data-popover-popup` = `/galaxies/selectGalaxyNamespace/selected/attribute/
  [local:1/]eventid:N`, icons `rebel` (global) / `empire` (local), source
  `fab`.

### 3.4 ACL

`app/Controller/Component/ACLComponent.php`: `events/addTag`,
`galaxies/attachMultipleClusters`, `galaxies/selectGalaxyNamespace`,
`galaxies/selectGalaxy`, `galaxies/selectCluster`, `tags/selectTaxonomy`,
`tags/selectTag` all require `perm_tagger`. `ACLComponent::canModifyTag()`
(line 1164): site admin, OR (`perm_tagger`|`perm_sync`) AND (can modify the
event OR (tag is local AND user is host org)).

### 3.5 Gap statement

- **Tags:** no endpoint attaches tags to multiple *events*; `events/addTag`
  rejects anything that isn't a resolvable single event.
- **Clusters:** `attachMultipleClusters` is one event xor many attributes;
  the `'selected'` branch cannot carry event IDs.
- **UI:** no tag/cluster mass buttons on the event index; the event-scoped
  picker submit functions lack a `'selected'` branch.

---

## 4. Goals / Non-Goals

### Goals
- G1: Mass-attach one or more tags (incl. tag collections) to all selected
  events from the event index, with a global-or-local preference.
- G2: Mass-attach one or more galaxy clusters to all selected events from
  the event index, with a global-or-local preference.
- G3: Per-event permission enforcement server-side; partial success with an
  honest summary (attached-global / attached-local-downgraded /
  skipped-duplicate / failed counts).
- G3b: **Auto-downgrade to local**: with a global preference, events the
  user cannot modify get the tag/cluster attached as *local* instead of
  failing — decided per event in the backend (`canModifyEvent` as the
  predicate), immune to JS tampering.
- G4: Reuse the existing generic-picker chains and `'selected'` conventions;
  no new picker UI.
- G5: Endpoints remain scriptable (the POST contracts are documented in §8).

### Non-Goals
- Mass *removal* of tags/clusters from the index (natural follow-up, not in
  scope; the design should not preclude it).
- A clean REST bulk API (e.g. `tags/attachTagToObject` accepting multiple
  UUIDs) — phase 2 candidate, see §12.
- Background/async processing — synchronous like mass delete (see §6.6).
- Cross-page selection ("select all results matching filter") — selection
  stays page-bounded, identical to mass delete semantics.

---

## 5. Design Decisions (sign-off requested)

> Per-decision recommendation given; flag disagreement before implementation
> starts. **D1–D3 shape the code; D4 is behavioral.**

### D1 — Extend `events/addTag` with the `'selected'` pattern vs. a new endpoint
**Recommendation: extend `events/addTag`** to accept `$id === 'selected'` +
`Event.event_ids` JSON, restructured as outer-event/inner-tag loops exactly
like `AttributesController::addTag`.
- *For:* house pattern (attributes do precisely this); the picker chain and
  `quickSubmitTagForm` then work with `addData.id = 'selected'` with a tiny
  JS branch; single endpoint to maintain; the single-event call shape stays
  byte-compatible (degenerate `$idList = [$id]`).
- *Against / risk:* `addTag` is a ~175-line action also reachable via API;
  restructuring it carries regression risk. Mitigation: keep the single-id
  fast path identical in behavior (same responses, same validation order),
  add integration tests for the single-event path *before* refactoring.
- *Rejected alternative:* new `events/massAddTag` action. Zero regression
  risk on `addTag` but duplicates ~80 lines of tag validation (or forces the
  same refactor anyway to share a private helper), adds an ACL entry, and
  diverges from the attribute convention.

### D2 — Clusters: extend `attachMultipleClusters` `'selected'` branch
**Recommendation: extend, not duplicate.** When
`$target_id === 'selected' && $target_type === 'event'`, read
`Galaxy.event_ids` (new hidden form field) instead of
`Galaxy.attribute_ids`. The endpoint is already bulk-shaped; this is a small,
additive branch. No new ACL entry needed.

### D3 — Toolbar UX: four buttons, mirroring the attribute toolbar
**Recommendation: four `ListTopBar` buttons** in the existing mass-action
button group of `index.ctp`, shown when ≥1 row is checked AND the user is a
tagger:
- *Tag selected events (global where permitted)* — `fa-icon: tag`,
  popover-popup `/tags/selectTaxonomy/selected/event`
- *Tag selected events (local)* — `fa-icon: tag` (title disambiguates,
  matching the attribute toolbar), popover-popup
  `/tags/selectTaxonomy/local:1/selected/event`
- *Add cluster to selected events (global where permitted)* —
  `fa-icon: rebel`, `fa-source: fab`, popover-popup
  `/galaxies/selectGalaxyNamespace/selected/event`
- *Add local cluster to selected events* — `fa-icon: empire`,
  `fa-source: fab`, popover-popup
  `/galaxies/selectGalaxyNamespace/selected/event/local:1`

The local buttons force local everywhere; the global buttons express a
*preference* the backend may downgrade per event (D6). The `local:1` named
param is only a preference signal — the backend never treats it as an
entitlement.

`element_simple.ctp` already renders `data-*` attributes and the global
`[data-popover-popup]` handler (`misp.js:5231`) launches the picker — no new
launch plumbing.
- *Rejected alternative:* one button + a local/global chooser step. Fewer
  buttons, but requires a new chooser popover with no existing server-side
  element to render it; breaks symmetry with the attribute toolbar users
  already know.

### D4 — Error semantics in the bulk loops: skip-and-count vs. abort-on-first
**Recommendation: skip-and-count for the new event paths.** The index
selection routinely contains events from other orgs (unlike the attribute
flow, which operates inside one event you can edit), so a mixed selection is
the *normal* case, not an error. Per event: global preference is first
auto-downgraded where applicable (D6); if even the downgraded attach is not
permitted → counted as failed, loop continues; duplicate tag/cluster →
counted as skipped. Response reports
`{attached: w, downgraded: x, skipped: y, failed: z}`.
- **Behavioral divergence flag:** the existing attribute branch of
  `attachMultipleClusters` throws `ForbiddenException` on the first
  non-permitted target (after earlier attaches already persisted —
  non-transactional abort). We leave that branch untouched (additive
  posture); the event branch gets the friendlier semantics. If you'd rather
  unify both to skip-and-count, say so — it's a one-line-ish change but it
  alters existing attribute behavior.
- Same treatment for the `MethodNotAllowedException` thrown by
  `Galaxy::attachCluster()` for `local_only` clusters attached globally: in
  the event branch, catch per target and count as failed (message surfaced
  once), rather than aborting the batch.

### D5 — Client-side permission pre-filtering: none
The delete flow filters on `data-can-modify` client-side. Tagging must NOT,
because `canModifyTag` is more permissive than `canModifyEvent` (host-org
users may attach *local* tags to events they cannot modify) and because the
global→local downgrade (D6) is a backend decision. Send all selected IDs
plus the preference; the server is authoritative (D4 reports the outcome).
The buttons themselves are gated by tagger-level access only
(`$this->Acl->canAccess('tags', 'selectTaxonomy')` /
`('galaxies', 'selectGalaxyNamespace')`).

### D6 — Global→local auto-downgrade, backend-enforced
With a **global** preference, each event is evaluated server-side:

```
effectiveLocal(event, preferLocal):
    if preferLocal:                  return true   # local everywhere
    if ACL->canModifyEvent(event):   return false  # owner/site admin → global
    return true                      # downgrade to local
```

The effective flag then goes through the *existing* permission primitive
`canModifyTag($user, $event, $effectiveLocal)` and into the `EventTag.local`
/ cluster-attach `local` flag. Consequences:

- Owner-org users and site admins attach globally under a global
  preference; everything else becomes local. The client's `local:1` named
  param can be tampered with at will — it only ever *widens* localness
  (forces local), never grants global. Global is derivable solely from
  `canModifyEvent`, which the client cannot influence.
- Downgraded (local) attaches do **not** `touch()`/unpublish the event —
  correct, since the user couldn't unpublish a foreign event anyway, and
  local tags never unpublish.
- **ACL boundary (DECIDED 2026-06-12):** `ACLComponent::canModifyTag`
  (`ACLComponent.php:1164`) stays untouched. The eligible population for
  tagging — bulk or single — remains exactly: event owners/creators
  (`canModifyEvent`, incl. site admins) and **host-org taggers** (local
  only, `hostOrgId === user.org_id`). A non-host-org tagger targeting a
  foreign event fails even after the local downgrade; that is the
  *intended* outcome, counted as `failed` in the summary. No ACL
  broadening as part of this feature.
- **Scope: bulk paths only (v1).** The single-event `addTag` and the
  attribute flows keep today's refuse-on-no-permission behavior. Extending
  the downgrade to single-event tagging would change an existing API
  contract — listed in §12 as a follow-up question.
- The downgrade count is reported separately in the response (`downgraded`)
  so the operator can see that part of the batch went local.

---

## 6. Detailed Design

### 6.1 Mass tag — backend (`EventsController::addTag`)

Restructure to the `AttributesController::addTag` shape:

1. **ID list resolution** (both GET and POST): if `$id === 'selected'`, skip
   the single-event lookup. Otherwise behave exactly as today.
2. **GET branch** (`!$this->request->is('post')`): for `'selected'`, set
   `object_id = 'selected'` and render `/Events/add_tag` as today. No event
   fetch.
3. **View** (`app/View/Events/add_tag.ctp`): when `$scope === 'Event'` and
   `$object_id === 'selected'`, additionally emit
   `echo $this->Form->input('Event.event_ids', []);` (hidden by the popover
   CSS the same way `Attribute.attribute_ids` is) so the form carries the
   target list. Form URL becomes `/events/addTag/selected[/local:1]` via the
   existing sprintf.
4. **POST branch**:
   - Resolve `$tag_id_list` once, up front (existing logic: numeric, JSON
     list, `collection_N` expansion, name lookup via
     `lookupTagIdForUser()`). Also fetch + validate all tags once against
     `Tag::createConditions($user)` (hoisted out of the per-event loop, as
     the attribute version does at `AttributesController.php:2737-2742`).
     `local_only` tags under a **global preference** are rejected up front
     for the whole batch with a "use the local action" message —
     per-event mixed outcomes (local on downgraded events, refused on own
     events) would be more surprising than helpful.
   - Build `$eventIdList`: `['selected'] ? _jsonDecode(Event.event_ids) :
     [$id]`. Deduplicate; reject empty list.
   - Outer loop over events: fetch event (`recursive -1`), compute
     `$effectiveLocal` per D6 (`$local || !__canModifyEvent($event)`), then
     `__canModifyTag($event, $effectiveLocal)` → on failure increment
     `failed`, continue (D4). Track `downgraded` when
     `$effectiveLocal && !$local`.
   - Inner loop over tags: dedup check (existing `EventTag` exists query) →
     `skipped`; taxonomy-exclusivity check
     (`checkIfNewTagIsAllowedByTaxonomy`) per event → `failed` with reason;
     save `EventTag` with `local = $effectiveLocal`, log — as today.
   - **Unpublish once per event** if ≥1 tag was attached to it with
     `$effectiveLocal == false` (not once per tag — mirror the batched
     `touch` at `AttributesController.php:2825`). Downgraded/local attaches
     never touch the event.
   - Response: existing JSON shape, message extended to the per-event
     summary, e.g. `"Tag(s) added to 12 events (4 as local — no modify
     rights, 3 skipped as duplicates, 2 events failed: no permission)."`
     Keep `saved: true` if ≥1 attach succeeded, `saved: false` if all
     failed (matches attribute semantics).

### 6.2 Mass tag — frontend

1. `index.ctp`: add the two tag buttons (D3) to the mass-action group, with
   `'class' => 'hidden mass-tag'` and `requirement` gating on tagger access.
2. `misp.js listCheckboxesCheckedEventIndex()`: toggle `.mass-tag` (and
   `.mass-galaxy`, §6.4) alongside `.mass-export` (any checked row — no
   `data-can-modify` filter, D5).
3. `misp.js quickSubmitTagForm()`: add the `'selected'` branch, mirroring
   `quickSubmitAttributeTagForm`:
   - after `$formData.find('#EventTag').val(...)`, if
     `event_id === 'selected'`, fill `#EventEventIds` with the selected
     event IDs;
   - success/complete: if `'selected'`, `location.reload()` instead of
     `loadEventTags()`/`loadGalaxies()` (those helpers target the event-view
     DOM and don't exist on the index).
4. New tiny collector `getSelectedEventIds()` in misp.js reading
   `$('.select:checked')` `data-id`s and returning the JSON string
   (the existing `getSelected()` is bound to `.select_attribute` and must
   not be repurposed).

### 6.3 Mass clusters — backend (`GalaxiesController::attachMultipleClusters`)

1. POST branch, target list resolution becomes:
   ```php
   if ($target_id === 'selected') {
       if ($target_type === 'event') {
           $target_id_list = $this->_jsonDecode($this->request->data['Galaxy']['event_ids']);
       } else {
           $target_id_list = $this->_jsonDecode($this->request->data['Galaxy']['attribute_ids']);
       }
   }
   ```
2. In the `(cluster × target)` loop, **only for the
   `'selected'+event` path**: replace throw-on-failure with skip-and-count
   (D4) and apply the D6 downgrade — per event compute
   `$effectiveLocal = $local || !ACL->canModifyEvent($user, $target)`, then
   `ACL->canModifyTag($user, $target, $effectiveLocal)` (failure → `failed`,
   continue) and pass `$effectiveLocal` into
   `Galaxy::attachCluster(..., $effectiveLocal)`. Track `downgraded`.
   Clusters from `local_only` galaxies under a global preference are
   rejected up front for the whole batch (consistent with the tag rule,
   §6.1) instead of letting `Galaxy::attachCluster()` throw mid-loop.
   Existing single-target and attribute behavior unchanged.
3. `mirror_on_event` stays attribute-only (guard already keyed on
   `$target_type === 'attribute'`).
4. View (`app/View/Galaxies/ajax/attach_multiple_clusters.ctp`): add a
   hidden `event_ids` input next to the existing `attribute_ids` one (only
   when `$target_type === 'event' && $target_id === 'selected'`, to keep the
   form minimal).

### 6.4 Mass clusters — frontend

1. `index.ctp`: the two cluster buttons (D3), `'class' => 'hidden
   mass-galaxy'`, requirement-gated. No `eventid:` named param (that is for
   the attribute/matrix context only).
2. `misp.js quickSubmitGalaxyForm()`: the `'selected'` branch becomes
   scope-aware:
   ```js
   if (target_id === 'selected') {
       if (scope === 'event') {
           $formData.find('#GalaxyEventIds').val(getSelectedEventIds());
       } else {
           $formData.find('#GalaxyAttributeIds').val(getSelected());
       }
   }
   ```
   The success path already does `location.reload()` for `'selected'` — no
   change.

### 6.5 Permissions & ACL

- **No new ACL entries** (D1/D2 reuse `events/addTag` and
  `galaxies/attachMultipleClusters`, both already `perm_tagger`).
- Per-event enforcement: `__canModifyTag()` / `ACL->canModifyTag()` inside
  the loops — identical primitive as single-event flows, so the bulk path
  can never attach anything the per-event path would refuse.
- Tag visibility: bulk path validates tags against
  `Tag::createConditions($user)` exactly as the single path does (org/user
  restricted tags, hidden tags).

### 6.6 Side effects & performance

- **Unpublish:** attaching effectively-global tags/clusters `touch()`es
  each event — published *own-org* events in the selection WILL be
  unpublished. Foreign events are never unpublished: under a global
  preference they receive local (downgraded) attaches, and local attaches
  never touch (D6). This is the established semantic of tagging
  (single-event flow does the same); the result message should mention how
  many events were modified so the operator understands republish is
  needed. No extra warning dialog (the picker is already a deliberate
  two-step action) — flag if you want one.
- **Per-attach fan-out:** each `EventTag` save fires ZMQ/Kafka notifications
  and workflow triggers (`EventTag::afterSave`), plus one Log row. Unchanged
  per attach; bulk just multiplies by selection size.
- **Bounded synchronous work:** selection is page-bounded (select-all =
  current page, default 60 rows), same envelope as mass delete which is also
  synchronous. Worst realistic case (60 events × a tag collection of ~10
  tags = 600 saves) is well within request limits. No background job in v1;
  if index page sizes grow, the escalation path is a `Job`-backed variant —
  out of scope.
- **Non-transactional:** like every existing bulk loop in MISP, partial
  failure leaves earlier attaches in place. The summary counts make this
  visible (D4).

---

## 7. Edge Cases

| # | Case | Behavior |
|---|------|----------|
| 1 | Global preference, event not modifiable, user is host org | **Downgraded to local** (D6), attached, counted as `downgraded` |
| 1b | Global preference, event not modifiable, user NOT host org | Downgrade computed, but local attach refused by `canModifyTag` → counted as failed, loop continues — **intended** per the D6 ACL boundary |
| 1c | Client tampers `local:1` off / forges the preference | Irrelevant: global is only granted when `canModifyEvent` passes server-side; preference can only force local, never global (D6) |
| 2 | Tag already on an event | Skipped as duplicate (existing dedup), counted. Note: dedup is per (event, tag) regardless of local flag — a pre-existing global tag means the downgraded local attach is skipped, matching single-event behavior |
| 3 | Exclusive taxonomy conflict (`checkIfNewTagIsAllowedByTaxonomy`) on some events | Per-event failure with reason, others proceed |
| 4 | `local_only` tag chosen via the *global* button | Rejected up front for the whole batch — "use the local action" (§6.1) |
| 5 | Cluster from `local_only` galaxy via the *global* button | Rejected up front for the whole batch (§6.3) |
| 6 | Local preference, user is host-org but not event owner | Allowed (`canModifyTag` local branch) — the reason for D5 |
| 7 | Empty `event_ids` / nothing selected | `saved: false`, "Nothing to add." (buttons are hidden with no selection anyway) |
| 8 | Tag collections (`collection_N`) in the picker | Expanded once, then applied per event (existing expansion reused) |
| 9 | Published own-org events, global preference | Unpublished via `touch()` — surfaced in summary (§6.6). Foreign events never unpublished (downgrade → local → no touch) |
| 10 | Duplicate IDs in `event_ids` | Deduplicate the ID list before looping |
| 11 | Non-numeric junk in `event_ids` | Per-ID event fetch fails → counted as failed, no exception leak |
| 12 | Site admin, global preference | Never downgraded (`canModifyEvent` always true) — attaches globally everywhere, foreign published events DO get unpublished (existing semantics) |

---

## 8. Request/Response Contracts (also the scripting interface)

### 8.1 Mass tag
```
POST /events/addTag/selected[/local:1]
Content-Type: application/x-www-form-urlencoded (UI form) — API callers may
send the equivalent JSON body

data[Event][event_ids] = "[12,13,14]"        (JSON list, IDs)
data[Event][tag]       = "[5,7]"             (JSON list of tag IDs, tag name,
                                              or "collection_3")

The optional `local:1` named URL param expresses the LOCAL preference.
Without it the preference is global, which the backend downgrades per
event (D6) — the param is never an entitlement.

→ 200 {"saved": true,
       "success": "Tag(s) added to 12 events (4 as local — no modify
                   rights, 3 skipped, 2 failed).",
       "attached": 8, "downgraded": 4, "skipped": 3, "failed": 2,
       "check_publish": true}
→ 200 {"saved": false, "errors": "..."}      (all failed / invalid input)
```
Single-event calls (`/events/addTag/{id}`) keep today's exact contract.

### 8.2 Mass clusters
```
POST /galaxies/attachMultipleClusters/selected/event[/local:1]

data[Galaxy][target_ids] = "[101,205]"       (JSON list of cluster IDs)
data[Galaxy][event_ids]  = "[12,13,14]"      (JSON list of event IDs)

→ 200 {"saved": true, "success": "...", "check_publish": true}
```
Attribute (`/selected/attribute`) and single-target calls unchanged.

---

## 9. Test Plan

1. **Regression guard first** (before the `addTag` refactor): integration
   test exercising today's single-event `/events/addTag/{id}` with: single
   tag id, JSON tag list, tag name, `collection_N`, local:1, duplicate
   (skip), and no-permission cases. Re-run after the refactor — byte-level
   message changes acceptable, semantics not.
2. **Bulk tag:** via API-key POST (or session login dance —
   `reference_misp_login_dance`) create 3 events as org A (PyMISP), then:
   - org-A user, global preference, own events → 3 `EventTag` rows with
     `local = 0` (verify via `/events/view`), all 3 unpublished;
   - re-run → 3 skipped duplicates;
   - **downgrade matrix** (org B = host org, org C = neither owner nor
     host org; events owned by org A):
     - org-B tagger, global preference → 3 rows with `local = 1`,
       `downgraded: 3`, events stay published;
     - org-C tagger, global preference → 0 rows, `failed: 3`;
     - org-C tagger, `local:1` → 0 rows, `failed: 3` (host-org rule);
     - site admin, global preference → 3 rows `local = 0`, no downgrade,
       events unpublished;
     - mixed selection (1 org-B-owned + 2 org-A-owned) as org-B tagger,
       global preference → 1 global + 2 local-downgraded, counts match;
   - **tamper check:** org-B tagger POSTs to the no-`local:1` URL with
     forged payloads → DB `EventTag.local` is still 1 for the foreign
     events (assert on DB/API state, not the response message — per
     `feedback_verify_visible_outcome_not_property`);
   - `local_only` tag, global preference → whole batch rejected up front.
3. **Bulk clusters:** same matrix against
   `/galaxies/attachMultipleClusters/selected/event`, plus: cluster from a
   `local_only` galaxy via global path → batch rejected up front; verify
   galaxy tag was `captureTag`d and `EventTag.local` reflects the
   downgrade per event.
4. **UI verification** (per `reference_dashboard_widget_render_verification`
   / headless chromium recipe): on the index, check 2 events → 4 new buttons
   appear; tag picker opens via the toolbar button; full picker→submit→
   reload round-trip attaches the tag (assert via API afterwards); buttons
   absent for a non-tagger role; buttons hidden with zero selection.
5. **Attribute-flow non-regression:** event view → select attributes → mass
   tag + mass cluster (the `'selected'` attribute paths share
   `quickSubmitGalaxyForm` and `add_tag.ctp`) — must behave exactly as
   before.

Test artifacts live under `tests/` following the existing curl/PyMISP
integration style; PHP-side unit coverage only where logic is extractable
(per `project_misp_test_convention`, bare PHPUnit in `app/Test/`).

---

## 10. Implementation Plan (sequential, one commit per task)

- [ ] **T1** Regression-guard integration test for single-event
      `events/addTag` (§9.1). `chg: [test] coverage for events/addTag
      single-event contract`
- [ ] **T2** Backend: `events/addTag` `'selected'` support incl. D6
      global→local downgrade + `add_tag.ctp` `event_ids` field (§6.1).
      `new: [event] mass tagging of selected events via addTag selected
      pattern`
- [ ] **T3** Backend: `attachMultipleClusters` `event_ids` branch +
      skip-and-count + D6 downgrade + form field (§6.3). `new: [galaxy]
      attach clusters to multiple events via selected pattern`
- [ ] **T4** Frontend: toolbar buttons, `listCheckboxesCheckedEventIndex`,
      `getSelectedEventIds`, `quickSubmitTagForm`/`quickSubmitGalaxyForm`
      branches (§6.2, §6.4). `new: [UI] mass tag / mass cluster actions on
      event index`
- [ ] **T5** Bulk integration tests (§9.2–9.3). `chg: [test] mass tag and
      mass cluster integration coverage`
- [ ] **T6** UI verification pass + attribute-flow non-regression (§9.4–9.5),
      screenshots attached to PR.

Branch from `2.5`; PR back to `2.5` (confirm — CLAUDE.md says feature
branches come off `2.5`, but new features sometimes land via `develop`).

## 11. Files Touched (complete list — additive-posture audit)

| File | Change |
|------|--------|
| `app/Controller/EventsController.php` | `addTag()`: `'selected'` + event-loop restructure (largest existing-code change, guarded by T1) |
| `app/Controller/GalaxiesController.php` | `attachMultipleClusters()`: event_ids branch, skip-and-count in new path only |
| `app/View/Events/add_tag.ctp` | conditional `Event.event_ids` hidden input |
| `app/View/Galaxies/ajax/attach_multiple_clusters.ctp` | conditional `event_ids` hidden input |
| `app/View/Events/index.ctp` | four toolbar button entries |
| `app/webroot/js/misp.js` | `listCheckboxesCheckedEventIndex()` toggles, `getSelectedEventIds()`, `'selected'` branches in two submit functions |
| `tests/…` | new integration tests |

No ACL, route, schema, or composer changes. No new endpoints.

## 12. Open Questions / Phase 2

1. **D4 divergence** — unify attribute path to skip-and-count too, or keep
   throw behavior? (default: keep)
2. ~~**D6 reach for non-host-org taggers**~~ — **RESOLVED 2026-06-12: no
   broadening.** Only event owners/creators and host-org taggers may tag /
   be effective targets of multi-select tagging. Non-host-org taggers
   failing on foreign events is intended behavior (see D6 ACL boundary).
3. **D6 scope** — extend the global→local downgrade to the single-event
   `addTag` / attribute flows later, for consistency? (default: bulk only;
   single-event flows keep refusing, as today)
4. Mass *remove* tag/cluster from index — follow-up PRD?
5. Clean REST bulk API: extend `tags/attachTagToObject` to accept a list of
   UUIDs (single endpoint, UUID-based, sync-friendly). Phase 2 candidate.
6. Should the result toast distinguish *which* events failed/downgraded
   (IDs), not just counts? Cheap to add to the response payload; UI message
   stays counts.
