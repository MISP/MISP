# Collection Sync

Instance-to-instance synchronisation for **Collections** (and their element
pointers), added on top of the existing MISP sync mechanism. This document is
the developer reference for the feature: what it does, how it is wired, the
enforcement rules, and how to operate and test it.

For the general sync protocol (pull/push loop, authentication, filter rules,
conflict resolution) see `sync_mechanism.md`; collection sync reuses that
machinery and follows the **Analyst Data** sync shape throughout.

---

## 1. What syncs

A *Collection* is a named, curated bundle of records (its *elements*, shown
to users as *members*). Collection sync exchanges the collection record and its
elements between instances.

- **References, not the records.** The collection and its element references
  cross the wire; the referenced events, attributes, objects and galaxy
  clusters are **never** cascade-synced by this feature. A synced collection
  may therefore reference targets that are absent on the peer; a dangling
  reference is harmless. Two kinds of member carry their content with them
  because no other record holds it: a value member keeps its own text, and a
  standalone object comes with its record (see below).
- **Elements in scope** (`CollectionElement::$valid_types`):

  | `element_type` | Addressed by | Notes |
  |----------------|--------------|-------|
  | `Event`, `GalaxyCluster` | `element_uuid` | The only types a MISP older than 3.0 holds (`CollectionElement::PRE30_TYPES`). |
  | `Attribute`, `Object` | `element_uuid` | 3.0 and later. |
  | `AttributeValue` | `element_sha256` | 3.0 and later. The member keeps its text in `element_value`, whether or not MISP holds the value. |
  | `StandaloneObject` | `element_uuid` | 3.0 and later. An object MISP does not hold as a record of an event (a module's answer, or one made from a template), stored in `standalone_objects`. |

- **Value members keep their text.** `collection_elements.element_value`
  travels with the element. The receiver keeps it only when its SHA-256 is the
  element's `element_sha256` (`CollectionElement::capturedText()`); anything
  else is dropped and the member stays an address. Analyst data still addresses
  values by SHA-256 alone, see `value_targets.md`.
- **Standalone objects travel with their record.** The element carries
  `element_uuid`; the sender attaches the `standalone_objects` row
  (`CollectionElement::withRecords()`) and the receiver stores it
  (`captureRecord()`) before the element. The record is never edited: the same
  module answer has the same uuid everywhere.
- **Where a member came from.** `collection_elements.origin` (JSON: module,
  type, value, ran_at) is set for a value or answer that came from a module,
  and travels with the element.
- **Both directions.** Pull and push are implemented together, mirroring
  analyst-data sync.
- **Distribution gates what leaves.** A collection crosses only when its own
  `distribution` permits it and, if it is shared beyond its organisation, only
  once it is published (section 4). There is no per-element visibility filter.
- **The sender's corpus is authoritative.** On capture the incoming element set
  replaces the local one wholesale (adds, updates, and deletes local-only
  elements), except for the types a pre-3.0 sender cannot hold (section 5).

### Who added a member, and when

`collection_elements.user_id` and `created` record who added each member and
when. `created` travels. `user_id` does not leave the collection's
organisation: `Collection::withoutAdders()` removes it (and the element's
`published` flag) from what is pushed, and `Collection::rearrangeCollection()`
and the REST index drop it for anyone outside the collection's organisation
(site admins excepted, `Collection::showsAdders()`). A member received from
another instance names nobody and keeps the time it was added there.

---

## 2. Schema

The first columns came with the legacy migrations **158** and **159**
(`AppModel::$db_changes`, frozen at `db_version = 159`):

| Migration | Column | Type | Meaning |
|-----------|--------|------|---------|
| 158 | `collections.locked` | `tinyint(1) NOT NULL DEFAULT 0` | `0` = created locally (authoritative), `1` = synced in from a peer. Mirrors `events.locked`. |
| 159 | `servers.push_collections` | `tinyint(1) NOT NULL DEFAULT 0` | Per-server toggle: push collections to this peer. |
| 159 | `servers.pull_collections` | `tinyint(1) NOT NULL DEFAULT 0` | Per-server toggle: pull collections from this peer. |

Every later schema change is a migration under
`app/Lib/Migration/Migrations/`, tracked by id in `schema_migrations` (see
`database-migrations.md`); nothing is added to `$db_changes` any more.

| Migration id | What it does |
|--------------|--------------|
| `20261014_141955_value_address_columns` | `collection_elements.element_sha256`, nullable `element_uuid`, `UNIQUE (element_sha256, collection_id)`: value members. |
| `20261016_180259_schema_v3_collection_elements` | Brings `collection_elements` to the 3.0 table definition. |
| `20261016_180307_schema_v3_collections` | Brings `collections` to the 3.0 table definition. |
| `20261028_090206_collection_element_provenance` | `collection_elements.user_id`, `collection_elements.created`: who added a member and when. Empty on existing members. |
| `20261028_100344_collection_publish_state` | `collections.published`, `collections.last_published`, `collections.analysis`; `collection_elements.published`; the table `collection_element_removals`. Existing shared collections start published, members included; organisation-only ones start unpublished. |
| `20261118_080050_collection_members_outside_misp` | `collection_elements.element_value` and `collection_elements.origin`; the table `standalone_objects`. Fills `element_value` for existing value members from the value table. |
| `20261120_081016_active_workspace_on_a_collection` | No DDL. Converts a user's stored `active_workspace` setting from a graph to the collection that graph is drawn on. |

`standalone_objects` holds `uuid` (unique), `module`, `name`, `template_uuid`,
`template_version`, `meta_category`, `description`, `comment`, `attributes`
(JSON) and `created`. `collection_element_removals` holds one row per published
member taken out since the last publish (`collection_id`, `element_type`,
`element_uuid` or `element_sha256`, `user_id`, `created`); the publish review
reads it and a publish clears it.

---

## 3. Feature negotiation

Advertised booleans, mirroring `filter_sightings` / `perm_analyst_data`, plus
one version check. `ServersController::getVersion()` advertises the flags and
`ServerSyncTool::isSupported()` reads them from the peer's cached `getVersion`
payload:

| Constant | Read as | What it gates |
|----------|---------|---------------|
| `FEATURE_COLLECTION_SYNC` | `collection_sync` | Collection sync at all. |
| `FEATURE_ANALYST_GRAPH` | `analyst_graph` | Analyst data sync carries the `Graph` type. |
| `FEATURE_VALUE_TARGETS` | the peer's `version` is 3.0.0 or later | Whether the peer holds anything beyond event and galaxy cluster members, and value-addressed analyst data. |
| `FEATURE_STANDALONE_OBJECTS` | `standalone_objects` | Whether the peer can hold standalone object members. |

A peer that omits `collection_sync` makes `isSupported` false, so `Server::pull`
and `Server::push` skip the collection blocks silently, with **no
`/collections/*` round-trip** attempted. Other data types sync normally.
`Collection::push` additionally drops what the peer cannot hold before it
offers anything (section 5).

---

## 4. Pull flow

`Server::pull` (inside the `full`/`update` technique gate, after the analyst-data
pull) runs the collection block when
`!empty($server['Server']['pull_collections']) && isSupported(FEATURE_COLLECTION_SYNC)`:

1. `Collection::pull($user, $serverSync)`:
   - `buildPullFilterRules(server)` → the `orgc_name` OR/NOT filter (from the
     server's `pull_rules`), which the remote `indexMinimal` resolves to `orgc_id`.
     Against a 3.0 remote (`FEATURE_VALUE_TARGETS`) the rules also carry
     `published: 1`, as the event pull asks `events/index` for published events.
   - `ServerSyncTool::collectionIndexMinimal($rules)` → remote `POST
     /collections/indexMinimal` → a flat `{uuid: modified}` map (collections have
     no analyst-data `type` dimension).
   - **Dedup:** fetch uuids that are missing locally **or** strictly newer on the
     remote (`localModified < remoteModified`; equal is skipped). A collection
     created here (`locked = 0`) is not fetched from a non-internal server, since
     the capture would refuse it (section 6), as `filterCollectionsForPush` already
     declines it on push.
   - `pullCollectionsInChunks` — `array_chunk(100)` →
     `ServerSyncTool::fetchCollections($chunk)` (remote `GET /collections/index/uuid[]:….json`,
     full collections **including** `CollectionElement`) → each RAW collection to
     the shared capture sink. The remote's version decides whether the capture
     treats the sender as older than 3.0 (`FEATURE_VALUE_TARGETS`).
2. The imported count is folded into the pull `$change` DB-log line and returned
   as element `[6]` of `Server::pull`'s result array (callers index `[0..5]`
   positionally ⇒ appending `[6]` is non-breaking). The user-facing
   "*… N collections pulled*" clause is added in `ServersController::pull` and
   `ServerShell::pull`.

---

## 5. Push flow

`Server::push` (after the analyst-data push block) runs the collection block when
`!empty($server['Server']['push_collections']) && isSupported(FEATURE_COLLECTION_SYNC)`:

1. `Collection::push($user, $serverSync)`:
   - `collectDataForPush($server)` — eligible = **published** (see below) and
     distribution 1–3, or 4 when the server is a member of the collection's
     sharing group (`collectValidSharingGroupIDs`). The dist=4 sharing group is
     enriched with its full org/server structure so the remote `captureSG` can
     create it if missing; the `Orgc` / `SharingGroup` / `CollectionElement`
     corpus is nested under `Collection`, each standalone object member with its
     record. Filtered by `Event::checkDistributionForPush(…, 'Collection')` and
     the server's org push-rules (`isPushableForServerSyncRules`).
   - **Peers that cannot hold every member type.** Without
     `FEATURE_VALUE_TARGETS` (older than 3.0), `withoutElementsNewIn30()` keeps
     only `Event` and `GalaxyCluster` elements. Without
     `FEATURE_STANDALONE_OBJECTS`, `withoutStandaloneObjects()` drops
     `StandaloneObject` elements. The collections themselves still go.
   - Offer `{uuid: modified}` to `ServerSyncTool::filterCollectionsForPush`; the
     remote replies with the subset it wants (its receive-side dedup).
   - For each wanted uuid, `uploadCollectionToServer` →
     `prepareForPushToServer` (re-check dist=4 SG membership + distribution rules,
     **strip local `id`**, strip each element's `user_id` and `published`) →
     remote `POST /collections/captureCollection`.
2. The pushed count is appended to the push `$change` DB-log line. The push
   **caller** message surfaces only events (parity with the other sync types);
   the collections count lives in the DB-log, not that message.

**Push sends RAW.** `prepareForPushToServer` does **not** downgrade distribution
and does **not** set `locked` — the receiving capture sink owns both. Pre-applying
them here would double-downgrade. This keeps push symmetric with pull (both pass
raw payloads).

### Publishing: a shared collection waits until it is published

A collection shared beyond its organisation (`distribution != 0`) changes in-house
until someone with the right publishes it, as an event does.

| Field | Meaning |
|-------|---------|
| `collections.published` | Partners may receive the collection. Cleared by any change to it, a member added or removed, or a graph or relationship its organisation drew on it. |
| `collections.last_published` | When it was last published. |
| `collections.analysis` | How far the investigation went: `0` Initial, `1` Ongoing, `2` Completed (`Collection::ANALYSIS_LEVELS`). Set with a publish, or on its own through `collections/analysis`. |
| `collection_elements.published` | Partners already hold this member. |
| `collection_element_removals` | Published members taken out since the last publish, so the review can list them. |

`Collection::publish()` sets `published` and `last_published` (and `analysis`
when given), marks every member released and clears the removal rows.
`collections/publish` then sends it at once, as an event's publish does:
`Collection::publishRouter()` enqueues `publish_collection` (`EventShell`, the
prio queue), or runs inline without background jobs, and
`Collection::uploadToServers()` pushes that collection alone to every server with
`push` and `push_collections`, followed by the graphs and relationships it held
back (`AnalystData::push()` narrowed to them). Later pushes and pulls carry it as
before.
`Collection::unpublish()` clears `published` only: partners keep the version
they last received and `modified` stays, so they need not refetch it. A
collection shared with the organisation only (`distribution = 0`) has nothing to
publish.

A collection that is shared beyond its organisation and not published is
*withheld* (`Collection::isWithheld()`, `Collection::releasedConditions()`):

- It is not pushed (`collectDataForPush` requires `published`).
- It is not pulled. As an unpublished event, it is still listed and shown to
  whoever may see it, another 3.0 instance included, with `published: false`;
  the pulling instance asks `indexMinimal` for `published: 1` and the capture
  sink ignores a payload that says it is withheld (a collection unpublished
  between the index and the fetch).
- A MISP older than 3.0 (`SyncTool::requesterBelow30()`, from the
  `User-Agent: MISP <x.y.z>` header) has no publish step to tell them apart,
  so `collections/index`, `collections/view` and `collections/indexMinimal`
  serve it released collections only (`Collection::servedConditions()`).
- With `MISP.unpublishedprivate`, it is hidden from other organisations' users
  altogether (`Collection::buildConditions()`, `mayView()`), as an unpublished
  event is.
- What its organisation drew on it is withheld from another instance:
  analyst data `indexMinimal`,
  the analyst data pushed and the relationships nested in event, attribute and
  object views drop the collection's graphs and the relationships between its
  members (`Collection::withoutHeldBack()`, `servedRelationships()`,
  `holdsBack()`). Notes and opinions never wait.

Publishing and unpublishing take the edit right on the collection plus
`perm_publish` (`Collection::canPublish()`), the same as publishing an event;
a site admin always may. The review the publish shows
(`Collection::publishReview()`, members added and removed since the last
publish, links, graphs, and values narrower than the collection) lists at most
`Collection::REVIEW_LIMIT` entries per kind.

A collection captured from a peer is stored as published
(`captureCollection` sets `published` and takes `last_published` from the
payload), since a peer only sends what it published. From a sender older than
3.0 only its `Event` and `GalaxyCluster` members and their removals are released:
members of other types kept here keep their own state, and if one of them, or
its removal, is still unpublished, the collection stays withheld until someone
here publishes it.

When a collection is widened, `collections/shareAlong` lists the graphs and
relationships its organisation drew on it that reach fewer than the new
sharing; the edit form can apply them (`Collection::applyShareAlong()`).

---

## 6. The shared capture sink — `Collection::captureCollection`

The single ingest point for **both** directions (pull, and the push-receive
controller action). Modelled on `GalaxyCluster::captureCluster` (the integer-FK
analogue — collections key org/orgc/SG by integer id, not uuid columns). It owns
every enforcement rule, so callers pass the **raw** remote collection:

- **locked = 1.** Every accepted capture is marked synced-in.
- **Published.** A capture is stored as published.
- **Last-writer-wins, guarded by `locked`.** A locally-created (`locked=0`)
  collection is authoritative and is **never** overwritten by a non-internal
  remote (blocked). Otherwise the strictly-newer `modified` wins; equal/older is
  skipped. (An *internal* server may overwrite a local original.)
- **Creator neutralised.** `user_id` is pinned to the sync user, `org_id` to
  the sync user's org; `orgc_id` / `sharing_group_id` are resolved by UUID.
- **Distribution downgrade on incoming.** `1 → 0`, `2 → 1`, unless the server is
  internal *and* the remote sync user has `perm_sync_internal` *and* the host org
  matches (mirrors `updatePulled*BeforeInsert`). `3` and `4` are unchanged; an
  unresolvable dist=4 sharing group falls back to dist=0.
- **Corpus replace.** The incoming `CollectionElement` set replaces the local
  one via `CollectionElement::captureElements()`. **Key present but empty ⇒ cull
  all** local elements; **key absent ⇒ elements left untouched** (so the fetch
  endpoint must always serialize `CollectionElement`, even when empty). Rows
  match by their uuid, else by the element they point at.
- **A sender older than 3.0.** `captureCollection` takes `$fromPre30` (the pulls
  pass it from the remote's version; push receive passes `null`, so the
  requester's `User-Agent` decides, `SyncTool::valueTargetsWithheld()`). From
  such a sender only `Event` and `GalaxyCluster` elements are taken, and local
  elements of the other types are **kept**, not culled as absent
  (`CollectionElement::heldBefore30()`).
- **Provenance.** A new element from another instance gets `user_id = NULL`
  and the `created` it came with; `published` is set to true.
- **Value text.** `element_value` is kept only when it hashes to
  `element_sha256`. A standalone object's record is validated and stored
  before the element; an element naming another record than the one attached is
  dropped.
- **Mass-assignment discipline.** All identity/security fields
  (`uuid`, `org_id`, `orgc_id`, `user_id`, `locked`) are pinned from
  server-derived context via an explicit `$fieldList`, which also carries
  `published`, `last_published` and, when valid, `analysis`; the payload `id` is dropped
  (capture keys on `uuid`). The remote `modified` is preserved verbatim (dedup
  depends on it).

Element-modified propagation: `CollectionElement` add/remove/capture bumps
the parent `Collection.modified` (so `{uuid: modified}` dedup stays correct),
except inside `captureElements`, which suppresses the bump so the remote
`modified` written by the sink stays authoritative.

`locked` cannot be flipped by a normal web user: `Collection::beforeValidate`
forces `locked=0` on create for non-`perm_sync` callers, and
`CollectionsController::edit` pins `locked` to the stored value. Only the capture
sink (a `perm_sync` context) sets `locked=1`.

---

## 7. Endpoints, ACL, CSRF

New `CollectionsController` sync actions (all REST; CSRF is auto-unlocked for REST
in `AppController::beforeFilter`, so no `unlockedActions[]` entries are needed):

| Action | ACL (`ACLComponent` `collections` block) | Purpose |
|--------|------------------------------------------|---------|
| `indexMinimal` | `['*']` | `{uuid: modified}` index (visibility-filtered inside); `published` 1 or 0 keeps released or withheld collections only. |
| `index` | `['*']` | Full collection fetch (REST adds `contain CollectionElement` + `uuid[]` filter). |
| `filterCollectionsForPush` | `['perm_sync']` | Push-receive dedup handshake. |
| `captureCollection` | `['perm_sync']` | Push-receive upload → the shared sink. |
| `publish`, `unpublish` | `['perm_modify', 'perm_publish']` | Release a shared collection to partners, or withdraw it (section 5). |
| `analysis` | `['perm_modify']` | Set how far the investigation went. |
| `shareAlong` | `['perm_modify']` | What would go along with a collection widened to a distribution. |

On the requester side, `collections/index`, `collections/view` and
`collections/indexMinimal` leave withheld collections out for a MISP older than
3.0 (`Collection::servedConditions()`), and `index` and `view` serve the
elements through `Collection::servedElementOptions()`: a requester older than
3.0 is served only `Event` and `GalaxyCluster` elements. A collection the caller
may not see answers 404, as one that does not exist, on `view`, `edit`,
`delete` and the element `add`/`delete`.
ACL is **default-deny**: an action absent from the controller's block falls
through to site-admin-only then Forbidden, so every sync action needs an explicit
entry. `captureCollection` / `filterCollectionsForPush` additionally hard-check
`perm_sync` + `_isRest()` in the action body (defense-in-depth). Access uses the
existing `perm_sync` permission — there is no sync-specific permission for collections.
Routing needs no `routes.php` change (default `/:controller/:action`).

---

## 8. UI & operation

- **Server add / edit form** (`View/Servers/edit.ctp`, shared by `add()`): two
  checkboxes, *Push Collections* / *Pull Collections*, after the analyst-data
  pair. `ServersController::edit()` whitelists both in its save `$fieldList`
  (`add()` saves field-list-less, so they persist automatically).
- **Server list** (`View/Servers/index.ctp`): two boolean columns (there is no
  `Servers/view.ctp` — the index is the server-view surface).
- **Job output:** the pull-completed message gains "*… N collections pulled.*";
  the push count is in the push `$change` DB-log.

To enable for a peer: tick *Pull Collections* and/or *Push Collections* on the
`Server` record (both instances must run the feature code — negotiation silently
skips otherwise). On a real deploy, confirm the migrations of section 2 are applied
(`Admin migrationStatus`).

Both instances should run a current version: a peer that does not advertise
`standalone_objects`, or is older than 3.0, receives fewer member types, and
what it sends back never removes members it cannot hold. Collections shared
beyond their organisation reach partners only once published.

---

## 9. Testing

- **Unit (bare PHPUnit, `app/Test/`):**
  - `CollectionCaptureTest.php` — every `captureCollection` branch (create/update,
    locked block, downgrade, dist=4 SG, corpus replace, mass-assignment).
  - `CollectionPullTest.php` — `Collection::pull` (negotiation gate, dedup, RAW
    passthrough, chunking, `buildPullFilterRules`).
  - `CollectionPushTest.php` — the push chain (orchestration, receive dedup,
    push-rules, `prepareForPushToServer`, `collectDataForPush`).
  - `CollectionElementCaptureTest.php`, `CollectionMembersOutsideMispTest.php` —
    element capture, value text, standalone objects, pre-3.0 senders.
  - `CollectionPublishTest.php` — publish state, withheld collections and what
    they hold back.
  - `ServerSyncCollectionNegotiationTest.php` — capability flags.
  - `SyncAnalystDataWithheldTest.php` — analyst data of withheld collections.
- **End-to-end (`tests/testlive_collection_sync.py`):** a PyMISP harness with a
  **loopback** mode (CI-friendly, single instance — asserts negotiation + the
  push/pull round-trips) and a **two-instance** mode (`REMOTE_HOST`/`REMOTE_AUTH`
  — asserts the capture write branch: `locked=1`, dist 2→1, element replication,
  idempotency + origin protection). A self-loopback cannot make a collection
  actually cross (skip-on-equal against an equal local copy), so the
  write-branch assertions require a distinct peer. Run against a `debug=0`
  instance (debug-mode PHP warnings corrupt REST JSON bodies).

---

## 10. Code map

| Concern | Location |
|---------|----------|
| Schema | Legacy 158/159 in `app/Model/AppModel.php` (`$db_changes`); everything since under `app/Lib/Migration/Migrations/` (section 2) |
| Capture sink + pull + push model | `app/Model/Collection.php` (`captureCollection`, `pull`, `push`, `collectDataForPush`, `filterCollectionsForPush`, `prepareForPushToServer`, `withoutElementsNewIn30`, `withoutStandaloneObjects`, `servedElementOptions`) |
| Publish state and withholding | `app/Model/Collection.php` (`publish`, `unpublish`, `isWithheld`, `releasedConditions`, `withheldScopes`, `holdsBack`, `withoutHeldBack`, `servedRelationships`, `publishReview`, `shareAlong`) |
| Elements | `app/Model/CollectionElement.php` (`captureElements`, `heldBefore30`, `withRecords`, `captureRecord`, `addItems`, modified-bump in `afterSave` / `afterDelete`), `app/Model/StandaloneObject.php` |
| Sync client methods | `app/Lib/Tools/ServerSyncTool.php` (`collectionIndexMinimal`, `fetchCollections`, `filterCollectionsForPush`, `pushCollection`, `isSupported`); `app/Lib/Tools/SyncTool.php` (`requesterMispVersion`, `requesterIsMisp`, `valueTargetsWithheld`) |
| Receive endpoints + ACL | `app/Controller/CollectionsController.php`, `app/Controller/Component/ACLComponent.php` (`collections` block) |
| Pull/push wiring + negotiation advertise | `app/Model/Server.php` (`pull` / `push` collection blocks), `app/Controller/ServersController.php` (`getVersion`) |
| Server toggles UI | `app/View/Servers/edit.ctp`, `app/View/Servers/index.ctp` |
