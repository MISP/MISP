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

A *Collection* is a named, curated bundle of pointers to Events and/or Galaxy
Clusters (its *elements*). Collection sync exchanges the collection record and
its element **pointers** between instances.

- **Pointers only (D1).** The collection and its element references cross the
  wire; the referenced Events / Galaxy Clusters are **never** cascade-synced by
  this feature. A synced collection may therefore reference targets that are
  absent on the peer (accepted — a dangling pointer is harmless).
- **Elements in scope:** `Event` and `GalaxyCluster` only
  (`CollectionElement::$valid_types`).
- **Both directions (D2).** Pull and push are implemented together, mirroring
  analyst-data sync.
- **Distribution is the only leak gate (D4).** A collection crosses only when its
  own `distribution` permits it; there is no per-element visibility filter.
- **Corpus is authoritative (D5).** On capture the incoming element set replaces
  the local one wholesale (adds, updates, and deletes local-only elements).

---

## 2. Schema

Three columns, added by migrations **158** and **159**
(`AppModel::updateDatabase()`; canonical schema `db_schema.json` at repo root,
`db_version = 159`; also present in `INSTALL/MYSQL.sql`'s baseline `CREATE TABLE`s):

| Migration | Column | Type | Meaning |
|-----------|--------|------|---------|
| 158 | `collections.locked` | `tinyint(1) NOT NULL DEFAULT 0` | `0` = created locally (authoritative), `1` = synced in from a peer. Mirrors `events.locked`. |
| 159 | `servers.push_collections` | `tinyint(1) NOT NULL DEFAULT 0` | Per-server toggle: push collections to this peer. |
| 159 | `servers.pull_collections` | `tinyint(1) NOT NULL DEFAULT 0` | Per-server toggle: pull collections from this peer. |

### ⚠ Migration-numbering / deploy trap

The feature's migrations were originally numbered **155/156**, which sit *below*
`develop`'s event-template migration **157**. `AppModel::findUpgrades()` applies
only migration keys **strictly greater than** the stored `admin_settings.db_version`.
So an instance that had already reached `db_version 157` via upstream `develop`
(and never had 155/156) would **skip** them on gaining this code — the columns
would never be created, while `getVersion` already advertises `collection_sync`
(a live trap: capability advertised, columns missing). This bit the second test
instance during E2E.

**Fix (commit `f94da2aa5`):** the migrations were renumbered to **158/159**, above
the current `develop` max, so any instance `<= 157` applies them via
`findUpgrades`. Already-migrated boxes self-heal: re-adding an existing column is
an **accepted** duplicate-column error (`AppModel::isAcceptedDatabaseError`,
SQLSTATE `42S21` / MySQL `1060`). The `$db_changes` map is intentionally gappy
(`… 154, 157, 158, 159`) — do not backfill a no-op `155/156`.

---

## 3. Feature negotiation

Advertised-boolean, mirroring `filter_sightings` / `perm_analyst_data` (not a
version gate — there is no release number to hardcode):

- `ServerSyncTool::FEATURE_COLLECTION_SYNC = 'collection_sync'`.
- `ServersController::getVersion()` advertises `'collection_sync' => true`
  (`ServersController.php:1997`).
- `ServerSyncTool::isSupported(FEATURE_COLLECTION_SYNC)` reads
  `$this->info()['collection_sync']` (the peer's cached `getVersion` payload).

An older peer omits the key ⇒ `isSupported` is false ⇒ `Server::pull` /
`Server::push` skip the collection blocks silently, with **no `/collections/*`
round-trip** attempted. Other data types sync normally.

---

## 4. Pull flow

`Server::pull` (inside the `full`/`update` technique gate, after the analyst-data
pull) runs the collection block when
`!empty($server['Server']['pull_collections']) && isSupported(FEATURE_COLLECTION_SYNC)`:

1. `Collection::pull($user, $serverSync)`:
   - `buildPullFilterRules(server)` → the `orgc_name` OR/NOT filter (from the
     server's `pull_rules`), which the remote `indexMinimal` resolves to `orgc_id`.
   - `ServerSyncTool::collectionIndexMinimal($rules)` → remote `POST
     /collections/indexMinimal` → a flat `{uuid: modified}` map (collections have
     no analyst-data `type` dimension).
   - **Dedup:** fetch uuids that are missing locally **or** strictly newer on the
     remote (`localModified < remoteModified`; equal is skipped — D6).
   - `pullCollectionsInChunks` — `array_chunk(100)` →
     `ServerSyncTool::fetchCollections($chunk)` (remote `GET /collections/index/uuid[]:….json`,
     full collections **including** `CollectionElement`) → each RAW collection to
     the shared capture sink.
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
   - `collectDataForPush($server)` — eligible = distribution 1–3, or 4 when the
     server is a member of the collection's sharing group
     (`collectValidSharingGroupIDs`). The dist=4 sharing group is enriched with
     its full org/server structure so the remote `captureSG` can create it if
     missing; the `Orgc` / `SharingGroup` / `CollectionElement` corpus is nested
     under `Collection`. Filtered by `Event::checkDistributionForPush(…,
     'Collection')` and the server's org push-rules (`isPushableForServerSyncRules`).
   - Offer `{uuid: modified}` to `ServerSyncTool::filterCollectionsForPush`; the
     remote replies with the subset it wants (its receive-side dedup).
   - For each wanted uuid, `uploadCollectionToServer` →
     `prepareForPushToServer` (re-check dist=4 SG membership + distribution rules,
     **strip local `id`**) → remote `POST /collections/captureCollection`.
2. The pushed count is appended to the push `$change` DB-log line. The push
   **caller** message surfaces only events (parity with the other sync types);
   the collections count lives in the DB-log, not that message.

**Push sends RAW.** `prepareForPushToServer` does **not** downgrade distribution
and does **not** set `locked` — the receiving capture sink owns both. Pre-applying
them here would double-downgrade. This keeps push symmetric with pull (both pass
raw payloads).

---

## 6. The shared capture sink — `Collection::captureCollection`

The single ingest point for **both** directions (pull, and the push-receive
controller action). Modelled on `GalaxyCluster::captureCluster` (the integer-FK
analogue — collections key org/orgc/SG by integer id, not uuid columns). It owns
every enforcement rule, so callers pass the **raw** remote collection:

- **locked = 1.** Every accepted capture is marked synced-in.
- **D6 last-writer-wins, guarded by `locked`.** A locally-created (`locked=0`)
  collection is authoritative and is **never** overwritten by a non-internal
  remote (blocked). Otherwise the strictly-newer `modified` wins; equal/older is
  skipped. (An *internal* server may overwrite a local original.)
- **D7 creator neutralised.** `user_id` is pinned to the sync user, `org_id` to
  the sync user's org; `orgc_id` / `sharing_group_id` are resolved by UUID.
- **Distribution downgrade on incoming.** `1 → 0`, `2 → 1`, unless the server is
  internal *and* the remote sync user has `perm_sync_internal` *and* the host org
  matches (mirrors `updatePulled*BeforeInsert`). `3` and `4` are unchanged; an
  unresolvable dist=4 sharing group falls back to dist=0.
- **Corpus replace (D5).** The incoming `CollectionElement` set replaces the local
  one via `CollectionElement::captureElements()`. **Key present but empty ⇒ cull
  all** local elements; **key absent ⇒ elements left untouched** (so the fetch
  endpoint must always serialize `CollectionElement`, even when empty).
- **Mass-assignment discipline (PRD §7).** All identity/security fields
  (`uuid`, `org_id`, `orgc_id`, `user_id`, `locked`) are pinned from
  server-derived context via an explicit `$fieldList`; the payload `id` is dropped
  (capture keys on `uuid`). The remote `modified` is preserved verbatim (dedup
  depends on it).

Element-modified propagation (D5): `CollectionElement` add/remove/capture bumps
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
| `indexMinimal` | `['*']` | `{uuid: modified}` index (visibility-filtered inside). |
| `index` | `['*']` | Full collection fetch (REST adds `contain CollectionElement` + `uuid[]` filter). |
| `filterCollectionsForPush` | `['perm_sync']` | Push-receive dedup handshake. |
| `captureCollection` | `['perm_sync']` | Push-receive upload → the shared sink. |

ACL is **default-deny**: an action absent from the controller's block falls
through to site-admin-only then Forbidden, so every sync action needs an explicit
entry. `captureCollection` / `filterCollectionsForPush` additionally hard-check
`perm_sync` + `_isRest()` in the action body (defense-in-depth). Access uses the
existing `perm_sync` permission — **no new permission** was introduced (D3).
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
skips otherwise). On a real deploy, confirm the migrations actually ran
(`Admin runUpdates` → `db_version 159`, columns present) — see the numbering trap
in §2.

---

## 9. Testing

- **Unit (bare PHPUnit, `app/Test/`):**
  - `CollectionCaptureTest.php` — every `captureCollection` branch (create/update,
    locked block, downgrade, dist=4 SG, corpus replace, mass-assignment).
  - `CollectionPullTest.php` — `Collection::pull` (negotiation gate, D6 dedup, RAW
    passthrough, chunking, `buildPullFilterRules`).
  - `CollectionPushTest.php` — the push chain (orchestration, receive dedup,
    push-rules, `prepareForPushToServer`, `collectDataForPush`).
- **End-to-end (`tests/testlive_collection_sync.py`):** a PyMISP harness with a
  **loopback** mode (CI-friendly, single instance — asserts negotiation + the
  push/pull round-trips) and a **two-instance** mode (`REMOTE_HOST`/`REMOTE_AUTH`
  — asserts the capture write branch: `locked=1`, dist 2→1, element replication,
  D6 idempotency + origin protection). A self-loopback cannot make a collection
  actually cross (D6 skip-on-equal against an equal local copy), so the
  write-branch assertions require a distinct peer. Run against a `debug=0`
  instance (debug-mode PHP warnings corrupt REST JSON bodies).

---

## 10. Code map

| Concern | Location |
|---------|----------|
| Schema migrations 158/159 | `app/Model/AppModel.php` (`updateDatabase`, `$db_changes`), `db_schema.json`, `INSTALL/MYSQL.sql` |
| Capture sink + pull + push model | `app/Model/Collection.php` (`captureCollection`, `pull`, `push`, `collectDataForPush`, `filterCollectionsForPush`, `prepareForPushToServer`) |
| Element modified-bump | `app/Model/CollectionElement.php` (`afterSave` / `afterDelete`, `captureElements`) |
| Sync client methods | `app/Lib/Tools/ServerSyncTool.php` (`collectionIndexMinimal`, `fetchCollections`, `filterCollectionsForPush`, `pushCollection`, `isSupported`) |
| Receive endpoints + ACL | `app/Controller/CollectionsController.php`, `app/Controller/Component/ACLComponent.php` (`collections` block) |
| Pull/push wiring + negotiation advertise | `app/Model/Server.php` (`pull` / `push` collection blocks), `app/Controller/ServersController.php` (`getVersion`) |
| Server toggles UI | `app/View/Servers/edit.ctp`, `app/View/Servers/index.ctp` |
