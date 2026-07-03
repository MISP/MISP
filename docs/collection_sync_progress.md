# Collection Sync — Progress Tracker

In-repo, checked-in source of truth for ticked task state across sessions.
Full design lives in `collection_sync_prd.md` (owner's `~/prds`, not in-repo).

- **Branch:** `develop` (merged from `feature-collection-sync` at `6170ffa18`, 2026-07-01).
  Original feature branch was off `2.5`; ongoing work continues on `develop`.
- **Model commit this builds on:** `846c130fa` — *"new: [collections] feature added. Still missing sync integration - WiP"*
- **Execution rule:** strictly sequential — one task, one commit (body cites task id);
  gitchangelog titles (`new:`/`fix:`/`chg: [collections] …`). `[security]` label only if CVE-worthy.
- **Line-number caveat:** all `file:line` anchors in the PRD are point-in-time;
  re-verify against the working tree before editing.

## Locked design decisions (full rationale → PRD §4)
- **D1** pointers-only (sync collection + element refs verbatim; never cascade-sync targets)
- **D2** both directions (pull + push together; analyst-data shape)
- **D3** server toggles `pull_collections` / `push_collections`; gate on existing `perm_sync`; no new perm
- **D4** no per-element leak filter (the collection's own `distribution` is the sole gate)
- **D5** element edits propagate; corpus authoritative (incoming set replaces local)
- **D6** last-writer-wins by `modified` + `collections.locked` (Event/Analyst-Data rule)
- **D7** neutralize creator `user_id` → sync user on capture
- **D8** full UI/job surfacing (toggles + collection counts in job/preview/server view)

Accepted non-additive touch points = **PRD §5**. Anything beyond that list needs fresh sign-off.

---

## Phase 0 — Scaffolding & research lock-in
- [x] **T0.1** Create this tracker (`docs/collection_sync_progress.md`).
- [x] **T0.2** Confirm feature-flag registry location + `isSupported` wiring; fix the exact
  `FEATURE_COLLECTION_SYNC` constant name and where it's declared. → findings below.
- [x] **T0.3** Confirm ACL/route/CSRF-unlock mechanism for new sync actions. → findings below.

### T0.3 findings — ACL / routes / CSRF-unlock (re-verify line #s before editing)
- **CSRF is auto-unlocked for all REST calls.** `AppController::beforeFilter` (`:230-242`):
  when `$this->_isRest()` it sets `$this->Security->unlockedActions = [$action]` and
  `doNotGenerateToken = true`. Sync calls are always REST (API key + JSON) ⇒ **no per-action
  `$this->Security->unlockedActions[]` registration is needed** for the sync receive/handshake
  endpoints. (The per-action `unlockedActions[]` lines seen in other controllers are only for
  *non-REST* AJAX endpoints; `AnalystDataController` adds none.)
- **ACL registry:** `app/Controller/Component/ACLComponent.php`, the `ACL_LIST` array.
  `'collections'` block at `:130-140`, `'collectionElements'` at `:141-147`.
- **★ DEFAULT-DENY ★** `checkAccess()` (`:1498-1556`): unknown controller → `NotFoundException`
  (`:1505`); an action **absent** from the controller's list skips every permission branch and
  falls through to site-admin-only (`:1552`) then `ForbiddenException` (`:1555`). ⇒ **every new
  sync action MUST get an explicit entry in the `'collections'` ACL block**, or a non-site-admin
  sync user (`perm_sync`, the normal sync role) is hard-403'd.
- **Analyst-data ACL template** (`:22-33`) to mirror for collections:
  - read endpoints → `'indexMinimal' => ['*']`, `'index' => ['*']`, `'view' => ['*']`
    (visibility is filtered *inside* via `buildConditions`; `['*']` = any authenticated user).
  - write/handshake → `'filterAnalystDataForPush' => ['perm_sync']`,
    `'pushAnalystData' => ['perm_sync']`.
  Planned collection entries (added in T3.2/T4.2): `indexMinimal => ['*']`, the fetch endpoint
  → `['*']` (or reuse `index`), `filterCollectionsForPush => ['perm_sync']`,
  `captureCollection => ['perm_sync']`.
- **Routes:** `app/Config/routes.php` has **no** `analyst_data`/`collections` entries — default
  CakePHP `/:controller/:action` routing covers sync endpoints. ⇒ **no `routes.php` change is
  required** (tightens PRD §5 item 7: the real touch point is `ACLComponent.php`, not routes).
- **Defense-in-depth in-action gate:** `AnalystDataController::pushAnalystData` (`:336-341`)
  *also* hard-checks `perm_sync` (+`perm_analyst_data`) and `_isRest()` in the action body, on
  top of ACL. Mirror this in the collection capture/filter actions (D3 ⇒ `perm_sync` only, no
  new perm, no `perm_analyst_data` analogue).

### T0.2 findings — feature negotiation (re-verify line #s before editing)
- **Consumer side:** `ServerSyncTool::isSupported($flag)` (`app/Lib/Tools/ServerSyncTool.php:502`)
  switches on the flag and reads `$this->info()` — the remote's metadata fetched from
  `GET /servers/getVersion` (`ServerSyncTool::info()` `:377`).
- **Constant registry:** the `FEATURE_*` / `PERM_*` consts are a single `const` block at the
  top of `ServerSyncTool.php` (`:7-19`). Add `FEATURE_COLLECTION_SYNC = 'collection_sync'` here.
- **Advertiser side:** `ServersController::getVersion()` (`app/Controller/ServersController.php:1982-1998`)
  builds the info payload (`version`, `perm_sync`, `perm_analyst_data`, `filter_sightings`, …).
- **Two negotiation patterns coexist:**
  1. *Version-gated* (e.g. `FEATURE_SIGHTING_REST_SEARCH` `:532` parses `$info['version']`).
     Needs a hardcoded target release (`2.5.X` / `>2`).
  2. *Advertised-boolean* (e.g. `FEATURE_FILTER_SIGHTINGS` `:510` reads `$info['filter_sightings']`;
     `PERM_ANALYST_DATA` `:530` reads `$info['perm_analyst_data']`). Remote adds one key.
- **LOCKED CHOICE → advertised-boolean.** Add `'collection_sync' => true` to the `getVersion`
  payload, `FEATURE_COLLECTION_SYNC = 'collection_sync'` to the const block, and
  `case self::FEATURE_COLLECTION_SYNC: return isset($info['collection_sync']) && $info['collection_sync'];`
  to `isSupported`. Rationale: no release-version number to guess (we don't know the hotfix);
  mirrors `filter_sightings`, the closest analogue (a boolean capability, not a pure version gate);
  backport-robust. Refines PRD §6.8 (which loosely said "mirror `FEATURE_SIGHTING_REST_SEARCH`").

## Phase 1 — Schema & model foundations
- [x] **T1.1** Add `collections.locked` — migration 155 + canonical schema. → findings below.

### T1.1 findings — schema-migration edit sites (CORRECTS the PRD)
- **★ Canonical schema is `db_schema.json` at repo ROOT ★** (read by `Server::getExpectedDBSchema`
  `Server.php:3559`; `schemaDiagnostics` compares actual-vs-this). **The PRD's `app/Lib/db_schema.php`
  is WRONG** — that path is an empty, untracked 0-byte scratch file. Do not edit it.
- **Three edit sites for a schema column** (verified working pattern from `case 153`):
  1. `AppModel::updateDatabase()` — new `case 155:` with the `ALTER` (`AppModel.php:2701`).
  2. `AppModel` `$db_changes` map — `155 => false` (no forced logout; gap at 154 is intentional).
  3. `db_schema.json` — add the column object to `schema.collections` **and** bump top-level
     `db_version` 153→155 (it tracks the latest migration). `MYSQL.sql` — add the column to the
     `collections` CREATE TABLE; **leave MYSQL.sql's `db_version='126'` baseline untouched** (the
     established convention — e.g. `taxii_servers.enabled`/153 is in MYSQL.sql with db_version 126).
- **`locked` column = `tinyint(1) NOT NULL DEFAULT 0`** (mirrors `events.locked` byte-for-byte in
  both db_schema.json and MYSQL.sql). No index on `locked` (matches events; indexes section untouched).
- **Dev DB live state (read-only check):** `collections` has the 12 original cols, **no `locked`**;
  `admin_settings.db_version = 154` (dev runs `develop` code → already has TAXII 154). ⇒ migration 155
  applies cleanly on top (`findUpgrades(154)` yields only 155). Live `runUpdates` application deferred
  (dev is a 2.5-code-on-154-DB hybrid after the branch switch; apply during regression / T6.3).
- [x] **T1.2** Add `servers.pull_collections` + `push_collections` — migration 156 (same three
  places as T1.1). `tinyint(1) NOT NULL DEFAULT 0`, mirrors `pull/push_analyst_data`; placed after
  `pull_galaxy_clusters` (order is cosmetic — `compareDBSchema` keys by column_name). db_version→156.
- [x] **T1.3** Bump `Collection.modified` on element add/remove/capture (D5). → findings below.

### T1.3 findings — element-modified propagation (D5)
- **Implemented purely at the model layer** in `CollectionElement` (zero controller edits — cleaner
  than PRD §6.3's controller-touch plan, and a strict subset of the §5 accepted touch points):
  `afterSave` + `beforeDelete`(stash collection_id)/`afterDelete` → `touchCollection()` which does
  a callback-free `Collection->updateAll(['modified' => now], ['id' => collectionId])`.
- **Covers all five mutation paths** (verified via CRUDComponent): `CRUD->add` (`save`),
  `addElementToCollection` (`save`), `CRUD->delete` (`delete`), `CRUD->deleteSelection`
  (per-item `delete`), and `captureElements` (`save`/`delete`).
- **`updateAll` chosen** over `saveField`: no callbacks/validation, and it harmlessly affects 0 rows
  if the parent is mid-cascade-delete (avoids a spurious-insert / stale-id edge).
- **Sync-capture suppression:** new `public $skipCollectionModifiedBump` flag, set inside
  `captureElements`, makes element saves/deletes there NOT bump `modified` — capture's `modified`
  is the REMOTE's value, set authoritatively by `Collection::captureCollection` (T2.1). Without
  this, capture would clobber the remote `modified` and break `{uuid: modified}` dedup.
- **★ LIVE-VERIFIED on dev (localhost:5007, this branch's code) ★** API add element → collection
  `modified` jumped 2024-03-05 → 2026-06-30 (now); API delete element (after resetting modified to
  2024-01-01) → bumped to now again. Test element removed, original modified restored.
- [x] **T1.4** `Collection` model: set `locked=0` on local create; allow capture to set `1`. → findings below.

### T1.4 findings — locked mass-assignment guard on create
- **Implemented in `Collection::beforeValidate`** create-branch (`empty($this->id)`): force
  `locked=0` for any caller lacking `perm_sync`, mirroring the existing `perm_sync` exemption on
  `orgc_id` two lines up. A `perm_sync` user (the sync-capture path, T2.1) is NOT forced, so
  `captureCollection` can still set `locked=1` to mark a synced-in original. Additive, model-only.
- **★ LIVE-VERIFIED on dev (localhost:5007) ★** — non-sync Publisher user (id 196, org 531,
  `perm_sync=0`) POSTed `Collection[locked]=1` to `/collections/add`; stored row had `locked=0`.
  (`locked` is now a real column, so absent the guard Cake would have persisted the supplied `1`
  ⇒ discriminating positive test.) Test collection deleted afterwards.
- **✓ RESOLVED — edit-path bypass** (user signed off 2026-07-01; separate commit). `CollectionsController::edit`
  `override` now also pins `'locked' => $oldCollection['Collection']['locked']` (alongside
  id/orgc_id/org_id/user_id), so an owner can no longer flip `locked` on their own collection via
  edit to bypass the create guard. The web edit path never legitimately changes `locked` (only the
  T2.1 capture sink does), so an unconditional pin — matching how orgc/org/user are pinned — is correct.
  **Live-verified** (see the discriminating matrix below). Extending the pre-existing audit override
  (`9341690e9b`) was explicitly approved.
- **★ CACHE GOTCHA (cost real debugging time — record for T2.1+ live verification) ★** After a
  migration adds a column, MISP's CakePHP-2 caches must be cleared or the running app's `find()`
  silently omits the new column (schema/DB have it, but the SELECT list doesn't). TWO caches matter:
  `app/tmp/cache/models/` (`_cake_model_`, the describe cache) **AND** `app/tmp/cache/persistent/myapp_cake_core_method_cache`
  (`_cake_core_`, where `DboSource::fields()` caches the generated column list keyed by ALIAS, not by
  schema). Clearing only `models/` is NOT enough — the stale method_cache made a `perm_sync=0`
  `locked=1` create *look* forced-to-0 when really Cake was dropping `locked` from the INSERT (a FALSE
  PASS). Clear both (or reload php-fpm) before trusting any live schema-column verification.
- **Discriminating verification matrix (2026-07-01, dev localhost:5007, caches cleared):**
  - A) `perm_sync=0` create `locked=1` → stored **0** (guard forces).
  - B) `perm_sync=1` create `locked=1` → stored **1** (exemption works; proves column is writable ⇒ A is discriminating).
  - C) `perm_sync=0` edit `locked=1`+desc → locked **0**, desc changed, HTTP 200 (edit-pin holds, other fields editable).
  - D) `perm_sync=1` edit `locked=0` on a locked=1 row → locked stays **1**, HTTP 200 (edit never flips locked).

## Phase 2 — Shared capture sink
- [x] **T2.1** Implement `Collection::captureCollection()` (PRD §6.2) — orgc/org/SG capture,
  user_id neutralize, distribution downgrade, locked conflict rule, corpus replace.
  → findings below.
- [x] **T2.2** Unit tests for every `captureCollection` branch (PRD §9.1). → findings below.

### T2.2 findings — captureCollection unit tests (`app/Test/CollectionCaptureTest.php`)
- **22 tests, 62 assertions, all green** ([[project-misp-test-convention]]: bare `app/Test/*.php`,
  pure PHPUnit, framework classes stubbed at file top — no CakePHP bootstrap, no DB, so no
  schema-cache false-pass trap; the live sink is exercised for real at T3/T4 E2E).
- **Harness:** stub `App`/`Configure`/`CakeText`/`ClassRegistry`/`__`/`AppModel` at file top, `require`
  the real `Collection.php`, then a `TestableCollection extends Collection` overrides `find()`/`save()`/
  `create()` with an in-memory sim (first `find` = injected existing row; later `find` = saved payload +
  local id). Stub doubles for `Orgc->captureOrg`, `Event->captureSGForElement` (via ClassRegistry),
  `CollectionElement->captureElements`. **Works because captureCollection pins every identity field and
  applies the downgrade BEFORE `save()`** ⇒ asserting on the captured save payload tests the real logic.
  (beforeValidate is not exercised — the create-branch pins are all explicit in captureCollection, and
  beforeValidate's create-guard was already live-verified in T1.4.)
- **Coverage** (all 7 PRD §9.1 targets, each discriminating): create (pin+downgrade); orgc fallback;
  update-when-newer / skip-when-older / **skip-on-equal**; locked block from external + bypass for
  internal; downgrade 2→1 / 3-unchanged / no-downgrade-for-internal+perm_sync_internal /
  downgrade-when-host-org-mismatch; dist=4 SG resolve / unresolvable→dist0 / non-SG nulls sg_id;
  element capture with local id / empty-set culls / absent-key untouched / not-captured-on-save-fail;
  mass-assignment (payload id/org/orgc/user_id/locked all ignored) + fieldList excludes id;
  modified-passed-through; sibling-shaped payload normalisation.
- **★ Discriminating power mutation-verified ★** — neutering the downgrade broke 3 downgrade tests and
  neutering the locked block broke the locked-block test (exactly 4 expected failures); reverted.
- **★ Test-isolation gotcha (fixed) ★** — `ClassRegistry` is also stubbed by `PewPewMapWidgetTest`;
  both guard with `class_exists()`, so in a full-suite run whichever file loads first wins for everyone
  (mine sorts before PewPew). My first cut returned null for unregistered names, which broke PewPew's
  `init('EventTag')->responses` (15 errors). Fixed by matching PewPew's contract: `init()` auto-creates
  a `find()`/`responses` fake (uniquely-named `CollectionTestFakeModel`) for unregistered names; the
  Event double is pre-registered into `$instances`. **Full `app/Test/` suite: 422 tests, 0 errors, 2
  pre-existing skips.** (Other shared stubs — App/`__` won by earlier files; Configure/AppModel/CakeText
  mine-wins but compatible — verified via the full-suite baseline of 400.)

### T2.1 findings — captureCollection sync sink (commit `a3c44705a`)
- **Signature:** `captureCollection(array $user, array $collection, $server = false,
  $remotePermSyncInternal = false): array` → `['success','imported','ignored','failed','errors']`.
  **No `$fromPull`/`$orgId` params** (unlike captureCluster): org_id is the sync user's org for
  BOTH directions (see below), and the downgrade always applies on incoming, so neither was needed.
- **★ Template = `GalaxyCluster::captureCluster` (`:736-860`), NOT captureAnalystData ★** — GalaxyCluster
  is the true analogue because Collection keys org/orgc/SG by **integer FK** (`orgc_id`/`org_id`/
  `sharing_group_id`); AnalystData uses `orgc_uuid` **string** columns. `captureOrg()`
  (`Organisation.php:199`) returns the local **id** by default (`$returnUUID=false`) — perfect for
  `orgc_id`. Added a private `captureOrganisationAndSG($collection,$user)` mirroring GalaxyCluster's
  (`Orgc->captureOrg` → orgc_id; `Event->captureSGForElement` for dist=4 → sharing_group_id, sets
  dist=0 if SG unresolvable).
- **org_id = `$user['Organisation']['id']` for BOTH pull and push-receive** (deliberate simplification
  vs GalaxyCluster, which uses the *server's* org_id on pull). Rationale: (a) `beforeValidate` (T1.4)
  already forces exactly this on create, so sink + web-create agree; (b) push-receive `$user` IS the
  pushing sync user ⇒ org_id = source org, matching GalaxyCluster's push convention; (c) one org rule,
  no create/update divergence. **If a future need arises for server-org ownership on pull, revisit here.**
- **D7 neutralize:** `user_id` pinned to `$user['id']`, `org_id` to the sync user's org, `locked=1`,
  explicitly in the save data (works on the update branch where beforeValidate is skipped) AND via
  `$this->current_user = $user` (drives beforeValidate on the create branch; its perm_sync exemption
  lets locked=1 stand — T1.4).
- **Mass-assignment (PRD §7):** save uses an explicit `$fieldList` = `[uuid,name,type,description,
  distribution,sharing_group_id,org_id,orgc_id,user_id,locked,modified]`; payload `id` is `unset`
  (create) / never sourced from payload (update keys on existing uuid → id). No `created` in fieldList
  ⇒ Cake sets it to now on create, untouched on update.
- **★ `modified` preserved on save (load-bearing for dedup) ★** — verified against CakePHP source
  (`Model.php:1847-1855`): a date field present in BOTH the data AND the whitelist is NOT overwritten
  with now (`$fieldHasValue && $fieldInWhitelist` ⇒ `continue`). Since I include `modified` in data +
  fieldList, the remote `modified` I write survives (a null/empty modified would be unset @1823-1825
  and auto-filled — so pass a real datetime).
- **Downgrade centralized in the sink** (per handoff item 3): `1→0`, `2→1` unless
  `host_org_id set && server internal && host_org_id==server.org_id && remotePermSyncInternal`
  (mirrors `updatePulled*BeforeInsert`). **⇒ T3.3 pull and T4.x push MUST pass the RAW remote
  collection and NOT pre-downgrade** (else double-downgrade). Pull passes `$remotePermSyncInternal`
  from `cachedUserInfo`; push-receive passes `!empty($user['Role']['perm_sync_internal'])`.
- **Elements (D5):** the corpus is pulled aside (`$elements`) and passed to
  `CollectionElement::captureElements(['Collection'=>['id'=>localId,'CollectionElement'=>$elements]])`
  AFTER the parent save. captureElements already self-manages `skipCollectionModifiedBump` (T1.3), so
  no external flag-wrapping needed (handoff item 6 predates that — it's already handled). Guarded on
  `array_key_exists('CollectionElement', …)`: **present-but-empty `[]` ⇒ cull all local elements**
  (authoritative), **key absent ⇒ elements left untouched** (so the T3.2 fetch endpoint MUST always
  serialize `CollectionElement`, even empty, for a true corpus replace).
- **No CollectionBlocklist** model exists ⇒ no blocklist step (unlike captureCluster/captureAnalystData).
- **NOT yet live-verified** — captureCollection has no HTTP entry point until T3.2/T4.2; T2.2 (bare
  PHPUnit, stubbed framework classes) is the dedicated branch-by-branch verification. Lint clean.

## Phase 3 — Pull
- [x] **T3.1** `ServerSyncTool`: `collectionIndexMinimal` + `fetchCollections` (+ T0.2 negotiation
  triad landed). Commit `7d4072421`. → findings below.

### T3.1 findings — ServerSyncTool collection index/fetch + negotiation (commit `7d4072421`)
- **Two consumer methods** added after `pushAnalystData` (`ServerSyncTool.php:~292`), both returning
  `HttpSocketResponseExtended` (caller does `->json()`, mirroring `fetchIndexMinimal`/`fetchAnalystData`):
  - `collectionIndexMinimal(array $rules)` → POST `/collections/indexMinimal`, returns `{uuid: modified}`
    (flat — collections have NO analyst-data-style `type` dimension, so no `{type:{uuid:modified}}` nesting).
  - `fetchCollections(array $uuids)` → GET `/collections/index` + `createParams(['uuid'=>$uuids])` + `.json`
    → `/collections/index/uuid[]:<u1>/uuid[]:<u2>.json`. Full collections **incl. `CollectionElement`**.
    Mirrors `fetchAnalystData` minus the `/{type}` URL segment.
- **Both gated** behind `isSupported(self::FEATURE_COLLECTION_SYNC)` (throw `RuntimeException` when
  unsupported — defensive belt-and-suspenders; the real skip happens earlier in `Collection::pull`/
  `Server::pull`, mirroring how `AnalystData::pull` early-returns at `isSupported` before ever calling
  these).
- **T0.2 negotiation triad landed here** (was deferred "to T3.1 or when first needed"; the isSupported
  case is *mandatory* now — gating on an unknown flag hits `default:` → `InvalidArgumentException`):
  - const `FEATURE_COLLECTION_SYNC = 'collection_sync'` (`:20`, end of the const block).
  - `isSupported` case (`:578`): `isset($info['collection_sync']) && $info['collection_sync']`
    (advertised-boolean, mirrors `filter_sightings`/`perm_analyst_data` — NOT version-gated).
  - advertiser `ServersController::getVersion` (`:1996`): `'collection_sync' => true`. ⇒ two feature-code
    instances negotiate support; an older peer omits the key ⇒ `isSupported` false ⇒ silent skip.
- **Endpoints these hit are T3.2** (`/collections/indexMinimal` POST + the `index` fetch). **★ T3.2 fetch
  is mostly free ★** (user-corrected, code-verified): the existing `index` action, hit via API (`.json`),
  already gives no-pagination + JSON + CSRF-off by default (`CRUDComponent::index:57` does a plain
  `find('all')` for REST), `Collection.uuid` is already in its `filters` (`CollectionsController.php:329`)
  so `uuid[]` filtering works unchanged, and `'index'=>['*']` already exists in the ACL. The ONLY fetch gap
  is `index`'s `contain` (`['Orgc','SharingGroup']`) lacking `CollectionElement` — add it **when
  `_isRest()`** so the corpus (even empty) serializes for capture (T2.1). `indexMinimal` is the one
  genuinely-new action (mirror `AnalystDataController::indexMinimal`; but translate `orgc_name`→`orgc_id`
  integer FK, not `orgc_uuid`). `fetchCollections`'s URL already targets `/collections/index` ⇒ no client
  change needed.
- **Additive within existing files** (PRD §5 items 2 + 6). Lint clean (`parallel-lint`, PHP 8.3). Not
  live-verifiable yet (no caller until T3.3/T3.4; no live 2-instance harness until Phase 6).
- [x] **T3.2** `CollectionsController::indexMinimal` + full-fetch endpoint (CSRF-unlocked, ACL `['*']`).
  Commit `f94147a89`. **★ LIVE-VERIFIED on dev (localhost:5007) ★** → findings below.

### T3.2 findings — pull-side controller/model endpoints (commit `f94147a89`)
- **Three additive edits** (all live-verified with sync user 187, perm_sync=1, against the 3 dev
  collections: U1=74049a17 dist=2/5-elements, U2=7f3ea871 dist=0/other-org/HIDDEN, U3=fb063f85 dist=4/0-elements):
  1. **`Collection::indexMinimal($user, $filters=[])`** (model) — `[uuid => modified]` for collections
     visible+distributable via `buildConditions($user['id'])`, ANDed with `$filters`. Flattened analogue of
     `AnalystData::indexMinimal` (no type dimension). Verified: no-filter → {U1,U3}; U2 (dist=0 other org)
     correctly EXCLUDED.
  2. **`CollectionsController::indexMinimal`** (new action) — reads POST `orgc_name` OR/NOT, translates to
     `orgc_id` conditions, delegates to the model. ACL `'indexMinimal' => ['*']` added (default-deny needs
     the explicit entry; visibility is inside via buildConditions — no blanket perm_sync gate, matching
     analyst-data). Verified discriminating: `orgc_name=Iglocska` → {U1,U3}; `!Iglocska` → {}; unknown org
     → {} (empty-options guard); list-form `["Iglocska"]` → {U1,U3}. Non-sync user 196 (perm_sync=0) also
     gets 200 + visibility-filtered result (ACL `['*']` is correct — visibility, not the sync perm, gates).
  3. **`CollectionsController::index`** REST-only additions (both gated on `_isRest()` ⇒ HTML index path
     provably untouched): (a) `contain CollectionElement` so the fetch payload carries the element corpus —
     verified U1 returns 5 flat element rows (`id,uuid,element_uuid,element_type,collection_id,description`),
     **U3 returns `CollectionElement: []` (key PRESENT, empty)** = the T2.1 corpus-replace requirement; (b)
     harvest bare `uuid[]` named params into an explicit **`Collection.uuid` IN()** condition.
- **★ TWO BUGS caught by discriminating live tests (would have been latent) ★**:
  - **uuid filter silently ignored** — the index `filters` list registers the *fully-qualified*
    `'Collection.uuid'`, but `IndexFilterComponent::__massageData` (`:62-68`) only harvests a named param
    whose key **literally equals** a filter-list entry; the sync URL sends bare `uuid[]`. So the filter never
    applied and the fetch returned ALL visible collections (a false pass until a single-uuid request proved
    it — request only U2 returned U1+U3). Fixed with the explicit REST condition (§3b). Chose an
    alias-qualified `Collection.uuid` over adding bare `'uuid'` to the shared list because bare `uuid` is
    ambiguous against the joined `Orgc`/`SharingGroup` uuid columns. **Discriminating proof: request U2+U3 →
    only U3** (U1 excluded by uuid filter, U2 by visibility).
  - **`orgc_name` resolution 500'd** — `Organisation::fetchOrg` hardcodes `LOWER(Organisation.name)`; calling
    it via the `Collection->Orgc` association (alias `Orgc`) emitted `Unknown column 'Organisation.name'`.
    Fixed by resolving through a canonically-aliased `Organisation` model (`$this->loadModel('Organisation')`).
    (Same latent flaw exists in the analyst-data copy; only bites on a non-numeric/non-uuid name.)
- **No CSRF/pagination/JSON work needed** — confirmed those are REST defaults (`CRUDComponent::index:57`
  `find('all')` for REST, no paginate; `RestResponse` JSON; REST CSRF auto-unlock). User's steer was correct.
- **`fetchCollections` client URL (`/collections/index`) needs NO change** — it already targets this action.
- Regression: `CollectionCaptureTest` 22/22 green (model method is purely additive). Lint clean.
- [x] **T3.3** `Collection::pull` (+ chunking, org pull-rules) → `captureCollection`.
  Commit `fda46c5b1`. → findings below.

### T3.3 findings — Collection::pull chunked fetch → captureCollection (commit `fda46c5b1`)
- **Three additive methods** on `Collection.php` (+ one `App::uses('ServerSyncTool','Tools')`
  so the `pull()` type hint autoloads, mirroring `AnalystData.php:3`):
  - **`pull(array $user, ServerSyncTool $serverSync): int`** — mirrors `AnalystData::pull`
    (`:1158`) flattened: (1) `isSupported(FEATURE_COLLECTION_SYNC)` early-return-0 negotiation
    gate; (2) `buildPullFilterRules(server)` → `collectionIndexMinimal($rules)->json()` inside a
    try/catch (`logException` + return 0 on failure); (3) dedup — `find('all')` local
    `[uuid=>modified]` for the remote uuid set, keep uuids **missing locally OR strictly-newer
    remote** (`strtotime(local) < strtotime(remote)`, **skip-on-equal = D6**); (4) delegate to
    `pullCollectionsInChunks`. **No `foreach ANALYST_DATA_TYPES` layer** — the index is a flat
    `{uuid: modified}` map (T3.1/T3.2 shape), not `{type:{uuid:modified}}`.
  - **`pullCollectionsInChunks(...)`** (private) — `array_chunk($uuids, 100)`;
    `fetchCollections($chunk)->json()` per chunk (try/catch + continue on failure); each RAW
    collection → `captureCollection($user, $collection, $serverSync->server(), $remotePermSyncInternal)`;
    sum `['imported']` where `['success']`. `$remotePermSyncInternal =
    !empty($serverSync->cachedUserInfo()['Role']['perm_sync_internal'])` (mirrors `pullInChunks:1216-1217`).
  - **`buildPullFilterRules(array $server): array`** (private) — verbatim copy of
    `AnalystData::buildPullFilterRules` (`:1265`): `{orgc_name: [OR names…, '!'+NOT names…]}`.
    The `indexMinimal` controller action consumes `orgc_name` and resolves → `orgc_id` (T3.2).
- **★ Carry-forward honoured: pull passes the RAW remote collection, does NOT pre-downgrade ★**
  The T2.1 sink owns the distribution downgrade + `locked=1` + D6 conflict rule; pre-downgrading
  in pull would double-downgrade. Confirmed the sink's downgrade key is `$remotePermSyncInternal`,
  passed through from `cachedUserInfo`.
- **★ Dedup vs sink division of labour ★** — `pull()`'s `modified` dedup is a *fetch optimisation*
  (avoid pulling equal/older); the sink independently re-enforces D6 (strictly-newer + locked-block)
  as the authoritative gate. Mirrors analyst-data (index dedup + `updatePulledBeforeInsert` +
  `captureAnalystData` all re-apply). Belt-and-suspenders, not redundant.
- **Element-shape spot-check (handoff ask) — CONFIRMED.** `CollectionElement::captureElements`
  (`:207-270`) iterates `$data['Collection']['CollectionElement']` reading each element's flat keys
  `uuid`/`element_uuid`/`element_type`/`description` — exactly the flat rows the T3.2 fetch payload
  serializes (`id,uuid,element_uuid,element_type,collection_id,description`, verified live in T3.2).
  captureCollection lifts `CollectionElement` out and passes it as-is ⇒ shapes match end-to-end.
- **Dedup local lookup uses `find('all')` + manual `[uuid=>modified]` build** (not `find('list')`)
  — matches the proven flatten pattern already in `Collection::indexMinimal` (`:205-214`), avoids
  the `find('list')` fields-order subtlety.
- **NOT live-verified** (follows the T3.1 precedent — a caller-less consumer method). A genuine
  pull needs a **distinct** remote peer: the dev box is single-instance and the two-instance
  harness is parked until Phase 6; a same-instance loopback would only exercise the skip-on-equal
  read path (local == remote ⇒ returns 0), never the capture-create branch. The real entry point
  arrives at **T3.4** (`Server::pull` wiring, `:695` next to the `AnalystData->pull` call) — run a
  loopback smoke test there, full round-trip at T6.1. Lint clean (PHP 8.3); `CollectionCaptureTest`
  22/22 green (pull is purely additive — captureCollection unchanged).
- [x] **T3.4** Wire into `Server::pull` behind `pull_collections` + feature negotiation.
  Commit `4a97bb06c`. **★ LIVE-VERIFIED via self-loopback on dev (localhost:5007) ★** → findings below.

### T3.4 findings — Server::pull collections block (commit `4a97bb06c`)
- **One additive block** in `Server::pull` (`Server.php`, inside the `full`/`update` technique gate,
  right after the `AnalystData->pull` call at `:695`), plus count-plumbing:
  - Gate: `!empty($server['Server']['pull_collections'])` (T1.2 toggle, mirrors the
    `pull_galaxy_clusters` gate) **AND** `$serverSync->isSupported(FEATURE_COLLECTION_SYNC)`
    (negotiation — reads the info already cached by the `:609` version fetch, so no extra HTTP;
    `Collection::pull` re-checks it too, belt-and-suspenders). Job progress line `'Pulling collections.', 90`.
  - `$this->Collection = ClassRegistry::init('Collection'); $pulledCollections = $this->Collection->pull($user, $serverSync);`
  - `$pulledCollections = 0` init added to the existing `$pulledProposals = … = 0;` chain (used
    outside the technique gate by `$change`/return).
  - **Count surfacing:** added `%s collections` to the `$change` sprintf (the pull DB-log line) and
    **appended `$pulledCollections` to the return array as index `[6]`**. Verified all three callers
    (`ServersController::pull:844-853`, `ServerShell::pull:160`, `ServerShell` scheduled `:579`)
    index `$result[0..5]` positionally ⇒ appending [6] is non-breaking. Full user-facing message
    surfacing (the "…N collections pulled" strings in those callers) deferred to **T5.2** / D8.
- **PRD §5 item 1** ("new collection block in `pull()`") — non-additive touch point, pre-accepted.
  Additive *within* the method (a new block; only the count sprintf/return lines edited).
- **★ LIVE-VERIFIED via self-loopback (canonical run, as the intended sync user 185) ★** — server 7
  (`http://localhost:5007`, this instance) temporarily `pull=1, pull_collections=1`, pull triggered via
  `POST /servers/pull/7/full` (background worker, www-data). **Result:** job 1391 completed, **auth_fail=0**;
  pull log line `2334559` = *"0 events, … , 0 analyst data and 0 collections pulled or updated"* — the new
  clause is live. **Three-layer discriminating proof (0 is live dedup, not an empty index or a defaulted 0):**
  (1) a direct `POST /collections/indexMinimal` as user 185 returns **all 3 collections** with modified
  `{74049a17:2024-03-05 08:20:34, 7f3ea871:2024-12-15 16:24:35, fb063f85:2024-12-15 16:24:47}` — **exactly
  equal to the local rows** (user 185 = org 1 = the owning org, so buildConditions shows all 3, incl. the
  dist=0 one); (2) the pull's Apache access-log entry `POST /collections/indexMinimal HTTP/1.1 200 516` with
  UA `MISP 2.5.42 - #<current-commit>` proves the block ran `Collection::pull`'s real index round-trip
  (516 B = the 3-entry map); (3) imported=0 ⇒ the live skip-on-equal dedup filtered all 3 (equal modified),
  correctly suppressing any `fetchCollections` follow-up. **The write branch (fetch → captureCollection) is
  structurally unreachable in a self-loopback** — a single DB can't make the remote index strictly-newer than
  the local row it *is* — so that's the Phase 6 two-instance E2E (T6.1). **Server 7 left as a working loopback**
  (authkey now user 185's valid `mBuok…` key — repaired the pre-existing stale `lmro33…`; pull/pull_collections
  reverted to 0). Lint clean. *(An earlier run used user 187's key as a substitute before the correct 185 key
  was available — same 0-collections outcome, superseded by this canonical run.)*
- [~] **T3.5** Pull tests (PRD §9). **★ DEFERRED to Phase 6 per user (2026-07-01) ★** — all per-phase
  testing is folded into Phase 6 (T6.x) once the implementation is finished. The T3.4 self-loopback
  already live-smoke-tested negotiation + index + skip-on-equal dedup; the write branch + full E2E are
  T6.1 (two-instance). No standalone pull unit tests this phase.

## Phase 4 — Push
- [x] **T4.1** `ServerSyncTool`: `filterCollectionsForPush` + `pushCollection`. Commit `9abd6bb64`.
  → findings below.

### T4.1 findings — ServerSyncTool push-side pair (commit `9abd6bb64`)
- **Two consumer methods** added after `fetchCollections` (`ServerSyncTool.php`), grouping all four
  collection sync methods together; both return `HttpSocketResponseExtended` (caller does `->json()`):
  - `filterCollectionsForPush(array $candidates)` → POST `/collections/filterCollectionsForPush` — sends
    the local `{uuid: modified}` push candidates; remote replies with the UUID subset it wants (missing or
    strictly-older there). Mirrors `filterAnalystDataForPush` (`:231`), no `type` dimension.
  - `pushCollection(array $collection)` → POST `/collections/captureCollection` — uploads ONE collection
    (nested under `Collection`, with its `Orgc`/`SharingGroup`/`CollectionElement` corpus) with a log
    message; feeds the remote's shared `captureCollection` sink. Mirrors `pushAnalystData` (`:285`) —
    per-item (caller loops in T4.3), NOT batched.
- **Both gated** behind `isSupported(FEATURE_COLLECTION_SYNC)` (throw when unsupported — defensive; the
  real negotiation skip happens earlier in `Collection::push`/`Server::push`, mirroring the pull side).
- **Endpoints are T4.2** (`/collections/filterCollectionsForPush` + the `captureCollection` receive action).
  Additive within an accepted touch point (PRD §5 item 2). Lint clean. Not live-verifiable until a caller
  exists (T4.3/T4.4); full push verification is Phase 6 (two-instance).
- [x] **T4.2** `CollectionsController::filterCollectionsForPush` + `captureCollection` (CSRF-unlocked, perm_sync).
  Commit `d5242ad46`. **★ LIVE-VERIFIED on dev (localhost:5007) ★** → findings below.

### T4.2 findings — push-receive controller/model endpoints (commit `d5242ad46`)
- **Three additive edits** (all live-verified against the 3 dev collections + a temp import):
  1. **`Collection::filterCollectionsForPush($candidates)`** (model) — flat receive-side dedup mirror of
     `AnalystData::filterAnalystDataForPush` (no `type` dimension). Returns the `{uuid: modified}` subset
     the local side WANTS: uuid missing locally → wanted; uuid present + `locked=1` + candidate strictly
     newer → wanted; uuid present + `locked=0` (locally-created, authoritative) → dropped; present + not
     strictly-newer → dropped. Shares a private `isCandidateValidForPush($candModified, $existing)` helper
     (locked==0 ⇒ false; existing.modified >= candidate ⇒ false) — a straight port of the analyst-data one.
  2. **`CollectionsController::filterCollectionsForPush()`** — POST-only (`MethodNotAllowedException`
     otherwise), delegates to the model, `RestResponse->viewData`. ACL `'filterCollectionsForPush' => ['perm_sync']`.
  3. **`CollectionsController::captureCollection()`** — in-action `perm_sync` + `_isRest()` + POST gate;
     hands the **RAW** payload to the existing T2.1 sink `Collection::captureCollection($user, $data, false,
     !empty($user['Role']['perm_sync_internal']))`. **Push-receive passes `$server=false`** ⇒ the sink treats
     it as external+non-internal (downgrade + locked protection both apply), `remotePermSyncInternal` from
     the PUSHING user's own role (contrast pull: server + remote `cachedUserInfo`). Return mirrors
     `pushAnalystData` (`saveSuccessResponse`/`saveFailResponse`, imported/ignored/failed counts) — note
     `success` is only true when `imported>0`, so an ignored/not-newer re-push returns `saveFailResponse`
     (faithful to the analyst-data template). ACL `'captureCollection' => ['perm_sync']`.
- **`$this->Collection` auto-available** in the actions (no `loadModel('Collection')`) — same as the
  live-verified T3.2 `indexMinimal` sibling; empirically proven, not re-derived.
- **ACL default-deny** ⇒ both new actions got explicit `'collections'` entries (kept alphabetical among
  siblings). **CSRF auto-unlocks for REST** ⇒ no `unlockedActions[]` needed (T0.3 lock-in).
- **★ Live verification matrix (dev localhost:5007, all discriminating) ★**
  - `filterCollectionsForPush` (sync user 187): {existing-locked0-way-newer, existing-locked0-equal,
    missing} → only the **missing** uuid returned (locked=0 rows dropped even when the candidate is much
    newer — D6 authoritative-local). Temp-locked collection 3 (`locked=1`): equal→`[]`, strictly-newer→uuid
    wanted, older→`[]`.
  - `captureCollection`: **non-sync user 196 → HTTP 403** (ACL `perm_sync` layer; in-action gate is
    defense-in-depth beneath it). **Sync user 187 import** of a payload carrying injected
    `user_id/org_id/orgc_id=9999, locked=0, distribution=2`: DB row landed **`locked=1`, `org_id=orgc_id=149`
    (sync user's org), `user_id=187` (D7 neutralised), `distribution=1` (2→1 downgrade), `modified` preserved
    at the remote value.** Re-push **equal modified → ignored** (name change did NOT apply); **strictly-newer
    → 1 imported** (name + modified updated, still locked=1). This is the **first HTTP exercise of the T2.1
    capture sink** — every pin/downgrade/D6 rule holds over the wire.
  - **DB side-effect caught + repaired:** `collections.modified` is `datetime … ON UPDATE CURRENT_TIMESTAMP`,
    so the two raw `UPDATE … SET locked` statements used to stage the locked=1 test auto-bumped collection 3's
    `modified`; restored to `2024-12-15 16:24:47`. (The capture path is unaffected — Cake writes `modified`
    explicitly, overriding the ON UPDATE default, as Test 4/5b confirmed.) Test import collection deleted; dev
    DB back to the original 3 collections.
- **Additive within accepted touch points** (PRD §5 items 2 + 6). Lint clean (`parallel-lint`, PHP 8.3).
  **Next: T4.3** — `Collection::push` (+ `collectDataForPush` eligibility, `prepareForPushToServer`).
- [x] **T4.3** `Collection::push` (+ `collectDataForPush` eligibility, `prepareForPushToServer`).
  Commit `64ad9a02e`. → findings below.

### T4.3 findings — Collection::push model (commit `64ad9a02e`)
- **Six additive methods** on `Collection` (mirror `AnalystData::push` / `collectDataForPush` /
  `collectValidSharingGroupIDs` / `isPushableForServerSyncRules` / `uploadEntryToServer` /
  `prepareForPushToServer`, flattened — no `type` dimension):
  - **`push($user, ServerSyncTool)`** → `int` count. `isSupported(FEATURE_COLLECTION_SYNC)` gate →
    `collectDataForPush` → build `{uuid: modified}` candidates → `ServerSyncTool::filterCollectionsForPush`
    (T4.1) → for each wanted uuid `uploadCollectionToServer`. Handles the `['response']` unwrap on the
    remote reply. **Symmetric with `Collection::pull`** (int return; `push_collections` toggle left to the
    caller `Server::push`/T4.4, exactly as `pull_collections` is checked in `Server::pull`, not `Collection::pull`).
  - **`collectDataForPush($server)`** — eligible = `distribution` 1-3, OR 4 with `$server` in the SG
    (`collectValidSharingGroupIDs`, checkIfServerInSG per SG). Enriches the dist=4 SharingGroup with the full
    `Organisation`/`SharingGroupOrg`/`SharingGroupServer` structure (so the remote `captureSG` can create it if
    missing — copy of the analyst-data `$sgStore` cache). **Nests** the `Orgc`/`SharingGroup`/`CollectionElement`
    corpus under `Collection` (the shape `checkDistributionForPush`, `pushCollection` and the remote
    `captureCollection` sink all expect). Filters by `Event::checkDistributionForPush(…, 'Collection')` (blocks
    dist<2 for external; dist=4 SG-membership) + org push-rules (`isPushableForServerSyncRules`, keyed on
    `Orgc.uuid`).
  - **`uploadCollectionToServer` + `prepareForPushToServer`** — per-collection upload; prepare re-checks the
    dist=4 SG-server membership (403) + `checkDistributionForPush` (403) and **strips the local `id`**.
- **★ RAW passthrough — the deliberate divergence from analyst-data ★** `prepareForPushToServer` does **NOT**
  downgrade distribution and does **NOT** set `locked` (contrast `AnalystData::updateAnalystDataForSync`, which
  does both on the push side). The shared `captureCollection` sink OWNS the downgrade + `locked=1` (T2.1), and
  **T4.2 live-proved it downgrades on receive** (pushed dist=2 → landed dist=1). Pre-downgrading here would
  double-downgrade. This keeps push symmetric with pull (both pass RAW). Carry-forward honoured.
- **Element corpus shape** verified symmetric with the pull path: `contain => ['CollectionElement']` yields
  rows with `uuid`/`element_uuid`/`element_type`/`description` — exactly what `captureElements` reads (line
  236-238), and the remote `captureElements` rebuilds each element clean (ignores the local `id`/`collection_id`).
- **Reused, not re-derived:** `Event::checkDistributionForPush` (context `'Collection'` reads
  `$object['Collection']['distribution']` + `['SharingGroup']`), `SharingGroup::checkIfServerInSG`, the
  `loadLog()`/`logException()` AppModel helpers. `push_rules` is `NOT NULL` (text) ⇒ `json_decode` needs no
  null-guard.
- **Caller-less until T4.4** (mirrors T3.3 → T3.4 precedent): committed on lint + static/template verification;
  **the T4.4 self-loopback push will live-exercise the full chain** (collect → filter → upload → remote capture
  → DB write) — a *stronger* test than pull's self-loopback, since push actively writes (pull's loopback could
  only reach skip-on-equal). Additive (PRD §5 item 8). Lint clean (`parallel-lint`, PHP 8.3). **Next: T4.4** —
  wire `Collection::push` into `Server::push` behind `push_collections` + negotiation (`Server.php` ~`:1229`;
  mirror the T3.4 pull block at `Server::pull` ~`:695`).
- [x] **T4.4** Wire into `Server::push` behind `push_collections` + feature negotiation.
  Commit `013d9cfc1`. **★ LIVE-VERIFIED via self-loopback push on dev (localhost:5007) ★** → findings below.

### T4.4 findings — Server::push collections block (commit `013d9cfc1`)
- **One additive block** in `Server::push` (`Server.php`, right after the analyst-data push block
  `:1422-1433`, before the push `Log` save `:1449`), plus count-plumbing, mirroring the T3.4 pull block:
  - Gate: `!empty($server['Server']['push_collections'])` (T1.2 toggle) **AND**
    `$serverSync->isSupported(ServerSyncTool::FEATURE_COLLECTION_SYNC)` (negotiation — reads the info
    already cached by the `:1255` `checkVersionCompatibility` version fetch, no extra HTTP;
    `Collection::push` re-checks it too, belt-and-suspenders). **The `push_collections` toggle is
    checked HERE, not in `Collection::push`** — symmetric with `pull_collections` in `Server::pull`.
  - Body: `$this->Collection = ClassRegistry::init('Collection'); $pushedCollections = $this->Collection->push($user, $serverSync);`
    + a **message-only** `$job->saveProgress($jobId, __('Pushing collections.'))` when `$jobId`.
    **No percentage** (deliberate divergence from pull's `90`): push has no fixed progress scale — its
    event loop already reaches 100% at `:1391`, and sightings/analyst-data emit no progress — so a fixed
    percent here would regress the bar. Message-only matches the push method's own convention.
  - `$pushedCollections = 0` initialised before the gate (defined when the toggle is off), appended to
    the push DB-log `$change` string (`:1449`) as `. $pushedCollections . ' collections pushed.'`.
    **The return shape `array($successes, $fails)` (`:1454`) is deliberately NOT changed** (callers
    `list($successes,$fails)` it; fuller user-facing surfacing is T5.2/D8). Note push's `$change` is a
    plain concatenation (contrast pull's `sprintf`), so the append is a concat too.
- **★ LIVE-VERIFIED via self-loopback push (server 7 → localhost:5007) ★** — `push=1, push_collections=1`,
  `POST /servers/push/7/full` (admin key, background worker, **job 1392 completed, "Job done."**).
  **Result:** new push log (id `2334750`) = *"0 events pushed or updated. 0 events failed or didn't need
  an update. **0 collections pushed.**"* — the new clause is live (the prior push log used the old
  clause-less format ⇒ clean before/after). **Discriminating three-layer proof (0 is a LIVE round-trip,
  not a short-circuited/defaulted 0):** (1) `server-sync.log` shows the push firing, in order,
  `GET /servers/getVersion 200` → `POST /events/filterEventIdsForPush 200` → `POST /events/index 200` →
  **`POST /collections/filterCollectionsForPush 200 2`** — the T4.4 wiring running `Collection::push`'s
  real chain (T4.1 `ServerSyncTool` client → T4.2 receive endpoint → back); (2) the `2`-byte `[]` response
  = the remote (=self) wanting NONE of the offered collections = the **D6 clean-loopback drop** of the
  offered `locked=0` originals (authoritative-local); the very presence of the `filterCollectionsForPush`
  call proves `collectDataForPush` produced ≥1 candidate (U1 dist=2) and offered it — a failed
  toggle/negotiation gate would emit **no** call at all; (3) collections table unchanged (3 rows, all
  `locked=0`) ⇒ no spurious capture. Toggles reverted; server 7 left as the working loopback.
- **★ Corrects the T4.3 body's optimism — a push self-loopback does NOT reach the capture-write branch
  either.** Same DB ⇒ the remote `filterCollectionsForPush` can never *want* a `locked=0` or
  equal-`modified` row it already holds (D6), so `0` is the correct terminal outcome, NOT a bug. The
  fetch/capture-over-push **write branch** (T4.2's `captureCollection` was already live-verified directly
  via curl in T4.2, but the push-driven path to it) needs a **distinct peer** → **Phase 6 T6.1**, the
  same limitation class as the T3.4 pull loopback.
- **Note (flagged for review): the block is gated on the toggle + negotiation ONLY, exactly per the
  handoff plan — NOT on `$push['canPush']`.** The sibling event/sightings/analyst-data pushes each gate on
  a `$push` capability; collections have no separate remote capability (D3), so `$push['canPush']` would be
  the faithful analogue and would skip a guaranteed-403 upload attempt when the remote refuses this sync
  user. Omitted per the plan (harmless — the remote's `perm_sync` ACL still enforces `captureCollection`);
  recorded as an **optional T5 tightening** for the user's call.
- **PRD §5 item 1** (accepted non-additive touch point); additive *within* the method. Lint clean
  (`parallel-lint`, PHP 8.3). **★ Phase 4 implementation COMPLETE (T4.1–T4.4); T4.5 tests → Phase 6.**
  **Next: Phase 5 (UI/D8) — T5.1** server add/edit/view collection toggles.
- [~] **T4.5** Push tests (PRD §9). **★ DEFERRED to Phase 6 per user (2026-07-01) ★** (see T3.5 note — all
  testing folds into Phase 6 once implementation is finished).

## Phase 5 — UI surfacing & negotiation polish
- [x] **T5.1** Server add/edit/view: collection toggles. Commit `45b83b56f`.
  **★ LIVE-VERIFIED on dev (localhost:5007) ★** → findings below.
- [x] **T5.2** Sync job output + pull/push preview: collection counts. Commit `73185042b`.
  **★ LIVE-VERIFIED via self-loopback pull (localhost:5007) ★** → findings below.
- [ ] **T5.3** End-to-end feature-negotiation skip verified against a simulated old peer.

### T5.1 findings — server-form collection toggles (commit `45b83b56f`)
- **Three additive edits**, mirroring the `pull_analyst_data`/`push_analyst_data` toggles verbatim:
  1. **`app/View/Servers/edit.ctp`** (`:96-97` area) — two bare `$this->Form->input('push_collections')`
     / `pull_collections` calls right after the analyst-data pair. **`edit.ctp` is shared by `add()`**,
     which does `$this->render('edit')` (`ServersController.php:501`) — so ONE template edit surfaces the
     checkboxes on BOTH the add and edit forms.
  2. **`ServersController::edit()`** (`:570`) — added `'push_collections', 'pull_collections'` to the save
     `$fieldList`. **`add()` needs NO change** — it saves with `$this->Server->save($this->request->data)`
     (`:435`, no `$fieldList`), so the two fields persist automatically once present in the form POST.
  3. **`app/View/Servers/index.ctp`** (`:141` area) — two `boolean`/`class=short` columns
     ("Push Collections" / "Pull Collections", `data_path`+`sort` = `Server.push/pull_collections`) after
     the analyst-data columns. **★ There is NO `app/View/Servers/view.ctp`** — the server-list `index.ctp`
     is where per-server sync-toggle state is displayed (the handoff's "server view" surfacing = these columns).
- **★ LIVE-VERIFIED on dev (localhost:5007), all discriminating ★** (caches cleared first — the schema-column
  cache gotcha; Form->input introspects the tinyint(1) columns to render a checkbox, not a text input):
  - **`edit()` `$fieldList` persistence** — REST `POST /servers/edit/7` (admin key): `{push_collections:1,
    pull_collections:1}` → DB `servers.push_collections=1, pull_collections=1`; then `{…:0,…:0}` → both back
    to `0`. The 0→1→0 round-trip proves the two fields are genuinely mass-assignable via the new whitelist
    entry (not stuck at a default). Server 7 restored to baseline `0/0`.
  - **edit form checkboxes** — web GET `/servers/edit/7` (admin session): renders
    `<input type="checkbox" name="data[Server][push_collections]" id="ServerPushCollections">` +
    `pull_collections`, with auto-labels "Push Collections"/"Pull Collections" — byte-identical shape to the
    analyst-data checkboxes directly above.
  - **add form checkboxes** — web GET `/servers/add` (renders `edit.ctp`): same two checkboxes present.
  - **index columns** — web GET `/servers/index`: both boolean columns render with `sort:Server.push/pull_collections`
    sort links.
- **Additive UI only** (PRD §5 item 5 — accepted touch point). Lint clean (`parallel-lint`, PHP 8.3, all 3 files).
  **Next: T5.2** (collection counts in sync job output + pull/push preview — the `$change` DB-log strings
  already carry the count; the deferred caller-side "…N collections pulled/pushed" user-facing messages +
  preview screens land here). **Optional T5 tightening still open** (flagged at T4.4): `Server::push`
  collections block gates on toggle + negotiation only, not `$push['canPush']`.

### T5.2 findings — collection counts in pull job output (commit `73185042b`)
- **Scope reduced to the pull caller strings after auditing the sibling (analyst-data)
  surfacing — parity, not invention:**
  - **Pull plumbing already there (T3.4):** `Server::pull` returns a 7-element array
    (`Server.php:724` `[$successes,$fails,$pulledProposals,$pulledSightings,$pulledClusters,
    $pulledAnalystData,$pulledCollections]`); index **[6]** = collections. The `$change` DB-log
    line already carries "…%s collections pulled or updated" (`Server.php:714`). The **gap** was
    the caller-side "Pull completed. …" user-facing strings, which stopped at `$result[5]`
    (analyst data).
  - **Two edits, mirroring `$result[5]` verbatim:** `ServersController::pull` (`:846`, the
    synchronous `!background_jobs` path) + `ServerShell::pull` (`:162`, the background-worker
    Job status) both got `, %s collections pulled.` appended with `$result[6]`. Also added
    `$this->set('pulledCollections', $result[6])` (`ServersController:855`) for parity with the
    `pulledAnalystData` view var two lines up (both vestigial — the action redirects right after —
    but kept for sibling consistency).
  - **Third pull caller NOT edited:** `ServerShell` scheduled pull (`:579`) reads only
    `$result[0]` for the 1/2/3/4 error codes and relies on the `$change` DB-log line (already has
    the count) ⇒ no message edit needed there.
- **★ Push side needs NO caller edit — parity = DB-log only ★** Audited both push callers:
  `ServersController::push` (`:935`) surfaces **only events** ("%s events pushed, %s events could
  not be pushed") — analyst-data/sightings/clusters push counts are NOT surfaced to the caller;
  `ServerShell::push` (`:203`) just reports "Job done.". So no sync type surfaces a per-type count
  to a push caller. Collections push count already lives in the `Server::push` `$change` DB-log
  (T4.4, `:1463`) — faithful parity. (The optional `$push['canPush']` tightening from T4.4 is a
  separate concern, still open.)
- **★ No pull/push preview surface exists for ANY sibling sync type ★** The only `preview*`
  actions on `ServersController` are `previewIndex`/`previewEvent` (`:108`/`:179`) — remote-EVENT
  preview, not a per-type-count pull/push preview. Analyst-data added none. ⇒ PRD §6.9's "preview"
  has no sibling to mirror; nothing built (parity, not invention).
- **`$result[6]` exposure = identical to the existing `$result[5]`** — both are unguarded in the
  same message expression, and both are undefined only on the `pull_relevant_clusters` early-return
  (`Server.php:633`, a 5-element array). Pre-existing for `[5]`; my `[6]` shares its exact fate ⇒
  no new risk, faithful mirror (guarding would diverge from the sibling and is out of scope).
- **★ LIVE-VERIFIED via self-loopback pull (localhost:5007) ★** — server 7 (→ this instance)
  temporarily `pull=1, pull_collections=1`; `POST /servers/pull/7/full` (admin key user 1,
  background worker) → **job 1399** status message = *"Pull completed. 0 events pulled, … 0 analyst
  data pulled, **0 collections pulled.**"* — the new clause renders `$result[6]` correctly
  positioned, non-crashing, with a real value (0 = self-loopback skip-on-equal; T6.1 already proved
  a **nonzero** count on a real 5008-delta pull, "…1 collections pulled or updated"). Server 7
  restored to baseline `0/0`. Lint clean (`parallel-lint`, PHP 8.3, both files). Additive within
  accepted touch points (PRD §5). **Next: T5.3** (negotiation-skip vs a simulated old peer).

## Phase 6 — End-to-end testing & docs
- [~] **T6.1** Two-instance (or loopback) live sync E2E. **★ LIVE E2E VALIDATED 2026-07-03 across two real
  instances (5007 ⇄ 5008) — both capture-write branches proven ★.** The scripted `tests/` deliverable (PRD §9.2)
  is the remaining sub-item. → findings below.

### T6.1 findings — two-instance write-branch E2E (2026-07-03)
- **★ Harness: a genuine second instance ★** — 5008 (`mispx` DB, reachable locally with the same creds) on
  `develop` + the feature code (user brought it up to snuff: manually applied migrations 155/156 since
  `findUpgrades(157)` skips keys < 157 — the numbering-reconciliation trap, now confirmed real). Both directions
  wired: 5007 server row **42 (`mispx`) → 5008** (key = 5008 user 2 / org 2 iglocska, perm_sync); 5008 row 1 → 5007.
  Both DBs directly queryable (`misp`=5007, `mispx`=5008) ⇒ capture verified at the row level on both sides.
- **★ This reaches the branch NO self-loopback can ★** — a self-loopback's `filter*ForPush`/index always sees an
  equal/`locked=0` local copy of every offered uuid (same DB) ⇒ never fetches/captures. A distinct peer with a
  collection the other side lacks makes the **fetch→capture** (pull) and **upload→capture** (push) write branches
  fire for real.
- **PULL write branch (5008 → 5007), fully discriminating:** seeded a dist=2 collection `64578a85…` on 5008
  (orgc=iglocska, 1 Event-ptr element, `modified 2026-07-03 08:42:53`), set `pull_collections=1` on server 42,
  `POST /servers/pull/42/full`. Captured on 5007 (id 969): **`locked=1`**, **`distribution=1` (2→1 downgrade)**,
  `user_id`/`org_id`=local puller (D7 neutralize), **`orgc_id` resolved by UUID** (5007 org 1 = Iglocska
  `84977a3b` = 5008's orgc, not a fallback), **`modified` preserved exactly**, **element replicated** with a fresh
  element uuid. Pull log: *"…and 1 collections pulled or updated"*. `server-sync.log` proved the real fetch:
  `POST /collections/indexMinimal 200` → **`GET /collections/index/uuid[]:64578a85….json 200 679`** (the
  679-byte full-collection fetch → capture). **Re-pull → "0 collections", still exactly 1 copy** (D6 skip-on-equal
  idempotency; no dup).
- **PUSH write branch (5007 → 5008), fully discriminating:** isolated to collections-only (server 42 temporarily
  `push=0` + `push_sightings`(already 0)/`push_galaxy_clusters=0`/`push_analyst_data=0` off — `pushSightings`
  honors `push_sightings` `Sighting.php:1346`, `AnalystData::push` honors `push_analyst_data` `:785`, and the
  collections block gates only on `push_collections && isSupported`, independent of `Server.push` — so a
  collections-only push runs with **zero** event/sighting/cluster/analyst side-effect on 5008; the 84,486
  sightings were NOT dumped). `POST /servers/push/42/full` → U1 (`74049a17`, dist=2, 5 elements) captured on 5008
  (id 2): **`locked=1`**, **`distribution=1` (2→1)**, `org_id`/`orgc_id`/`user_id`=2 (5008 sync user; orgc resolved
  by UUID to 5008's iglocska), **`modified 2024-03-05 08:20:34` preserved**, **all 5 elements replicated**. Push
  log: *"…1 collections pushed."* (the T4.4 clause). `server-sync.log`:
  `POST /collections/filterCollectionsForPush 200` → **`POST /collections/captureCollection 200 199`** (the real
  upload+capture). **Re-push → "0 collections", still 1 copy** (D6 idempotency).
- **★ D6 origin-protection confirmed cross-instance:** the pulled `64578a85…` (now `locked=1` on 5007) was
  offered back to 5008 on the push, and 5008 **dropped it** (it holds the `locked=0` authoritative original) —
  the last-writer-wins + locked rule holds over the wire, not just in unit tests. U3 (dist=4) correctly not
  pushed (server not in its SG); dist=0 not eligible.
- **Migration-numbering trap CONFIRMED real (operational):** an instance already at `db_version 157` (upstream
  develop) that gains the feature code will have `runUpdates` **skip** cases 155/156 (both < 157) ⇒ columns must
  be applied manually (the 3 ALTERs). `getVersion` still advertises `collection_sync:true` (code-driven) while
  the columns are missing ⇒ a live trap. Recorded for T6.2 docs + any real deploy.
- **Cleanup:** both instances returned to baseline (5007 → its 3 originals; 5008 → 0 collections; server 42
  toggles restored `push=1,pull=1,push_sightings=0,push_galaxy_clusters=1,push_analyst_data=1,collections=0`).
- **Remaining T6.1 sub-item:** a checked-in reusable `tests/` E2E script (PRD §9.2). The behaviour is now
  live-proven; the deferred T3.5/T4.5 unit tests also still fold into Phase 6. **The core feature promise
  (bidirectional write-branch sync + locked/downgrade/neutralize/D6) is LIVE-VALIDATED across two instances.**
- [ ] **T6.2** Sync docs (`docs/dev/…`) describe collection sync.
- [ ] **T6.3** Final regression: parallel-lint, phpunit, `Admin schemaDiagnostics`.

---

## Parked / open items (full list → PRD §10)
- **Test infra (before Phase 6):** dev box exposes a single instance (localhost:5007);
  true sync needs two *both running the feature code*. User to pick: second local instance
  (recommended) / loopback Server row / PyMISP harness. Phases 0–5 don't depend on this.
- **`Collection.modified` granularity:** DATETIME (second resolution) — mirror analyst-data
  skip-on-equal for same-second ties. Verify at T2.1.
- **`org_id` vs `orgc_id` on capture:** confirm exact Event convention, replicate (T2.1).
- **Migration ordering:** schema migrations must land before any code reads the new columns.

### ★ MIGRATION RENUMBER 155/156 → 158/159 (2026-07-03, commit `f94da2aa5`) — SUPERSEDES the numbering below
The original 155/156 choice (below) assumed collection-sync merges into develop BEFORE the event-template
`exposed` migration (157), so every instance passes through 155/156 before 157. **That breaks for an instance
that reaches `db_version 157` via upstream develop (has 157, never had 155/156) then gains this code —
`findUpgrades()` skips 155/156 (< 157) ⇒ columns never created, yet `getVersion` still advertises
`collection_sync` (a live deploy trap; it bit 5008, which needed the 3 ALTERs hand-applied).** **Fix:** the
feature's migrations now live ABOVE the current develop max — **158** (`collections.locked`) + **159** (servers
toggles), moved after `case 157:` in `AppModel`; `$db_changes` map → `…154, 157, 158, 159`; `db_schema.json`
db_version → **159**; MYSQL.sql unchanged (columns already in its baseline CREATE TABLE). **Safe for
already-migrated boxes:** re-adding an existing column is an ACCEPTED duplicate-column error
(`AppModel::isAcceptedDatabaseError`, SQLSTATE 42S21/1060 → "the update went through") ⇒ this dev box + 5008
self-heal on the next `runUpdates` (db_version → 159, no breakage, no dup columns). **LIVE-VERIFIED here**
(was at 157 w/ columns): web-triggered runUpdates applied 158+159 as accepted-duplicate no-ops → db_version 159,
columns intact. Everywhere below that says "155/156" is historical — the live numbers are **158/159**.

### Phase 1 prep — migration numbering (verified 2026-06-30, this branch)
- **This `2.5` branch:** highest `case` = **153** (`taxii_servers.enabled`,
  `AppModel.php:2698`); `$db_changes` map ends `153 => false` (`:101`).
- **`develop`:** already holds `case 154` (TAXII `auth_type`) + `154 => false`.
- **⇒ Use 155 (T1.1 `collections.locked`) and 156 (T1.2 server toggles)** — NOT 154/155.
  **USER-CONFIRMED 2026-06-30.** 154 *looks* free on `2.5` but is already claimed by `develop`
  (TAXII `auth_type`); numbering past it avoids a hard collision when these branches merge.
  (Matches the PRD's original 155/156.)
- **The map does NOT need to be gapless — do NOT add a no-op `154 => false`.** `findUpgrades()`
  (`AppModel.php:3552-3556`) applies every `DB_CHANGES` key strictly `> db_version` (a single
  monotonic integer stored in `admin_settings.db_version`); it tolerates gaps fine. The 153→155
  hole is harmless. **Adding `154 => false` would be an active hazard:** an instance that reaches
  `db_version=156` via this branch would then *skip* `develop`'s real `154` (156 > 154 ⇒ TAXII
  `auth_type` never applied). So: leave 154 undefined here; it arrives via the normal
  `develop→2.5` merge. **Before any merge/deploy, rebase the feature branch onto a 2.5 base that
  already contains `develop`'s `case 154:`** so 154 isn't skipped (and renumber 155/156 if the
  base advanced further). Irrelevant for the local single-instance dev/test loop.

## Session log
- **2026-07-03 — session 9:** **T5.2 done** (commit `73185042b`). Surfaced the pulled-collections
  count (`Server::pull` return index [6], from T3.4) in the user-facing "Pull completed. …" messages,
  mirroring the analyst-data `$result[5]` verbatim: `, %s collections pulled.` appended in
  `ServersController::pull` (`:846`) + `ServerShell::pull` (`:162`), plus a parity
  `$this->set('pulledCollections', $result[6])`. **Push needs no caller edit** — no sync type surfaces
  a per-type count to push callers (events-only in `ServersController::push`; "Job done." in
  `ServerShell::push`), so parity keeps the collections push count in the `Server::push` `$change`
  DB-log alone (T4.4). **No preview surface exists** for any sibling sync type (only remote-event
  preview), so none invented. **★ LIVE-VERIFIED via self-loopback pull ★** (server 7, job 1399): job
  message now reads "…0 analyst data pulled, 0 collections pulled." (0 = self-loopback skip-on-equal;
  T6.1 already showed a nonzero count on a real delta). Lint clean; additive (PRD §5). **Next: T5.3**
  (negotiation-skip vs a simulated old peer).
- **2026-07-03 — session 8:** **T5.1 done** (commit `45b83b56f`) → **Phase 5 STARTED.** Surfaced the
  `pull_collections`/`push_collections` server toggles in the UI (D8), mirroring `pull/push_analyst_data`:
  two `Form->input` checkboxes in `edit.ctp` (shared by `add()` via `render('edit')`), the two field names
  added to `ServersController::edit()`'s save `$fieldList` (`add()` saves fieldList-less ⇒ automatic), and
  two boolean columns in `index.ctp` (there is no `Servers/view.ctp`). **★ LIVE-VERIFIED (localhost:5007) ★** —
  REST edit of server 7 flips both DB cols 0→1→0 (discriminating); add + edit forms render both checkboxes;
  index shows both sortable boolean columns. Additive (PRD §5 item 5); lint clean. **Next: T5.2** (collection
  counts in sync job output + pull/push preview).
- **2026-07-03:** **Migration renumber 155/156 → 158/159** (commit `f94da2aa5`) — user-suggested fix for the
  upstream-develop-at-157 skip trap surfaced by the 5008 E2E. Moved the collections migrations ABOVE develop's
  event-template `157` (so `findUpgrades` on any instance ≤157 applies them); `$db_changes` map + `db_schema.json`
  db_version → 159; MYSQL.sql unchanged. Safe for already-migrated boxes via the accepted duplicate-column path.
  **LIVE-VERIFIED** (this box 157→159, 158/159 ran as accepted-duplicate no-ops, columns intact). See the
  RENUMBER note in the migration-numbering section. **NB commits since T4.4 are on branch `collection_sync`**
  (user switched off `develop` this session); `develop` still at `5bec30427`.
- **2026-07-03:** **★ T6.1 LIVE E2E VALIDATED (two real instances, 5007 ⇄ 5008) ★** — no code change; docs only.
  User stood up 5008 (`mispx` DB, develop + feature code + manually-applied migrations 155/156) wired both ways to
  5007 (server row 42). **Both capture-write branches — unreachable by any self-loopback — proven live & fully
  discriminating:** PULL 5008→5007 captured a seeded dist=2 collection as `locked=1`, dist 2→1, orgc-by-UUID,
  user/org neutralized, modified preserved, element replicated (real `indexMinimal`+`index` fetch in
  `server-sync.log`); PUSH 5007→5008 captured U1 the same way (real `filterCollectionsForPush`+`captureCollection`
  round-trip), isolated to collections-only so 5007's 84k sightings weren't dumped. Both idempotent on re-run
  (D6 skip-on-equal, no dup); D6 origin-protection held cross-instance (a `locked=0` original is never
  overwritten by a push-back). Confirmed the migration-numbering trap is real (155/156 < 157 ⇒ `runUpdates`
  skips them; columns need manual ALTERs, yet `getVersion` still advertises support — a deploy trap for T6.2
  docs). Both instances cleaned back to baseline. Remaining T6.1 = a checked-in `tests/` E2E script. **The core
  feature promise is now LIVE-VALIDATED end-to-end.** Next: T6.1 scripted harness / T6.2 docs / T6.3 regression,
  and Phase 5 UI (T5.1) still outstanding.
- **2026-07-03:** **T4.4 done** (commit `013d9cfc1`) → **Phase 4 implementation COMPLETE (T4.1–T4.4).**
  Wired a collections block into `Server::push` after the analyst-data push block (`:1422-1433`), gated on
  `push_collections` (T1.2) + `isSupported(FEATURE_COLLECTION_SYNC)`; `ClassRegistry::init('Collection')->push()`;
  count appended to the `$change` DB-log concat; **return shape untouched** (T5.2 does the user-facing
  surfacing). Message-only `saveProgress` (push has no fixed progress scale). **★ LIVE-VERIFIED via
  self-loopback push ★** (server 7 → localhost:5007, `push=1/push_collections=1`, job 1392): push log shows
  "…0 collections pushed."; `server-sync.log` shows `POST /collections/filterCollectionsForPush 200 2` = the
  wiring firing `Collection::push`'s real T4.1→T4.2 chain, the `[]` response = D6 drop of the offered
  `locked=0` originals (live 0, not a short-circuit; collectDataForPush offered U1). Collections unchanged;
  toggles reverted. **Corrects T4.3's optimism** — a push self-loopback also can't reach the capture-write
  branch (same-DB D6); that's Phase 6 T6.1 with a distinct peer. Flagged an optional T5 `$push['canPush']`
  gate tightening for review. Lint clean. **Next: Phase 5 T5.1** (server-form collection toggles).
- **2026-07-01:** **T4.1 done** (commit `9abd6bb64`) — `ServerSyncTool::filterCollectionsForPush`
  (POST `/collections/filterCollectionsForPush`, push dedup) + `pushCollection` (POST
  `/collections/captureCollection`, per-item upload w/ log message), both gated behind
  `isSupported(FEATURE_COLLECTION_SYNC)`; mirror the analyst-data push pair, no `type` dimension.
  Additive (PRD §5 item 2); lint clean; endpoints built in T4.2. **★ Testing decision (user, 2026-07-01):
  T3.5 + T4.5 (and per-phase tests) DEFERRED to Phase 6 — finish the implementation first, test at the
  two-instance E2E stage.** **Next: T4.2** — `CollectionsController::filterCollectionsForPush` +
  `captureCollection` receive endpoints (CSRF-unlocked via REST, `perm_sync`).
- **2026-07-01:** **T3.4 done** (commit `4a97bb06c`) — collections block wired into `Server::pull`
  inside the `full`/`update` gate after analyst data, gated on `pull_collections` (T1.2) +
  `isSupported(FEATURE_COLLECTION_SYNC)`; count fed into the `$change` log line + appended to the
  return array [6] (callers index [0..5] ⇒ non-breaking). **★ LIVE-VERIFIED via self-loopback ★**
  (server 7 → localhost:5007, pull_collections=1, user-187 key): pull completed, log line shows
  "…and 0 collections pulled or updated"; Apache log's `POST /collections/indexMinimal 200` with the
  MISP sync UA at commit `6f7be07bc` proves the block ran Collection::pull's real index fetch (0 =
  expected self-loopback skip-on-equal; write branch needs a distinct peer → Phase 6). Server 7
  restored. Lint clean. **Next: T3.5** — pull tests (PRD §9).
- **2026-07-01:** **T3.3 done** (commit `fda46c5b1`) — `Collection::pull` + private
  `pullCollectionsInChunks` + `buildPullFilterRules` (+ `App::uses ServerSyncTool`), mirroring
  `AnalystData::pull`/`pullInChunks` flattened (no `type` dimension). isSupported gate → index
  fetch → `modified` dedup (skip-on-equal, D6) → `array_chunk(100)` fetch → RAW → `captureCollection`
  (sink owns downgrade/locked/D6, so no pre-downgrade; `remotePermSyncInternal` from `cachedUserInfo`).
  Element flat-row shape spot-checked against `captureElements` — matches. Additive; lint clean;
  `CollectionCaptureTest` 22/22. Not live-verified (caller-less consumer, T3.1 precedent — real
  entry point is T3.4 `Server::pull:695`; two-instance E2E parked to Phase 6). **Next: T3.4** —
  wire into `Server::pull` behind `pull_collections` + negotiation.
- **2026-07-01:** **T3.2 done** (commit `f94147a89`) — `Collection::indexMinimal` model method +
  `CollectionsController::indexMinimal` action (ACL `['*']`, orgc_name OR/NOT → orgc_id) + REST-only
  `index` additions (contain CollectionElement, harvest `uuid[]` → `Collection.uuid` IN). **★ First
  live HTTP verification of the sync surface ★** on dev localhost:5007 with sync user 187 — all
  discriminating (visibility gate, uuid filter, orgc OR/NOT, empty-corpus present-as-`[]`). **Caught +
  fixed two latent bugs live:** the `uuid[]` filter was silently ignored (fully-qualified `Collection.uuid`
  filter key never matches the bare `uuid` named param in `__massageData`) so the fetch returned all
  visible collections; and `orgc_name` 500'd (fetchOrg via the `Orgc`-aliased assoc → unknown-column).
  User's steer confirmed: no-pagination/JSON/CSRF are REST defaults, so the fetch reuses `index`.
  `CollectionCaptureTest` 22/22 green. **Next: T3.3** — `Collection::pull` (chunked fetch → captureCollection).
- **2026-07-01:** **T3.1 done** (commit `7d4072421`) — `ServerSyncTool::collectionIndexMinimal`
  (POST `/collections/indexMinimal` → `{uuid:modified}`) + `fetchCollections` (GET `/collections/index`
  uuid named-params `.json` → full collections + elements), both gated behind
  `isSupported(FEATURE_COLLECTION_SYNC)`. Landed the **T0.2 negotiation triad** alongside: const
  `FEATURE_COLLECTION_SYNC='collection_sync'`, `isSupported` case (advertised-boolean), and
  `ServersController::getVersion` advertising `collection_sync=>true`. Modelled on the analyst-data
  pair (no `type` dimension for collections). Lint clean; not live-verifiable until a caller exists
  (T3.3/T3.4). Additive (PRD §5 items 2+6). **Phase 3 started.** Next: **T3.2** — `CollectionsController::indexMinimal`
  + fetch endpoint (CSRF-unlocked via REST, ACL `['*']`/`['perm_sync']` per T0.3; must serialize
  `CollectionElement` always, honour `uuid[]` filter, no pagination for sync).
- **2026-06-30:** T0.1 done — branch `feature-collection-sync` created off `2.5`, tracker added.
- **2026-06-30:** **Phase 0 complete** — T0.2 (feature negotiation: advertised-boolean
  `collection_sync`) + T0.3 (CSRF auto-unlocked via REST; ACL is default-deny so every new
  sync action needs an explicit `'collections'` ACL entry; no routes.php change) locked in.
  Next: Phase 1 (T1.1 `collections.locked` migration).
- **2026-06-30:** **T1.1 done** — `collections.locked tinyint(1) NOT NULL DEFAULT 0` as
  migration 155 (AppModel case 155 + `155 => false`), `db_schema.json` (column + db_version→155),
  `MYSQL.sql`. Corrected PRD's canonical-schema path (`db_schema.json` at ROOT, not
  `app/Lib/db_schema.php`). Statically validated; dev DB target confirmed (no `locked`, at 154).
  Next: T1.2 (server toggles, migration 156).
- **2026-06-30:** **T1.2 done** — `servers.push_collections` + `pull_collections`
  `tinyint(1) NOT NULL DEFAULT 0` as migration 156 (two ALTERs AFTER `pull_galaxy_clusters`),
  `db_schema.json` (both cols + db_version→156), `MYSQL.sql`. Validated; dev `servers` lacks them.
  Next: T1.3 (bump `Collection.modified` on element add/remove/capture — D5 prerequisite for dedup).
- **2026-06-30:** **T1.3 done** — D5 modified-bump implemented as `CollectionElement` model
  callbacks (afterSave/afterDelete → `Collection->updateAll(modified=now)`), suppressed during
  `captureElements` via `$skipCollectionModifiedBump`. Zero controller edits. **Live-verified** on
  the dev box (add + delete both bumped `modified`). Next: T1.4 (Collection `locked` default on
  local create; mass-assignment guard). NB to live-verify T1.4+ run migrations 155/156 on the dev
  box first (`cake Admin runUpdates`; dev is at 154, applies only 155/156).
- **2026-07-01:** **Merged `feature-collection-sync` → `develop`** (merge commit `6170ffa18`).
  **Migration numbering reconciled (no renumber):** develop's in-flight event-template track had
  deliberately numbered its `event_templates.exposed` migration **157** (above this branch's 155/156),
  so there was NO collision — kept 155 (collections.locked) / 156 (servers toggles); develop's 154
  (TAXII auth_type) + 157 preserved. Final monotonic `runUpdates` sequence **153→154→155→156→157**;
  AppModel `$db_changes` map unioned. `db_schema.json` `db_version` set to **157** (develop's
  event-template commit had left it at 154 despite adding the column — corrected in the merge).
  MYSQL.sql auto-merged; `event_templates.exposed` intentionally not in MYSQL.sql (baseline is ingested
  then brought current by the AppModel case-157 migration at install — per owner). Resolves the parked
  "merge hygiene" item. Full `app/Test/` suite green post-merge (422/0). **Dev DB now at db_version
  157** — 155/156 + 157 (event_templates.exposed) all applied and column-verified (fpm auto-applied 157;
  MISP console must run as www-data not iglocska). `feature-collection-sync` branch deleted (merged).
  Ongoing work now on `develop`. Next: Phase 3 T3.1.
- **2026-07-01:** **T2.2 done** — `app/Test/CollectionCaptureTest.php`: 22 bare-PHPUnit tests (62
  assertions) covering every captureCollection branch via a TestableCollection in-memory harness; all
  green. Mutation-verified discriminating (neuter downgrade → 3 fail, neuter locked block → 1 fail).
  Fixed a full-suite ClassRegistry stub collision with PewPewMapWidgetTest (auto-create fake for
  unregistered names). **Full `app/Test/` suite: 422 tests, 0 errors.** **Phase 2 COMPLETE.**
  Next: Phase 3 (Pull) — T3.1 `ServerSyncTool` collection index/fetch.
- **2026-07-01:** **T2.1 done** (commit `a3c44705a`) — `Collection::captureCollection()` +
  private `captureOrganisationAndSG()` helper added (additive; no existing paths touched). Modelled on
  `GalaxyCluster::captureCluster` (integer-FK org/orgc/SG analogue, not AnalystData's uuid columns).
  Centralises D5 corpus-replace / D6 locked+modified conflict / D7 user_id neutralize / distribution
  downgrade in one sink for both directions. Verified CakePHP preserves the remote `modified` on save
  (dedup-critical). Lint clean; not live-verifiable until T3.2/T4.2 (no HTTP entry point yet).
  **Next: T2.2** (bare-PHPUnit branch tests). **Phase 2 half done.**
- **2026-07-01:** **T1.4 done** (commit `fafe71eb4`) — `Collection::beforeValidate` forces
  `locked=0` on local create for non-`perm_sync` callers; capture path exempt. **Live-verified**
  (perm_sync=0 user's `locked=1` create stored as 0). **Migrations 155/156 already applied** —
  dev DB is now at **db_version 156** with `collections.locked` + `servers.pull/push_collections`
  present (someone ran `runUpdates` since the last session; the "dev still at 154" note is stale).
  **Phase 1 COMPLETE.** Surfaced an OPEN edit-path `locked` bypass (see T1.4 findings) for
  sign-off. Next: **Phase 2 T2.1 `Collection::captureCollection()`** (the shared sink).
