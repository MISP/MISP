# Collection Sync — Progress Tracker

In-repo, checked-in source of truth for ticked task state across sessions.
Full design lives in `collection_sync_prd.md` (owner's `~/prds`, not in-repo).

- **Branch:** `feature-collection-sync` (off `2.5`)
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
- [ ] **T2.2** Unit tests for every `captureCollection` branch (PRD §9.1).

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
- [ ] **T3.1** `ServerSyncTool`: `collectionIndexMinimal` + `fetchCollections`.
- [ ] **T3.2** `CollectionsController::indexMinimal` + full-fetch endpoint (CSRF-unlocked, perm_sync).
- [ ] **T3.3** `Collection::pull` (+ chunking, org pull-rules) → `captureCollection`.
- [ ] **T3.4** Wire into `Server::pull` behind `pull_collections` + feature negotiation.
- [ ] **T3.5** Pull tests (PRD §9).

## Phase 4 — Push
- [ ] **T4.1** `ServerSyncTool`: `filterCollectionsForPush` + `pushCollection`.
- [ ] **T4.2** `CollectionsController::filterCollectionsForPush` + `captureCollection` (CSRF-unlocked, perm_sync).
- [ ] **T4.3** `Collection::push` (+ `collectDataForPush` eligibility, `prepareForPushToServer`).
- [ ] **T4.4** Wire into `Server::push` behind `push_collections` + feature negotiation.
- [ ] **T4.5** Push tests (PRD §9).

## Phase 5 — UI surfacing & negotiation polish
- [ ] **T5.1** Server add/edit/view: collection toggles.
- [ ] **T5.2** Sync job output + pull/push preview: collection counts.
- [ ] **T5.3** End-to-end feature-negotiation skip verified against a simulated old peer.

## Phase 6 — End-to-end testing & docs
- [ ] **T6.1** Two-instance (or loopback) live sync E2E script under `tests/` (PRD §9.2).
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
