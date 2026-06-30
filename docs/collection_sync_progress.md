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
- [ ] **T1.1** Add `collections.locked` (MYSQL.sql + db_schema.php + migration).
- [ ] **T1.2** Add `servers.pull_collections` + `push_collections` (same three places).
- [ ] **T1.3** Bump `Collection.modified` on element add/remove/capture (D5).
- [ ] **T1.4** `Collection` model: set `locked=0` on local create; allow capture to set `1`.

## Phase 2 — Shared capture sink
- [ ] **T2.1** Implement `Collection::captureCollection()` (PRD §6.2) — orgc/org/SG capture,
  user_id neutralize, distribution downgrade, locked conflict rule, corpus replace.
- [ ] **T2.2** Unit tests for every `captureCollection` branch (PRD §9.1).

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

## Session log
- **2026-06-30:** T0.1 done — branch `feature-collection-sync` created off `2.5`, tracker added.
- **2026-06-30:** **Phase 0 complete** — T0.2 (feature negotiation: advertised-boolean
  `collection_sync`) + T0.3 (CSRF auto-unlocked via REST; ACL is default-deny so every new
  sync action needs an explicit `'collections'` ACL entry; no routes.php change) locked in.
  Next: Phase 1 (T1.1 `collections.locked` migration).
