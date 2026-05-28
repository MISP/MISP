# Dashboard v2 — Session handoff (2026-05-28 — DD-39 MISP health widget + DD-40 cache-status widget; next: TBD — user-flagged)

Twenty-second session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-40).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** Two entries this session:
  the `MispAdminHealthWidget + HealthList` and the
  `MispCacheStatusWidget + NetworkGraph extension` bullets near the
  bottom of "Post-5.5 — New features".
- `dashboard-design-decisions.md` — DD-01..DD-40 (DD-39 + DD-40 this
  session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (7 signed commits, `%G?`=U, not merged)

```
26cedc730 new MispCacheStatusWidget — server & feed cache freshness (DD-40)
8bc98b95e new NetworkGraph — per-node kind, info status, feedSymbol (DD-40)
f70a1dd04 chg open DD-40 — MispCacheStatusWidget + NetworkGraph extension
5c05c40c4 chg handoff refreshed — DD-39 landed (intra-session)
8ad0d329e new MispAdminHealthWidget — application-layer health rollup (DD-39)
14ae69b46 new HealthList render kind (DD-39)
d0d7c3976 chg open DD-39 — generic MISP health widget + HealthList render kind
```

Two new admin-tier widgets this session:

1. **`MispAdminHealthWidget` (DD-39)** — application-layer health
   rollup that surfaces only the diagnostic checks that are *not*
   green. Healthy MISP shows just an "All checks passing" header; that
   absence-of-rows IS the signal. Pure consumer of existing
   `Server::*Diagnostics()` methods. New `HealthList` render kind.

2. **`MispCacheStatusWidget` (DD-40)** — hub-and-spoke diagram of sync
   servers + feeds with caching enabled, spokes coloured by cache age
   (< 1d info / ≥ 1d warn / no cache danger). Reuses DD-33's
   NetworkGraph front end, surgically extended with a per-node `kind`
   field (server vs feed) + `info` status tier + new RSS-waves
   `feedSymbol()`. `MispAdminSyncTestWidget` renders byte-identically
   after the renderer change.

Both fully verified (REST + headless-Chrome screenshots against the
full CSS stack). Pure additions. **The USER does the merge — do NOT
open the PR or merge.**

## What landed (reuse these facts)

### DD-40 — `MispCacheStatusWidget` + NetworkGraph extension (latest)
- **Same front end as the sync widget (DD-33), different dimension —
  cache freshness.** Spokes: sync servers with `caching_enabled=1`
  (server-rack glyph) + feeds with `caching_enabled=1` (RSS-waves
  glyph). Each coloured by cache age: **< 1d info (cyan), ≥ 1d warn
  (amber), no cache yet danger (red)** — user-spec thresholds.
- **NetworkGraph extended in-place** (user-explicit sign-off — "use
  the same front end, update it with the additional functionalities
  you need"). Three surgical changes in
  `app/webroot/js/dashboard/charts/charts.module.mjs`:
    1. New `feedSymbol(colour)` builder — **RSS-waves glyph** (two
       concentric arcs + filled dot in lower-left, user-chosen via
       AskUserQuestion fork vs stacked-chevrons / document-with-
       arrow). Same theme-aware `image://` pipeline as `serverSymbol`.
    2. Status colour map gains `info: --misp-dash-info` (cyan token
       already in `dashboard.default.css`); status enum becomes
       `{self, ok, warn, error, info}`.
    3. `symbolFor` restructured to nested
       `symbolFor[kind][status]` (2 kinds × 5 statuses = 10 cached
       symbols). Node-mapping reads optional `kind` field (default
       `'server'`); hub overrides to `'server'` unconditionally — the
       diagram centre is always a MISP instance regardless of spoke
       types.
- **Backward-compat verified.** `MispAdminSyncTestWidget` emits no
  `kind` field, no `info` status — defaults preserve the DD-33 code
  path. Live JSON render pre/post the renderer change was
  byte-identical; screenshot pre/post would render identically.
- **Widget is a pure consumer** of existing model helpers:
  `Server::attachServerCacheTimestamps()` and
  `Feed::attachFeedCacheTimestamps()` hydrate
  `Server.cache_timestamp` / `Feed.cache_timestamp` from
  `misp:server_cache_timestamp:{id}` / `misp:feed_cache_timestamp:{id}`
  in Redis. **No Redis key read directly; no diagnostic logic
  re-implemented.** Filter on `caching_enabled = 1` per table.
- **Per-row classification.** `cache_timestamp` empty → `error` with
  `· never` label; `age >= 86400 s` → `warn` with humanised age (`85d
  3h`); else → `info` with humanised age (`5h`).
- **Humanisation shape lifted from `IndexTable/Fields/caching.ctp`**
  (two-largest-units form — `Xd Yh`, `Xh Ym`, `Xm Ys`) so the
  dashboard reads consistently with the existing Server / Feed list
  views.
- **Age embedded in the visible node label** (`#7 5007 · 85d 3h`,
  `darkfeed · never`) — age IS the load-bearing signal here, would be
  hidden in a tooltip-only design.
- **Tooltip carries URL + status sentence** (`Cached 85d 3h ago —
  stale. Server cache.` / `Caching enabled — never cached. Feed
  cache. Format: misp.`). Uses NetworkGraph's existing `_url` /
  `_message` slots.
- **Empty state.** Returns `{nodes:[<hub>], links:[], error:<msg>}`
  when zero spokes — mirrors DD-33's empty-state pattern.
- **Widget shape.** `MispCacheStatusWidget`: `$render='NetworkGraph'`,
  `$category='system'`, default size `4×5`, `$autoRefreshDelay=false`
  (manual refresh — admin pulls when they want fresh probe;
  `$cacheLifetime=1` is a tick-level anti-spam guard; the timestamps
  in Redis are cheap to read and move slowly), site-admin gate.
- **No ECharts series change → no bundle rebuild.** Reuses GraphChart
  from DD-33; gallery thumbnail reuses `thumbNetworkGraph` (no new
  render kind).
- **Verified.** `node --check` clean (charts.module.mjs); `php -l`
  clean ×2 (widget + NetworkGraph.ctp). Live REST render of
  `MispCacheStatusWidget` → HTTP 200, 5 spokes on the dev box (3
  servers: 1 stale 85d 3h, 2 never-cached; 2 feeds: both stale 65d).
  Live REST render of `MispAdminSyncTestWidget` post-change is JSON
  byte-identical to pre-change (no regression). **Headless-Chrome
  screenshot** against the full CSS stack exercising both panels —
  top panel (DD-33 backward-compat, server icons in self/ok/warn/
  error) renders identically; bottom panel (DD-40 mixed, 3 server +
  3 feed spokes across info/warn/error) shows distinct RSS-waves
  glyphs in cyan/amber/red. Temp webroot eye-check file deleted
  post-screenshot.
- **Pure addition for the widget; surgical reversible extension for
  the renderer.** Reverse widget = delete file. Reverse renderer
  extension = remove `feedSymbol()` + `info` map entry + collapse
  `symbolFor` back to a single layer.

### DD-39 — `MispAdminHealthWidget` + `HealthList` render kind (earlier in this session)
- **Scope (user-narrowed via AskUserQuestion fork).** Site-admin only,
  **issue-only display** — only non-green rows render. Healthy MISP =
  just the "All checks passing" header. User explicit on "not nearly
  as verbose" — broader rollup proposal rejected.
- **The 8 checks (user-specified shortlist, pure consumer of existing
  `Server::*Diagnostics()` methods):**
    1. **MISP version outdated** — `getCurrentGitStatus(true)`,
       `upToDate==='older'` → warn.
    2. **PHP under-provisioned** — `getIniSetting()` against
       recommended table (memory_limit≥2048M etc.).
    3. **MySQL under-provisioned** — `dbConfiguration()` against
       `MYSQL_RECOMMENDED_SETTINGS`.
    4. **Filesystem perms** — `writeable{Dirs,Files}Diagnostics()` +
       `readableFilesDiagnostics()` rolled into one row; value 2 fail,
       value 1 warn.
    5. **Module reach** — `moduleDiagnostics()` for
       Enrichment/Import/Export (Cortex excluded); 2=warn, string=fail,
       disabled=skip.
    6. **GnuPG** — `gpgDiagnostics()`, status 2-4=fail, 1=skip.
    7. **STIX** — `stixDiagnostics()`, operational!=1=fail,
       invalid_version=warn.
    8. **Session handler** — `sessionDiagnostics()`,
       `handler !== 'php_redis'` warn (NOT `error_code !== 0` — the
       database handler returns 0 too).
    9. **DB updates** — `dbSchemaDiagnostic()`,
       `update_fail_number_reached` fail, `update_locked` warn,
       version mismatch warn (skip `expected==='?'`).
- **New `HealthList` render kind** chosen via fork (QueueList /
  StatGrid don't fit single-status one-line check rows). Typed-row
  contract `header`/`check`/`message`. Severity allow-list `warning`
  / `danger` only (info filtered at widget). Two severity glyphs
  (warn-triangle, danger-circle) + a success check-mark for the
  healthy header — chip+glyph carry the colour signal together, no
  per-check distinct icons.
- **Caching (DD-20).** `$cache_duration = 300` (5min). Five
  diagnostics do real work (Python subprocess for stix, HTTP module
  pings ×3, SHOW VARIABLES, GPG init+sign test, schema file +
  compare).
- **Verified.** Live REST render surfaced 8 real issues on the dev
  box (3 MySQL warn, 1 fs danger, 3 module danger, 1 db-version
  warn). HTML class histogram + escaping (apostrophes encoded once
  as `&#039;`) + headless-Chrome screenshot against full CSS stack
  all clean.

## Prior-session facts (still true — condensed; reuse)

### Render-kind family (DD-31 / DD-32 / DD-33 / DD-35 / DD-38 / DD-39)
The dashboard now has these v2 render kinds beyond the legacy SimpleList,
BarChart, MultiLineChart, WorldMap, Index, Button, OrgsPictures, Attack,
Achievements, PieChart, MonitorLineChart:

- **StatGrid** (DD-31) — KPI metric cards. Used by `UsageDataWidget`.
- **NetworkGraph** (DD-33, extended DD-40) — ECharts `graph` series,
  hub-and-spoke, server-rack + RSS-waves glyphs, 5-status colour set
  `{self, ok, warn, error, info}`. Used by `MispAdminSyncTestWidget`
  and `MispCacheStatusWidget`.
- **UserList** (DD-35) — avatar/name/meta/badge rows; opt-in search
  + per-row action (DD-36). Used by `LoggedInUsersWidget`.
- **QueueList** (DD-38) — queue-health rows with two
  independently-coloured chips. Used by `MispAdminWorkerWidget`.
- **HealthList** (DD-39) — issue-only health rollup rows
  `[severity glyph] check_name [detail] [severity chip]`. Used by
  `MispAdminHealthWidget`.

Every new render kind needs (CLAUDE.md): a glyph in
`app/webroot/js/dashboard/gallery/render-thumbs.mjs`. The full-CSS-stack
verification rule
(`feedback_verify_visible_outcome_not_property`) bites every time.

### ECharts vendored bundle (DD-02 + tree-shake rule)
A new `series.type` must be added to the vendored bundle's `use([...])`
and rebuilt — else `type:'<new>'` renders nothing
(`project_misp_echarts_bundle_treeshaken`). Build dir
`/tmp/echarts-bundle` (echarts@6.0.0 + esbuild@0.24.0) reusable;
`vendor/VENDORING.md` has the recipe. **No bundle rebuild this session
either** — DD-39 is pure HTML/CSS, DD-40 reuses GraphChart from DD-33.

### Render-kind contract conventions (reuse)
- **Widget `handler()`s emit RAW strings**; the renderer `h()`s each
  interpolated scalar exactly once (DD-34).
- **Colour decisions live in the widget**; the renderer maps an
  allow-listed class/status name to a `.misp-*-chip-<sem>` token pair
  / `image://` symbol. Don't paint inline styles.
- **Drilldown URLs gated by `DashboardURLValidator::validate`** (DD-03).
- **Not the renderer's job to scroll** (DD-31).

### `Server::*Diagnostics()` cross-call gotchas (carried — DD-39)
- All take `&$diagnostic_errors` by reference and `$diagnostic_errors++`
  internally. Pass `int 0` per call (NOT `array()`; the PHP-8
  "Cannot increment array" pattern bit MispAdminWorkerWidget).
- `moduleDiagnostics()` returns `0|1|2|<error string>`.
- `gpgDiagnostics()` returns `{status: 0-4, version}`.
- `stixDiagnostics()` returns `{operational: 0|1|-1, invalid_version,
  test_run, <per-pkg>}`. **`operational==1` is OK, not 0.**
- `sessionDiagnostics()` returns `{handler, expired_count,
  error_code}`. **`error_code==0` doesn't mean "php_redis"** — check
  `handler === 'php_redis'` directly.
- `dbSchemaDiagnostic()` returns `{actual_db_version,
  expected_db_version, update_locked, remaining_lock_time,
  update_fail_number_reached, ...}`. `expected === '?'` when the
  schema file can't load — skip the comparison.
- `getCurrentGitStatus(true)` returns `{commit, branch,
  latestCommit, version: {current, newest, upToDate}}`. `upToDate` ∈
  `same|older|newer|error|disabled`.

### Server & Feed cache helpers (DD-40)
- `Server::attachServerCacheTimestamps(array $servers)` and
  `Feed::attachFeedCacheTimestamps(array $feeds)` hydrate
  `cache_timestamp` (Unix sec OR `null`/`false` if never cached) by
  pipelined Redis `GET` on
  `misp:server_cache_timestamp:{id}` / `misp:feed_cache_timestamp:{id}`.
- Filter on `caching_enabled = 1` (tinyint(1) column on both tables).
- Don't iterate Redis keys directly — use these helpers; the read
  pattern is already pipelined.
- Humanisation shape (two-largest-units form: `2d 4h`, `5h 30m`) is
  copied from `app/View/Elements/genericElements/IndexTable/Fields/caching.ctp`
  for consistency with the existing list views.

## Open follow-ups (none blocking)

- **In-browser verification of DD-39 + DD-40 (deferred to the user —
  hard-refresh Ctrl-Shift-R):**
    * **MISP Health** widget renders in the "system" category and
      surfaces the dev-box issues (3 MySQL warn / 1 fs danger / 3
      module danger / 1 db-version mismatch).
    * **MISP Cache Status** widget renders in the "system" category,
      hub + 3 servers (1 stale / 2 never) + 2 feeds (both stale) on
      the dev box, with distinct server-rack vs RSS-waves icons.
    * Verify the existing **MISP Sync Test** widget still renders
      identically (DD-40 backward-compat check on a real board).
- **NEXT SESSION'S TASK: TBD — user-flagged.** Natural extensions
  worth surfacing (offer the user a quick fork via AskUserQuestion if
  none is pre-flagged):
    * **HealthList polish** — per-row anchor drilldown into the
      diagnostics page tab (currently every row goes to the
      diagnostics root).
    * **MispCacheStatusWidget polish** — per-node click drilldown
      (server-rack → `/servers/cacheServer/<id>`, feed-icon →
      `/feeds/view/<id>`). Currently the diagram is read-only; would
      need a small `drilldown` map per node, wired through
      NetworkGraph's existing `pickDrilldownKey('network', ...)`
      path or a fresh hook.
    * **Cache-status thresholds configurable** — make the 1-day
      threshold a widget config param so admins on slow-cache
      instances can bump it.
    * **`MispAdminSyncTestWidget` flip to `info` for caching-only
      servers** — currently it treats every spoke as a sync connection;
      could add a small "this is cache-only" hint.
    * **Roll StatGrid out** to the remaining key/value admin widgets;
      glyphs per metric.
- Pre-existing (carried): **DD-11 ACL-enforced switchable geo widget
  path**; **org/COVID maps palette opt-in**; default-templates **live
  non-admin ACL check**; **REST API-key auth flaky in a prior session**
  (browser/session auth unaffected — used all session).
- **Phase 6 merge — the USER does this, not us.**

## Live test instance

- URL `http://localhost:5007/dashboards` (302 without a session; 200 with).
  Admin user 1 (`admin@admin.test`, pw `Password12345`), Overmind theme.
  Cookie jar `/tmp/cj_stat.txt` is the one from session 21, still valid.
  Re-mint via `reference_misp_login_dance` if it 302s.
- DB: `mysql -u misp -pPassword1234 misp`. MISP Redis: `redis-cli -n 13`.
  **SESSIONS are in Redis db0** (`PHPREDIS_SESSION:*`).
- **Health state on the dev box** (DD-39 anchor): 8 issues — 3 MySQL
  warn / 1 fs danger / 3 module danger / 1 db-version mismatch warn.
- **Cache state on the dev box** (DD-40 anchor): 3 cache-enabled
  servers (#3 iglocska.eu never-cached, #7 5007 cached 85d 3h ago,
  #35 Localhost never-cached) + 2 cache-enabled feeds (#10
  diamondfox_panels cached 65d ago, #72 1-signature test cached 65d
  ago). Cache timestamps in Redis db13 (NOT db0) under
  `misp:{server,feed}_cache_timestamp:{id}`.
- **Workers state on the dev box** (DD-38 anchor): 6 queues / 21
  workers alive; `default=5/5`, `email=5/5`, `cache=5/5`, `prio=5/5`,
  `update=1/1`, `scheduler=0/0`.
- State: `db_version=151`; branch `dashboards`. Build dir
  `/tmp/echarts-bundle` reusable for bundle rebuilds.

### Reusable verification recipes
```bash
# Lint
php -l app/Lib/Dashboard/<Widget>.php
node --check app/webroot/js/dashboard/charts/charts.module.mjs
node --check app/webroot/js/dashboard/charts/vendor/echarts.bundle.mjs
node --check app/webroot/js/dashboard/gallery/render-thumbs.mjs

# Render a widget body via the web-UI cookie path.
curl -s -b /tmp/cj_stat.txt -X POST -H "Accept: application/json" \
  "http://localhost:5007/dashboards/renderWidget/test1" \
  --data-urlencode "widget=<WidgetName>" --data-urlencode "config={}"
# NB: cached widgets ($cache_duration) serve a stale payload — purge first:
redis-cli -n 13 --scan --pattern 'misp:<snake>_cache*' | xargs -r redis-cli -n 13 DEL

# Eye-check a render kind visually (NEW renderer-only renderkinds —
# HealthList / QueueList / UserList / StatGrid — or chart renderers
# via initChartsIn). Drop a temp .html into app/webroot referencing the
# FULL CSS stack (bootstrap5-custom + mainOvermind + fontawesome7 +
# dashboard/dashboard.default + dashboard/dashboard.midnight +
# theme/Overmind/css/dashboard/overmind.css) — anything less is a
# false-pass trap (feedback_verify_visible_outcome_not_property).
# For ECharts kinds, include:
#   <script type="module">
#     import { initChartsIn } from '/js/dashboard/charts/charts.module.mjs';
#     initChartsIn(document.body);
#   </script>
# Then:
google-chrome --headless=new --no-sandbox --hide-scrollbars \
  --window-size=500,1000 --screenshot=/tmp/x.png \
  --virtual-time-budget=6000 http://localhost:5007/_xx_test.html
# Read the PNG. DELETE the temp webroot file after (it's publicly served).

# Rebuild the echarts bundle (add a series type): edit
# /tmp/echarts-bundle/entry.mjs use([...]), esbuild per VENDORING.md.

# Inspect cache timestamps directly:
redis-cli -n 13 --scan --pattern 'misp:server_cache_timestamp:*'
redis-cli -n 13 --scan --pattern 'misp:feed_cache_timestamp:*'

# Stop / start a worker to exercise DD-38 chip thresholds:
supervisorctl -c /etc/supervisor/supervisord.conf stop misp-workers:misp-worker-default-00
supervisorctl -c /etc/supervisor/supervisord.conf start misp-workers:misp-worker-default-00
```

## Convention reminders

- **Context budget:** keep within the first ~20% normally; user OK'd up to
  40% for UI work (`feedback_context_threshold_warning`).
- **Commit per progress-tracker task; never `git add -A`; explicit `git
  add` + `git status --short`; sign (`%G?`=U).** GPG warm all session.
- **Edit/Write flips a file's group to `iglocska:iglocska`** — `chgrp
  www-data` every edited web-served/app file afterward (incl. docs).
- **Record meaningful decisions as DD-NN + a PRD §15 row.** Refinements
  get a NEW DD; small in-session polish stays as a sub-note.
- **Render-kind glyph rule** (CLAUDE.md): new `$render` → glyph in
  `render-thumbs.mjs`. DD-40 didn't trigger this (reuses NetworkGraph);
  DD-39 added `HealthList`.
- **ECharts series-type sibling rule:** a new `series.type` must be
  added to the vendored bundle's `use([...])` + rebuilt
  (`project_misp_echarts_bundle_treeshaken`). Not triggered this
  session.
- **Widget `handler()`s emit RAW strings; the renderer owns escaping**
  (DD-34).
- **Colour decisions live in the widget; the renderer is dumb.** The
  widget knows the thresholds; the renderer maps an allow-listed
  class/status name to a token-pair. Consistent across DD-31 / DD-32 /
  DD-38 / DD-39 / DD-40 — uphold for any new render kind.
- **`Server::*Diagnostics()` methods take `&$diagnostic_errors` by
  reference and `$diagnostic_errors++` internally.** Pass `int 0` per
  call.
- **Session handler check is `handler === 'php_redis'`, NOT
  `error_code === 0`** (database handler also returns 0).
- **Cache timestamps live in Redis db13** (NOT db0 / NOT the
  `cake_sessions` table); read via the `attach{Server,Feed}CacheTimestamps()`
  helpers, not direct `redis-cli`.
- **NetworkGraph extensions are backward-compatible by default.** New
  fields like `kind` get sensible defaults so existing widgets keep
  rendering identically. Always verify with a live JSON render of the
  pre-existing consumer (DD-40 did this for `MispAdminSyncTestWidget`).
- User wants **rigorous pushback + genuine forks via AskUserQuestion**,
  and to **re-verify rather than defend** when a premise is questioned.

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 (DD-31..40) +
   `dashboard-design-decisions.md` DD-39 + DD-40 (+ DD-31..38 for the
   prior sessions' render kinds + the mutation/action pattern from
   DD-36) + this file.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302 (or 200 with the cookie jar — re-mint
   `/tmp/cj_stat.txt` via `reference_misp_login_dance` if it 302s).
3. **Next session's task: TBD — user-flagged.** Wait for the user to
   name the work. Natural extensions are listed in "Open follow-ups"
   above (HealthList anchor drilldowns, MispCacheStatusWidget per-node
   drilldown, configurable cache thresholds, etc.) — surface them via
   AskUserQuestion if the user opens with "what next?" rather than a
   directive.
4. **Gotchas to carry:**
   (a) new ECharts series type → rebuild the bundle's `use([...])`;
   (b) ESM imports ignore the `?v=185` buster → hard-refresh after a
   vendored-bundle/JS change;
   (c) sessions live in Redis **db0** (`PHPREDIS_SESSION:*`), MISP's
   own data + caches in **db13**;
   (d) widget `handler()`s emit raw strings — the renderer escapes;
   (e) a body-filling render kind must let `.misp-widget-body` own
   scrolling;
   (f) Edit tool flips file group — `chgrp www-data` after edits;
   (g) **CSS verification must load the FULL stack** + assert the
   computed/visible outcome (not the property you set);
   (h) `workerDiagnostics()` mixes per-queue arrays with top-level
   summary keys — iterate by `BackgroundJobsTool::VALID_QUEUES`;
   (i) **colour decisions belong in the widget**, the renderer just
   maps an allow-listed class/status to a token pair;
   (j) `Server::*Diagnostics()` methods take `&$errors` by reference —
   pass `int 0` (not `array()`; PHP 8 crash);
   (k) session-handler check is `handler === 'php_redis'`, NOT
   `error_code === 0`;
   (l) NetworkGraph supports per-node `kind` (`'server'|'feed'`,
   default `'server'`) and 5 statuses (`self|ok|warn|error|info`) —
   when adding new render-kind consumers, default to back-compat
   shapes;
   (m) Server / Feed cache timestamps come from
   `attach{Server,Feed}CacheTimestamps()` — they pipeline-read
   `misp:{server,feed}_cache_timestamp:{id}` from Redis db13.
5. Do NOT start the merge — the user does that. Watch context; refresh
   this handoff before wrapping.
