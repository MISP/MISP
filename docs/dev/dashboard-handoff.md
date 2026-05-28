# Dashboard v2 — Session handoff (2026-05-28 — DD-39 generic MISP health widget; next: TBD — user-flagged)

Twenty-second session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-39).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** This session's entry is the
  `MispAdminHealthWidget + HealthList render kind` bullet near the
  bottom of "Post-5.5 — New features".
- `dashboard-design-decisions.md` — DD-01..DD-39 (DD-39 this session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (3 signed commits, `%G?`=U, not merged)

```
8ad0d329e new MispAdminHealthWidget — application-layer health rollup (DD-39)
14ae69b46 new HealthList render kind (DD-39)
d0d7c3976 chg open DD-39 — generic MISP health widget + HealthList render kind
```

One user-driven new feature: a **generic MISP health widget** that
fills the gap left by the dense physical-resource widget collection
(Resource / SystemResource / Workers / Monitor trio) with an
**application-layer rollup** — 8 fixed checks, **issue-only display**
(only non-green rows render; healthy MISP shows just an "All checks
passing" header). User narrowed the scope from my broader proposal —
no broad DB-connection / error-log-count / itemised-security-posture
sprawl, just these 8: version vs latest, PHP/MySQL provisioning,
filesystem perms, module reachability, GnuPG, STIX, session handler,
DB-update state. New `HealthList` render kind for the typed-row
contract (header / check / message); pure consumer of existing
`Server::*Diagnostics()` methods.

**Live verification done** (REST JSON + HTML render path + headless-
Chrome screenshot against the full CSS stack — see "What landed"
below for the dev-box state that surfaced 8 real issues). Pure
addition; reverse = delete widget + renderer + CSS block + thumb
entry. **The USER does the merge — do NOT open the PR or merge.**

## What landed (reuse these facts)

### DD-39 — `MispAdminHealthWidget` + `HealthList` render kind (this session's only work)
- **Scope (user-narrowed via AskUserQuestion fork).** Site-admin only,
  **issue-only display** — only non-green rows render. Healthy MISP =
  just the "All checks passing" header row; that absence-of-rows is
  the good-news signal. User explicit on "not nearly as verbose" — my
  broader rollup proposal (DB connection + Redis db0/db13 + itemised
  security posture + error_log count) was **rejected** in favour of
  the fixed 8-check shortlist below.
- **The 8 checks (user-specified shortlist, pure consumer of existing
  `Server::*Diagnostics()` methods — no diagnostic logic re-
  implemented):**
    1. **MISP version outdated** — `Server::getCurrentGitStatus(true)`,
       `upToDate==='older'` → warn. `error`/`disabled` skipped (=
       "couldn't check", not "outdated"; surfacing on air-gapped
       installs = noise).
    2. **PHP setting under-provisioned** — `Server::getIniSetting()`
       against the recommended table (`memory_limit≥2048M`,
       `max_execution_time≥300s`, `upload_max_filesize≥50M`,
       `post_max_size≥50M`); each under-recommended = one warn row.
    3. **MySQL setting under-provisioned** — `Server::dbConfiguration()`
       against `MYSQL_RECOMMENDED_SETTINGS`; each under-recommended =
       one warn row.
    4. **Filesystem read/write issues** — `Server::writeableDirsDiagnostics()`
       + `writeableFilesDiagnostics()` + `readableFilesDiagnostics()`;
       value 2 (not writable / unreadable) = fail, value 1 (not found)
       = warn; **rolled into one row** with a "N not writable, M not
       found" detail (this is the issue widget, not the diagnostics
       page — per-path enumeration belongs there).
    5. **Module system not reachable** — `Server::moduleDiagnostics($type)`
       for Enrichment / Import / Export (**Cortex excluded** — different
       third-party infra surface; surfacing it as "not reachable" on
       instances that never enabled it would be noise). 2 (enabled but
       no modules) = warn; error string from the HTTP ping = fail; 1
       (disabled) = skip (user-intentional).
    6. **GnuPG not configured correctly** — `Server::gpgDiagnostics()`,
       status 2-4 = fail (library load / signing key / signing test
       failures). 1 (not configured) = skip (could be intentional on a
       consumer-only instance).
    7. **STIX library status failure** — `Server::stixDiagnostics()`,
       `operational !== 1` = fail, `invalid_version` = warn.
    8. **Session handler not php_redis** — `Server::sessionDiagnostics()`,
       **check `handler !== 'php_redis'` not `error_code`** (database
       handler returns `error_code=0` but isn't `php_redis` — what the
       user explicitly asked to surface).
    9. **DB updates not up-to-date / locked** — `Server::dbSchemaDiagnostic()`.
       `update_fail_number_reached` = fail; `update_locked` = warn;
       `actual_db_version !== expected_db_version` = warn (skip when
       `expected==='?'` — schema file unavailable, e.g. non-MySQL DB).
- **New render kind chosen via fork** (vs reuse QueueList / vs reuse
  StatGrid). QueueList's two-chip row over-weights for single-status
  check rows; StatGrid centres value, bad for one-line rows. New
  `HealthList.ctp` + `.misp-health-*` CSS + `thumbHealthList`
  registered (CLAUDE.md rule).
- **Severity glyph set is two-glyph (warn-triangle, danger-circle), not
  per-check distinct.** Sub-decision resolved without a separate fork
  — chip+glyph already carry the colour signal together, per-check
  icons would compete for the same attention. Inline SVG +
  `currentColor` (DD-32 theme independence). A third `success` glyph
  (check-mark in a circle) for the always-rendered header's "All
  checks passing" state. Glyphs inlined in `HealthList.ctp` (only
  three — no separate `HealthGlyph::get()` tool needed; if the set
  grows past four, extract).
- **Typed-row contract.** `header` (always renders — "All checks
  passing" or "N issues found") / `check`
  `{check, name, severity, severity_class, detail, drilldown}` /
  `message`. **Severity allow-list = `warning`, `danger` only** —
  info-tier rows are filtered out at the widget level and never reach
  the renderer. Header severity reflects worst row severity.
- **Caching (DD-20).** `$cache_duration = 300` (5min). Five of the
  diagnostics do real work — `stixDiagnostics()` spawns a Python
  subprocess via `ProcessTool::execute()`, `moduleDiagnostics()`
  HTTP-pings the module endpoints (×3 module types),
  `dbConfiguration()` runs `SHOW VARIABLES`, `gpgDiagnostics()` does
  GPG init + sign test, `dbSchemaDiagnostic()` reads schema files +
  compares. 5min keeps the widget cheap to render without hiding a
  fresh incident for more than one refresh cycle.
- **Widget shape.** `MispAdminHealthWidget`: `$render = 'HealthList'`,
  `$category='system'`, default size `3×4`, `$autoRefreshDelay=60`,
  `$cache_duration=300`, site-admin gate via `checkPermissions()`.
- **Verified.** `php -l` clean (widget + renderer); `node --check`
  clean (render-thumbs.mjs). **Live REST render → HTTP 200, 8 issues
  surfaced on the dev box:** 3 MySQL warn (`innodb_io_capacity` /
  `innodb_log_file_size` / `innodb_read_io_threads` below
  recommended), 1 filesystem danger (1 not writable / 0 not found —
  some `tmp/` subdir on this dev box), 3 module danger (Enrichment /
  Import / Export — no module daemon running), 1 db-version-mismatch
  warn (dev-branch actual=151 ahead of expected=150 from the snapshot
  schema file — true positive but misleading copy on this end; would
  read correctly on a production "behind" state). **HTML render class
  histogram clean** — 8 rows, 4 chip-danger + 4 chip-warning, 9 glyph
  SVGs (1 header + 8 rows). **Escaping confirmed** — apostrophes in
  module curl-error messages encoded once as `&#039;` (single-escape;
  DD-34 renderer-owns-escaping pattern holds). **Headless-Chrome
  screenshot** against the full CSS stack (bootstrap5 + mainOvermind
  + fontawesome7 + dashboard.default + midnight + overmind theme
  override) exercising all 3 header severities + warn/danger chips +
  long-detail truncation + missing-detail row — all render cleanly.
  Temp webroot eye-check file deleted post-screenshot.
- **Pure addition, fully reversible.** No existing widget / model /
  controller / renderer / CSS rule touched. Reverse = delete widget
  + renderer + CSS block + thumb registry entry.

## Prior-session facts (still true — condensed; reuse)

### Render-kind family (DD-31 / DD-32 / DD-33 / DD-35 / DD-38 / DD-39)
The dashboard now has these v2 render kinds beyond the legacy SimpleList,
BarChart, MultiLineChart, WorldMap, Index, Button, OrgsPictures, Attack,
Achievements, PieChart, MonitorLineChart:

- **StatGrid** (DD-31) — KPI metric cards, `{title,value,change,
  drilldown,html_title,type:gap,html,icon}` contract (drop-in for
  SimpleList plus the `icon` glyph slot from DD-32). Card grid via
  `auto-fill / minmax(min(120px,100%),1fr)`. Used by `UsageDataWidget`.
- **NetworkGraph** (DD-33) — ECharts `graph` series (hub-and-spoke,
  `layout:'none'`, links by index, server-rack `image://` SVG node
  symbols via `serverSymbol(colour)`). Used by `MispAdminSyncTestWidget`.
- **UserList** (DD-35) — avatar/name/meta/badge rows; typed contract
  `header`/`user`/`message`; opt-in `search` (header) + per-row
  `action` (DD-36, sibling `<button>` not nested in the drilldown `<a>`).
  Used by `LoggedInUsersWidget`.
- **QueueList** (DD-38) — queue-health rows with two
  independently-coloured chips; typed contract `header`/`queue`/`message`.
  Used by `MispAdminWorkerWidget`.
- **HealthList** (DD-39, this session) — issue-only health-rollup rows
  `[severity glyph] check_name [detail] [severity chip]`; typed contract
  `header`/`check`/`message`. Severity allow-list = warning/danger only;
  info filtered at the widget. Used by `MispAdminHealthWidget`.

Every new render kind needs (CLAUDE.md): a glyph in
`app/webroot/js/dashboard/gallery/render-thumbs.mjs` (`thumb<Name>` builder
+ `REGISTRY` entry). The CSS-stack and computed-outcome verification
lesson (`feedback_verify_visible_outcome_not_property`) bites here every
time: a harness that loads only `dashboard.default.css` is missing
`bootstrap.css` / theme cascade and asserts may silently lie.

### ECharts vendored bundle (DD-02 + tree-shake rule)
A new `series.type` must be added to the vendored bundle's `use([...])`
and the bundle rebuilt — else `type:'<new>'` renders nothing
(`project_misp_echarts_bundle_treeshaken`). Build dir
`/tmp/echarts-bundle` (echarts@6.0.0 + esbuild@0.24.0) reusable;
`vendor/VENDORING.md` has the recipe. **No bundle rebuild this session
either** (HealthList is pure HTML/CSS, no ECharts series).

### Render-kind contract conventions (reuse)
- **Widget `handler()`s emit RAW strings**; the renderer `h()`s each
  interpolated scalar exactly once (DD-34 — caught again this session
  on STIX/module error strings carrying apostrophes; encoded as
  `&#039;` exactly once).
- **Colour decisions live in the widget**; the renderer maps an
  allow-listed class name to a `.misp-*-chip-<sem>` token pair. Don't
  let the widget paint inline styles or pick colour values directly.
- **Drilldown URLs gated by `DashboardURLValidator::validate`** (DD-03)
  — relative or same-host only; renderer drops unsafe URLs and renders
  the row un-linked.
- **Not the renderer's job to scroll** (DD-31): `.misp-widget-body`
  owns padding + `overflow:auto`. Don't set width/height/overflow on
  the inner container.

### `Server::*Diagnostics()` cross-call gotchas (carried — DD-39)
- All take `&$diagnostic_errors` by reference and `$diagnostic_errors++`
  internally. Pass `int 0` per call (NOT `array()`; the PHP-8
  "Cannot increment array" pattern bit MispAdminWorkerWidget last
  session). MispAdminHealthWidget passes a fresh `$errs = 0` per call
  and ignores the post-call value — the widget makes its own severity
  decision from the return value.
- `Server::moduleDiagnostics()` returns `0|1|2|<error string>`:
  0=OK, 1=disabled (skip), 2=enabled-but-no-modules (warn), string =
  error (fail).
- `Server::gpgDiagnostics()` returns `{status: 0-4, version}`. 0=OK,
  1=not configured (skip — could be intentional), 2=load failed,
  3=key/passphrase issue, 4=sign test failed.
- `Server::stixDiagnostics()` returns `{operational: 0|1|-1,
  invalid_version: bool, test_run: bool, <per-pkg>}`. Note
  `operational==1` is OK, `0` and `-1` are both fail.
- `Server::sessionDiagnostics()` returns `{handler, expired_count,
  error_code}`. **`error_code==0` doesn't mean "php_redis"** — the
  database handler with low expired_count also returns 0; check
  `handler === 'php_redis'` directly.
- `Server::dbSchemaDiagnostic()` returns `{actual_db_version,
  expected_db_version, update_locked, remaining_lock_time,
  update_fail_number_reached, diagnostic, error, ...}`. `expected ===
  '?'` when the schema file can't load (non-MySQL DB) — skip the
  comparison.
- `Server::getCurrentGitStatus(true)` returns `{commit, branch,
  latestCommit, version: {current, newest, upToDate}}`. `upToDate` ∈
  `same|older|newer|error|disabled`. HTTP call to GitHub with 3s
  timeout; respect the 5min cache for repeated renders.

## Open follow-ups (none blocking)

- **In-browser verification of DD-39 (deferred to the user — hard-refresh
  Ctrl-Shift-R):** confirm on the real admin dashboard — the **MISP
  Health** widget should render in the "system" category, surfacing
  the same 8 issues the REST probe found (or fewer if any have been
  fixed since). Add it to a board to eye-check the chrome integration.
- **NEXT SESSION'S TASK: TBD — user-flagged.** Natural extensions
  worth surfacing (offer the user a quick fork via AskUserQuestion if
  none of these is pre-flagged):
    * **HealthList polish** — per-row "Open the diagnostics page at
      THIS section" drilldown (currently every row links to
      `/servers/serverSettings/diagnostics` at the top; an anchor
      fragment per check would land the admin on the right tab).
    * **Health widget: dismissable rows** — some checks (e.g. STIX
      versions, MISP version outdated) might be "acknowledged" for a
      time-bound window; needs a small mutating action like DD-36's
      session-invalidate. Probably overkill for first pass.
    * **`MispAdminSyncTestWidget` + DD-39 cousin** — the sync test
      widget surfaces per-server connectivity but doesn't have a
      "summary roll-up" health surface; a `SyncHealthWidget` could
      reuse HealthList for the failing-servers view.
    * **`MispStatusWidget` flip to StatGrid** — pre-existing carried
      follow-up; the `(View)` link is already handled by StatGrid.
    * **Roll StatGrid out** to the remaining key/value admin widgets
      (resource widgets); glyphs per metric as needed.
    * **Network diagram polish** (DD-33; user floated, not committed):
      distinct "this instance" hub icon; edges tinted by status.
- Pre-existing (carried): **DD-11 ACL-enforced switchable geo widget
  path**; **org/COVID maps palette opt-in**; default-templates **live
  non-admin ACL check** (no non-admin API key on the box); **REST
  API-key auth was flaky a couple of sessions ago** (browser/session
  auth unaffected — used all this session).
- **Phase 6 merge — the USER does this, not us.**

## Live test instance

- URL `http://localhost:5007/dashboards` (302 without a session; 200 with).
  Admin user 1 (`admin@admin.test`, pw `Password12345`), Overmind theme.
  **Browser/session auth works** (login dance recipe in memory
  `reference_misp_login_dance`; cookie jar `/tmp/cj_stat.txt` is the one
  from last session and still valid this session). REST API-key path
  was flaky in a prior session but the session-cookie REST path
  (Accept: application/json + the cookie jar) worked all session for
  renderWidget probes.
- DB: `mysql -u misp -pPassword1234 misp`. MISP Redis: `redis-cli -n 13`.
  **SESSIONS are in Redis db0** (`PHPREDIS_SESSION:*`) — NOT db13, NOT
  `cake_sessions` table.
- **Health state on the dev box** (DD-39 verification anchor):
  8 issues surfaced — 3 MySQL warn (`innodb_io_capacity`/
  `innodb_log_file_size`/`innodb_read_io_threads`), 1 filesystem
  danger (1 path not writable), 3 module danger (Enrichment / Import
  / Export endpoints unreachable on `127.0.0.1:6666/6767`), 1
  db-version mismatch warn (actual=151 ahead of expected=150 — dev
  branch state). Session = `php_redis` ✓ (so no row); GPG ✓; STIX ✓
  (operational=1, valid versions); version check ✓ (not surfacing —
  presumably `same` or `error`/`disabled`).
- **Workers state on the dev box** (DD-38 anchor):
  6 queues / 21 workers alive; queue alives are
  `default=5/5, email=5/5, cache=5/5, prio=5/5, update=1/1,
  scheduler=0/0`. All queues have 0 pending jobs.
- State: `db_version=151`; branch `dashboards`. Build dir
  `/tmp/echarts-bundle` reusable for bundle rebuilds.

### Reusable verification recipes
```bash
# Lint
php -l app/Lib/Dashboard/<Widget>.php
node --check app/webroot/js/dashboard/charts/charts.module.mjs
node --check app/webroot/js/dashboard/charts/vendor/echarts.bundle.mjs
node --check app/webroot/js/dashboard/gallery/render-thumbs.mjs

# Render a widget body via the web-UI cookie path. JSON path is most
# useful — wrapped envelope you can pipe through jq/python.
# (Cookie jar /tmp/cj_stat.txt — re-mint via reference_misp_login_dance
# if it 302s.)
curl -s -b /tmp/cj_stat.txt -X POST -H "Accept: application/json" \
  "http://localhost:5007/dashboards/renderWidget/test1" \
  --data-urlencode "widget=<WidgetName>" --data-urlencode "config={}"
# NB: cached widgets ($cache_duration) serve a stale payload — purge first:
redis-cli -n 13 --scan --pattern 'misp:<snake>_cache*' | xargs -r redis-cli -n 13 DEL
# For MispAdminHealthWidget the cache key is misp:misp_admin_health_widget_cache*.

# Eye-check a render kind visually (NEW renderer-only renderkinds,
# HealthList/QueueList/UserList/StatGrid). Drop a temp .html into
# app/webroot referencing the FULL CSS stack (bootstrap5-custom +
# mainOvermind + fontawesome7 + dashboard/dashboard.default +
# dashboard/dashboard.midnight + theme/Overmind/css/dashboard/overmind.css)
# — anything less is a false-pass trap
# (feedback_verify_visible_outcome_not_property). Then:
google-chrome --headless=new --no-sandbox --hide-scrollbars \
  --window-size=500,1000 --screenshot=/tmp/x.png \
  --virtual-time-budget=4000 http://localhost:5007/_xx_test.html
# Read the PNG. DELETE the temp webroot file after (it's publicly served).

# Rebuild the echarts bundle (add a series type): edit
# /tmp/echarts-bundle/entry.mjs use([...]), esbuild per vendor/VENDORING.md,
# cp the .mjs + LEGAL over (LEGAL dest name is echarts.bundle.LEGAL.txt).

# Inspect live sessions (db0):
redis-cli -n 0 --scan --pattern 'PHPREDIS_SESSION:*' | head

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
  `render-thumbs.mjs`. This session added `HealthList`.
- **ECharts series-type sibling rule:** a new `series.type` must be
  added to the vendored bundle's `use([...])` + rebuilt, else it
  silently renders nothing (memory
  `project_misp_echarts_bundle_treeshaken`). Not triggered this session
  (HealthList is HTML/CSS only).
- **Widget `handler()`s emit RAW strings; the renderer owns escaping**
  (DD-34). Don't `h()` in the widget when the render kind already
  escapes — it double-escapes. (Confirmed working this session against
  apostrophe-laden module error strings.)
- **Colour decisions live in the widget; the renderer is dumb.** The
  widget knows the thresholds; the renderer maps an allow-listed class
  name to a token-pair via CSS. Pattern is consistent across DD-31 /
  DD-32 / DD-38 / DD-39 chips and badges — uphold for any new render
  kind.
- **`Server::*Diagnostics()` methods take `&$diagnostic_errors` by
  reference and `$diagnostic_errors++` internally.** Pass `int 0` per
  call (NOT `array()`; PHP 8 "Cannot increment array").
- **Session handler check is `handler === 'php_redis'`, NOT
  `error_code === 0`** — the database handler returns `error_code=0`
  too. Codified as a DD-39 fold-in.
- **CSS verification must load the FULL stack** (bootstrap.css + theme
  + dashboard.default.css). Bootstrap's `input[type="search"]` (0,1,1)
  etc. silently beat single-class dashboard rules; assert the
  computed/visible outcome, not the attribute/property you set
  (`feedback_verify_visible_outcome_not_property`).
- User wants **rigorous pushback + genuine forks via AskUserQuestion**,
  and to **re-verify rather than defend** when a premise is questioned.

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 (DD-31..39) + `dashboard-design-decisions.md`
   DD-39 (+ DD-31..38 for the prior sessions' render kinds + the
   mutation/action pattern from DD-36) + this file.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302 (or 200 with the cookie jar — re-mint
   `/tmp/cj_stat.txt` via `reference_misp_login_dance` if it 302s).
3. **Next session's task: TBD — user-flagged.** Wait for the user to
   name the work. Natural extensions are listed in "Open follow-ups"
   above (HealthList polish, sync-health cousin widget, StatGrid
   rollout, etc.) — surface them via AskUserQuestion if the user opens
   with "what next?" rather than a directive.
4. **Gotchas to carry:**
   (a) new ECharts series type → rebuild the bundle's `use([...])`;
   (b) ESM imports ignore the `?v=185` buster → hard-refresh after a
   vendored-bundle/JS change;
   (c) sessions live in Redis **db0** (`PHPREDIS_SESSION:*`), MISP's own
   data in **db13**;
   (d) widget `handler()`s emit raw strings — the renderer escapes;
   (e) a body-filling render kind must let `.misp-widget-body` own
   scrolling;
   (f) Edit tool flips file group — `chgrp www-data` after edits;
   (g) **CSS verification must load the FULL stack** + assert the
   computed/visible outcome (not the property you set);
   (h) toggling an element via `[hidden]` needs an explicit
   `[hidden]{display:none}` when the element has an author `display:`;
   (i) `workerDiagnostics()` mixes per-queue arrays with top-level
   summary keys — iterate by `BackgroundJobsTool::VALID_QUEUES`;
   (j) **colour decisions belong in the widget**, the renderer just
   maps an allow-listed class to a token pair;
   (k) `Server::*Diagnostics()` methods take `&$errors` by reference —
   pass `int 0` (not `array()`; PHP 8 crash);
   (l) session-handler check is `handler === 'php_redis'`, NOT
   `error_code === 0` (database handler also returns 0).
5. Do NOT start the merge — the user does that. Watch context; refresh
   this handoff before wrapping.
