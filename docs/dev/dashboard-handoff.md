# Dashboard v2 — Session handoff (2026-05-28 — DD-43 rotated-file + DD-44 admin-template snapshot landed; next: TBD)

Twenty-fourth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-44).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** Two new entries this
  session in "Post-5.5 — New features": the `MailLogTool rotated-file
  traversal (DD-43)` bullet and the `Shipped admin dashboard template
  — full snapshot replace (DD-44)` bullet.
- `dashboard-design-decisions.md` — DD-01..DD-44 (DD-43 + DD-44 this
  session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (3 signed commits, `%G?`=U, not merged)

```
47f3ccb41 chg DD-44 — shipped admin dashboard template: v2 snapshot
721b69163 new DD-43 — MailLogTool rotated-file traversal
<handoff refresh commit>
```

Plus the in-tree settings.local.json fix from the `/doctor` prompt
at the start of the session (replaced a broken `:*` mid-pattern
permission rule with a prefix-matching `--scan:*` form) — that was
the harness's local-config; not a dashboard-v2 change.

Two pieces of work, both landed and verified:

1. **DD-43 — `MailLogTool` rotated-file traversal.** Closes the
   explicit bounded-scan caveat carried in the DD-41 search-filter
   sub-note ("rotated files aren't opened; search-deep-history isn't
   promised — deferred follow-up"). When `$search !== ''` and the
   live-tail returns fewer than `$limit` matching rows, MailLogTool
   fills remaining slots from rotated companions (`<path>.1` plain
   + `<path>.N.gz`) in age order. Without `$search`, byte-identical
   to DD-41 — the search-gated trigger IS the opt-in.

2. **DD-44 — Shipped admin dashboard template snapshot.** The v1-era
   6-widget Administrator template (UsageData / NewUsers /
   AuthenticationFailure / MispStatus / Logins / APIActivity)
   replaced with a 14-widget snapshot of the dev-box admin's hand-
   curated v2 layout. Fresh uuid (user picked "full snapshot
   replace" scope); description refreshed to enumerate the v2
   surface; the full DD-31..DD-43 widget family is now represented
   in the default admin board. **AuthenticationFailureWidget +
   MispStatusWidget intentionally dropped** — mirrors the admin's
   personal curation (D4 surface is niche, resource trio +
   MispAdminHealth cover MispStatus's slot).

## What landed (reuse these facts)

### DD-43 — `MailLogTool` rotated-file traversal

- **Scope-tight refactor of `MailLogTool` only** — widget API is
  unchanged (no new config knobs, no render-kind change). The
  `tail($path, $lookbackBytes, $limit, $search)` signature is the
  same as DD-41; behaviour for an empty `$search` is byte-identical.
- **Three new private methods**:
  - `_tailPlainFseek()` — DD-41 fseek body factored out; reused by
    the live file AND uncompressed rotated `.1` companions (same
    bounded-tail path).
  - `_scanForward($path, $isGzip, $limit, $search)` — streaming
    `gzopen`+`gzgets` (or `fopen`+`fgets`) chronological scan; per-
    file `array_reverse` to newest-first; memory bound = matches ×
    ~200B/row + 10M-line hard iteration cap.
  - `_findRotated()` — `glob('<path>.*')` filtered to
    `[ctype_digit][.gz]?` suffixes only; sorted by rank ASC. Bogus
    siblings like `mail.log.foo` / `.bak` never enter the candidate
    list at all.
- **Per-file safety bundle `_isReadableAllowedFile()`** — re-runs the
  full DD-41 three-layer check (allow-list regex + `is_file` +
  `realpath` re-validation against allow-list + `is_readable`) on
  every rotated companion. A `<path>.99 -> /etc/passwd` symlink IS
  discovered by `_findRotated()` (the symlink itself sits in
  `/tmp/` or `/var/log/` so passes the regex) but rejected before
  any content is opened.
- **Age-ordered concatenation preserves global newest-first**: each
  file's rows are reversed within-file, files are visited newest-
  rotation-first, so the natural concat order IS newest-first
  across files. No final sort needed; the `array_slice` to `$limit`
  at the end catches per-file overshoot.
- **Empty-state header adapts**: when zero matches AND rotated
  companions exist, `"No matches for '<term>' across N log files"`
  replaces the DD-41 phrasing `"in the last X of log"` (which
  would understate the actual scan). Requires new public helper
  `MailLogTool::countLogFiles($path)` — cheap, stats only.
- **PHPUnit coverage backfilled** — new `app/Test/MailLogToolTest.
  php` (24 tests, 54 assertions): path safety, DD-41 baseline,
  DD-43 rotated traversal (incl. symlink rejection + bogus suffix
  filter), `countLogFiles()` helper. No PHPUnit existed for
  `MailLogTool` before this DD — DD-41 verified by REST + headless-
  Chrome only; the refactor's blast radius warranted the backfill.
- **Verified.** php -l clean ×2; PHPUnit 24/24; live REST renders
  against synthetic live+`.1`+`.2.gz` fixture across 8 scenarios
  (no-search, search-fills-live-only, search-spills-rotated,
  search-only-in-gz, zero-matches with new across-N-files empty-
  state, etc.); reflection-driven safety check confirms `.99` and
  `.98` symlinks pointing at `/etc/passwd` are discovered as
  candidates but rejected by `_isReadableAllowedFile()`. Backward-
  compat: omit `$search` → byte-identical to DD-41.
- **Open follow-up (deferred).** The `.gz` reader currently
  decompresses each rotated file linearly. For a giant
  `mail.log.2.gz` on a chatty mail relay (rare on MISP boxes —
  they typically only send their own outgoing mail), that's a few
  hundred ms per render when the search filter is active.
  Acceptable in v1 (cache_duration=30, autoRefreshDelay=60). If
  this surfaces as a real complaint, the fix is a bounded-
  decompress-from-end approach using `gzseek()` with a backwards-
  binary-search for the last `$lookbackBytes` of decompressed
  content. Not v1.

### DD-44 — Shipped admin dashboard template snapshot

- **`app/files/dashboard-templates/admin/template.json` regenerated
  from admin user 1's `user_settings.dashboard`** by a one-off
  Python snippet (run from `/tmp/`, deleted after — no committed
  build script; this is a one-time data refresh, not a recurring
  pipeline).
- **uuid**: `1bf983ac-539d-4e7a-828b-aa5585cfbe2c` →
  `5000487b-3e75-46e4-8c43-96da9dc2268b`. Fresh uuid signals the
  materially-different layout cleanly; the explicit `cake
  Dashboard importDefaultTemplates` ingest prunes the old uuid as
  orphaned.
- **name** unchanged (`Administrator`). **description** refreshed to
  enumerate the v2 surface ("live resource monitors (CPU, memory,
  disk), instance usage statistics, system health rollup, sync
  test and cache freshness, worker queues, mail log, recent
  logins, API activity, and the latest users to join").
- **`value`** = 14-widget verbatim copy of admin user 1's live
  layout. Was 6 widgets (UsageData / NewUsers /
  AuthenticationFailure / MispStatus / Logins / APIActivity). Now
  14, covering the full DD-31..DD-43 family.
- **`instance_id` gaps preserved** — admin's live config has
  `w_1, w_2, w_5..w_8, w_10..w_17` (history of add/remove);
  sequential renumber rejected as cosmetic + risky for any state
  cross-referencing the IDs.
- **Other metadata preserved**: `selectable=true`,
  `restrict_to_org_id=0`, `restrict_to_role_id=0`,
  `restrict_to_permission_flag='perm_site_admin'`.
- **AuthenticationFailureWidget + MispStatusWidget intentionally
  dropped from the new layout** — the admin's curated config
  removed both. D4 surface is niche; resource trio +
  MispAdminHealth cover the MispStatus slot.
- **Backward-compat (user-acknowledged for the new-uuid scope):**
  `importDefaultTemplates --prune` removes the old uuid on next
  explicit operator ingest; silent auto-ingest on update (DD-24)
  leaves it alone so installations don't experience a "template
  disappeared" moment.  `user_settings.dashboard` holds the
  resolved widget array (not a template-uuid reference), so no
  existing user layout is touched — only the gallery's selectable-
  templates surface is affected.
- **Verified.** `python3 -m json.tool` parses; `cake Dashboard
  importDefaultTemplates` reports `[OK] Administrator (#19)` +
  `[PRUNE] Administrator (#12) — no longer shipped` + `3 imported,
  0 failed, 1 orphaned pruned`; DB row at new uuid contains 14
  widgets, byte-identical JSON to user_settings.dashboard;
  `/dashboards/listTemplates.json` returns the new template with
  `user_id=0`, `selectable=true`, `restrict_to_permission_flag='perm_site_admin'`.

## Prior-session facts (still true — condensed; reuse)

### Render-kind family (DD-31 / DD-32 / DD-33 / DD-35 / DD-38..42)
The dashboard now has these v2 render kinds beyond the legacy SimpleList,
BarChart, MultiLineChart, WorldMap, Index, Button, OrgsPictures, Attack,
Achievements, PieChart, MonitorLineChart:

- **StatGrid** (DD-31) — KPI metric cards. Used by `UsageDataWidget`.
- **NetworkGraph** (DD-33, extended DD-40) — ECharts `graph` series,
  hub-and-spoke, server-rack + RSS-waves glyphs, 5-status colour set
  `{self, ok, warn, error, info}`. Used by `MispAdminSyncTestWidget`
  and `MispCacheStatusWidget`.
- **UserList** (DD-35, extended DD-36 + DD-41) — avatar/name/meta/
  badge rows; opt-in search + per-row action (DD-36); DD-41 adds
  optional `glyph` token slot + optional `recipe` array on message
  rows. Used by `LoggedInUsersWidget` (no extensions), `LoginsWidget`
  (DD-42), `APIActivityWidget` (DD-42 — uses `glyph`),
  `MispMailLogWidget` (DD-41 + DD-43 — uses both `glyph` and
  `recipe`; DD-43 extends `MailLogTool` to scan rotated companions).
- **QueueList** (DD-38) — queue-health rows with two independently-
  coloured chips. Used by `MispAdminWorkerWidget`.
- **HealthList** (DD-39) — issue-only health rollup rows
  `[severity glyph] check_name [detail] [severity chip]`. Used by
  `MispAdminHealthWidget`.

Every new render kind needs (CLAUDE.md): a glyph in
`app/webroot/js/dashboard/gallery/render-thumbs.mjs`. Neither DD-43
nor DD-44 added a new render kind, so neither triggered the glyph
rule.

### Mail log access on production instances (DD-41)
- `/var/log/mail.log` on Debian/Ubuntu is `640 syslog:adm`;
  `/var/log/maillog` on RHEL is `600 root:root`. `www-data` is not
  in `adm` by default.
- **Single recommended recipe** (DD-41, narrowed via follow-up):
  drop `/etc/rsyslog.d/30-mail-world-readable.conf` with the scoped
  `$FileCreateMode 0644` bracketing form, restart rsyslog, then
  `chmod 644 /var/log/mail.log` for the pre-existing file. RHEL /
  CentOS additionally needs `create 0644 syslog adm` in
  `/etc/logrotate.d/rsyslog`.

### MailLogTool::tail rotated-file traversal contract (DD-43)
- Trigger: `$search !== ''` AND live-tail returned < `$limit`
  matching rows. Without a search filter, only the live file is
  scanned (no value in plowing through rotated history just for
  "latest N events").
- File order: live → `.1` (plain) → `.2.gz` → `.3.gz` → ...
- Per-file safety bundle re-runs the DD-41 allow-list + realpath
  check on every rotated companion — symlinks to outside `/var/log`
  or `/tmp` are dropped silently.
- Plain rotated `.1` uses the same fseek tail as live; `.N.gz` uses
  streaming forward scan via `gzopen`+`gzgets`.
- Empty-state text: `"No matches for '<term>' across N log files"`
  when rotated companions exist; the DD-41 `"in the last X of log"`
  phrasing kept only when no rotations are found.

### `__n` plural agreement only switches the FIRST number (DD-42)
When a header carries two counts ("N users · M logins"), compose from
TWO separate `__n` calls — a single combined `__n` key only switches
plural on the first placeholder, so "1 user · 51 login" would ship.
Apply across any future multi-count UserList / SimpleList header.

### Render-kind contract conventions (reuse)
- **Widget `handler()`s emit RAW strings**; the renderer `h()`s each
  interpolated scalar exactly once (DD-34).
- **Colour decisions live in the widget**; the renderer maps an
  allow-listed class/status/glyph token to a token-pair / SVG / HTML
  block. Don't paint inline styles.
- **Drilldown URLs gated by `DashboardURLValidator::validate`** (DD-03).
- **Token-driven slot extensions** (DD-39 `severity_class`, DD-41
  `glyph` + `recipe`): widgets pass a token name from a hard-coded
  allow-list; the renderer maps the token to the SVG / HTML. NOT raw
  SVG/HTML in handler return values — DD-34 escaping invariant.

### `Server::*Diagnostics()` cross-call gotchas (carried — DD-39)
- All take `&$diagnostic_errors` by reference and increment internally.
  Pass `int 0` per call (NOT `array()`).
- `moduleDiagnostics()` returns `0|1|2|<error string>`.
- `stixDiagnostics()` `operational==1` is OK, not 0.
- `sessionDiagnostics()` `error_code==0` doesn't mean "php_redis" —
  check `handler === 'php_redis'` directly.
- `dbSchemaDiagnostic()` `expected === '?'` when the schema file
  can't load — skip the comparison.

### Server & Feed cache helpers (DD-40)
- `Server::attachServerCacheTimestamps($servers)` /
  `Feed::attachFeedCacheTimestamps($feeds)` hydrate
  `cache_timestamp` from Redis db13 via pipelined GETs.
- Filter on `caching_enabled = 1`. Don't iterate Redis keys directly
  — use these helpers.

### CakePHP `virtualFields` for aliased aggregates (DD-42)
A `find` with `'fields' => ['COUNT(Log.id) AS Log__count']` only
lands in `$log['Log']['count']` if the model has
`$this->Log->virtualFields['count'] = 0;` (or equivalent) declared
before the `find`. The DD-42 LoginsWidget rework dropped the legacy
declaration and crashed with "Undefined array key 'count'" on first
render — caught immediately, restored verbatim. Same pattern applies
to any other aliased aggregate.

### Dashboard template import flow (DD-22 / DD-24 / DD-44)
- `app/Console/cake Dashboard importDefaultTemplates` runs the
  explicit ingest with `$prune=true`: pruning orphans + upserting
  shipped uuids. Used after editing any
  `app/files/dashboard-templates/*/template.json`.
- The silent auto-ingest on update (DD-24) runs without `--prune`,
  so changing a uuid leaves the old row in place until an admin
  re-runs the CLI import.
- `Dashboard::__importTemplate()` validates required keys
  `{uuid, name, value}` + `Validation::uuid($uuid)` + `is_array
  ($value)` — anything malformed throws and is reported in the
  shell's `[FAIL]` summary.

## Open follow-ups (none blocking)

- **In-browser verification of DD-43 + DD-44 (deferred to user —
  hard-refresh Ctrl-Shift-R):**
  * MispMailLogWidget with `search` config set hits rotated `.1` /
    `.gz` companions when the live tail is too short (test against
    `/tmp/test-mail-rotated.log` fixture or live `/var/log/mail.log`
    with rotations present).
  * Template gallery (`/dashboards/listTemplates`) shows the new
    Administrator template (14 widgets); "Use this" loads the
    full v2 layout.
- **NEXT SESSION'S TASK: TBD — user-flagged.** Natural extensions
  worth surfacing (offer the user a quick fork via AskUserQuestion
  if none is pre-flagged):
    * **`MispMailLogWidget` polish (carried)** — the remaining
      sub-options from this session's mail-widget fork: (b) inline
      header search-box (Tier 3 from the DD-41 fork — transient
      search-param protocol extension); (c) slide-in side panel for
      the setup help (current `<details>` is the v1 cut); (d) per-
      row drilldown (no clean MISP-internal target — would need a
      postqueue-output bridge); (e) filter chips (Sent / Deferred /
      Bounced / Expired) in the header to pre-narrow the row list;
      (g) ship `/etc/rsyslog.d/misp-mail.conf` as a packaged
      INSTALL helper.
    * **Other shipped dashboard templates** — DD-44 only refreshed
      `admin/template.json`. `analyst/template.json` and
      `community/template.json` may also be due for a v2-era
      refresh (check whether either references v2 render kinds; if
      not, ship a similar snapshot from a curated reference layout).
    * **`HealthList` polish** (carried) — per-row anchor drilldown
      into the diagnostics page tab.
    * **`MispCacheStatusWidget` polish** (carried) — per-node click
      drilldown.
    * **Cache-status thresholds configurable** (carried).
    * **`MispAdminSyncTestWidget` flip to `info` for caching-only
      servers** (carried).
    * **Roll StatGrid out** to the remaining key/value admin widgets.
    * **Audit other legacy widgets** for SimpleList → typed-row-
      contract rework (DD-42 hit two; there may be more on the
      gallery — `MispAdminResourceWidget`, `MispSystemResourceWidget`
      if they still emit raw HTML).
    * **`MailLogTool` gz-tail optimisation** (DD-43 deferred) — if a
      chatty mail relay surfaces a render-cost complaint, replace
      the full-file gz forward scan with a bounded `gzseek`+
      backwards-binary-search for the last `$lookbackBytes` of
      decompressed content.
- Pre-existing (carried): **DD-11 ACL-enforced switchable geo widget
  path**; **org/COVID maps palette opt-in**; default-templates **live
  non-admin ACL check**.
- **Phase 6 merge — the USER does this, not us.**

## Live test instance

- URL `http://localhost:5007/dashboards` (302 without a session; 200 with).
  Admin user 1 (`admin@admin.test`, pw `Password12345`), Overmind theme.
  Cookie jar `/tmp/cj_stat.txt` is the session-21 jar, still valid into
  this session (no re-mint needed).
- DB: `mysql -u misp -pPassword1234 misp`. MISP Redis: `redis-cli -n 13`.
  **SESSIONS are in Redis db0** (`PHPREDIS_SESSION:*`).
- **Postfix** installed locally; `/var/log/mail.log` is `644 syslog:adm`
  via the DD-41 rsyslog recipe — MispMailLogWidget renders live mail
  entries on this dev box (no rotated companions present on the
  dev box yet — DD-43 rotated traversal verified against synthetic
  `/tmp/test-mail-rotated.log{,.1,.2.gz}` fixture and then cleaned
  up).
- **Login activity on the dev box** (DD-42 anchor): 51 logins this
  month by user #1 (admin@admin.test).
- **API activity on the dev box** (DD-42 anchor): 3 keys / 1008
  requests / 1 unknown key in this month's window.
- **Health state** (DD-39 anchor): 8 issues.
- **Cache state** (DD-40 anchor): 3 cache-enabled servers + 2
  feeds.
- **Workers state** (DD-38 anchor): 6 queues / 21 workers alive.
- **Admin user 1's saved dashboard**: 14 widgets covering the
  full v2 family (the source of the DD-44 template snapshot).
- State: `db_version=151`; branch `dashboards`. Build dir
  `/tmp/echarts-bundle` reusable for bundle rebuilds.

### Reusable verification recipes
```bash
# Lint
php -l app/Lib/Dashboard/<Widget>.php
php -l app/Lib/Tools/<Tool>.php
node --check app/webroot/js/dashboard/charts/charts.module.mjs
node --check app/webroot/js/dashboard/gallery/render-thumbs.mjs

# Render a widget body via the web-UI cookie path (JSON wrapper).
curl -s -b /tmp/cj_stat.txt -X POST -H "Accept: application/json" \
  "http://localhost:5007/dashboards/renderWidget/test1" \
  --data-urlencode "widget=<WidgetName>" --data-urlencode "config={}"

# HTML render (drop Accept: application/json):
curl -s -b /tmp/cj_stat.txt -X POST \
  "http://localhost:5007/dashboards/renderWidget/test1" \
  --data-urlencode "widget=<WidgetName>" --data-urlencode "config={}"

# Cached widgets ($cache_duration) serve stale payload — purge first:
redis-cli -n 13 --scan --pattern 'misp:<snake>_cache*' | xargs -r redis-cli -n 13 DEL

# Eye-check a render kind visually — DD-41 recipe (chrome doesn't
# have the cookie jar, so PRE-RENDER the widget HTML via curl, inline
# into a static page under app/webroot referencing the FULL CSS stack
# (bootstrap5-custom + mainOvermind + fontawesome7 +
#  dashboard.default + dashboard.midnight + Overmind theme).
google-chrome --headless=new --no-sandbox --hide-scrollbars \
  --window-size=1200,520 --screenshot=/tmp/x.png \
  --virtual-time-budget=4000 http://localhost:5007/_xx_test.html
# Read the PNG. DELETE the temp webroot file after (publicly served).

# DD-43 mail-log rotated-traversal verification — drop synthetic
# live/.1/.2.gz fixture under /tmp/, exercise via REST, clean up.
# See app/Test/MailLogToolTest.php for the per-file fixtures (helper
# methods liveFixture/plainRotatedFixture/gzRotatedFixture).

# DD-44 admin-template verification:
app/Console/cake Dashboard importDefaultTemplates
mysql -u misp -pPassword1234 misp -e "SELECT uuid, name, LENGTH(value) AS bytes FROM dashboards WHERE user_id=0;"

# Rebuild the echarts bundle (add a series type): edit
# /tmp/echarts-bundle/entry.mjs use([...]), esbuild per VENDORING.md.

# Stop/start a worker to exercise DD-38 chip thresholds:
supervisorctl -c /etc/supervisor/supervisord.conf stop misp-workers:misp-worker-default-00
supervisorctl -c /etc/supervisor/supervisord.conf start misp-workers:misp-worker-default-00
```

## Convention reminders

- **Context budget:** keep within the first ~20% normally; user OK'd
  up to 40% for UI work. Carry forward.
- **Commit per progress-tracker task; never `git add -A`; explicit
  `git add` + `git status --short`; sign (`%G?`=U).**
- **Edit/Write flips a file's group to `iglocska:iglocska`** —
  `chgrp www-data` every edited web-served/app file afterward (incl.
  docs). `iglocska` is in `www-data` so chgrp works without sudo.
- **Record meaningful decisions as DD-NN + a PRD §15 row.**
  Refinements get a NEW DD; small in-session polish stays as a
  sub-note inside the parent DD.
- **Render-kind glyph rule** (CLAUDE.md): new `$render` → glyph in
  `render-thumbs.mjs`. DD-43 / DD-44 didn't trigger this.
- **Widget `handler()`s emit RAW strings; the renderer owns
  escaping** (DD-34). Watch SimpleList legacy widgets that emit
  `html_title` / `html` — those bypass `h()` and should be migrated
  to typed-row render kinds where possible (DD-42 hit two).
- **Colour decisions live in the widget; the renderer is dumb.**
  Consistent across DD-31 / DD-32 / DD-38..42.
- **Token-driven slot extensions** (DD-41 glyph + recipe; DD-39
  severity_class): widgets pass a TOKEN, the renderer holds the
  inline-SVG / HTML.
- **Mail-log path safety** (DD-41 + DD-43): three-layer check —
  reject `..` / NUL, regex allow-list `/(var/log|tmp)/...`, post-
  existence realpath re-check.  DD-43 extends this to every
  rotated companion before opening.  Operator opt-in by config;
  never silently expand www-data privileges.
- **Multi-count `__n` plurals** (DD-42): compose from separate
  `__n` calls per number; a combined key only switches plural on
  the first.
- **Cake `virtualFields` for aliased aggregates** (DD-42): a
  `COUNT(...) AS Model__field` alias needs
  `$this->Model->virtualFields['field'] = 0;` declared first.
- **Dashboard template import** (DD-22 / DD-24 / DD-44): explicit
  CLI ingest uses `$prune=true`; silent auto-ingest does not.
  Changing a uuid means the old row sits until the next explicit
  re-ingest.  `user_settings.dashboard` holds the resolved widget
  array (not a uuid reference), so user dashboards aren't affected
  by template changes.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**,
  and to **re-verify rather than defend** when a premise is
  questioned.

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 (DD-31..44) +
   `dashboard-design-decisions.md` DD-43 + DD-44 (+ DD-31..42 for
   prior sessions' render kinds + the mutation/action pattern from
   DD-36) + this file.
2. Verify instance: `curl -s http://localhost:5007/dashboards
   -o /dev/null -w "%{http_code}\n"` → 302 (or 200 with the cookie
   jar — re-mint `/tmp/cj_stat.txt` via `reference_misp_login_dance`
   if it 302s).
3. **Next session's task: TBD — user-flagged.** Wait for the user
   to name the work. Natural extensions are listed in "Open
   follow-ups" above — surface them via AskUserQuestion if the user
   opens with "what next?" rather than a directive.
4. **Gotchas to carry:**
   (a) new ECharts series type → rebuild the bundle's `use([...])`;
   (b) ESM imports ignore the `?v=185` buster → hard-refresh after
   a vendored-bundle/JS change;
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
   (j) `Server::*Diagnostics()` methods take `&$errors` by
   reference — pass `int 0` (not `array()`; PHP 8 crash);
   (k) session-handler check is `handler === 'php_redis'`, NOT
   `error_code === 0`;
   (l) NetworkGraph supports per-node `kind` + 5 statuses — default
   to back-compat shapes when adding consumers;
   (m) Server / Feed cache timestamps come from
   `attach{Server,Feed}CacheTimestamps()` — Redis db13;
   (n) **mail-log path is an operator opt-in** — the widget's
   empty-state recipe carries the verbatim shell snippet; DO NOT
   silently add `www-data` to `adm`;
   (o) **DD-42 plural gotcha** — multi-count headers need TWO
   `__n` calls (one per number); single combined key only switches
   plural on the first;
   (p) **Cake aliased aggregates** — `Model__count` alias needs a
   `virtualFields` declaration on the model first or it returns
   undefined;
   (q) **DD-41 search filter** — `MailLogTool::tail(..., $search='')`
   filters BEFORE the limit cap (so `$limit` = matching rows, not
   all rows). Widget's `search` config triggers a 64 KB → 1 MB
   lookback bump;
   (r) **DD-43 rotated traversal** — only fires when `$search !=
   ''` AND live-tail < `$limit`; each rotated companion goes
   through the same allow-list + realpath safety bundle; empty-
   state header adapts to "across N log files" when companions
   exist;
   (s) **DD-44 admin template uuid changed** — old
   `1bf983ac-...` pruned, new `5000487b-...` is the shipped
   default; `user_settings.dashboard` is unaffected (resolved
   widget array, not a template reference).
5. Do NOT start the merge — the user does that. Watch context;
   refresh this handoff before wrapping.
