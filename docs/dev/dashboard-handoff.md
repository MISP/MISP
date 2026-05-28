# Dashboard v2 — Session handoff (2026-05-28 — DD-41 mail-log widget landed; next: TBD — user-flagged)

Twenty-third session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-41).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** One new entry this session:
  the `MispMailLogWidget + UserList glyph/recipe slots` bullet near
  the bottom of "Post-5.5 — New features".
- `dashboard-design-decisions.md` — DD-01..DD-41 (DD-41 this session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (5 signed commits, `%G?`=U, not merged)

```
bc8873ca3 new MispMailLogWidget — outgoing-mail status tail (DD-41)
6192eabde new UserList — optional `recipe` slot on message rows
18f1cea2e new MailLogTool — postfix mail-log tail reader (DD-41)
bcc0ced03 new UserList — optional `glyph` slot (token allow-list)
722df1cf2 chg open DD-41 — MispMailLogWidget + UserList glyph slot
```

One new admin-tier widget + two reusable UserList extensions:

1. **`MispMailLogWidget` (DD-41)** — recent outgoing-mail tail from
   the OS mail log (`/var/log/mail.log`, postfix-format). The only
   source that captures **remote bounces**: MISP's audit log
   (`logs.action='email'`) only records local sends, never the
   upstream MTA verdict. Site-admin only. Five status branches
   (sent / deferred / bounced / expired / undeliverable) each map to
   a glyph token (check / warn / danger).

2. **`MailLogTool`** — new `app/Lib/Tools/MailLogTool.php`, the
   postfix parser. Bounded tail-read via `fseek` (default 64 KB
   lookback), handles both RFC3339 and legacy-syslog date formats,
   path-allow-list `^/(var/log|tmp)/...` + explicit `..` reject +
   post-existence realpath check. Returns up to N normalised rows
   newest-first.

3. **UserList extensions (two slots, both backward-compat)** —
   (a) optional `glyph` token slot (`{check, warn, danger, info}`)
   → status-tinted avatar via `.misp-user-glyph-{token}` CSS class;
   (b) optional `recipe` array on `message` rows → inline
   `<details><summary>How to enable this widget</summary><ul>…</ul>
   </details>` block. Both token-driven (not raw HTML / SVG) so
   DD-34's renderer-owns-escaping invariant holds. `LoggedInUsersWidget`
   (DD-35 consumer) renders byte-identically.

Fully verified (REST + headless-Chrome screenshot against the full
CSS stack — both empty-state and happy-path side-by-side). Pure
additions for the widget + tool; surgical reversible extensions for
UserList. **The USER does the merge — do NOT open the PR or merge.**

## What landed (reuse these facts)

### DD-41 — `MispMailLogWidget` + UserList glyph/recipe slots (latest)

- **Data source — OS mail log, NOT MISP-internal.** User-explicit fork
  rejected three MISP-internal alternatives because **none capture
  remote bounces**: (a) `logs.action='email'` only records local-MTA
  acceptance; (b) extending `User::sendEmail()` exception path still
  blind to upstream verdicts (250 OK ≠ delivered); (c) `Job` table /
  BackgroundJobs `email` queue same blind spot. The OS log is the only
  source carrying `status=sent/deferred/bounced/expired/undeliverable`
  per-recipient.
- **Access constraint surfaced + chosen via fork.** `/var/log/mail.log`
  is `640 syslog:adm` on Debian/Ubuntu (`600 root:root` on RHEL);
  `www-data` is not in `adm` by default; adding it grants read on
  **most of `/var/log/*`** — a meaningful production-fleet privilege
  expansion (user-rejected). User chose: **configurable
  `MISP.mail_log_path` (default `/var/log/mail.log`) + clear empty-
  state with inline `<details>` setup-help** when the path is
  unreadable. Operator picks adm membership, dedicated rsyslog tee
  under `/var/log/misp/`, or a POSIX ACL — widget surfaces what setup
  is needed, no silent privilege expansion.
- **Path-allow-list (three layers).** (1) reject `..` / NUL upfront;
  (2) regex match `~^/(var/log|tmp)/[A-Za-z0-9._/-]+$~`; (3) after
  file-existence check, `realpath()` re-check against the allow-list.
  `/tmp/...` is permitted because the verification recipe uses a
  synthetic fixture there; **production never reads from `/tmp/`**.
  Verified: `/var/log/../etc/passwd` blocked by layer 1; symlink under
  `/tmp/x.log → /etc/passwd` blocked by layer 3.
- **`MailLogTool::tail($path, $lookbackBytes=65536, $limit=20)`** —
  `fopen + fseek` from end-of-file, discard the first (likely-truncated)
  line, parse the rest. Two regex patterns for both RFC3339 (modern
  rsyslog default) and legacy 3-token syslog timestamps. Scoped to
  postfix delivery processes that emit `status=`:
  `smtp|lmtp|local|virtual|error|bounce`. Other postfix daemons
  (master / pickup / cleanup / qmgr / postfix-script) skipped silently.
  Per-row `{ts, recipient, status, message, relay, queue_id}`.
  Returns newest-first, capped to `$limit`. Empty/missing file → empty
  array.
- **Failure modes (typed).** `InvalidArgumentException` = path not in
  allow-list; `RuntimeException` = file missing / unreadable / realpath
  out-of-allow-list. The widget catches both, returns a `message`
  row with the relevant recipe.
- **UserList extension #1 — `glyph` token slot** (the avatar override).
  Optional `glyph` field in user-row shape, value from a 4-entry
  allow-list `{check, warn, danger, info}`. Renderer has 4 inline-SVG
  defs + a CSS class `.misp-user-glyph-{token}` pulling the matching
  `--misp-dash-{success|warning|danger|info}` (foreground +
  `-muted` background) token pair. Avatar precedence: `glyph` →
  `org`-logo → initials chip. **Token, NOT raw SVG** — same pattern
  as DD-39's `severity_class` allow-list, so DD-34 escaping holds.
- **UserList extension #2 — `recipe` slot on `message` rows.**
  Optional `recipe` array of strings → inline `<details>` block beneath
  the title + value text. Summary i18n-aware "How to enable this
  widget"; each line a separate `<li>`, h()'d individually. Pure
  HTML, no JS, accessible. CSS block `.misp-user-help` sets the
  disclosure styling.
- **Status → glyph + chip mapping (widget-side).** `sent`→`check`/Sent,
  `deferred`→`warn`/Deferred, `bounced`→`danger`/Bounced,
  `expired`→`danger`/Expired, `undeliverable`→`danger`/Undeliverable.
  Header row tallies per status ("5 events · 1 Sent · 1 Deferred · …").
- **Row meta** = `<status label> · <humanised age> ago · relay=<r> ·
  <truncated MTA message>` — 80-char truncate on the message tail.
  Humanisation shape lifted from DD-40 (2-largest-units form,
  `1d 4h`, `5h 30m`, `45m 12s`), identical to the cache-status widget.
- **Widget shape.** `MispMailLogWidget`: `$render='UserList'`,
  `$category='system'`, default size `4×5`, `$autoRefreshDelay=60`,
  `$cache_duration=30` (anti-thundering-herd only), site-admin gate.
  Config: `log_path`, `limit` (hard-cap 200), `lookback_bytes` (hard-
  cap 4 MB).
- **No new render kind → no thumb glyph required** (UserList already
  registered). No ECharts change → **no bundle rebuild**.
- **`LoggedInUsersWidget` (DD-35 consumer) renders byte-identically.**
  Verified pre/post the UserList extension: HTML class histogram
  unchanged (no `misp-user-glyph*` / `misp-user-help` classes appear
  since the widget emits neither field). Backward-compat held.
- **Verified visually.** Headless-Chrome screenshot against the full
  CSS stack exercising both panels — happy path with 5 distinct
  status glyphs (3 red, 1 amber, 1 green) + empty state with the
  expanded `<details>` recipe (5 setup-help lines) renders cleanly
  side-by-side. Temp webroot eye-check file deleted post-screenshot.
- **Pure addition for the widget + tool; surgical extension for
  UserList.** Reverse widget = delete `MispMailLogWidget.php`. Reverse
  tool = delete `MailLogTool.php`. Reverse UserList extension =
  remove the `glyph` + `recipe` blocks (template + CSS); existing
  widgets keep rendering identically because none currently pass
  either field.

## Prior-session facts (still true — condensed; reuse)

### Render-kind family (DD-31 / DD-32 / DD-33 / DD-35 / DD-38 / DD-39 / DD-40 / DD-41)
The dashboard now has these v2 render kinds beyond the legacy SimpleList,
BarChart, MultiLineChart, WorldMap, Index, Button, OrgsPictures, Attack,
Achievements, PieChart, MonitorLineChart:

- **StatGrid** (DD-31) — KPI metric cards. Used by `UsageDataWidget`.
- **NetworkGraph** (DD-33, extended DD-40) — ECharts `graph` series,
  hub-and-spoke, server-rack + RSS-waves glyphs, 5-status colour set
  `{self, ok, warn, error, info}`. Used by `MispAdminSyncTestWidget`
  and `MispCacheStatusWidget`.
- **UserList** (DD-35, extended DD-36 + DD-41) — avatar/name/meta/badge
  rows; opt-in search + per-row action (DD-36); **DD-41 adds**
  optional `glyph` token slot (avatar override, 4 token allow-list)
  + optional `recipe` array on message rows (inline `<details>` setup
  help). Used by `LoggedInUsersWidget` (no extensions) +
  `MispMailLogWidget` (uses both).
- **QueueList** (DD-38) — queue-health rows with two independently-
  coloured chips. Used by `MispAdminWorkerWidget`.
- **HealthList** (DD-39) — issue-only health rollup rows
  `[severity glyph] check_name [detail] [severity chip]`. Used by
  `MispAdminHealthWidget`.

Every new render kind needs (CLAUDE.md): a glyph in
`app/webroot/js/dashboard/gallery/render-thumbs.mjs`. DD-41 didn't
trigger this (UserList already registered). The full-CSS-stack
verification rule (`feedback_verify_visible_outcome_not_property`)
bites every time.

### ECharts vendored bundle (DD-02 + tree-shake rule)
A new `series.type` must be added to the vendored bundle's `use([...])`
and rebuilt — else `type:'<new>'` renders nothing
(`project_misp_echarts_bundle_treeshaken`). Build dir
`/tmp/echarts-bundle` (echarts@6.0.0 + esbuild@0.24.0) reusable;
`vendor/VENDORING.md` has the recipe. **No bundle rebuild this session
either** — DD-41 is pure HTML/CSS.

### Render-kind contract conventions (reuse)
- **Widget `handler()`s emit RAW strings**; the renderer `h()`s each
  interpolated scalar exactly once (DD-34).
- **Colour decisions live in the widget**; the renderer maps an
  allow-listed class/status name to a `.misp-*-chip-<sem>` token pair
  / `image://` symbol. Don't paint inline styles.
- **Drilldown URLs gated by `DashboardURLValidator::validate`** (DD-03).
- **Not the renderer's job to scroll** (DD-31).
- **Token-driven slot extensions** (DD-39 `severity_class`, DD-41
  `glyph` + `recipe`): widgets pass a token name from a hard-coded
  allow-list; the renderer maps the token to the SVG / HTML. NOT raw
  SVG/HTML in handler return values — DD-34 escaping invariant.

### Mail log access on production instances (DD-41)
- `/var/log/mail.log` on Debian/Ubuntu is `640 syslog:adm`;
  `/var/log/maillog` on RHEL is `600 root:root`. `www-data` is **not**
  in `adm` on any standard distro by default.
- **Recipe narrowed to one recommended strategy** (follow-up consult,
  see DD-41 sub-note): scoped rsyslog `$FileCreateMode 0644` at
  `/etc/rsyslog.d/30-mail-world-readable.conf`:
  ```
  $FileCreateMode 0644
  mail.*    -/var/log/mail.log
  $FileCreateMode 0640
  ```
  then `sudo systemctl restart rsyslog`. **The 0640 reset line is
  load-bearing** — without it, the 0644 mode leaks to every subsequent
  rsyslog-created file. Threat-model framing: MISP usually runs in a
  dedicated VM/container, so the only meaningful read scope is
  `www-data`. Local-user PII concern is nil there.
- **Logrotate.** Debian/Ubuntu's default `/etc/logrotate.d/rsyslog`
  has no `create` line (verified on the dev box) → logrotate inherits
  rsyslog's `FileCreateMode` automatically across rotations. RHEL /
  CentOS does use `create`; operator must add
  `create 0644 syslog adm` to the rsyslog logrotate stanza.
- Rejected alternatives (DD-41 sub-note preserves the audit trail):
  `adm` group membership (privilege expansion across all `/var/log/*`);
  dedicated `/var/log/misp/mail.log` tee (creates a second log file
  the operator must remember to rotate / monitor); POSIX ACL
  (equivalent privacy scope but lost on rotation without a
  `postrotate` hook).

### `Server::*Diagnostics()` cross-call gotchas (carried — DD-39)
- All take `&$diagnostic_errors` by reference and `$diagnostic_errors++`
  internally. Pass `int 0` per call (NOT `array()`; the PHP-8
  "Cannot increment array" pattern bit MispAdminWorkerWidget).
- `moduleDiagnostics()` returns `0|1|2|<error string>`.
- `gpgDiagnostics()` returns `{status: 0-4, version}`.
- `stixDiagnostics()` returns `{operational: 0|1|-1, invalid_version,
  test_run, <per-pkg>}`. **`operational==1` is OK, not 0.**
- `sessionDiagnostics()` returns `{handler, expired_count, error_code}`.
  **`error_code==0` doesn't mean "php_redis"** — check
  `handler === 'php_redis'` directly.
- `dbSchemaDiagnostic()` returns `{actual_db_version,
  expected_db_version, update_locked, remaining_lock_time,
  update_fail_number_reached, ...}`. `expected === '?'` when the
  schema file can't load — skip the comparison.
- `getCurrentGitStatus(true)` returns `{commit, branch,
  latestCommit, version: {current, newest, upToDate}}`. `upToDate` ∈
  `same|older|newer|error|disabled`.

### Server & Feed cache helpers (DD-40)
- `Server::attachServerCacheTimestamps(array $servers)` /
  `Feed::attachFeedCacheTimestamps(array $feeds)` hydrate
  `cache_timestamp` (Unix sec OR `null`/`false`) by pipelined Redis
  `GET` on `misp:server_cache_timestamp:{id}` /
  `misp:feed_cache_timestamp:{id}`.
- Filter on `caching_enabled = 1` (tinyint(1) column on both tables).
- Don't iterate Redis keys directly — use these helpers.

## Open follow-ups (none blocking)

- **In-browser verification of DD-41 (deferred to the user — hard-
  refresh Ctrl-Shift-R):**
    * **MISP Mail Log** widget renders in the "system" category and
      surfaces the empty-state recipe (the dev box's `/var/log/mail.log`
      is `640 syslog:adm` and `www-data` isn't in `adm`, so this is
      the expected default state).
    * Configure `log_path = /tmp/test-mail.log` (if the fixture is
      still on disk) or any readable postfix log → renders the row
      tail with distinct glyphs per status.
    * Verify existing **Logged-in users** widget still renders
      identically (DD-41 backward-compat check on a real board).
- **NEXT SESSION'S TASK: TBD — user-flagged.** Natural extensions
  worth surfacing (offer the user a quick fork via AskUserQuestion if
  none is pre-flagged):
    * **MispMailLogWidget polish** — (a) slide-in side panel for the
      setup help (the current inline `<details>` is the v1 cut; user
      mused on "clickable help that slides in the right menu");
      (b) per-row drilldown to the full log entry / queue id;
      (c) filter chip in the header (Sent / Deferred / Bounced /
      Expired) to pre-narrow the row list;
      (d) failure-only mode (suppress `sent` rows for noise reduction);
      (e) ship a `/etc/rsyslog.d/misp-mail.conf` recipe as a packaged
      INSTALL helper so operators get strategy #2 without
      copy-pasting.
    * **HealthList polish** (carried from prior session) — per-row
      anchor drilldown into the diagnostics page tab.
    * **MispCacheStatusWidget polish** (carried) — per-node click
      drilldown (server-rack → `/servers/cacheServer/<id>`, feed-icon
      → `/feeds/view/<id>`).
    * **Cache-status thresholds configurable** (carried).
    * **`MispAdminSyncTestWidget` flip to `info` for caching-only
      servers** (carried).
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
  Cookie jar `/tmp/cj_stat.txt` is the session-21 jar, still valid.
  Re-mint via `reference_misp_login_dance` if it 302s.
- DB: `mysql -u misp -pPassword1234 misp`. MISP Redis: `redis-cli -n 13`.
  **SESSIONS are in Redis db0** (`PHPREDIS_SESSION:*`).
- **Postfix** installed (locally only — no internet relay; the user did
  `sudo apt install postfix` this session). `/var/log/mail.log` exists
  mode `640 syslog:adm`. `www-data` is NOT in `adm` — the widget's
  default-path render hits the empty-state recipe. **Add www-data to
  `adm` if you want the widget to read it on this dev box — but per
  user direction this is NOT recommended for production fleets.**
- **Synthetic mail-log fixture** at `/tmp/test-mail.log` exercises all
  5 status branches across both timestamp formats — useful for
  re-verifying the parser quickly. **May be missing now** if `/tmp/`
  was cleared between sessions; re-create from the
  `app/Lib/Tools/MailLogTool.php` test recipe (the synthetic lines are
  in the DD-41 design-decisions entry).
- **Health state on the dev box** (DD-39 anchor): 8 issues — 3 MySQL
  warn / 1 fs danger / 3 module danger / 1 db-version mismatch warn.
- **Cache state on the dev box** (DD-40 anchor): 3 cache-enabled
  servers + 2 cache-enabled feeds.
- **Workers state on the dev box** (DD-38 anchor): 6 queues / 21
  workers alive.
- State: `db_version=151`; branch `dashboards`. Build dir
  `/tmp/echarts-bundle` reusable for bundle rebuilds.

### Reusable verification recipes
```bash
# Lint
php -l app/Lib/Dashboard/<Widget>.php
php -l app/Lib/Tools/<Tool>.php
node --check app/webroot/js/dashboard/charts/charts.module.mjs
node --check app/webroot/js/dashboard/gallery/render-thumbs.mjs

# Render a widget body via the web-UI cookie path.
curl -s -b /tmp/cj_stat.txt -X POST -H "Accept: application/json" \
  "http://localhost:5007/dashboards/renderWidget/test1" \
  --data-urlencode "widget=<WidgetName>" --data-urlencode "config={}"
# NB: cached widgets ($cache_duration) serve a stale payload — purge first:
redis-cli -n 13 --scan --pattern 'misp:<snake>_cache*' | xargs -r redis-cli -n 13 DEL

# Eye-check a render kind visually (NEW renderer-only renderkinds —
# HealthList / QueueList / UserList / StatGrid — or chart renderers
# via initChartsIn). Two viable patterns:
#   (a) Inline pre-rendered HTML into a static page — fetch the
#       widget HTML via curl with the cookie jar, embed into a temp
#       file under app/webroot referencing the FULL CSS stack
#       (bootstrap5-custom + mainOvermind + fontawesome7 +
#       dashboard.default + dashboard.midnight + Overmind theme).
#       This is the DD-41 verification recipe — chrome doesn't
#       have the cookie jar.
#   (b) Drive an authenticated browser session yourself (harder; only
#       worth it for JS-heavy renderers — chart kinds).
# Anything less than the full CSS stack is a false-pass trap
# (feedback_verify_visible_outcome_not_property).
google-chrome --headless=new --no-sandbox --hide-scrollbars \
  --window-size=1200,820 --screenshot=/tmp/x.png \
  --virtual-time-budget=6000 http://localhost:5007/_xx_test.html
# Read the PNG. DELETE the temp webroot file after (it's publicly served).

# Mail-log fixture for DD-41 (recreate if /tmp was cleared):
# - RFC3339 lines:    `2026-05-28T15:01:01.000+02:00 host postfix/smtp[N]: AAAA: to=<x@y>, relay=…, status=sent (250 OK)`
# - Legacy lines:     `May 28 15:04:04 host postfix/error[N]: BBBB: to=<x@y>, relay=none, status=expired (…)`
# - Status branches:  sent / deferred / bounced / expired / undeliverable.

# Rebuild the echarts bundle (add a series type): edit
# /tmp/echarts-bundle/entry.mjs use([...]), esbuild per VENDORING.md.

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
  iglocska is in `www-data` so chgrp works without sudo.
- **Record meaningful decisions as DD-NN + a PRD §15 row.** Refinements
  get a NEW DD; small in-session polish stays as a sub-note.
- **Render-kind glyph rule** (CLAUDE.md): new `$render` → glyph in
  `render-thumbs.mjs`. DD-41 didn't trigger this (UserList reused).
- **ECharts series-type sibling rule:** a new `series.type` must be
  added to the vendored bundle's `use([...])` + rebuilt
  (`project_misp_echarts_bundle_treeshaken`). Not triggered this
  session.
- **Widget `handler()`s emit RAW strings; the renderer owns escaping**
  (DD-34).
- **Colour decisions live in the widget; the renderer is dumb.** The
  widget knows the thresholds; the renderer maps an allow-listed
  class/status/glyph token to a token-pair. Consistent across
  DD-31 / DD-32 / DD-38 / DD-39 / DD-40 / DD-41 — uphold for any new
  render kind or slot extension.
- **Token-driven slot extensions** (DD-41 glyph + recipe; DD-39
  severity_class): widgets pass a TOKEN, the renderer holds the
  inline-SVG / HTML. Never raw SVG/HTML in handler return values.
- **Mail-log path safety (DD-41):** three-layer check — reject `..` /
  NUL, regex allow-list `/(var/log|tmp)/...`, post-existence realpath
  re-check. Operator opt-in by configuration; never assume www-data
  has read.
- **UserList row precedence (DD-41):** `glyph` → `org` (logo) →
  initials chip. Backward-compat: rows missing both fields render via
  initials.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**,
  and to **re-verify rather than defend** when a premise is questioned.

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 (DD-31..41) +
   `dashboard-design-decisions.md` DD-41 (+ DD-31..40 for prior
   sessions' render kinds and the mutation/action pattern from DD-36) +
   this file.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302 (or 200 with the cookie jar — re-mint
   `/tmp/cj_stat.txt` via `reference_misp_login_dance` if it 302s).
3. **Next session's task: TBD — user-flagged.** Wait for the user to
   name the work. Natural extensions are listed in "Open follow-ups"
   above (MispMailLogWidget polish / drilldown / filter chip,
   HealthList anchor drilldown, MispCacheStatusWidget per-node
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
   `misp:{server,feed}_cache_timestamp:{id}` from Redis db13;
   (n) **mail-log path is an operator opt-in** — the widget's empty-
   state recipe lists the three access strategies (adm membership,
   dedicated rsyslog tee, POSIX ACL). DO NOT silently add `www-data`
   to `adm` — user-rejected. Always exercise the empty-state path
   in verification.
5. Do NOT start the merge — the user does that. Watch context; refresh
   this handoff before wrapping.
