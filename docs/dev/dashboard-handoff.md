# Dashboard v2 — Session handoff (2026-05-28 — DD-41 mail-log + search filter + DD-42 widget rework landed; next: TBD)

Twenty-third session, continued. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-42).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** Two new entries this
  session in "Post-5.5 — New features": the `MispMailLogWidget +
  UserList glyph/recipe` bullet (DD-41) and the
  `LoginsWidget + APIActivityWidget UserList rework + AuthFailures
  description` bullet (DD-42).
- `dashboard-design-decisions.md` — DD-01..DD-42 (DD-41 + DD-42 this
  session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (12 signed commits, `%G?`=U, not merged)

```
68780b6f0 new DD-41 — server-side search filter on MispMailLogWidget
32e507cfa chg handoff refreshed — DD-41 + DD-42 landed (intra-session)
26cd6c832 chg AuthenticationFailureWidget — clarify D4 provenance (DD-42)
11674fd73 chg APIActivityWidget — flip SimpleList -> UserList (DD-42)
cdfeaa70f chg LoginsWidget — flip SimpleList -> UserList (DD-42)
bf70129ba chg open DD-42 — Logins + APIActivity to UserList; AuthFailures description
8f25d87a4 chg DD-41 — recipe: note the pre-existing-file gotcha
3281e8f99 chg DD-41 — slim recipe to verbatim shell snippet
2d4def330 chg DD-41 — narrow setup recipe to one rsyslog strategy
9cdfc5957 chg handoff refreshed — DD-41 landed; next-session task TBD
bc8873ca3 new MispMailLogWidget — outgoing-mail status tail (DD-41)
6192eabde new UserList — optional `recipe` slot on message rows
18f1cea2e new MailLogTool — postfix mail-log tail reader (DD-41)
bcc0ced03 new UserList — optional `glyph` slot (token allow-list)
722df1cf2 chg open DD-41 — MispMailLogWidget + UserList glyph slot
```

Three pieces of work, all surfaced and resolved live:

1. **DD-41 — `MispMailLogWidget`** (postfix mail-log tail) + **UserList
   glyph / recipe slot extensions**. Site-admin widget rendering the
   last N postfix delivery records with status-tinted glyphs (sent →
   green check, deferred → amber warn, bounced/expired/undeliverable →
   red danger). Operator setup recipe narrowed to a single verbatim
   shell snippet (scoped `$FileCreateMode 0644` in rsyslog +
   `chmod 644 /var/log/mail.log` for the pre-existing-file case).

2. **DD-41 sub-note — server-side search filter on the mail-log
   widget.** Case-insensitive substring filter via a `search` config
   param (Tier 2 per the AskUserQuestion fork — server-side, no new
   protocol plumbing). Filters recipient + relay + queue_id + message
   *before* the limit cap so `$limit` reflects matching rows. When
   `search` is set, default lookback bumps 64 KB → 1 MB so the filter
   has range. Bounded-scan caveat documented: doesn't open rotated
   files (`mail.log.1`, `.gz` companions).

3. **DD-42 — front-end rework of three "legacy" widgets**.
   `LoginsWidget` + `APIActivityWidget` flipped from SimpleList to
   UserList — same data sources, just the row contract modernised
   (avatar + name + meta + badge + drilldown, DD-34 escaping
   restored). `AuthenticationFailureWidget` got a description-only
   fix to clarify it's the D4 project widget (sshd events ingested
   from a D4 collector as MISP events), NOT MISP login failures.

Fully verified (REST + headless-Chrome screenshots against the full
CSS stack). Pure additions for DD-41; user-explicit sign-off for DD-
42's touch of existing widgets. **The USER does the merge — do NOT
open the PR or merge.**

## What landed (reuse these facts)

### DD-41 sub-note — server-side search filter on MispMailLogWidget (latest)

- **Tier chosen via fork** — Tier 1 (client-side row filter via DD-
  36's `search:true` slot) too narrow (only filters the displayed 20
  rows); Tier 3 (inline search box + transient-search-param protocol
  extension) larger blast radius; **Tier 2** (server-side filter via
  config param, no protocol plumbing) the sweet spot.
- **`MailLogTool::tail(...)` signature** gains optional 4th arg
  `$search=''`. Non-empty → each parsed row filtered by
  `stripos($recipient . ' ' . $relay . ' ' . $queue_id . ' ' . $message, $search)`
  BEFORE the limit cap, so `$limit` reflects matching rows (not all
  rows in the window). **Substring, not regex** — good enough for
  "find all entries for alice@…", avoids the false-positive surface
  of regex over user input.
- **Widget config gains `search`.** When set, **default lookback
  bumps 64 KB → 1 MB** so the filter has actual range to scan
  (operator can still override `lookback_bytes` either way; the 4 MB
  hard-cap is preserved).
- **Header text adapts.** Filter active + matches:
  `'N match(es) for "<search>" · <per-status tally>'`. Filter
  active + no matches: `'No matches for "<search>" in the last
  <bytes> of log'`. Filter empty: original per-status tally.
- **Caching alignment.** `WidgetCache` keys on widget path +
  `sha256(config)` (DD-20). `search` is in config, so each distinct
  term naturally gets its own cache entry — `$cache_duration=30`
  still works without invalidation plumbing.
- **Bounded-scan caveat** (carried in DD-41 sub-note + the
  "Open follow-ups" list below): even at 4 MB hard-cap, the filter
  doesn't open rotated files (`mail.log.1`, `.gz` companions).
  Search-deep-history isn't promised — that's deferred follow-up
  work (gzip decompression + rotated-file traversal).
- **Verified.** Synthetic-fixture matrix: unfiltered, substring
  recipient match, substring message match, no-match, case-
  insensitive, limit-clamped-to-newest-match. Live REST renders
  against `/var/log/mail.log` confirm bumped lookback (visible in
  empty-state: `"in the last 1.0 MB of log"`) and the filter-active
  header text.

### DD-42 — Legacy-widget UserList rework + AuthFailures description

- **Scope is the front end only.** Data sources / query shapes /
  config schemas / autoRefreshDelay are all left intact. The rework
  is the row contract + render kind, nothing else. User-explicit
  sign-off to touch existing widgets (per
  `feedback_additive_only_posture`).
- **`LoginsWidget`** — was SimpleList, now `$render='UserList'`.
  Same `Log.action='login'` aggregation (`COUNT GROUP BY user_id`);
  added a second `User->find` with Organisation + Role contained for
  the renderer's avatar + meta. Row =
  `{name:email, meta:'<org> · <role>', badge:count, org:{id,name,uuid},
    drilldown:'/admin/users/view/<id>'}`. Header
  `'N user(s) · M login(s)'`. Deleted-user → muted row with
  `'user #<id> (deleted)'`. Restored the legacy `virtualFields['count']`
  declaration that Cake needs for the `Log__count` alias to land in
  `$log['Log']['count']` — removing it caused an "Undefined array
  key 'count'" warning that I caught in the first render.
- **`APIActivityWidget`** — was SimpleList, now `$render='UserList'`.
  Same Redis zrange-per-day + AuthKey lookup; AuthKey → User →
  Organisation + Role contained. Known row =
  `{name:email, meta:'key <prefix> · <org> · <role>', badge:count,
    org:{...}, drilldown:'/auth_keys/view/<id>'}` — drilldown targets
  the KEY so the admin can revoke / inspect; owner identity is the
  primary line. Unknown row uses DD-41's glyph slot =
  `{glyph:'warn', name:key_prefix, meta:'Unknown key — …',
    badge:count, muted:true}` — replaces the legacy
  `<span class="red">` + native-title-tooltip pattern.
- **Header pluralisation gotcha.** Both widget headers carry two
  numbers ("N users · M logins" / "N keys · M requests · K unknown").
  A combined `__n('N user · M login', 'N users · M logins', count)`
  only switches plural on the **first** count — `__n` is per-string,
  not per-placeholder. Cleanest fix: two separate `__n` calls
  composed via string concat:
  ```php
  $usersLabel  = sprintf(__n('%d user',  '%d users',  $userCount), $userCount);
  $loginsLabel = sprintf(__n('%d login', '%d logins', $total),     $total);
  $value = $usersLabel . ' · ' . $loginsLabel;
  ```
  Apply this pattern to any future UserList header that carries more
  than one count.
- **`AuthenticationFailureWidget` — description-only fix.** Old
  `$title='Authentication Failure Data'` + description "Widget
  visualising authentication failures collected in d4." easily
  misread on a MISP dashboard as *MISP* login failures (someone
  trying to log in to MISP and failing). New `$title='D4
  Authentication Failures'` + description clarifies it's sshd /
  similar events ingested from a D4 collector as MISP events, with
  an explicit pointer to LoginsWidget for the MISP login surface.
  No code / render / schema change.
- **DD-34 escaping invariant restored in passing.** Both list
  widgets previously emitted raw HTML in `html_title` / `html` /
  `value` (the SimpleList legacy plumbing echoed those verbatim).
  UserList's typed rows + per-scalar `h()` close that gap.
- **Drilldown patterns differ by widget intent.** LoginsWidget
  drills to the USER (the actor who logged in); APIActivityWidget
  drills to the KEY (so the admin can revoke / inspect the active
  credential). Both are MISP-internal paths, DD-03 validated at
  render time.
- **Sizes bumped 2×2 → 3×4** on both widgets — UserList row chrome
  (avatar + name + meta + badge) doesn't fit a 2×2 tile.
- **Backward-compat held.** `LoggedInUsersWidget` (DD-35 / DD-41
  consumer) renders byte-identically — class histogram unchanged,
  no `glyph` / `recipe` fields emitted there. Mirrors DD-40's
  canary-check approach.
- **Verified.** `php -l` clean ×3; live REST renders for both list
  widgets return correct UserList row shapes; headless-Chrome
  screenshot against the full CSS stack shows both rendering as
  proper siblings to `LoggedInUsersWidget`.

### DD-41 — `MispMailLogWidget` + UserList glyph/recipe slots (earlier in session)

- **Data source — OS mail log, NOT MISP-internal.** Only source
  that captures **remote bounces**: MISP's audit log
  (`logs.action='email'`) records local sends but never sees the
  upstream MTA verdict; adding a failure-logging path to
  `User::sendEmail()` was rejected for the same reason (SMTP `250
  OK` from local MTA ≠ delivery).
- **Access constraint — operator opt-in.** `/var/log/mail.log` is
  `640 syslog:adm` on Debian/Ubuntu (`600 root:root` on RHEL);
  `www-data` is not in `adm` by default; adding it would grant read
  on **most of `/var/log/*`** (user-rejected privilege expansion).
- **Recipe narrowed to a single verbatim shell snippet** (follow-up
  consult after I over-built it into a three-option menu). The
  snippet drops `/etc/rsyslog.d/30-mail-world-readable.conf` with a
  scoped `$FileCreateMode 0644 ... mail.* ... $FileCreateMode 0640`
  bracketing form (**the reset is load-bearing** — without it, 0644
  leaks to every subsequent rsyslog-created file), restarts rsyslog,
  then `chmod 644 /var/log/mail.log` for the pre-existing-file case
  (rsyslog's `FileCreateMode` only fires on file CREATION — restart
  doesn't re-create). Threat-model framing: MISP usually runs in a
  dedicated VM / container, so "world-readable" collapses to
  "www-data-readable".
- **Path-allow-list (three layers).** Reject `..` / NUL upfront →
  regex match `~^/(var/log|tmp)/[A-Za-z0-9._/-]+$~` → post-existence
  `realpath()` re-check against the allow-list (catches a symlink
  under `/tmp/` pointing at `/etc/shadow`).
- **`MailLogTool`** — bounded tail-read via `fseek`, parses both
  RFC3339 and legacy-syslog postfix formats, scoped to
  `smtp|lmtp|local|virtual|error|bounce` processes with `status=`.
- **UserList extension #1 — `glyph` token slot.** Optional `glyph`
  field on user rows, value from a 4-entry allow-list
  `{check, warn, danger, info}`. Renderer has 4 inline-SVG defs +
  CSS class `.misp-user-glyph-{token}` pulling the matching
  `--misp-dash-{success|warning|danger|info}` token pair. **Token,
  NOT raw SVG** — DD-34 escaping invariant holds. Avatar precedence:
  `glyph` → `org`-logo → initials chip.
- **UserList extension #2 — `recipe` slot on `message` rows.**
  Optional `recipe` array. Multi-line strings → `<pre>` code block;
  single-line strings → `<p>` prose. Both `h()`'d. Lets a message
  row carry a copy-pasteable shell snippet inside an inline
  `<details>` block (zero JS, accessible).
- **Status → glyph + chip mapping (widget-side).** `sent`→`check`/
  Sent, `deferred`→`warn`/Deferred, `bounced`/`expired`/
  `undeliverable`→`danger`/<label>. Per-row meta: status label +
  humanised age + relay + truncated MTA message. Humanisation lifted
  from DD-40 / `IndexTable/Fields/caching.ctp` (two-largest-units
  form — consistent "ago" across the operational widget family).
- **Backward-compat held.** `LoggedInUsersWidget` (DD-35) emits no
  `glyph` / `recipe`, falls through to legacy avatar + message
  paths; HTML class histogram unchanged.

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
  `MispMailLogWidget` (DD-41 — uses both `glyph` and `recipe`).
- **QueueList** (DD-38) — queue-health rows with two independently-
  coloured chips. Used by `MispAdminWorkerWidget`.
- **HealthList** (DD-39) — issue-only health rollup rows
  `[severity glyph] check_name [detail] [severity chip]`. Used by
  `MispAdminHealthWidget`.

Every new render kind needs (CLAUDE.md): a glyph in
`app/webroot/js/dashboard/gallery/render-thumbs.mjs`. Neither DD-41
nor DD-42 added a new render kind, so neither triggered the glyph rule.

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

## Open follow-ups (none blocking)

- **In-browser verification of DD-42 (deferred to user — hard-refresh
  Ctrl-Shift-R):** Logins widget + API Activity widget render as
  UserList tiles in the "system" category, looking like siblings to
  LoggedInUsersWidget. AuthenticationFailureWidget title shows "D4
  Authentication Failures" with the clearer description.
- **NEXT SESSION'S TASK: TBD — user-flagged.** Natural extensions
  worth surfacing (offer the user a quick fork via AskUserQuestion
  if none is pre-flagged):
    * **`MispMailLogWidget` polish** — (a) **rotated-file
      traversal** (open `mail.log.1` + `.gz` companions so the
      `search` param can reach beyond the bounded 4 MB tail — the
      sub-note's documented caveat); (b) inline search-box UX
      (Tier 3 from this session's fork — transient-search-param
      protocol extension so admins type into a header box instead
      of opening widget config); (c) slide-in side panel for the
      setup help (current `<details>` is the v1 cut); (d) per-row
      drilldown to the full log entry or queue id; (e) filter chip
      in the header (Sent / Deferred / Bounced / Expired) to
      pre-narrow the row list; (f) failure-only mode (suppress
      `sent` rows); (g) ship a `/etc/rsyslog.d/misp-mail.conf`
      recipe as a packaged INSTALL helper so operators don't
      copy-paste from the widget.
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
      gallery that would benefit from the same treatment — e.g. the
      MispAdminResourceWidget, MispSystemResourceWidget if they
      still emit raw HTML).
- Pre-existing (carried): **DD-11 ACL-enforced switchable geo widget
  path**; **org/COVID maps palette opt-in**; default-templates **live
  non-admin ACL check**.
- **Phase 6 merge — the USER does this, not us.**

## Live test instance

- URL `http://localhost:5007/dashboards` (302 without a session; 200 with).
  Admin user 1 (`admin@admin.test`, pw `Password12345`), Overmind theme.
  Cookie jar `/tmp/cj_stat.txt` is the session-21 jar, still valid.
- DB: `mysql -u misp -pPassword1234 misp`. MISP Redis: `redis-cli -n 13`.
  **SESSIONS are in Redis db0** (`PHPREDIS_SESSION:*`).
- **Postfix** installed (locally only — sudo apt install postfix this
  session). `/var/log/mail.log` is now `644 syslog:adm` after the
  user's `chmod 644 /var/log/mail.log` — MispMailLogWidget renders
  live mail entries on this dev box.
- **Synthetic mail-log fixture** at `/tmp/test-mail.log` exercises
  all 5 status branches across both timestamp formats — may have
  been wiped between sessions; re-create from the DD-41 spec lines.
- **Login activity on the dev box** (DD-42 anchor): 51 logins this
  month by user #1 (admin@admin.test).
- **API activity on the dev box** (DD-42 anchor): 3 keys / 1008
  requests / 1 unknown key in this month's window.
- **Health state** (DD-39 anchor): 8 issues.
- **Cache state** (DD-40 anchor): 3 cache-enabled servers + 2
  feeds.
- **Workers state** (DD-38 anchor): 6 queues / 21 workers alive.
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

# DD-41 mail-log specific:
ls -la /var/log/mail.log    # should be 644 syslog:adm on this dev box
redis-cli -n 13 --scan --pattern 'misp:authkey_log:*'   # DD-42 API activity source

# Rebuild the echarts bundle (add a series type): edit
# /tmp/echarts-bundle/entry.mjs use([...]), esbuild per VENDORING.md.

# Stop/start a worker to exercise DD-38 chip thresholds:
supervisorctl -c /etc/supervisor/supervisord.conf stop misp-workers:misp-worker-default-00
supervisorctl -c /etc/supervisor/supervisord.conf start misp-workers:misp-worker-default-00
```

## Convention reminders

- **Context budget:** keep within the first ~20% normally; user OK'd
  up to 40% for UI work. THIS SESSION ended around 28% — slightly
  over. Carry forward.
- **Commit per progress-tracker task; never `git add -A`; explicit
  `git add` + `git status --short`; sign (`%G?`=U).**
- **Edit/Write flips a file's group to `iglocska:iglocska`** —
  `chgrp www-data` every edited web-served/app file afterward (incl.
  docs). `iglocska` is in `www-data` so chgrp works without sudo.
- **Record meaningful decisions as DD-NN + a PRD §15 row.**
  Refinements get a NEW DD; small in-session polish stays as a
  sub-note inside the parent DD.
- **Render-kind glyph rule** (CLAUDE.md): new `$render` → glyph in
  `render-thumbs.mjs`. DD-41 / DD-42 didn't trigger this.
- **Widget `handler()`s emit RAW strings; the renderer owns
  escaping** (DD-34). Watch SimpleList legacy widgets that emit
  `html_title` / `html` — those bypass `h()` and should be migrated
  to typed-row render kinds where possible (DD-42 hit two).
- **Colour decisions live in the widget; the renderer is dumb.**
  Consistent across DD-31 / DD-32 / DD-38..42.
- **Token-driven slot extensions** (DD-41 glyph + recipe; DD-39
  severity_class): widgets pass a TOKEN, the renderer holds the
  inline-SVG / HTML.
- **Mail-log path safety** (DD-41): three-layer check — reject
  `..` / NUL, regex allow-list `/(var/log|tmp)/...`, post-existence
  realpath re-check. Operator opt-in by config; never silently
  expand www-data privileges.
- **Multi-count `__n` plurals** (DD-42): compose from separate
  `__n` calls per number; a combined key only switches plural on
  the first.
- **Cake `virtualFields` for aliased aggregates** (DD-42): a
  `COUNT(...) AS Model__field` alias needs
  `$this->Model->virtualFields['field'] = 0;` declared first.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**,
  and to **re-verify rather than defend** when a premise is
  questioned.

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 (DD-31..42) +
   `dashboard-design-decisions.md` DD-41 + DD-42 (+ DD-31..40 for
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
   lookback bump. Bounded by the 4 MB hard-cap; rotated files
   not yet opened (deferred polish).
5. Do NOT start the merge — the user does that. Watch context;
   refresh this handoff before wrapping.
