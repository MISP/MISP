# Dashboard v2 — Session handoff (2026-05-29 — UsageDataWidget cleanup + DD-45 Pew-pew map Phases A+B landed; next: Phase C (front-end 2D))

Twenty-fifth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-45 with the Phase B2 category correction).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** Post-5.5 "New features"
  carries DD-43, DD-44 + this session's DD-45 (Pew-pew attack flow
  map) — **Phases A + B all closed this session**; Phases C / D / E
  queued as sequential checklist sub-tasks.
- `dashboard-design-decisions.md` — DD-01..DD-45.  DD-45 carries a
  Phase B2 sub-note about the category correction
  (`'system'` → `'events'`) and the dev-DB arc-inventory reality
  (1 visible arc, 3 self-loops).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (5 signed commits, `%G?`=U, not merged)

```
205d97dce new DD-45 B3 — PHPUnit coverage for AttackFlowMapWidget (15 tests / 30 assertions)
32b2333ab new DD-45 B2 — AttackFlowMapWidget: galaxy-derived attacker→victim resolution
daafa0035 new DD-45 B1 — iso-centroids.json from world-110m.geojson + build script
3d5c60703 new DD-45 — pew pew attack flow map: planning docs (Phase A)
ae2c8a980 chg UsageDataWidget — drop dead /* checkPermissions */ block
<final handoff-refresh commit>
```

Audit + planning + full backend phase, all in one session. Four
pieces:

1. **Admin-template widget-access audit + UsageDataWidget cleanup.**
   User asked "every widget in the admin template should require
   admin privileges — is that the case?". Audit: **12/14 widgets
   actively gate on `perm_site_admin` via `checkPermissions()`**;
   2 are deliberately open — `UsageDataWidget` (aggregate
   statistics, no admin-only data; commented gate carried a
   "There is nothing sensitive in here" note) and `NewUsersWidget`
   (handler self-redacts emails + id-drilldown for non-admins).
   First audit was wrong on UsageDataWidget — `awk` matched the
   commented-out method body and I missed the `/*` wrapper.
   Self-corrected; the dead comment block (lines 422-431 of
   `app/Lib/Dashboard/UsageDataWidget.php`) was removed so it
   doesn't trip the next audit. Commit `ae2c8a980`.

2. **Dark-theme readiness check.** User asked "how prepared is
   the CSS for a light/dark toggle?". Audit: **dashboard side
   is fully ready** — 46 `--misp-dash-*` tokens defined on
   `:root`, 887 `var(--...)` usages, `dashboard.midnight.css`
   exists as a dormant overlay activated by `:root[data-theme=
   "midnight"]`, `charts.module.mjs::tokenOn()` makes ECharts
   theme-aware. PRD §8.1 explicitly anticipated this. **User
   agreed with my pushback** that a dashboard-local toggle is
   architecturally wrong — dark mode should ship as a global
   MISP `/Themed/<DarkTheme>/` overlay, not a per-page toggle.
   No code change. Decision saved as
   [[project-misp-dark-theme-sequencing]] memory.

3. **DD-45 — Pew-pew attack flow map (Phase A planning).** New
   widget scoped: `AttackFlowMapWidget` + new `PewPewMap` render
   kind, animated attacker→victim arcs in two modes (2D lines-
   airline + 3D echarts-gl globe), data sourced from threat-
   actor galaxy cluster `country` element → country-galaxy tag
   on event. Forks resolved (see DD-45 in design-decisions);
   phased plan written into progress.md.

4. **DD-45 Phase B (backend) — closed in this session.** Three
   commits, one per sub-task:
   * **B1 (`daafa0035`)** — `app/files/scripts/build_iso_centroids.
     py` (one-off Python build script using pycountry + the
     vendored `world-110m.geojson`); output
     `app/webroot/js/dashboard/charts/vendor/iso-centroids.json`
     (175 ISO entries, 4 KB raw / 2 KB gzipped, antimeridian
     unwrap verified against Fiji). `VENDORING.md` updated with
     row + reproduction recipe.
   * **B2 (`32b2333ab`)** — `app/Lib/Dashboard/AttackFlowMapWidget.
     php`. Resolves attacker country from threat-actor cluster's
     `country` element; victim from country-galaxy cluster's
     `ISO`; per-event cross-product; self-loops skipped;
     aggregate by (src_iso, dst_iso); `arsort` + `array_slice`
     at `max_arcs` (default 500); centroids loaded from
     iso-centroids.json. Two spec deviations resolved during
     implementation (DD-45 + PRD §15 + progress.md updated):
     `$category='events'` not `'system'` (matches
     AttributeGeoMapWidget) and params simplified to
     `time_window` / `mode` / `max_arcs` (org filter +
     date_range dropped per AttributeGeoMapWidget parity).
   * **B3 (`205d97dce`)** — `app/Test/AttackFlowMapWidgetTest.
     php`. 15 tests / 30 assertions / all green. Pure PHPUnit;
     stubs `ClassRegistry::init` + a fake `EventTag` model
     with response queue at the top of the file; `WWW_ROOT`
     pointed at a per-test temp dir for the centroids fixture.
     Coverage: empty paths, single-event arc, self-loop skip
     (including the "doesn't poison siblings" path), repeated-
     pair aggregation, cross-product (4 arcs from 2×2),
     within-event ISO dedupe, max_arcs truncation, invalid-ISO
     drop, missing-centroid drop, mode normalisation.

   **Dev-DB arc reality (carried for next session):** the
   Phase A scope-decision question estimated "~35 arcs". Real
   measurement after B2 landed: **1 visible arc only** —
   IR → US from event 1421's Charming Kitten / APT33 / APT35
   actor cluster. The other 3 dual-tagged events resolve to
   self-loops (Russia → Russia from Sofacy, Iran → Iran ×2
   from MuddyWater) and are correctly skipped per spec. The
   widget IS correct; the dev box just has thin data.
   Production instances will be richer; if Phase C visual
   verification needs more arcs to be meaningful, the user-
   rejected fixture-tagging fork can be revisited.

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

### UsageDataWidget — dead checkPermissions comment removed

- `app/Lib/Dashboard/UsageDataWidget.php` lines 422-431 carried
  a `/* There is nothing sensitive in here. ...checkPermissions
  body... */` block. PHP never parsed it; widget was always open
  to all users (matches its presence in both `admin/template.
  json` and `community/template.json`). Removed so it doesn't
  trip the next reader.
- Commit `ae2c8a980`. Pure cleanup; behaviour byte-identical.

### Admin template widget-access audit (informational, no DD)

- **Audit method:** for each of the 14 widgets in `app/files/
  dashboard-templates/admin/template.json`, run PHP-reflection
  + grep-after-comment-strip against
  `app/Lib/Dashboard/<Name>.php` looking for an active
  `checkPermissions()` method.
- **Result (post-cleanup):** 12 / 14 actively gate on
  `perm_site_admin` (LoginsWidget, APIActivityWidget,
  BenchmarkTopListWidget, MispAdminSyncTestWidget,
  MispAdminWorkerWidget, CpuLoadMonitorWidget,
  MemoryUsageMonitorWidget, DiskUsageMonitorWidget,
  LoggedInUsersWidget, MispAdminHealthWidget,
  MispCacheStatusWidget, MispMailLogWidget). 2 open by design:
  UsageDataWidget (aggregate-only) and NewUsersWidget (handler
  self-redacts emails + drilldown for non-admins,
  `cache_scope='user'` prevents cross-viewer leak).
- **First-audit landmine to remember:** the bash awk pattern
  `awk '/function checkPermissions/,/^    }/'` will happily
  match a function body that lives inside a `/* ... */` block.
  PHP reflection (`ReflectionClass::hasMethod`) or grep with
  pre-stripped comments is the correct audit.
- **Bonus finding (corrected):** my first audit pass claimed
  Community template silently drops UsageDataWidget for non-
  admins via `Dashboard::import()`'s `loadWidget(..., true)`
  filter. **Wrong** — the gate was commented out; widget loads
  normally. Both audits + the commit message document the
  self-correction so it doesn't recur.

### Dark-theme readiness check (informational, no DD)

- Quantified the dashboard's token surface: **46
  `--misp-dash-*` tokens** defined on `:root` of
  `app/webroot/css/dashboard/dashboard.default.css`, **887
  `var(--misp-dash-*)` usages** across the file.
- `dashboard.midnight.css` (49 lines) is a complete dark
  overlay activated by `:root[data-theme="midnight"]`. Loaded
  alongside `dashboard.default.css` in both
  `app/View/Layouts/dashboard.ctp:31-32` AND
  `app/View/Themed/Overmind/Layouts/dashboard.ctp:48-49`.
- `charts.module.mjs::tokenOn(hostEl, name, fallback)` reads
  `getPropertyValue` from the host element at render time —
  ECharts repaints follow the cascade automatically.
- **8 hardcoded colour rules remain outside `:root`** —
  mostly translucent `rgba(0,0,0,0.x)` borders/scrims that
  work on both backgrounds; the one `rgba(220, 38, 38, 0.10)`
  at `dashboard.default.css:544` is the real candidate for a
  token if dark mode is rolled out.
- **Gap in `dashboard.midnight.css`:** does NOT redefine
  `--misp-dash-{success,danger,warning,info}-muted` — the
  WorldMap choropleth low-stops would render with their
  light-theme translucent values on a dark base.  Visual check
  needed if/when a dark theme ships.
- **Decision:** dark mode is parked until a global MISP dark
  theme exists.  Per PRD §8.1 ("Activation is owned by MISP's
  theme system, not the dashboard"), the right path is a
  `Themed/<DarkTheme>/` overlay covering the whole MISP UI; the
  dashboard inherits via tokens for free. Memory note
  [[project-misp-dark-theme-sequencing]] saved.

### DD-45 — `AttackFlowMapWidget` + `PewPewMap` render kind (planning only)

- **New v2 render kind** with two modes: 2D `lines-airline`-
  style great-circle arcs (ECharts `geo` + `lines` series, with
  animated trail effect) and 3D `lines3D` on `globe` (echarts-
  gl extension, lazy-loaded). Same `flows[]` payload feeds both.
- **Data source (forks resolved against IP-pair option):**
  attacker country = threat-actor galaxy cluster's `country`
  galaxy element (ISO alpha-2, 937 clusters carry this on the
  dev DB); victim country = country-galaxy tag on the same
  event (cluster's `ISO` element). One arc per `(event, actor,
  victim)` triple; aggregate across events by `(src_iso,
  dst_iso)` into a `value` count; cap at `max_arcs` (default
  500).
- **Centroid resolution:** build-time `iso-centroids.json`
  (~3 KB, generated from the existing `world-110m.geojson`
  vendor file by a new `app/files/scripts/
  build_iso_centroids.py`). Polygon centroids with
  antimeridian handling so Fiji / Russia / Kiribati land
  correctly.
- **3D bundle: lazy-load.** Forks resolved against eager-
  vendoring (~500 KB-1 MB extra on first paint for the 95% of
  deployments that don't use 3D). Approach: build a separate
  `app/webroot/js/dashboard/charts/vendor/echarts-gl.bundle.
  mjs` + world-texture asset; `charts.module.mjs::
  buildPewPewOption3D` dynamic-imports on first 3D-mode render
  (browser-cached thereafter).
- **Default mode = 2D.** Conservative; avoids ~1-2s GL fetch
  on first-render of a freshly-placed widget. User opts into
  3D via config dropdown.
- **Widget shape:** `$render='PewPewMap'`, `$category=
  'system'`, `$cache_duration=3600`, `$cache_scope='global'`,
  open to all users (no admin gate — aggregate-only, mirrors
  AttributeGeoMapWidget DD-11 posture), default size 6×5.
- **Theming:** arc body uses `--misp-dash-danger`; destination
  glow uses `--misp-dash-warning`. Tokens resolve via existing
  `tokenOn()` helper; light/dark transparent.
- **CLAUDE.md glyph rule applies:** Phase C-4 adds
  `thumbPewPewMap()` to `render-thumbs.mjs`.
- **Dev DB verification surface:** ~35 events with both
  signals → realistic dozens of arcs visible. Sparse but not
  zero; visual verification feasible without fixture seeding.
- Full spec: `dashboard-design-decisions.md` DD-45. Phased
  implementation checklist: `dashboard-progress.md` under
  "Post-5.5 — New features".

### (Carried prior-session detail — still load-bearing)

The detailed `DD-43 — MailLogTool rotated-file traversal` and
`DD-44 — Shipped admin dashboard template snapshot` blocks
from the previous handoff still describe live shipped
behaviour. Trimmed from this handoff to keep it focused on
the live next-session pointer; consult the previous handoff
in git (`git show 296449fdd:docs/dev/dashboard-handoff.md`)
if you need the full DD-43 / DD-44 narratives.

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

## Open follow-ups (active work + carried)

### NEXT SESSION'S TASK — DD-45 Phase C (front-end 2D)

Phase B is closed.  Phase C is the 2D animated arcs: rebuild
the ECharts bundle, ship the render-kind template, build the
chart option, add the gallery glyph, screenshot-verify.  One
commit per sub-task (per `feedback_commit_per_task`):

- **C1.** Rebuild `app/webroot/js/dashboard/charts/vendor/
  echarts.bundle.mjs` with `LinesChart` added.  Recipe from
  `vendor/VENDORING.md` "Reproducing the bundle" section:
  edit `/tmp/echarts-bundle/entry.mjs` to add `LinesChart` to
  both the `import { ... } from 'echarts/charts';` and the
  `echarts.use([...])` call; re-run esbuild; copy the new
  `echarts.bundle.mjs` + `.LEGAL.txt` into
  `app/webroot/js/dashboard/charts/vendor/`.  Note the
  bundle-size delta in `VENDORING.md` (expected +15-20 KB
  gzipped; `LinesChart` is a small series type).  Per
  [[project-misp-echarts-bundle-treeshaken]] — without the
  `use()` registration, `type:'lines'` silently renders
  nothing.  `/tmp/echarts-bundle/` already has `node_modules`
  from prior session (per Apr 6 timestamps); a fresh
  `npm install` is probably needed (~30s).
- **C2.** `app/View/Elements/dashboard/Widgets/PewPewMap.ctp`
  — render kind shim.  Reads `payload.mode` from the data
  passed in; calls `chartsModule.buildPewPewOption2D(payload,
  hostEl)` (Phase C path) or `...3D(...)` (Phase D path; for
  now wires only the 2D call, with a "3D pending Phase D"
  placeholder for the 3d-globe branch).  Per
  [[feedback_dashboard_chrome_icons]] — render-kind chrome
  stays inline SVG, not FA.  `.misp-widget-body` owns
  scrolling (body-filling render kinds let it).
- **C3.** `buildPewPewOption2D(payload, hostEl)` in
  `app/webroot/js/dashboard/charts/charts.module.mjs`.
  ECharts geo + lines series.  Two layers per the DD-45
  spec: background static arcs (`lineStyle: { type:
  'solid', opacity: 0.4 }`) + foreground animated trail
  (`effect: { show: true, trailLength, symbol: 'arrow' }`).
  Width scales by `Math.log(value+1)`; opacity by normalised
  value.  Colours resolve via the existing `tokenOn(hostEl,
  '--misp-dash-danger', '#dc2626')` (arc body) +
  `'--misp-dash-warning'` (destination glow).  Re-uses the
  same `world-110m.geojson` map registration as
  `buildGeoOption`.
- **C4.** `thumbPewPewMap()` builder in
  `app/webroot/js/dashboard/gallery/render-thumbs.mjs`.
  Single-colour SVG glyph at 80×45 viewBox, currentColor.
  Schematic: a small world outline (3-4 country blobs) + two
  diagonal arcs converging on a centre point.  Registered in
  the bottom `REGISTRY` object under key `'PewPewMap'`.
  CLAUDE.md render-kind glyph rule.
- **C5.** Visual verification (DD-41 recipe).  Pre-render
  the widget HTML via curl against `/dashboards/renderWidget/
  test1` (use API key auth — see [[reference-misp-test-instance]]
  — since the cookie jar `/tmp/cj_stat.txt` may need re-
  minting via [[reference-misp-login-dance]] if it 302s).
  Inline the rendered HTML into a static page under
  `app/webroot/_test_pewpew.html` referencing the FULL CSS
  stack (bootstrap5-custom + mainOvermind + fontawesome7 +
  dashboard.default + dashboard.midnight + Overmind theme).
  Headless Chrome screenshot.  Read the PNG.  **Delete the
  temp webroot file after.**  Per
  [[feedback_verify_visible_outcome_not_property]] — verify
  the computed/visible outcome (arc rendered, trail
  animating), not just the property you set.

### Carried for Phase D / E

Full sequential plan in `dashboard-progress.md`.
* **Phase D** (front-end 3D, lazy-loaded): build separate
  `echarts-gl.bundle.mjs`; vendor `world-texture-2k.jpg`;
  `buildPewPewOption3D` with dynamic `import()`; mode-switch
  config wiring; visual verification.
* **Phase E** (polish): cache tuning, follow-ups recorded,
  handoff refresh.

### Carried follow-ups (not active)

- **In-browser verification of DD-43 + DD-44** (deferred to user
  — hard-refresh Ctrl-Shift-R): MispMailLogWidget rotated-file
  scan against live `/var/log/mail.log` with rotations; template
  gallery shows the new Administrator template (14 widgets).
- **`MispMailLogWidget` polish (carried from DD-41)** — (b)
  inline header search-box; (c) slide-in side panel for setup
  help; (d) per-row drilldown (no clean MISP-internal target);
  (e) filter chips (Sent/Deferred/Bounced/Expired); (g) ship
  `/etc/rsyslog.d/misp-mail.conf` as a packaged INSTALL helper.
- **Other shipped dashboard templates** — `analyst/template.
  json` and `community/template.json` may be due for a v2-era
  refresh similar to DD-44.
- **HealthList polish** — per-row anchor drilldown into
  diagnostics page tab.
- **MispCacheStatusWidget polish** — per-node click drilldown.
- **Cache-status thresholds configurable.**
- **MispAdminSyncTestWidget — flip to `info` for caching-only
  servers.**
- **Roll StatGrid out** to remaining key/value admin widgets.
- **Audit other legacy widgets for SimpleList → typed-row
  rework** — `MispAdminResourceWidget`, `MispSystemResourceWidget`
  if they still emit raw HTML.
- **MailLogTool gz-tail optimisation (DD-43 deferred)** —
  bounded `gzseek`+backwards-binary-search if a chatty mail
  relay surfaces render-cost complaint.
- **Dark MISP theme work** — when the global MISP dark theme
  initiative starts, the dashboard's small carryover is: (a)
  audit the 8 hardcoded `rgba(...)` rules in `dashboard.default.
  css` (one `rgba(220, 38, 38, 0.10)` at line 544 worth
  token-ifying); (b) ensure the dark overlay redefines
  `--misp-dash-{success,danger,warning,info}-muted`. See
  [[project-misp-dark-theme-sequencing]].
- Pre-existing: **DD-11 ACL-enforced switchable geo widget
  path**; **org/COVID maps palette opt-in**; default-templates
  **live non-admin ACL check**.
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

1. Read `dashboard-prd.md` §15 row DD-45 +
   `dashboard-design-decisions.md` DD-45 (full spec, forks
   resolved, data shape, vendoring approach) + this file. The
   prior DD-31..DD-44 family is still load-bearing for any
   widget work; consult their PRD rows if a sub-task touches a
   pre-existing render kind / convention.
2. Verify instance: `curl -s http://localhost:5007/dashboards
   -o /dev/null -w "%{http_code}\n"` → 302 (or 200 with the cookie
   jar — re-mint `/tmp/cj_stat.txt` via `reference_misp_login_dance`
   if it 302s).
3. **Next session's task: DD-45 Phase C (C1 first).**  Rebuild
   the ECharts vendor bundle with `LinesChart` added (see
   `vendor/VENDORING.md` recipe).  Then C2 (PewPewMap.ctp),
   C3 (buildPewPewOption2D), C4 (thumbPewPewMap glyph), C5
   (visual verification).  One commit per sub-task.  Do NOT
   start Phase D until Phase C is fully green.
4. **DD-45-specific gotchas to carry:**
   * **Tree-shaken ECharts bundle gotcha** (well-trodden):
     adding `LinesChart` to the imports list only is NOT
     enough — `echarts.use([..., LinesChart, ...])` also has
     to register it. Otherwise `type:'lines'` silently
     renders nothing. Same trap as PieChart / GraphChart hit
     in prior sessions per
     [[project-misp-echarts-bundle-treeshaken]].
   * **Cookie jar may need re-minting** — the dev box's
     `/tmp/cj_stat.txt` 302'd this session; for headless-
     Chrome screenshot of a logged-in page, re-mint via the
     login-dance recipe or use the API key + Accept JSON
     for REST endpoints.
   * **Centroid antimeridian handling** — already solved in
     Phase B1.  Centroids landed correctly for Fiji
     (178.6, -17.3) and Russia (99.7, 61.9); the
     `iso-centroids.json` is committed and ready for Phase C3
     to consume on the JS side (although it's already read
     server-side by the widget — Phase C only needs the
     `flows[]` payload as-rendered).
   * **Dev-DB renders thin** — only 1 arc visible (IR → US);
     the visual verification will see a sparse map. Don't
     interpret the sparsity as a bug; production data will be
     richer.  If the verification *needs* more arcs to be
     meaningful, revisit the user-rejected fixture-tagging
     fork (offer via AskUserQuestion).
   * **Aggregate-only posture** — no per-user variation, no
     drilldown URL, cache_scope `'global'`. Matches
     AttributeGeoMapWidget (DD-11). Phase C5 shouldn't add
     per-arc click handlers.
   * **max_arcs cap** — default 500; truncation is value-desc
     so the strongest signals stay visible.
5. **General gotchas to carry:**
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
   widget array, not a template reference);
   (t) **DD-45 lazy-loaded GL bundle** — `echarts-gl.bundle.
   mjs` is a SEPARATE vendor file fetched via dynamic
   `import()` on first 3D render, NOT included in the main
   `echarts.bundle.mjs`. Don't merge them.
6. Do NOT start the merge — the user does that. Watch context;
   refresh this handoff before wrapping.
