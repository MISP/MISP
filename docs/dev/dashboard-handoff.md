# Dashboard v2 — Session handoff (2026-05-28 — DD-37 Usage trim + DD-38 QueueList / worker-widget rework; next: generic MISP health widget)

Twenty-first session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-38).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** This session's two entries are
  the Discussion-cards drop under the `UsageDataWidget` StatGrid block, and
  the MispAdminWorkerWidget rework as its own bullet near the bottom of
  "Post-5.5 — New features".
- `dashboard-design-decisions.md` — DD-01..DD-38 (DD-37 + DD-38 this session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (2 signed commits, `%G?`=U, not merged)

```
4c0ad6947 new QueueList render kind + MispAdminWorkerWidget rework (DD-38)
3f074b362 chg drop the Discussion (Thread/Post) cards from UsageDataWidget (DD-37)
```

Two user-driven trims/reworks. DD-37 was a small scope cut on the UsageData
widget (Discussion cards out, with the supporting Thread/Post code stripped
along with them so the queries don't keep running on every uncached render).
DD-38 was the bigger piece — converting the worker-widget from a SimpleList
3-rows-per-queue list into a single row per queue with two independently-
coloured chips, plus a new render kind to host the shape and a six-glyph SVG
set to label the queues at a glance.

**Live in-browser verification of DD-38 is deferred to the user
(hard-refresh Ctrl-Shift-R — the `?v=185` buster does NOT propagate to ESM
imports).** Everything else verified end-to-end (REST + HTML render, 10/10
threshold unit checks, headless-Chrome screenshot against the full CSS
stack). **The USER does the merge — do NOT open the PR or merge.**

## What landed (reuse these facts)

### DD-38 — `QueueList` render kind + MispAdminWorkerWidget rework (this session's main work)
- **Spec.** One row per background-queue: `[glyph] queue_name [alive/total]
  [pending_jobs]`, with the two chips **independently coloured** so
  "workers alive but stuck" is the at-a-glance signal. Workers chip: `0/0`
  warning (precedence over `x==y`), `x<y` danger, `x==y` info. Jobs chip:
  `<50` info, `50..99` warning, `>=100` danger. **Scheduler omits the jobs
  chip** (workerDiagnostics() doesn't surface a jobCount for it — zero
  would falsely read as "0 pending"; the row renders without the chip).
- **New render kind chosen via fork** (vs SimpleList drop-in / vs StatGrid):
  two right-aligned chips with **different colour classes per row** can't
  ride on SimpleList's single `class` field cleanly (would need raw HTML
  in `value` → defeats DD-34's renderer-owns-escaping); StatGrid cards
  centre the value and can't carry two chips. So new `QueueList.ctp` +
  `.misp-queue-*` CSS + `thumbQueueList` (CLAUDE.md glyph rule).
- **Six per-queue glyphs — inline SVG via new `QueueGlyph::get($name)` tool
  (mirrors `StatGlyph`).** Keys are the `BackgroundJobsTool::VALID_QUEUES`
  names: `default` (stacked boxes), `email` (envelope), `cache`
  (lightning), `prio` (flame — iterated once: an initial teardrop was
  re-sculpted into a curling-tip flame after the first screenshot),
  `update` (circular sync-arrows), `scheduler` (clock). FA classes
  rejected — DD-32 lesson (themes load different FA majors).
- **Data contract.** Typed rows: `header` / `queue` /
  `message`. Queue row carries `{queue, name, glyph, alive, total,
  workers_class, jobs, jobs_class, drilldown}`. **Colour decisions live
  in the widget** (it knows the thresholds + the `worker_array` shape);
  the renderer only maps the allow-listed class name to the matching
  `.misp-queue-chip-<sem>` token pair. Adding a new colour stop = adding
  one CSS rule, no logic in the renderer changes. **This pattern is the
  emerging convention across DD-31/35/38**: widget owns the semantic
  decisions, renderer is dumb / token-driven.
- **Bug fix folded in.** `workerDiagnostics()` mixes per-queue arrays
  with top-level scalar/bool summary keys (`controls`,
  `proc_accessible`, `supervisord_status`) at the same dict level. The
  old widget skipped two by name + would crash on the third under the
  new `array_key_exists('jobCount', $queue)` call (`$queue === true`).
  Fixed by **constraining iteration to `BackgroundJobsTool::VALID_QUEUES`**
  rather than skipping by name — any future top-level summary key the
  diagnostics function adds can't accidentally render as a "queue".
- **Widget changes.** `$render` `SimpleList → QueueList`; default size
  `2×2 → 3×4` (six rows + header don't fit a 2×2); `autoRefreshDelay=5`
  kept (worker freshness is the value here); **no cache** (diagnostics
  call is cheap — supervisor poll + 5 Redis LLENs); site-admin gate
  unchanged. Drilldown → `/servers/serverSettings/workers`.
- **Verified.** `php -l` clean ×3 (widget, glyph, renderer); `node
  --check` clean (render-thumbs.mjs); live REST render = HTTP 200, 6
  queues + header `6 queues · 21 workers alive`; HTML render
  class-histogram = 10 info chips + 1 warning chip (the dev box has an
  empty `scheduler` queue, `0/0` workers → amber); **10/10 threshold
  unit checks pass** (all 4 chip states + `0/0`-over-`x==y` precedence);
  **headless-Chrome screenshot** against the full CSS stack
  (`bootstrap5-custom + mainOvermind + fontawesome7 +
  dashboard.default + dashboard.midnight + overmind theme override` —
  per `feedback_verify_visible_outcome_not_property`) exercising all
  four chip colours + all six glyphs renders cleanly. Temp webroot
  eye-check file deleted post-screenshot. Pure addition; reverse by
  flipping `$render` back to SimpleList + restoring the old handler.

### DD-37 — Drop the Discussion (Thread/Post) cards from `UsageDataWidget`
- **Scope cut from v1.** Discussion threads + Discussion posts cards out
  of UsageData. **Hard removal**, not hide-the-cards: a partial removal
  leaves the four `$threadCount{,Month}`/`$postCount{,Month}` queries
  running every uncached render and the six helper methods as dead code.
  Thread + Post core models untouched (other consumers fine); only the
  widget's coupling to them is gone.
- **What went.** `$validFields` entries + `$statistics` definitions +
  `$Thread` property + `ClassRegistry::init('Thread')` in handler() +
  the four count queries at the top of handler() + the six unreferenced
  `getThreadsCount*` / `getPostsCount*` helpers + the stale
  `//Monthly data is not added` comment that referred to those locals.
  Net: 525→432 lines.
- **Cache interaction (DD-20).** `WidgetCache` keys on
  `<path>:sha256(config)` — payload shape doesn't reach the key, so
  existing entries are obsolete-not-wrong; expire within the 1h TTL.
  Dev-box scan was already empty.
- **Verified.** `php -l` clean; live REST render → HTTP 200, **12 cards**
  (Events, Attributes, Attributes/event, Correlations, Active proposals,
  Users, Users w/ PGP, Organisations, Local organisations, Event creator
  orgs, Average users/org, Advanced authkeys); zero
  `thread|post|discussion` substrings. Deliberate trim. Reverse by
  reverting `3f074b362`.

## Prior-session facts (still true — condensed; reuse)

### Render-kind family (DD-31 / DD-32 / DD-33 / DD-35 / DD-38)
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
- **QueueList** (DD-38, this session) — queue-health rows with two
  independently-coloured chips; typed contract `header`/`queue`/`message`.
  Used by `MispAdminWorkerWidget`.

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
`vendor/VENDORING.md` has the recipe. Current vendored series:
`use([Tooltip, Title, Grid, BarChart, LineChart, MapChart, GeoComponent,
ScatterChart, PieChart, MonitorLineChart-equivalent helpers,
GraphChart])`. **No bundle rebuild this session** — QueueList is pure
HTML/CSS.

### Worker-widget specifics (carried — DD-38)
- `workerDiagnostics()` queue set comes from `BackgroundJobsTool::VALID_QUEUES`
  (`default`, `email`, `cache`, `prio`, `update`, `scheduler`). Top-level
  summary keys (`controls`, `proc_accessible`, `supervisord_status`) co-exist
  and **must not** be treated as queues.
- `$pid => $worker` shape per queue: `{pid, user, alive, correct_user, ok}`.
- `scheduler` queue has no `jobCount` (dispatch-only).

### Render-kind contract conventions (reuse)
- **Widget `handler()`s emit RAW strings**; the renderer `h()`s each
  interpolated scalar exactly once (DD-34 — double-escape caught by a
  dev-DB org name that's literally an XSS probe).
- **Colour decisions live in the widget**; the renderer maps an
  allow-listed class name to a `.misp-*-chip-<sem>` token pair. Don't
  let the widget paint inline styles or pick colour values directly.
- **Drilldown URLs gated by `DashboardURLValidator::validate`** (DD-03)
  — relative or same-host only; renderer drops unsafe URLs and renders
  the row un-linked.
- **Not the renderer's job to scroll** (DD-31): `.misp-widget-body`
  owns padding + `overflow:auto`. Don't set width/height/overflow on
  the inner container.

## Open follow-ups (none blocking)

- **IN-BROWSER VERIFICATION of DD-38 (deferred to the user — hard-refresh
  Ctrl-Shift-R):** confirm on a real admin board — the **MISP Workers**
  widget now renders as a QueueList: six queue rows, glyph + name + two
  chips per row, header summary, scheduler row with no jobs chip.
  Threshold colours can be eye-checked by stopping a worker
  (`supervisorctl stop misp-workers:misp-worker-…`) and reloading — the
  affected queue's workers chip flips info → danger.
- **NEXT SESSION'S TASK (user-flagged):** **a "generic MISP health"
  widget.** The "system"-category space is already populated by
  `MispAdminResourceWidget` (Redis info, PHP memory), `MispSystemResourceWidget`
  (disk threshold, system stats), `MispAdminWorkerWidget` (DD-38), and the
  monitor trio (`CpuLoadMonitorWidget` / `MemoryUsageMonitorWidget` /
  `DiskUsageMonitorWidget`, DD-29/30). `MispStatusWidget` is **user-scoped**
  (`category=status`, NOT admin) and surfaces login + event-creation
  notifications — orthogonal. A "generic health" widget therefore probably
  means the **logical/application-layer rollup** that today's collection
  doesn't surface clearly:
    * **DB** — connection + schema-version-vs-latest (`AppModel::$db_version`
      vs `AppModel::DB_CHANGES`)
    * **Redis** — connection (DB-13 + the sessions DB-0)
    * **Workers** — rolled-up health (count of queues with unhealthy
      workers chip; this widget could even reuse the DD-38 thresholds)
    * **Update job** — pending DB updates / last update result (logs)
    * **Security posture** — Security.advanced_authkeys, Security.salt,
      HTTPS enforcement, GnuPG key configured, …
    * **Recent error log entries** — count of `error_log` rows in the
      last N minutes
  Forks the next session should surface up-front (via AskUserQuestion):
    1. **Scope** — admin-only (full health rollup, mirrors the DD-38
       posture) vs user-scoped (just "is MISP healthy?" green/amber/red
       traffic light)?
    2. **Render kind** — reuse StatGrid (each check = a card, glyph +
       value + status colour) vs reuse QueueList (each check = a row,
       with a single status chip — the contract is close enough to fit
       a check-list) vs a **new `HealthList` render kind** (typed rows
       designed for "checkname / status / detail / drilldown", reusable
       by any future health-rollup widget). My lean: probably QueueList
       reuse (the contract maps cleanly — `queue` rows have a label +
       coloured chip + optional secondary metric) or a thin new render
       kind, depending on how much the user wants distinct affordances.
    3. **Categorisation** — group checks (DB / Redis / Workers / Updates
       / Security) with `gap` row separators, or flat list?
- **UserList polish ideas** (not committed): per-user avatar-chip hue
  variety; real user avatars if MISP ever grows them; server-side
  search if concurrently-online sets get huge; bulk "log out ALL users".
- **Roll StatGrid out** to the remaining key/value admin widgets
  (`MispStatusWidget` — its legacy `(View)` link is already handled by
  StatGrid; the resource widgets). Glyphs per metric as needed.
- **Network diagram polish** (user floated, not committed): distinct
  "this instance" hub icon; edges tinted by status.
- Pre-existing (carried): **DD-11 ACL-enforced switchable geo widget
  path**; **org/COVID maps palette opt-in**; default-templates **live
  non-admin ACL check** (no non-admin API key on the box); **REST
  API-key auth was flaky mid-prior-session** (browser/session auth
  unaffected — used all this session).
- **Phase 6 merge — the USER does this, not us.**

## Live test instance

- URL `http://localhost:5007/dashboards` (302 without a session; 200 with).
  Admin user 1 (`admin@admin.test`, pw `Password12345`), Overmind theme.
  **Browser/session auth works** (login dance recipe in memory
  `reference_misp_login_dance`; cookie jar `/tmp/cj_stat.txt` re-minted
  fresh this session). REST API-key path was flaky in a prior session
  but the session-cookie REST path (Accept: application/json + the
  cookie jar) worked all session for renderWidget probes.
- DB: `mysql -u misp -pPassword1234 misp`. MISP Redis: `redis-cli -n 13`.
  **SESSIONS are in Redis db0** (`PHPREDIS_SESSION:*`) — NOT db13, NOT
  `cake_sessions` table.
- **Workers state on the dev box** (DD-38 verification anchor):
  6 queues / 21 workers alive; queue alives are
  `default=5/5, email=5/5, cache=5/5, prio=5/5, update=1/1,
  scheduler=0/0`. All queues have 0 pending jobs, so live chips are
  all info except `scheduler` (warning, amber). To eye-check the
  warning/danger chip states you need to either stop a worker (flips
  the relevant workers chip danger) or seed the jobs queue.
- State: `db_version=151`; branch `dashboards`. Build dir
  `/tmp/echarts-bundle` reusable for bundle rebuilds.

### Reusable verification recipes
```bash
# Lint
php -l app/Lib/Dashboard/<Widget>.php
node --check app/webroot/js/dashboard/charts/charts.module.mjs
node --check app/webroot/js/dashboard/charts/vendor/echarts.bundle.mjs

# Render a widget body via the web-UI cookie path. JSON path is most
# useful — wrapped envelope you can pipe through jq/python.
# (Cookie jar /tmp/cj_stat.txt — re-mint via reference_misp_login_dance
# if it 302s.)
curl -s -b /tmp/cj_stat.txt -X POST -H "Accept: application/json" \
  "http://localhost:5007/dashboards/renderWidget/test1" \
  --data-urlencode "widget=<WidgetName>" --data-urlencode "config={}"
# NB: cached widgets ($cache_duration) serve a stale payload — purge first:
redis-cli -n 13 --scan --pattern 'misp:<snake>_cache*' | xargs -r redis-cli -n 13 DEL

# Eye-check a render kind visually (NEW renderer-only renderkinds,
# QueueList/UserList/StatGrid). Drop a temp .html into app/webroot
# referencing the FULL CSS stack (bootstrap5-custom + mainOvermind +
# fontawesome7 + dashboard/dashboard.default + dashboard/dashboard.midnight
# + theme/Overmind/css/dashboard/overmind.css) — anything less is a
# false-pass trap (feedback_verify_visible_outcome_not_property). Then:
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
  `render-thumbs.mjs`. This session added `QueueList`.
- **ECharts series-type sibling rule:** a new `series.type` must be
  added to the vendored bundle's `use([...])` + rebuilt, else it
  silently renders nothing (memory
  `project_misp_echarts_bundle_treeshaken`). Not triggered this session
  (QueueList is HTML/CSS only).
- **Widget `handler()`s emit RAW strings; the renderer owns escaping**
  (DD-34). Don't `h()` in the widget when the render kind already
  escapes (every v2 render kind does) — it double-escapes.
- **Colour decisions live in the widget; the renderer is dumb.** The
  widget knows the thresholds; the renderer maps an allow-listed class
  name to a token-pair via CSS. Pattern is consistent across DD-31 /
  DD-32 / DD-38 chips and badges — uphold for any new render kind.
- **`workerDiagnostics()` mixes per-queue arrays with top-level summary
  keys.** Iterate by `BackgroundJobsTool::VALID_QUEUES`, don't iterate
  the returned dict and skip by name (a new top-level key tomorrow will
  silently render as a "queue" otherwise — DD-38 fold-in fix).
- **CSS verification must load the FULL stack** (bootstrap.css + theme
  + dashboard.default.css). Bootstrap's `input[type="search"]` (0,1,1)
  etc. silently beat single-class dashboard rules; assert the
  computed/visible outcome, not the attribute/property you set
  (`feedback_verify_visible_outcome_not_property`).
- User wants **rigorous pushback + genuine forks via AskUserQuestion**,
  and to **re-verify rather than defend** when a premise is questioned.

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 (DD-31..38) + `dashboard-design-decisions.md`
   DD-37 + DD-38 (+ DD-31..36 for the prior sessions' render kinds + the
   mutation/action pattern from DD-36) + this file.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302 (or 200 with the cookie jar — re-mint
   `/tmp/cj_stat.txt` via `reference_misp_login_dance` if it 302s).
3. **Next session's task: generic MISP health widget.** Inventory the
   existing system-category landscape first (it's surprisingly populated
   — see "Open follow-ups" above). Then **surface the three forks
   up-front via AskUserQuestion** before writing code:
   (a) scope = admin rollup vs user-facing traffic-light,
   (b) render kind = reuse QueueList / reuse StatGrid / new `HealthList`,
   (c) grouping = `gap`-separated check sections vs flat list.
   Likely candidates for checks to include: DB connection + schema
   version (`AppModel::$db_version` vs `AppModel::DB_CHANGES`); Redis
   connection (DB-13 + DB-0 sessions); workers rollup (count of queues
   with non-info workers chip — reuses DD-38 thresholds); pending DB
   updates / last update log; security posture (`Security.advanced_authkeys`,
   `Security.salt`, HTTPS, GnuPG); recent error_log entry count.
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
   maps an allow-listed class to a token pair — uphold for the
   health widget's pass/warn/fail states too.
5. Do NOT start the merge — the user does that. Watch context; refresh
   this handoff before wrapping.
