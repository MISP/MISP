# Dashboard v2 — Session handoff (2026-05-27 — phantom-FK fix + live system-monitor widgets (CPU/mem/disk) with Redis-backed history)

Seventeenth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-30).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** Post-5.5 work continues in the
  "New widget types" and "New features" sections; this session's widgets are
  sub-bullets under the new "Live system-monitor widgets" block.
- `dashboard-design-decisions.md` — DD-01..DD-30 (DD-28/29/30 new this
  session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (6 signed commits, all `%G?`=U, none merged)

```
df45a09bf fix add PieChart to the vendored ECharts bundle so the disk pie renders (DD-29)
4194b0124 chg persist monitor history server-side in Redis; pre-populate the graph from it (DD-30)
38c9f721e new add admin memory-usage streaming monitor widget (DD-29)
5993390c6 new add admin CPU-load streaming monitor widget + the monitor render kind (DD-29)
c0002c881 new add admin disk-usage pie monitor widget + the pie render kind (DD-29)
596f423d1 fix drop phantom Dashboard belongsTo Organisation/Role FKs (DD-28)
```

Two user threads: a **bounded latent-bug fix** (DD-28), then a **new feature**
— three admin-gated live system-monitor widgets (DD-29) with a follow-up to
persist their history in Redis (DD-30), plus a bundle fix surfaced by the user
testing the disk pie in-browser.

**The USER does the merge — do NOT open the PR or merge.**

## What landed (reuse these facts)

### DD-28 — dropped the `Dashboard` model's phantom `belongsTo Organisation`/`Role`
- The model declared `belongsTo Organisation` (`foreignKey 'org_id'`) **and**
  `Role` (default `'role_id'`), but the table has **neither** column
  (`restrict_to_org_id` / `restrict_to_role_id`). `Mysql::update()`/`delete()`
  auto-join *every* belongsTo via `_getJoins()`, so `updateAll`/`deleteAll`
  crashed (`Unknown column 'Dashboard.org_id' in 'ON'`). Latent: `find` is
  always `recursive=-1`, single-id `save`/`delete` don't join.
- Repo-wide check confirmed **nothing reads** either assoc (only `User` is
  consumed, the `contain` at `DashboardsController.php:1064`). **User chose
  drop** (over repoint / repoint+rename). Also dropped the dead
  `org_id`/`role_id` `validate` rules.
- **Supersedes DD-27's implementation** (behaviour unchanged):
  `__unsetPreviousDefault()` reverted from the find-loop-`saveField` +
  `$this->id` dance to a single `updateAll` (the phantom join was its only
  reason to exist). DD-25 prune + DD-26 fallback comments truthed-up.
- Verified live: joined `updateAll`/`deleteAll` no longer crash (SQL joins only
  `users`); demote-all self-restored `{13:Analyst}`→0→`{13:Analyst}`.

### DD-29 — live system-monitor widgets (CPU / memory / disk)
A livelier, **site-admin-gated** alternative to `MispSystemResourceWidget`
(`checkPermissions` → `perm_site_admin`; auto-discovered, no registry). Three
widgets, **one core-JS touch the user signed off via plan approval**:
- **DiskUsageMonitorWidget** — new **`pie`** render kind. `$render='PieChart'`,
  `autoRefreshDelay=10` (snapshot on the standard scheduler refresh). handler
  returns Used/Free bytes + `used_pct` + `threshold`. New `PieChart.ctp` +
  `buildPieOption` in `charts.module.mjs` (donut, centre %, danger-token
  recolour over threshold) + `formatBytes` + `thumbPieChart` glyph.
- **CpuLoadMonitorWidget** / **MemoryUsageMonitorWidget** — new **`monitor`**
  streaming render kind. `$render='MonitorLineChart'`, **`autoRefreshDelay=false`**
  (the board scheduler must NOT re-render these — that would wipe the chart).
  CPU = 1-min load avg normalized to %-of-cores (`sys_getloadavg()[0]/cores*100`,
  cores from `/proc/cpuinfo`; `yMax=100` is a *floor* that expands past 100% on
  overload — user's metric choice over `/proc/stat`-delta CPU%). Memory = used %
  via `(1-MemAvailable/MemTotal)*100` (truer than the old widget's `MemFree`).
- **The streaming mechanism (key reuse):** the chart polls its **own** handler
  via the existing `renderWidget` **`exportjson`** contract (the same call
  `Board._exportWidget` makes: `POST {renderUrl}/{id}/exportjson:1` body
  `{widget,config}`) — **no new endpoint/route/ACL**. Uncached because the
  widgets don't declare `$cache_duration` (the `WidgetCache::remember` wrapper
  is a pass-through). New `monitor-chart.mjs` owns the poll loop; `charts.module
  .mjs` got only a `kind==='monitor'` dispatch + a `teardown()` branch in
  `disposeChart` (clears the interval — no orphan timers on remove/refresh).
  Poll base URL read from the board root's `data-misp-board-renderwidget-url`.

### DD-30 — server-side Redis history for the monitor lines (refines DD-29)
- DD-29's buffer was **client-only** (JS closure) → empty on reload/refresh.
  Now the buffer lives in **Redis**; the client just renders whatever series
  the handler returns. In-place streaming kept (no flicker), but it repaints a
  **persisted** series → survives reload/refresh, shared across viewing admins.
  (User picked this over the simpler scheduler-redraw, which would flicker.)
- New `app/Lib/Dashboard/Tools/MonitorSeriesStore::record($metric,$value,$window,
  $interval)`: one **sorted set per metric** (`misp:dashboard_monitor:<metric>`,
  score=ts, member=`"ts:value"`); `zAdd` + `zRemRangeByScore` to the window +
  `expire` at window+interval (idle metrics self-clean); cross-viewer **dedup**
  skips an append younger than `interval/2`; Redis-down → single-point series.
  Reuses `RedisTool::init()` (DB 13). **Global per-metric key** (host-wide facts).
- Contract change: CPU/memory `handler()` now return **`history`**
  (`[[ts,value],…]`) not a single `value`; `MonitorLineChart.ctp` carries
  `history`+`interval_sec`; `monitor-chart.mjs` `render(history)` formats labels
  from the **server** ts (stable across reloads).

### Bundle fix — PieChart was missing from the vendored ECharts bundle
- **User-surfaced:** the disk widget showed the centre `% used` number but no
  pie slices. Root cause: the tree-shaken `echarts.bundle.mjs` (DD-02/DD-07)
  only `use()`d `BarChart, LineChart, MapChart` → a `type:'pie'` series renders
  **nothing** (the `TitleComponent` still drew the number). Rebuilt per the
  VENDORING.md recipe with `PieChart` added (echarts@6.0.0, esbuild@0.24.0;
  649→666 KB raw). VENDORING.md table+recipe updated.
- ⚠️ **GENERAL GOTCHA (see memory `project_misp_echarts_bundle_treeshaken`):**
  any NEW ECharts series type (pie done; future: scatter, gauge, heatmap, …)
  must be added to the bundle's `echarts.use([...])` + rebuilt, or it silently
  renders nothing. This is a sibling rule to the render-thumbs glyph rule.

## Open follow-ups (none blocking)

- **IN-BROWSER VERIFICATION (deferred to user — do first next session if you
  have browser access):** hard-refresh (Ctrl-Shift-R — the `?v=185` buster does
  NOT propagate to ESM module imports, so a normal reload keeps the cached old
  bundle) and confirm: (1) disk **pie renders**; (2) CPU/memory lines
  **accumulate** over ~60s and now **survive a reload** (Redis-backed); (3) the
  CPU line moves slowly (1-min load avg is smoothed — expected).
- **Dev-box API-key auth hiccup:** the REST/curl path (`Authorization: <key>`)
  started returning "Authentication failed" mid-session (~10:17). Key id 35
  (user 1) is valid+unexpired in the DB, user 1 enabled, no brute-force key in
  Redis db13 — likely a REST auth throttle from the burst of test calls (or an
  `allowed_ips` constraint). **Browser/session auth is unaffected** (the board
  uses the session cookie). If you need the REST path for verification next
  session and it's still blocked, investigate the throttle / re-mint a key.
- Pre-existing (carried): **DD-11 ACL-enforced switchable geo widget path**;
  **org/COVID maps palette opt-in**; default-templates **live non-admin ACL
  check** (no non-admin API key on the box). DD-28 closed the phantom-`org_id`
  discovered-work item.
- More new widget types / features — user may enumerate.
- **Phase 6 merge — the USER does this, not us.**

## Live test instance

- URL `http://localhost:5007/dashboards` (302 without a session). Admin user 1
  (`admin@admin.test`, pw `Password12345`), Overmind theme. Admin API key
  `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC` (id 35) — **REST auth was failing
  at session end; browser login works**.
- DB: `mysql -u misp -pPassword1234 misp`. Redis: `redis-cli -n 13`.
- State: `db_version=151`; built-ins #12 Administrator / #13 Analyst / #14
  Community (`user_id=0`); **#13 Analyst is the global default**. Monitor Redis
  keys `misp:dashboard_monitor:{cpu,memory}` were created during testing (they
  TTL out). The echarts-bundle build dir `/tmp/echarts-bundle` (echarts@6.0.0 +
  esbuild@0.24.0 installed) is reusable for future bundle rebuilds.

### Reusable verification recipes
```bash
# Lint sweep
php -l app/Lib/Dashboard/<Widget>.php
node --check app/webroot/js/dashboard/charts/monitor-chart.mjs
# Monitor store, direct (bypasses HTTP/auth) — throwaway shell calling
# (new CpuLoadMonitorWidget())->handler($adminUser, ['window'=>60,'interval'=>2])
# in a loop; assert history grows + dedups. Inspect:
redis-cli -n 13 ZRANGE misp:dashboard_monitor:cpu 0 -1 WITHSCORES
redis-cli -n 13 TTL misp:dashboard_monitor:cpu
# REST handler (when API auth works): bare handler output as JSON
curl -s -X POST "http://localhost:5007/dashboards/renderWidget/w1/exportjson:1" \
  -H "Authorization: <key>" -H "Accept: application/json" \
  --data-urlencode "widget=DiskUsageMonitorWidget" --data-urlencode "config={}"
# Rebuild the echarts bundle (add a series type): edit entry.mjs use([...]),
# esbuild per app/webroot/js/dashboard/charts/vendor/VENDORING.md, cp over.
```

## Convention reminders

- **Context budget: keep within the first ~20%** normally; this session the
  user exceptionally allowed 40% (`feedback_context_threshold_warning`).
- **Commit per progress-tracker task; never `git add -A`; explicit `git add` +
  `git status --short`; sign (`%G?`=U).** GPG warm all session.
- **Edit/Write flips a file's group to `iglocska:iglocska`** — `chgrp www-data`
  every edited web-served/app file afterward.
- **Record meaningful decisions as DD-NN + a PRD §15 row.** Refinements get a
  NEW DD that supersedes the old aspect (DD-28 superseded DD-27's impl; DD-30
  refines DD-29) — never an in-place edit of the superseded DD.
- **Render-kind glyph rule** (CLAUDE.md): new `$render` → glyph in
  `render-thumbs.mjs`. This session added `PieChart` + `MonitorLineChart`.
- **NEW sibling rule — ECharts series types:** a new `series.type` must be added
  to the vendored bundle's `use([...])` + rebuilt, else it silently renders
  nothing (memory `project_misp_echarts_bundle_treeshaken`). Candidate for a
  CLAUDE.md addition next to the glyph rule (didn't edit CLAUDE.md unprompted).
- User wants **rigorous pushback + genuine forks via AskUserQuestion**, and to
  **re-verify rather than defend** when a premise is questioned.

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 (DD-28..30) + `dashboard-design-decisions.md`
   DD-28/29/30 + this file.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null -w
   "%{http_code}\n"` → 302.
3. **No task is mandated.** If you have browser access, do the deferred
   in-browser verification of the three monitor widgets first (pie renders,
   lines accumulate + survive reload, after a hard-refresh). Otherwise the user
   may pick a follow-up above, a new widget/feature, or the merge.
4. **Gotchas to carry:** (a) new ECharts series type → rebuild the bundle's
   `use([...])`; (b) ESM imports ignore the `?v=185` buster → hard-refresh after
   a vendored-bundle change; (c) monitor widgets are `autoRefreshDelay=false` +
   self-poll via `exportjson` + Redis buffer (`MonitorSeriesStore`); (d)
   Dashboard `updateAll`/`deleteAll` now work (DD-28); (e) Edit tool flips file
   group — `chgrp www-data` after edits.
5. Do NOT start the merge — the user does that. Watch context; refresh this
   handoff before wrapping.
