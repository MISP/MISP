# Dashboard v2 — Session handoff (2026-05-27 — widget glow-up: StatGrid KPI cards, sync-test network diagram, logged-in-users widget)

Eighteenth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-34).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** This session's work is under the
  "Post-5.5 — New features" section (StatGrid, network diagram, logged-in
  users), each a top-level bullet.
- `dashboard-design-decisions.md` — DD-01..DD-34 (DD-31/32/33/34 new this
  session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (6 signed commits, all `%G?`=U, none merged)

```
92dfa2349 new LoggedInUsersWidget — active sessions (PHP→Redis engine) (DD-34)
bc407888b chg NetworkGraph nodes as coloured server icons (DD-33 follow-up)
2370c9a03 new sync-test widget as a hub-and-spoke network diagram (DD-33)
8a8f84087 fix StatGrid double + overflowing scrollbar; body owns scrolling
d10dc2756 chg StatGrid cards: per-metric glyph + title tooltip (DD-32)
34da32445 new StatGrid render kind (KPI metric cards) + Usage widget flip (DD-31)
```

All user-driven "make the admin widgets nicer / add a widget" work, post-5.5.
**The USER does the merge — do NOT open the PR or merge.**

## What landed (reuse these facts)

### DD-31 — `StatGrid` render kind (KPI metric cards)
- New `View/Elements/dashboard/Widgets/StatGrid.ctp` + `.misp-stat-*` CSS block
  in `dashboard.default.css` + `thumbStatGrid` glyph. **Same data contract as
  `SimpleList`** (`{title,value,change,drilldown,html_title,type:gap,html}`) →
  a drop-in render-flip with no `handler()` change; reusable by the other
  key/value admin widgets next. Adds value formatting (thousands grouping,
  1-decimal non-ints, string pass-through). `UsageDataWidget` flipped
  `SimpleList→StatGrid`, default size `2×5→4×6`. **User chose the card-grid
  treatment over compact-rows via a previews fork.**
- **Scroll fix (commit `8a8f84087`):** the grid must NOT set
  `width/height:100% + padding + overflow` — `.misp-widget-body` already owns
  padding + the single `overflow:auto` (no global `box-sizing:border-box`).
  Grid is pure layout now; `minmax(min(120px,100%),1fr)` so a narrow resize
  can't force a horizontal scroll. **Pattern for any future body-filling
  render kind: let `.misp-widget-body` own scrolling.**

### DD-32 — StatGrid labels → per-metric glyph + `title` tooltip
- Narrow cards truncated the text label. StatGrid `icon` contract key (named
  glyph) → renders an inline-SVG glyph, full field name moves to the card
  `title=` tooltip; no-icon rows keep the text label (drop-in unaffected).
- **Inline SVG, NOT FontAwesome — load-bearing finding:** the dashboard
  layouts load DIFFERENT FA majors per theme (Overmind = `fontawesome7.min`,
  base/UiBeta = `font-awesome` FA5/6), so FA classes are unreliable. New
  `app/Lib/Dashboard/Tools/StatGlyph::get($name)` returns a `currentColor`
  24×24 SVG (14 glyphs + `''` fallback). `UsageDataWidget` names a glyph per
  metric.

### DD-33 — sync-test widget as a hub-and-spoke network diagram
- `MispAdminSyncTestWidget` flips `SimpleList→NetworkGraph` (new render kind,
  ECharts `graph` series). Handler reshapes the same `runConnectionTest()`
  loop into `{nodes, links}`: a `self` hub (`MISP.baseurl`/`MISP.org`) + one
  node per sync server; links `self→server`. **3 node states kept** (fork:
  user said green/red, but `warn`=reachable-but-missing-perm is real signal):
  `ok` green / `warn` amber / `error` red / `self` accent, via semantic tokens.
- **Fixed hub-and-spoke `layout:'none'`** (deterministic, no reshuffle on
  refresh); links by node **index** (dup/empty names safe); generous series
  margins (`20/20/16/22%`) so `bottom`-labels don't clip; `roam:true`; tooltip
  = name/url/message (the outage reason). `autoRefreshDelay=false` (connection
  tests hit the network per render). Size `3×2→4×5`. New `buildNetworkOption`
  in `charts.module.mjs` (registered `network:`) + `thumbNetworkGraph` glyph.
- **Node styling (`bc407888b`):** nodes are **coloured server-rack icons**
  (white LEDs + vent bars) via ECharts `image://` SVG data-URI symbols
  (`serverSymbol(colour)`), built from the resolved theme token at render time
  (theme-aware; 4 symbols reused). `path://` rejected (single-colour fill, no
  white detail).
- **⚠️ BUNDLE REBUILD (sibling tree-shaking rule):** `graph` is a new ECharts
  series type → **`GraphChart` added to the vendored bundle's `use([...])` and
  rebuilt** (666→702 KB raw / 221→239 KB gz), else `type:'graph'` renders
  nothing. VENDORING.md table+recipe updated. `/tmp/echarts-bundle`
  (echarts@6.0.0 + esbuild@0.24.0) is the reusable build dir.

### DD-34 — `LoggedInUsersWidget` (new from scratch)
- Lists users with a live session + per-user session count, drilldown to
  `/admin/users/view/<id>`. Site-admin gated; `autoRefreshDelay=60`; SimpleList
  render (no new kind). Pure addition (auto-discovered).
- **VERIFIED FROM SOURCE: no engine-agnostic session enumeration exists** —
  `CakeSessionHandlerInterface` / `CakeSession` / PHP `SessionHandlerInterface`
  are all per-id (`read/write/destroy($id)`, no `list()`); memcached/apcu can't
  enumerate. So scope is **PHP→Redis only** (`session.save_handler==='redis'`);
  other engines → an "unsupported engine" row. (Engine-agnostic alternative
  would be MISP's own `users.current_login`/`last_api_access` — "recently
  active", not "live session".)
- Mechanism: parse `session.save_path`, **direct `new Redis()`** (NOT
  `RedisTool` — that targets MISP's DB-13; sessions are in the php save_path's
  redis db0), `SCAN PHPREDIS_SESSION:*` (cap 20k), extract `Auth.User.id` from
  each PHP-serialised blob (`Auth|a:1:{s:4:"User";a:N:{s:2:"id";…`, regex; id
  only — no token), tally per user, `contain Organisation.name, Role.name`.
- **Escaping convention (re)confirmed:** widget `handler()`s emit **raw**
  strings; the SimpleList renderer `h()`s title/value once. Pre-escaping in the
  widget double-escapes (caught by a dev-DB org name that's literally an XSS
  probe `FOO"><img src=x onerror=…>` — rendered inert either way, but garbled
  when double-escaped).

## Open follow-ups (none blocking)

- **IN-BROWSER VERIFICATION (deferred to user — hard-refresh Ctrl-Shift-R; the
  `?v=185` buster does NOT propagate to ESM imports, so a normal reload keeps
  the cached old bundle/JS):** confirm on a real board — StatGrid Usage cards
  (glyphs + tooltips, no scrollbars); the sync-test **network diagram** (server
  icons, hover tooltip shows url+reason, drag/zoom); the **logged-in-users**
  list. All three rendered green via headless Chrome this session, but a live
  board pass is the gold standard.
- **Prettify `LoggedInUsersWidget`?** It's a plain SimpleList; could become a
  StatGrid-style or avatar treatment if wanted (user deferred).
- **Roll StatGrid out to the other key/value admin widgets** (`MispStatusWidget`
  — note its legacy `html` `(View)` link is already handled by StatGrid; the
  resource widgets). Glyphs per metric as needed.
- **Network diagram polish ideas** (user floated, not committed): distinct
  "this instance" hub icon; edges tinted by status.
- Pre-existing (carried): **DD-11 ACL-enforced switchable geo widget path**;
  **org/COVID maps palette opt-in**; default-templates **live non-admin ACL
  check** (no non-admin API key on the box); **REST API-key auth was flaky
  mid-prior-session** (browser/session auth unaffected — used all this session).
- **Phase 6 merge — the USER does this, not us.**

## Live test instance

- URL `http://localhost:5007/dashboards` (302 without a session; 200 with).
  Admin user 1 (`admin@admin.test`, pw `Password12345`), Overmind theme.
  **Browser/session auth works** (login dance recipe in memory
  `reference_misp_login_dance`; cookie jar `/tmp/cj_stat.txt` was used all
  session). REST API-key path was flaky in a prior session.
- DB: `mysql -u misp -pPassword1234 misp`. MISP Redis: `redis-cli -n 13`.
  **SESSIONS are in Redis db0** (`PHPREDIS_SESSION:*`, php redis save_handler,
  `session.save_path=tcp://localhost:6379`) — NOT db13, NOT the `cake_sessions`
  table (empty; `Session.defaults='php'`). ~276 session keys, 5 logged-in users
  during testing.
- State: `db_version=151`; branch `dashboards`. Build dir `/tmp/echarts-bundle`
  reusable for bundle rebuilds.

### Reusable verification recipes
```bash
# Lint
php -l app/Lib/Dashboard/<Widget>.php
node --check app/webroot/js/dashboard/charts/charts.module.mjs
node --check app/webroot/js/dashboard/charts/vendor/echarts.bundle.mjs

# Render a widget body via the web-UI path (needs the session cookie jar;
# see reference_misp_login_dance to (re)mint /tmp/cj_stat.txt):
curl -s -b /tmp/cj_stat.txt -X POST \
  "http://localhost:5007/dashboards/renderWidget/test1" \
  --data-urlencode "widget=<WidgetName>" --data-urlencode "config={}"
# NB: cached widgets (cache_duration) serve a stale payload — purge first:
redis-cli -n 13 --scan --pattern 'misp:<snake>_cache*' | xargs -r redis-cli -n 13 DEL

# Visually verify a JS/chart render (ESM doesn't load over file:// — serve
# over HTTP): drop a test .html into app/webroot referencing
# /js/dashboard/charts/charts.module.mjs + /css/dashboard/dashboard.default.css,
# then `google-chrome --headless=new --screenshot=… --virtual-time-budget=8000
# http://localhost:5007/_test.html` and Read the PNG. DELETE the temp webroot
# file after (it's publicly served).

# Rebuild the echarts bundle (add a series type): edit /tmp/echarts-bundle/
# entry.mjs use([...]), esbuild per vendor/VENDORING.md, cp the .mjs + LEGAL
# over (LEGAL dest name is echarts.bundle.LEGAL.txt).

# Inspect live sessions (db0):
redis-cli -n 0 --scan --pattern 'PHPREDIS_SESSION:*' | head
```

## Convention reminders

- **Context budget:** keep within the first ~20% normally; user OK'd up to 40%
  for UI work this session (`feedback_context_threshold_warning`).
- **Commit per progress-tracker task; never `git add -A`; explicit `git add` +
  `git status --short`; sign (`%G?`=U).** GPG warm all session.
- **Edit/Write flips a file's group to `iglocska:iglocska`** — `chgrp www-data`
  every edited web-served/app file afterward (incl. docs).
- **Record meaningful decisions as DD-NN + a PRD §15 row.** Refinements get a
  NEW DD (DD-32 refined DD-31's labels; DD-33 carried a same-session node-style
  follow-up as a sub-note, not a new DD — judgement call for small polish).
- **Render-kind glyph rule** (CLAUDE.md): new `$render` → glyph in
  `render-thumbs.mjs`. This session added `StatGrid` + `NetworkGraph`.
- **ECharts series-type sibling rule:** a new `series.type` must be added to the
  vendored bundle's `use([...])` + rebuilt, else it silently renders nothing
  (memory `project_misp_echarts_bundle_treeshaken`). This session added
  `GraphChart`. (Both rules are good CLAUDE.md-addition candidates next to the
  glyph rule — not edited unprompted.)
- **Widget `handler()`s emit RAW strings; the renderer owns escaping** (DD-34).
  Don't `h()` in the widget when the render kind already escapes (SimpleList
  does) — it double-escapes.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**, and to
  **re-verify rather than defend** when a premise is questioned (this session:
  the "no engine-agnostic session enumeration" check was a re-verify-the-premise
  win → narrowed DD-34's scope).

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 (DD-31..34) + `dashboard-design-decisions.md`
   DD-31/32/33/34 + this file.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null -w
   "%{http_code}\n"` → 302 (or 200 with the cookie jar).
3. **No task is mandated.** If you have browser access, do the deferred
   in-browser pass of the three new widgets first. Otherwise the user may pick a
   follow-up above, a new widget/feature, or the merge.
4. **Gotchas to carry:** (a) new ECharts series type → rebuild the bundle's
   `use([...])`; (b) ESM imports ignore the `?v=185` buster → hard-refresh after
   a vendored-bundle/JS change; (c) sessions live in Redis **db0**
   (`PHPREDIS_SESSION:*`), MISP's own data in **db13**; (d) widget `handler()`s
   emit raw strings — the renderer escapes; (e) a body-filling render kind must
   let `.misp-widget-body` own scrolling (don't set width/height/overflow on the
   inner container); (f) Edit tool flips file group — `chgrp www-data` after
   edits.
5. Do NOT start the merge — the user does that. Watch context; refresh this
   handoff before wrapping.
