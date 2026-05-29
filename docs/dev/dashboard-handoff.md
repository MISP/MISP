# Dashboard v2 — Session handoff (2026-05-29 — DD-47 CLOSED: globe.gl real-3D "Globe (3D)" pew-pew mode ships + verified; DD-48: widget renamed AttackFlowMap → PewPewMap; DD-49: selectable globe skins night/day/dark)

Twenty-eighth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..**DD-48**). DD-48 (widget rename) is the newest row.
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** Post-5.5 "New features"
  carried DD-43, DD-44, DD-45, **DD-47 — all now CLOSED.** DD-47's
  G1..G7 are all ticked.
- `dashboard-design-decisions.md` — DD-01..**DD-48**. DD-47 status is
  now "IMPLEMENTED + verified, CLOSED"; DD-48 records the rename.

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (12 signed commits, `%G?`=U, not merged)

```
9cb63877c chg DD-47 — mark CLOSED + implemented in design-decisions status
8fa051f36 chg DD-47 G7 + CLOSE — tick progress tracker
7da1df6a0 chg DD-47 G3-G6 — tick progress tracker
a87f48b6c new DD-47 G5 — webgl-globe mode enum + labels
8bf91d8bf new DD-47 G4 — async dispatch for webgl-globe in initChart
15b7c886c new DD-47 G3 — initWebglGlobe glue (globe.gl arcs + rings)
a531ef2bd chg DD-47 G2 — tick progress tracker
2e9ffe919 new DD-47 G2 — vendor night-lights earth texture (earth-night-2k.jpg)
29d822ad8 chg DD-48 — record widget rename (PRD §15 + design-decisions)
84ad96d19 chg DD-48 — rename AttackFlowMapWidget → PewPewMapWidget
0903cae05 chg DD-47 G1 — tick progress tracker
d6e572b8d new DD-47 G1 — lazy globe.bundle.mjs (globe.gl + three, tree-shaken)
```

**Two headlines:** (1) the pew-pew widget now ships a **third, opt-in
render mode** — a real WebGL textured globe (globe.gl/Three.js),
lazy-loaded; (2) the widget was **renamed to "Pew-pew map"** everywhere
(class/file/title), per the user — the name is the joke (a jab at the
Norse attack map). All three modes (2D flat / lightweight orthographic /
real-3D WebGL) share ONE `flows[]` payload + ONE unchanged server side.

## DD-48 — the rename (do not re-litigate)

`AttackFlowMapWidget` → **`PewPewMapWidget`** / `$title` "Attack flow
map" → **"Pew-pew map"**. The render kind (`PewPewMap.ctp`,
`$render='PewPewMap'`) + JS registry (`pewpew`, `buildPewPewOption`,
`thumbPewPewMap`) were ALREADY pew-pew; only the class, file, `$title`,
`$cache_path` (`misp:attack_flow_map_cache` → `misp:pew_pew_map_cache`)
and the test lagged. **Load-bearing safety point:** a widget's class
name is the identifier stored in saved dashboard blobs — a hard rename
orphans saved instances. Safe HERE only because the branch is unmerged;
the one dev-box instance (`user_settings` id 34, widget `w_6`) was
SQL-migrated + caches purged. **If this ships and is later renamed, use
a back-compat alias, not a hard rename.** See DD-48.

## DD-47 — the WebGL globe (reuse these facts)

### The opt-in third mode
`mode='webgl-globe'` → friendly label **"Globe (3D)"**. Enum is now
`['2d','3d-globe','webgl-globe']` with `enum_labels`
`{2d:'2D map', 3d-globe:'Globe (lightweight)', webgl-globe:'Globe (3D)'}`.
Default stays `'2d'`. **Gotcha (caught + fixed):** `resolveMode()`'s
PHP whitelist must track the enum — a value missing there silently
degrades to `'2d'`.

### `globe.bundle.mjs` — the lazy vendor bundle (G1)
- `app/webroot/js/dashboard/charts/vendor/globe.bundle.mjs`: esbuild
  tree-shaken ESM of **globe.gl@2.46.1** (three@0.184.0 /
  three-globe@2.45.2). **1.76 MB raw / 508 KB gzipped.** Exports the
  `Globe` factory as `default` + named. **NOT** in `echarts.bundle.mjs`.
- 42 bundled packages, all permissive (MIT/ISC/Apache-2.0/Unlicense) —
  AGPL-OK, no new copyleft review (DD-07). Ships `globe.bundle.LEGAL.txt`
  (esbuild banners) + **one consolidated `globe.bundle.LICENSES.txt`**
  (every package's full license) rather than 42 sidecars. VENDORING.md
  has the build recipe + a license-walk regen script + a
  copyleft-on-bump warning.

### `earth-night-2k.jpg` — the texture (G2, user-picked: night lights)
- NASA Black Marble city-lights night image (public domain), from
  three-globe's MIT example dir, downscaled 4096×2048 → **2048×1024 q85
  = 205 KB**. No license sidecar (NASA PD). Night surface deliberately:
  arcs pop, pre-aligns with the incoming dark theme, leans into the
  Norse riff. Verified live: 200 / image/jpeg.

### `charts.module.mjs` — `initWebglGlobe` glue (G3/G4/G6)
- **`initWebglGlobe(hostEl, payload)`** — globe.gl owns its own WebGL
  canvas, so it is NOT an ECharts builder. Maps `flows[]` →
  `arcsData` (value→stroke log scale, animated dash tracer) + `ringsData`
  (one pulsing ring per victim centroid, sized by incoming value), sets
  `globeImageUrl` + atmosphere + a North-Atlantic `pointOfView`
  (`{lat:30,lng:-10,altitude:2.2}`).
- **The integration pattern (REUSE):** returns a **`{ teardown }`
  handle** — the SAME shape `initMonitorChart` uses, which
  `disposeChart()` already supports (`typeof live.teardown ===
  'function'`). So dispose needed zero new code. teardown disconnects
  the ResizeObserver + the theme MutationObserver, calls globe.gl's
  `_destructor()`, and empties the host.
- **Non-blocking (deviation from G4's "await" wording, deliberate):**
  the handle returns SYNC; the lazy `import()` resolves in the
  background behind a self-contained inline loading placeholder. So a
  multi-widget board doesn't stall `Promise.all(initChart)` on the
  508 KB download. `teardown()` flips a `disposed` flag so a dispose
  racing a slow import is honoured. Still satisfies DD-47 approach-pt-3
  (loading placeholder).
- **`loadGlobeBundle()`** memoises the import promise → a second
  webgl-globe widget reuses the first fetch (+ browser module cache).
- **Dispatch (G4):** in `initChart`, a branch
  `if (kind==='pewpew' && payload.mode==='webgl-globe')` BEFORE the
  ECharts path + `ensureWorldMap()` (the globe uses the texture, not the
  echarts world map). The 2d / 3d-globe ECharts modes are untouched.
- **Theming bridge (G6, folded into G3):** globe.gl won't read
  `--misp-dash-*`. `applyColours()` reads `--misp-dash-danger` (arc
  gradient via `withAlpha()` hex/rgb→rgba) + `--misp-dash-warning` (ring
  fade) + atmosphere; a `MutationObserver` on `<html data-theme>`
  re-invokes it on light↔dark with NO re-init. `withAlpha()` is a new
  module-scope helper (handles `#rgb`/`#rrggbb`/`rgb()`/`rgba()`).

### Verification (G7 — no real-browser fallback needed)
Headless Chrome 141 + `--enable-unsafe-swiftshader
--use-angle=swiftshader` rendered the globe cleanly. Temp page (full CSS
stack, synthetic 6-arc payload) under webroot, screenshotted + DOM
probed, then deleted (302 confirms). **Light + dark** both render the
night globe with red danger arcs + a danger atmosphere glow; midnight
retones to #f87171 + dark card. **DOM probe proved lazy-only-on-3D:**
`webgl-globe` → `globeBundleLoaded:true, textureLoaded:true, canvas
616×420`; `2d` → both `false`. Import-cache on 2nd render guaranteed by
the memoised promise.

## DD-49 — globe skins (reuse these facts)

The `webgl-globe` mode has a per-widget **`skin`** config (the night
texture is dark by design; the user wanted a daytime option):
**`night`** (default, city lights), **`day`** (NASA Blue Marble), **`dark`**
(minimal grey). Front-end only — a different `globeImageUrl`; `flows[]`
now carries a `skin` hint; the 2d/3d-globe modes ignore it. **Only the
selected skin's image downloads** (lazy, per instance). **A skin must be
in 3 places or it degrades to `night`:** the `$schema` `skin` enum +
`resolveSkin()` whitelist (`PewPewMapWidget.php`) AND the
`GLOBE_TEXTURES` map (`charts.module.mjs`). Textures: NASA PD,
2048×1024, `vendor/earth-{night,day,dark}-2k.jpg` (205/279/81 KB).
Arc/ring/atmosphere stay token-driven across all skins. Verified
night/day/dark live + headless-Chrome screenshots of day + dark.
Adding a skin = vendor an image + 3 registrations (VENDORING.md recipe).
NB: the widget's `$cache_duration` is currently **`false`** (a user
working-tree change, preserved) — caching is OFF, so every render
recomputes with the correct mode/skin.

## DD-45 family — render-kind & widget facts (still load-bearing)

### Pew-pew widget shape (DD-45/46/47/48)
- **`PewPewMapWidget`** (renamed DD-48) → `$render='PewPewMap'`,
  `$category='events'`, `$cache_duration=3600`,
  `$cache_path='misp:pew_pew_map_cache'`, `$cache_scope='global'`, open
  to all users (aggregate-only, mirrors `AttributeGeoMapWidget` DD-11),
  default 6×5.
- Config params: `time_window`, `mode` (`2d`|`3d-globe`|`webgl-globe`,
  default `2d`), `max_arcs` (default 500).
- Data: one arc per `(event, threat-actor cluster's country, victim
  country-galaxy ISO)` triple; aggregated by `(src_iso, dst_iso)`;
  centroids server-side via `iso-centroids.json`.
- **Dev-DB reality**: ONE visible arc (IR→US, event 1421). Production is
  richer; the dev box is thin by nature, NOT a bug. For a richer demo
  use a synthetic multi-arc test page (G7/C5/D5 recipe).
- `.ctp` is a dumb shim emitting `data-misp-chart="pewpew"` +
  `{mode, flows[]}`; ALL mode dispatch lives in `charts.module.mjs`
  (2d/3d-globe in `buildPewPewOption`; webgl-globe in `initWebglGlobe`).

### Prior render-kind family (DD-31..DD-43) — unchanged, still live
StatGrid, NetworkGraph, UserList, QueueList, HealthList, PewPewMap. Every
new `$render` needs a glyph in `render-thumbs.mjs` (CLAUDE.md).
`thumbPewPewMap` already shipped (Phase C); webgl-globe is the SAME
render kind (`PewPewMap`), so no new glyph was needed.

## Open follow-ups (active + carried)

### NEXT — the only tracked phase left is Phase 6 (merge to `develop`) — the USER does this, not us.
The dashboard feature set is complete: 2D map, lightweight orthographic
globe, and real WebGL globe all ship. Carried polish below is optional.

### Globe (3D) polish (DD-47, deferred — all optional)
- **Auto-rotate** (`globe.controls().autoRotate = true`) — trivial; left
  off in v1 for screenshot stability (same call DD-46 deferred for the
  orthographic mode). A slow spin would suit the playful vibe.
- **Ring visibility** — rings pulse; tune `ringMaxRadius` /
  `ringRepeatPeriod` / a brighter warning if they read too subtle.
- **In-browser confirm of the "Globe (3D)" / "Globe (lightweight)"
  `<select>` labels** in the real configure modal (data path verified;
  `enum_labels` passthrough established DD-46 D4).
- Optional **starfield/space backdrop** instead of the transparent
  canvas — premium but heavier; transparent blends with both themes.

### Carried (not active)
- **In-browser verification of DD-43 + DD-44** (hard-refresh): rotated
  mail-log scan; Administrator template (14 widgets) in the gallery.
- **Other shipped templates** — `analyst/` + `community/template.json`
  may be due a v2-era refresh like DD-44.
- **MispMailLogWidget polish** (DD-41); **MailLogTool gz-tail
  optimisation** (DD-43 deferred); **HealthList / MispCacheStatusWidget
  per-row drilldown**; **cache-status thresholds configurable**;
  **MispAdminSyncTestWidget `info` for caching-only servers**.
- **Roll StatGrid out** to remaining key/value admin widgets; **audit
  legacy SimpleList widgets** for typed-row rework.
- **Dark MISP theme work** — when the global initiative starts: audit
  the 8 hardcoded `rgba(...)` rules in `dashboard.default.css` (esp.
  `rgba(220,38,38,0.10)` ~line 544); the dark overlay should redefine
  `--misp-dash-{success,danger,warning,info}-muted`. NB the globe's
  retheme bridge (DD-47 G6) ALREADY reads tokens live, so dark mode will
  retone its arcs/atmosphere for free. See
  [[project_misp_dark_theme_sequencing]].
- Pre-existing: **DD-11 ACL-enforced switchable geo widget path**;
  **org/COVID maps palette opt-in**; default-templates **live non-admin
  ACL check**.
- **Phase 6 merge — the USER does this, not us.**

## Live test instance

- URL `http://localhost:5007/dashboards` (302 without a session; 200
  with). Admin user 1 (`admin@admin.test`, pw `Password12345`), Overmind
  theme. Cookie jar `/tmp/cj_stat.txt` was **valid this session** (200);
  re-mint via [[reference_misp_login_dance]] if it 302s next session.
- DB: `mysql -u misp -pPassword1234 misp`. MISP Redis: `redis-cli -n 13`.
  **SESSIONS in Redis db0** (`PHPREDIS_SESSION:*`); MISP data + caches in
  **db13**.
- Pew-pew dev-DB render: **1 arc (IR→US)** — see DD-45 family notes.
- State: `db_version=151`; branch `dashboards`. Build dirs reusable:
  `/tmp/echarts-bundle`, `/tmp/d3geo-bundle`, **`/tmp/globegl-bundle`**
  (globe.gl + three + three-globe + esbuild; entry.mjs re-exports Globe).

### Reusable verification recipes
```bash
# Lint
php -l app/Lib/Dashboard/PewPewMapWidget.php
node --check app/webroot/js/dashboard/charts/charts.module.mjs
./app/Vendor/bin/phpunit app/Test/PewPewMapWidgetTest.php   # 15 tests

# Render a widget body (JSON wrapper) — pew-pew returns {mode,flows[]}.
# NOTE the renamed class + the new webgl-globe mode:
curl -s -b /tmp/cj_stat.txt -X POST -H "Accept: application/json" \
  "http://localhost:5007/dashboards/renderWidget/test1" \
  --data-urlencode "widget=PewPewMapWidget" \
  --data-urlencode 'config={"time_window":"-1","mode":"webgl-globe","skin":"day","max_arcs":500}'

# Cached widgets serve stale — purge first (NOTE the renamed key):
redis-cli -n 13 --scan --pattern 'misp:pew_pew_map_cache*' | xargs -r redis-cli -n 13 DEL

# Eye-check the WebGL globe (G7 recipe): build a temp page under
# app/webroot loading the FULL CSS stack (dashboard.default +
# dashboard.midnight), inline a <div data-misp-chart="pewpew"
# data-misp-chart-payload='{"mode":"webgl-globe","flows":[...]}'>, import
# {initChartsIn} from '/js/dashboard/charts/charts.module.mjs' and call
# initChartsIn(document.body). Tokens cascade from :root so no wrapper
# class is needed; set <html data-theme="midnight"> for dark. Screenshot
# with: google-chrome --headless=new --no-sandbox
#   --enable-unsafe-swiftshader --use-angle=swiftshader
#   --virtual-time-budget=9000 --screenshot=out.png URL
# A --dump-dom of performance.getEntriesByType('resource') asserts the
# lazy bundle/texture loaded (and NOT on a 2d-mode page). READ the png,
# DELETE the temp file (publicly served — 302 confirms removal).

# Rebuild the globe bundle / re-vendor the texture: VENDORING.md
# "Reproducing the globe.gl 3D bundle (DD-47)".
```

## Convention reminders (carry)
- **Context budget:** keep within the first ~20% normally; user OK'd up
  to ~40% for UI work. Warn aggressively near the boundary + at task
  boundaries.
- **Commit per progress-tracker task; never `git add -A`; explicit
  `git add` + `git status --short`; sign (`%G?`=U).** Rhythm: one code
  commit + one tracker-tick commit per sub-task. **GPG agent may need
  unlocking** — if `gpg: signing failed: Timeout`, ask the user to run
  `! echo test | gpg --clearsign` to cache the passphrase, then retry.
- **Edit/Write flips a file's group to `iglocska:iglocska`** —
  `chgrp www-data` every edited web-served/app file (incl. docs).
- **Record meaningful decisions as DD-NN + a PRD §15 row.** DD-48 (the
  rename) was recorded as such this session.
- **Render-kind glyph rule** (CLAUDE.md): new `$render` → glyph in
  `render-thumbs.mjs`. (webgl-globe reused the PewPewMap kind — no new
  glyph.)
- **Widget `handler()`s emit RAW strings; the renderer owns escaping**
  (DD-34). **Colour decisions: renderer maps an allow-listed token to a
  token-pair / SVG** (DD-31/38..42). The globe extends this: it reads
  the SAME `--misp-dash-danger`/`-warning` tokens via `tokenOn`.
- **Two vendoring patterns now coexist:** the tree-shaken ECharts main
  bundle (a new series type needs BOTH the import AND `echarts.use()` —
  [[project_misp_echarts_bundle_treeshaken]]) AND the **lazy
  globe.bundle.mjs** (dynamic-`import()`, NOT in the main bundle,
  fetched only on webgl-globe). Don't merge them.
- **ESM imports ignore the `?v=185` buster → hard-refresh after a
  vendored-bundle / JS change.**
- **CSS/visual verification must load the FULL stack** + assert the
  computed/visible outcome (screenshot, not the property you set) —
  [[feedback_verify_visible_outcome_not_property]].
- **A `{teardown}` handle is the way to put a non-ECharts widget into
  `liveCharts`** (monitor charts + now the globe) — `disposeChart`
  branches on it.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**
  (the texture fork this session), and to **re-verify rather than
  defend** when a premise is questioned.

## Quick-start for the next session
1. Read this file + `dashboard-prd.md` §15 rows **DD-45..DD-49** +
   `dashboard-design-decisions.md` DD-45/46/47/48/49. The DD-31..DD-44
   family is still load-bearing for any widget work.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302 (or 200 with the cookie jar; re-mint
   `/tmp/cj_stat.txt` via `reference_misp_login_dance` if it 302s).
3. **Dashboard v2 is feature-complete** (three pew-pew modes shipped +
   verified; all phases except merge closed). The only tracked phase
   left is **Phase 6 (merge to `develop`) — the USER does this, not
   us.** Do NOT start the merge. If asked for more, the optional polish
   list above (globe auto-rotate, in-browser select-label confirm,
   DD-43/44 in-browser checks, template refreshes) is the menu.
4. Watch context; refresh this handoff before wrapping.
