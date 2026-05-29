# Dashboard v2 — Session handoff (2026-05-29 — DD-45 CLOSED: pew-pew map ships 2D + orthographic globe; DD-46 pivoted off echarts-gl; DD-47 planned: globe.gl real-3D third mode, build next session)

Twenty-seventh session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-46). **DD-46** is the newest row.
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** Post-5.5 "New features"
  carries DD-43, DD-44 + DD-45 (Pew-pew attack flow map) —
  **Phases A + B + C + D + E ALL closed**.  DD-45 is DONE.
- `dashboard-design-decisions.md` — DD-01..DD-46.  **DD-46** records the
  globe-tech pivot (echarts-gl → d3-geo orthographic 2.5D).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (DD-45 Phase D via DD-46; 11 signed commits, `%G?`=U, not merged)

```
02b03e772 chg DD-45 D5 + Phase D — tick progress tracker
f6c62c170 chg DD-45 D4 — tick progress tracker
40f3452ac new DD-45 D4 — mode-switch label + stale-text refresh (DD-46)
e7862f4e9 chg DD-45 D3 — tick progress tracker
2cc853a57 new DD-45 D3 — orthographic globe branch in pew-pew builder (DD-46)
6c9234a29 chg DD-45 D1 — tick progress tracker
069f5ddd0 new DD-45 D1 — geoOrthographic in d3-geo bundle (DD-46 globe path)
1d39578df chg DD-46 — pew-pew globe via d3-geo orthographic, supersedes echarts-gl Phase D
b91802375 chg DD-45 handoff refreshed — Phase C landed; next: Phase D   (prev session)
```

**DD-45 is fully landed and verified live.** The pew-pew attack-flow
map ships TWO modes from one `flows[]` payload: a 2D flat-map (Phase C,
prior session) and a **from-space orthographic "globe"** (Phase D, this
session). Both render attacker→victim great-circle arcs with an
animated trail + pulsing destination glow, retheme light/dark via
tokens, and cache globally.

## The DD-46 pivot (the headline of this session)

Phase D was specced (DD-45) as a lazy-loaded **echarts-gl** WebGL globe
(`globe` + `lines3D`). Implementing D1 surfaced that echarts-gl is a
**liability**:
- **Unmaintained** (last release 2022). `2.1.0` claims echarts@6 but
  still ships echarts@5-era *extensionless* deep imports
  (`echarts/lib/coord/geo/fix/textCoord`) that break echarts@6's strict
  `exports` map (`"./*":"./*"`). It only built with a hand-written
  esbuild resolver plugin — a standing liability (echarts@7 could break
  it with no upstream fix).
- **Heavy + fragile**: the self-contained GL bundle was **247 KB
  gzipped** (duplicates echarts core; can't share the main instance) +
  a hard WebGL requirement + `claygl`.

The user re-opened the look premise; an AskUserQuestion fork picked
**d3-geo orthographic "2.5D"** over echarts-gl / globe.gl / stay-2D.
**DD-46** records it. The globe is now the SAME Phase C arc engine
(`geo` + `lines` + `effectScatter` + `tokenOn`) with `geo.projection`
swapped to a hemisphere-culling orthographic. `geoOrthographic` is in
**d3-geo core, already vendored** — net cost **+0.1 KB gzipped**. No
WebGL, no new dependency, no globe texture. Tradeoff accepted: a globe
*silhouette* (flat-shaded political disc), not a photo-textured lit
sphere; auto-rotation is manual (deferred).

### The one load-bearing technical fact (reuse this)

**d3's `geoOrthographic`, called as a POINT FUNCTION `p([lon,lat])`,
does NOT apply `clipAngle`** — back-hemisphere points fold onto the
front face. The fix (in `charts.module.mjs::orthographicProjection`):
return `[NaN, NaN]` for any point whose great-circle cosine to the view
centre is `< 0`. **ECharts' `geo` coordinate system tolerates the NaN
sentinel cleanly** — its bbox auto-fit ignores NaNs and the canvas
renderer skips NaN path segments — so the limb renders crisp with no
folding. Verified by spike + the D5 screenshots.

## What landed this session (reuse these facts)

### `charts.module.mjs` — pew-pew builder now draws both modes
- `buildPewPewOption2D` **renamed → `buildPewPewOption`** (it draws both
  modes now). Registry: `pewpew: buildPewPewOption`.
- New module-scope helper **`orthographicProjection(rotate)`** (the
  culling wrapper above) + const **`PEWPEW_GLOBE_ROTATE = [10, -30]`**
  (North-Atlantic framing: view centre ≈ [-10, 30], so US + EU +
  attacker arcs read together).
- The `geo` block gets `projection: orthographicProjection(...)` ONLY
  when `payload.mode === '3d-globe'`; `'2d'` keeps native flat lon/lat.
  Everything else (3 z-stacked arc layers, danger/warning tokens) is
  identical between modes. **Dispatch stays SYNC** — d3-geo is a static
  import; no lazy `import()`, voiding the DD-45 async-restructure gotcha.
- `geoOrthographic` added to the import from `./vendor/d3-geo.bundle.mjs`.

### `d3-geo.bundle.mjs` — geoOrthographic added (D1)
- Export barrel `entry.mjs`: `export { geoNaturalEarth1,
  geoOrthographic } from 'd3-geo';`. Rebuilt per the `VENDORING.md`
  d3-geo recipe. **17.4 → 18.1 KB raw / 7.4 → 7.5 KB gz** (+0.1 KB gz —
  shares d3-geo core). VENDORING.md size row + exports + recipe updated.

### `configure.module.mjs` + `WidgetSchema.php` — `enum_labels` (D4)
- New **optional** schema key `enum_labels: {value: label}` for `enum`
  fields. The configure-form `<select>` shows the label, falling back
  to the raw value when unmapped — so all existing enum fields are
  unchanged. Documented in the `WidgetSchema.php` contract doc-comment;
  `getSchema()` passes it through wholesale (no key-strip) and
  `json_encode` keeps it, so it reaches `data-widget-schema`.
- `AttackFlowMapWidget` maps `{2d:'2D map', 3d-globe:'Globe'}`. The
  **stored value stays `'3d-globe'`** (schema stability, DD-44-style) —
  only the label is friendly. Stale echarts-gl text in the widget's
  `$description`/`$params`/`$schema` help + class doc-comment refreshed.

### Verification (D5, no code commit)
Headless-Chrome screenshots (C5 recipe, full CSS stack): the **real
pipeline** renders the dev-DB single arc (IR→US, value 1) on the
orthographic disc; a **synthetic 6-arc** test page shows clean limb +
culled back face + scaled arcs/glows; **light + dark** both retheme via
`tokenOn` (midnight retones danger→#f87171, warning→amber) with ZERO JS
change; the **main bundle is untouched** (git-clean) and
charts.module.mjs's import graph has **no echarts-gl / WebGL / dynamic
import** — so no GL asset can load (static-confirmed). Temp webroot
files deleted (302 confirms).

## DD-45 family — render-kind & widget facts (still load-bearing)

### Pew-pew widget shape (DD-45 + DD-46)
- `AttackFlowMapWidget` → `$render='PewPewMap'`, `$category='events'`,
  `$cache_duration=3600`, `$cache_scope='global'`, open to all users
  (aggregate-only, mirrors `AttributeGeoMapWidget` DD-11), default 6×5.
- Config params: `time_window`, `mode` (`2d`|`3d-globe`, default `2d`),
  `max_arcs` (default 500, value-desc truncation).
- Data: one arc per `(event, threat-actor cluster's `country`, victim
  country-galaxy `ISO`)` triple; aggregated by `(src_iso, dst_iso)`;
  centroids resolved server-side via `iso-centroids.json` (DD-45 B1).
- **Dev-DB reality**: ONE visible arc (IR→US, event 1421 Charming
  Kitten/APT33/APT35). The other dual-tagged events are self-loops
  (RU→RU, IR→IR×2), correctly skipped. Production is richer; the dev
  box is thin by nature, NOT a bug. For a richer demo use the synthetic
  multi-arc test-page approach (D5/C5) or revisit the user-rejected
  fixture-tagging fork (offer via AskUserQuestion).
- `.ctp` is a dumb shim emitting `data-misp-chart="pewpew"` +
  `{mode, flows[]}`; all mode dispatch lives in `charts.module.mjs`.

### Prior render-kind family (DD-31..DD-43) — unchanged, still live
StatGrid (DD-31), NetworkGraph (DD-33/40), UserList (DD-35/36/41),
QueueList (DD-38), HealthList (DD-39), PewPewMap (DD-45/46). Every new
`$render` needs a glyph in `render-thumbs.mjs` (CLAUDE.md) — PewPewMap's
`thumbPewPewMap` shipped in Phase C.

## Open follow-ups (active + carried)

### NEXT SESSION — DD-47: build the globe.gl real-3D third mode (plan ready: G1..G7).
DD-45 is closed (2D + orthographic shipped). The user opted to add a
**third, opt-in render mode** (`mode='webgl-globe'`): a real WebGL
textured globe via **globe.gl** (Three.js) — the echarts-gl *look*,
on a maintained MIT library (globe.gl 2.46.1, published 2026-05-16; vs
echarts-gl's 2022 + echarts@6 incompatibility, the DD-46 reason we
dropped it). **DD-47** holds the full spec + the resolved forks;
`dashboard-progress.md` has the phased plan **G1..G7**. This session
*planned* it (DD-47 + plan, no code); next session *builds* it.

Key facts for the build (all in DD-47):
- **Front-end only** — the server `handler()`, caching, and `flows[]`
  payload are unchanged; this is a parallel render path.
- **Separate lazy bundle** `globe.bundle.mjs` (esbuild tree-shaken,
  NOT in the main bundle), dynamic-`import()`ed on first `webgl-globe`
  render only. This re-introduces the lazy-bundle + async-dispatch
  machinery DD-46 removed — now justified (real weight ≈ several hundred
  KB gz; genuinely-different output).
- **globe.gl owns its own WebGL canvas** — it is NOT an ECharts option
  builder. So it gets a dedicated `initWebglGlobe(hostEl, payload)`
  (static glue) that lazy-imports the bundle + maps `flows[]` →
  `arcsData` + `ringsData`. Only the `pewpew`+`webgl-globe` dispatch
  branch goes async; the 2d/3d-globe ECharts modes stay sync.
- **Theming is bespoke** — globe.gl won't read `--misp-dash-*`; bridge
  via `tokenOn` at init + a `data-theme` observer for live retheme (the
  zero-JS retheme the other two modes get free is NOT automatic here).
- **Texture** — G2 vendors an earth image; AskUserQuestion sub-fork
  (Blue Marble PD / night-lights / flat political).
- **Mode enum** — add `'webgl-globe'` (value stable) + `enum_labels`
  friendly text; default stays `'2d'`.
- **Verify caveat** — headless-Chrome WebGL may need
  `--enable-unsafe-swiftshader` / `--use-angle=swiftshader`.

The remaining tracked phase after DD-47 is **Phase 6 (merge to
`develop`) — the USER does this, not us.** Other carried polish below.

### Pew-pew globe polish (surfaced in Phase E, deferred — DD-46)
- **Auto-centre the globe on the flows' centroid** (busiest region
  faces front) and/or expose `rotate` as a config knob. With the dev-DB
  single arc the US glow lands near the top-left limb (visible but
  edge-ish); a data-driven default centre would frame it better.
- **Globe auto-rotation** (slow spin) — deferred to keep render cheap +
  the canvas still for screenshots.
- **Optional sphere/ocean backing fill** behind the geo — the political
  disc reads fine on both themes already; low priority.

### Carried (not active)
- **In-browser confirm of the "Globe" `<select>` label** (trivial —
  open the pew-pew widget's configure modal; data path already
  verified).
- **In-browser verification of DD-43 + DD-44** (hard-refresh
  Ctrl-Shift-R): MispMailLogWidget rotated-file scan; new Administrator
  template (14 widgets) in the gallery.
- **Other shipped templates** — `analyst/` + `community/template.json`
  may be due a v2-era refresh like DD-44.
- **MispMailLogWidget polish** (DD-41): inline header search-box;
  slide-in setup-help panel; filter chips; package
  `/etc/rsyslog.d/misp-mail.conf` INSTALL helper.
- **MailLogTool gz-tail optimisation** (DD-43 deferred): bounded
  `gzseek`+backwards-binary-search if a chatty relay surfaces a cost
  complaint.
- **HealthList / MispCacheStatusWidget per-row drilldown**;
  **cache-status thresholds configurable**; **MispAdminSyncTestWidget
  `info` for caching-only servers**.
- **Roll StatGrid out** to remaining key/value admin widgets; **audit
  legacy SimpleList widgets** (`MispAdminResourceWidget`,
  `MispSystemResourceWidget`) for typed-row rework.
- **Dark MISP theme work** — when the global initiative starts, the
  dashboard carryover is: audit the 8 hardcoded `rgba(...)` rules in
  `dashboard.default.css` (esp. `rgba(220,38,38,0.10)` at line 544); the
  dark overlay should redefine `--misp-dash-{success,danger,warning,
  info}-muted`. See [[project-misp-dark-theme-sequencing]].
- Pre-existing: **DD-11 ACL-enforced switchable geo widget path**;
  **org/COVID maps palette opt-in**; default-templates **live non-admin
  ACL check**.
- **Phase 6 merge — the USER does this, not us.**

## Live test instance

- URL `http://localhost:5007/dashboards` (302 without a session; 200
  with). Admin user 1 (`admin@admin.test`, pw `Password12345`), Overmind
  theme. Cookie jar `/tmp/cj_stat.txt` was **valid this session** (200);
  re-mint via [[reference-misp-login-dance]] if it 302s next session.
- DB: `mysql -u misp -pPassword1234 misp`. MISP Redis: `redis-cli -n 13`.
  **SESSIONS in Redis db0** (`PHPREDIS_SESSION:*`); MISP data + caches in
  **db13**.
- Pew-pew dev-DB render: **1 arc (IR→US)** — see DD-45 family notes.
- State: `db_version=151`; branch `dashboards`. Build dirs reusable:
  `/tmp/echarts-bundle` (main), `/tmp/d3geo-bundle` (d3-geo — now exports
  geoOrthographic). The abandoned `/tmp/echartsgl-bundle/` (DD-46) can be
  deleted; it never touched the repo.

### Reusable verification recipes
```bash
# Lint
php -l app/Lib/Dashboard/<Widget>.php
node --check app/webroot/js/dashboard/charts/charts.module.mjs

# Render a widget body (JSON wrapper) — pew-pew returns {mode,flows[]}:
curl -s -b /tmp/cj_stat.txt -X POST -H "Accept: application/json" \
  "http://localhost:5007/dashboards/renderWidget/test1" \
  --data-urlencode "widget=AttackFlowMapWidget" \
  --data-urlencode 'config={"time_window":"-1","mode":"3d-globe","max_arcs":500}'

# Cached widgets serve stale — purge first:
redis-cli -n 13 --scan --pattern 'misp:attack_flow_map_cache*' | xargs -r redis-cli -n 13 DEL

# Eye-check a render kind visually (DD-41/C5/D5 recipe): build a static
# page under app/webroot loading the FULL CSS stack (dashboard.default +
# dashboard.midnight at minimum for token theming), inline the
# data-misp-chart div with a {mode,flows[]} payload, `import
# {initChartsIn} from '/js/dashboard/charts/charts.module.mjs'` and call
# initChartsIn(document.body). For dark: set data-theme="midnight" on
# <html> (drive via location.hash and screenshot URL#midnight). Screenshot
# with headless Chrome, READ the png, DELETE the temp file (publicly served).

# Rebuild d3-geo bundle (add a projection): edit /tmp/d3geo-bundle/
# entry.mjs export line, esbuild per VENDORING.md. geoOrthographic +
# geoNaturalEarth1 are in d3-geo CORE; geoRobinson/geoCylindricalEqualArea
# in d3-geo-projection.
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
- **Record meaningful decisions as DD-NN + a PRD §15 row.** A material
  reversal of a prior DD = a NEW DD (DD-46 superseded DD-45's Phase D).
- **Render-kind glyph rule** (CLAUDE.md): new `$render` → glyph in
  `render-thumbs.mjs`.
- **Widget `handler()`s emit RAW strings; the renderer owns escaping**
  (DD-34). **Colour decisions live in the widget; renderer maps an
  allow-listed token to a token-pair / SVG** (DD-31/38..42).
- **Tree-shaken ECharts bundle** ([[project-misp-echarts-bundle-treeshaken]]):
  a new series type needs BOTH the `echarts/charts` import AND the
  `echarts.use([...])` call. Main bundle carries `Bar, Line, Map, Pie,
  Graph, Lines, EffectScatter` (721 KB / 245 KB) — **untouched by Phase D**.
- **ESM imports ignore the `?v=185` buster → hard-refresh after a
  vendored-bundle / JS change.**
- **CSS verification must load the FULL stack** + assert the
  computed/visible outcome (not the property you set) —
  [[feedback_verify_visible_outcome_not_property]].
- User wants **rigorous pushback + genuine forks via AskUserQuestion**,
  and to **re-verify rather than defend** when a premise is questioned —
  both paid off this session (the echarts-gl@6 incompat + the
  orthographic-folding behaviour were both verified by build/spike, not
  asserted; the look premise re-open led to DD-46).

## Quick-start for the next session
1. Read this file + `dashboard-prd.md` §15 rows DD-45 + DD-46 + **DD-47**
   + `dashboard-design-decisions.md` DD-45/DD-46/DD-47. The DD-31..DD-44
   family is still load-bearing for any widget work.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302 (or 200 with the cookie jar; re-mint
   `/tmp/cj_stat.txt` via `reference_misp_login_dance` if it 302s).
3. **DD-47 G1 first** — build the lazy `globe.bundle.mjs` (globe.gl +
   three, esbuild tree-shaken; per the G1 plan + the `VENDORING.md`
   recipe pattern). Then G2 (texture, AskUserQuestion sub-fork) → G3
   (`initWebglGlobe`) → G4 (async dispatch) → G5 (mode enum/label) →
   G6 (live retheme) → G7 (verify). One commit per sub-task.
   **DD-47 is opt-in polish** — defer if priorities shift; the two
   shipped modes stand alone.
4. Do NOT start the merge — the user does that. Watch context; refresh
   this handoff before wrapping.
