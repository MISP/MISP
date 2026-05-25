# Dashboard v2 — Session handoff (2026-05-25 — pre-merge polish + NEXT: geo world-map widget)

Twelfth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl. DD-10).
- `dashboard-progress.md` — task state. **Phase 5 + Phase 5.5 closed.**
  Phase 6 (merge) is the only remaining tracked phase.
- `dashboard-design-decisions.md` — DD-01..DD-10 (DD-10 new this session).

This file is the bridge: ephemeral session-level context. Replace it
as work progresses.

## ⚠️ NEXT SESSION — the plan the user gave (READ FIRST)

**Build a new widget: geolocate recent MISP data onto the WorldMap.**
The user's words: *"design a new widget that will deduce localisation
of recent MISP data and display it in a world map widget. Use mmdb
(which we already integrate in userprofiles) to get the country for
each `ip-src` / `ip-dst` / `domain|ip` attribute."*

This is the first of the **"new widget types / new functionality"**
phase the user flagged after the UX-polish round. It is a *design +
build* task — start by surfacing the design decisions (data source,
recency window, geo-lookup performance, drilldown) before coding, per
the user's standing preference for rigorous pushback. **The user still
does the merge themselves — do NOT open the PR or merge.**

### Recon already done for this widget (reuse — all verified this session)

**Good news: this slots cleanly into existing infrastructure.** No new
render kind, no new glyph, no vendored deps, no controller/model change
expected — it should be a *pure addition* of one widget class (+ maybe
a small geo helper), matching the additive-only posture.

1. **WorldMap render kind already exists** — `public $render =
   'WorldMap'`. Template `app/View/Elements/dashboard/Widgets/WorldMap.ctp`
   (ECharts geo, vendored `world-110m.geojson`), glyph `thumbWorldMap`
   in `render-thumbs.mjs`. So the new widget just sets `$render =
   'WorldMap'` — **no new render kind ⇒ no new glyph needed** (the
   CLAUDE.md glyph rule only bites for *new* render kinds).

2. **WorldMap data contract** the handler must return (from
   `WorldMap.ctp`'s header + `OrganisationMapWidget`):
   ```php
   [
     'data'      => ['XX' => count, ...],  // 2-letter ISO alpha-2 → count
     'scope'     => 'IP geolocation',       // tooltip prefix (free text)
     'drilldown' => ['XX' => '/url', ...],  // OPTIONAL, DD-03, ISO-keyed
   ]
   ```
   The renderer translates ISO→English GeoJSON name server-side via
   `WidgetToolkit::getCountryCodeMapping()` (inverted), validates each
   drilldown URL through `DashboardURLValidator`, and silently drops
   ISO codes the toolkit doesn't know. Empty `data` → "No data."

3. **Reference widget:** `app/Lib/Dashboard/OrganisationMapWidget.php`
   is the closest template — same render, builds `['data' => [ISO =>
   count], 'scope' => ...]`, declares a `date_range` canonical schema
   param (toolbar-reachable, DD-05), an `int` `limit` (top-N countries),
   uses `WidgetToolkit->getCountryCodeMapping()`. **Copy its shape.**
   (`CsseCovidMapWidget` is a second WorldMap example.)

4. **mmdb / geo lookup (the userprofiles integration):**
   `app/Model/UserLoginProfile.php`:
   - `const GEOIP_DB_FILE = APP.'files'.DS.'geo-open'.DS.'GeoOpen-Country.mmdb'`
     — **present on the dev box** (11 MB, GeoOpen-Country, MISP-managed).
   - `public function countryByIp($ip)` → `new GeoIp2\Database\Reader(
     GEOIP_DB_FILE); $reader->country($ip)->country->isoCode;` returns
     the **ISO alpha-2** (e.g. "FR") or null on miss. Guards
     `class_exists('GeoIp2\Database\Reader')`.
   - **`GeoIp2\Database\Reader` is available** (geoip2 package vendored
     at `app/Vendor/geoip2/geoip2`, autoload confirmed).
   - **Perf gotcha:** `countryByIp` opens a *fresh Reader per call*.
     Geolocating many attributes this way is wasteful — for the widget,
     open the `Reader` **once** and loop the IPs (a small private helper
     in the widget, or a new `Lib/Dashboard/Tools` helper). Guard the
     `class_exists` + `file_exists(GEOIP_DB_FILE)` and emit the "No
     data." / a "GeoIP DB unavailable" empty-state if missing.

5. **Fetching the recent IP attributes (ACL-AWARE — security-relevant):**
   - Model is **`MispAttribute`** (renamed from `Attribute` for the PHP 8
     `#[Attribute]` clash). `ClassRegistry::init('MispAttribute')`.
   - **Must respect ACL** — only geolocate attributes the dashboard user
     may see. Use `MispAttribute->fetchAttributes($user, $options)`
     (ACL-aware; signature `fetchAttributes(array $user, array $options
     = [], ...)`), OR go through `Event::restSearch(...)` like
     `EventStreamWidget` / `AttackWidget` do (the higher-level filter
     dispatcher, also ACL-aware, supports canonical filters). **Do NOT**
     raw-`find()` the attributes table — that bypasses ACL.
   - Conditions: `type IN ('ip-src','ip-dst','domain|ip')` + a recency
     bound (`Attribute.timestamp >` window, from the schema's
     `date_range`/`time_window`). Bound the result set (limit / window)
     — geolocating every IP attribute on a large instance is heavy.
   - **IP extraction gotcha:** for `ip-src`/`ip-dst` the IP is `value1`;
     for the composite `domain|ip` the IP is **`value2`** (value1 is the
     domain). Pull the right field per type before the geo lookup.

### Open design decisions to surface to the user (likely DD-11)

- **Drilldown (DD-03):** mapping a country back to a MISP search is
  non-trivial — MISP has no native "geo" attribute filter. Options:
  (a) no drilldown initially (renderer makes it optional); (b) link to
  `/attributes/index` filtered by `type` + the value-list of IPs in
  that country (long URL, but precise); (c) a future server-side geo
  filter. Recommend (a) for v1, note (b)/(c) as additive follow-ups.
- **Recency window + caching:** what default window (e.g. last 7/30
  days)? Set `cacheLifetime` so the geo sweep isn't re-run every paint.
- **Reader reuse / helper placement:** inline private helper vs a
  shared `Lib/Dashboard/Tools/GeoLocator` (reusable, testable).
- **Private/reserved/IPv6 IPs:** `countryByIp` returns null → drop, or
  bucket as "None"? (OrganisationMapWidget drops unmapped silently.)
- **Widget identity:** name/title/category/default w·h. Suggest
  `AttributeGeoMapWidget` (category `misp` or a new `geo`), default
  ~`width 3 height 4` (match OrganisationMapWidget). Widgets are
  auto-discovered from `app/Lib/Dashboard/*.php` — no registration.
  **chgrp www-data** the new file before commit.

## TL;DR — this session (3 signed commits, all `%G?` = U)

A pre-merge UX-polish round, user-driven one tweak at a time:

- `b2e8a90be` — **fix**: export (download) menu was clipped on a 1-row
  (80px) widget by `.misp-widget`'s rounded-corner `overflow:hidden`.
  Confirmed real via a headless before/after harness; fixed with a
  transient CSS lift `.misp-widget:has(.misp-widget-menu.is-open) {
  overflow: visible }` (mirrored on `.card.misp-widget--overmind`).
  Corners re-clip on close; body keeps its own `overflow:auto`. Chosen
  over the parked "move overflow to body" idea (which risked a 6px
  scrollbar/corner poke on scrolling widgets). Both themes, CSS-only.
- `b71488bf8` — **new (DD-10)**: config Import/Export reimplemented as a
  **board-owned side panel** (theme-independent). The v1 `modal-open`
  carryover only worked on the default theme — Overmind loads a leaner
  stack (BS5 + `mispOvermind.js`, no jQuery/`misp.js`, no `modal-open`
  handler, incompatible `openModal` fragment contract). New ESM
  `config-io.module.mjs` opens the configure panel in modes
  `data-misp-configure-mode="import"|"export"` (mirrors gallery's panel
  reuse). Export → `/dashboards/export` REST → bare widget-array JSON +
  Copy; Import → normalise blob → POST to `/dashboards/updateSettings`
  (proven, applies LayoutFixup, CSRF-exempt on JSON) → reload. Menu
  items became `data-misp-board-action="import-config"|"export-config"`
  (href kept as no-JS fallback). **User verified the round-trip works.**
- `a78adc173` — **chg**: removed the Phase 0.3 **debug-readout footer**
  (a `<code>` dumping the live layout JSON to every user, with a subtree
  style MutationObserver refreshing it). Prototype cruft — markup, CSS,
  the const, `_updateDebugReadout()` + its 4 call sites + the boot
  observer all gone. `window.MISPBoard` kept for devtools.

## Where we are

```
Phase 0.4 / 1 / 2 / 3 / 4 / 5 / 5.5                               [x] CLOSED
Phase 6 — Merge to develop                                       [ ] (USER does this; not us)

Post-5.5 pre-merge polish (untracked phase — user-driven, in progress):
  [x] DD-09 calm chrome
  [x] Overmind prototype pill removed
  [x] Per-widget raw-data export restored (+ underline + download fixes)
  [x] Export menu clip on 1-row widgets fixed (CSS :has() transient lift)
  [x] Import/Export config → board-owned side panel (theme-independent; DD-10)
  [x] Removed Phase 0.3 debug-readout footer (layout-JSON dump) — prototype cruft
  [ ] More UX tweaks — user may enumerate more
  [→] NEXT: new widget types — geo world-map widget (mmdb → WorldMap) is first
```

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id 1 (`admin@admin.test`), password `Password12345`.
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`.
- **Admin is on the Overmind theme** (`UserSetting:ui_theme="Overmind"`).
  Overmind loads `mispOvermind.js` + `bootstrap.bundle.min` only (no
  jQuery / `misp.js`) under `Themed/Overmind/Layouts/dashboard.ctp`.
  The default theme uses `app/View/Layouts/dashboard.ctp` (full misp.js
  stack). **Anything that must work for the admin has to work without
  jQuery / misp.js globals** — that's what bit the Import/Export modal
  (DD-10). Test both themes; flip `ui_theme` to `"default"` and restore.
- DB: `mysql -u misp -pPassword1234 misp`.

**Dashboard state:** the user ran a live Export→Import round-trip test
this session (Import POSTs to `updateSettings`, which re-saves the blob
through `LayoutFixup` — so the stored bytes may have been re-encoded,
but the board is intact and functional). Working tree clean for all
dashboard files. **ALWAYS back up + restore `UserSetting:dashboard`
byte-exact around any DB-mutating smoke.**

**Hard-refresh after any CSS/JS edit** — the `?v=185` cache-buster in
`AppController` does NOT bump per-file. Several "is it broken?" reports
across sessions were just stale cached assets. (The user prefers to
eyeball UI changes live and will tell you specific things to check —
ask rather than spinning up headless Chrome unless there's real value.)

### Reusable smoke recipes

```bash
KEY=dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC
# Render a widget (REST: {data,renderer,config}; HTML: the .ctp body):
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  --data-urlencode "widget=<Name>Widget" --data-urlencode "config={}" \
  http://localhost:5007/dashboards/renderWidget
# Widget metadata (schema/category/render) for the gallery:
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  http://localhost:5007/dashboards/widgets
# Session-login dance for HTML pages: see reference-misp-login-dance memory.
# Headless render harness: works for CSS-only checks; ES-module imports
#   need an HTTP server (file:// blocks module CORS) — copy module+css to
#   /tmp, `python3 -m http.server`, load over http://localhost.
```

## Key architecture facts confirmed this session (reuse these)

- **Theme split is the headline gotcha.** Default theme = `misp.js` +
  jQuery + `openGenericModal` (`a.modal-open` handler). Overmind =
  `mispOvermind.js` + BS5 + `openModal(url)` (injects into a pre-existing
  `#mainModal` / `#mainModalBody`, incompatible with `#genericModal`
  fragments). The shared `View/Dashboards/index.ctp` + `board.module.mjs`
  + the dashboard ESM modules are the **only** JS guaranteed on both
  themes. **Board-owned ESM surfaces are the way; theme global modals
  are not** (DD-10 convention).
- **The configure side panel is the reusable overlay.** `[data-misp-
  configure-root]` + `-backdrop` + `-body` + `-title`, footer actions
  `[data-misp-configure-action="cancel|save"]`. Borrow it by setting
  `data-misp-configure-mode="<mode>"`, filling `-body`, removing
  `hidden` from panel+backdrop, and observing the panel's `hidden`
  attribute (a `MutationObserver`) for cleanup — the shared ✕ / Cancel /
  backdrop chain (configure.module) flips `hidden`; ESC and the body
  input listeners are gated on configure's private form state, so each
  non-form mode brings its **own ESC**. Used by `gallery.module.mjs`
  (mode `gallery`) and now `config-io.module.mjs` (modes `import` /
  `export`). CSS: non-form modes hide footer+preview + full-width body
  (folded into the gallery-mode selectors, shared sheet → both themes).
- **`updateSettings` is the proven save endpoint:** POST `Dashboard
  [value]=<widget-array JSON>`, `Accept: application/json` (⇒ `_isRest()`
  ⇒ CSRF-exempt, REST response), applies `LayoutFixup::applyReadFixups`.
  Both the layout save and the DD-10 import use this exact wire shape.
- **WorldMap renderer + mmdb facts** — see the NEXT-SESSION recon above.
- **Widget action vocab** (`board.module` `_wireBoardActions`):
  `toggle-mode | save | discard | add-widget | toggle-refresh |
  import-config | export-config`. `_closeContainingMenu(trigger)`
  closes a containing `[data-misp-menubutton]` on pick (menu-buttons
  don't self-close on an in-root click).
- **No themed widget-renderer overrides exist** → every
  `Widgets/<renderer>.ctp` is theme-independent; theme = page CSS +
  ECharts tokens only. New widgets get their renderer for free on both
  themes.

## Discovered work / parked

- ~~Export menu clipping on short widgets~~ — **FIXED** (`b2e8a90be`).
- ~~Import/Export broken under Overmind~~ — **FIXED** (DD-10, `b71488bf8`).
- ~~Phase 0.3 debug-readout footer~~ — **REMOVED** (`a78adc173`).
- **`LayoutFixup` mixed-id mint collision** — parked; provably
  unreachable from real UI flows. Only a hand-edited import blob
  triggers it; the DD-10 import normaliser doesn't change that. Cheap
  fix logged in the progress doc if ever wanted.
- Carryovers (unchanged): `blocklist_orgs` rich picker (needs handler
  rewrite); Chart.min.js / D3 migration (non-dashboard consumers);
  import HTML form-paste string-foreach quirk (now *bypassed* by the
  DD-10 panel, which POSTs to updateSettings; the quirk only remains on
  the legacy `/dashboards/import` action reachable via the no-JS href
  fallback); file-mode-drift root cause; time_window dropdown UX; grid
  drop-on-occupied cascade; tlp:clear invisible bars; OrgEventsWidget
  months>13 dates; EventEvolutionLineWidget end_date; live-preview race;
  dormant `dashboard.midnight.css` loader; EventStreamWidget pre-fetch
  overshoot. Real widgets' DD-03 drilldown maps are wired but nothing
  in-tree consumes them yet — the geo widget is a natural first consumer.

## Convention reminders

- Commit per logical task (or per-feature for a cohesive batch); never
  `git add -A`; explicit `git add` + `git status --short` first; body
  references the task. **Sign commits** (`%G?`=U).
- **New files: `chgrp www-data` before commit** (the geo widget class +
  any geo helper will need this).
- **Themed wrapper parity:** any chrome / `data-*` change on the base
  `widget/wrapper.ctp` must be mirrored in the Overmind wrapper in the
  SAME commit. (Renderer `.ctp`s under `Widgets/` are theme-shared — no
  mirror needed there.)
- **Dashboard chrome icons are inline glyphs/SVG, not Font Awesome.**
- **External links pair `target=_blank` + `rel=noopener noreferrer`.**
- **Record meaningful design decisions as DD-NN** in
  `dashboard-design-decisions.md` + a PRD §15 binding row (DD-10 set the
  most recent pattern). Lightweight cleanups don't need a DD (the
  debug-readout removal didn't get one).
- **Render-kind glyph requirement:** any *new* `$render` value / new
  `Widgets/` template ships a matching glyph in `render-thumbs.mjs` in
  the same commit. (The geo widget reuses `WorldMap` → does NOT trigger
  this.)
- User wants **rigorous pushback**, not a yes-machine — surface
  trade-offs, name alternatives, recommend, then go with the user's
  call. Use AskUserQuestion for genuine forks (this session: which
  refinement first; Import/Export presentation).
- **Additive-only posture:** greenfield dashboard features are pure
  additions; touching MISP core code beyond ACL/routes/composer is a red
  flag needing sign-off. The geo widget should be one new class (+ maybe
  one helper) — no controller/model edits expected.
- Tracker/decision docs are ground truth between hitm/afk sessions.
- Surface context status past 75% at task boundaries. (This session
  ended ~26%.)

## Quick-start cheatsheet for the next session

1. Read `dashboard-prd.md` (spec) + `dashboard-design-decisions.md`
   (DD-01..DD-10) + this file. Skim `dashboard-progress.md` only if you
   need task-level history.
2. Verify the instance: `curl -s http://localhost:5007/dashboards
   -o /dev/null -w "%{http_code}\n"` → 302 without a session.
3. **The task is the geo world-map widget** (§ "NEXT SESSION" above).
   Start by surfacing the open design decisions to the user, then build:
   one widget class under `app/Lib/Dashboard/`, `$render = 'WorldMap'`,
   handler returns `['data' => [ISO => count], 'scope' => ...]` built by
   geolocating recent ACL-scoped `ip-src`/`ip-dst`/`domain|ip` attributes
   via the mmdb Reader. Copy `OrganisationMapWidget` as the skeleton.
   `chgrp www-data`; commit signed; record DD-11 if a real decision lands.
4. Do NOT start the merge — the user does that themselves.
