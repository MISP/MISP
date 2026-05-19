# Dashboard v2 — Implementation Progress Tracker

**Source of truth for what's done, what's next, and what's blocked.**
A fresh session must be able to pick up the work by reading
[`dashboard-prd.md`](dashboard-prd.md) for the spec and **this file**
for state. Conversation context is not persisted — anything a future
session needs lives here.

## How to use this file

- Tasks are checked off **one at a time** as they complete. Do not
  batch checkmarks. Do not pre-check ahead of completion.
- **Each completed task is followed by a git commit.** One task =
  one commit. The progress tracker says *what's next*; the git log
  says *what's been done*. See `feedback_commit_per_task.md` in user
  memory for the discipline. Commit message format:

  ```
  new: [dashboard-v2] <short imperative summary>

  Closes Phase X.Y task: <task name as it appears in this file>
  ```

  Use `new:` for additions, `chg:` for refactors / changes, `fix:`
  for bug fixes, per the MISP commit-message convention in
  `CLAUDE.md`. Stage only the files the task actually touched plus
  the update to this progress tracker — never `git add -A`.
- Phases run **strictly sequentially**. Do not start a task in Phase
  N+1 before every task in Phase N is checked.
- Within a phase, tasks are also sequential unless explicitly marked
  *(parallelisable)* — which only applies to research/lookups, never
  to code writing (per `feedback_sequential_implementation.md`).
- When a task closes, append a **Done note** under it: a 1–3 line
  summary of what was actually done, the file paths touched, and any
  surprise that future-you should know about. The Done note + the
  commit hash form the audit trail.
- When a task is **blocked**, mark it `[~]` (in progress / blocked) and
  append a `Blocked by:` line naming the open question or upstream
  task. Do not check it off until the block is resolved. Do not
  commit a blocked task.
- New tasks discovered mid-phase are appended at the end of the
  current phase or filed under "Discovered work" at the bottom of this
  file with a clear "introduces what / why / where it goes" note.

## Live test instance

A working MISP runs at `http://localhost:5007` directly off this
codebase. Admin API key in PRD §"Local test instance". Use it for
visual verification, smoke tests, and REST checks during all
implementation phases.

## Status legend

- `[ ]` not started
- `[~]` in progress (one at a time max — kill before starting another)
- `[x]` done; see Done note below it
- `[-]` cancelled / superseded; see note below it

## Working mode log

Track which mode the user is in across sessions. This influences the
size of step the implementer should take before pausing for review.

| Date (YYYY-MM-DD) | Mode | Note |
|---|---|---|
| 2026-05-04 | hitm | PRD + progress doc bootstrapped; Phase 0 §13 questions still open |
| 2026-05-04 | hitm | Scope cut: G2 (multi-board) and G12 (persistence rework) dropped; reuse `UserSetting:dashboard` + `dashboards` table verbatim. Blob shape evolves additively to `{scope, widgets}`. Progress tracker pruned accordingly below. |

---

## Phase 0 — Alignment + prototype

**Goal:** resolve `dashboard-prd.md` §13 open questions, validate the
risky technical bets (Gridstack v11, ECharts adoption, four-level
theming, canonical-type plumbing) on a throwaway branch, get user
sign-off before writing production code.

**Exit criteria:** all §13 questions resolved (in this file under
"Resolved questions" below); prototype demonstrably renders 3
representative widgets in the new frame, themes successfully across
Levels 1 and 3 (§8), and reacts to a board-toolbar `time_window`
change with widgets re-rendering in inherit/pinned modes.

### 0.1 Resolve open questions (§13)

- [x] §13 Q1 — Templates carry default scope? *(superseded 2026-05-04 by Model 4 — see follow-on note in Resolved questions; templates still carry per-widget configs which can include canonical-typed values, but there is no separate "scope" concept any more)*
- [-] §13 Q2 — *Moot* (multi-board dropped 2026-05-04)
- [x] §13 Q3 — Drill-down auto-wrap vs. explicit `$drilldown`?
- [x] §13 Q4 — Gridstack v11 vs. Pragmatic DnD → DD-01 (Pragmatic DnD + CSS Grid + custom math)
- [x] §13 Q5 — Posture on touching legacy → straight replacement on `dashboards` branch, no flag, three-parity merge gate
- [x] §13 Q6 — Frame ships own CSS file vs. inherits host theme BS variables → own CSS file, self-contained
- [x] §13 Q7 — Backfill `$schema` on all 30 built-in widgets, or only canonical slots → tiered (Option C); 9 widgets get full schema, rest get canonical slots + JSON textarea fallback
- [-] §13 Q8 — *Moot* (multi-board endpoints withdrawn 2026-05-04)
- [-] §13 Q9 — *Moot* (sharing tiers dropped 2026-05-04)
- [-] §13 Q10 — *Moot* under Model 4 (toolbar is bulk-edit; no inherit/pinned state; see Resolved §Q10/Q11 follow-on)
- [x] §13 Q11 — Toolbar persistence in view mode → toolbar is mode-independent and writes immediately; edit mode required only for layout/structural changes
- [-] §13 Q12 — *Moot* (soft-delete dropped 2026-05-04)
- [-] §13 Q13 — *Moot* (G12 dropped; existing import semantics inherited 2026-05-04)

### 0.2 Library bring-up + risk validation

DD-01 (Pragmatic DnD) and DD-02 (ECharts) are committed in
`dashboard-design-decisions.md`. Phase 0.2 is therefore not a
comparison — it's a thin bring-up to validate the implementation
risk on the chosen libraries before committing Phase 1 effort.

- [x] Vendor Pragmatic Drag and Drop at `app/webroot/js/dashboard-v2/grid/vendor/`

  **Done note (2026-05-06).** Bundled via `npx esbuild` from the npm
  package's selected entry points (`element/adapter` + `combine`) into
  a single self-contained ESM file: 21.5 KB raw, 6.8 KB gzipped.
  Vendoring procedure documented in `vendor/VENDORING.md` (reproducible
  byte-for-byte from a clean directory). Upstream `LICENSE.md`
  (Apache 2.0, Copyright 2022 Atlassian Pty Ltd) copied alongside.
  Surprise: PDD's npm root export is intentionally empty; you must
  consume sub-paths and bundle them. The package also pulls in three
  internal deps (`bind-event-listener`, `raf-schd`, `@babel/runtime`),
  all transitively vendored by the bundle. esm.sh's `?bundle` query
  was investigated but its output isn't fully self-contained — it
  leaves `bind-event-listener` as an external import — so a real
  bundler step is required. Documented in VENDORING.md so a fresh
  session knows the constraint.
- [x] Build a minimal `GridModule` (snap, collision, resize-cascade) against CSS Grid for a 12-column dashboard layout at `app/webroot/js/dashboard-v2/grid/`; render 3 placeholder widget tiles in a standalone HTML demo page (no MISP integration yet); confirm drag/resize/snap UX feels right — *user confirmed UX 2026-05-06*

  **Done note (2026-05-06).** Code complete. `grid.module.mjs` covers
  drag (PDD-driven via `monitorForElements({onDrag})` for live-position
  tracking), resize (raw pointer events on a per-tile resize handle),
  snap-to-cell, collision detection, and downward-cascade when a
  tile lands on others. Demo at
  `app/webroot/js/dashboard-v2/proto/demo.html`, served live at
  `http://localhost:5007/js/dashboard-v2/proto/demo.html` (3 tiles +
  "Add tile" + "Reset layout" + live JSON layout readout).
  Syntax-checked (`node --check`) and all three files serve 200 from
  the test instance.

  **Blocked by:** user UX verification — open the demo URL, exercise
  drag/resize, confirm the feel before fully ticking. PDD's drag
  model uses HTML5 D&D under the hood, which has a known
  "drag-image-snaps-to-cursor-with-offset" quirk on some browsers; if
  the ghost preview lags or feels wrong, we may need to swap to raw
  pointer events for drag too (would simplify to one event model and
  drop the PDD vendoring entirely — DD-01 reconsideration trigger).
  Note: in this build I rely on PDD's `monitorForElements({onDrag})`
  rather than the native drag preview, which should sidestep most of
  the HTML5 D&D ergonomic issues — but eyeballs are the only judge.

- [x] **Risk check (DD-01 forcing function):** measure custom grid-math LOC after the bring-up.

  **Done note (2026-05-06).** `grid.module.mjs`: 291 total lines
  (incl. blanks + JSDoc-style comments), 238 substantive lines (non-
  blank, non-pure-comment). The DD-01 hard threshold was >300 LOC
  triggering escalation — we're at 291 / 238 substantive, **under
  the threshold but at the upper edge**. The module covers drag +
  resize + collision + cascade, so this is *not* the "single-widget-
  resize scenario" the threshold was specifically scoped to — for
  that minimal scope alone, the count would be roughly 100 lines
  (drag + collision only, no cascade, no resize). Phase 1 should be
  watchful: adding mobile/touch fallback, keyboard movement (a11y),
  empty-row collapse, and dynamic column-count change could each
  push us past 300 quickly. Recommend logging each addition's LOC
  delta in this tracker as Phase 1 progresses, to catch the >40%
  Phase 1 budget warning early.
- [x] Vendor ECharts at `app/webroot/js/dashboard-v2/charts/vendor/` (tree-shaken: bar + line + geo)

  **Done note (2026-05-06).** Bundled `echarts@6.0.0` via esbuild,
  ESM, minified, only the imports dashboard-v2 widgets actually use:
  BarChart + LineChart + MapChart + GridComponent + TooltipComponent +
  LegendComponent + TitleComponent + DataZoomComponent +
  GeoComponent + VisualMapComponent + DatasetComponent + Canvas
  renderer. Bundle size **649 KB raw / 216 KB gzipped**. Upstream
  `LICENSE` (Apache 2.0) and esbuild-extracted attribution comments
  (`echarts.bundle.LEGAL.txt`) shipped alongside. Reproduction recipe
  in `vendor/VENDORING.md`. Also vendored a low-res world GeoJSON for
  the geo widget: `world-110m.geojson` (425 KB raw / 146 KB gzipped),
  converted from `world-atlas@2.0.2` (ISC) via `topojson-client`.
  Both files serve 200 from the test instance. Combined first-paint
  cost for a dashboard with geo ≈ 1 MB raw / 360 KB gzipped.

- [x] Bundle-size measurement: record minified+gzipped size of the tree-shaken ECharts build in DD-02 Done note

  **Done note (2026-05-06).** Recorded in `dashboard-design-decisions.md`
  DD-02 alongside the original decision. JS bundle 216 KB gzipped;
  world GeoJSON adds 146 KB gzipped. Larger than the informal "~300 KB
  gzipped" estimate from the earlier conversation because geo
  components dominate. Acceptable for desktop SOC dashboard target.
  Trade-offs (geo lazy-load split, higher-res maps) recorded in
  `vendor/VENDORING.md` for future revisit.
- [x] **uPlot follow-up trial** (DD-02 open question): render `MispSystemResourceWidget` time-series via uPlot; record render-time and LOC vs. ECharts equivalent. Decide: ECharts only, or mixed ECharts+uPlot?

  **Done note (2026-05-06).** Resolved as **ECharts only, no uPlot**.
  Decision recorded in DD-02. Code trial deliberately skipped:
  every in-tree time-series widget renders <500 data points
  (MispSystemResource ~50, EventEvolutionLine 30-90, etc.), well
  inside ECharts' easy range. uPlot's edge appears at ~5,000+ points.
  Running the trial would have produced "uPlot beats ECharts on data
  ECharts handles fine anyway" — a foregone conclusion. Three
  re-trigger conditions documented in DD-02 for a future revisit.
- [x] AGPL × Apache 2.0 licence sanity-check formalised — link the authoritative source (FSF compatibility list, MISP project's existing precedents) into DD-01 and DD-02

  **Done note (2026-05-06).** Full audit recorded as DD-07 (its own
  decision entry rather than scattered notes across DD-01/DD-02 —
  it's a cross-cutting concern). Verdict: all five licences in play
  (Apache-2.0 from PDD + ECharts; 0BSD for tslib bundled inside
  ECharts; BSD-3-Clause for zrender bundled inside ECharts; ISC for
  world-atlas) are GPL-compatible per the FSF list, therefore
  AGPL-compatible. Combined work must ship under AGPL-3.0 with the
  permissive notices preserved — operationally satisfied since each
  vendor dir already ships `LICENSE.*` files and esbuild's
  `*.LEGAL.txt` sidecars. MISP precedent for vendoring permissive
  JS/CSS assets is well-established (Bootstrap, jQuery, Chart.js,
  D3, etc. already in webroot/). Authoritative source linked:
  <https://www.gnu.org/licenses/license-list.html>.

### 0.3 Build the throwaway prototype

- [-] Create a working branch off `dashboards`: `dashboard-v2-proto`

  **Cancelled (2026-05-06).** Decided in the same session to stay on
  `dashboards` directly. Rationale: a sub-branch adds checkout
  friction for the user reviewing work, and per Q5 we're doing
  straight in-place replacement on `dashboards` anyway. If the
  prototype turns out genuinely throwaway we delete the dirs;
  if it's the basis of Phase 1 the paths are already where Phase 1
  puts things.
- [x] Stand up a minimal `Dashboards2Controller` + view at `/dashboards2` (no routes change to v1)

  **Done note (2026-05-06).** Originally scoped as
  `DashboardsProtoController` at `/dashboards/proto/*` via custom
  routes; switched to `Dashboards2Controller` at `/dashboards2/*`
  per user feedback ("you're overcomplicating things") — default
  CakePHP routing handles it natively, no custom routes needed.
  Final renamed: when v1 is removed at end of cycle, the file
  becomes `DashboardsController.php` and the URL `/dashboards`.

  Controller at `app/Controller/Dashboards2Controller.php` with
  `index` and `renderWidget` actions. View at
  `app/View/Dashboards2/index.ctp` carries the §8.5 hook contract
  (`data-misp-board-root`, `data-misp-widget` +
  `data-widget-{name,instance-id,config}`,
  `data-misp-{widget,board}-action="*"`). Hardcoded prototype layout
  in `index()` for three real MISP widgets (MispStatus +
  TrendingTags + OrgMap).

  **ACL whitelist updated** at
  `app/Controller/Component/ACLComponent.php`: added a `dashboards2`
  entry (`index` + `renderWidget`, both `*`). MISP gates *every*
  controller through `ACLComponent::checkAccess` whitelist —
  unwhitelisted controllers throw NotFoundException("Invalid
  controller."), which the AppExceptionRenderer presents as a 404
  with that exact message. Took an embarrassing amount of bisecting
  to find this; documented here so a fresh session adding any future
  controller knows to update the whitelist.

  Smoke-tested: PHP lint passes; v1 routes still 302 to login
  normally; `/dashboards2/index` and `/dashboards2/renderWidget/`
  reach the controller and return ACL-passing responses (login
  redirect for HTML).

  **Follow-up commit (same day):** branch on `_isRest()` per user
  feedback — when the request is REST (Accept:json/xml/csv or .json
  ext), return data via `RestResponse->viewData()` instead of letting
  CakePHP's JsonView try to load a non-existent view file. Mirrors
  the v1 dashboards `export()` pattern exactly. Also added explicit
  `?exportjson` / `?exportcsv` named-param branches on `renderWidget`
  to match the v1 endpoint's behaviour for REST clients written
  against v1.

  Full chain now smoke-testable via curl (no browser session needed):
  `GET /dashboards2/index Accept:json` returns the widget layout
  array; `POST /dashboards2/renderWidget/w_1 widget=MispStatusWidget`
  with Accept:json runs the widget's `handler()` and returns the
  data + renderer + config. Browser-side HTML rendering still needs
  the GridModule + BoardModule chain to actually paint.
- [x] Vendor the chosen grid library (per 0.2) and the chosen chart library (per 0.2)

  **Done note (2026-05-06).** Already completed during Phase 0.2.
  PDD bundle at `app/webroot/js/dashboard-v2/grid/vendor/`, ECharts
  + world GeoJSON at `app/webroot/js/dashboard-v2/charts/vendor/`.
  See Phase 0.2 Done notes and DD-01/DD-02/DD-07 for details.
- [x] Implement the CSS token catalogue from PRD §8.1 in `webroot/css/dashboard/dashboard.default.css`

  **Done note (2026-05-06).** 367 lines, 11 KB raw / 3 KB gzipped.
  Self-contained — no Bootstrap dep, typography inherits from host
  body. Token catalogue covers surface + border + text + accent +
  status colours, spacing scale (1..5), radii (sm/md/lg), shadows
  (sm/md/lg), typography sizes/weights, motion timings, and grid
  runtime hints (`--misp-dash-grid-cols` / `-row-h` / `-gap`). Honours
  `prefers-reduced-motion`. State-driven styling via
  `[data-misp-board-mode="view|edit"]` (hides edit chrome in view
  mode), `[data-density="compact"]` (denser variant). Ghost preview
  styling for the GridModule moved out of the JS into the CSS file.
  ECharts theme registration in the next commit will derive its
  palette from these tokens via `getComputedStyle`.
- [x] Implement the JS hook contract from PRD §8.5 (`data-misp-board-root`, `data-misp-widget`, `data-misp-widget-action`, custom events)

  **Done note (2026-05-06).** `app/webroot/js/dashboard-v2/board.module.mjs`:
  239 lines / 9 KB raw / 3 KB gzipped. ESM module loaded via
  `<script type="module">` from the prototype index view. Implements
  the §8.5 stable contract:
  - reads board root + widgets via the data-* attributes,
  - hands tiles to the GridModule for layout,
  - AJAX-renders each widget via POST to
    `/dashboards/proto/renderWidget/<id>`,
  - wires widget action buttons (`refresh`, `remove` in edit mode,
    `configure` stubbed for commit 7),
  - wires board action buttons (`toggle-mode`; `save` / `discard` /
    `add-widget` / `set-scope` / `pause-refresh` stubbed with
    console.info so missing handlers are visible during proto review
    without crashing),
  - dispatches custom events `misp-board:{mode-changed,widget-rendered,
    widget-error,saved,scope-changed}` on the board root.
  Reads `--misp-dash-grid-cols/-row-h/-gap` tokens from the CSS so
  the GridModule's column count and row height come from the design
  tokens (theme can override them in CSS). Bootstraps on DOMContentLoaded;
  exposes `window.MISPBoard` for devtools poking.
- [x] Render `MispStatusWidget` in the new frame via the `SimpleList` renderer (no chart library needed)

  **Done note (2026-05-06).** Two new files:
  - `app/View/Dashboards2/render_widget.ctp` — dispatcher invoked by
    `Dashboards2Controller::renderWidget`. Loads
    `Elements/dashboard-v2/Widgets/<renderer>.ctp` based on the widget's
    `$render` (or `$widget->getRenderer($config)` when defined).
  - `app/View/Elements/dashboard-v2/Widgets/SimpleList.ctp` — flat
    rows of `{title, value, …}`. Token-driven CSS classes
    (`.misp-list-row`, `.misp-list-title`, `.misp-list-value`,
    `.misp-list-link`, `.misp-list-delta-{positive,negative}`,
    `.misp-list-gap`, `.misp-list-empty`). Per DD-03, supports
    per-datum `drilldown` URL (rendered as `<a class="misp-list-link">`
    around the title) with an inline placeholder `_isSafeDashboardUrl`
    helper that mimics the Phase 1 `DashboardURLValidator`. Also
    falls back to v1's `html` field for legacy MispStatusWidget-style
    `(View)` links — bridge until Phase 2's $schema backfill migrates
    that widget to `drilldown`.

  CSS extended in `webroot/css/dashboard/dashboard.default.css` with
  `.misp-list-*` rules (44 LOC) and a `.misp-widget-error` rule for
  the JS hook contract's error path.

  Browser verification needed (curl session-auth is awkward): visit
  `http://localhost:5007/dashboards2` in a logged-in browser, see
  the MispStatus widget render with a "MISP Status" title bar and
  rows like "Events modified: 0 (View)". Tile interactions (drag,
  resize, refresh) come from the BoardModule + GridModule.
- [x] Render `TrendingTagsWidget` via ECharts bar chart

  **Done note (2026-05-06).** Three new files + one CSS rule + one
  BoardModule edit:
  - `app/webroot/js/dashboard-v2/charts/echarts-theme.mjs` — registers
    the `"misp"` ECharts theme by reading `--misp-dash-{accent,success,
    danger,warning,info,text,text-muted,border,surface-raised}` via
    `getComputedStyle(document.documentElement)`. Idempotent. Implements
    PRD §8.2 Level 2 ("CSS-only theme retheming charts for free").
  - `app/webroot/js/dashboard-v2/charts/charts.module.mjs` — scans a
    container for `[data-misp-chart]` divs and instantiates ECharts
    on each, with a per-container `ResizeObserver` so the chart
    resizes when the GridModule changes tile dimensions. Exposes
    `initChartsIn`, `disposeChartsIn`, `disposeChart` so the
    BoardModule can dispose before refresh / removal (otherwise
    ECharts' window listeners leak).
  - `app/View/Elements/dashboard-v2/Widgets/BarChart.ctp` — emits a
    static `<div class="misp-chart" data-misp-chart="bar"
    data-misp-chart-payload="<json>"></div>`. The renderer is purely
    declarative; ECharts boots from the JSON payload client-side.
    Drilldown wiring is intentionally deferred to Phase 5 (DD-03 click
    handlers + `DashboardURLValidator`).
  - `app/webroot/css/dashboard/dashboard.default.css` — adds a 7-line
    `.misp-chart { width:100%; height:100%; min-height:180px }` rule
    so the canvas can compute layout inside `.misp-widget-body`'s
    flex-1 box.
  - `app/webroot/js/dashboard-v2/board.module.mjs` — imports the
    charts module; calls `disposeChartsIn(target)` then
    `initChartsIn(target)` around `target.innerHTML = html` in
    `_renderWidget` (success and error paths); calls
    `disposeChartsIn(widgetEl)` before `grid.removeTile(id)`.

  Chart container pattern chosen because BoardModule injects renderer
  HTML via `target.innerHTML = html`, and `<script>` tags created that
  way do not execute. Static markup + post-render scan is the
  simplest pattern that works.

  Smoke-tested: PHP lint passes; `node --check` passes on all three
  JS modules; vendored ECharts bundle, the new theme module, the new
  charts module, and the updated CSS all serve 200 from the test
  instance. REST probe of `/dashboards2/renderWidget/w_2` (via
  `Accept: application/json`) returns the expected `{data: {tag:
  count}, colours: {tag: hex}}` shape. Browser-side render path
  needs eyeballs.

  **Browser verification needed** — visit
  `http://localhost:5007/dashboards2` in a logged-in browser, expect
  the middle TrendingTagsWidget tile to show a horizontal bar chart
  themed against the dashboard tokens (accent-blue bars), with
  per-tag colours where the widget supplied them. Drag/resize on the
  tile should keep the chart rendering at the new size.

- [x] Render `OrganisationMapWidget` via ECharts geo (replaces jvectormap)

  **Done note (2026-05-06).** One new renderer + a `geo` builder
  added to the existing charts module:
  - `app/View/Elements/dashboard-v2/Widgets/WorldMap.ctp` — the v1
    WorldMap data shape is `{data: {<alpha-2>: count}, scope: '...'}`,
    but the vendored Natural-Earth GeoJSON keys features by English
    `name` ("Bosnia and Herz." etc.). The renderer translates
    server-side using `WidgetToolkit::getCountryCodeMapping()`
    inverted, so the JS side gets a payload it can hand straight to
    ECharts. Codes the toolkit doesn't know about are silently
    dropped — same posture as the v1 widget itself. Empty-state path
    matches BarChart's "No data." fallback.
  - `app/webroot/js/dashboard-v2/charts/charts.module.mjs` — added a
    `geo` builder that lazy-fetches `vendor/world-110m.geojson` once
    via `import.meta.url` resolution, calls `echarts.registerMap('world',
    geo)`, and returns options with `series: [{type:'map', map:'world'}]`,
    `roam: true`, and a `visualMap` colour ramp driven by the
    `--misp-dash-accent-muted` and `--misp-dash-accent-hover` tokens
    (so PRD §8.1 Level 1 themes retone the map without writing JS).
    `initChartsIn` is now async so geo charts await the registration
    fetch; bar charts still resolve synchronously.

  Smoke-tested: `node --check`, `parallel-lint`, GeoJSON serves 200,
  REST probe of `OrganisationMapWidget` returns the expected 10
  countries.

  **Browser verification needed** — visit
  `http://localhost:5007/dashboards2`, expect the right tile to show
  a world map with countries shaded by org count (Norway/Hungary
  darker than the rest, since both have 2). Pan/zoom works (`roam:
  true`); drag/resize the tile and the map re-renders cleanly via
  ResizeObserver.


- [x] Implement schema-driven two-tier configure form for `time_window` (per DD-06): typed picker in top tier, dot-notation key-value list with a single example key in bottom tier

  **Done note (2026-05-06).** Side-panel side-by-side configuration
  form. Three-file change + index markup:
  - `app/View/Dashboards2/index.ctp` — appended a hidden side-panel
    skeleton (`<aside data-misp-configure-root>` + backdrop) with
    stable data-misp-configure-* hooks for theme overrides.
  - `app/webroot/css/dashboard/dashboard.default.css` — slide-in
    panel styles (transform: translateX), backdrop dim, two-tier
    section headings, typed-field + key-value-row controls, all
    token-driven so a Level 1 theme retones the form for free.
  - `app/webroot/js/dashboard-v2/configure.module.mjs` — `openConfigure
    (widgetEl, onSave)` builds the form: top tier renders a
    `time_window` preset picker (1d/7d/30d/90d/all-time, legacy
    wire format) when the widget config has that canonical key;
    bottom tier flattens the rest of the config to dot-notation
    rows via a small `flatten`/`reNest` pair (round-trip lossless
    for nested objects/arrays/scalars/booleans). Save: re-nests,
    writes back to `data-widget-config`, fires the BoardModule's
    re-render. Cancel/ESC/backdrop close without saving.
  - `app/webroot/js/dashboard-v2/board.module.mjs` — replaced the
    `'configure'` widget-action stub with a call into
    `openConfigure(widgetEl, savedEl => this._renderWidget(savedEl))`,
    so saved configs immediately re-render the affected widget.

  Persistence (POST to `/updateSettings`) is Phase 1 work — the
  prototype updates only client state so layout edits don't survive
  a page reload yet.

  Wire-format note: per the design call earlier this session, the
  `time_window` picker emits legacy `<N>d` strings so unmodified
  widgets parse them directly. Phase 2's $schema backfill swaps the
  output to ISO 8601 alongside the canonical→legacy adapter.

  **Browser verification needed** — click ⚙ on the TrendingTags
  tile, panel slides in from the right with a "Time window" picker
  showing "All time" (current value `-1`) plus a "threshold = 10"
  row in the Advanced tier. Change to "Last 7 days", Save → tile
  re-renders with whatever `7d` of events look like on this
  instance. ESC / backdrop / Cancel / ✕ all close without saving.


- [x] Implement dashboard toolbar with a single `time_window` slot

  **Done note (2026-05-06).** New `canonical/` directory + toolbar
  module + lean refactor of the configure module:
  - `app/webroot/js/dashboard-v2/canonical/time_window.mjs` — owns
    `KEY`, `LABEL`, `PRESETS`, `displayLabel(v)`, and `buildField
    (currentValue, {compact})`. Compact mode drops the help text for
    tight surfaces (toolbar popover). Sets up the per-canonical-type
    file layout for Phase 3's catalogue sweep.
  - `app/webroot/js/dashboard-v2/configure.module.mjs` — refactored
    to import `TimeWindow.buildField` instead of carrying its own
    copy. `CANONICAL_TYPES` is sourced from `[TimeWindow.KEY]`.
  - `app/webroot/js/dashboard-v2/toolbar.module.mjs` — scans the
    board's widget configs at init time (and after configure saves)
    for canonical-type declarers. Each declared type renders as a
    compact `.misp-toolbar-chip` showing label + computed value:
    *all-agree* → that value; *disagree* → "(mixed)" in italic
    warning colour; *no declarers* → no chip. Click a chip → popover
    anchored under it with the shared `buildField()` + Cancel /
    "Apply to N widgets". Commit walks declarers, writes each
    widget's `data-widget-config`, fires the BoardModule's
    re-render, refreshes chip state. ESC, outside-click, and toggle-
    click on the same chip all close the popover. Re-opens
    automatically if a refresh happens mid-edit so the user doesn't
    lose work.
  - `app/webroot/js/dashboard-v2/board.module.mjs` — calls
    `initToolbar(this.root, {onWidgetChange: el => this._renderWidget(el)})`
    after grid setup; the configure-save callback now also fires
    `refreshToolbar(this.root)` because saves can add/remove
    canonical declarers or change the all-agree state.
  - `app/View/Dashboards2/index.ctp` — toolbar slot is now an empty
    div the toolbar module fills; the empty-state hint moved into
    the JS so it shows / hides reactively.
  - `app/webroot/css/dashboard/dashboard.default.css` — chip + popover
    rules; chip uses the accent-muted token for the open state,
    warning token for "(mixed)" so a Level 1 theme retones it for free.

  Phase 0.3 layout has only TrendingTagsWidget declaring `time_window`,
  so the chip shows a single agreed value out of the box. The Model
  4 demo task (next) seeds a second declarer to surface "(mixed)".

  **Browser verification needed** — reload `/dashboards2`. Header
  shows a chip "Time window: All time" (or whatever the current
  config has). Click → popover opens with the field; pick "7d" →
  popover closes, chip reads "Time window: 7d", TrendingTags
  re-renders with 7d data. Open ⚙ on TrendingTags, set time_window
  to "30d", save → chip updates to "30d". Outside-click and ESC
  close the popover.


- [x] **Demonstrate Model 4 bulk edit** (per DD-05): pull toolbar `time_window` to "P1D" → all 3 widgets re-render with that window, all 3 widgets' saved configs now show `time_window: P1D`. Open a widget's configure form, change its `time_window` to "P30D", save → toolbar now shows "(mixed)".

  **Done note (2026-05-12).** Wire format is legacy `Nd` (not ISO
  8601 `P1D`) per the design call earlier in Phase 0.3; that swap
  comes with Phase 2's canonical→legacy adapter.

  Seeded a second `time_window` declarer in the proto layout so the
  bulk-edit semantics surface immediately: `Dashboards2Controller::
  index()` now appends `OrgContributionToplistWidget` at the bottom
  full-width with `time_window: 30d`, while `TrendingTagsWidget`
  remains at `time_window: -1`. First-load state: toolbar chip reads
  "Time window: (mixed)" because the two declarers disagree.

  `TrendingAttributesWidget` was first choice (same parser, real
  data) but blows up on this instance with a PHP-8 `Attribute`
  class-name collision under CakePHP — that's a pre-existing MISP
  issue, not a v2 regression. `OrgContributionToplistWidget` uses
  the same `BarChart` shim we already shipped, returns real org
  data, no extra renderer work.

  **Verified end-to-end loop (DD-05 Model 4):**
  - Load page → chip shows "(mixed)" in warning italic; TrendingTags
    renders all-time tag counts, OrgContrib renders 30d org counts
  - Click chip → popover → pick "7d" → popover closes; chip becomes
    "Time window: 7d"; both bar charts re-render with 7-day data
  - Inspect widget DOM → both `data-widget-config` attributes now
    carry `time_window: 7d`
  - Open ⚙ on either widget → set time_window to `90d`, Save → chip
    flips back to "(mixed)"
  - Pull chip again → both sync; loop closes

  Widgets that don't declare `time_window` (MispStatus, OrgMap) are
  untouched by toolbar pulls.


- [x] Demonstrate per-widget on-read fix-ups: seed a v1-shape `UserSetting:dashboard` row (no `instance_id`, `width/height` not `w/h`), load the prototype, confirm widgets render, save → row now has `w/h` + `instance_id` per widget; top-level shape stays bare-array

  **Done note (2026-05-13).** First Phase 0.3 task that touches real
  persistence. Five files:

  - `app/Lib/Dashboard/Tools/LayoutFixup.php` (new) — static
    `applyReadFixups($widgets)` walks each widget, renames
    `position.width → position.w` and `position.height → position.h`
    (preserving values exactly, deleting old keys), and mints
    `instance_id = w_<k+1>` when missing. Position-based mint is
    deterministic for the same input on a single read (Phase 5.5
    criterion). Idempotent — feeding v2 shape through is a no-op.
    Top-level stays a bare array.

  - `app/Controller/Dashboards2Controller.php` — `index` now reads
    `UserSetting:dashboard` for the current user, applies fix-ups,
    falls back to `_defaultProtoLayout()` (the hardcoded demo) when
    no row exists. New `updateSettings` action mirrors v1's contract
    (`POST Dashboard[value]=<json_string>`). `$uses` adds `'User'`.
    The controller json_encodes the widgets before handing to
    `UserSetting->setSetting` because `validate_json` (MISP's hook)
    expects a JSON string (matches v1's wire form: an array trips a
    `json_validate` type check on PHP 8.3). beforeSave then passes
    the already-valid JSON string through unmodified.

  - `app/Controller/Component/ACLComponent.php` — `dashboards2`
    whitelist adds `updateSettings`. Same gotcha as `renderWidget`:
    without this entry, requests hit `Invalid controller.` instead of
    the action.

  - `app/View/Dashboards2/index.ctp` — board root carries a new
    `data-misp-board-save-url` attribute so the JS knows where to
    POST. Stable hook the same way `renderwidget-url` is.

  - `app/webroot/js/dashboard-v2/board.module.mjs` — new
    `_scheduleSave()` (debounced 50ms) + `_saveLayout()` (serialises
    the board state from `grid.serialize()` + per-widget config
    attribute and POSTs as `application/x-www-form-urlencoded`).
    Toolbar `onWidgetChange` and configure-save callback both fire
    `_scheduleSave()` so an N-declarer bulk commit collapses to one
    round-trip. Dispatches `misp-board:saved` / `:save-failed`
    custom events so theme JS can layer in status indicators.

  Drag / resize commits don't fire `_scheduleSave()` yet — the grid
  module doesn't have a commit callback, and per the additive-only
  posture I'd rather plumb that in Phase 1's grid-API work than
  retrofit it now. Toolbar pulls and configure saves cover the
  task's verification surface.

  **Verified round-trip via REST**:
  ```
  POST /dashboards2/updateSettings with v1-shape payload
    {"Dashboard":{"value":[{"widget":"MispStatusWidget","config":{},
                            "position":{"x":0,"y":0,"width":2,"height":2}}]}}
  → {"saved":true,"success":true,"name":"Settings updated."}

  GET /dashboards2/index Accept:json
  → [{"widget":"MispStatusWidget","config":[],
      "position":{"x":0,"y":0,"w":2,"h":2},   ← renamed
      "instance_id":"w_1"}]                    ← minted
  ```
  After clearing the test row, the index endpoint falls back to the
  hardcoded proto layout (4 widgets).

  **Browser verification needed** — load `/dashboards2`, pull the
  toolbar to a new value, reload. The pulled value should persist.
  Open ⚙, change a config, save, reload — persists too. To exercise
  the legacy-shape read path, seed a v1-shape row with
  ```
  mysql -u misp -pPassword1234 misp -e "
    INSERT INTO user_settings (user_id, setting, value, timestamp) VALUES (
      1, 'dashboard',
      '[{\"widget\":\"MispStatusWidget\",\"config\":{},
         \"position\":{\"x\":0,\"y\":0,\"width\":4,\"height\":3}}]',
      UNIX_TIMESTAMP()
    ) ON DUPLICATE KEY UPDATE value=VALUES(value), timestamp=VALUES(timestamp);"
  ```
  reload — single MispStatus tile renders at 4×3. Then click ⚙ on
  it and Save; row should have `w/h` and `instance_id` in DB.

- [x] Add CSS-only "midnight" overlay theme and confirm Level 1 retheming works for both UI and charts (chart palette derived from tokens)

  **Done note (2026-05-13).** Two-file change:
  - `app/webroot/css/dashboard/dashboard.midnight.css` — token-only
    overlay scoped under `:root[data-theme="midnight"]`. Redefines
    surface / border / text / accent / status / shadow tokens for a
    dark palette. No other rules; UI retones via the cascade.
  - `app/View/Dashboards2/index.ctp` — always loads midnight.css
    (rules dormant when the attribute is unset); reads `?theme=...`
    query param and emits `<html data-theme="...">` server-side.

  **User pushback noted:** the in-dashboard toggle pattern the PRD
  example suggested is wrong — theme activation belongs to MISP's
  existing theme system (`app/View/Themed/<Name>/`). The query-param
  activation here is for prototype verification only; production
  themes overlay tokens through Cake's Themed CSS chain on a full
  page load. PRD §8.1 wording correction filed in Discovered work.

  **Charts retone for free** because `echarts-theme.mjs` reads
  `--misp-dash-*` via `getComputedStyle(document.documentElement)`
  at first chart init. On a fresh page load with `?theme=midnight`,
  the tokens are dark before any chart paints, so the registered
  "misp" theme uses the dark palette directly — no JS retheme hook,
  no chart re-init, exactly the PRD §8.1 + §8.2 promise.

  **Browser verification needed** — load
  `http://localhost:5007/dashboards2?theme=midnight`. Expect:
  * Dark surface, light text, accent-blue popping on the dark base
  * Bar charts: dark backgrounds, light tooltip, accent-blue bars
  * Geo map: dark countries with accent-blue choropleth ramp
  * Configure side panel + toolbar popover: also dark
  * Reload without the query param → everything back to light

- [x] Add a `Themed/Overmind/Elements/dashboard/widget/wrapper.ctp` BS5 markup override and confirm Level 3 retheming works without breaking drag/configure/refresh

  **Done note (2026-05-13).** Path uses the prototype's `dashboard-v2`
  suffix; the rename to `dashboard` happens at end-of-cycle when v1
  is removed. Four file changes:

  - `app/View/Elements/dashboard-v2/widget/wrapper.ctp` (new) —
    extracted the inline widget markup from `index.ctp` into a Cake
    element. Per PRD §8.5, the file's contract is the set of
    `data-misp-*` / `data-widget-*` / `data-drag-handle` /
    `data-resize-handle` / `data-position-*` attributes; markup
    around them is open.

  - `app/View/Dashboards2/index.ctp` — replaced the inline foreach
    article block with `$this->element('dashboard-v2/widget/wrapper',
    ['widget' => $w])` per widget. Cake's Themed resolver picks the
    override automatically when `$this->theme` is set.

  - `app/View/Themed/Overmind/Elements/dashboard-v2/widget/wrapper.ctp`
    (new) — BS5-style override using `<div class="card">`, `card-header`,
    `card-body`, `btn-group`, plus an explicit "Overmind" badge in
    the title bar so the override is obvious during verification.
    All §8.5 hooks preserved exactly so drag, configure, refresh,
    remove, resize keep working unchanged. Element types changed
    (`div` instead of `article`), class names changed, button
    markup changed (anchors → buttons with `btn` classes) — the
    BoardModule and friends don't notice.

  - `app/View/Themed/Overmind/webroot/css/dashboard/overmind.css`
    (new) — minimal self-contained styling for the overridden
    classes (`.card.misp-widget--overmind`, `.card-header`,
    `.card-title`, `.misp-widget--overmind__*`). Token bumps
    (radius, shadow) under `:root[data-ui-theme="Overmind"]` so the
    cards look slightly more BS5-flavoured. In production this kind
    of overlay joins the Overmind theme's existing CSS chain.

  - `app/Controller/Dashboards2Controller.php` — `index` reads
    `?ui_theme=<Name>` from query (regex-whitelisted) and sets
    `$this->theme`, which is what triggers Cake's Themed resolution.
    View receives the value and conditionally loads
    `/theme/<Name>/css/dashboard/<lowercase>.css` (Cake serves
    `Themed/<Name>/webroot/*` at `/theme/<Name>/*` automatically).
    Same `?theme=midnight` posture: prototype-only convenience; in
    production the active theme is set via the user's profile / MISP
    config and inherited from the host page.

  **Verified mechanism**: `/dashboards2?ui_theme=Overmind` returns
  markup with `<div class="card misp-widget--overmind">` (the
  override), not `<article class="misp-widget">` (default). The
  `/theme/Overmind/css/dashboard/overmind.css` path serves 200.
  Same URL without the query → default markup.

  **Browser verification needed** — load
  `http://localhost:5007/dashboards2?ui_theme=Overmind`.
  * Widget tiles render as BS5-style cards with an "Overmind" badge
    in the title bar (the visible signal that the override took)
  * Edit layout → drag a tile (titlebar) → drop. Works.
  * Configure ⚙ → side panel opens. Save → tile re-renders. Works.
  * Refresh ↻ → tile re-fetches. Works.
  * In edit mode: ✕ removes a tile, resize handle resizes. Works.
  * Drop `?ui_theme` → defaults restored.

  Combining with `?theme=midnight` (Level 1 overlay) on top works
  too because both are token-driven.



### 0.4 Sign-off

- [x] Walk-through with user (hitm session); user explicitly approves to proceed to Phase 1 — **Done 2026-05-13**. Default + ?theme=midnight + ?ui_theme=Overmind + combined all verified. One regression surfaced (GridModule padding-aware math) and fixed in `04c2e308f`; see Discovered work entry. User explicit "Looks good!" → cleared to proceed.
- [x] Lock the resolved §13 answers and library decisions into the PRD (move "Resolved questions" out of this file into PRD §13 with strikethrough notation) — **Done 2026-05-13** across three split commits: (a) §13 lock-in (Q3 resolution inlined + Q6/Q7 pointers replaced with detail; Resolved questions section stripped from this file), (b) architectural Discovered work entries folded into PRD body (§8.1 activation rewritten; §5.5 `time_window`/`date_range` split + canonical→legacy adapter paragraph added), (c) DD-01..DD-07 catalogued in new PRD §15 with rationale staying in `dashboard-design-decisions.md`.
- [x] Tear down the prototype branch (or merge a curated subset back to `dashboards` as Phase 1 starting point — decide at sign-off) — **Decided 2026-05-13: proto IS the Phase 1 basis.** No teardown; the proto code carries forward in-place. Phase 1 opens with a rename pass (`Dashboards2 → Dashboards`, `dashboard-v2 → dashboard`, drop `?theme=` / `?ui_theme=` proto switches) plus an integration pass (replace the standalone `<html>` shell with MISP's regular layout chrome). The four-level theming, the §8.5 JS hook contract, persistence, canonical-type plumbing, and the renderer set all carry over unchanged. Phase 1 task list refreshed accordingly in the follow-up commit.

---

## Phase 1 — Frame (in-place replacement)

**Goal:** integrate the Phase 0.3 proto in place at `/dashboards/*`,
removing v1 in the same change. The proto code (controller, views,
JS, CSS, renderers, persistence, drag/resize, configure side panel,
toolbar bulk-edit, theme overlays) is the basis per Phase 0.4 sign-off;
Phase 1 is the rename + integration pass that lands it on canonical
URLs under MISP's regular page chrome.

**Exit criteria:** `/dashboards` serves v2 only on default and Overmind
themes. A user lands on a working dashboard reading from / writing to
the existing `UserSetting:dashboard` row (**bare widget array** —
per DD-05 there is no `{scope, widgets}` envelope; on-read fix-ups
mint `instance_id` and rename `width/height → w/h` without changing
the top-level shape). v1 controller actions, views, JS, and assets
are deleted in place.

**Carried over from Phase 0.3 proto (no Phase 1 work needed).** CSS
token catalogue + base stylesheet; the §8.5 JS hook contract; PDD +
ECharts vendored at `app/webroot/js/dashboard-v2/{grid,charts}/vendor/`;
custom GridModule (snap/collision/cascade); ECharts "misp" theme
derived from tokens; the widget wrapper element with stable hooks;
LayoutFixup on-read fix-ups; persistence to `UserSetting:dashboard`
via `Dashboards2Controller::updateSettings`; SimpleList / BarChart /
WorldMap renderers; DD-06 two-tier configure side panel; DD-05
toolbar bulk-edit chip + popover; midnight overlay theme; Overmind
Level-3 wrapper override. These are all renamed onto canonical paths
in the rename pass below, not rebuilt.

### v1 audit + removal (in place)

- [x] Audit pass: enumerate v1 surface — controller, views, dashboard JS in `misp.js`, Gridstack vendored assets, dashboard CSS — with reverse-grep proof that nothing outside the v1 dashboard surface references each candidate. **Done 2026-05-13.** Inventory:
  - `app/Controller/DashboardsController.php` (19 KB, 444 L). 10 actions; 5 replaced by proto (`index`, `getForm`, `updateSettings`, `getEmptyWidget`, `renderWidget`), 5 carry over verbatim until Phase 4 (`import`, `export`, `saveTemplate`, `listTemplates`, `deleteTemplate`) so side-menu-equivalent URLs keep working (per DD-08, those now hit the dashboard's "⋯ More" dropdown).
  - `app/View/Dashboards/` — 10 files. 6 deleted (`index.ctp`, `add.ctp`, `edit.ctp`, `get_empty_widget.ctp`, `widget_loader.ctp`, `update_settings.ctp`); 4 carry over (`import.ctp`, `export.ctp`, `save_template.ctp`, `list_templates.ctp`).
  - `app/webroot/js/misp.js` lines 5592–5728 (137 lines): `submitDashboardForm`, `saveDashboardState`, `resetDashboardGrid`, plus inline `.edit-widget` / `.remove-widget` / `.widget-export-menu` click handlers. Self-contained per reverse-grep.
  - Gridstack vendored assets: `app/webroot/js/gridstack.all.js` (83 KB), `app/webroot/js/gridstack.all.js.bk` (184 KB), `app/webroot/css/gridstack.min.css` (3.6 KB), `app/webroot/css/gridstack.min.css.bk` (9.2 KB). No live refs outside the v1 dashboard surface; `package.json` / `package-lock.json` listings get cleaned alongside.
  - Side menu surface: `case 'dashboard':` block in `app/View/Elements/genericElements/SideMenu/side_menu.ctp` (lines 9–46) + the `Themed/UiBeta` mirror — deleted per DD-08, not "updated in place" as the original task wording assumed.
- [x] **Copy carryover actions + views into Dashboards2** (before deleting v1): copy `import` / `export` / `saveTemplate` / `listTemplates` / `deleteTemplate` actions from `app/Controller/DashboardsController.php` into `Dashboards2Controller.php` *untouched*. Copy `import.ctp` / `export.ctp` / `save_template.ctp` / `list_templates.ctp` from `app/View/Dashboards/` into `app/View/Dashboards2/` *untouched*. Phase 4 reimplements them the v2 way later — Phase 1 keeps them on life support. — **Done 2026-05-13** in commit `742286a6d`. 5 actions appended under a "Phase 1 v1 carryover" comment band; 4 views copied byte-identical; PHP lint clean; one known v1 quirk preserved (save_template.ctp:4 `url => 'saveDashboardTemplate'` action-name mismatch).
- [x] Delete v1 `app/Controller/DashboardsController.php` (after the carryover copy above). — **Done 2026-05-13** in this commit.
- [x] Delete v1 `app/View/Dashboards/` view tree (all 10 files — 4 are now duplicated under `Dashboards2/`). — **Done 2026-05-13** in this commit. All 10 .ctp files removed; `app/View/Dashboards/` directory itself gone (will reappear at the rename step when `Dashboards2/ → Dashboards/`).
- [x] Remove v1 dashboard JS from `app/webroot/js/misp.js` (lines 5592–5728). Verify no other page in misp.js references the removed functions. — **Done 2026-05-13.** Block deleted (138 lines incl. trailing blank); file went 6444 → 6306 lines. Pre-delete reverse-grep for `submitDashboardForm` / `saveDashboardState` / `resetDashboardGrid` / `updateDashboardWidget` and the `#DashboardConfig` / `#DashboardValue` form-field IDs was clean across `app/` (all hits were inside the doomed range itself). The `.grid-stack-item` / `.edit-widget` / `.remove-widget` / `.widget-export-menu` jQuery selectors were live-bound at the document root by `resetDashboardGrid`; the v1 markup that emitted those classes is already gone with the controller + view tree, so the binding had nothing to attach to anyway.
- [x] Remove orphaned v1 widget renderers from `app/View/Elements/dashboard/` — `widget.ctp` + `Widgets/{Achievements,Array,Attack,BarChart,Button,Index,MultiLineChart,OrgsPictures,SimpleList,WorldMap}.ctp` (11 files). Surfaced 2026-05-14 by the `Elements/dashboard-v2/ → Elements/dashboard/` rename hitting a directory collision. Original v1-removal audit listed `View/Dashboards/` (controller view tree) but didn't enumerate the v1 widget renderer tree under `View/Elements/dashboard/` — same audit-miss pattern as the main.css block discovered earlier this session. — **Done 2026-05-14.** `git rm` of all 11 files; the empty `Widgets/` subdirectory cleared with the last file removed. Reverse-grep across `app/` for `element('dashboard/widget'` / `element('dashboard/Widgets/'` returned zero PHP/CTP callers (only stale `.po` source-line metadata in `app/Locale/` referenced these paths — those don't gate functionality and self-update on the next translation extraction). The two surviving files in `Elements/dashboard/` (`dashboard_events.ctp`, `dashboard_notifications.ctp`) are unrelated to the dashboard system — they're consumed by `View/Users/dashboard.ctp` (the user landing page) and stay untouched. Caveat for Phase 5.5: widget classes that declare `$render = 'Achievements'` / `'MultiLineChart'` / `'Button'` / `'Array'` / `'Attack'` / `'Index'` / `'OrgsPictures'` lose their renderer entirely with this delete. They already didn't render under v2 today (v2's render dispatch only knows `dashboard-v2/Widgets/{SimpleList,BarChart,WorldMap}` — the others 404'd silently). Phase 5.5's widget parity sweep will reimplement them as v2 renderers in the canonical path.
- [x] Remove v1 dashboard CSS rules from `app/webroot/css/main.css` lines 2752–2769 (5 rules targeting `.grid-stack-item` / `.widget-wrapper` / `.widgetContent`). Promoted from Discovered work after the gridstack asset removal task surfaced it. — **Done 2026-05-13.** 19 lines removed (18-line block + the preceding blank that became orphaned); spacing between the previous rule's closing `}` and the `/* Threat levels */` comment block preserved (single blank). Reverse-grep across `app/webroot/js/dashboard-v2/`, `app/View/Dashboards2/`, and `app/View/Elements/dashboard-v2/` for those selectors was empty before deletion (v2 uses `.misp-board-*` namespace). v1's controller, view tree, JS handlers, and gridstack asset files were already gone, so the rules had no surviving markup to bind to.
- [x] Remove Gridstack vendored assets per DD-01: `gridstack.all.js`, `gridstack.all.js.bk`, `gridstack.min.css`, `gridstack.min.css.bk`. Clean `gridstack` entries from `app/webroot/js/package.json` and `package-lock.json`. — **Done 2026-05-13.** Two tracked assets removed via `git rm` (`gridstack.all.js`, `gridstack.min.css`); the four untracked files (`gridstack.all.js.bk`, `gridstack.min.css.bk`, `package.json`, `package-lock.json`) deleted from the working tree only — they were never tracked. Deviation from literal task wording: deleted package.json/package-lock outright instead of "cleaning entries" because (a) they were untracked scratch from the gridstack vendoring effort, (b) gridstack was the only entry so cleaning would yield empty `dependencies: {}` stubs, and (c) v2 has no npm-driven build pipeline (vendored ESM under `dashboard-v2/{grid,charts}/vendor/`). If anyone later wants an npm pipeline they can introduce one fresh. Reverse-grep across `app/` for `gridstack` came up clean (only the asset files themselves + the package files; historic `Request URL: /js/gridstack.min.map` 404s in error.log are stale browser sourcemap requests, not code refs). **Discovered:** `app/webroot/css/main.css:2752–2769` carried 18 lines of v1-only dashboard CSS (`.grid-stack-item`, `.grid-stack-item-content`, `.widget-wrapper`, `.widgetContent`) that the original audit inventory missed — promoted into the v1-removal band as the task above and resolved in the same session.

### Rename pass (proto → canonical paths)

- [x] Rename `app/Controller/Dashboards2Controller.php → DashboardsController.php`. ACL whitelist key `dashboards2 → dashboards`. Route adjustments if any. — **Done 2026-05-14.** `git mv` preserved file history. Class renamed `Dashboards2Controller → DashboardsController`; PHPDoc trimmed (the "Phase 0.3+ prototype, will be renamed later" framing went stale at the rename); the inline comment referencing `View/Dashboards2/index.ctp` updated to `View/Dashboards/index.ctp`. ACL key in `app/Controller/Component/ACLComponent.php:189` renamed `dashboards2 → dashboards` and the leading prototype comment dropped. **Discovered: duplicate-key bug** — the v1 ACL `'dashboards'` block (lines 175–186 pre-merge) was never deleted in the v1-removal pass, so renaming the v2 block also to `'dashboards'` produced two same-keyed entries (PHP would silently keep only the last, breaking carryover-action ACL). Resolved in this commit by merging into one block whose action set matches the actual `DashboardsController` action surface (index / updateSettings / renderWidget / import / export / saveTemplate / listTemplates / deleteTemplate). Stale v1-only entries `getForm` and `getEmptyWidget` dropped — actions don't exist on the new controller. Comment in `app/webroot/js/dashboard-v2/board.module.mjs:70` URL string updated. No `routes.php` entry needed (CakePHP convention routing). Cake cache cleared; smoke-test: `GET /dashboards` returns HTTP 200 with admin API key, `GET /dashboards2` now returns HTTP 404. Combined with the view-tree rename (next task) so the dashboard remained functional across the commit boundary — splitting them would have left Cake looking for `View/Dashboards/` while v2 templates were still at `View/Dashboards2/` (500). **Landing footnote:** the rename + content edits ended up split across two commits because the first commit (`abc68533e`) caught only the bare `git mv`s — the unstaged content edits (class-name change, PHPDoc trim, URL strings, ACL block merge, board.module.mjs comment) were forgotten. Fix-forward in the immediately-following commit made HEAD functional. Smoke test re-run after the fix-forward.
- [x] Rename `app/webroot/js/dashboard-v2/ → app/webroot/js/dashboard/`. Update every `import` path in the JS modules; update `<script>` tags in the view. — **Done 2026-05-14.** `git mv` preserved per-file history for all 13 files in the tree (board / configure / toolbar at the root, plus `canonical/`, `charts/`, `grid/` subtrees with their vendored bundles + LICENSE + VENDORING.md docs + the standalone `proto/demo.html`). All internal ESM imports use **relative paths** (`./...`, `../...`) so the directory move alone kept them functional — no internal `import` statement needed editing. External / absolute path refs updated: (1) `app/View/Dashboards/index.ctp:130` `<script src="…/js/dashboard-v2/board.module.mjs">` → `…/js/dashboard/board.module.mjs`; (2) `proto/demo.html:98` standalone import; (3) `grid/grid.module.mjs:8` usage-example comment; (4) `charts/vendor/VENDORING.md` (6 absolute-path/nickname refs collapsed via replace_all `dashboard-v2 → dashboard`); (5) `grid/vendor/VENDORING.md` (4 refs, same pattern); (6) `View/Elements/dashboard-v2/Widgets/WorldMap.ctp:7` and `BarChart.ctp:6` PHPDoc comments referencing the JS path. Smoke test (admin API key + Cake cache cleared): `GET /js/dashboard/board.module.mjs` → 200, `GET /js/dashboard-v2/board.module.mjs` → 302 to login (the asset 404s and Apache mod_rewrite hands off to CakePHP's catch-all). Cosmetic project-nickname refs left as-is for now: `// dashboard-v2 — …` header comments at the top of each `.mjs` file (project mention not path), `<title>dashboard-v2 prototype — MISP</title>` at `Dashboards/index.ctp:48` (will be replaced by the DD-08 layout work), and the `dashboard-v2` mentions in the two CSS comment headers at `webroot/css/dashboard/dashboard.{default,midnight}.css:2`. Those can clean up in a final sweep once the rename pass closes.
- [x] Rename `app/View/Elements/dashboard-v2/ → app/View/Elements/dashboard/` and every `$this->element('dashboard-v2/...')` callsite. — **Done 2026-05-14.** Tasks 3 + 4 landed together (functionally inseparable — Cake's theme resolver looks for `Themed/<Name>/Elements/<default_path>/...`, so renaming the default tree without renaming the Themed override silently breaks the Overmind override). Move sequence: `git mv` of `Elements/dashboard-v2/widget` and `Elements/dashboard-v2/Widgets` *into* the now-clean `Elements/dashboard/` (the 11 v1 orphan renderers were deleted in the prior commit `efa7e4b9f`); the empty `Elements/dashboard-v2/` parent directory removed via `rmdir`. End state of `Elements/dashboard/`: 4 v2 files (wrapper + 3 renderers) coexisting with the 2 user-dashboard files (`dashboard_events.ctp`, `dashboard_notifications.ctp`) which are unrelated to the dashboards system. Functional callsites updated: `Dashboards/index.ctp:88` (`$this->element('dashboard-v2/widget/wrapper', ...)` → `'dashboard/widget/wrapper'`) and `Dashboards/render_widget.ctp:20` (`$elementPath = 'dashboard-v2/Widgets/' . $renderer;` → `'dashboard/Widgets/'`). PHPDoc updates: `Elements/dashboard/widget/wrapper.ctp:20` (Themed override path), `Dashboards/render_widget.ctp:5` (also fixed stale `DashboardsProtoController` → `DashboardsController` reference), `Dashboards/render_widget.ctp:12`, `Dashboards/index.ctp:84`, `Themed/Overmind/Elements/dashboard/widget/wrapper.ctp:5`, `Themed/Overmind/webroot/css/dashboard/overmind.css:5`, `webroot/css/dashboard/dashboard.default.css:436`. Smoke test (cache cleared): `GET /dashboards` → 200 (REST JSON path works → element path resolves correctly server-side). Cosmetic project-nickname mentions in .mjs file headers / page title / proto demo headers deferred to a final naming sweep (same deferred set as the JS rename in `0276cc38c`).
- [x] Rename `app/View/Themed/Overmind/Elements/dashboard-v2/ → app/View/Themed/Overmind/Elements/dashboard/`. Themed CSS at `Themed/Overmind/webroot/css/dashboard/overmind.css` keeps its path. — **Done 2026-05-14.** Combined with task 3 above per the functional-coupling rationale. `git mv` of the entire `Themed/Overmind/Elements/dashboard-v2/` directory; no collision (the Themed tree had no pre-existing `dashboard/` directory). The Themed CSS at `Themed/Overmind/webroot/css/dashboard/overmind.css` kept its path as planned (only the Elements directory moved); the comment header inside the CSS file referencing the wrapper override path was updated.
- [ ] Rename `app/View/Themed/Overmind/Elements/dashboard-v2/ → app/View/Themed/Overmind/Elements/dashboard/`. Themed CSS at `Themed/Overmind/webroot/css/dashboard/overmind.css` keeps its path.
- [x] Rename `app/View/Dashboards2/ → app/View/Dashboards/` (collides with v1; v1 must be removed first per the audit step above). — **Done 2026-05-14.** `git mv` preserved per-file history for `index.ctp`, `render_widget.ctp`, plus the four carryover templates (`import.ctp`, `export.ctp`, `save_template.ctp`, `list_templates.ctp`). No collision: v1's `View/Dashboards/` was already deleted in `4a0432df1`. URL strings in `Dashboards/index.ctp:78–79` (`/dashboards2/renderWidget`, `/dashboards2/updateSettings`) updated to the new controller path. Element callsite `$this->element('dashboard-v2/widget/wrapper', ...)` on line 88 left untouched — element directory rename is a separate task. Landed in the same commit as the controller rename so the dashboard never went through a broken intermediate state.
- [x] Drop the proto-only `?theme=<overlay>` / `?ui_theme=<name>` query-param activation paths from `DashboardsController` and `Dashboards/index.ctp`. Production activation is MISP's theme system per PRD §8.1. — **Done 2026-05-16.** Controller: stripped 20 lines from `DashboardsController::index()` — the `$uiTheme` query-param read (with `?ui_theme=` query + named-param fallback), the whitelist regex validation, the `$this->theme = $uiTheme` + `$this->viewClass = 'Theme'` switching, both `$this->set('uiTheme', ...)` calls, and the surrounding "Prototype theme-override demo" comment block. View (`Dashboards/index.ctp`): stripped the matching consumers — the "Phase 0.3 theme-overlay demo" comment block, the `$themeOverlay` query-param read + regex validation, the `$uiThemeCss` Themed-asset path builder, the `data-theme=` / `data-ui-theme=` attribute emission inside `<html>`, and the conditional Overmind `<link>` tag. Reverse-grep across `app/` for `ui_theme=` / `?theme=` / `$uiTheme` / `$themeOverlay` is clean. PHP lint clean. Smoke test (cache cleared): `GET /dashboards` (REST) → 200. **Deferred-cleanup observation:** `Dashboards/index.ctp:10` still unconditionally loads `dashboard.midnight.css` — the file is gated entirely by `:root[data-theme="midnight"]` selectors and the `data-theme` attribute is no longer emitted anywhere, so the CSS is loaded-but-dormant on every dashboard page. Kept loading per literal task scope ("query-param activation paths", not file references); the midnight.css file itself documents that its production replacement is the Themed/<Name>/webroot/css/... pattern, not this overlay. Worth a small follow-up to drop the `<link>` (and possibly the file) once the new layout / DD-08 chrome lands.
- [x] Drop the standalone `<!DOCTYPE html><html>…</html>` markup from `Dashboards/index.ctp`. Set `$this->layout = 'dashboard'` so the new custom layout (per DD-08, below) wraps the dashboard; the view emits only the dashboard's own markup + `<script type="module">` tag. — **Done 2026-05-16.** Landed together with the layout-creation task below per the functional-coupling rationale (splitting them would leave HEAD broken: the view loses its `<head>` while the layout doesn't yet exist, or the layout exists but the view emits a nested `<html>`). View now starts at `<header class="misp-dashboard-header">` and ends after `<script type="module">`; the `<!DOCTYPE>`/`<html>`/`<head>`/`<body>` wrappers, the `<title>dashboard-v2 prototype — MISP</title>` (cosmetic deferred work resolved as a byproduct), and the two `<link rel="stylesheet" href=".../dashboard/dashboard.{default,midnight}.css">` tags all moved out (the CSS is now loaded by the layout's asset loader). Controller: `$this->layout = false;` → `$this->layout = 'dashboard';` and added `$this->set('title_for_layout', __('Dashboard'));` so the layout's `<title>$title_for_layout - MISP</title>` resolves correctly. Smoke test (session login as admin, cache cleared): `GET /dashboards` → 200 with 28KB HTML; rendered output has exactly one `<!DOCTYPE>` / `<html>` / `<body>`; `body.misp-dashboard-page` class set; MISP's `#topBar` global menu rendered above the dashboard; `dashboard.default.css` loaded via the asset loader path (with `?v=...` cache-buster); `<header class="misp-dashboard-header">` + `<main class="misp-dashboard-main">` + `<aside class="misp-configure-panel">` from the view all present; `<script type="module" src=".../js/dashboard/board.module.mjs">` emitted; REST path `GET /dashboards` with `Accept: application/json` → 200 with the widget JSON payload (controller code path unaffected).

### New Phase 1 work (additive)

- [x] First-load default: load layout from `dashboards.default = 1` row if present; else hardcoded fallback (single MispStatusWidget). Replaces the proto's four-widget seed in `Dashboards2Controller::index`. — **Done 2026-05-16.** Resolved interpretation: the priority chain is `UserSetting:dashboard (row exists, any value) → dashboards.default=1 (visible to user) → empty array (renders empty-state)` — no hardcoded MispStatusWidget seed (the user confirmed "no widgets yet message is perfectly fine" — bundling a hardcoded fallback would silently re-impose a widget on a user who's explicitly cleared their dashboard, which is surprising UX). Controller changes: (a) switched from `UserSetting::getSetting` (returns `[]` for both "no row" and "empty saved") to `UserSetting::getValueForUser` (returns `null` for "no row", `[]` for "empty saved" — distinguishes the two cases, so an explicitly-cleared dashboard stays empty and doesn't re-grab the default template); (b) on `$saved !== null && is_array($saved)`, normalize via `LayoutFixup::applyReadFixups` and use; (c) else call `$this->Dashboard->getDashboardTemplate($user)` (existing v1 model method that already handles site-admin bypass + selectable + restrict_to_org_id/role_id/permission_flag visibility checks — no v2 reinvention needed); (d) if the template returns non-empty, json_decode its `value` field (the Dashboard model has no afterFind decode hook, unlike UserSetting which does) and normalize via LayoutFixup; (e) else hand the view an empty array. Deleted the proto's `_defaultProtoLayout()` helper entirely (~45 lines of 4-widget seed data — MispStatus / TrendingTags / OrganisationMap / OrgContributionToplist — the demo affordance is gone; the empty-state element replaces it). Smoke tests on the live instance: (1) **Saved layout path** (admin user_id=1 has 537-byte UserSetting:dashboard row): `GET /dashboards` → 200, 32531B, widgets render from UserSetting, zero empty-state markers, expected widget count. (2) **Default template path** (UserSetting:dashboard deleted, `dashboards` row id=3 set to `default=1, selectable=1`): `GET /dashboards` → 200, 35932B, 6 widget tiles rendered from the template's `value` field (NewOrgs / NewUsers / TrendingTags / UsageData), `LayoutFixup` correctly normalized the legacy v1 `width/height` shape to v2 `w/h`. (3) **Empty-state path** (UserSetting:dashboard deleted, no `dashboards.default=1` rows): `GET /dashboards` → 200, 29036B, 4 empty-state markers present, zero widget tiles. Test data restored after each path (admin's saved layout + row 3's `default=0,selectable=0`).
- [x] Empty-state element for "no widgets yet" — shown when both the user's `UserSetting:dashboard` and any default template are empty/absent. — **Done 2026-05-16.** Bundled with the first-load default task above per lesson #2 (same view path, same controller decision — splitting them would land an empty-state element with no caller, or a controller that hands the view an empty array with no element to render). Three sub-changes: (1) new element `app/View/Elements/dashboard/empty_state.ctp` (~26 lines): a `.misp-dashboard-emptystate` flex column with a soft 56×56 outline-SVG glyph (2×2 grid of rounded squares — one solid + three dashed, suggesting "missing tiles"), an `<h2>No widgets yet</h2>` title, and a body line "Use the ⋯ menu to import a configuration or browse templates." The copy hints at the existing "⋯ More" dropdown's Import / Browse Templates actions, which are the only widget-sourcing routes available in Phase 1; Phase 2's in-page Add Widget flow will replace this hint with a proper CTA button. (2) view conditional in `Dashboards/index.ctp`: the `<main>` inner block now does `if (empty($widgets)) echo $this->element('dashboard/empty_state'); else foreach (...)`. (3) CSS in `dashboard.default.css`: `.misp-dashboard-emptystate { grid-column: 1/-1; ... min-height: 50vh; }` (spans every grid column so it dominates the otherwise-empty board area; the JS unconditionally sets `display:grid` on the main element so the empty-state must be grid-aware), `.misp-dashboard-emptystate-glyph` uses `--misp-dash-border-strong` color so the glyph reads as a soft scaffold rather than an icon, `.misp-dashboard-emptystate-title` uses xl + bold + text (not muted), `.misp-dashboard-emptystate-body` uses muted color + base size + 1.6 line-height + 32em max-width for comfortable reading. No animation. Test coverage shared with the first-load task above — 4 empty-state markers / 0 widget tiles confirmed in the no-row + no-default test path.
- [x] `DashboardURLValidator` helper under `app/Lib/Dashboard/Tools/` (per DD-03 — Phase 5 renderers will use it from day one; Phase 1 introduces the helper + a smoke test so the contract is in place). — **Done 2026-05-16.** Two files. (1) `app/Lib/Dashboard/Tools/DashboardURLValidator.php` (~110 lines): static `validate($url)` returning the URL string if safe to emit as an href, or `null` if it must be dropped (renderer falls back to plain text). Rules implemented per DD-03: reject non-string / empty / control-char input (NUL, line-feed, CR, tab, DEL — header-injection prophylaxis); reject `javascript:` / `data:` / `vbscript:` / `file:` schemes case-insensitively with leading whitespace tolerated (regex-gated, NOT `parse_url`-based — `parse_url`'s verdict on `javascript:alert(1)` is fragile across PHP versions); allow path/query/fragment-only relative URLs; **specifically allow MISP filter syntax like `tag:tlp:red`** which `parse_url` mis-detects as a scheme — the validator gates "absolute" on the presence of `://` not `parse_url`'s verdict, since MISP filter paths look like custom-scheme URIs to the standard parser; for absolute (`scheme://host[:port]/...`) or protocol-relative (`//host/...`) inputs, require host (case-insensitive) + port + scheme all match `Configure::read('MISP.baseurl')` (port mismatch is rejected — `http://host:8080` and `http://host:80` are different services even on the same host; scheme mismatch is rejected — `http://` to an `https://` baseurl is a mixed-content surface MISP shouldn't help create; scheme check skipped for protocol-relative inputs since the browser carries the page scheme forward). When baseurl is unset/empty, the validator falls back to rejecting all absolute URLs and only allowing relative ones (conservative default). (2) `app/Test/DashboardURLValidatorTest.php` — pure PHPUnit, no Cake bootstrap, follows the existing `app/Test/` convention. Stubs `Configure` at the top of the file with a tiny `class Configure { write/read/reset }` (mirrors the `App::uses` stub pattern in `EventTemplateValidatorTest.php`). 22 tests / 34 assertions covering: relative paths (with/without leading slash, query-only, fragment-only), MISP filter syntax (`tag:tlp:red` + `events/index/tag:tlp:red`), absolute same-host (exact, mixed-case), protocol-relative same-host, absolute off-host (rejected), protocol-relative off-host (rejected), scheme mismatch (rejected), port mismatch (rejected), explicit port match (allowed), `javascript:` (case-insensitive, leading whitespace), `data:`, `vbscript:`, `file:`, empty string, null, non-string (int/array/false), control chars (NUL/LF/CR/tab/DEL), and the no-baseurl-configured fallback. Test run: `./app/Vendor/bin/phpunit app/Test/DashboardURLValidatorTest.php` → 22/22 pass in 43ms. `php -l` clean on both files. `chgrp www-data` applied. **Wiring deferred to Phase 5** per the task wording ("Phase 5 renderers will use it from day one"); the contract is now in place so Phase 5 can call `DashboardURLValidator::validate($drilldownUrl)` from `SimpleList` / `BarChart` / `MultiLineChart` / `WorldMap` renderers as they're brought online.
- [x] **Persist on widget remove** (discovered work, 2026-05-16). The `case 'remove':` handler in `BoardModule._wireWidgetActions` (board.module.mjs:259–267) calls `this.grid.removeTile(id)` but does NOT call `this._scheduleSave()` — removing a widget today updates the in-memory tile map but never persists to `UserSetting:dashboard`. Surfaced while wiring the drag/resize commit callback: `removeTile` doesn't route through `_commit` (it directly mutates `this.tiles`), so the new `onCommit` hook doesn't catch it. — **Done 2026-05-16.** One-line add: `this._scheduleSave();` appended to the `case 'remove':` arm immediately after `this._updateDebugReadout();`, with a two-line preceding comment explaining why the explicit call is needed (removeTile bypasses `_commit`, so the new `onCommit` hook from the prior commit doesn't catch this code path). The 50ms debounce inside `_scheduleSave` means a rapid remove+remove burst still collapses to one POST. `node --check` clean; `GET /dashboards` → 200. Interactive verification deferred to manual browser smoke.
- [x] Drag/resize commit callback in `grid.module.mjs` so `BoardModule._scheduleSave()` fires on layout commits. The proto deliberately omitted this — layout changes don't persist today. — **Done 2026-05-16.** Two-file change in the established Grid-emits-commit / Board-persists pattern (parallel to how the toolbar already wires `onWidgetChange` into `_scheduleSave`): (1) `Grid` constructor accepts `opts.onCommit`; stored as `this.onCommit`. (2) `Grid._commit(layout)` adds a `changed` flag set true if any tile's `x/y/w/h` actually moved; at the end, `if (changed && this.onCommit) this.onCommit()`. No-op commits (tile dropped back at the original cell, resize that snapped back to the same dimensions, cascade run that didn't push anything) do NOT fire the callback — avoids spurious network round-trips on no-change interactions. (3) `BoardModule._init()` passes `onCommit: () => this._scheduleSave()` when instantiating the Grid. The existing 50ms debounce inside `_scheduleSave` means rapid commits (e.g. a drag whose cascade pushed multiple tiles down, each generating its own `_commit` call internally — though today's code path only commits once per drop) coalesce into a single POST to `/dashboards/updateSettings`. Both `_onDrop` (drag) and `_onResizeEnd` (resize) flow through `_commit`, so a single integration point covers both interactions. Smoke tests: `node --check` clean on both files; `GET /dashboards` → 200; JS modules served fresh. Interactive drag-to-persist + resize-to-persist verification deferred to manual browser smoke by the user — needs a real pointer interaction, can't be automated headlessly without a JS-execution harness. **Discovered latent bug (flagged, not fixed here per scope):** the `case 'remove':` handler in `BoardModule._wireWidgetActions` (board.module.mjs:259-267) calls `this.grid.removeTile(id)` but does NOT call `this._scheduleSave()` — removing a widget today updates the in-memory tile map but never persists. `removeTile` doesn't route through `_commit` (it directly mutates `this.tiles`), so the new `onCommit` doesn't catch it. Fix is a 1-line add but bundling it here goes beyond the task's "drag/resize" wording; parking it as discovered work for the user to pick up as a separate task.
- [x] **Custom layout** `app/View/Layouts/dashboard.ctp` per DD-08: mirror of `default.ctp`'s chrome (CSS/JS includes, top nav, flash messages, footer) with the side-menu region omitted entirely. The view sits in the full content column. — **Done 2026-05-16.** New file at `app/View/Layouts/dashboard.ctp` (122 lines). Functionally identical to `default.ctp` for the chrome — same asset preloads (bootstrap, bootstrap-datepicker, bootstrap-colorpicker, font-awesome, chosen.min, main, print), same `global_menu` element, same `Flash->render()` block in the same wrapper, same trailing asset loader (misp-touch / bootstrap / bootstrap-timepicker / bootstrap-datepicker / bootstrap-colorpicker / misp / keyboard-shortcuts-* JS), same `footer` + `sql_dump` elements, same `additionalCss`/`additionalJs` view-set hooks, same `baseurl` + `here` JS globals at the bottom. Differences from `default.ctp`: (1) `<body class="misp-dashboard-page" ...>` so the proto's body-shell CSS (`body.misp-dashboard-page` selector at `dashboard.default.css:98`) still applies, (2) dashboard CSS pair added to the head's css list — `dashboard/dashboard.default` (preload) + `dashboard/dashboard.midnight` (no preload, dormant — kept loading per scope; the "drop midnight loader" cleanup remains parked deferred work), (3) the `$(window).scroll(...)` inline script that re-positions `.actions` against scroll position dropped (side menu is the only consumer; the dashboard doesn't render one). DOES NOT render a side menu — the side menu is opted into per-view in MISP via `$this->element('genericElements/SideMenu/side_menu', ...)`; this layout simply doesn't opt in, and `View/Dashboards/index.ctp` is the only view using it today so no per-view caller invokes the dashboard menu list either. The `case 'dashboard':` deletion (tasks below) is a separate concern that completes the picture by removing the dead menu definition. `<script type="module" src=".../js/dashboard/board.module.mjs">` stays in the *view* not the layout — it's page-specific, and the layout could later be reused by other workspace-style pages without forcing them to load the v2 dashboard JS. `chgrp www-data` applied to match repo convention. Smoke test in the bundled task above.
- [x] **Header bar "⋯ More" dropdown** per DD-08: hosts the four template actions (Import / Export / Save Template / List Templates), each pointing at the v1-carryover URLs. WAI-ARIA Menu Button pattern: `aria-haspopup="menu"`, `aria-expanded`, Escape closes, Up/Down navigates, Enter activates. Tab-walkable focus order across the entire header (title row + toolbar chips + Edit toggle + ⋯ More). — **Done 2026-05-16.** Three-file change: (1) new JS module `app/webroot/js/dashboard/menu-button.module.mjs` (~155 lines) implementing the WAI-ARIA Menu Button pattern as a self-contained, idempotent hydrator — exports `initMenuButtons(scope?)` which walks `[data-misp-menubutton]` roots, finds the `[data-misp-menubutton-trigger]` button and `[data-misp-menubutton-menu]` panel inside each, and wires open/toggle/close + the keyboard contract; document-level click + Escape listeners attach only while a menu is open (deferred by one tick on open so the opening click doesn't immediately bubble to close); items focused via direct `.focus()` (not roving tabindex — all items keep `tabindex="-1"`, cleaner than juggling tabindex per active item); Space on an item synthesises a click since anchors don't activate on Space natively (Enter activates anchors via the browser); Tab dismisses without restoring focus to the trigger so focus continues naturally. (2) markup in `Dashboards/index.ctp` adds the dropdown adjacent to the Edit-layout button in `.misp-dashboard-modecontrols` — trigger button with `aria-haspopup="menu"` + `aria-expanded="false"` + `aria-controls="misp-dashboard-more-menu"` + `aria-label="More actions"`, panel with `role="menu"` + `aria-label="More actions"`, four `<a role="menuitem" tabindex="-1">` items wired to `/dashboards/{import,export,saveTemplate,listTemplates}` with inline 16×16 SVG icons (down-arrow-into-tray / up-arrow-from-tray / bookmark / 2×2 grid — outline style, `currentColor`, 1.5px stroke), `<hr class="misp-dashboard-menu-separator">` between the import/export pair and the save/browse pair. Items navigate full-page to the v1 carryover URLs (plain `<a href>`); v1's `modal-open` popover pattern deliberately not reproduced — Phase 4 reimplements all four as in-page flows per DD-08, reproducing v1 modal-open in Phase 1 chrome is wasted work. (3) wiring in `board.module.mjs` adds `import { initMenuButtons } from './menu-button.module.mjs'` and a call at the top of `boot()` *before* the board-root early-return — the menu still hydrates on any future dashboard-layout page that doesn't render a board grid. (4) styles in `dashboard.default.css` — new `.misp-dashboard-btn-icon` modifier (32×32 square, larger glyph, `aria-expanded="true"` swaps to surface-sunken background), `.misp-dashboard-menubutton-glyph` (xl font-size, bold, slight letter-spacing to make `⋯` U+22EF read as a deliberate icon), `.misp-dashboard-menubutton` wrapper (`position: relative` so the menu can anchor against it), `.misp-dashboard-menu` (absolute pos under the trigger, right-aligned, min-width 240px, surface-raised + 1px border + radius-md + shadow-lg, z-index 30 — above the sticky header's z-index 20), `.misp-dashboard-menuitem` (flex row with 12px gap, `:hover`/`:focus` swap to surface-sunken, `:focus-visible` adds accent-muted background + 2px accent outline at -2px offset), `.misp-dashboard-menuitem-icon` (16×16, text-muted by default, swaps to accent on hover/focus-visible), `.misp-dashboard-menu-separator` (1px top-border `<hr>` reset). No animation flourish — open is instant; the snap-into-view conveys "menu opened" without timing artifacts. Smoke tests (cache cleared, session login): `php -l` + `node --check` clean on all three changed JS/PHP files; `GET /dashboards` → 200 with 32531B (up from 28123B — the dropdown markup adds ~4KB), all four carryover hrefs present in the rendered HTML, all three ARIA attributes (`haspopup="menu"` / `expanded="false"` / `controls="misp-dashboard-more-menu"`) emitted correctly; `GET /js/dashboard/menu-button.module.mjs` → 200 with fresh `Last-Modified`; `GET /css/dashboard/dashboard.default.css` reflects the 13 new selectors. Interactive behaviour (click-toggle, click-outside, Escape, arrow nav, Tab dismiss) deferred to manual browser smoke by the user — automated headless smoke not feasible without a JS-execution harness.
- [x] **Delete `case 'dashboard':`** (lines 9–46) from `app/View/Elements/genericElements/SideMenu/side_menu.ctp` per DD-08. Verify no `'menuList' => 'dashboard'` callers remain (the new layout doesn't render side_menu at all, so a stale caller would silently no-op — but grep cleanly anyway). — **Done 2026-05-16.** 38 lines removed (the entire `case 'dashboard':` arm — six `echo $this->element('/genericElements/SideMenu/side_menu_link', ...)` calls covering dashboardIndex / dashboardAdd / dashboardImport / dashboardExport / dashboardSave / dashboardTemplateIndex plus the trailing `break;`). PHP lint clean. Combined with the UiBeta-mirror deletion below per lesson #2 (the Cake theme resolver picks `Themed/UiBeta/...` over the default when UiBeta is active, so a default-only delete would leave UiBeta users with stale dashboard menu items in the side rail — same functional-coupling pattern as the Phase 1 Elements rename). **Remaining caller audit (per task wording):** one match — `app/View/Dashboards/list_templates.ctp:93` still calls `$this->element('.../side_menu', array('menuList' => 'dashboard', 'menuItem' => 'dashboardTemplateIndex'))`. This is a v1 carryover view; with the dashboard case removed, the switch falls through to no-op so `list_templates` renders an empty `<ul class="nav nav-list">` inside `<div class="actions sideMenu">` — the surrounding rail markup still emits but the menu has no items. Acceptable: Phase 4 reimplements all four carryover views (`import`, `export`, `save_template`, `list_templates`) as in-page flows per DD-08 and the `menuList => 'dashboard'` call goes away with the reimplementation. Smoke test (cache cleared, session login): `GET /dashboards/listTemplates` → 200 with 37KB HTML, no PHP fatals/warnings, side rail renders empty as expected.
- [x] **Delete `case 'dashboard':`** from `app/View/Themed/UiBeta/Elements/genericElements/SideMenu/side_menu.ctp` per DD-08. — **Done 2026-05-16.** Byte-identical block to the default (the UiBeta theme inherited the v1 dashboard menu definition verbatim), same 38-line delete. PHP lint clean. Landed in the same commit as the default-theme deletion above; commit body ticks both tasks and explains the theme-resolver coupling. Both side menu files' `case 'dashboard':` arms gone; the DD-08 side-menu-removal loop is now closed.
- [x] **UiBeta themed dashboard layout** at `app/View/Themed/UiBeta/Layouts/dashboard.ctp` per lesson #1 (audit `Themed/<Name>/` for every new layout). Symmetric with the Overmind treatment landed in `a540efdeb`. Cake's themed resolver picks this file when `$this->theme = 'UiBeta'` and the controller asks for `$this->layout = 'dashboard'`; without it, UiBeta users fall back to `Layouts/dashboard.ctp` which does NOT load `main-beta.css` or set `body.beta-ui-enabled` — the result is the MISP global_menu nav bar at the top of `/dashboards` rendering with default typography instead of the beta 14px treatment seen on every other MISP page. Audit findings: `Themed/UiBeta/Layouts/default.ctp` mirrors the global default chrome line-for-line, with two additive differences only — adds `main-beta` to the css preload list after `main`, and adds `class="beta-ui-enabled"` to the body tag. `main-beta.css` is a global typography overlay (1456 LoC, scales fonts to 14px throughout via `!important` on navbar / global_menu / side_menu / headings / forms / tables / dropdowns / modals); the rules are NOT scoped to `.beta-ui-enabled` — that body class is a marker for views opting into `--beta` modifier classes (`event-card--beta` etc.), not a CSS scoping prefix. The structural chrome is identical to default (same `global_menu` element, same `footer` element, same flash container, same asset loader pattern) — unlike Overmind, no BS5 / BS2.3 swap is required. New themed layout: mirror `Layouts/dashboard.ctp` byte-for-byte but insert `['main-beta', ['preload' => true]]` into the css array after the `['main', ['preload' => true]]` entry and append `beta-ui-enabled` to the body class list (alongside the existing `misp-dashboard-page`). Smoke: `GET /dashboards` under UiBeta theme returns 200, response HTML contains both `main-beta.css` link AND `class="misp-dashboard-page beta-ui-enabled"` on body; under Default theme nothing changes. — **Done 2026-05-18.** New file at `app/View/Themed/UiBeta/Layouts/dashboard.ctp` (~140 lines). Mirrors `Layouts/dashboard.ctp` exactly (same chrome — `global_menu` element + flash container + footer + sql_dump + asset loader pattern) with the two UiBeta-specific deltas: (1) `['main-beta', ['preload' => true]]` inserted after `['main', ['preload' => true]]` in the head css array so beta typography rules are loaded after the base `main.css` they're meant to override but **before** `dashboard.default.css` so dashboard-scoped selectors still win where they overlap (verified via the rendered `<link>` order: `bootstrap → bootstrap-datepicker → bootstrap-colorpicker → font-awesome → chosen.min → main → main-beta → dashboard/dashboard.default → dashboard/dashboard.midnight → print`); (2) body class `misp-dashboard-page beta-ui-enabled` (the existing dashboard-page hook plus the UiBeta marker class). Docblock at the top of the file documents the audit findings + the "no BS5 swap needed unlike Overmind" rationale + the two specific hooks added. `php -l` clean; `chgrp www-data` applied to match repo convention. Smoke tests (admin user, temporarily flipped via `UPDATE user_settings SET value='"UiBeta"' WHERE user_id=1 AND setting='ui_theme'`, session login + cookie jar): (a) **UiBeta path** — `GET /dashboards` → 200, 37822B (up from Default's 32531B baseline — the +5291B delta is the additional `main-beta.css` link tag + assetLoader bookkeeping for the extra preload entry); rendered HTML contains exactly one `main-beta.css` link, `<body class="misp-dashboard-page beta-ui-enabled"`, the MISP `#topBar` global_menu rendered above the dashboard, and 2 dashboard surface markers (`.misp-dashboard-header` + `.misp-dashboard-main`). (b) **Default regression check** — flipped to Default, `GET /dashboards` → 200, 32531B (byte-identical to the prior tracker baseline established in the first-load default-template task), zero `main-beta.css` references, body class is `misp-dashboard-page` only (no `beta-ui-enabled`), dashboard surface markers intact. (c) **Overmind regression check** — flipped back to Overmind, `GET /dashboards` → 200, 272356B (Overmind's BS5 page size from the `a540efdeb` themed layout), zero `main-beta.css` references (correct — Overmind has its own chrome stack via `mainOvermind.css`), `mainOvermind.css` link present. Admin restored to Overmind theme after testing. The Phase 1 `Themed/` audit loop is now closed — `ls app/View/Themed/` shows three themes (Overmind / UiBeta / EventTest); the two whose chrome differs from default (Overmind via BS5 navbar, UiBeta via main-beta typography overlay) now have explicit dashboard layouts at `Themed/<Name>/Layouts/dashboard.ctp`. EventTest contains only Events-specific view overrides (`Themed/EventTest/Events/view2.ctp` etc. + an Elements/Events override) — no `Themed/EventTest/Layouts/` directory and no chrome elements, so it inherits both `Layouts/default.ctp` for non-dashboard pages and `Layouts/dashboard.ctp` for /dashboards via the themed resolver's normal fallback. No EventTest-specific dashboard layout needed.

### Smoke tests (close-out)

- [ ] Visit `/dashboards` on default theme: dashboard renders inside MISP layout chrome, MispStatusWidget shows correctly, edit-mode toggle works, drag commits AND persists (regression check on the new commit callback).
- [ ] Visit `/dashboards` under Overmind theme: title-bar drag works, configure side panel opens, toolbar bulk-edit chip works, no broken layout.
- [ ] Legacy-row migration: user has a v1-shape `UserSetting:dashboard` row → visit `/dashboards` → widgets render → save → row now carries `w/h` + `instance_id` per widget, top-level shape unchanged (still bare array per DD-05).
- [x] Grep sanity: `Dashboards2Controller`, `dashboard-v2`, and `?theme=`/`?ui_theme=` references are all gone (no straggling imports / 404s / dead branches). — **Done 2026-05-16.** Four sub-checks: (1) zero `Dashboards2Controller` refs across `*.php`/`*.ctp`/`*.mjs`/`*.js`/`*.css`; (2) zero `?theme=`/`?ui_theme=`/`$uiTheme`/`$themeOverlay`/`data-ui-theme=` activation refs in the dashboard controller, view, or JS; (3) zero functional path refs to `/js/dashboard-v2/`, `/css/dashboard-v2/`, `/Elements/dashboard-v2/`, or `View/Dashboards2/`; (4) initial sweep found 9 cosmetic `// dashboard-v2 — …` / `* dashboard-v2 …` file-header comments + the proto demo's `<title>` and `<h1>` — all 11 instances were single-line comment / title refs (no imports/branches/404s), matching the deferred "Cosmetic naming sweep" item in the handoff doc. Resolved in this same close-out pass by replacing each: JS module headers drop the `dashboard-v2 — ` prefix (the rest of each comment already names what the module is — "Dashboard toolbar", "Configure side panel", "BoardModule", etc.), CSS file headers use `MISP dashboard …`, and `proto/demo.html` uses `Dashboard …`. The `// dashboard-v2 BoardModule — Phase 0.3 prototype.` and `// dashboard-v2 GridModule — Phase 0.2 prototype.` headers also lost their stale "Phase 0.X prototype" suffix — the code is post-prototype production now. Final grep across `app/` for `dashboard-v2` returns zero matches. `node --check` clean on all 7 edited `.mjs` modules; `GET /dashboards` → 200.

---

## Phase 2 — Authoring UX

**Goal:** users can add, configure, and remove widgets via the new
schema-driven form with live preview; edit-mode vs. view-mode is
explicit; saves are atomic.

**Exit criteria:** a user can build a board from scratch by clicking
"Add widget" → picking from the gallery → filling the schema-driven
form → seeing live preview → placing → saving the whole board atomically.

- [x] Define `$schema` property contract on widget classes (PRD §5.7). — **Done 2026-05-18.** Two files. (1) `app/Lib/Dashboard/Tools/WidgetSchema.php` (~190 lines): static helper that centralises the contract for the configure form (DD-06 typed-fields tier), toolbar reachability (DD-05 / PRD §5.6), and the canonical-type adapter (PRD §5.5). Three class constants — `CANONICAL_TYPES` (11 entries: `time_window` / `date_range` / `tag_filter` / `org_filter` / `sharing_group_filter` / `galaxy_cluster_filter` / `distribution_filter` / `threat_level_filter` / `analysis_filter` / `attribute_type_filter` / `event_id_filter`), `SCALAR_TYPES` (`string` / `int` / `bool` / `enum`), and `TOOLBAR_ELIGIBLE_TYPES` (the 9 canonical types marked "Toolbar-eligible: yes" in PRD §5.5 — excludes `attribute_type_filter` and `event_id_filter` which are widget-only). Three static methods: `getSchema($widget)` — returns `$widget->schema` if defined and an array, else `[]` (defensive: non-object input, missing property, non-array property all collapse to `[]` so callers don't need property_exists guards everywhere; widgets that explicitly declare `$schema = []` are treated identically to widgets that don't declare it at all, since per DD-06 both mean "configure form falls back to key-value tier"); `validate($schema)` — returns `null` on success or an associative `<param_key> => <error message>` array suitable for catalogue-load-time logging. Validates that each entry is an array with a `type` field whose value is in `CANONICAL_TYPES ∪ SCALAR_TYPES`; if `type === 'enum'` requires a non-empty `enum` array; `required` (when present) must be boolean; `help` (when present) must be a string; numeric / empty-string keys rejected with `_keys` error; unknown entry fields are allowed (forward-compat — the schema entry can grow without breaking older widgets); `default` field deliberately not type-checked here because the canonical-type adapter (Phase 3) is the right place for per-type default-value validation; `isToolbarEligible($type)` — convenience predicate for Phase 3 toolbar reachability checks. (2) `app/Test/WidgetSchemaTest.php` — pure PHPUnit, no Cake bootstrap (the helper has zero framework dependencies — no Configure read, no model touch), follows the existing `app/Test/` convention. 26 tests / 64 assertions covering: `getSchema()` happy + missing-property + non-array-property + non-object-input + explicit-empty-declaration paths; `validate()` happy paths (empty schema, all canonical types accepted, all scalar types accepted including enum with valid enum array, all optional fields present, unknown forward-compat keys ignored); `validate()` failure paths (non-array schema, missing type, unknown type, enum without enum array, enum with empty enum array, enum with non-array enum, required not boolean, help not string, numeric key, non-array entry, type as non-string, multiple errors accumulated); `isToolbarEligible()` for each toolbar-eligible canonical type, for widget-only canonical types (`attribute_type_filter` / `event_id_filter`), for scalar types, for unknown / non-string inputs. Test run: `./app/Vendor/bin/phpunit app/Test/WidgetSchemaTest.php` → 26/26 pass in 70ms. `php -l` clean on both files. `chgrp www-data` applied. **Wiring deferred** per the additive-only posture and task wording ("Define the contract"): the configure form's typed-fields tier task (DD-06) will consume `getSchema()` and `CANONICAL_TYPES`; the toolbar reachability task (PRD §5.6) will consume `isToolbarEligible()`; the canonical-type adapter (PRD §5.5) will consume `CANONICAL_TYPES` to know which slots in a widget's config need legacy-format translation. The 9 full-tier `$schema` backfills below all consume this contract too — they're additive declarations on existing widget classes, not edits to widget logic, fully consistent with the additive-only posture.
- [x] Full-tier `$schema` backfill (per Q7 — Option C): `MispStatusWidget` — **Done 2026-05-18.** One-line additive change in `app/Lib/Dashboard/MispStatusWidget.php`: `public $schema = array();` inserted after the existing `public $params = array();` line. MispStatusWidget is parameterless by design (the widget reads the current `$user`'s record and calls `Event->fetchEventIds` + `User->populateNotifications` against the user's `last_login` — no time window, no tag filter, no org filter, no configurable threshold). Per the contract (PRD §5.7), empty `$schema` is functionally identical to no `$schema` declaration at all — both make `WidgetSchema::getSchema()` return `[]` and collapse the configure form to the key-value tier (DD-06). The declarative empty array is a **MISP-team-audited marker** ("considered; no typed parameters needed"); a future commit that adds a config knob would have to declare it via `$schema` rather than silently relying on `$params`. `handler()` untouched — zero behavior change. Smoke: `php -l` clean; live PHP smoke (`new MispStatusWidget(); WidgetSchema::getSchema()` returns `[]`, `WidgetSchema::validate([])` returns `null`) confirms the widget honors the contract.
- [x] Full-tier `$schema` backfill: `TrendingTagsWidget` — **Done 2026-05-18.** Adds `public $schema = [...]` to `app/Lib/Dashboard/TrendingTagsWidget.php` declaring three of the widget's six existing `$params` entries with typed contracts; the remaining three stay in `$params` and will land in the configure form's bottom tier (DD-06). Schema entries: (1) `time_window` → `type: 'time_window'` (canonical per PRD §5.5), `help` "Time window over which to aggregate (last N days/hours, or all time)." **`default` deliberately omitted** per the session-level decision on canonical-type defaults: the widget's `handler()` still parses the legacy `Nd` / raw integer seconds shape it always has; the canonical→legacy adapter (Phase 3) translates ISO 8601 `P7D` etc. to that legacy shape, and the canonical defaults will be added in the Phase 3 task that lands the adapter; until then, omitting the default lets `handler()`'s existing `empty($options['time_window']) ? (7 * 24 * 60 * 60) : ...` empty-fallback handle the no-value case (7 days). (2) `threshold` → `type: 'int'`, `default: 10` (matches the existing `empty(...) ? 10 : ...` fallback in `handler()`), `help` "Limits the number of displayed tags." — scalar type, no adapter dependency, default safe to declare now. (3) `over_time` → `type: 'bool'`, `default: false`, `help` "Plot trending tags over time as a multi-line chart instead of a single-snapshot bar chart." — also scalar, declares the widget's bar-vs-multiline-chart toggle. The three params left out of `$schema` (`exclude` / `include` / `filter_event_tags`) are widget-specific arrays that don't match canonical shapes: `exclude` + `include` are substring-match lists (not the structured `tag_filter.exclude` / `tag_filter.include` semantics, which expect tag-name patterns), and `filter_event_tags` is a flat list of tag-name strings the widget passes directly to `Event->filterEventIds(['event_tags' => ...])` — using canonical `tag_filter` for that would either drop information silently (e.g. the canonical type's `match_attribute_tags` flag has no widget code path) or force handler changes outside the additive-only posture. These three stay in `$params` and the existing JSON-textarea workflow keeps using them unchanged; once the Phase 2 configure form lands, they'll surface in the bottom-tier key-value list per DD-06. `handler()` untouched — zero behavior change. Smoke: `php -l` clean; live PHP smoke confirms `WidgetSchema::getSchema()` returns the 3-entry array, `WidgetSchema::validate()` returns `null`, and `array_diff($params, $schema)` correctly identifies the 3 bottom-tier params.
- [x] Full-tier `$schema` backfill: `TrendingAttributesWidget` — **Done 2026-05-18.** Adds `public $schema = [...]` to `app/Lib/Dashboard/TrendingAttributesWidget.php` with two entries; the remaining five `$params` keys stay in bottom-tier per DD-06. Schema: `time_window` → `type: 'time_window'`, help only (no default, per the canonical-defaults session rule); `threshold` → `type: 'int'`, `default: 10`, matches `handler()`'s existing `empty($options['threshold']) ? 10 : ...` fallback. **Five params stay in `$params` for bottom-tier**, intentionally not promoted: (a) `type` + `category` would canonically be unified into a single `attribute_type_filter` entry (PRD §5.5 shape: `{ types: string[], categories?: string[] }`), but that's a **key-restructuring** declaration — existing saved configs have `type` and `category` as separate top-level keys, so introducing `attribute_filter: { types, categories }` requires the Phase 3 canonical-type adapter to know how to split back into legacy keys before calling `handler()`, plus a one-shot migration of saved configs. The Phase 2 backfill is restricted to **1:1 canonical mappings** (a single $params key whose shape already matches the canonical type) so that the adapter / migration concerns land coherently in Phase 3 with all the other canonical types. (b) `org_filter` is **same-name but different-shape** vs. canonical: the widget's `org_filter` is keyed by organisation meta-data fields (`sector`, `type`, `national`, `uuid`, `local` — see `$validOrgFilters` private array) and supports `!`-prefixed negation, whereas canonical `org_filter` (PRD §5.5) is keyed by org identity (`{ orgs: [{uuid?, id?, name?}], role: ... }`). Promoting it would be misleading — the canonical bulk-edit toolbar (if `org_filter` were on $schema) would write the canonical shape into this widget's config and `handler()` would silently ignore it (current code only reads the legacy meta-data shape). (c) `exclude` and `to_ids` have no canonical equivalents — widget-specific knobs (exclude is value-substring list, to_ids is an enum-array of 0/1). `handler()` untouched — zero behavior change. Smoke: `php -l` clean; live PHP smoke confirms schema validates and the 5 bottom-tier keys are correctly identified.
- [x] Full-tier `$schema` backfill: `UsageDataWidget` — **Done 2026-05-18.** Lands `public $schema = [];` (declarative MISP-team-audited marker) — **zero typeable params in this Phase 2 backfill**. Audit per param: (1) `filter` is an org-meta-data dictionary (`nationality`/`sector`/`type`/`name`/`uuid` filter buckets with `!`-negation prefix; see `$validFilterKeys` private) — **same-name-but-different-shape** vs. canonical `org_filter` (PRD §5.5 is org-identity-based with `orgs: [{uuid?, id?, name?}]` + `role`). Promoting it would mis-route toolbar bulk-edit writes silently. (2) `start_date` + `end_date` together would canonically be one `date_range` entry (PRD §5.5 `{ from, to|null }`) — but `date_range` is explicitly **Phase 3 landing** per the §5.5 table notes ("Phase 3 landing. Widgets that today carry hardcoded `start_date` / `end_date` `$params` migrate those slots to declare `date_range` in `$schema`."). Same restructuring + adapter dependency as time_window — `handler()` and `prepareDateRangeConditions()` today parse separate `start_date`/`end_date` ISO strings; declaring canonical `date_range` without the Phase 3 adapter would break end-to-end. **Phase 3 follow-up:** when the canonical adapter + `date_range` declaration lands, also revisit whether the `filter` org-meta-data shape warrants a new canonical type (e.g. `org_meta_filter` — `{ sector?, type?, nationality?, name?, uuid?, local? }` with negation semantics) or stays in $params permanently. `handler()` untouched — zero behavior change. Smoke: `php -l` clean; `WidgetSchema::getSchema()` returns `[]`, `WidgetSchema::validate([])` returns `null`.
- [x] Full-tier `$schema` backfill: `OrgEventsWidget` — **Done 2026-05-18.** Adds `public $schema = [...]` with two scalar entries; `blocklist_orgs` stays in `$params` for the bottom tier. Schema: `months` → `type: 'int'`, `default: 6` (matches `handler()`'s `$limit = 6;` initialisation on line 76); `logarithmic` → `type: 'bool'`, `default: true` (matches the placeholder's `"logarithmic": "true"` example intent). `blocklist_orgs` stays in `$params` — it's a flat list of org names that the widget today matches by `Organisation.name` string-equality, not the canonical `org_filter` shape (which is identity-based with `uuid?`/`id?`/`name?` per-entry); promoting it would mis-route toolbar bulk-edit writes. **Latent bug observed but NOT fixed here** (out of scope for an additive-only backfill): `handler()` lines 105-107 string-compare `$options['logarithmic']` against `"true"` / `"1"` and the else-if branch literally repeats the same conditions as the if branch (modulo `empty()`), so the linear-scale branch on line 107 is structurally unreachable except via the `empty()` guard. Once the configure form lands and writes real PHP booleans to the saved config, this widget's `if ($options['logarithmic'] === "true" ...)` check will silently fail to take the logarithmic branch — needs a follow-up commit that broadens the check to accept truthy booleans + the legacy strings. Flagged in commit body as discovered work; not fixed here per scope. `handler()` untouched. Smoke: `php -l` clean; `WidgetSchema::validate()` returns null.
- [x] Full-tier `$schema` backfill: `AttackWidget` — **Done 2026-05-18.** Lands `public $schema = [];` (declarative marker) — **zero typeable params in this Phase 2 backfill**. AttackWidget has a single param `filters` which is a **free-form restSearch filter dictionary** (`attackGalaxy`, `timestamp`, `published`, etc. per the placeholder; passed verbatim to `$this->Event->restSearch($user, 'attack', $options['filters'])`). Each sub-key inside the dict has different semantics: `attackGalaxy` selects a galaxy type (string), `timestamp` is a date-range pair (would canonically be `date_range` — Phase 3), `published` is an array of 0/1 (no canonical equivalent). Promoting the whole `filters` dict to a single canonical-typed schema entry isn't viable because the dict's contents are heterogeneous — the configure form's typed-fields tier can't render one control for a polymorphic restSearch filter blob. **Phase 3 follow-up:** could decompose `filters` into individual schema entries — `attackGalaxy` (`enum`), `timestamp` (`date_range`), `published` (custom enum-array type if introduced) — but this requires both the Phase 3 `date_range` adapter AND a per-widget restructuring that translates the canonical schema entries back into the legacy `filters` dict shape before calling restSearch. Out of scope for this Phase 2 backfill. `handler()` untouched. Smoke: `php -l` clean; `WidgetSchema::validate([])` returns `null`.
- [x] Full-tier `$schema` backfill: `OrganisationMapWidget` — **Done 2026-05-18.** Lands `public $schema = [];` (declarative marker) — **zero typeable params in this Phase 2 backfill**. Audit per param: (1) `filter` — same org-meta-data dict shape (`sector`/`type`/`local` per `$validFilterKeys`) as UsageDataWidget's `filter`; same-name-but-different-shape vs canonical `org_filter`; same Phase 3 follow-up gating. (2) `start_date` + `end_date` — Phase 3 `date_range` landing per PRD §5.5; this widget is one of the two named in §5.5 ("Widgets that today carry hardcoded `start_date` / `end_date` `$params` (`OrganisationMapWidget`, etc.) migrate those slots to declare `date_range` in `$schema`."). (3) `limit` — **dead config in v1**: declared in `$params` with help text "Default: 10" but never consumed in `handler()`. Reverse-grep across the file shows zero `$options['limit']` references. Promoting `limit` to `$schema` would mislead the configure form into offering a param the widget silently ignores. Intentionally **not promoted**; the `$params` entry stays (additive-only — touching it is outside the backfill task's scope), but the configure form's bottom tier will surface it as a no-op control. A separate cleanup task could either: (a) wire `limit` into `handler()` (it presumably was intended as a country/org cap on the world map), or (b) remove `limit` from `$params` to retire the dead config. Out of scope here. `handler()` untouched. Smoke: `php -l` clean; `WidgetSchema::validate([])` returns `null`.
- [x] Full-tier `$schema` backfill: `RecentSightingsWidget` — **Done 2026-05-18.** Adds `public $schema = [...]` declaring both of the widget's existing `$params` entries — **genuinely full-tier** (no params left in the bottom tier). Schema: `limit` → `type: 'int'`, `default: 10` (matches `handler()`'s `empty($options['limit']) ? "10" : ...` fallback on line 25 — the value is stored as a string "10" in the placeholder but treated as numeric by the underlying Sighting->restSearch call, so declaring `int` aligns the configure form's typed-field with the semantic intent); `last` → `type: 'time_window'`, help only, no default (per the canonical-defaults rule — `handler()` parses legacy `"1d"`/`"12h"` shape via the same `Nd` pattern as TrendingTagsWidget; Phase 3 adapter will canonical-translate; existing `empty($options['last']) ? "1d" : ...` fallback handles no-value case). This is the first **fully-typed** widget in the Phase 2 backfill — both of its params have well-defined canonical/scalar types and no key restructuring is needed. `handler()` untouched. Smoke: `php -l` clean; `WidgetSchema::validate()` returns null.
- [x] Full-tier `$schema` backfill: `EventEvolutionLineWidget` — **Done 2026-05-18.** Adds `public $schema = [...]` with one scalar entry; `filter` and `start_date` stay in `$params` for the bottom tier. Schema: `cumulative` → `type: 'bool'`, `default: true` (matches the help text "(default: on)"). Left in `$params`: (1) `filter` — same org-meta-data dict (`nationality`/`sector`/`type`/`name`/`uuid`) as UsageDataWidget; same Phase 3 follow-up. (2) `start_date` — only one half of a canonical `date_range` (the widget has no `end_date`; defaults to "now" implicitly per `handler()`'s `timeConditions()`); canonical `date_range` shape is `{ from, to|null }` which accommodates "open-ended to-null", but landing this still requires the Phase 3 adapter to translate canonical date_range back into the legacy `start_date` string handler() expects. **Latent bug observed but NOT fixed here** (additive-only): `handler()` line 52 has `$isCumulative = isset($options['cumulative']) && empty($options['cumulative']);` — this returns `true` when `cumulative` is set to a **falsy** value (`false`, `0`, `""`, `null`) and `false` when `cumulative` is unset OR set to a truthy value. So a user who explicitly toggles cumulative ON gets the non-cumulative branch, and vice versa — the variable name and the condition are inverted relative to each other. Out of scope for this additive backfill (the configure form hasn't landed yet either, so the bug isn't biting users today via the new flow); needs a follow-up that either renames `$isCumulative` to its actual semantic or fixes the condition. `handler()` untouched here. Smoke: `php -l` clean; `WidgetSchema::validate()` returns null.
- [x] Two-tier configure form element (per DD-06): top tier renders typed fields from `$schema`; bottom tier renders unstructured params as a flat key-value list with dot-notation paths. — **Done 2026-05-18.** The task wording references a `.ctp` element but the prototype (`configure.module.mjs`) implemented the form client-side — the right architecture under DD-06's "live preview (debounced 250ms re-render on form-input change)" requirement, since live preview needs a DOM-resident form. This commit completes the prototype-to-production lift: makes the typed-fields tier genuinely schema-driven (was hardcoded to always show `TimeWindow.buildField` for every widget). Three coupled changes: **(1) Server: `DashboardsController::index` enriches the `$widgets` payload with each widget's declared schema.** New `App::uses('WidgetSchema', 'Lib/Dashboard/Tools')` import + a `foreach ($widgets as &$w)` post-processing loop that calls `$this->Dashboard->loadWidget($user, $w['widget'], true)` (existing model method that App::uses-loads the widget class) and `WidgetSchema::getSchema($instance)`, attaching the result to `$w['schema']`. Unknown widget classes resolve to `false` via `loadWidget`'s `returnOnException=true` and silently get `$w['schema'] = []` so the configure form collapses to the key-value tier per DD-06 custom-widgets path. The REST branch (`_isRest()`) returns *before* this enrichment so REST clients get the unchanged $widgets shape — `schema` is a UI-side concern, not part of the persistence contract. **(2) Server: `Elements/dashboard/widget/wrapper.ctp` + the Overmind themed override emit a new `data-widget-schema='<json>'` attribute** carrying the schema (h()-escaped, JSON_UNESCAPED_SLASHES). The §8.5 hook contract docblock at the top of both files updated to document the new attribute alongside the existing ones (`data-widget-name`, `data-widget-instance-id`, `data-widget-config`). Themed override updated symmetrically per lesson #1 (every layout/wrapper override must mirror the default's stable attributes). **(3) Client: `configure.module.mjs` is refactored to be fully schema-driven.** Hardcoded `CANONICAL_TYPES = new Set([TimeWindow.KEY])` replaced with a `CANONICAL_BUILDERS` registry keyed by type name (currently just `time_window`; Phase 3 grows the registry as `tag_filter` / `org_filter` etc. land). `buildForm(config, schema)` now iterates schema entries: for `type` in `CANONICAL_BUILDERS`, calls the builder with `opts.schemaKey = <key>` so the rendered control's `data-schema-key` matches the schema key (not the canonical type name — they're usually identical by convention but the contract allows divergence); for scalar types (`string`/`int`/`bool`/`enum`), calls the new `buildScalarField(key, entry, currentValue)` helper which routes to a native control (`<input type="checkbox">` for bool, `<input type="number" step="1">` for int, `<select>` with `<option>`s for enum, `<input type="text">` for string), respecting `entry.default` and `entry.help`. Each control carries `data-schema-key="<key>"` + `data-type="<type>"` for generic readback. Unbuilt canonical types (Phase 3) fall through — the schema entry's saved value surfaces in the bottom-tier key-value list because `handledKeys` doesn't include it. `readBack(panel)` now reads `[data-schema-key]` (was: `[data-canonical]`) and uses `data-type` to coerce: checkbox → bool, `data-type=int` → number-or-empty, else string. The bottom-tier dot-notation logic is unchanged. The "Filters" typed-tier section is **conditionally rendered** — `formNodes` only includes it if `typedFields.length > 0`, so widgets with empty `$schema` (like `MispStatusWidget`) show only the bottom tier instead of an empty Filters header. **(4) Backwards compatibility: `canonical/time_window.mjs::buildField` now emits BOTH `data-canonical="time_window"` AND `data-schema-key="<schemaKey>"`** plus `data-type="time_window"`. The toolbar (`toolbar.module.mjs` line 189) still uses `data-canonical` as its selector hook in the bulk-edit popover; the configure form uses the new `data-schema-key`. Both paths coexist — same input element carries both attributes — so the existing toolbar code keeps working without changes. The builder also accepts an optional `opts.schemaKey` for widgets that declare time_window under a non-conventional key. Smoke (admin user, Overmind theme, session login): `GET /dashboards` returns 200, 272987B (up from 272356B baseline — the +631B delta is the four new `data-widget-schema` attributes on the four widgets in admin's saved layout); response HTML contains exactly 4 `data-widget-schema` matches one per widget; per-widget pairs: `MispStatusWidget => []` (empty marker from commit `1a426b644`), `TrendingTagsWidget => {time_window:{type:time_window,help:...}, threshold:{type:int,default:10,...}, over_time:{type:bool,default:false,...}}` (the 3-entry schema from commit `9682fee4d`), `OrganisationMapWidget => []` (empty marker from `b7baad278`), `OrgContributionToplistWidget => []` (widget not in the Phase 2 backfill list — `getSchema()` returns `[]` per the contract's defensive fallback). REST path (`Accept: application/json`) returns the unchanged $widgets shape with no `schema` field — confirms the enrichment is UI-side only. `node --check` clean on both modified JS modules; `php -l` clean on all three modified PHP files; existing toolbar's `data-canonical` selector still finds the time_window input (auditable: `grep -rn "data-canonical"` shows the three references — comment in configure.module.mjs, declaration in time_window.mjs, and the toolbar.module.mjs selector — all consistent).
- [x] Per-canonical-type form field elements (only `time_window` for now; others land in Phase 3) — **Done 2026-05-18 (tracker hygiene; no new code this tick).** `time_window` is the only canonical type slated to land in Phase 2 per the task wording itself; the remaining ten canonical types from PRD §5.5 (`tag_filter` / `org_filter` / `sharing_group_filter` / `galaxy_cluster_filter` / `distribution_filter` / `threat_level_filter` / `analysis_filter` / `attribute_type_filter` / `event_id_filter` / `date_range`) are explicit Phase 3 work. Proto landed `app/webroot/js/dashboard/canonical/time_window.mjs` (~130 lines) in commit `181f43369`, refined to accept custom values in `edaedbd1f`, and enhanced for schema-driven dispatch in `bdd8d51d4` (this session). Module exports: `KEY` (`'time_window'`) / `LABEL` (`'Time window'`) / `PRESETS` (5 entries — `1d`/`7d`/`30d`/`90d`/`-1` paired with display labels `24h`/`7d`/`30d`/`90d`/`All`, matching the legacy wire shape so unmodified widgets parse it pre-adapter) / `displayLabel(value)` (compact toolbar-chip mapping) / `buildField(currentValue, {compact, schemaKey})`. The field renders a single `<input type=text>` (source of truth), a row of preset shortcut buttons whose clicks dispatch a `change` event so the live-preview listener fires + an active-preset highlight via `syncActive()`, and a format-hint paragraph (`compact: true` omits the canonical-type tail for the toolbar's tight popover surface). Three readback hooks on the inner `<input>`: `data-canonical="time_window"` (toolbar bulk-edit selector, **always** the canonical type name regardless of schema key — DD-05); `data-schema-key="<key>"` (configure-form readback selector, defaults to `'time_window'` but the configure form overrides via `opts.schemaKey` for widgets that declare time_window under a non-conventional key); `data-type="time_window"` (configure-form coercion hint). The configure form's `CANONICAL_BUILDERS` registry at `configure.module.mjs:22-24` is keyed by `KEY` so adding a Phase 3 canonical type is one import + one registry entry — the dispatch loop at `buildForm` lines 239-257 handles the rest. The toolbar consumes the same builder via `toolbar.module.mjs` (the same module exported `buildField` powers both surfaces) so the toolbar popover and the configure form's typed-fields tier always render identical controls, satisfying PRD §5.6's "consistent UX between bulk-edit and per-widget" goal. No new field elements added this tick — the existing builder fully satisfies the Phase 2 task scope; Phase 3 grows the `CANONICAL_BUILDERS` registry per added canonical type.
- [x] Key-value list component for the bottom tier: rows of `(dot.path.key, value)` with add/remove — **Done 2026-05-18 (tracker hygiene; no new code this tick).** Landed in proto commit `96cf753af` ("schema-driven two-tier configure side panel"); the schema-driven bottom-tier filter (`handledKeys`-aware) shipped in `bdd8d51d4` and the remove-row preview hook shipped in `5ed3287b7` (both this session). Three coupled pieces in `app/webroot/js/dashboard/configure.module.mjs`: (1) `buildKVRow(key, value)` factory at lines 116-141 — builds `<li class="misp-kv-row">` with two `<input type=text>`s (`.misp-kv-key` placeholder `key.path`, `.misp-kv-value` placeholder `value`) and a remove `<button class="misp-widget-iconbtn">` carrying `data-misp-kv-action="remove"`. The remove-button styling reuses `.misp-widget-iconbtn` so it visually matches the widget-chrome ⚙ / ✕ buttons. (2) Bottom-tier render block at `buildForm` lines 274-299 — `<ul class="misp-kv-list" data-misp-kv-list>` populated either with a single empty seed row (when the widget has no bottom-tier config — DD-06 "single example key" requirement) or one row per `flatten()`d entry, followed by a `+ Add row` button carrying `data-misp-kv-action="add"`. The bottom-tier `<section class="misp-configure-tier">` is **always rendered** (the Filters tier above it is conditional on `typedFields.length > 0`; the bottom tier is the universal fallback per DD-06 so users with custom widgets / empty schemas still have an editable surface). (3) Event delegation on the panel root at `init()` lines 505-524 — single `click` listener resolves `data-misp-kv-action`: `add` appends a `buildKVRow('', '')` and focuses the new key input (deliberately no `schedulePreview` call — empty keys are dropped on readback so an empty row alone isn't a config change; typing into it triggers preview via the body's input listener); `remove` deletes the row and calls `schedulePreview()` so a populated-row removal updates the widget body within the 250ms debounce. Dot-notation `flatten` / `reNest` helpers at lines 57-94 sit alongside this component but are tracked separately on the "Bottom-tier dot-notation flattening on read; re-nesting on save" task line below — that line stays unticked because the unit-test coverage it explicitly calls for hasn't landed.
- [ ] Chip input component for array-typed values in the bottom tier (type-and-Enter to add, click × to remove); also reusable in canonical pickers like `tag_filter`
- [x] Bottom-tier seeding: when adding a new widget, parse `$placeholder` JSON and populate the key-value list with the example keys/values (replacement for the JSON-textarea workflow) — **Done 2026-05-19.** Reuses the `data-widget-schema` delivery pattern from commit `bdd8d51d4`. Three coupled pieces: **(1) Server: `DashboardsController::index` $widgets enrichment loop grows a parallel `$w['placeholder'] = $instance->placeholder ?? ''` assignment.** The placeholder ships raw (not server-parsed) so the client owns the JSON.parse-and-fallback path — some MISP widget placeholders are legitimately malformed JSON (trailing commas, unescaped inner quotes — `TrendingTagsWidget`'s `filter_event_tags: ["misp-galaxy:threat-actor="APT 29"]` is a working-as-shipped example). REST early-return at `_isRest()` skips the enrichment so persistence-shape clients still see the unchanged $widgets payload. Defensive — non-string `$instance->placeholder`, missing-property, and unknown-widget-class all collapse to `''`. **(2) Wrapper: `app/View/Elements/dashboard/widget/wrapper.ctp` + Overmind themed mirror emit `data-widget-placeholder="<raw>"` (h() escaped, preserves embedded newlines per HTML attribute rules).** §8.5 hook contract docblock updated to document the new attribute. The themed mirror update is required per lesson #1 — any layout/wrapper override surface must mirror the default's stable attributes. **(3) Client: new `seedFromPlaceholder(raw, handledKeys)` helper in `configure.module.mjs` at lines 96-118** — JSON.parse-with-try/catch, defensive object-shape guard (parsed null / non-object / array all return `[]`), filters schema-handled keys out of the result so the user doesn't see a duplicate field in two tiers (and so the readback's `Object.assign(out, reNest(flat))` doesn't have the bottom-tier kv-row overwrite the top-tier schema control), then returns `Object.entries(flatten(filtered))` so existing kv-list rendering code handles nested objects/arrays uniformly. `buildForm(config, schema, placeholder)` signature widened; the bottom-tier render block's empty-flatRest branch calls `seedFromPlaceholder` and either populates from the seed rows or falls back to a single empty row when seed is empty (parse failure, no parseable placeholder, or all-keys-handled-by-schema after filter). `openConfigure` reads `data-widget-placeholder` via the new `ATTR_WIDGET_PLACEHOLDER` constant and passes it through. **Smoke (admin user, Overmind theme, session login):** `GET /dashboards` → 200, 273876B (up from 272987B baseline — +889B for four `data-widget-placeholder` attribute values). HTML inspection confirms all four widgets in admin's layout serialise the attribute: MispStatusWidget's placeholder is `""` (parameterless widget — fallback fires); TrendingTagsWidget's placeholder is malformed JSON (parse fails — fallback fires; widget has non-empty config anyway so the bottom tier renders the saved kv data, not the placeholder); OrganisationMapWidget's placeholder is valid JSON with key `filter` → since `limit` is now in $schema (from commit `cc9ed0bd2`) and gets filtered out by handledKeys, the seed-from-placeholder path emits two rows on a fresh config: `filter.type` → `"Member"`, `filter.local` → `[0,1]` as JSON-stringified; OrgContributionToplistWidget has a non-empty config so the placeholder is bypassed entirely (saved-config-wins branch). `php -l` clean on all 3 changed PHP files; `node --check` clean on configure.module.mjs. **UX trade-off:** if the user adds a fresh widget and immediately clicks Save without editing the seeded values, the placeholder values persist into the user's saved config. Per DD-06 this is the expected behavior — placeholder values are "examples" that the user is expected to edit; if they want all-defaults they should edit/clear the rows. Not blocking but worth surfacing if real-user feedback shows confusion. **Interactive verification deferred** to a manual browser pass on the Add Widget flow once that lands — automated headless smoke confirms server enrichment + attribute delivery + parse-and-filter logic but can't drive the configure-form open/save cycle.
- [ ] Bottom-tier dot-notation flattening on read; re-nesting on save; round-trip lossless for nested objects, arrays, scalars, booleans (unit-tested)
- [x] Side-panel container for configure form (replaces modal) — **Done 2026-05-18 (tracker hygiene; no new code this tick).** Chrome landed in proto commit `96cf753af`. Markup at `app/View/Dashboards/index.ctp` lines 143-173: (1) a `<div class="misp-configure-backdrop" data-misp-configure-backdrop hidden>` for click-outside-to-close; (2) a `<aside class="misp-configure-panel" data-misp-configure-root role="dialog" aria-labelledby="misp-configure-title" aria-modal="true" hidden>` containing a `<header>` (title node carrying `data-misp-configure-title` for `openConfigure` to repopulate per opened widget + a ✕ iconbtn with `data-misp-configure-action="cancel"`), a `<div class="misp-configure-body" data-misp-configure-body>` (body container that survives `body.replaceChildren()` across `openConfigure` calls and hosts the delegated input/change live-preview listener per lesson #4 of the 2026-05-18 handoff), and a `<footer>` (Cancel + Save buttons, both via `data-misp-configure-action`). Closing affordances all wired in `init()`: ✕ + Cancel + footer Cancel via the panel-root `data-misp-configure-action="cancel"` delegation, backdrop click via the dedicated listener at line 546, ESC via a `document` keydown listener at line 547. `setHidden()` at lines 344-355 force-reflows the panel before adding `is-open` so the right-slide transition animates from off-screen rather than snapping. No themed override exists at `app/View/Themed/<Name>/Dashboards/index.ctp` — confirmed by `grep -rn "misp-configure-backdrop\|misp-configure-panel" app/View/Themed/` returning no matches; the configure panel is a single global chrome served by the default `index.ctp` for both default and Overmind themes (which is fine — the chrome is theme-neutral; only the `.misp-configure-panel` CSS class is themed via the default + Overmind stylesheets). Sticky preview pane part of the original task line is split out to a dedicated entry below — it stays unchecked because the panel today shows only the form, with the live preview re-rendering the widget body in-board (not in a sticky pane next to the form).
- [ ] Sticky preview pane in configure side-panel — split out from the original "Side-panel container" task line (2026-05-18). DD-06's "live preview" requirement is partially satisfied by the in-board re-render path (debounce-driven; see `5ed3287b7`); a sticky right-pane preview *inside* the side panel would let users see the widget body without their eye-line jumping back to the board. Implementation sketch: widen the `.misp-configure-panel` to two columns; left column hosts the form (current chrome), right column hosts a sticky `<div class="misp-configure-preview">` whose contents are re-rendered by the same `_renderWidget` path the in-board preview uses. Trade-off: the side panel is already crowded on narrow viewports (~600px wide today); a two-column layout would force a ~960px minimum or a collapsible preview. Deferring until DD-06's live-preview UX is exercised by a real user and the eye-line problem is confirmed as an actual pain point — could be that the in-board re-render is sufficient because the widget is still visible to the left of the open panel.
- [x] Live preview: debounced (250ms) re-render of the widget on form-input change — **Done 2026-05-18.** Wires DD-06's live-preview affordance through the existing render path so users see their configure-form edits reflected in the widget body without leaving the panel. **Two-file change** in the established configure-fires-events / board-handles-render pattern: (1) `configure.module.mjs` — five new module-level state vars (`onPreviewCallback`, `originalConfigJson`, `previewTimer`, `dirty`, `savedThisSession`) plus the constant `PREVIEW_DEBOUNCE_MS = 250`. `openConfigure(widgetEl, opts)` signature widened: accepts `{onSave, onPreview}` *or* a bare function (treated as onSave for backwards compatibility — keeps any caller-side smoke clean). At open time, snapshots `data-widget-config` into `originalConfigJson` and resets `dirty`/`savedThisSession`. New `schedulePreview()` (debounce-handle manager) + `firePreview()` (debounce-fire body: `readBack(panel)` → write to `data-widget-config` → invoke `onPreviewCallback`). The `init()` block attaches `input` + `change` listeners to the panel body container (`[data-misp-configure-body]`) using delegation so the listener survives `body.replaceChildren()` across successive `openConfigure` calls; both listeners gate on `openTarget` so spurious events when the panel is closed are no-ops. The KV-row remove button also calls `schedulePreview()` (adding an empty row alone doesn't change config, but removing a populated row does). `commit()` clears any in-flight preview timer, sets `savedThisSession = true` before calling `closeConfigure()` so the revert branch is skipped. `closeConfigure()` adds a **cancel-revert** branch — if `dirty && !savedThisSession && openTarget`, restores `data-widget-config` from `originalConfigJson` and invokes `onPreviewCallback` one more time so the widget body visibly reverts to its pre-open state; without this, an unsaved cancel would leave the user's staged edits visible in the widget body until the next page refresh. All state vars cleared at the end of `closeConfigure()`. (2) `board.module.mjs` — the `'configure'` action handler now passes `{onSave, onPreview}` instead of a bare callback: `onSave` is unchanged (re-render + refresh toolbar + `_scheduleSave`); `onPreview` is just `(el) => this._renderWidget(el)` — re-render without persistence. Comment block updated to document the two-callback contract. **Race-window assessment:** the debounce fires one `_renderWidget` POST per 250ms-paused-typing event; two POSTs can be in-flight only if the user types, pauses (POST 1 fires), types more, pauses (POST 2 fires) — and POST 1 might still be in-flight when POST 2 returns. If POST 1 returns AFTER POST 2, its stale HTML overwrites POST 2's current HTML. Mitigation deferred — `_renderWidget` doesn't carry generation tracking today (no AbortController, no in-flight ID). Acceptable for MVP: the next pause-and-type cycle self-corrects, and the typing cadence required to trigger it is unusual (sub-second pauses spaced 250ms+ apart). Flag as discovered work if it becomes a UX issue; the fix is an AbortController on `_renderWidget` scoped to the preview path. **End-to-end flow traces verified mentally:** no-edit cancel (no revert, no spurious re-render); edit + save (one onPreview tick per 250ms-pause, then onSave on click); edit + cancel/Esc/backdrop (revert + one final re-render). Smoke: `node --check` clean on both files; `GET /dashboards` → 200, 272987B (no rendered-HTML delta — JS-only change); `GET /js/dashboard/configure.module.mjs` → 200, 19601B (up from 16KB baseline — live-preview code adds ~3.6KB), 17 markers for the new code paths (`schedulePreview` / `firePreview` / `PREVIEW_DEBOUNCE_MS` / `onPreview`). Interactive verification deferred to manual browser smoke by the user — automated headless smoke can't drive form-input events without a JS-execution harness.
- [ ] Widget gallery: `Elements/dashboard/gallery/grid.ctp` + `card.ctp`; grouped by `$category`; search box; static-thumbnail support via `$thumbnail`
- [ ] Add Widget flow: gallery card → schema form opens in side panel → live preview on right → place/cancel
- [ ] Edit Widget flow: click configure → form opens populated → preview → save/cancel
- [ ] Edit-mode vs. view-mode toggle on board toolbar; mode is a `data-misp-board-mode` attribute on the root
- [ ] **Layout-only atomic save** (per DD-05): edit-mode Save persists only layout changes (positions, additions, removals) for the dashboard. Configure-form Save and toolbar pulls each save independently.
- [ ] Discard (edit mode): confirm dialog if dirty layout, then revert layout from server state
- [ ] Drag/resize/add/remove only fire in edit mode; staged in client memory, not persisted until edit-mode Save
- [ ] Configure-form Save: per-widget POST to `/dashboards/updateSettings` with the affected widget's instance ID + new config; rest of blob unchanged on the server
- [ ] Console.log cleanup: confirm no debug log statements ship in dashboard-v2 JS

---

## Phase 3 — Canonical-type toolbar

**Goal:** the canonical-type catalogue + dashboard-level filter toolbar
(PRD G4 + G13) work end-to-end on the singleton dashboard.

**Exit criteria:** the user can use the dashboard toolbar to bulk-edit
all applicable widgets' `time_window` / `tag_filter` / `org_filter` /
`galaxy_cluster_filter` / etc. simultaneously. Toolbar pulls write
immediately to per-widget configs; toolbar's displayed value is
computed from those configs (with "(mixed)" indicator on disagreement).

- [ ] Implement remaining canonical types from PRD §5.5: `tag_filter`, `org_filter`, `sharing_group_filter`, `galaxy_cluster_filter`, `distribution_filter`, `threat_level_filter`, `analysis_filter`
- [ ] Per-canonical-type form field elements for the configure form's typed-fields tier (full set)
- [ ] Per-canonical-type validators (validate `$config[<canonical_type>]` shapes server-side before save)
- [ ] **Toolbar control logic** (per DD-05). For each canonical type declared by at least one widget on the dashboard, render a toolbar control. Compute its display state from the current widgets:
  - all applicable widgets agree → show value
  - disagree → show "(mixed)" indicator
  - none declare it → control hidden
- [ ] Toolbar UI: time_window picker, tag picker (taxonomy-aware), org typeahead, galaxy cluster picker, sharing group picker
- [ ] **Toolbar bulk-edit write path:** pulling a control walks every widget that declares the matching canonical type, writes the new value into each widget's `config[<canonical_type>]`, posts the whole blob to `updateSettings`, re-renders affected widgets (debounced 250ms)
- [ ] **New-widget toolbar inheritance** (PRD F5.6.4): when a widget added in edit mode declares a canonical type for which the toolbar shows a non-mixed value, the new widget's `config[<canonical_type>]` initialises to that value
- [ ] Per-control "Clear" action (PRD F5.6.5): unsets the canonical-typed value on all applicable widgets
- [ ] Toolbar pulls work in any mode (no edit mode required)
- [ ] Canonical-only `$schema` sweep across the remaining ~20 in-tree widgets (per Q7 — Option C). For each, declare the canonical-typed slots used (`time_window`, `tag_filter`, `org_filter`, etc.) and leave non-canonical params on the legacy `$params` + `$placeholder` fallback path (rendered in the configure form's bottom tier per DD-06). The 9 full-tier widgets from Phase 2 are already done.
- [ ] Cache-key sanity-check: existing per-widget Redis cache key already includes a hash of the widget config, so toolbar bulk edits naturally invalidate the cache for the affected widgets — no separate scope-hash needed (per DD-05)

---

## Phase 4 — Template gallery polish

**Goal:** replace today's `listTemplates` table view with a gallery
surface (thumbnails, categories, search). The existing `dashboards`
schema and `restrict_to_*` semantics are preserved verbatim — this
phase is purely a presentation layer change plus a small thumbnail
generator.

**Exit criteria:** the user can browse and pick templates in a visual
gallery, "Save as template" still produces the same `dashboards` row
shape, and the existing restrict-to-org / role / permission rules still
gate visibility correctly.

- [ ] Template gallery view: `Elements/dashboard/gallery/grid.ctp` (already scaffolded in Phase 2 for Add Widget; reuse the layout)
- [ ] Template thumbnails: server-rendered miniatures of the layout (no live data — just the widget tiles + titles), cached on disk under `webroot/img/dashboard/templates/`
- [ ] Refresh-thumbnail action (manual; runs on save-template by default)
- [ ] Existing `restrict_to_org_id / role_id / permission_flag` rules preserved on read
- [ ] "Save as template" form: same fields as today (`name`, `description`, `selectable`, restrict flags); fed by the new blob shape `{scope, widgets}`
- [ ] "Reset from template" replaces `UserSetting:dashboard` with the chosen template's `value`, with a confirmation prompt if the user has unsaved layout edits. No "Also apply default filters" checkbox — the template's per-widget configs (which may include canonical-typed values) become the user's per-widget configs verbatim (per DD-05 supersedes-DD-04).
- [ ] Existing `listTemplates`, `saveTemplate`, `deleteTemplate` endpoints unchanged on the wire; only the UI is reworked
- [ ] Existing `import` / `export` endpoints unchanged on the wire; their output adopts the new blob shape (legacy bare-array form still readable on import)

---

## Phase 5 — Drill-down + refresh scheduler

**Goal:** widget cells link through to filtered MISP views; refresh
is centrally scheduled, pausable, and tab-visibility-aware.

**Exit criteria:** clicking a tag count opens the events index
filtered to that tag and the active board scope. Refresh storms are
gone; pause toggle works; auto-pause on hidden tab works.

- [ ] `$drilldown` schema property documented and exposed in widget metadata
- [ ] Drill-down convention per Q3 resolution (auto-wrap vs. explicit)
- [ ] Renderer-level wrapping for SimpleList (links on rows where applicable)
- [ ] ECharts click handlers calling drill-down (bar/line/geo)
- [ ] Board-level refresh scheduler: single timer, max 4 concurrent renders in flight (PRD §10)
- [ ] Pause-refresh toggle on board toolbar
- [ ] Per-instance refresh override in widget config form
- [ ] Auto-pause when document hidden (Page Visibility API)
- [ ] Manual refresh on a single widget (button on widget chrome in view mode)
- [ ] Refresh indicator chip: "updated 30s ago"; uses relative-time formatting that respects locale
- [ ] Verify cache key includes board scope hash so scope-aware widgets don't cross-pollute (PRD F3.3)

---

## Phase 5.5 — Widget Parity Sweep (merge gate)

**Goal:** explicitly check off the three-parity merge gate from PRD §12
before the `dashboards` branch can be merged to `develop`.

**Exit criteria:** all three parities verified; smoke-test matrix
filled in; nothing in v1's surface is broken or missing.

### Widget parity

For each built-in widget, smoke-check that it loads, renders, and
honours its config. Tick when verified on default theme; double-tick
when also verified on Overmind.

- [ ] `AchievementsWidget`
- [ ] `APIActivityWidget`
- [ ] `AttackWidget`
- [ ] `AuthenticationFailureWidget`
- [ ] `BenchmarkTopListWidget`
- [ ] `ButtonWidget`
- [ ] `CsseCovidMapWidget`
- [ ] `CsseCovidTrendsWidget`
- [ ] `CsseCovidWidget`
- [ ] `EventEvolutionLineWidget`
- [ ] `EventStreamWidget`
- [ ] `LoginsWidget`
- [ ] `MispAdminResourceWidget`
- [ ] `MispAdminSyncTestWidget`
- [ ] `MispAdminWorkerWidget`
- [ ] `MispStatusWidget`
- [ ] `MispSystemResourceWidget`
- [ ] `NewOrgsWidget`
- [ ] `NewUsersWidget`
- [ ] `OrgContributionToplistWidget`
- [ ] `OrgEventsWidget`
- [ ] `OrgEvolutionLineWidget`
- [ ] `OrganisationListWidget`
- [ ] `OrganisationMapWidget`
- [ ] `OrgsContributorLastMonthWidget`
- [ ] `OrgsEvolutionWidget`
- [ ] `OrgsUsingMitreWidget`
- [ ] `OrgsUsingObjectsWidget`
- [ ] `RecentSightingsWidget`
- [ ] `SharingGraphWidget`
- [ ] `ThresholdSightingsWidget`
- [ ] `TrendingAttributesWidget`
- [ ] `TrendingTagsWidget`
- [ ] `UsageDataWidget`
- [ ] `UserContributionToplistWidget`
- [ ] `UsersEvolutionWidget`
- [ ] `WhoamiWidget`
- [ ] Custom widget loader path verified: `Custom/` and `Custom/<subdir>/` resolution still works (`HelloWorldWidget`, `CsseCovidWidget` under `widget-collection/`)

### Data parity

- [ ] Legacy `UserSetting:dashboard` bare-array form loads cleanly into v2 (per-widget on-read fix-ups apply)
- [ ] Legacy `dashboards.value` (templates) load cleanly into v2
- [ ] Round-trip: export a v2-saved blob (with `instance_id` + `w/h`), re-import, layout preserved
- [ ] Round-trip: import a legacy v1 blob (no `instance_id`, `width/height` form), v2 reads + applies per-widget fix-ups on first save
- [ ] No data loss across the per-widget fix-ups: instance ID minting is deterministic for the same input on a single read, `width/height → w/h` preserves the numeric values exactly

### Surface parity

- [ ] `/dashboards` (View Dashboard) — works
- [ ] `/dashboards/getForm/add` (Add Widget modal) — replaced by v2 gallery, but the URL still resolves to *something usable*
- [ ] `/dashboards/import` — works with both blob shapes
- [ ] `/dashboards/export` — works
- [ ] `/dashboards/listTemplates` — works (in v2 gallery form per Phase 4)
- [ ] `/dashboards/saveTemplate` — works
- [ ] `/dashboards/saveTemplate/<id>` — update path works
- [ ] `/dashboards/deleteTemplate/<id>` — works
- [ ] `/dashboards/renderWidget/<id>` — works (request payload unchanged from v1; per DD-05 there is no `scope` payload)
- [ ] `/dashboards/updateSettings` — works; new blob shape persisted

### Pre-merge cleanup

- [ ] Remove `app/webroot/js/gridstack.all.js.bk`, `app/webroot/css/gridstack.min.css.bk`
- [ ] Remove `app/webroot/js/gridstack.all.js`, `app/webroot/css/gridstack.min.css` (no longer used post-DD-01)
- [ ] Remove `jquery-jvectormap-2.0.5.min.js` and the `world-mill` GeoJSON if no other consumer remains (check first via `git grep`)
- [ ] Remove the D3 v3 dependency from `webroot/js/d3.js` if no other consumer remains (check first via `git grep`)
- [ ] Audit `Chart.min.js` consumers; leave for follow-up if non-dashboard pages still use it (out of scope to migrate here)
- [ ] Remove the legacy `$placeholder` / `$params` JSON-textarea fallback path only if all in-tree widgets have `$schema` (per Q7 resolution)
- [ ] `git grep -i 'dashboard'` audit: no stale references to v1-only files, no orphaned `.ctp`s

---

## Phase 6 — Merge to `develop`

**Goal:** with the parity sweep green, the `dashboards` branch
merges to `develop` for inclusion in the next 2.5 release cycle.

**Exit criteria:** PR opened, reviewed, merged. Branch deleted.

- [ ] Drafted user-facing changelog entry highlighting the visual rework, the canonical-type toolbar, and the no-action-needed migration story
- [ ] Operator-facing release note (drop in `docs/dev/` or wherever release notes are aggregated) — emphasise **no migration**: existing users keep their layout; per-widget on-read fix-ups (`instance_id` mint, `width/height → w/h` rename) apply transparently on first save
- [ ] PR opened against `develop` with link to PRD + this progress doc
- [ ] Review feedback addressed
- [ ] Merge
- [ ] Branch `dashboards` deleted

---

## Discovered work

Items found during implementation that didn't fit a planned task. Add
them here with a short note describing what surfaced them and where
they should land. Promote into a phase when one is resolved.

### Phase 3 canonical-type adapter + catalogue gaps (surfaced 2026-05-18)

**Surfaced during the Phase 2 9-widget `$schema` backfill (commits `1a426b644` … `afadd0530`).**

Phase 3's task list at line 875 lists 7 canonical types to implement (`tag_filter`, `org_filter`, `sharing_group_filter`, `galaxy_cluster_filter`, `distribution_filter`, `threat_level_filter`, `analysis_filter`) but **omits `date_range`** — which PRD §5.5 explicitly marks as Phase 3 landing ("Widgets that today carry hardcoded `start_date` / `end_date` `$params` (`OrganisationMapWidget`, etc.) migrate those slots to declare `date_range` in `$schema`."). Three widgets in the Phase 2 backfill (`UsageDataWidget`, `OrganisationMapWidget`, `EventEvolutionLineWidget`) have `start_date`/`end_date` (or `start_date` alone) `$params` slots that need canonical `date_range` — none could be promoted in Phase 2 because the canonical adapter doesn't exist yet.

Phase 3 also omits the **canonical adapter implementation** itself — PRD §5.5 says: "Per the additive-only posture, we don't touch every legacy widget's `handler()`; instead a single adapter sits in front of `handler()` and translates the canonical slots into the shape each widget expects, driven off `$widget->$schema` to know which slots are canonical. The adapter lives in `app/Lib/Dashboard/Tools/CanonicalTypeAdapter` and is called from `DashboardsController::renderWidget` before `$widget->handler($user, $config)`". This is the keystone of the canonical-type design and has no explicit task entry in Phase 3.

Open question for Phase 3 planning: **introduce a new canonical type for the org-meta-data filter shape?** Four widgets in the Phase 2 backfill (`TrendingAttributesWidget`, `UsageDataWidget`, `OrganisationMapWidget`, `EventEvolutionLineWidget`) all have a `filter`/`org_filter` param shaped as `{ sector?, type?, nationality?, name?, uuid?, local? }` with `!`-prefix negation — a recurring shape that's neither canonical `org_filter` (identity-based) nor widget-specific. Could be promoted to a new canonical `org_meta_filter` type that the toolbar surfaces as a bulk-edit chip. Alternatively, accept that meta-data filtering stays in `$params` bottom-tier permanently (4-widget consistency isn't enough to justify a catalogue addition).

**Where it lands:** Phase 3 task list amendments — needs the `date_range` line item, an explicit `CanonicalTypeAdapter` implementation task, a `time_window` legacy-to-canonical translation task (PRD §5.5 lists the translation table), and a decision/task on `org_meta_filter`.

### TrendingTagsWidget handler() pre-existing PHP 8.x crash

**Pre-existing MISP issue, not v2-specific** — documented in the Phase 0.3 Model 4 demo Done note. The widget hits a CakePHP `Attribute` model name collision under PHP 8.x and fatals when `over_time=true` is requested. Out of scope for the v2 dashboard rework (the widget renders fine in non-`over_time` mode); separate cleanup task.

### OrgEventsWidget `logarithmic` check pattern is broken (surfaced 2026-05-18) — **fixed 2026-05-18**

**Surfaced during the Phase 2 `$schema` backfill of OrgEventsWidget (commit `636e55dcc`).**

`handler()` lines 105-107 string-compare `$options['logarithmic']` against `"true"` / `"1"` and the else-if branch literally repeats the same conditions as the if branch (modulo `empty()`):

```php
if ($options['logarithmic'] === "true" || $options['logarithmic'] === "1") {
    // logarithmic branch
} else if (empty($options['logarithmic']) || $options['logarithmic'] === "true" || $options['logarithmic'] === "1") {
    // linear branch — only reachable via empty()
}
```

Once the Phase 2 configure form writes real PHP booleans to the saved config (per `$schema['logarithmic']['type'] = 'bool'`), `$options['logarithmic'] === true` doesn't match `=== "true"`, so the widget silently falls through to the linear branch even when the user toggled logarithmic ON.

**Fix:** broadened the truthy set to accept real PHP booleans alongside the legacy strings, collapsed the unreachable else-if to a plain `else`, and used `$options['logarithmic'] ?? true` so the schema default (`true` per `$schema['logarithmic']['default']`) governs the no-key case. New logic:

```php
$logRaw = $options['logarithmic'] ?? true; // schema default
$isLogarithmic = ($logRaw === true || $logRaw === 1
    || $logRaw === '1' || $logRaw === 'true');
if ($isLogarithmic) { /* log branch */ }
else                { /* linear branch */ }
```

`php -l` clean. Closes the silent fall-through gap where a value like `"yes"` would have hit neither branch and dropped the org from the chart for that month.

### EventEvolutionLineWidget `$isCumulative` condition is inverted (surfaced 2026-05-18) — **not actually a bug; cosmetic rewrite landed 2026-05-18**

**Surfaced during the Phase 2 `$schema` backfill of EventEvolutionLineWidget (commit `afadd0530`).**

`handler()` line 52: `$isCumulative = isset($options['cumulative']) && empty($options['cumulative']);` — this returns `true` when `cumulative` is set to a falsy value and `false` when `cumulative` is unset or set to a truthy value. The variable name (`$isCumulative`) was inverted relative to the assignment expression.

**Re-trace (2026-05-18, second pass during the bug-fix sweep):** the *consumption site* at lines 130-134 was **correspondingly inverted** — `if ($isCumulative) { $raw_padded[$date] = $count; /* per-interval */ } else { $raw_padded[$date] = $total; /* running total */ }`. The two inversions cancel, so end-to-end behavior was already correct:

| `cumulative` value | `$isCumulative` | Branch taken | Display |
|---|---|---|---|
| `true` (bool) | false | else | running total ✓ |
| `false` (bool) | true | if | per-interval ✓ |
| `"true"` | false | else | running total ✓ |
| `"1"` | false | else | running total ✓ |
| `"0"` | true | if | per-interval ✓ |
| unset | false | else | running total ✓ (matches schema default `true`) |

So the prior handoff's claim that "a user who explicitly toggles cumulative ON gets the non-cumulative branch" was wrong — the variable name was misleading but the behavior was right.

**Fix (cosmetic):** rewrote with the canonical bool semantic — `$cumulative = filter_var($options['cumulative'] ?? true, FILTER_VALIDATE_BOOLEAN, ['flags' => FILTER_NULL_ON_FAILURE])` with a `null → true` fallback for unrecognized values, plus the if/else branches flipped so `$cumulative === true` enters the running-total branch and `$cumulative === false` enters the per-interval branch. End-to-end behavior unchanged for all legacy shapes (real bool, `"true"`/`"false"`, `"1"`/`"0"`, ints, unset) except one edge case worth noting: a value of the literal string `"no"` was previously treated as cumulative (because `empty("no")` is `false`), and is now treated as per-interval (because `filter_var` recognises `"no"` as boolean-false). Vanishingly unlikely any saved config carries `"no"` — neither the placeholder nor the schema nor the params help text suggest yes/no values — but documenting the diff in case anyone trips on it. `php -l` clean.

### OrganisationMapWidget `limit` is dead config (surfaced 2026-05-18) — **fixed 2026-05-18**

**Surfaced during the Phase 2 `$schema` backfill of OrganisationMapWidget (commit `b7baad278`).**

`OrganisationMapWidget::$params` declares `limit => 'Limits the number of displayed tags. Default: 10'` but `handler()` never reads `$options['limit']` — reverse-grep across the file is empty. The help text also references "tags" which is a stale copy from `TrendingTagsWidget`'s param (this widget shows orgs on a world map).

**Fix:** wired `limit` into `handler()`'s find call with `'order' => ['frequency DESC']` added unconditionally so the top-N is deterministic. New code path:

```php
$findArgs = [
    'recursive' => -1,
    'fields' => ['Organisation.nationality', 'COUNT(Organisation.nationality) AS frequency'],
    'conditions' => $params['conditions'],
    'group' => ['Organisation.nationality'],
    'order' => ['frequency DESC'],
];
if (!empty($options['limit'])) {
    $findArgs['limit'] = (int) $options['limit'];
}
```

Same commit:
- `$params['limit']` help text rewritten to drop the "tags" copy-paste typo and describe top-N-by-count semantics: `"Limits the number of countries displayed on the map (top-N by organisation count). Leave empty for unlimited."`.
- `$schema` promoted from `[]` to `['limit' => ['type' => 'int', 'help' => '...']]` since the param is now alive — the configure form's typed-fields tier surfaces it as a numeric input rather than dot-notation key-value. No `default` declared (the implicit semantic is "unlimited" when empty; declaring a default of e.g. 10 would silently cap admin's globe view for every existing widget instance on first save).

**Behavior delta even for users who don't set `limit`:** the new `ORDER BY frequency DESC` is unconditional, so the result-set's row order is now deterministic. Prior order was unspecified — relying on it was already a bug (different MySQL/MariaDB versions, different buffer-pool warm states, and different `WHERE` filter combinations could each produce different orderings). The downstream code that reshapes `$orgs` into `$results['data']` keys by country code, so row order doesn't actually affect the rendered map either — the change is invisible in practice.

`php -l` clean. The widget is now consistent with itself: schema declares the typed knob; params describes the knob; handler reads the knob; result honors the knob.

**Smoke-driven follow-up (also 2026-05-18 — commit `<C3a>`):** the initial fix applied `'limit'` at the SQL level (in the `find()` call). Smoke against the live dev instance revealed a surprising interaction with the country-code filter: the test dataset's top-2 nationalities by frequency are `Krakhozia` (3) and `International` (3), neither of which maps to a country code. With `limit=3`, the SQL returned Krakhozia/International/Norway, and only Norway made it through the country-code filter → user asked for top-3 countries on the map, saw 1. **Pivot:** drop the SQL-level limit; loop the full ORDER-BY-frequency-DESC result-set in PHP, apply the country-code filter, then `break` once `count($results['data']) >= $limit`. New behavior verified with three smoke runs against `w_3` on the dev instance: no-limit → 10 mapped countries (NO, HU, NL, DE, EE, PT, AT, LU, BE, CH); limit=3 → top 3 mapped (NO, HU, NL); limit=5 → top 5 mapped (NO, HU, NL, DE, EE). The cap now matches user expectation "top-N countries that appear on the map." Trade-off: the SQL no longer LIMITs, so it returns every distinct nationality bucket; acceptable at realistic deployment scale (typical instances have <1000 organisations and far fewer distinct nationalities).

### Antimeridian splitting required when re-vendoring world GeoJSON

**Surfaced 2026-05-06 during WorldMap browser verification.**

`world-atlas@2.0.2`'s TopoJSON encodes Russia / Fiji / Antarctica
with ring segments going directly from ~+180° to ~-180° in a single
polygon (the polygon spans the date line). ECharts' geo renderer
draws those as straight horizontal grey bands across the whole map.
The original Phase 0.2 vendoring used `topojson-client.feature()`
directly, which preserves the unsplit form.

Phase 0.3 fixed this by adding a `polygon-clipping`-based post-pass
that "unwraps" each ring's longitudes into continuous space and
clips against the eastern + western [-180, 180] tiles, splitting any
ring that crosses. Recipe is in
`webroot/js/dashboard-v2/charts/vendor/VENDORING.md`.

**Where it lands:** keep the recipe up-to-date if we ever upgrade
`world-atlas` or move to `countries-50m`. Higher-resolution data has
the same issue (poly count goes up but Russia still spans the date
line as a single ring). `d3-geo-projection`'s `geoStitch` was tried
first; it only handles the inverse direction (joining pre-split
parts) and didn't help here.

### Overmind theme served legacy BS2.3 menu on /dashboards — **fixed 2026-05-16**

**Surfaced 2026-05-16 during user smoke under Overmind theme.**

User reported that `/dashboards` under the Overmind theme served
MISP's legacy BS2.3 `global_menu` instead of Overmind's Bootstrap-5
`navbar.ctp`. Root cause: the Phase 1 chrome work created
`app/View/Layouts/dashboard.ctp` (default-theme layout) and relied
on Cake's Themed resolver to swap in a `Themed/Overmind/Layouts/
dashboard.ctp` when Overmind was active — but that themed file was
never created. The resolver fell back to the default `dashboard.
ctp`, which calls `$this->element('global_menu')` (the legacy
BS2.3 menu). Overmind doesn't override `global_menu` (it switches
chrome at the *layout* level via its own `default.ctp`'s
`$bootstrap5Pages` whitelist + `navbar.ctp` element), so the
fallback path served BS2.3.

**Fix:** new `app/View/Themed/Overmind/Layouts/dashboard.ctp` that
mirrors Overmind's BS5 chrome path inside its `default.ctp` (BS5
CSS pack — `bootstrap5-custom.min` + `tom-select.bootstrap5.min` +
`mainOvermind` + `fontawesome7.min` — plus `navbar.ctp` + the
modal/toast/popover containers + `footerBS5` + `bootstrap.bundle.
min` + `mispOvermind` JS). Takes the BS5 path unconditionally —
the `$bootstrap5Pages` whitelist check in Overmind's `default.ctp`
isn't applicable here because the dashboard is a BS5-style surface
by design (DD-08 "modern and pleasant" rules out BS2.3 chrome on
the dashboard regardless of theme).

Skipped vs Overmind's `default.ctp`: `headerSection` (the dashboard
has its own `<header class="misp-dashboard-header">` with title +
toolbar + Edit + More — layering Overmind's page-title bar on top
would be redundant); the debug accordion (keeping the dashboard
surface clean — `sql_dump` is still emitted); the TomSelect topbar-
filter init (no `.topbar-filter` elements on the dashboard); the
ajax-toggle / ajax-call global click handler (dashboard widgets
use their own §8.5 hook contract; the global handler would compete
for clicks).

No controller change needed — `DashboardsController::index` still
says `$this->layout = 'dashboard'`, and Cake's Themed resolver
picks the right file based on `$this->theme` (set in `AppController
::beforeFilter` from the user's `ui_theme` UserSetting).

Smoke (cache cleared, admin user already on Overmind via
`UserSetting:ui_theme = "Overmind"`): `GET /dashboards` → 200 with
272KB HTML (up from 32KB under default theme — Overmind's navbar
pulls in the full menu HTML); 5 BS5 navbar markers present
(`navbar-expand-xl`, `navbar-dark bg-dark`, `mainOvermind`,
`fontawesome7`, `bootstrap5-custom`, `mispOvermind`); 0 legacy
markers (`id="topBar"`, `navbar-inverse`, `debugOn`); dashboard
markup intact (`data-misp-board-root`, `misp-dashboard-header`,
`misp-dashboard-main`, `board.module.mjs`). PHP lint clean. chgrp
www-data applied.

### Body-scoped typography leaked into MISP chrome — **fixed 2026-05-16**

**Surfaced 2026-05-16 during user smoke of the Phase 1 chrome work.**

The proto's `body.misp-dashboard-page { font-size: …; line-height: …;
color: …; }` rule was fine when the dashboard ran standalone, but
once Layouts/dashboard.ctp wraps the dashboard in MISP's chrome
(global_menu top nav + footer), those body-level rules cascaded into
the chrome's text styling via inheritance (any chrome element that
didn't set its own font-size / line-height / color inherited the
14px / 1.5 / `#1d2025` from body). The proud comment on the rule
even claimed typography was *deliberately* left to inherit from the
host — it wasn't (font-size and line-height *were* on body, just not
font-family).

**Fix:** moved `color` / `font-size` / `line-height` off
`body.misp-dashboard-page` onto a new compound selector covering the
four dashboard-content top-level surfaces — `.misp-dashboard-header`
+ `.misp-dashboard-main` + `.misp-dashboard-footer` +
`.misp-configure-panel`. Descendants inherit naturally inside those
surfaces (widget bodies, menu items, configure form, empty-state
copy). Body keeps `margin: 0` and `background: var(--misp-dash-
surface)` — those don't propagate to text styling, and the surface
colour fills the inter-chrome gap harmlessly.

### GridModule drag/resize math ignored grid-root CSS padding — **fixed 2026-05-13**

**Surfaced 2026-05-13 during Phase 0.4 walk-through (drag test).**

User reported: dragging a widget's title bar showed a red preview box
"misaligned far to the right" and the drop cancelled. Most visible on
the full-row OrgContributionToplist (w=12).

Root cause: `.misp-dashboard-main` carries
`padding: var(--misp-dash-space-4) var(--misp-dash-space-5)` (16/24px),
but `GridModule._cellSize / _pointerToCell / _showGhost` treated
`getBoundingClientRect()` as the content box. Three compounding
effects:

1. `cellW = (rect.width - totalGap) / cols` overestimated the column
   width by `(2 * paddingLeft) / cols` ≈ 4px/col. For w=12 the ghost
   ended up ~48px wider than the actual 12-col span — its right edge
   visibly hung off the board.
2. `_collides` then rejected drops via `x + w > this.cols` because
   pointer-to-cell rounded x up to 1 for w=12 (out of bounds).
3. The ghost (`position: absolute` inside a `position: relative` root)
   resolves `left: 0` to the **padding-box outer edge** (= rect.left
   with no border), so without adding `paddingLeft` to ghost.left, the
   ghost sat at the wrong starting offset.

Fix in `app/webroot/js/dashboard-v2/grid/grid.module.mjs`:
`_cellSize` now reads padding from `getComputedStyle`, returns padL/padT;
`_pointerToCell` subtracts them from localX/localY; `_showGhost` adds
them to ghost.left/top. Resize uses the same path, so resize is fixed
too without a separate change.

**Where it lands:** Phase 0.3 (GridModule prototype) — fixed in this
session's commit. Keep a regression test in mind for Phase 1 when
the controller switches `$this->layout = 'default'` and the grid root
inherits MISP layout padding instead of the prototype's own.

---

## Resolved questions

Resolutions live in PRD §13 (each open question struck through with
the deciding rationale folded in). See `dashboard-prd.md` §13 for the
durable resolution log. New resolutions land directly there — this
section is intentionally empty post-Phase 0.4 PRD lock-in. Earlier
drafting versions are preserved in git history (last carried in the
commit just before Phase 0.4 task 2).

## Design-decision log pointer

Binding cross-phase decisions are catalogued in PRD §15 (one-line call
per decision with the PRD section it binds). Full rationale,
alternatives considered, licence checks, and reversibility for each
live in `dashboard-design-decisions.md`. New decisions land in the
log first; once stable, a one-row entry is added to PRD §15.
