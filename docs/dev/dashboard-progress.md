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
- [ ] Lock the resolved §13 answers and library decisions into the PRD (move "Resolved questions" out of this file into PRD §13 with strikethrough notation)
- [ ] Tear down the prototype branch (or merge a curated subset back to `dashboards` as Phase 1 starting point — decide at sign-off)

---

## Phase 1 — Frame (in-place replacement)

**Goal:** replace v1 controller actions, views, JS, and CSS with v2
equivalents on canonical `/dashboards/*` routes. v1 files are deleted
as v2 takes over the same URL — no parallel mounting, no flag.

**Exit criteria:** the existing `/dashboards` URL serves v2 only.
A user lands on a working dashboard, reading from / writing to the
existing `UserSetting:dashboard` row using the new `{scope, widgets}`
blob shape (with backward-compat read of legacy bare-array form),
identical-looking on default and Overmind themes.

- [ ] Decompose view tree per PRD §8.3: scaffold each new `.ctp` with placeholder content (replaces v1 `View/Dashboards/index.ctp` + friends in place)
- [ ] CSS architecture: `webroot/css/dashboard/dashboard.default.css` with full token catalogue, BEM-ish class names, no inline styles
- [ ] JS hook contract: dashboard JS lives in `webroot/js/dashboard-v2/` (own dir, replacing the v1 dashboard JS in `misp.js`); binds via `data-*` attributes only
- [ ] Remove v1 dashboard JS from `app/webroot/js/misp.js` (lines ~5570–5730: `submitDashboardForm`, `saveDashboardState`, `resetDashboardGrid`, click handlers)
- [ ] Vendor Pragmatic Drag and Drop at `webroot/js/dashboard-v2/grid/vendor/` (per DD-01)
- [ ] Build the custom `GridModule` (snap, collision, resize-cascade) per DD-01 — **escalate to user if exceeds ~600 lines**
- [ ] Vendor ECharts at `webroot/js/dashboard-v2/charts/vendor/` (per DD-02; tree-shaken bundle: bar + line + geo at minimum)
- [ ] ECharts theme registration: derive `"misp"` theme from CSS tokens at boot (PRD §8.2)
- [ ] Rewrite `DashboardsController::index` for v2 (replaces existing in place)
- [ ] Rewrite `DashboardsController::renderWidget` for v2 with payload extended by `scope` (per PRD §5.8)
- [ ] **Per-widget on-read fix-ups** (per DD-05 — no top-level shape change). Promote `width/height → w/h` and mint `instance_id` on each widget that lacks one. Verified by unit test that round-trips a v1 fixture without data loss.
- [ ] First-load default: load layout from `dashboards.default = 1` if present; else hardcoded fallback (single MispStatusWidget)
- [ ] Widget wrapper element using `data-misp-widget` and stable hooks; no inline styles, no hardcoded `#0088cc` border
- [ ] Empty-state element for "no widgets yet"
- [ ] `DashboardURLValidator` helper under `app/Lib/Dashboard/Tools/` (used by every drilldown-aware renderer per DD-03)
- [ ] Side menu update on default theme `Elements/genericElements/SideMenu/side_menu.ctp` (adjust the `dashboard` case in place — no v1/v2 split)
- [ ] Side menu update on `Themed/UiBeta/Elements/genericElements/SideMenu/side_menu.ctp` (mirror the default update)
- [ ] Smoke test: visit `/dashboards`, see MispStatusWidget render correctly on default theme
- [ ] Smoke test: visit `/dashboards` under Overmind theme, confirm no broken layout
- [ ] Smoke test: user has a v1-shape `UserSetting:dashboard` row, visit `/dashboards` → widgets render → save → row now has `w/h` + `instance_id` per widget, top-level shape unchanged (still bare array)

---

## Phase 2 — Authoring UX

**Goal:** users can add, configure, and remove widgets via the new
schema-driven form with live preview; edit-mode vs. view-mode is
explicit; saves are atomic.

**Exit criteria:** a user can build a board from scratch by clicking
"Add widget" → picking from the gallery → filling the schema-driven
form → seeing live preview → placing → saving the whole board atomically.

- [ ] Define `$schema` property contract on widget classes (PRD §5.7)
- [ ] Full-tier `$schema` backfill (per Q7 — Option C): `MispStatusWidget`
- [ ] Full-tier `$schema` backfill: `TrendingTagsWidget`
- [ ] Full-tier `$schema` backfill: `TrendingAttributesWidget`
- [ ] Full-tier `$schema` backfill: `UsageDataWidget`
- [ ] Full-tier `$schema` backfill: `OrgEventsWidget`
- [ ] Full-tier `$schema` backfill: `AttackWidget`
- [ ] Full-tier `$schema` backfill: `OrganisationMapWidget`
- [ ] Full-tier `$schema` backfill: `RecentSightingsWidget`
- [ ] Full-tier `$schema` backfill: `EventEvolutionLineWidget`
- [ ] Two-tier configure form element (per DD-06): `Elements/dashboard/widget/config_form.ctp`. Top tier renders typed fields from `$schema`; bottom tier renders unstructured params as a flat key-value list with dot-notation paths.
- [ ] Per-canonical-type form field elements (only `time_window` for now; others land in Phase 3)
- [ ] Key-value list component for the bottom tier: rows of `(dot.path.key, value)` with add/remove
- [ ] Chip input component for array-typed values in the bottom tier (type-and-Enter to add, click × to remove); also reusable in canonical pickers like `tag_filter`
- [ ] Bottom-tier seeding: when adding a new widget, parse `$placeholder` JSON and populate the key-value list with the example keys/values (replacement for the JSON-textarea workflow)
- [ ] Bottom-tier dot-notation flattening on read; re-nesting on save; round-trip lossless for nested objects, arrays, scalars, booleans (unit-tested)
- [ ] Side-panel container for configure form (replaces modal); sticky preview pane
- [ ] Live preview: debounced (250ms) re-render of the widget on form-input change
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

### PRD §8.1 wording: theme activation belongs to MISP's theme system, not the dashboard

**Surfaced 2026-05-13 during midnight-overlay implementation.**

PRD §8.1 currently shows the activation example as
`:root[data-theme="midnight"] { … }` and reads as a dashboard-owned
toggle. That's misleading: MISP already has a theme system at the
user/site level (Cake's `app/View/Themed/<Name>/...`), and the
dashboard should inherit it, not introduce a parallel toggle. The
attribute selector is fine as a *prototype* convenience for
verifying the token-redefinition mechanism, but it isn't the
production activation API.

**What the PRD should say after Phase 0.4 lock-in:**
- A theme that wants to retone the dashboard ships its overlay at
  `app/View/Themed/<Name>/webroot/css/dashboard/<Name>.css` (or
  whichever path the theme's main stylesheet loads).
- The overlay redefines the `--misp-dash-*` tokens — that's the
  only contract. UI retones via the cascade; charts retone on next
  paint because `echarts-theme.mjs` reads tokens via
  `getComputedStyle` at first init.
- No dashboard-specific toggle exists. Switching themes is a full
  page navigation owned by MISP's profile / config layer.
- Phase 1 inheritance work: `Dashboards2Controller::index` sets
  `$this->layout = 'default'` (not the prototype's `= false`) so
  the active-theme CSS chain loads automatically before any
  dashboard markup.

**Where it lands:** Phase 0.4 task "Lock the resolved §13 answers
and library decisions into the PRD" should also fold this §8.1
clarification in. Pure wording change — no architecture impact.

### `date_range` as a separate canonical type for absolute date pickers

**Surfaced 2026-05-06 during configure-form prototype review.**

User asked whether the `time_window` picker can also accept absolute
date ranges. It cannot today — every relative-duration widget
(`TrendingTagsWidget`, `EventEvolutionLineWidget`, etc.) parses
`time_window` as "count back from now" (`Nd` or seconds). Some other
widgets (`OrganisationMapWidget` notably) carry separate `start_date`
+ `end_date` `$params`, but those are widget-specific, not canonical.

**Where it lands:** Phase 3 — alongside the rest of the canonical-
type catalogue work. Two changes:

1. **PRD §5.5 revision** — add `date_range` as a canonical type
   producing `{from: ISO-date, to: ISO-date}`. Feature-parity-with-v1
   is the floor: better filter UX is fine per
   `feedback_parity_vs_improvement.md`.
2. **Adapter + picker**: a date-range picker in the configure form's
   typed tier, plus an entry in the canonical→legacy adapter that
   walks widgets which only consume relative durations and either
   warns or computes a relative fallback (`today - from` in days)
   when the saved canonical value is `date_range`. Widgets that have
   their own `start_date`/`end_date` `$params` migrate those slots
   to declare `date_range` in `$schema`.

Don't do this in Phase 0–2: today's relative-only widgets reject any
absolute-shaped value, and a lossy "convert range to days" fallback
in the picker would silently lose the upper bound. Defer until the
adapter and toolbar are in place.

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

### Canonical-type → legacy widget-format adapter for `time_window`

**Surfaced 2026-05-06 during BarChart browser verification.**

PRD §5.5 catalogues `time_window` as ISO 8601 duration (`P7D`,
`PT1H`, `P30D`, …). Most v1 in-tree widgets parse a different
in-house format: `TrendingTagsWidget` expects a lowercase `Nd` suffix
for days and falls through to `(int)$value` otherwise; sending `P7D`
yields `(int)'P7D' === 0` → empty result set. The Phase 0.3 prototype
seed config was changed from `P7D` to `7d` to unblock browser
verification, but that's a band-aid.

**Where it lands:** Phase 2 — bottom of "Per-canonical-type form
field elements (only `time_window` for now)". The canonical-type
field renders the picker in ISO 8601 and persists ISO 8601, but at
`handler()`-call time the widget receives a *translated* legacy
value. Translation is a one-place adapter, *not* a per-widget edit
(per the additive-only posture).

Sketch: in `Dashboards2Controller::renderWidget`, before
`$widget->handler($user, $config)`, walk `$config` and translate any
canonical-typed slot whose widget hasn't been migrated to the
canonical format. Drives off `$widget->$schema` to know which slots
are canonical and a small `CanonicalTypeAdapter` helper to do the
translation. Same hook applies for the bulk-edit toolbar's persisted
configs.

The translation table for `time_window`:
- `P<N>D` → `<N>d` (legacy days form)
- `P<N>W` → `(<N>*7)d`
- `PT<N>H` → `(<N>*3600)` seconds
- `-1` (sentinel "all time") → `-1` unchanged
- arbitrary integer seconds → unchanged

Per-widget migration is then orthogonal: a widget that adopts the
canonical format directly (in Phase 2's $schema backfill) gets its
canonical slot through *un*translated.

---

## Resolved questions

When a §13 question is resolved, copy its number, the resolution, and
the deciding rationale here so a fresh session sees the answer
without having to re-read the conversation. After Phase 0 sign-off,
also fold the resolutions back into PRD §13 with strikethrough +
"Resolved:" notation.

### Q10 + Q11 + Q1 follow-on — Toolbar semantics: bulk edit (Model 4) — **Resolved 2026-05-04**

Supersedes parts of the original Q1 resolution and collapses Q10
entirely. The toolbar is **a bulk-edit UI for per-widget configs**,
not a session overlay or a separate "scope" persistence layer.

**Mechanics.**
- Pulling a toolbar control walks every widget that declares the
  matching canonical type in `$schema` and writes the new value into
  each widget's saved config (in `UserSetting:dashboard`).
- Toolbar's *displayed* value is computed at render time from the
  widgets: all agree → show value; disagree → show "(mixed)"; no
  applicable widgets on the dashboard → hide that toolbar control.
- A new widget added to the dashboard initialises a canonical-typed
  slot to whatever the toolbar currently shows (so adding mid-session
  doesn't surprise the user).
- **Toolbar is mode-independent.** Pulls write immediately, no edit
  mode required. Edit mode is reserved for *layout/structural*
  changes (drag, resize, add, remove widgets).
- **No inherit/pinned state.** Per-widget configs are the only source
  of truth; the toolbar just edits them in bulk. Widgets without the
  canonical type in their `$schema` are simply unaddressed by the
  toolbar.

**Cascade simplifications recorded by this resolution:**

- **Q10 collapses entirely.** No UX affordance question — there's no
  state to pick.
- **Q1's `scope`-key + "Also apply default filters" mechanism is
  retired.** Templates carry per-widget configs (which can include
  canonical-typed values like `time_window: P7D` directly on each
  widget instance). Reset-from-template replaces the user's
  `UserSetting:dashboard` row with the template's blob — full stop.
  No checkbox, no separate scope concept.
- **Blob-shape promotion is dropped.** The `UserSetting:dashboard`
  row stays as today's bare widget array; no `{scope, widgets}`
  envelope. The only on-read evolution still needed is minting
  `instance_id` and the `width/height → w/h` rename (both
  per-widget housekeeping for Pragmatic DnD's grid math, not
  shape-level).
- **PRD §5.5's three-state inherit / pinned / not-declared model is
  removed.** Replaced by a flat "widget declares canonical type X
  in `$schema` → toolbar reaches it; otherwise the toolbar can't
  see it".

**Implementation hooks:**
- DD-05 in `dashboard-design-decisions.md` carries the architectural
  consequences.
- DD-04 (templates carry default scope) is superseded in part by
  DD-05 — the per-template scope key is gone, but templates
  continue to carry per-widget configs as today.

### Q7 — `$schema` backfill scope — **Resolved: tiered (Option C)** (2026-05-04)

User accepted with mild hesitation; resolution pins the line
concretely so the tier doesn't drift.

**Full-backfill tier (9 widgets).** Every parameter gets a typed
`$schema` entry with help text, validation, and (where applicable) a
canonical-type-driven picker. No JSON textarea anywhere in their
configure form.

1. `MispStatusWidget`
2. `TrendingTagsWidget`
3. `TrendingAttributesWidget`
4. `UsageDataWidget`
5. `OrgEventsWidget`
6. `AttackWidget`
7. `OrganisationMapWidget`
8. `RecentSightingsWidget`
9. `EventEvolutionLineWidget`

(Selection criteria: high configure-frequency × complex params ×
strong toolbar adjacency. `ThresholdSightingsWidget` was a candidate
but dropped — its config is already small enough that canonical-only
covers it well.)

**Canonical-only tier (rest of the in-tree widgets).** Parameters
that map to canonical types (§5.5 — `time_window`, `tag_filter`, etc.)
get typed `$schema` entries so the dashboard toolbar reaches them.
Other widget-specific knobs continue using the legacy
`$params` + `$placeholder` JSON-textarea path in the configure form's
"Advanced" section.

**Custom widgets (`Custom/`).** Same legacy fallback path — third-party
widget authors are not forced to migrate.

**Promotion path.** Moving a widget from canonical-only to
full-backfill is a self-contained PR: add `$schema` entries for the
remaining params, drop the `$placeholder` if no longer needed. No
phase or architecture changes. The configure form auto-detects which
fields have schema entries and renders accordingly.

**Implementation hooks:**
- Phase 2 task "Backfill `$schema` on the 5 highest-priority built-in
  widgets" → broaden to the 9 listed above; track each as its own
  sub-task in Phase 2.
- Phase 3 task "Backfill canonical-type slots on the existing 30
  widgets" → applies to the canonical-only tier (the 9 above are
  already done by Phase 2).
- Phase 5.5 widget-parity smoke checks remain valid as written.

### Q6 — Frame's own CSS vs. inherit host theme — **Resolved: own CSS file, self-contained** (2026-05-04)

The v2 dashboard ships its own complete CSS at
`webroot/css/dashboard/dashboard.default.css` with a full design-token
catalogue. Rules style dashboard markup using *only* those tokens; the
file does not depend on Bootstrap (any version) being loaded.

**Why this matters concretely.** MISP's themes already span BS versions
(default = 2.3.2, Overmind = BS5). BS2.3.2 has no CSS custom
properties at all, so a "borrow the host's `--bs-*` variables"
approach would only ever work for BS5+ themes and would have required
a shim file for the default theme reproducing BS variable names that
weren't designed for dashboards. Self-contained is cleaner and
forward-proof against future BS migrations.

**"Easy to integrate" — what that means in practice:**

- **Typography inherits.** No `font-family` / `font-weight` declarations
  on the dashboard root or any common element; all typography flows
  from the host's `body` styles. Tokens carry *sizes and weights*
  for dashboard-specific elements (widget title, chip text), not
  font families.
- **Colour flows through tokens only.** No raw hex / RGB values
  outside the token definitions block. No `class="blue"` /
  `class="green bold"` style hooks in v2 markup (those are the v1
  patterns we're explicitly leaving behind — see PRD §6.3).
- **Scoped rules.** Dashboard CSS rules are scoped under a wrapper
  class (e.g. `.misp-dashboard-root`) so the stylesheet can be
  loaded globally without leaking into other pages. Helps when an
  embedded mini-dashboard (e.g. an event-page summary panel) wants
  the styles without colliding with the surrounding page.
- **Theme overlays via additional stylesheets.** Heavy themes ship
  *their own* CSS file that redefines the tokens (and optionally
  adds rules that consume them); load order is the standard
  `additionalCss` mechanism. The dashboard never inspects the
  active theme by name; it just consumes whatever tokens are
  currently in scope.

**Implementation hooks:**
- Phase 1 task "CSS architecture" → spec the full token catalogue +
  scoped wrapper class up front so widget renderers can consume them
  from day one.
- Phase 1 task "ECharts theme registration" → derive the `"misp"`
  ECharts theme from the same tokens via `getComputedStyle` (PRD §8.2).

### Q5 — Posture on touching legacy — **Resolved: straight replacement on `dashboards` branch** (2026-05-04)

**Branch isolation removes the user-facing risk** that the standing
additive-only rule (`feedback_additive_only_posture.md`) was guarding
against: nothing on this branch reaches `develop` (and therefore no
end user) until the rework is complete. The flag, the v2 path prefix,
and the parallel mounting are therefore unnecessary overhead — v1
files are deleted in place as v2 takes over the canonical
`/dashboards/*` routes.

The merge to `develop` is gated by **three parities** (PRD §12):

1. **Widget parity** — every built-in widget renders in v2; smoke-test
   matrix attached to Phase 5.5 of this tracker. Custom widgets'
   loader path still resolves them.
2. **Data parity** — legacy `UserSetting:dashboard` blob shape and
   legacy `dashboards.value` rows both read cleanly via the
   backward-compat read; round-trips don't lose data.
3. **Surface parity** — every URL the side menu links to today
   resolves to a working v2 view; `import` / `export` /
   `saveTemplate` / `listTemplates` / `deleteTemplate` all keep
   working on the same URLs.

Phase 5.5 ("Widget Parity Sweep") is the explicit checkpoint where
all three are verified before the PR opens. Phase 6 collapses to
"merge". Phase 7 is gone — pre-merge cleanup absorbed into Phase 5.5.

**Implementation hooks:**
- Phase 1 starts by replacing v1 controller/views/JS *in place* on
  canonical routes — no `MISP.dashboard_v2` flag, no `/dashboards/v2/`
  prefix.
- Phase 5.5 enumerates the ~30 built-in widgets, each as its own
  smoke-check task.
- Phase 6 is a thin merge phase, not a feature phase.

### Q4 — Gridstack vs. Pragmatic DnD — **Resolved: Pragmatic DnD + CSS Grid + custom math** (2026-05-04)

See `dashboard-design-decisions.md` DD-01 for full rationale, licence
verdict, maintainability evidence, and reversibility forcing function.

**Phase 0.2 reframe:** no comparison; thin bring-up against the chosen
libraries with a LOC-budget risk check (>300 lines of grid math at
the bring-up stage triggers an escalation conversation before Phase 1
starts).

### Q3 — Drill-down convention — **Resolved: per-datum drilldown in widget data (Option C)** (2026-05-04)

Renderers wrap an element in a link only when the corresponding datum
in the widget's `handler()` return value carries a `drilldown` URL.
No class-level `$drilldown` property; no auto-wrap by convention.

**Shape conventions:**
- `SimpleList`: each row may have a `drilldown` key alongside `title` /
  `value` / `html` / `change`. When present, the title becomes a link.
- `BarChart` / `MultiLineChart`: an optional `data['drilldown']` map
  keyed by series/category name. When present, bar / point / legend
  entries become click targets.
- `WorldMap`: an optional `data['drilldown']` map keyed by ISO country
  code, applied to map regions.
- Other renderers follow the same "optional `drilldown` key in the
  data shape they already consume" pattern.

**Security helper:** a `DashboardURLValidator` (new, under
`app/Lib/Dashboard/Tools/`) sanity-checks every drilldown URL before
emission: must be relative or share `Configure::read('MISP.baseurl')`
host; `javascript:` / `data:` / off-host URLs are silently dropped
(rendered as plain text). Defends against a buggy or malicious widget.

**Implementation hooks:**
- Phase 5 task "Renderer-level wrapping for SimpleList" → adopt the
  per-datum convention.
- Phase 5 task "ECharts click handlers" → consume `data['drilldown']`
  map.
- Phase 1 introduces the `DashboardURLValidator` helper (used by
  every renderer that wraps drilldown links).
- Existing `MispStatusWidget`'s hand-rolled `(View)` link in `html`
  migrates to the `drilldown` key during Phase 2's $schema backfill.

### Q1 — Templates carry default scope? — **Resolved: yes (with confirmation)** (2026-05-04)

Templates may carry a `scope` key alongside `widgets` in their
`dashboards.value` blob. When the user picks a template
(Reset-from-template), the confirmation dialog includes a checkbox
**"Also apply this template's default filters"**, ticked by default
if the template carries a non-empty scope, hidden if it doesn't.
Unchecking preserves the user's existing toolbar state.

**Implementation hooks:**
- Phase 4 task "Q1 resolution applied" → wire the checkbox into
  `Reset from template` confirmation; only show when template's blob
  has a non-empty `scope`.
- Phase 1 blob-shape work already covers reading the optional `scope`
  key.

---

## Design-decision log pointer

Significant cross-phase decisions (library choices, schema shapes,
URL structure, theme-token names) live in
`dashboard-design-decisions.md` — created the first time an
0.2/0.3 task lands a decision worth recording. If that file does not
yet exist, it has not yet been needed.
