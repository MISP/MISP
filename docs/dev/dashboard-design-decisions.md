# Dashboard v2 — Design Decision Log

**Purpose.** Cross-phase decisions worth pinning for fresh sessions:
library choices, schema shapes, URL structure, theme-token names.
A fresh session should read this *before* reading task-level state in
`dashboard-progress.md`, because these decisions constrain the
implementation tasks.

**Discipline.** One decision per `### DD-NN` heading. Each entry
records: the call, the date, the rationale (one short paragraph), the
alternatives considered, the licence/maintainability check, and the
reversibility (what would force a revisit, what the cost of switching
later would be). New decisions append to the bottom; existing
decisions stay; if a decision is overturned, it gets a follow-up
entry rather than being edited in place — the trail matters.

---

## DD-01 — Drag and drop / grid layout: **Pragmatic Drag and Drop + CSS Grid (custom math)**

**Date.** 2026-05-04
**Phase context.** Resolves §13 Q4 (PRD). Affects Phase 0.2, Phase 1.

**Decision.** Replace Gridstack entirely. The dashboard layout uses
**CSS Grid** for placement and **Pragmatic Drag and Drop** (Atlassian,
Apache 2.0) for the drag/resize gestures. The snap, collision,
resize-with-cascade, and mobile-touch logic is custom code we own,
expected to be ~200–400 lines of vanilla JS in `webroot/js/dashboard-v2/grid/`.

**Rationale (per user, 2026-05-04).** Lean is preferred; smaller
maintained surface area; no upstream-version-bump risk; modern vanilla
DOM API alignment. Both candidates were licence-compatible; Pragmatic
DnD wins on bundle size (~10KB vs. ~50KB) and on owning-our-grid-math
giving us fewer external opinions to bend to design tokens.

**Alternatives considered.**
- **Gridstack v11+** — batteries-included (snap, collision, mobile,
  a11y) and a known quantity. Rejected because the batteries cost
  bundle size and CSS opinions; user prefers leaner with custom math.
- **Sortable.js** — drag/sort only, no grid math. Strictly weaker
  than Pragmatic DnD for the same job.
- **Muuri** — flex-grid hybrid; awkward for column-aligned dashboards.
- **Native HTML5 DnD only** — accessibility and touch are weak;
  Pragmatic DnD specifically solves these.

**Licence.** Pragmatic Drag and Drop is **Apache 2.0**. AGPL × Apache
2.0 is a known one-way-OK combination (Apache 2.0 is permissive; an
AGPL project can include Apache 2.0 dependencies without contagion).

**Maintainability.** Pragmatic DnD is developed by Atlassian and
powers production drag interactions in Jira, Trello, and GitHub
Issues. Active maintenance; public repo at
`atlassian/pragmatic-drag-and-drop`. Treated as a low-bus-factor risk
for the foreseeable future. (User noted personal sentiment toward
Atlassian; the dependency itself is sound.)

**Reversibility.** Switching off Pragmatic DnD later is a *one-file*
change: the grid module wraps it behind a small adapter (`PragmaticDndAdapter`)
so an alternative drag source could be substituted without touching
the snap/collision logic. **Force a revisit if** during Phase 1 the
custom grid math exceeds ~600 lines or grows >40% of Phase 1's effort
budget — escalate to the user before continuing.

**Implementation implications.**
- Phase 0.2: drop the "Gridstack v11 trial" task; replace with a
  small bring-up of Pragmatic DnD against 3 widgets, focused on
  validating the snap/collision math complexity ahead of Phase 1.
- Phase 1: vendor Pragmatic DnD at `webroot/js/dashboard-v2/grid/vendor/`;
  custom grid module at `webroot/js/dashboard-v2/grid/`.
- Cleanup (Phase 7): the `gridstack.all.js`, `gridstack.min.css`,
  and `.bk` siblings get deleted with the rest of v1.

---

## DD-02 — Charting library: **Apache ECharts** (with potential uPlot follow-up)

**Date.** 2026-05-04
**Phase context.** Pinned PRD goal §G10. Affects Phase 0.2 and
all subsequent renderer work.

**Decision.** All chart renderers (`BarChart`, `MultiLineChart`,
`WorldMap`, future heatmap/treemap/sankey) consolidate on
**Apache ECharts**. Replaces the current mix of D3 v3-era code,
jvectormap 2017, hand-rolled HTML divs, and Chart.js (the latter
remains for non-dashboard pages but is *also* a candidate for ECharts
consolidation later — out of scope for this PRD).

**Rationale.** One library covers bar/line/multi-line/area, geo maps
(built-in `world.json`), heatmap, treemap, sunburst, sankey. ESM
tree-shaken builds keep bundle size manageable for the subset we use.
Theme system maps cleanly onto the design-token approach (G11).
Replacing three libraries with one is a net code reduction.

**Alternatives considered.**
- **uPlot** — 50KB gz, ~100× faster than ECharts on dense time-series.
  Not a full replacement (no maps, no treemaps), but a strong fit for
  performance/system-resource widgets specifically. **Resolved
  2026-05-06 — ECharts only, no uPlot.** Trial deemed a foregone
  conclusion without running code: every in-tree time-series widget
  (`MispSystemResourceWidget`, `EventEvolutionLineWidget`,
  `OrgEvolutionLineWidget`, `MultiLineChart` consumers) renders <500
  data points; ECharts handles that with no perceptible lag. uPlot's
  performance edge only kicks in around 5,000+ points. Adopting a
  second chart library would add real maintenance cost (theming,
  upgrades, two interaction models for users) for a hypothetical
  perf gain. **Re-trigger conditions** for a future revisit:
  (a) a new widget needs >5,000 points per render with sub-100ms
  paint; (b) we ship a widget streaming live data faster than 1 Hz;
  (c) ECharts' tree-shaken bundle grows past ~400 KB gzipped after
  adding more chart types and we need a second-tier "perf-only"
  library to keep one widget lightweight.
- **Chart.js v4** — simpler; missing geo, heatmap, treemap, sankey.
  Insufficient for this scope.
- **Observable Plot** — declarative, smaller; no geo maps; less
  interactive. Doesn't fit dashboard-grade interactivity needs.
- **D3 directly** — power, but the existing 600-line MultiLineChart
  is exactly the kind of code we want to delete.
- **Highcharts** — commercial licence required for commercial use.
  Incompatible posture for an AGPL project's downstream users.

**Licence.** Apache ECharts is **Apache 2.0**. AGPL × Apache 2.0 is
one-way-OK (same as DD-01).

**Maintainability.** ECharts is an Apache Foundation top-level
project. Stable governance, large community, frequent releases.
Low-bus-factor risk.

**Reversibility.** Renderer templates (`Elements/dashboard/Widgets/*.ctp`)
each consume a small, stable widget data shape (per DD-03 below).
Swapping the chart library means rewriting the renderer body, not the
widget classes or the data shape. Roughly a phase of work to switch
later if needed; not a one-way door.

**Implementation implications.**
- Phase 0.2: bundle-size measurement task remains.
- Phase 0.2: uPlot trial task remains as a follow-up question.
- Phase 1: vendor ECharts at `webroot/js/dashboard-v2/charts/vendor/`;
  register theme `"misp"` derived from CSS tokens at boot (PRD §8.2).
- Cleanup (Phase 7): `d3.js` (v3), `jquery-jvectormap-*` removed
  from the dashboard path (after verifying no other consumer remains
  in the codebase).

**Bundle size (measured 2026-05-06 in Phase 0.2).** Tree-shaken
build with BarChart + LineChart + MapChart + supporting components
(Grid, Tooltip, Legend, Title, DataZoom, Geo, VisualMap, Dataset) +
Canvas renderer = **649 KB raw / 216 KB gzipped**. World GeoJSON for
the geo widget adds another **425 KB raw / 146 KB gzipped**. Combined
first-paint cost for a dashboard with geo: ~1 MB raw / ~360 KB
gzipped. Larger than the earlier informal estimate of "~300 KB
gzipped" because geo components dominate. A deployment without geo
widgets pays only the JS cost (216 KB gz). Acceptable for the
desktop SOC dashboard target (PRD non-goal: no mobile-first redesign).
See `webroot/js/dashboard-v2/charts/vendor/VENDORING.md` for the
full breakdown and the trade-offs to revisit later (geo lazy-load,
higher-res maps, naming conventions).

---

## DD-03 — Drilldown convention: **per-datum `drilldown` URL in widget data**

**Date.** 2026-05-04
**Phase context.** Resolves §13 Q3 (PRD). Affects Phases 1 (validator)
and 5 (renderer wiring).

**Decision.** Renderers wrap a rendered element in a link only when
the corresponding datum in the widget's `handler()` return value
carries a `drilldown` URL key. No class-level `$drilldown` property,
no auto-wrap by convention.

**Rationale.** Per-datum URLs give widget authors fine-grained control
("link the bar for `tlp:red` to `/events/index/tag:tlp:red`, but
don't link the 'Total' row"). Class-level URL templates are too
coarse; auto-wrap by convention is brittle (no universal convention
knows where to drill from arbitrary widget output). MispStatusWidget
already proves the per-datum pattern via its hand-rolled `(View)`
link in raw `html`; this decision formalises it.

**Shape conventions per renderer.**
- `SimpleList`: each row may carry `drilldown` alongside `title` /
  `value` / `html` / `change`. Title becomes a link when present.
- `BarChart`, `MultiLineChart`: optional `data['drilldown']` map
  keyed by series/category name; bars / points / legend entries
  become click targets.
- `WorldMap`: optional `data['drilldown']` map keyed by ISO country
  code; map regions become click targets.
- Other renderers follow the same "optional `drilldown` key in the
  data shape they already consume" pattern.

**Security helper.** A `DashboardURLValidator` (new, under
`app/Lib/Dashboard/Tools/`) sanity-checks every drilldown URL before
emission: must be relative or share `Configure::read('MISP.baseurl')`
host; `javascript:` / `data:` / off-host URLs are silently dropped
(rendered as plain text). Defends against a buggy or malicious widget.

**Alternatives considered.**
- **Auto-wrap by convention.** Brittle; breaks for widgets whose
  output doesn't fit the convention; creates accessibility noise.
- **Class-level `$drilldown` URL template.** Too coarse; can't express
  per-row variation.

**Reversibility.** Adopting a more sophisticated convention later
(e.g. JSON Pointer path expressions) is additive — `drilldown`
strings continue to work as a degenerate case.

---

## DD-04 — ~~Templates carry default scope, applied with confirmation~~ — *superseded in part by DD-05*

**Date.** 2026-05-04
**Phase context.** Originally resolved §13 Q1. Superseded later the
same day by DD-05 (Model 4 toolbar semantics).

**Original decision (recorded for trail).** Templates' blob would carry
a `scope` key alongside `widgets`; Reset-from-template would offer an
"Also apply this template's default filters" checkbox.

**Why superseded.** DD-05 collapses the separate "scope" concept
entirely. Templates still carry per-widget configs (and those configs
*can* include canonical-typed values like `time_window: P7D` on
specific widget instances), but there is no top-level `scope` key to
opt into separately, and no checkbox in the Reset confirmation. Reset
replaces the user's blob with the template's, full stop — the
template's encoded values become the user's per-widget configs.

**What's preserved from DD-04.** Templates carry encoded values in the
sense that *each widget instance in the template* can have its
parameters pre-set. The expressive power for template designers is
unchanged; the storage layer is just simpler.

---

## DD-05 — Toolbar is bulk edit; no separate "scope" concept

**Date.** 2026-05-04
**Phase context.** Resolves §13 Q10 (collapsed) and Q11 (reframed).
Supersedes part of DD-04. Affects PRD §G4, §5.5, §5.6, §5.7, §7.1,
and the Terminology section.

**Decision.** The dashboard toolbar is **a bulk-edit UI for per-widget
configs**, not a runtime scope or session overlay.

**Mechanics.**
- Pulling a toolbar control walks every widget on the dashboard that
  declares the matching canonical type in `$schema` and writes the
  new value into each widget's saved config in `UserSetting:dashboard`.
  This is identical to the user opening each widget's configure form
  one by one and changing the value, just done in one action.
- The toolbar's *displayed* state is computed at render time from
  the widgets: all applicable widgets agree on a value → show that
  value; values disagree → show "(mixed)" indicator; no widget on
  the dashboard declares this canonical type → hide that toolbar
  control entirely.
- A new widget added to the dashboard initialises any canonical-typed
  slot it declares to whatever the toolbar currently shows — so
  adding mid-session doesn't surprise the user with the widget's
  hardcoded default.
- The toolbar is **mode-independent**: pulling writes immediately,
  no edit mode required. Edit mode is reserved for layout/structural
  changes only (drag, resize, add, remove widgets).
- **No inherit/pinned state per widget.** Per-widget configs are
  always the source of truth; the toolbar simply edits them in bulk.

**Rationale.** This was always the user's intent ("a quick way to
mass override settings on the user's dashboard ... auto updates the
config of each widget ... persists similarly to any individual widget
config modification"). My earlier Models 1–3 (session overlay,
fallback defaults, inherit/pinned) were over-engineered translations
of patterns from Grafana / Looker that don't fit MISP's edit-heavy
personal-dashboard usage. Model 4 collapses the architecture to one
source of truth and removes a UX affordance question (Q10) entirely.

**Cascade simplifications.**
- PRD §5.5: drop the three-state "inherit / pinned / not declared"
  model. Replace with flat "widget declares canonical type X in
  `$schema` → toolbar reaches it; otherwise it doesn't". Remove
  `BoardScopeHelper`'s inherit/pinned resolution code; widgets just
  read their own `$options` as today.
- PRD §5.6: rewrite mechanics around bulk edit + computed-display.
  Drop "Clear all"-affecting-pin language; "Clear all" simply
  unsets the canonical-typed values across all applicable widgets.
- PRD §7.1: drop the `{scope, widgets}` envelope. The
  `UserSetting:dashboard` row stays as today's bare widget array.
  The only per-row evolution still needed is `width/height → w/h`
  rename and `instance_id` mint, both per-widget housekeeping for
  Pragmatic DnD's grid math (still required for DD-01 to work).
- PRD §5.7 and Terminology: remove "Scope" and "Inherit / Pinned"
  entries. "Canonical parameter type" entry stays — still needed
  for the toolbar's catalogue.
- DD-04: superseded in part (see above).

**Reversibility.** A future "session overlay" or "fallback default"
toolbar mode could be added by introducing a new toolbar mode picker
("Apply to: this session only / save to all widgets"). The default
behaviour stays bulk-edit-and-save; the alternative would be a
deliberate UX addition. Not a one-way door.

**Implementation hooks.**
- Phase 1 task "Blob-shape evolution" → narrow to per-widget
  housekeeping (`instance_id` mint, `w/h` rename); drop the scope
  envelope work.
- Phase 3 task list rewritten: toolbar control logic walks widget
  configs; no inherit/pinned plumbing in `BoardScopeHelper`.
- Phase 4 "Reset from template" task simplified: replace user's
  `UserSetting:dashboard` blob with template's. No checkbox.

---

## DD-07 — Licence compatibility audit (vendored deps × MISP AGPL-3.0)

**Date.** 2026-05-06
**Phase context.** Closes the formal licence sanity-check called out
in Phase 0.2 (formerly hand-waved as "should be fine" in DD-01 and
DD-02). Affects Phase 7 cleanup and any future vendoring.

**Decision.** All Phase 0.2 vendored dependencies are licence-compatible
with MISP's AGPL-3.0. The combined work can be distributed as AGPL-3.0
provided the upstream licence files travel with the bundle (which they
do — see the per-vendor `LICENSE.*` files in
`app/webroot/js/dashboard-v2/{grid,charts}/vendor/`).

**Inventory of licences in scope.**

| Vendored item | Upstream licence | Source | Compatibility verdict |
|---|---|---|---|
| `pragmatic-drag-and-drop.bundle.mjs` | **Apache-2.0** | Atlassian Pty Ltd | ✅ |
| `echarts.bundle.mjs` | **Apache-2.0** | Apache Software Foundation | ✅ |
| `tslib` *(transitive, bundled inside echarts.bundle.mjs)* | **0BSD** (Microsoft) | TypeScript runtime helpers | ✅ — notice preserved in `echarts.bundle.LEGAL.txt` |
| `zrender` *(transitive, bundled inside echarts.bundle.mjs)* | **BSD-3-Clause** (Baidu Inc.) | ECharts' rendering library | ✅ — notice preserved in `echarts.bundle.LEGAL.txt` |
| `world-110m.geojson` | **ISC** (Mike Bostock; data from Natural Earth, public domain) | world-atlas npm package | ✅ |

**Authoritative basis.**

- **FSF licence compatibility list** — <https://www.gnu.org/licenses/license-list.html>
  - Apache 2.0: listed under *"GPL-Compatible Free Software Licenses"*
    with the note "compatible with version 3 of the GPL"; AGPL-3.0
    inherits this since it's a superset of GPL-3.0 with the network-use
    clause.
  - ISC: same section, "compatible with the GNU GPL". Functionally
    equivalent to MIT for compatibility purposes.
  - BSD-3-Clause: same section, "compatible with the GNU GPL".
  - 0BSD: same section, "compatible with the GNU GPL". Effectively
    public-domain-equivalent.
- **One-way compatibility direction.** All of the above are permissive
  licences; combining them into an AGPL work is allowed and the
  combined work must be distributed under AGPL-3.0 (with the
  permissive notices preserved). The reverse — including AGPL code in
  an Apache 2.0 work — is *not* permitted, but that's not our
  direction.

**MISP project precedent.**

The MISP repo already vendors many permissively-licensed JS / CSS
assets in `app/webroot/js/` and `app/webroot/css/`:

- Bootstrap (MIT), jQuery (MIT), Chart.js (MIT), D3 (BSD-3-Clause),
  Moment (MIT), CodeMirror (MIT), Drawflow (MIT), and others ship
  alongside the AGPL MISP source.
- The pattern (vendor under `webroot/`, preserve LICENSE files
  alongside, document attribution) is established. Phase 0.2's
  vendoring follows the same convention.

**Operational requirements** (already satisfied by Phase 0.2 work):

1. Each vendored dependency ships its upstream LICENSE file alongside
   the bundle, named `LICENSE.<package>` so origin is unambiguous.
2. esbuild's `--legal-comments=external` option emits a `*.LEGAL.txt`
   sidecar capturing copyright notices from any transitively bundled
   source code (ECharts pulls in `tslib` and `zrender`). The sidecar
   is shipped alongside the bundle as a separate file.
3. Each vendor directory has a `VENDORING.md` documenting origin,
   version, build recipe, and the licences in play.
4. No upstream dependency requires source disclosure in the AGPL
   sense (none are themselves AGPL or copyleft).

**Reversibility.** Should a future vendored dependency turn up with an
incompatible licence (e.g. proprietary, commercial-use-restricted, or
a different copyleft like LGPL-with-static-linking-restrictions), the
audit table above is the place to flag it; the bundle would have to
be rebuilt without that dependency or the dependency replaced.

---

## DD-06 — Configure form is two-tier (typed fields + dot-notation key-value list)

**Date.** 2026-05-04
**Phase context.** Refines PRD §5.2 F2.2 and PRD §5.7 (`$placeholder`
fallback path). Affects Phase 2.

**Decision.** Each widget's configure form has **two tiers**:

1. **Typed fields tier (top).** For every parameter declared in
   `$schema`, render a type-aware field: a date-range picker for
   `time_window`, a taxonomy-aware tag picker for `tag_filter`, an
   org typeahead for `org_filter`, etc. (per the §5.5 canonical
   catalogue). For widget-specific scalar types (`int`, `bool`,
   `string`, `enum`), render the corresponding native form control.
   Help text from the schema entry shows alongside.

2. **Key-value list tier (bottom, "Advanced").** For every parameter
   *not* declared in `$schema`, plus any free-form keys from the
   widget's saved config that don't match a schema entry, render a
   flat list of rows where each row has a key (dot-notation path,
   e.g. `filter.nationality`) and a value. The list supports
   add/remove/edit row.

**Dot-notation paths.** The list flattens nested config for display:
the saved config

```json
{ "filter": { "nationality": ["FR", "DE"], "sector": "Finance" } }
```

renders as two rows: `filter.nationality = ["FR", "DE"]` and
`filter.sector = Finance`. On save, dot-paths are re-nested into
JSON. Round-trips lossless.

**Value type handling.**
- Scalar values: text input (the widget's validation will catch
  type mismatches at handler time).
- **Array values: chip input** (type-and-Enter to add an item, click
  × to remove). Detected from the existing config value on load;
  for a brand-new key added by the user, an explicit "array" toggle
  on the row picker switches the field to chip mode.
- Object values: not flattened beyond their dot-path key prefix —
  e.g. a deeply nested `a.b.c.d` is allowed but each leaf is a row.
- Boolean values: detected from the saved config; rendered as a
  checkbox.

**Seeded keys.** When the user adds a new widget, the form's
key-value tier seeds from the widget's `$placeholder` JSON (today's
example-config string). Replaces the JSON-textarea workflow: same
educational intent, friendlier surface.

**Custom widgets without `$schema`.** Their entire configure form
collapses to the key-value tier — there's no top tier to render.
This is the migration path for third-party custom widgets without
forcing them to adopt `$schema`.

**Rationale.** Closes the JSON-textarea pain point (PRD §6.3) without
forcing a full `$schema` backfill on every widget (per Q7's tiered
resolution). Power users still have access to every config knob; new
users get rich pickers for the things that matter.

**Reversibility.** Adding more typed-field types later (a richer
canonical catalogue, type-detection on flattened rows) is additive.
Removing the bottom tier later means committing to full `$schema`
coverage for every widget — a future-PR call.

**Implementation hooks.**
- Phase 2 task "Schema-driven configure form" → expand spec to
  include the two-tier structure.
- Phase 2 new task: chip input component for array values in the
  bottom tier.
- Phase 2 new task: key-value-with-dot-notation list component.

---

## DD-08 — Dashboard owns its chrome; side menu skipped

**Date.** 2026-05-13
**Phase context.** Surfaced during Phase 1 v1-audit. Affects PRD §6.2
(audit table), §8.3 (view tree note), §12 (surface-parity gate),
Phase 1 task list (side-menu update → side-menu *removal*), Phase 4
(import/export/save-template/list-templates land as in-page
controls, not side-menu links).

**Decision.** The v2 dashboard does not use MISP's side menu. It runs
under a custom Cake layout `app/View/Layouts/dashboard.ctp` that mirrors
`default.ctp`'s page chrome (CSS/JS includes, top nav, flash messages,
footer) but omits the side-menu region entirely. Every action that
previously lived in the side menu's `dashboard` case is hosted by the
dashboard's own header bar (proto's `<header class="misp-dashboard-
header">`): the canonical-type bulk-edit toolbar (DD-05), the edit-
mode toggle, the eventual Add Widget action (Phase 2), and a "⋯ More"
dropdown grouping the low-frequency template actions (Import, Export,
Save Template, List Templates).

**Rationale.** The dashboard is a workspace, not a CRUD index/view
surface. In-context controls beat left-rail navigation for the
operations that matter (edit layout, bulk-edit filters, add/remove
widgets); the actions that don't matter most of the time (template
import/export) belong behind one dropdown gesture, not in a permanent
left rail. User explicitly accepted UX divergence from the rest of
MISP for this surface specifically — "don't get hung up on the prior
design, modern and pleasant is the goal" (2026-05-13).

**Alternatives considered.**
- **Keep MISP's side menu, update the dashboard case in place.**
  Originally what Phase 1 assumed. Rejected: the side menu's horizontal
  real estate is dead weight on a workspace surface; the only items
  it surfaced were primary actions that belong in-context anyway.
- **Targeted Themed override of side_menu.ctp that empties the
  `dashboard` case.** A halfway move that still costs a left-rail
  region in the layout. Rejected — if the dashboard renders no side
  menu, the right place to encode that is the layout, not the menu
  element.
- **Drop the side menu but render dashboard inside `default.ctp` by
  leaving `$menuList` empty.** Cake's default layout still allocates
  the rail and styles the surrounding columns assuming it. The
  surrounding scaffold leaks visual weight even when the menu is
  empty. Rejected — `dashboard.ctp` cleanly removes the scaffold.

**Action mapping (side menu → in-page).**

| v1 side-menu item | Phase 1 home | Notes |
|---|---|---|
| View Dashboard | n/a | self — landing page is the dashboard |
| Add Widget | Phase 2 | Not in Phase 1 chrome (Phase 2 lands the in-page Add flow per the existing add-widget board action hook) |
| Import Config JSON | "⋯ More" dropdown | Calls v1-carryover `/dashboards/import` until Phase 4 reimplements |
| Export Config JSON | "⋯ More" dropdown | v1-carryover `/dashboards/export` |
| Save Dashboard Config | "⋯ More" dropdown | v1-carryover `/dashboards/saveTemplate` |
| List Dashboard Templates | "⋯ More" dropdown | v1-carryover `/dashboards/listTemplates` |

**A11y requirements** (binding for the header chrome).
- All header controls focusable via Tab; visible focus ring.
- "⋯ More" dropdown follows the WAI-ARIA Menu Button pattern:
  `aria-haspopup="menu"`, `aria-expanded`, Escape closes, Up/Down
  navigates items, Enter activates.
- Edit-mode toggle is a button with `aria-pressed`, already proto-
  shaped (just carries forward).
- Toolbar chips' popovers (DD-05) inherit the existing focus-trap
  pattern from the configure side panel (DD-06).

**Reversibility.** Re-introducing the side menu later is additive:
delete `app/View/Layouts/dashboard.ctp`, restore the `case 'dashboard':`
block in `Elements/genericElements/SideMenu/side_menu.ctp` (+ UiBeta
mirror), wire the header actions to navigate to the menu URLs. No
data-shape or contract change.

**Implementation hooks** (Phase 1).
- New: `app/View/Layouts/dashboard.ctp` (mirror of `default.ctp`,
  side-menu region omitted).
- Delete: `case 'dashboard':` block (lines 9–46) in
  `Elements/genericElements/SideMenu/side_menu.ctp` and the UiBeta
  mirror.
- New: "⋯ More" dropdown component in the dashboard's header bar,
  with the four template-action items (Import / Export / Save / List)
  wired to the v1-carryover URLs.
- The previously-tracked Phase 1 tasks "Side menu update on default
  theme" and "Side menu update on Themed/UiBeta" are replaced by:
  - "Delete `case 'dashboard':` from default side_menu.ctp"
  - "Delete `case 'dashboard':` from Themed/UiBeta side_menu.ctp"

**PRD wording corrections (folded in this commit).**
- §6.2: side-menu rows recast — they document the v1 surface being
  *removed*, not updated.
- §12 surface-parity gate: "every URL on the side menu" → "every URL
  surfaced by the dashboard's in-page controls". Also drops the
  stale `{scope, widgets}` envelope reference (DD-05 retired it).
- §15 picks up DD-08 as a binding row.

## DD-09 — Calm widget chrome: transparent titlebar, hover/focus-reveal action icons

**Date.** 2026-05-25
**Phase context.** Post-Phase-5.5 UX pass (the "resolve design decisions
before adding new widget types" round). Affects the widget wrapper
chrome in both themes; no markup, JS, contract, or data-shape change —
CSS only.

**Decision.** The widget titlebar is visually quiet by default. The
header **background fill and bottom divider are removed** in both
themes (default `.misp-widget-titlebar`; Overmind
`.misp-widget--overmind .card-header`) so the bar blends into the
widget surface. The per-widget **action icons** (refresh / configure /
remove) are **hidden in view mode and revealed on hover or keyboard
focus** of the widget; in **edit mode they are always visible**. The
**title text and the "updated Ns ago" refresh indicator stay visible
at all times** — they identify the widget and report status, they are
not controls.

**Rationale.** The board is a reading surface most of the time; a grid
of heavy, boxed title bars with always-on button rows competes with
the data. Quieting the chrome to "title on a clean surface" lets the
widget content carry the page, while the controls are one hover/focus
away when wanted. Edit mode is the exception: when the user is actively
arranging widgets the titlebar *is* the drag handle (it shows the ⠿
grip) and every control should be in reach, so chrome is fully exposed
there. Matches the user's standing "modern and pleasant" direction and
the common dashboard pattern of calm-in-view / exposed-in-edit.

**Accessibility.** Hover-only reveal would strand keyboard and
screen-reader users, so the reveal trigger is `:hover` **OR**
`:focus-within` — tabbing into any control (or any focusable element
in the widget body, e.g. a drilldown link) brings the action group up.
The icons are hidden with `opacity` + a fade transition, **not**
`display: none`, so they remain in the DOM and the tab order and the
titlebar never reflows when they appear/disappear. The board renders
`data-misp-board-mode="view"` server-side on first paint, so the
view-mode rule matches immediately — no flash of visible icons before
JS runs. Edit-only buttons (Remove) keep their existing
`[data-misp-board-mode="view"] … -edit-only { display:none }` gate, so
in view mode only Refresh + Configure can ever reveal.

**Reversibility.** Pure CSS, fully additive to revert: restore the
titlebar `background`/`border-bottom` and delete the
`[data-misp-board-mode="view"] … { opacity: 0 }` reveal rules in the
two stylesheets. No template or JS dependency.

**Implementation hooks.**
- `app/webroot/css/dashboard/dashboard.default.css` —
  `.misp-widget-titlebar` (transparent + no border) and a view-mode
  `opacity` reveal on `.misp-widget-actions` keyed off
  `.misp-widget:hover` / `:focus-within`.
- `app/View/Themed/Overmind/webroot/css/dashboard/overmind.css` —
  same treatment on `.misp-widget--overmind .card-header` and its
  `.btn-group`.
- **Convention for future widgets/themes:** any new theme's wrapper
  override should follow the same calm-in-view / exposed-in-edit
  chrome (transparent header, hover+focus-reveal controls, always-on
  in edit mode) for cross-theme consistency.

## DD-10 — Config Import / Export live in the dashboard's own side panel, not the theme global modal

**Date.** 2026-05-25
**Phase context.** Post-Phase-5.5 UX pass. Supersedes the "v1-carryover
modal" stopgap that DD-08 left on the "⋯ More" Import / Export items.

**Decision.** The "⋯ More" → **Import configuration** and **Export
configuration** actions open the dashboard's **own configure side panel**
(the surface Configure and Add Widget already use), in two new panel
modes `data-misp-configure-mode="import"` / `"export"`. They no longer
delegate to either theme's global modal. A new vanilla-ESM module
`app/webroot/js/dashboard/config-io.module.mjs` owns the panel content,
mirroring how `gallery.module.mjs` borrows the same panel (set mode,
fill body, show backdrop+panel, MutationObserver-on-`hidden` cleanup,
own ESC). The menu items become `data-misp-board-action="import-config"`
/ `"export-config"` (dispatched in `board.module`'s `_wireBoardActions`,
which closes the menu on pick) and **keep their `href` as a no-JS
fallback** to the legacy pages.

- **Export** fetches the saved config from `/dashboards/export` (REST),
  unwraps it to the bare widget array (DD-05 shape), and shows it
  pretty-printed in a read-only textarea with Copy.
- **Import** parses + normalises the pasted blob to a widget array
  (tolerating the v1 envelopes `{UserSetting:{value}}`,
  `{Dashboard:{value}}`, `{widgets:[]}`, and a bare array), then POSTs
  it to `/dashboards/updateSettings` — the board's own save endpoint,
  which applies `LayoutFixup` and is CSRF-exempt on the
  `Accept: application/json` path (identical wire shape to the layout
  save) — and reloads. This deliberately bypasses the legacy
  `DashboardsController::import()` action and its envelope-unwrap
  string-`foreach` quirk; the round-trip with Export is lossless.

**Rationale.** The carryover modal only ever worked on the **default**
theme: it relied on `misp.js`'s `a.modal-open` → `openGenericModal`
(jQuery). The **Overmind** dashboard layout loads a different, leaner
stack (BS5 + `mispOvermind.js`, no jQuery, no `misp.js`) with **no
`modal-open` handler** and a different modal helper (`openModal`) whose
fragment contract (`#mainModalBody` injection) is incompatible with the
old `#genericModal` markup the controller renders. So no single
`modal-open` wiring can work on both themes. The dashboard already owns
theme-independent overlay surfaces (Configure, Add Widget) in vanilla
ESM loaded on both themes (the shared `index.ctp` + `board.module`), so
hosting config I/O there is the only presentation that is correct on
both themes — and it matches DD-08 ("dashboard owns its chrome"). The
user chose the side panel over a centered dialog / in-page page
(2026-05-25).

**Alternatives considered.**
- **Add `modal-open` to the anchors** (the obvious 2-line fix).
  Rejected: inert under Overmind (no handler) — the admin's own theme,
  where the bug was reported.
- **Theme-aware dispatch** (`openGenericModal` on default, `openModal`
  on Overmind). Rejected: couples the dashboard to *both* theme globals
  and their differing fragment contracts; the `#genericModal` vs
  `#mainModalBody` markup mismatch makes it brittle.
- **Native `<dialog>` board-owned popup.** Viable and theme-independent;
  rejected in favour of reusing the existing panel (less new surface,
  consistent with Configure / Add Widget). The user picked the panel.
- **In-page styled pages** (like `saveTemplate`, Phase 4's documented
  direction). Viable and lowest-risk, but the user wanted a popup-style
  overlay, not a navigation.

**Reversibility.** Additive and self-contained: delete
`config-io.module.mjs`, drop the two `import-config` / `export-config`
cases + `_closeContainingMenu` in `board.module`, the two
`data-misp-board-action` attributes + the `data-misp-board-export-url`
hook in `index.ctp`, and the `[data-misp-configure-mode="import"|
"export"]` CSS. The anchors' `href` fallback already points at the
legacy pages, so removing the JS degrades to the old behaviour rather
than breaking. No controller, model, or data-shape change.

**Convention for future themes / config surfaces.** Dashboard-level
actions that need an overlay (config I/O, and anything similar later)
should be **board-owned** — rendered into the dashboard's own panel /
`board.module` vocabulary, theme-independent — rather than delegated to
a theme's global modal, which is not guaranteed present across themes.

**Implementation hooks.**
- New: `app/webroot/js/dashboard/config-io.module.mjs`.
- `board.module.mjs`: import + `export-config` / `import-config` cases +
  `_closeContainingMenu`.
- `app/View/Dashboards/index.ctp`: `data-misp-board-export-url` on the
  board root; `data-misp-board-action` on the two menu anchors (href
  retained); updated "⋯ More" comment.
- `app/webroot/css/dashboard/dashboard.default.css`: the two new panel
  modes folded into the gallery-mode selectors + `.misp-configio-*`
  body styling. Shared sheet → applies on both themes.

## DD-11 — Geo world-map widget: multi-source, ACL-free aggregate, capped

**Date.** 2026-05-26
**Phase context.** First of the post-5.5 "new widget types" round (the
phase the user flagged after the UX-polish work). Introduces
`app/Lib/Dashboard/AttributeGeoMapWidget.php` — a pure addition (one
class, no controller/model/renderer change), reusing the existing
`WorldMap` render kind (⇒ no new glyph per the CLAUDE.md rule).

**Decision.** A single widget geolocates recent MISP data to ISO
alpha-2 country counts for the `WorldMap` renderer, blending up to
**four individually-selectable sources** (config `sources`, default all
on; their counts are summed):

| `sources` value | What | Resolution to ISO |
|---|---|---|
| `ip` | `ip-src` / `ip-dst` / `ip-src\|port` / `ip-dst\|port` (value1) + `domain\|ip` (value2) | MISP-managed `GeoOpen-Country.mmdb`, one `GeoIp2\Database\Reader` opened once and reused across the sweep |
| `domain_tld` | ccTLD of `domain` / `domain\|ip` (value1) | the `country` galaxy's own `tld`→`ISO` elements (SQL self-join), exact 2-letter ccTLDs only |
| `country_galaxy` | events tagged `misp-galaxy:country="…"` | the cluster's `ISO` galaxy element (SQL join) |
| `threat_actor` | events tagged `misp-galaxy:threat-actor="…"` | the cluster's `country` galaxy element — already stored as ISO alpha-2 (SQL join) |

The map deliberately **mixes indicator-location** (`ip`, `domain_tld`)
**with attribution/relevance** (`country_galaxy`, `threat_actor`); the
per-source toggle lets a user isolate either reading. A single
attribute may contribute more than one signal (e.g. `domain|ip` counts
once for its IP and once for its ccTLD) — treated as two independent
signals, not double counting of one fact. The user chose toggleable,
default-all (2026-05-25/26).

**ACL: deliberately not enforced (the consequential call).** The
per-source queries are bare `find('column')` / join fetches over the
timeframe — **no per-user ACL**. So the aggregate per-country counts can
reflect data the viewing user could not normally see. This is an
accepted aggregate-inference exposure, bounded by: counts only (no
values, **no drilldown**, no attribution to a reporting org). The user
accepted this for v1 ("we're lenient with AGGREGATE information; without
drilldown a user only learns *that* data for a country exists, not who
reported it or in what context"), explicitly citing the precedent that
**global Statistics also avoids ACL**. Available to all users for v1.
The user would *prefer* ACL where it's affordable and wants **both an
ACL-enforced and a non-ACL path eventually, switchable on the
performance trade-off** — logged as a follow-up; v1 ships the non-ACL
path only.

**Performance guard ≠ `cacheLifetime`.** Investigated and confirmed:
`cacheLifetime` is **inert in dashboard v2** — `DashboardsController::
renderWidget()` does no server-side caching and `Dashboard::
__extractMeta()` does not surface it (only `autoRefreshDelay` reaches
the client). So the handoff's "set `cacheLifetime`" suggestion buys
nothing. The real guards are: (1) a **per-source cap** on the most-
recent rows scanned (`limit`, default **10000**, ordered by timestamp
DESC), (2) the **recency window** (`time_window` canonical, default
**P30D**, toolbar-reachable per DD-05; `-1` = all-time), and (3)
`autoRefreshDelay = false` so the sweep never re-runs on a timer — only
on page load / manual refresh. The mmdb Reader is opened **once** (vs
`UserLoginProfile::countryByIp`, which opens a fresh Reader per call).

**Bypassing `fetchAttributes` is intentional** beyond the ACL point:
`MispAttribute::fetchAttributes()` injects `Attribute.object_id = 0`
unless `flatten => 1`, so it would silently miss the many IP/domain
attributes that live inside objects. A bare `find('column')` has no
such implicit filter, so object attributes are included.

**Galaxy ISO via `galaxy_elements`, not JSON.** The country galaxy
carries both `ISO` and `tld` as galaxy elements, and the threat-actor
galaxy carries `country` as an ISO alpha-2 element. Both galaxy sources
(and the ccTLD map) resolve country **server-side via SQL joins through
`galaxy_elements`** — no per-render parsing of the galaxy JSON files.

**ISO hygiene.** Every source funnels through a `^[A-Z]{2}$` guard.
This drops the GeoOpen mmdb's literal **`"None"` placeholder** for
unallocated ranges (observed as the single largest "country" before the
guard) and any other non-ISO value. The `WorldMap` renderer then
further drops ISO codes its Natural-Earth name set doesn't know
(Singapore, Hong Kong, Monaco, …) — an inherited renderer limitation,
shared with `OrganisationMapWidget`; not fixed here (additive-only).

**ASN deferred (infeasible as first specified).** The user asked to
geolocate via ASN using `GeoOpen-Country-ASN.mmdb`. That file is **not
on the box**, and more fundamentally **mmdb is IP-network-keyed**: the
`geoip2` `Asn` model returns ASN *for an IP*, never country *for an
ASN*. A bare `AS` attribute therefore cannot be mapped to a country via
any mmdb. The widget's source list is built to accept a 5th source
cleanly; ASN→country awaits a concrete dataset from the user (a new
managed-data dependency) — logged, not built in v1.

**ccTLD is a deliberately weak signal.** Repurposed ccTLDs (`.io`, `.tv`,
`.co`, `.gg`, `.me`, `.ai`) geolocate to their registry country, not
the operator's location (live data: `.gg`→Guernsey topped the ccTLD
source). Honest-where-it-works; only exact 2-letter ccTLDs present in
the galaxy are honoured, the rest dropped. Users who don't want this
noise turn the `domain_tld` source off.

**Identity.** `title` "Recent data geolocation map", `category`
`events`, `render` `WorldMap`, default `width 3 height 4` (matches
`OrganisationMapWidget`). Auto-discovered from `app/Lib/Dashboard/*.php`.

**Alternatives considered.**
- **ACL-enforced fetch** (`fetchAttributes($user, …)` / `Event::
  restSearch`, the handoff's recommendation). Correct but heavy on a
  large instance; the user chose the non-ACL aggregate path for v1, with
  the ACL path kept as a future switchable option.
- **Site-admin-gating** the widget so the ACL bypass is moot (admins see
  all). Recommended by me; the user preferred broad availability with
  the accepted aggregate exposure instead.
- **Per-datum drilldown (DD-03).** Rejected by the user: the IP→country
  mapping is transient (recomputed per render, never persisted), so
  there is nothing stable to link a region to.
- **Parsing the galaxy JSON files** for the value→ISO / tld→ISO maps.
  Rejected for the `galaxy_elements` SQL join — no per-render file I/O,
  reflects the actually-imported galaxy.

**Reversibility.** Fully additive and self-contained: delete the one
class. No shared surface touched. Adding the ACL-enforced path later is
additive (a `sources`-style mode or an auto-switch on result-size);
adding ASN is additive (a 5th `sources` value + its dataset).

**Implementation hooks.**
- New: `app/Lib/Dashboard/AttributeGeoMapWidget.php` (chgrp www-data).
- No controller/model/renderer/glyph/CSS change.
- Verified: lint clean; REST render valid per-source and combined;
  `"None"` eliminated; gallery metadata correct; session HTML render
  emits the `data-misp-chart="geo"` payload with ISO→name translation.

## DD-12 — ASN geolocation via an offline-derived ASN→country map (the geo widget's 5th source)

**Date.** 2026-05-26
**Phase context.** Follow-up to DD-11 (the geo widget deferred ASN
"pending a dataset"). The user merged `develop` in, adding the MISP-
managed `app/files/geo-open/GeoOpen-Country-ASN.mmdb`, and chose to
derive an ASN→country map from it.

**The constraint that forced this shape (verified, not assumed).**
`GeoOpen-Country-ASN.mmdb` is **IP-prefix-keyed**, not ASN-keyed:
`get("8.8.8.8")` → `{country: {iso_code: "US",
AutonomousSystemNumber: "15169", AutonomousSystemOrganization:
"GOOGLE"}}`. There is **no `get("AS15169") → country`** path — and the
question is ill-posed against this data anyway, because the country is
recorded *per IP prefix* and a single ASN announces prefixes in many
countries. The PHP `MaxMind\Db\Reader` also exposes **no network
enumeration** (`get` / `getWithPrefixLen` / `metadata` / `close` only),
so the map cannot be built in PHP at render time. (My original DD-11
pushback — "mmdb can't map a bare ASN to a country" — held; the file
confirms it.)

**Decision.** A bare `AS` attribute is mapped to the country in which
its ASN announces the **most IPv4 address space** ("dominant announced
space"), via an **offline-derived lookup** committed to the repo:

- **Builder:** `app/files/scripts/generate_asn_country_map.py` — uses
  Python `maxminddb` (which *can* enumerate the trie; the PHP reader
  can't), walks every IPv4 prefix, sums `network.num_addresses` per
  `(ASN, ISO)`, and writes `asn → argmax-country` as JSON.
- **Artifact:** `app/files/geo-open/asn-country.json` — a flat
  `{"<asn>": "<ISO>"}` map (77,846 entries / ~1 MB on the current
  mmdb). The `geo-open` dir is git-tracked (the mmdbs themselves are
  committed there via a `.gitignore` force-include), so the derived
  map is **committed too** — the widget works out-of-the-box, no
  operator build step required for the shipped state.
- **Widget:** `AttributeGeoMapWidget` gains a 5th `sources` value
  `asn`. It loads + memoises the JSON (graceful empty if absent),
  fetches recent `AS` attributes (capped, recency-bounded, no ACL —
  same posture as the other sources, DD-11), normalises each value
  (strips a leading `AS`/zeros — MISP stores bare numbers like
  `48031`), looks it up, and tallies behind the same `^[A-Z]{2}$`
  guard.

**Why dominant-IPv4-space (not registration country).** For threat
infrastructure, "where does this AS actually operate address space" is
the operationally-relevant signal — a RU actor announcing mostly RU
space reads as RU even if the AS is registered in a flag-of-convenience
jurisdiction. Live spot-checks confirm sensible output: AS16276→FR
(OVH), AS6849→UA (Ukrtelecom), AS202425→SC (a known bulletproof-hosting
AS), AS15169/AS13335→US (Google/Cloudflare, where most of their space
sits). **IPv6 prefixes are excluded from the vote** — their address
counts (2^(128−len)) would swamp IPv4; an IPv6-only ASN is therefore
absent from the map (rare).

**Alternatives considered.**
- **RIR delegated-extended stats** (authoritative ASN→*registration*
  country). More "correct" by registration, but a *different* new data
  source to fetch+manage, and registration country is often *less*
  operationally meaningful than announced space for threat infra. The
  user chose to use the mmdb they provided.
- **Drop ASN** (DD-11's deferral). Cleanest, but the user wanted AS
  attributes on the map.
- **Build the map in PHP at render time.** Impossible — the PHP reader
  can't enumerate the trie.
- **Build per-render only for ASNs present on the instance.** Still
  needs enumeration; same blocker.

**Cost / maintenance (the honest downside).** This is no longer a
"pure one-class addition": it adds a Python build script + a committed
derived data file. The map is a **point-in-time snapshot** of the mmdb
and **must be regenerated when the mmdb updates** (re-run the script;
the widget picks up the new JSON with no code change). Wiring the
regeneration into MISP's existing mmdb-update mechanism is a logged
follow-up, not done here. The approximation is also coarse for global
multi-homed ASNs (large clouds skew to the US); users who don't want
that turn the `asn` source off (DD-11's per-source toggle).

**Reversibility.** Additive: delete the `asn` case + `asnCounts` /
`asnCountryMap` from the widget, and the script + JSON. The other four
sources are unaffected.

**Implementation hooks.**
- New: `app/files/scripts/generate_asn_country_map.py` (chgrp www-data).
- New (committed, derived): `app/files/geo-open/asn-country.json`.
- Changed: `AttributeGeoMapWidget` — `asn` source, map loader, docblock.
- Verified: lint clean; `asn`-only render 559/587 AS attrs mapped
  (top CN/US/RU); combined five-source render valid; session HTML
  render emits the `data-misp-chart="geo"` payload with the ASN-derived
  countries translated to GeoJSON names.

## DD-13 — WorldMap colour palette: named semantic palettes, widget-declared default + per-instance override

**Date.** 2026-05-26
**Phase context.** Post-5.5 new-widget round. Supersedes the
CSS-widget-name-scoped red override that first shipped on the threat
widgets (a stopgap, now retired).

**Decision.** A WorldMap widget selects its choropleth colour scale by a
**named palette**, returned as `'palette' => '<name>'` from `handler()`.
Five named palettes map to existing semantic theme tokens:

| palette | low stop | high stop |
|---|---|---|
| `accent` (default) | `--misp-dash-accent-muted` | `--misp-dash-accent-hover` |
| `danger` | `--misp-dash-danger-muted` | `--misp-dash-danger` |
| `success` | `--misp-dash-success-muted` | `--misp-dash-success` |
| `warning` | `--misp-dash-warning-muted` | `--misp-dash-warning` |
| `info` | `--misp-dash-info-muted` | `--misp-dash-info` |

(The `-muted` low-ends are new tokens added alongside the existing
`--misp-dash-accent-muted`.) `buildGeoOption` resolves the chosen
palette's token pair via `getComputedStyle`, so a retoned / dark theme
still recolours the map. Unknown names fall back to `accent`.

- **Default encoded in the widget:** the `palette` `$schema` entry's
  `default` (e.g. `'danger'` on the two threat widgets) — the
  CanonicalTypeAdapter injects it, and the handler also falls back to it.
- **Per-instance override:** `palette` is an `enum` `$schema` field, so
  it surfaces as a dropdown in the configure form; a user can recolour
  any one widget instance without touching others.
- **Renderer-generic:** `WorldMap.ctp` passes `palette` straight through
  to the chart payload (whitelisted client-side). Any WorldMap widget
  can opt in by emitting `palette`; `OrganisationMapWidget` /
  `CsseCovidMapWidget` don't, so they keep the default blue.

**Rationale.** The user wanted per-widget colour control with defaults
encoded in the widget. The first cut scoped red via a CSS rule keyed on
`[data-widget-name="..."]` overriding the accent tokens — it worked but
hardcoded widget names in the stylesheet and offered no per-instance
override. Named palettes anchored on semantic tokens give theme-
consistent, discoverable, per-instance-configurable colour with the
default living in the widget class, and keep the "ramp driven by CSS
tokens" property (PRD §8.1 retoning) intact.

**Alternatives considered.**
- **CSS widget-name override (the stopgap).** Retired — not per-instance
  configurable, hardcodes names in CSS, repurposes the accent token.
- **Arbitrary low/high colour pickers.** Maximum flexibility, but a
  fixed hex bypasses the theme tokens (won't adapt to a dark/retoned
  theme) and is a fiddlier config UI. Rejected; named palettes can be
  extended to arbitrary later if wanted (additive).

**Reversibility.** Additive: drop the `palette` payload key + the
`PALETTES` map in `buildGeoOption` + the `-muted` tokens; widgets fall
back to the accent ramp. No data-shape break (older saved configs
without `palette` just use the default).

**Convention for future WorldMap widgets.** Declare a `palette` `enum`
in `$schema` with the desired `default`, and return
`'palette' => !empty($options['palette']) ? $options['palette'] : '<default>'`
from `handler()`. Don't add per-widget colour rules to the stylesheet.

**Implementation hooks.**
- `dashboard.default.css`: 4 new `--misp-dash-*-muted` tokens; the
  `[data-widget-name]` red hack removed.
- `charts/charts.module.mjs`: `PALETTES` map in `buildGeoOption`,
  resolved from `payload.palette`.
- `WorldMap.ctp`: `palette` passthrough into the chart payload.
- `AttributeGeoMapWidget` + `ThreatActorCountryMapWidget`: `palette`
  `enum` schema (default `danger`), params doc, handler emit.
- Verified: lint + `node --check` clean; threat widgets default
  `danger`, override to `success` honoured; `OrganisationMapWidget`
  payload carries no palette → blue.

## DD-14 — WorldMap projection: configurable, Mercator default, hand-rolled (no d3-geo)

**Date.** 2026-05-26
**Phase context.** Post-5.5 new-widget round, immediately after DD-13.
The WorldMap had no projection set, so ECharts plotted raw lon/lat
(equirectangular / plate carrée). The user asked to make projection an
option and default it to Mercator.

**Decision.** WorldMap supports a `projection` option (currently
`mercator` | `equirectangular`), resolved client-side in
`buildGeoOption` and applied via ECharts 6's `series.projection`
(`project`/`unproject` pair). **Mercator is the default** — and it's a
*renderer-level* default: `buildGeoOption` uses `payload.projection ||
'mercator'`, so **every** WorldMap widget (incl. `OrganisationMapWidget`
/ `CsseCovidMapWidget`, which don't declare it) renders Mercator now,
with no change to those widgets. `equirectangular` omits the projection
(ECharts' native flat lon/lat grid, the pre-DD-14 look).

**Mercator is hand-rolled, not d3-geo.** The forward/inverse are the
standard spherical Mercator (~6 lines):
`project([λ,φ]) = [λ·π/180, −ln(tan(π/4 + φ·π/360))]`,
`unproject([x,y]) = [x·180/π, 2·atan(e^−y)·180/π − 90]`. Latitude is
clamped to ±85.0511° (the Web-Mercator limit) so Antarctica's −90°
vertices don't send `y → ∞`. **The y term is negated in both** because
a custom projection's output is consumed as raw canvas coordinates
(y increases *downward*) — unlike ECharts' native lon/lat path it is
NOT auto-flipped, so without the negation north renders at the bottom.
The pair is exact inverses (verified by a node round-trip test:
Paris/DC/Beijing/Moscow/Buenos Aires, equator, pole-clamp) — a wrong
inverse silently breaks roam/zoom hit-testing, not just the image.

**Correction (2026-05-26, same day).** This shipped twice wrong before
settling: first `−ln` forward + `e^y` inverse (mismatched pair → roam
hit-test mirrored), then "fixed" to `+ln` forward + `e^y` inverse
(round-trip now exact, but the map rendered **upside down** — caught
visually by the user, not by the test). The correct pair is `−ln`
forward + `e^−y` inverse: exact inverse **and** north-up. **Lesson: a
round-trip test only proves the inverse is self-consistent; it says
nothing about orientation. The *sign* of the forward decides which way
is up, so a round-trip-correct projection can still be upside down —
assert north-maps-above-south (or eyeball it), don't stop at round-trip.**

- **Default encoded / per-instance override:** like DD-13, `projection`
  is an `enum` `$schema` field (default `mercator`) on the two threat
  widgets → a configure-form dropdown; the handler emits it. Org/COVID
  widgets get Mercator via the renderer default without a per-widget
  toggle (one-line opt-in if ever wanted).

**Alternatives considered.**
- **d3-geo** (Mercator/Robinson/Winkel-Tripel/…). The "proper" library,
  but a new vendored dep (and licence/bundle cost per DD-07) for what is
  ~6 lines for Mercator. Rejected for now; revisit if richer projections
  (Robinson, Natural Earth) are wanted — those need polynomial tables or
  iteration and are the real reason to pull in d3-geo.
- **Equirectangular as an explicit projection fn.** Unnecessary — the
  ECharts native rendering already *is* equirectangular, so the
  `equirectangular` choice just omits `series.projection`.

**Reversibility.** Additive: drop the `PROJECTIONS` map + the
`series.projection` spread + the `projection` payload key and widgets
fall back to ECharts' native equirectangular. No data-shape break (old
configs without `projection` use the mercator default).

**Convention for future WorldMap widgets.** Same as DD-13's palette:
declare a `projection` `enum` in `$schema` if per-widget choice is
wanted; the renderer defaults to mercator regardless.

**Implementation hooks.**
- `charts/charts.module.mjs`: `PROJECTIONS.mercator` (project/unproject)
  in `buildGeoOption`; `...(projection ? { projection } : {})` on the
  map series; `payload.projection || 'mercator'` default.
- `WorldMap.ctp`: `projection` passthrough into the payload.
- `AttributeGeoMapWidget` + `ThreatActorCountryMapWidget`: `projection`
  `enum` schema (default `mercator`), params doc, handler emit.
- Verified: lint + `node --check` clean; Mercator round-trip exact;
  threat widgets default `mercator`, override `equirectangular` honoured;
  org map inherits the mercator default (no payload projection key).
