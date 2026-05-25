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
