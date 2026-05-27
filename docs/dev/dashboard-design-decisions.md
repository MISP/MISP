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
| `d3-geo.bundle.mjs` *(d3-geo 3.1.1 + d3-geo-projection 4.0.0)* | **ISC** (Mike Bostock) | d3-geo / d3-geo-projection npm packages | ✅ — added DD-15; both LICENSE files shipped |

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

## DD-15 — Robinson + Natural Earth projections via vendored d3-geo

**Date.** 2026-05-26
**Phase context.** Extends DD-14. DD-14 deferred richer projections
("d3-geo becomes worth it for Robinson / Natural Earth, which need
polynomial tables not worth hand-rolling"); the user asked to add them.

**Decision.** Add two more `projection` options — **`naturalEarth`**
(d3-geo core `geoNaturalEarth1`) and **`robinson`** (d3-geo-projection
`geoRobinson`) — backed by a newly **vendored d3-geo bundle**. Mercator
stays the default; these are opt-in rounded, less polar-distorted world
views. `mercator` + `equirectangular` remain dependency-free (DD-14).

**Why the dependency now (vs DD-14's hand-roll).** Mercator/equirect
are ~6 lines. Natural Earth is a closed-form *polynomial* with an
*iterative* inverse; Robinson is an *interpolation table* (Robinson's
published 5°-interval values) with an iterative inverse. Hand-rolling
those (esp. correct, accurate inverses for roam hit-testing — see
DD-14's orientation/inverse saga) is exactly the error-prone work a
battle-tested lib should own. d3-geo provides both forward + exact
`.invert` (round-trip verified ~1e-11).

**Integration.** ECharts 6 `series.projection` takes `project` /
`unproject`; d3 projection objects are `p([lng,lat])→[x,y]` with
`p.invert`. A `wrapD3(p)` adapter maps straight onto them. Crucially,
**d3 bakes north-up into its y-down output**, so — unlike the
hand-rolled mercator, which needed an explicit `−ln` to avoid rendering
upside down (DD-14 Correction) — the d3 projections need no sign
handling. d3's default scale/translate is irrelevant: ECharts fits the
projected bounding box to the viewport.

**Licence / weight.** d3-geo 3.1.1 and d3-geo-projection 4.0.0 are both
**ISC** (Mike Bostock) — GPL/AGPL-compatible, same direction as DD-07's
other deps; added to the DD-07 table, both upstream `LICENSE` files
shipped in `vendor/`. The esbuild `--legal-comments=external` sidecar
came out **empty** (no inline notices survive minification), so it's
omitted — the `LICENSE.*` files are the attribution. Tree-shaken bundle
is **17 KB raw / 7.2 KB gzipped** — marginal next to the ~360 KB-gz
ECharts+geo stack (DD-02).

**Alternatives considered.**
- **Hand-roll Natural Earth only** (its forward is closed-form, no
  table) and skip Robinson. Avoids the dep, but the iterative inverse is
  still fiddly and Robinson (the more recognisable projection) genuinely
  needs the table — so for one dep we get both, cleanly. Rejected.
- **Default to Robinson/Natural Earth.** Not done — DD-14 set mercator
  as the default deliberately ("conventional web-map look"); these are
  offered as options. One-line change if a different default is wanted.

**Reversibility.** Additive: remove the `import`, the two `PROJECTIONS`
entries + `wrapD3`, the two `enum` values, and the three `vendor/`
files; `mercator`/`equirectangular` are unaffected (no d3 dependency).

**Convention.** More projections from the same source = extend the
bundle's `entry.mjs`, rebuild per `vendor/VENDORING.md`, add a
`PROJECTIONS` entry + enum value. Robinson/Natural Earth invert
iteratively — always keep the round-trip **and** north-up checks.

**Implementation hooks.**
- New vendored: `vendor/d3-geo.bundle.mjs` (+ `LICENSE.d3-geo`,
  `LICENSE.d3-geo-projection`); build recipe in `vendor/VENDORING.md`.
- `charts/charts.module.mjs`: import `geoNaturalEarth1` / `geoRobinson`;
  `wrapD3` adapter; `naturalEarth` + `robinson` `PROJECTIONS` entries.
- `AttributeGeoMapWidget` + `ThreatActorCountryMapWidget`: the two new
  values in the `projection` `enum` + params doc.
- DD-07 licence table: d3-geo row added.
- Verified: `node --check` clean; vendored-bundle round-trip OK for both;
  REST honours `robinson`/`naturalEarth`; gallery enum lists all four.

## DD-16 — Gall-Peters projection vendored via d3-geo (extends DD-15)

**Date.** 2026-05-26
**Phase context.** Extends DD-14/DD-15. The user reviewed the four
shipped projections and asked to add **Peters** (Gall-Peters) as a
fifth WorldMap `projection` option.

**Decision.** Add a `peters` projection — the **Gall-Peters
cylindrical equal-area** projection (standard parallels at ±45°) —
backed by the **already-vendored** `d3-geo.bundle.mjs`, which gains
one export: `geoCylindricalEqualArea` (d3-geo-projection). The widget
wires it as `wrapD3(geoCylindricalEqualArea().parallel(45))`. Mercator
stays the default; `peters` is opt-in like Robinson / Natural Earth.

**The fork that was surfaced (and the call made).** Gall-Peters is
mathematically *trivial* — closed-form forward **and** closed-form
(non-iterative) inverse, simpler than the hand-rolled Mercator (no
log/exp, no latitude clamp; equal-area projections are finite at the
poles). By DD-14's *complexity criterion* (closed-form & simple →
hand-roll), it belongs in the hand-roll camp alongside Mercator —
`~6` lines, zero new bytes. By DD-15's *same-source convention* (more
d3 projections → extend the bundle), it belongs in the vendored camp.
Those two principles disagreed here, so it was put to the user as an
explicit fork. **The user chose to vendor it** (2026-05-26), trading a
bundle rebuild + a few hundred bytes for d3's battle-tested north-up
handling — sidestepping the DD-14 orientation gotcha entirely (a
hand-rolled custom projection's output is raw canvas coords, y-down,
NOT auto-flipped, so it would have needed an explicit `y` negation +
the north-above-south assertion that cost two wrong cuts on Mercator).
The wiring is then identical to Robinson / Natural Earth.

**Why `geoCylindricalEqualArea().parallel(45)` is Gall-Peters.** The
Peters projection *is* the cylindrical equal-area projection with
standard parallels at ±45°. d3's `geoCylindricalEqualArea` defaults to
parallel 38.58° (Trystan Edwards); `.parallel(45)` selects the
Gall-Peters aspect. Verified by the projection's signature aspect
ratio: width/height = π·cos²(45°) = **π/2 ≈ 1.5708** (asserted in the
build test, came out exact).

**Licence / weight.** No new dependency — `d3-geo-projection@4.0.0`
(ISC, Mike Bostock) is already in the DD-07 table and its LICENSE file
already shipped (DD-15). The rebuilt bundle is **17.4 KB raw / 7.4 KB
gzipped** (was 17 KB / 7.2 KB — the cylindrical-equal-area machinery is
largely shared with the other projections, so the growth is marginal).
The `--legal-comments=external` sidecar is still empty (omitted, as
DD-15). No DD-07 table change needed (same dep).

**Alternatives considered.**
- **Hand-roll it** (the DD-14 path — Gall-Peters is closed-form both
  ways). Cheapest (no rebuild, no bytes) and matches DD-14's stated
  criterion most precisely. Rejected by the user in favour of d3's
  north-up handling, which removes the orientation-bug risk class.
- **Default to an equal-area projection.** Not done — Mercator stays
  the default per DD-14 ("conventional web-map look"); Peters is an
  opt-in for users who want an area-faithful view (no high-latitude
  area inflation). One-line `$schema` `default` change if ever wanted.

**Reversibility.** Additive: remove the `geoCylindricalEqualArea`
import + the `peters` `PROJECTIONS` entry + the two `enum` values, and
rebuild the bundle without the export (or leave it — it's inert if
unreferenced). `mercator`/`equirectangular`/`naturalEarth`/`robinson`
unaffected. No data-shape break (old configs without `projection` use
the mercator default; a saved `peters` on a reverted build falls back
to mercator via the unknown-name guard).

**Convention.** Unchanged from DD-15: more projections from the same
source = extend `entry.mjs`, rebuild per `vendor/VENDORING.md`, add a
`PROJECTIONS` entry + enum value. d3 projections invert iteratively or
closed-form depending on the family — always keep the round-trip
**and** north-up checks (Gall-Peters passed both: round-trip ~2e-13,
north-up confirmed, aspect = π/2).

**Implementation hooks.**
- `vendor/d3-geo.bundle.mjs` rebuilt with `geoCylindricalEqualArea`
  added to `entry.mjs` (recipe + bundle row updated in `VENDORING.md`).
- `charts/charts.module.mjs`: import `geoCylindricalEqualArea`;
  `peters: wrapD3(geoCylindricalEqualArea().parallel(45))` in
  `PROJECTIONS`; comment updated.
- `AttributeGeoMapWidget` + `ThreatActorCountryMapWidget`: `peters`
  added to the `projection` `enum` + params doc + schema help text.
- Verified: `node --check` clean; vendored-bundle round-trip ~2e-13 +
  north-up + aspect π/2; `php -l` clean on both widgets; REST render
  honours `projection=peters` (default still mercator); gallery enum
  lists all five; session HTML render emits the `data-misp-chart="geo"`
  payload with `"projection":"peters"` + ISO→GeoJSON-name translation.

## DD-17 — WorldMap default projection: Natural Earth (supersedes DD-14's Mercator default)

**Date.** 2026-05-26
**Phase context.** Overturns the *default* set by DD-14 (Mercator).
DD-14 and DD-15 both flagged this as a deliberately-deferred, one-line
call left to the user ("Default to Robinson/Natural Earth? Not done —
DD-14 set mercator… One-line change if a different default is wanted").
The user made that call (2026-05-26): **Natural Earth becomes the
default**.

**Decision.** The default WorldMap projection is now **`naturalEarth`**
(d3-geo core `geoNaturalEarth1`, already vendored since DD-15), at
*both* layers that DD-14 established:

1. **Renderer-level default** in `charts.module.mjs` `buildGeoOption` —
   `payload.projection || 'naturalEarth'`, and the unknown-name fallback
   `PROJECTIONS.naturalEarth` (was `PROJECTIONS.mercator`). This governs
   every WorldMap widget that does **not** declare a projection — i.e.
   `OrganisationMapWidget` and `CsseCovidMapWidget`, which now render
   Natural Earth instead of Mercator (the same blast radius DD-14
   itself had when it made Mercator the renderer default).
2. **Widget-level `$schema` default** on the two threat maps
   (`AttributeGeoMapWidget`, `ThreatActorCountryMapWidget`) — the
   `projection` enum `default` and the `handler()` emit fallback both
   move from `'mercator'` to `'naturalEarth'`.

Mercator, equirectangular, Robinson and Peters all **remain selectable**
in the enum — only the *default* changes. Saved configs that explicitly
pin a projection are untouched (verified: explicit `mercator` still
honoured).

**Rationale.** For a glanceable global threat-data overview, Natural
Earth's rounded, low-distortion world view reads better than Mercator's
severe high-latitude area inflation (which visually over-weights Russia,
Canada, Greenland on a choropleth). Natural Earth is a compromise
projection designed precisely for general-purpose world maps. The user
preferred it as the out-of-the-box look. It is already vendored and
imported (DD-15), so this is a pure default flip — no bundle rebuild,
no new dependency.

**Why change the renderer-level default too (not just the threat
widgets).** Leaving the renderer default at Mercator while flipping
only the threat widgets' schema default would make org/COVID maps
Mercator and threat maps Natural Earth — two different "defaults" on
one board. "Natural Earth is the default" is only coherent if the
renderer-level fallback (the true default for non-declaring widgets)
moves too. Both layers changed together.

**Reversibility.** Trivially revert: restore `'mercator'` at the three
default sites (the renderer `|| 'mercator'` + unknown-name fallback, and
each widget's `$schema` default + handler fallback). No data-shape
change; saved explicit-projection configs are unaffected either way.

**Note on the trail.** DD-14 and DD-16 still read "Mercator is the
default" / "default still mercator" — those entries record what was
true when they landed and are deliberately **not** edited (per this
log's discipline). DD-17 is the superseding entry.

**Implementation hooks.**
- `charts/charts.module.mjs`: `payload.projection || 'naturalEarth'`;
  unknown-name fallback `PROJECTIONS.naturalEarth`; comment updated.
- `AttributeGeoMapWidget` + `ThreatActorCountryMapWidget`: `projection`
  `$schema` `default` → `naturalEarth`; `handler()` emit fallback →
  `naturalEarth`; params doc + schema help "(default)" label moved.
- Verified: `node --check` + `php -l` clean; REST default now
  `naturalEarth` on both threat widgets; explicit `mercator` still
  honoured; enum still lists all five.

## DD-18 — Widget aliasing: per-instance display name via `config.alias`, defaulting to the class `$title`

**Date.** 2026-05-26
**Phase context.** First of the post-5.5 "new features" round (the user
enumerated widget aliasing, default layouts, and geo caching as the next
batch). Lets a user run several instances of the same widget with
different configs and label each one distinctly.

**Decision.** A widget instance's titlebar label is, in precedence
order: **`config.alias`** (per-instance, user-set) → the class **`$title`**
(the human-readable widget name) → the class name (last-ditch). The
alias is a **config field** (`config.alias`), edited via a `string`
schema field **injected server-side** into every widget's `$schema`
(prepended so it leads the configure form), exactly mirroring the
existing `config.refresh_delay` override mechanism. No `$schema`
`default` — a blank alias means "use the widget's name", resolved at
render. The configure form's typed-tier heading was renamed
**"Filters" → "Settings"** (it now also carries the alias + the
refresh-delay override, neither of which is a filter).

**The fork that was surfaced (and the call made).** A dormant top-level
`alias` slot has existed since the Phase 1 proto (2026-05-13): the
wrapper rendered `alias ?? widget-class-name`, `board.module._saveLayout`
serialised `data-widget-alias`, but **nothing ever set it**
(`renderWrapper` hardcoded `null`, no editing UI), the fallback was the
**class name** not `$title`, and `index()` never even surfaced `$title`
— so every un-aliased titlebar showed its class name (a latent bug this
fixes). Two ways to finish it were put to the user:
- **`config.alias` (chosen).** Rides *all* existing infrastructure: the
  schema-driven configure form auto-renders the field, the per-widget
  config-patch save (`updateWidgetSettings`) persists it, no new save
  plumbing, no DD-05 staging-atomicity conflict. Consistent precedent
  (`refresh_delay` is also a non-handler presentation key in `config`).
- **Top-level `alias` (rejected).** Reuses the proto slot, but the
  config-patch save path carries `{instance_id, config}` only — a
  top-level alias could only be persisted by a full-blob `_saveLayout`,
  which the configure form deliberately avoids during edit-mode staging
  (DD-05). Would have needed new patch plumbing or a separate edit
  affordance. More code, worse fit.

The user picked the configure-form field over inline titlebar rename
(2026-05-26). The proto's vestigial top-level scaffolding was removed so
there is **one** notion of alias (`config.alias`), not two.

**Live titlebar update.** The configure-form Save re-renders only the
widget *body* (`_renderWidget`), leaving the titlebar untouched. So the
client mirrors the server's label precedence in `board.module._applyTitle`
(called on `onSave` + `onPreview`): it reads `config.alias` from
`data-widget-config`, falling back to a new **`data-widget-title`**
attribute (= the class `$title`) then `data-widget-name`. The label span
carries a stable **`data-misp-widget-title`** hook (theme-independent —
the default theme's title span is `.misp-widget-title`, Overmind's is
`.card-title`; only the hook is stable per §8.5).

**Multiple instances already worked.** Instances are addressed by
`instance_id` throughout (mint in `LayoutFixup` + client
`_mintFinalInstanceId`; patch indexing in `updateWidgetSettings`), never
by widget name — so N instances of one widget class have always been
supported. Aliasing only adds the per-instance *label*. (Confirmed live:
the admin board already runs 3 `UsageDataWidget` + 2
`TrendingAttributesWidget` instances, several with hand-authored
`config.alias` values — invisible under the old top-level-only wrapper,
correctly surfaced now.)

**Reversibility.** Additive within the dashboard's own code. Revert:
drop the `alias` schema injection in `index()`/`renderWrapper()`, restore
the wrapper label to `$widget['widget']`, remove `data-widget-title` /
`data-misp-widget-title` / `_applyTitle`, rename the section back. No
data-shape break — `config.alias` is just an ignored config key to the
handler (like `refresh_delay`), and saved configs without it fall back
to `$title`.

**Implementation hooks.**
- `DashboardsController::index()` — per-widget enrichment: set
  `$w['title']` (class `$title`, default class name); prepend an `alias`
  `string` schema field with help text naming the title.
- `DashboardsController::renderWrapper()` — mirror (Add Widget path):
  `$title` + prepended alias schema; `$widgetData` gains `'title'`,
  drops `'alias' => null`.
- `Elements/dashboard/widget/wrapper.ctp` + Overmind mirror — label
  precedence `config.alias → title → class-name`; emit
  `data-widget-title`; `data-misp-widget-title` hook on the label span;
  vestigial `data-widget-alias` removed; docblock updated.
- `board.module.mjs` — `_applyTitle()` helper + calls in
  `onSave`/`onPreview`; vestigial top-level `alias` read removed from
  `_saveLayout`.
- `configure.module.mjs` — typed-tier heading "Filters" → "Settings".
- Verified: `php -l` + `node --check` clean; `renderWrapper` default
  label = the `$title` ("Recent data geolocation map", not the class
  name), `config.alias` override honoured ("My Custom Map"),
  `data-widget-title` + alias schema present; live `index()` render of
  the 15-widget admin board shows real titles/aliases, alias schema on
  all wrappers.

## DD-19 — AttributeGeoMapWidget Redis cache: per-config hash key, 1h TTL, whole-payload read-through

**Date.** 2026-05-26
**Phase context.** Post-5.5 "new features" round (third item). The geo
sweep (5 sources, mmdb lookups + galaxy SQL joins) is the heaviest
dashboard render; the user asked to cache it in Redis. This is the
**first widget-owned cache** in dashboard v2 — it revisits DD-11's
finding that `cacheLifetime` is inert (nothing reads it); a widget that
wants caching owns it explicitly, as here.

**Decision.** Each distinct config is cached in Redis under
**`misp:attribute_geo_map_cache:<sha256>`** with a **1h TTL**. On render:
hash the result-determining params → if the key is present, return the
**deserialised payload verbatim**; else run the sweep, store the whole
payload (`setex`, 3600s), and return it. A missing/broken Redis
(`RedisTool::init` throws) degrades silently to a live sweep — caching
never breaks the widget.

- **What's hashed:** `sha256(json_encode([window, cap, sources, palette,
  projection]))` — exactly the inputs that shape the cached payload. The
  window/cap/sources drive the data; palette/projection are carried in
  the payload and returned verbatim, so they must be in the key (else a
  custom-palette config could be served another config's colour). The
  *effective* (resolved) values are hashed, not the raw config, so
  equivalent configs share an entry — e.g. `{}` and
  `{time_window:"30d"}` hash identically (both resolve to the 30-day
  default). Presentation-only keys that never reach this handler's
  output (`alias`, `refresh_delay` — DD-18 / Phase 5) are deliberately
  excluded so they don't fragment the cache.
- **Key is config-only, not per-user.** Correct *because* the widget is
  no-ACL (DD-11): the same config yields the same aggregate map for
  every viewer. (A future ACL-enforced path — DD-11's logged follow-up —
  would have to key by user / ACL-scope instead.)
- **Connection:** `RedisTool::init()` (DB 13, **prefix-free**, so the
  key is exactly the literal above) + `RedisTool::serialize` /
  `deserialize` (honours the instance's `redis_serializer`). One small
  `cacheRedis()` helper returns null on failure; the get/setex are
  inlined in `handler()`.

**Design evolution (recorded — the user iterated twice).** The original
brief was "cache **only** default settings; custom configs run live."
First cut implemented that by splitting the data map from the
presentation and re-wrapping on read. The user pushed back twice: (1)
that split was over-engineered — cache the **whole payload** and hand it
back as-is; then (2) better still, **don't special-case the default** —
key every config by a hash of its config so each unique setup caches for
an hour. The final design (this entry) is strictly simpler *and* more
useful than the brief: no `isDefault` apparatus, and custom configs
(common on a SOC board with several tuned instances) are cached too.

**Rationale.** Per-config hashing is the simplest correct generalisation:
no "is this default?" comparison, every setup benefits, equivalent
configs coalesce, and 1h TTL bounds both staleness and key sprawl (keys
self-expire; the number of live distinct configs is small in practice).

**Alternatives considered.**
- **Default-only single key** (the brief / first two cuts). Simpler key,
  but only the out-of-box config benefits and it needs an `isDefault`
  check. Superseded by the user.
- **Hash the raw `$options`.** Trivial, but fragments the cache on
  irrelevant keys (`alias`, `refresh_delay`, key ordering) and doesn't
  coalesce equivalent configs. Rejected for hashing the effective
  result-determining params instead.
- **Rely on `cacheLifetime`.** Inert in v2 (DD-11) — does nothing.

**Trade-off (flagged).** Within the TTL even a **manual refresh** serves
the cached payload — the widget can't distinguish refresh from page load
server-side. Accepted under the explicit "simple, 1h" brief; a
refresh-bypasses-cache affordance would need a new render param and is a
possible follow-up.

**Reversibility.** Additive and self-contained: delete the `cacheRedis()`
helper, the cache constants, and the get/setex blocks in `handler()`;
the sweep then always runs live. No data-shape change, no new dependency
(RedisTool is core), no schema change.

**Implementation hooks.**
- `AttributeGeoMapWidget`: `CACHE_KEY_PREFIX` + `CACHE_TTL` constants;
  `handler()` hashes the effective params, reads/returns on hit, sweeps
  + `setex` on miss; `cacheRedis()` helper (graceful null);
  `resolveSince` → `resolveWindowSeconds` (returns the window so it can
  feed the hash before deriving the lower-bound timestamp); docblock
  caching note.
- Verified: `php -l` clean; distinct configs → distinct sha256 keys;
  `{}` ≡ `{time_window:"30d"}` (same key); cache hit doesn't reset TTL;
  read-through returns the stored payload verbatim (sentinel); 1h TTL;
  Redis-down path falls back to a live sweep.

## DD-20 — Generic widget cache: `WidgetCache` helper, `cache_duration` / `cache_path` opt-in

**Date.** 2026-05-26
**Phase context.** Immediately generalises DD-19. The geo widget's
Redis cache proved out the approach; the user asked to extract it into a
reusable mechanism so any widget can opt in. DD-19's bespoke,
inside-`handler()` cache is retired in favour of this.

**Decision.** A widget opts into caching **declaratively**, with two
optional public properties and **no caching code in `handler()`**:

```php
public $cache_duration = 3600;                       // TTL seconds; > 0 enables
public $cache_path = 'misp:attribute_geo_map_cache'; // optional key prefix
```

A new `app/Lib/Dashboard/Tools/WidgetCache.php` owns the logic;
`DashboardsController::renderWidget()` wraps the single `handler()` call
in `WidgetCache::remember($widget, $config, fn)`:

- **Opt-in / pass-through.** `remember()` caches only when
  `cache_duration > 0`; otherwise (and on any Redis failure) it just
  runs the closure live. So widgets that declare nothing are completely
  unaffected — the wrap is transparent.
- **Key** = `<path>:<sha256(config)>`. **Path** = `cache_path` if
  declared, else auto-derived `misp:<Inflector::underscore(class without
  "Widget")>_cache` (AttributeGeoMapWidget → `misp:attribute_geo_map_cache`
  — the auto-derivation reproduces DD-19's exact key, so the geo widget
  could even omit `cache_path`; it sets it explicitly to document the
  example). The whole `handler()` payload is cached and returned
  verbatim on a hit; a miss runs the closure and `setex`-stores it.
- **Hash input.** The config passed to `handler()` (post
  `CanonicalTypeAdapter`, so defaults are already injected and canonical
  shapes normalised — equivalent configs coalesce), with keys `ksort`-ed
  (order-independent) and the framework-managed **`NON_DATA_KEYS`
  (`alias`, `refresh_delay`) stripped**.

**Why strip `alias` / `refresh_delay` (the one deviation from "hash all
the config").** Those keys live in `config` (DD-18 put `alias` there;
`refresh_delay` is the Phase 5 per-instance scheduler override) but never
reach a widget's `handler()` output. Hashing them would give each
differently-aliased instance of a cached widget its **own** cache entry —
directly defeating DD-18's multi-instance purpose (three aliased copies
of one map with identical data filters would each recompute the
expensive sweep instead of sharing one entry). Excluding them keeps the
cache shared across aliased instances. This was surfaced to the user as
a deliberate refinement of their "sha256 of all the config" instruction.

**Config-only key — and its precondition.** The key has **no per-user /
ACL dimension**: the same config returns the same payload to everyone.
That is correct **only** for ACL-free aggregate widgets (the
AttributeGeoMapWidget posture, DD-11). The `WidgetCache` docblock states
this precondition explicitly: a future ACL-enforced widget that wants
caching must add a user/ACL-scope dimension to the key and must not
reuse this helper unchanged.

**Connection / degradation.** `RedisTool::init()` (DB 13, prefix-free so
the key is exactly the literal) + `RedisTool::serialize`/`deserialize`.
Every Redis touch is wrapped so a missing/broken Redis (or unreadable
entry) degrades silently to a live render — caching never breaks a
widget.

**Rationale.** Two declarative properties + one transparent wrap at the
single render call site is the least-surface way to make caching
available to every widget. It keeps `handler()` implementations pure
(no cache plumbing), and the contract (path derivation, exclusion,
opt-in) is locked by a unit test for the widgets that will depend on it.

**Alternatives considered.**
- **Leave the cache inside each widget's `handler()`** (DD-19 style).
  Rejected — every cached widget would re-implement the get/hash/setex
  dance; the user explicitly asked to extract it.
- **A base `Widget` class widgets extend.** Heavier; the in-tree widgets
  are plain classes with no common base, and a render-site wrap needs no
  inheritance. Rejected for the property-driven helper.
- **Hash the raw config / hash literally everything.** Fragments the
  cache on `alias`/`refresh_delay` and on key order; rejected for the
  effective-config hash with framework-key exclusion + ksort.

**Reversibility.** Additive: delete `WidgetCache.php` + its test, revert
the `renderWidget` wrap to the direct `handler()` call, and drop the two
properties from any widget. No data-shape change, no new dependency
(RedisTool is core).

**Implementation hooks.**
- New: `app/Lib/Dashboard/Tools/WidgetCache.php` (`remember`,
  `isCacheable`, `key`, `path`; `NON_DATA_KEYS`); chgrp www-data.
- New: `app/Test/WidgetCacheTest.php` (9 tests — opt-in gating, explicit
  vs derived path, key format, framework-key exclusion, order-
  independence, data-change sensitivity, cross-widget non-collision,
  uncacheable pass-through). chgrp www-data.
- `DashboardsController::renderWidget`: `App::uses('WidgetCache', …)` +
  wrap the `handler()` call in `WidgetCache::remember(...)`.
- `AttributeGeoMapWidget`: reverted to the pure sweep (DD-19's inline
  cache + `cacheRedis()` + `resolveWindowSeconds` removed; `resolveSince`
  restored); declares `$cache_path` + `$cache_duration`; docblock points
  at WidgetCache.
- Verified: `php -l` clean ×4; `WidgetCacheTest` 9/9; live — geo widget
  caches under the generic key (1h TTL); `alias` / `refresh_delay`
  changes hit the **same** key; a `time_window` change makes a new key;
  a widget without the properties (`LoginsWidget`) renders live with no
  key created.

## DD-21 — `WidgetCache` per-user key scope: `cache_scope = 'user'` (extends DD-20)

**Date.** 2026-05-26
**Phase context.** The user asked to wire 1h caching into most widgets on
their admin board. Auditing each `handler()` against DD-20's documented
**config-only-key precondition** ("the same config must yield the same
payload for every viewer") split the board's widgets in two: most are
ACL-free aggregates (safe to cache config-only), but **three produce
per-user output** and so could **not** reuse DD-20 unchanged:

- **`TrendingAttributesWidget`** — branches on `$user['Role']['perm_site_admin']`
  / `$user['org_id']`: a regular user sees only their own org's
  attributes; a site-admin sees the whole instance.
- **`TrendingTagsWidget`** — `Event::filterEventIds($user, …)` ACL-scopes
  which events feed the tag tally.
- **`NewUsersWidget`** — redacts the `email` field unless the viewer is a
  site-admin (or `Security.disclose_user_emails` is set).

DD-20's docblock had explicitly anticipated this: "a future ACL-enforced
widget that wants caching must add a user/ACL-scope dimension to the key
and must not reuse this helper unchanged." This is that follow-up — the
dimension is added **to the helper as an opt-in**, rather than forking it.
The user's instruction: *"for anything that has per-user ACL include the
user in the key path."*

**Decision.** A third optional public property:

```php
public $cache_scope = 'user';   // optional; default 'global' (DD-20 config-only)
```

- **Default `'global'`** — unchanged DD-20 behaviour, key
  `<path>:<sha256(config)>`. All previously-cacheable widgets (the geo
  widget, the safe board aggregates) are untouched.
- **`'user'`** — the key gains a `u<id>:` segment:
  `<path>:u<id>:<sha256(config)>`. The user id is the **safe superset**
  of the actual ACL dimension (org_id + role for TrendingAttributes; the
  full event-ACL for TrendingTags; role for NewUsers) — two users who
  would compute identical payloads still get separate entries (a lower
  hit-rate, never a leak). The user id is the dimension the user named.
- **Fail-safe.** A `'user'`-scoped widget rendered **without** a usable
  user id is **not cached** — `remember()` returns a live compute before
  touching Redis. Skipping the cache can never leak; defaulting to a
  shared key could.

`remember()` and `key()` gain an optional trailing `$user` parameter
(back-compatible — existing 2/3-arg callers and the unit suite keep
working); `renderWidget()` already had `$user` in scope and now passes it
through.

**Why user id, not the precise ACL tuple.** Keying by the exact ACL
inputs (org_id+role, or a hash of the resolved event-id ACL) would raise
the hit-rate but is widget-specific, fragile (the ACL surface differs per
widget and can change), and easy to get subtly wrong — a single missed
dimension is a silent cross-user leak. User id is coarse, uniform, and
provably correct for every per-user widget. Hit-rate loss is bounded by
the 1h TTL and the per-user dashboard model (each user renders their own
board).

**Rationale.** One optional property + one optional argument keeps the
DD-20 contract intact for every existing caller while making per-user
caching a conscious, one-line opt-in. The safe/unsafe split is encoded
**at the widget** (`cache_scope`), where the author who knows the
handler's ACL posture declares it — not buried in the helper.

**Alternatives considered.**
- **Skip the three ACL widgets entirely** (cache only the safe
  aggregates). Offered; the user chose to cache them per-user instead —
  the two trending widgets are the most expensive on the board (full
  event/attribute sweeps), exactly what's worth caching.
- **Auto-detect ACL-dependence** (e.g. sniff whether `handler()` uses
  `$user`). Rejected — undecidable in general, and a wrong guess in
  either direction is bad (a missed leak, or needless cache fragmentation).
  Explicit opt-in matches DD-20's declarative philosophy.
- **Key by the resolved ACL tuple** rather than user id. Rejected as
  above (fragile, widget-specific); user id is the safe, uniform choice.

**Reversibility.** Additive: drop `cache_scope` from the three widgets to
fall back to live (uncached) renders, or remove the `scope()` helper +
the `$user` params to return to DD-20 exactly. No data-shape change, no
new dependency.

**Implementation hooks.**
- `WidgetCache`: new private `scope()`; `remember()` gains `$user` + the
  no-user fail-safe; `key()` gains `$user` + the `u<id>:` segment; docblock
  updated (property list + the Scope paragraph supersedes the old
  "No-ACL assumption" paragraph).
- `DashboardsController::renderWidget`: passes `$user` as `remember()`'s
  4th argument.
- `WidgetCacheTest`: +5 cases (user segment in key, different users →
  different keys, same user/config → same key, global scope ignores a
  passed user, user-scoped-without-user runs live) → 14/14.
- The three ACL widgets declare `$cache_duration = 3600` + `$cache_scope
  = 'user'`; the five safe aggregates declare `$cache_duration = 3600`
  only (DD-20 global key). See the progress tracker for the per-widget
  list + live verification.

## DD-22 — Default (built-in) dashboard templates: file-shipped, on-demand ingest into the gallery

**Date.** 2026-05-26
**Phase context.** The remaining user-enumerated post-5.5 feature ("three
default dashboard layouts — analyst / admin / community"). The user
specified the mechanism: mirror MISP's file-based reference-data pattern
(warninglists / taxonomies / object-templates / galaxies) — ship a
subdirectory of templates, ingest them on demand, and have them surface
in the existing dashboard template gallery.

**Findings that shaped the design.**
- The `dashboards` table **is** the template store (`uuid`, `name`,
  `description`, `value` = layout JSON, `default` = the single global
  default board, `selectable` = visible to others, `user_id` = owner,
  `restrict_to_org_id` / `restrict_to_role_id` /
  `restrict_to_permission_flag` = per-template ACL).
- The gallery (`listTemplates`) already enforces ACL in its query and
  the apply path (`getDashboardTemplate`) already supports an
  **instance-wide selectable template**: a row with `selectable=1` and
  empty `restrict_to_*` is visible + applicable to everyone, and
  `restrict_to_permission_flag='perm_site_admin'` scopes to admins. So
  **no ACL work was needed** — content authors target via those columns.
- `resetFromTemplate` runs `LayoutFixup::applyReadFixups` on apply, so
  shipped layouts use the canonical `{x,y,w,h}` position shape and stay
  forward-compatible.

**Decisions (all three forks surfaced to the user; the user picked each
recommended option).**

1. **Re-ingest strategy: overwrite by uuid, no version, no schema
   change.** The `dashboards` table has **no `version` column**. Rather
   than add one (a core-table migration via `runUpdates` — beyond the
   additive posture), each manifest carries a fixed `uuid` and the row is
   upserted on it (overwrite). This is sound here precisely because
   shipped templates are **read-only reference data**: a user never edits
   the built-in row (they *apply* it to their board — a separate
   `UserSetting` — or clone it into their own `dashboards` row), so an
   overwrite on re-ingest loses nothing user-authored. Re-ingest is
   idempotent (verified: re-run kept the same row id, count stayed 1).
   *Diverges from the warninglist version-gated idiom* — a deliberate,
   user-accepted simplification given the read-only nature + the desire
   to stay schema-additive. (Alternatives offered: add a `version`
   column; store version inside the `value` blob. Both declined.)

2. **Gallery placement: a new "Starter templates" bucket.** Built-ins
   are owned by a **system `user_id = 0`** — that is the built-in marker.
   `listTemplates` routes `user_id === 0` rows into a new `$starter`
   bucket (checked *before* the default/mine/shared branches) and the
   view renders a dedicated "Starter templates" section at the top of the
   gallery. Without this they would land in "Shared with me" (functional
   but mislabeled — shared by nobody). (Alternatives offered: reuse
   "Featured"; no UI change. Both declined.)

3. **Sequencing: mechanism first, then author the layouts.** This DD +
   commit land the plumbing + **one** sample template ("Overview
   (starter)"); the analyst / admin / community layouts are authored as a
   separate follow-up task.

**The ingest itself.** `Dashboard::importTemplatesFromDirectory($dir =
null)` globs `app/files/dashboard-templates/*/template.json`, reads each
via `FileAccessTool::readJsonFromFile`, and upserts through the private
`__importTemplate()` (validates `uuid`/`name`/`value`, forces
`user_id=0`, `selectable` default 1, `default=0`, copies `restrict_to_*`,
`json_encode`s `value`). Returns the warninglist-style
`['success' => [id => ['name'=>…]], 'fails' => [slug => msg]]`.

**Triggers.** Two, mirroring warninglists:
- Site-admin-only controller action `DashboardsController::
  importDefaultTemplates()` (POST; ACL `array()` = site-admin), surfaced
  as an "Import starter templates" button in the gallery header (admins
  only). Logs per-template success/fail; flashes a summary; redirects to
  the gallery.
- A new (additive) `DashboardShell::importDefaultTemplates` CLI command
  (`app/Console/cake Dashboard importDefaultTemplates`).

**Template manifest shape** (`app/files/dashboard-templates/<slug>/
template.json`): `uuid` (fixed), `name`, `description`, `selectable`,
optional `restrict_to_*`, and `value` (the array of widget instances:
`instance_id`, `widget`, `config` incl. `config.alias` per DD-18,
`position {x,y,w,h}`).

**Rationale.** Reuses the entire existing template stack (store, gallery,
ACL, apply, preview) — the only genuinely new surface is the ingest
method + one admin action + a CLI command + a gallery bucket + the files
dir. Mirrors the most idiomatic MISP ingest (warninglists), minus the
version gate (justified above).

**Alternatives considered.**
- **Virtual file-backed gallery entries** (read the files at gallery-
  render time, never touch the DB). More additive still, but diverges
  from the user's stated "ingest on demand" model and would need a
  parallel non-DB apply path. Rejected.
- **A dedicated `dashboard_templates` table.** Redundant — the
  `dashboards` table already is the template store and the gallery reads
  it. Rejected.
- **Add a `version` column** (full warninglist parity). Rejected for the
  schema-additive overwrite-by-uuid (fork 1).

**Reversibility.** Additive: delete `app/files/dashboard-templates/`, the
`importTemplatesFromDirectory`/`__importTemplate` methods, the
`importDefaultTemplates` action + ACL line, the `DashboardShell`, and the
gallery `$starter` bucket; `DELETE FROM dashboards WHERE user_id = 0`. No
schema change, no new dependency, no change to any existing template's
behaviour.

**Implementation hooks.**
- New: `app/files/dashboard-templates/overview-starter/template.json`
  (the sample). chgrp www-data (inherited). Required a `.gitignore`
  exception pair (`!/app/files/dashboard-templates` + `/*`) — `app/files/*`
  is ignore-all and `dashboard-templates` is a plain in-repo dir, not a
  submodule like warninglists, so its files must be explicitly un-ignored
  to ship.
- New: `app/Console/Command/DashboardShell.php`. chgrp www-data.
- `app/Model/Dashboard.php`: `importTemplatesFromDirectory()` +
  `__importTemplate()`.
- `app/Controller/DashboardsController.php`: `importDefaultTemplates()`
  action; `listTemplates` adds the `$starter` bucket + `starterTemplates`
  view var.
- `app/Controller/Component/ACLComponent.php`: `'importDefaultTemplates'
  => array()` (site-admin).
- `app/View/Dashboards/list_templates.ctp`: "Starter templates" section +
  admin "Import starter templates" header button + empty-state guard.
- Verified: `php -l` clean ×5 + manifest valid JSON; CLI ingest creates
  row #11 (`user_id=0`, `selectable=1`, `default=0`); re-run idempotent
  (same id, count 1); REST `listTemplates` returns the starter; session
  HTML gallery renders the "Starter templates" section + card + admin
  import button (no fatal — the preview SVG parsed the layout). Apply
  (`resetFromTemplate`) relies on the existing, unchanged path + verified
  shape parity with a live board; a destructive apply against the admin's
  15-widget board was intentionally not run.

## DD-23 — `asn-country.json` regeneration wired into `cake Admin preRelease` (DD-12 follow-up)

**Date.** 2026-05-27
**Phase context.** DD-12 shipped the geo widget's `asn` source backed by a
derived `app/files/geo-open/asn-country.json`, built offline by
`app/files/scripts/generate_asn_country_map.py` from the
`GeoOpen-Country-ASN.mmdb`. DD-12 logged a follow-up: "regenerate the JSON
when the mmdb updates." This DD closes it. The user picked this task.

**Premise correction (the finding that reshaped the task).** DD-12's
follow-up assumed *"MISP's existing geo-open mmdb-update mechanism"* to
hook into. **There is no such automated job.** The `geo-open` dir is a
plain git-tracked dir in the MISP repo (not a submodule, no downloader, no
cron, no `Admin` job); the mmdb files **and** `asn-country.json` are
committed artifacts. They update when a **maintainer hand-commits a fresh
file** — e.g. `8d9897be8 chg: [GeoOpen] GeoOpen-Country updated -
GeoOpen-Country-ASN added`, `f0f6d3254 chg: [GeoOpen] updated to the latest
version`. Instances receive new files via a plain `git pull` of MISP. (The
`UserLoginProfile.php` comment "GeoIP file managed by MISP" refers to this
manual maintainer cadence, not an automated fetch. The `misp-opendata`
scripts that mention public.lu *publish* MISP data outward; they do not
fetch the geo DB.) So the real question is **where the regen trigger
lives**, given the file only ever changes via a human commit.

**Decision.** Wire the regen into **`AdminShell::preRelease()`** — the
maintainer's pre-release CLI task that already refreshes committed JSON
artifacts (`db_schema.json`, `describeTypes.json`) before each release.
This is the precise point at which the maintainer regenerates + commits
derived artifacts, so `asn-country.json` joins them. (The user identified
`preRelease` as the right home after three trigger-location forks were
surfaced — maintainer-side / runtime self-healing background job /
staleness-guard-only.)

- New `AdminShell::updateAsnCountryMap()` runs the script via
  `ProcessTool::execute([ProcessTool::pythonBin(), <script>])` — the same
  managed-venv interpreter every other MISP python invocation uses
  (`MISP.python_bin`, default `python3`). The script writes to its default
  path (`app/files/geo-open/asn-country.json`), the tracked location, so
  the regenerated file lands exactly where the maintainer commits it —
  mirroring `dumpCurrentDatabaseSchema` writing `db_schema.json`.
- `preRelease()` calls it after the two existing dumps.
- It is **also** registered as a standalone subcommand
  (`cake Admin updateAsnCountryMap`, mirroring `dumpCurrentDatabaseSchema`'s
  registration) so a maintainer can regenerate after a **mid-cycle mmdb
  bump** without a full release.

**Fail-safe (visible but non-blocking).** `ProcessTool::execute` throws on
a non-zero exit (e.g. `maxminddb` not installed, or the mmdb absent). The
method catches it and emits a clear two-line `$this->err()` warning (stderr,
**non-fatal** — does not abort the release dump) naming the likely cause and
warning that the shipped json may be stale. On failure the script never
writes, so a stale `asn-country.json` is **left intact, never zeroed or
corrupted**. Rationale: an optional dev dep missing on a maintainer's box
shouldn't block the schema/describeTypes dumps, but a skipped regen must be
impossible to miss — hence loud-on-stderr rather than silent or fatal.

**`maxminddb` dependency → `requirements-dev.txt` (user's call).** The
package was declared in **no** MISP requirements file, so on a stock venv
the regen warned-and-skipped. It is now in `requirements-dev.txt`, not
`requirements.txt`: `preRelease`'s own help says "(for developers)", the
canonical flow is maintainer-regenerates-and-commits, and **production
instances consume the committed json and never regen**. Keeping it out of
prod avoids every install pulling a package almost none of them run.
(Trade-off accepted: an admin running the standalone subcommand in
production gets the warn-and-skip until they install `maxminddb` by hand —
guided by the warning.)

**Determinism (no spurious churn).** The script sorts keys + uses fixed
separators, so regenerating against an **unchanged** mmdb is byte-identical
— verified by a zero-line `git diff` after a live regen. The maintainer
therefore only sees (and commits) a diff when the mmdb actually changed.

**Why not a runtime / scheduler job.** Self-healing regen on each instance
(the "most automatic" fork) was declined implicitly by the choice of
`preRelease`: the file is a committed artifact, so regen belongs where the
maintainer commits the mmdb, not at request/worker time — which would
require `maxminddb` on every worker host and would dirty the git-tracked
`geo-open` dir on instances (a `git pull` would conflict). Adding a
scheduler task type would also touch existing scheduler code (beyond the
additive posture).

**Files touched.**
- `app/Console/Command/AdminShell.php`: new `updateAsnCountryMap()` method;
  one call added to `preRelease()`; `addSubcommand('updateAsnCountryMap')`
  registration. (Existing file — additive within it; the user directed the
  `preRelease` hook explicitly.)
- `requirements-dev.txt`: `maxminddb` (+ a comment noting its consumer).

**Verified.** `php -l` clean; the standalone subcommand regenerates through
the configured venv python (`> Wrote 77846 ASN->country entries to …`);
regen byte-identical to the committed json (empty `git diff`); spot-checks
sane (OVH 16276→FR, Cloudflare 13335→US); fail-safe path proven live (venv
**without** `maxminddb` → caught, two-line stderr warning, json untouched).
`maxminddb 3.1.1` (latest, pulled by the bare requirement) works with the
script's `open_database` + iteration API. Additive/reversible.

## DD-24 — Default dashboard templates: auto-ingest on update/install (extends DD-22)

**Date.** 2026-05-27
**Phase context.** DD-22 shipped the built-in starter templates with an
**on-demand** ingest only (the site-admin gallery button + the
`cake Dashboard importDefaultTemplates` CLI), and logged "auto-ingest on
update/install" as a follow-up. The user picked that follow-up.

**Finding surfaced first (rigorous-pushback).** MISP **does not**
auto-ingest reference-data *content* on update. The `updateMISP()` /
`updateDatabase()` migration chain creates the galaxy/warninglist/object
*tables*, but the actual content ingest of those corpora stays an
on-demand admin action (button / CLI). So auto-ingesting dashboard
templates on update is a deliberate **divergence** from that posture.

**Decision (user's call: unconditional).** The forks surfaced were
(1) unconditional auto-ingest, (2) gate behind an opt-out server setting,
(3) keep on-demand only (respect the norm). The user chose **unconditional**
— defensible because the starters are three tiny rows that are
`selectable`, deletable, and never the global `default` board (≠ a curated
galaxy/warninglist corpus), and out-of-the-box starters are a UX win.

**Mechanism (idiomatic, minimal).** Mirrors `case 150: fixDatabaseEncoding()`:
- `AppModel::DB_CHANGES` gains `151 => false` (no logout required).
- `AppModel::updateMISP()` gains `case 151:` →
  `$this->__importDefaultDashboardTemplates()`.
- New private `__importDefaultDashboardTemplates()` inits the `Dashboard`
  model, calls the existing DD-22 `importTemplatesFromDirectory()`, and
  logs a SYSTEM `update_database` entry naming the imported templates (and
  a second entry if any failed). It **returns `true` unconditionally** — a
  missing or partial `app/files/dashboard-templates/` dir must never fail
  the DB migration chain (the ingest already records per-template failures
  internally; DD-22's method returns an empty result, not a throw, on a
  missing dir).

**Covers both "update" and "install".** Existing instances run `case 151`
when they cross update 151. Fresh installs are covered by the *same* step:
`INSTALL/MYSQL.sql` baselines `db_version = 126` and `runUpdates` replays
the delta (127→151) via `findUpgrades`, so a new install also hits 151. No
separate install-seeding path needed.

**One-shot + replay-safe.** The step runs once per instance (when it
crosses 151). DD-22's ingest is idempotent (overwrite-by-uuid), so MISP's
"all updates are re-playable" guarantee holds. Consequence of one-shot: an
admin who manually deletes a built-in sees it return **once** on crossing
151 — accepted (with DD-25's pruning the shipped set is authoritative
anyway). A *later* release that changes the shipped templates would add its
own new `DB_CHANGES` entry to re-trigger ingest (standard MISP migration
cadence) — the committed `db_schema.json` `db_version` is not hand-bumped
here; it syncs at `preRelease` (DD-23).

**Files touched.** `app/Model/AppModel.php` only (the `DB_CHANGES` entry,
the `case 151:`, and the private method). No schema change.

**Verified — end-to-end by the live system itself.** After the code
landed, MISP's **own** background update mechanism autonomously detected
and ran update 151 through the real `runUpdates` path (no manual
invocation): `db_version` advanced to 151, all three built-in rows present
and correctly named, and a `logs` row recorded "Default dashboard templates
imported: Administrator, Analyst, Community". `php -l` clean. The
divergence-from-norm finding was surfaced to the user before coding.
Additive/reversible.

## DD-25 — Default dashboard templates: prune orphaned built-ins, opt-in to the explicit ingest (extends DD-22)

**Date.** 2026-05-27
**Phase context.** DD-22's `importTemplatesFromDirectory()` upserts by uuid
but never deletes; a built-in whose manifest was removed lingered as an
orphan (the "Overview" removal was a manual `DELETE`). The follow-up: make
the shipped set authoritative by pruning orphaned built-ins.

**Decision (user's call: opt-in, explicit ingest only).** Pruning is gated
by a new `$prune` parameter (default `false`). The **explicit** operator
ingests pass `true` — the gallery "Import starter templates" action
(`DashboardsController::importDefaultTemplates`) and the
`cake Dashboard importDefaultTemplates` CLI. The **silent** auto-ingest on
update (DD-24, `AppModel::__importDefaultDashboardTemplates`) calls the
method bare, so an update **never deletes a dashboard**. The fork
(prune-on-every-canonical-ingest vs. explicit-only) was surfaced; the user
chose explicit-only — automatic row deletion during a silent update is
higher-stakes than ingesting, so deletion stays an operator-initiated act.

**Why pruning `user_id = 0` is safe.** `saveDashboardTemplate()` always
writes the acting user's real id (and the global *default* board is just a
`default = 1` row owned by whoever set it) — so **`user_id = 0` is
exclusively the shipped built-ins**. Pruning them touches no user-authored
board or clone.

**Guards (each protects against a concrete failure).**
- **`default = 0` in the prune conditions.** An admin *can* promote a
  built-in to the global default via `saveDashboardTemplate` (it keeps
  `user_id = 0` and sets `default = 1`). Excluding `default = 1` means a
  promoted-then-orphaned built-in is never deleted out from under the
  instance. (Verified live: a `default = 1` orphan survived a prune.)
- **Non-empty shipped set.** Prune runs only when at least one manifest
  yielded a uuid. A missing/unreadable `app/files/dashboard-templates/`
  must not turn `NOT IN ()` into "delete every built-in".
- **uuid collected per parseable manifest, before its import is attempted.**
  A still-shipped template whose *save* transiently fails is still counted
  as shipped, so it is never mistaken for an orphan and pruned.

**Deletion mechanism: by id, one at a time — not `deleteAll`.** Discovered
latent bug: the `Dashboard` model declares `belongsTo Organisation` with
`foreignKey => 'org_id'`, but the `dashboards` table has **no `org_id`
column** (it uses `restrict_to_org_id`). `deleteAll()`/`updateAll()`
auto-join the belongsTo on the phantom column and crash
(`Unknown column 'Dashboard.org_id' in 'ON'`). So prune collects orphan ids
via a `recursive = -1` find (Dashboard-only conditions, no join) and calls
`$this->delete($id, false)` per row. (Logged as discovered work.)

**Surfacing.** The result array gains `'pruned' => [id => name]`. The
controller logs a `delete` audit entry per pruned row and appends an
"N orphaned pruned" count to its flash; the CLI prints `[PRUNE]` lines plus
the count. The auto-ingest's `pruned` key is always absent (bare call).

**Files touched.** `app/Model/Dashboard.php` (the `$prune` param + guarded
prune block), `app/Controller/DashboardsController.php` (pass `true`, log +
report), `app/Console/Command/DashboardShell.php` (pass `true`, report).
AppModel/DD-24 unchanged — it already calls the method bare.

**Verified live.** Explicit CLI ingest pruned a seeded `default = 0`
orphan while re-importing the three real built-ins (`1 orphaned pruned`); a
seeded `default = 1` orphan survived (`0 orphaned pruned`); and the bare
no-prune call (the exact DD-24 migration path) left a seeded orphan intact
with no `pruned` key. `php -l` clean ×3. Additive/reversible.

## DD-26 — Default dashboard templates: a manifest-declared fallback default, promoted when the instance has none (extends DD-22)

**Date.** 2026-05-27
**Phase context.** With starter templates now shipped (DD-22) and
auto-ingested (DD-24), a fresh user still lands on the empty board unless an
admin promotes a template to the global default — because the shipped
starters are `default=0` (`getDashboardTemplate(default=1)` finds nothing,
so `index()` renders the empty state). The user asked: make **Analyst** the
default *if, at ingest time, no template is set as the default*.

**Is `default` guarded against multiple flagged rows? (asked + answered.)**
**No hard guard.** The `dashboards` table has **no index/constraint on
`default`** at all. The single-default invariant is maintained only by
`saveDashboardTemplate()` → `__unsetPreviousDefault()`, which `find('first',
default=1)`s and demotes **exactly one** row before setting a new default —
so it assumes the invariant already holds (duplicates would not be fully
reconciled), and `getDashboardTemplate()` just `find('first')`s on the read
side. This shaped the design: the promotion below only ever fires when
`COUNT(default=1) === 0`, so it cannot create a second default.

**Decision.**
1. **Declarative fallback marker.** A manifest may carry
   `"default_fallback": true`. `importTemplatesFromDirectory()` collects the
   uuids of such manifests; after import (and prune), if **no** row holds
   `default=1`, it promotes the first fallback candidate (by id) to
   `default=1` via `saveField` (not `updateAll` — phantom `org_id` join,
   DD-25). Result gains `'promoted_default' => [id => name]`. Only **Analyst**
   carries the flag. Chosen over hardcoding Analyst's uuid in the model
   (declarative, future-proof, no magic constant).
2. **Fires on every ingest — explicit *and* the silent auto-ingest on
   update/install (user's call: "Both").** The promotion lives in
   `importTemplatesFromDirectory()` itself, so both the admin gallery/CLI
   ingest and DD-24's bare auto-ingest run it. Rationale: production
   instances cross update 151 *for the first time with this code in place*
   (151 has shipped nowhere yet), so the auto path establishes the default
   for them on update with no admin action. **It only ever fills an empty
   slot** — an admin's existing default is never overridden (the COUNT
   guard). Acknowledged consequence the user accepted: an admin who
   deliberately clears the default sees Analyst re-imposed on the next
   ingest that re-triggers (a *non-destructive* silent state change, unlike
   the prune which the user kept explicit-only).
3. **Refines DD-22's blanket `default=0`.** `__importTemplate` previously
   forced `default=0` on every upsert, which would silently demote a
   built-in an admin had promoted to default on each re-ingest (and, with
   promotion active, flip the instance to Analyst). It now **preserves the
   existing row's `default` on upsert** (fetches it in the `$existing`
   find), forcing `0` only on **insert** of a genuinely new row — so a
   newly-shipped built-in still never seizes the slot, but an admin's
   promotion survives re-ingest. (Trail discipline: DD-26 supersedes that
   one aspect of DD-22; DD-22 left unedited.)

**Surfacing.** CLI prints a `[DEFAULT]` line; the controller logs an
`update` audit entry + appends ' Set "X" as the default.' to its flash; the
DD-24 auto-ingest logs a SYSTEM `update_database` entry. All keyed off the
new `promoted_default` result element (absent when nothing was promoted).

**Files touched.** `app/files/dashboard-templates/analyst/template.json`
(`default_fallback: true`); `app/Model/Dashboard.php`
(`__importTemplate` default-preservation + the fallback-collect/promote
block); `app/Model/AppModel.php`, `app/Controller/DashboardsController.php`,
`app/Console/Command/DashboardShell.php` (reporting).

**Verified live.** (A) forced no default → ingest promoted Analyst
(`[DEFAULT] Analyst (#13)`), `COUNT(default=1)=1`. (B) admin sets Community
as default → re-ingest **preserved** Community (no re-promotion, count
stayed 1) — proving both `__importTemplate`'s default-preservation and the
COUNT guard. Re-run with a default present is a no-op. `php -l` clean ×4 +
manifest valid JSON. Additive/reversible.

## DD-27 — Harden `__unsetPreviousDefault()` to demote *all* defaults (closes DD-26's soft-invariant gap)

**Date.** 2026-05-27
**Phase context.** DD-26 documented that the single-default invariant is
**soft** — no schema constraint on `dashboards.default`, and
`__unsetPreviousDefault()` (called by `saveDashboardTemplate` when a new
default is saved) demoted only the **first** `default=1` row it found. So if
duplicates ever arose (direct DB edit, a past bug), selecting a new default
would leave the stragglers, and `getDashboardTemplate()`'s `find('first')`
would then pick ambiguously. The user asked to harden it.

**Decision.** `__unsetPreviousDefault()` now demotes **every** `default=1`
row before the caller saves the new one, so the invariant is reconciled on
each promotion regardless of prior state.

**Two non-obvious implementation points.**
- **Loop + `saveField` by id, not `updateAll`.** `updateAll`/`deleteAll`
  crash on the model's phantom `belongsTo Organisation` foreign key
  (`org_id`, no such column — the discovered-work bug DD-25 also worked
  around). A `recursive = -1` find collects the ids; each is demoted by id.
- **`$this->id` is saved and restored around the loop.** `saveField`
  mutates `$this->id`, and `saveDashboardTemplate` runs `$this->save(...)`
  immediately after — in the **create** path that final save relies on
  `$this->id` being false (set by the earlier `create()`) to INSERT. Without
  the restore, the demotion would leave `$this->id` pointing at a demoted
  row and the new template would overwrite it instead of inserting.
  Restoring `$this->id` keeps the create-vs-update decision the caller's,
  uncontaminated. (`$this->data` is irrelevant — the final save passes its
  data explicitly.)

**Files touched.** `app/Model/Dashboard.php` (`__unsetPreviousDefault` only).

**Verified live** (via the public `saveDashboardTemplate`): seeding two
`default=1` rows then promoting a third demoted **both** stragglers (count
→ 1, only the new one); and the create-with-`default=1` path inserted a
**new** row (row count +1) that became the sole default — proving the
`$this->id` preservation. `php -l` clean. Additive/reversible.

## DD-28 — Drop the `Dashboard` model's phantom `belongsTo Organisation`/`Role` (fixes the `updateAll`/`deleteAll` crash; supersedes DD-27's implementation)

**Date.** 2026-05-27
**Phase context.** The discovered-work bug DD-25/DD-26/DD-27 all worked
around: `Dashboard.php` declared `belongsTo Organisation` with
`'foreignKey' => 'org_id'` **and** `belongsTo Role` (default
`'foreignKey' => 'role_id'`), but the `dashboards` table has **neither**
column — it uses `restrict_to_org_id` / `restrict_to_role_id`. The user
chose to fix it properly this session.

**Root cause (traced, not assumed).** `Mysql::update()`/`delete()` (the
engine behind `updateAll`/`deleteAll`) call `_getJoins($model)`, which builds
a `LEFT JOIN` for **every** `belongsTo`/`hasOne` association
*unconditionally*; `getConstraint` writes each `ON` clause from the
association's `foreignKey`. So both phantom keys produced
`... ON Dashboard.org_id = …` / `Dashboard.role_id = …` →
`Unknown column 'Dashboard.org_id' in 'ON'`. `find` is immune because the
model is `recursive = -1` everywhere (no auto-join), and single-id
`save`/`delete($id)` don't join — which is why DD-22's ingest worked and the
bug stayed latent.

**Decision — drop, not repoint** (user's fork choice; alternatives were
repoint-FK and repoint+rename). A repo-wide check confirmed the two
associations are **completely unread**: every Dashboard `find` is
`recursive = -1`; the only consumed association is `User` (the `contain`
at `DashboardsController.php:1064`, FK `user_id` — valid); the
`$user['Role']['perm_site_admin']` reads in the model are the *authenticated
user's* role, not a Dashboard association; and `Organisation::
ORGANISATION_ASSOCIATIONS` (which maps `dashboards → restrict_to_org_id`) is
a plain cascade/merge data structure, not the CakePHP belongsTo. Ownership
is `user_id`; org/role/permission are *restrictions* enforced inline in
`getDashboardTemplate()`. So the honest minimal fix is to remove both dead
associations rather than invent a misleading `Organisation` alias meaning
"the restriction org."

**Changes.**
- `belongsTo` → just `User` (with a comment recording why org/role are not
  associations, to deter a future re-add of a phantom FK).
- Dropped the dead `validate` rules for `org_id` / `role_id` (also phantom
  columns — those rules never fired).
- **Supersedes DD-27's *implementation*** (behavior unchanged):
  `__unsetPreviousDefault()` reverts from the find-loop-`saveField` +
  `$this->id` save/restore dance to a single
  `updateAll(['Dashboard.default' => 0], ['Dashboard.default' => 1])`. The
  loop + `$this->id` dance existed **only** because `updateAll` was unsafe;
  with the phantom join gone, `updateAll` demotes *all* defaults in one
  statement and never touches `$this->id`, so the create-vs-update
  contamination DD-27 guarded against cannot arise. DD-27's *goal*
  (demote-all) stands; only the mechanism is simplified.
- DD-25 prune + DD-26 fallback comments truthed-up (their phantom-join
  justification removed); their **code is unchanged** — the prune `find`
  is still needed to report the pruned id=>name set, and the fallback
  `saveField`-by-id is the natural single-row path.

**Files touched.** `app/Model/Dashboard.php` only.

**Verified live.** Joined `updateAll`/`deleteAll` with no-match conditions
no longer crash (return true; row count unchanged); the dumped SQL joins
**only** `users` (`LEFT JOIN users AS User ON Dashboard.user_id = User.id`) —
no phantom column anywhere. The new `__unsetPreviousDefault` `updateAll` path
was exercised self-restoringly: defaults `{13:Analyst}` → demote-all → `0`
→ restored to `{13:Analyst}` (dev box left exactly as DD-26 set it).
`php -l` clean. Pre-existing bug; not introduced by the dashboard rework.

## DD-29 — Live system-monitor widgets (CPU / memory / disk) with client-side streaming

**Date.** 2026-05-27
**Phase context.** While refining the admin dashboard the user wanted a
livelier alternative to `MispSystemResourceWidget` (a `SimpleList` of one-shot
disk/load/mem strings): three site-admin-only widgets that sample every 10s as
charts — **CPU** + **memory** as rolling line graphs, **disk** as a pie. The
line graphs must accumulate a **rolling 180s window client-side while the
dashboard is open** (resetting on reload).

**Core problem.** The board's normal refresh (`Board._renderWidget`) replaces
the widget body `innerHTML` and re-inits its chart from scratch — that wipes a
client-accumulated buffer every tick. So the line charts cannot ride the
standard scheduler refresh.

**Decisions.**

1. **Client-side rolling buffer, not server-side.** The buffer lives in the
   chart's JS closure; reload / manual refresh starts fresh. Matches the
   user's "while the dashboard is open", needs no storage, and has no
   cross-user/cross-tab contention a shared server buffer would. The disk pie
   is a *snapshot* (no history needed), so it keeps the standard scheduler
   refresh (`autoRefreshDelay = 10`); only CPU/memory stream.

2. **Poll via the existing `renderWidget` `exportjson` contract — no new
   endpoint/route/ACL.** A streaming widget's `handler()` returns ONE current
   sample; the chart polls `POST {renderUrl}/{id}/exportjson:1` (the exact
   call `Board._exportWidget` makes) to fetch it as bare JSON. That path runs
   **live** for any widget without `$cache_duration` (the `WidgetCache::remember`
   wrapper is a pass-through), so the monitors are uncached by simply not
   opting in. The streaming widgets set **`autoRefreshDelay = false`** → no
   `data-widget-refresh-delay` → the board scheduler drops the tile (its own
   poll loop is the sole driver; no HTML-replacing re-render to wipe the
   buffer).

3. **Two new render kinds, minimal core-JS touch.** `PieChart` (`pie`) and
   `MonitorLineChart` (`monitor`), each a new `Widgets/<Kind>.ctp` + a glyph
   in `render-thumbs.mjs` (CLAUDE.md rule). The *only* core-file edit
   (`charts.module.mjs`) is: a `pie` builder added to the `builders` registry;
   a `kind === 'monitor'` branch in `initChart()` delegating to a **new**
   `monitor-chart.mjs` (all streaming logic lives there); and a `teardown()`
   branch in `disposeChart()`. There is no way to bootstrap JS after an AJAX
   `innerHTML` render without hooking the post-render path
   (`initChartsIn`/`initChart`), which lives in core JS — `charts.module.mjs`
   (whose whole job is "payloads → live charts") is the least-invasive hook
   and already owns the dispose-on-remove lifecycle. **User signed off on this
   core touch via plan approval** (additive-posture exception).

4. **CPU metric = 1-min load average normalized to % of cores**
   (`sys_getloadavg()[0] / cores * 100`, cores from `/proc/cpuinfo`). User's
   fork choice over true `/proc/stat`-delta CPU% (which costs a ~200ms blocking
   sample per poll) and over raw load average. Caveat carried: a 1-min average
   is smoothed, so the line moves slowly within a 180s window. The axis `yMax`
   is a **floor** (≥100 but expands if a sample exceeds it — normalized load
   can pass 100% on an overloaded host). **Memory = used %** via
   `MemTotal - MemAvailable` (a truer "used" than the existing widget's
   `MemFree`, which counts cache/buffers as used; falls back to `MemFree` on
   pre-`MemAvailable` kernels).

**Lifecycle / robustness.** `monitor-chart.mjs` returns
`{ chart, observer, teardown }`; `teardown()` clears the poll interval +
ResizeObserver + disposes the chart, so widget-remove and manual-refresh leave
no orphaned timers. The poll soft-pauses while `document.hidden` (matches the
scheduler's Page-Visibility behaviour) and treats a failed poll as a skipped
tick (keeps the accumulated series). The renderWidget base URL is read from the
board root's `data-misp-board-renderwidget-url` (the same attribute `Board`
uses) — single source of truth, no `$baseurl` in the template.

**Files.** New: `app/Lib/Dashboard/{DiskUsageMonitorWidget,CpuLoadMonitorWidget,
MemoryUsageMonitorWidget}.php`, `app/View/Elements/dashboard/Widgets/{PieChart,
MonitorLineChart}.ctp`, `app/webroot/js/dashboard/charts/monitor-chart.mjs`.
Edited (core, signed off): `charts.module.mjs` (pie builder + monitor
dispatch/teardown), `render-thumbs.mjs` (two glyphs). Auto-discovered
(`loadAllWidgets` scans `app/Lib/Dashboard/`); `checkPermissions` hides them
from non-admin galleries — no registry/ACL change.

**Verified.** `php -l` + `node --check` clean across the set; REST `exportjson`
returns live samples (disk: two polls show different free-bytes ⇒ uncached;
CPU normalized %; memory used %); wrapped envelopes dispatch
`renderer=PieChart`/`MonitorLineChart`; standalone `.ctp` renders emit the
right `data-misp-chart` payloads (incl. `yMax:null` auto-scale + empty/error
states). The in-browser accumulation / pause-on-hidden behaviour is the
user's to eyeball (no headless browser on the box; prior sessions deferred
gold-standard browser checks likewise). Additive; reversible. Implemented one
widget at a time (disk → CPU → memory), commit per task.

## DD-30 — Server-side Redis history for the monitor line widgets (refines DD-29's client-only buffer)

**Date.** 2026-05-27
**Phase context.** DD-29 accumulated the CPU/memory series **client-side only**
(in the chart's JS closure), so a page reload or a manual refresh started the
graph empty. The user asked to persist samples and "pre-populate the graph with
each call to the widget backend code with whatever is in Redis".

**Decision.** Move the rolling buffer **server-side into Redis**; the client
stops owning a buffer and simply renders whatever series the handler returns.
The in-place streaming (DD-29) is kept — no flicker — but it now repaints a
persisted series, so reload / manual refresh / a second viewing admin all show
the **same accumulated history**. (Considered + rejected the simpler "switch to
the standard scheduler redraw" alternative: it would delete `monitor-chart.mjs`
but re-init the chart every 10s, a visible flicker. User picked the in-place +
Redis option.)

**Mechanism.** New `app/Lib/Dashboard/Tools/MonitorSeriesStore::record($metric,
$value, $window, $interval)`:
- One **sorted set per metric** (`misp:dashboard_monitor:<metric>`), score =
  unix ts, member = `"<ts>:<value>"`. `zAdd` the current sample,
  `zRemRangeByScore` everything older than the window, `expire` the key at
  `window + interval` (idle metrics self-clean — no sampling happens while no
  dashboard polls), `zRangeByScore … WITHSCORES` to return the ordered series
  as `[[ts, value], …]`.
- **Cross-viewer dedup**: skip the `zAdd` when the newest sample is younger than
  `floor(interval/2)`s, so several admins polling the same global metric don't
  over-densify the series.
- **Redis-down**: returns a single-point series (the current sample) so the
  widget still renders. Reuses `RedisTool::init()` (DB 13) like `WidgetCache`.

**Data-contract change.** `CpuLoadMonitorWidget`/`MemoryUsageMonitorWidget`
`handler()` now `record()` the sample and return **`history`** (the full series)
instead of a single `value`. `MonitorLineChart.ctp` carries `history` in the
payload (+ `interval_sec` for the poll cadence; the window is enforced
server-side now). `monitor-chart.mjs` drops its client buffer/trim logic for a
`render(history)` that maps `[[ts,value],…]` → labels (formatted from the
**server** ts, so labels are stable across reloads) + values, and `setOption`s
in place; it seeds from `payload.history` and repaints from `data.history` on
each poll. The disk pie is unaffected (a snapshot — no history).

**Scope note.** The key is **global per metric**, not per-user: CPU/memory are
host-wide facts, identical for every admin, so a shared series is correct (and
these widgets are site-admin-gated anyway).

**Verified (shell, bypassing HTTP/auth — authoritative for the store).** 4 CPU
polls ~2s apart grew `history` `1→2→3→4` with live-drifting values; memory a
separate key (`83.83%`, matching a direct `/proc/meminfo` cross-check); two
immediate re-polls within the dedup gap left the length unchanged (5→5); the
Redis sorted set held ordered `ts:value` members with `TTL=62`s (window 60 +
interval 2). `php -l` + `node --check` clean. (An unrelated dev-box API-key auth
hiccup blocked the curl/HTTP path mid-session; it does not affect the
session-cookie browser path the board actually uses, and the widget code runs
only after auth.) Additive; reversible. Supersedes DD-29's client-only-buffer
aspect (DD-29's in-place rendering + exportjson poll stand).

## DD-31 — `StatGrid` render kind: KPI metric cards for key/value admin widgets

**Date.** 2026-05-27
**Phase context.** Post-5.5 "rework the key/value admin widgets into something
more visually pleasing." The user nominated the **Usage data** widget
(`UsageDataWidget`, `$render='SimpleList'`) as the first to convert, with the
intent to reuse the result across the other key/value admin widgets
(`MispStatusWidget`, the resource widgets, …).

**Decision.** A **new render kind `StatGrid`** rather than restyling
`SimpleList` in place — `SimpleList` is used by ~12 widgets, so a global
restyle would be a wide blast radius for a request scoped to a few admin
widgets. `StatGrid` lays each datum out as a **metric card**: small uppercase
muted label, large prominent value, optional coloured delta badge (`▲` success
/ `▼` danger). Cards sit in a responsive
`grid-template-columns: repeat(auto-fill, minmax(120px, 1fr))` — one column
when the widget is narrow, more as it widens, so it scales with v2's resize.

**Treatment fork (surfaced via `AskUserQuestion` previews).** Two directions
were offered: **(A) KPI card grid** (raised bordered cards, airy, scales to
width) and **(B) compact stat rows** (denser single column, big right-aligned
number, better at the narrow default slot). **User picked A.**

**Same data contract as `SimpleList`** — by design, so any key/value widget can
switch render kinds with no `handler()` change. `StatGrid.ctp` honours
`title` / `value` / `change` / `drilldown` (whole card becomes a
`DashboardURLValidator`-gated link, DD-03) / `html_title` (raw label) /
`type:gap` (→ full-width section break, its `title` labels it) / legacy `html`
(→ muted footer line). Value formatting added on top of SimpleList's raw echo:
integers grouped (`48901 → 48,901`), non-integer numerics keep one decimal
(`4.5`), integer-valued floats drop it (`38.0 → 38`), and pre-formatted strings
(`"96 (68 %)"`, `"N/A"`) pass through untouched (`is_numeric` gate). `change`
is rendered `number_format`-ed with an arrow whose colour/direction follows its
sign (the Usage widget's `change` is a this-month/range growth count, so always
the success `▲` in practice — the `▼` path is there for reuse).

**Styling.** Token-driven `.misp-stat-*` block in `dashboard.default.css`
only — no hardcoded colours, no inline styles — so the midnight theme (which
overrides `--misp-dash-*` tokens and nothing else; 0 component selectors)
retones it for free, same posture as every other renderer.

**Glyph (CLAUDE.md render-kind rule).** `thumbStatGrid()` added to
`render-thumbs.mjs` (a 2×2 grid of cards, each with a short "value" bar) and
registered under `StatGrid`, so gallery cards for `StatGrid` widgets get a
shape-evoking thumbnail rather than `thumbGeneric`.

**Widget flip + footprint.** `UsageDataWidget::$render` `SimpleList → StatGrid`;
default size widened `2×5 → 4×6` so the cards lay out ~2-up at the default
placement (matching the approved preview). No `handler()` / data change.

**Verified.** Live session render (cookie auth, the path the board uses):
`POST /dashboards/renderWidget/teststat1` (`widget=UsageDataWidget`) → HTTP 200,
all 14 cards, well-formed markup, `"0 (0 %)"` string value preserved (the dev
instance is quiet → mostly zeros, no deltas live). The format + delta branches
(thousands grouping, 1-decimal, string pass-through, `▲37`/`▼3`/`▲1,500`, no
badge on `0`) were unit-checked standalone in PHP. `php -l` (`.ctp` +
`UsageDataWidget`) and `node --check` (`render-thumbs.mjs`) clean. Pure
addition; reverse by flipping `$render` (+ size) back — `SimpleList` untouched.

## DD-32 — StatGrid card labels become per-metric glyphs + a title tooltip (refines DD-31)

**Date.** 2026-05-27
**Phase context.** First in-browser feedback on DD-31: in the narrow default
card the text label (e.g. "Attributes / event") truncates with an ellipsis, so
you can't tell what a card is. User asked to **replace the text label with a
per-card glyph and move the field name into a hover tooltip**.

**Decision.** StatGrid's contract gains an optional `icon` key (a *named*
glyph). When it resolves, the card renders that glyph in place of the text
label and the full `title` text moves to the card's `title=` attribute (native
hover tooltip + accessible name). A row without a resolvable `icon` keeps the
text label — StatGrid stays a drop-in for icon-less widgets. `UsageDataWidget`
names a glyph per metric (calendar=Events, tag=Attributes, layers=Attributes/
event, link=Correlations, pencil=Proposals, user=Users, key=PGP, building=Orgs,
home=Local orgs, sitemap=Creator orgs, users=Avg users/org, chat=Threads,
chat-lines=Posts, shield=Authkeys).

**Icon format — inline SVG, NOT FontAwesome (the load-bearing finding).** The
dashboard layouts load **different FA majors per theme**: the base and UiBeta
layouts pull `font-awesome` (FA5/6), but **Overmind** (the live instance's
theme) pulls `fontawesome7.min`. FA class-name conventions differ across those
majors, so an `<i class="fa …">` would render the wrong icon — or nothing —
depending on the active theme. Inline SVG with `currentColor` is theme-
independent (it inherits the token-driven colour), matching the dashboard
chrome and `empty_state.ctp`. So the glyphs live in a new
`app/Lib/Dashboard/Tools/StatGlyph::get($name)` returning a wrapped inline SVG
(0 0 24 24 viewBox, `currentColor`, `aria-hidden`) or `''` for an unknown name
(→ label fallback). New `.misp-stat-glyph` CSS: muted by default, accent on
card hover. (FontAwesome was the obvious first instinct — rejected once the
per-theme version skew surfaced; recorded so the next icon need doesn't
re-discover it.)

**Verified.** Purged the 1h `WidgetCache` key (the icon-less payload was cached
from DD-31's render), re-rendered live: 14 cards, 14 glyph SVGs, each card
carries `title="<field name>"`; deltas now render live (`▲3` on the discussion
metrics). All 14 glyphs **rasterised to a montage PNG and eye-checked** —
recognisable, consistent stroke. `php -l` clean (`StatGlyph` + `.ctp` +
`UsageDataWidget`). Additive; reverse by dropping the `icon` keys (labels
return). Refines DD-31's label rendering; the rest of DD-31 stands.

## DD-33 — `NetworkGraph` render kind: sync-test widget as a hub-and-spoke diagram

**Date.** 2026-05-27
**Phase context.** User: rework `MispAdminSyncTestWidget` (a flat
colour-coded `SimpleList`) into a **network diagram** — current instance as
the root, each connected sync server a node coloured by its live
connection-test outcome, hover a node for its URL + the test result (where an
admin reads the reason for an outage).

**Decision.** New **`NetworkGraph`** render kind backed by ECharts' `graph`
series. `MispAdminSyncTestWidget::$render` flips to it and its `handler()`
reshapes the same `runConnectionTest()` loop into `{nodes, links}`: a `self`
hub node (current instance, from `MISP.baseurl`/`MISP.org`) plus one node per
sync server, each carrying `status`, `url`, `message`; links are `self →
server`. The renderer is generic (any `{nodes, links}` graph), reused by the
sync widget first.

**Node states — kept the existing THREE, not two (fork surfaced).** The user
phrased it "green or red", but the old widget already distinguished a third
state, and that signal is worth keeping: `ok` green (connected, full access),
`warn` amber (reachable but missing sync/sighting/analyst-data permission —
the message spells out which), `error` red (unreachable/failed,
`syncTestErrorCodes[status]`); the hub is `self` (accent). User chose to keep
all three. Colours come from semantic theme tokens (`--misp-dash-success` /
`-warning` / `-danger` / `-accent`) so themes retone the graph.

**Layout — fixed hub-and-spoke, not force-directed.** `layout:'none'` with the
hub at centre and spokes placed on a ring (computed in `buildNetworkOption`),
so positions are deterministic and don't reshuffle between renders. Links use
node **indices** (not names) so duplicate/empty server names can't break edge
matching. ECharts fits the node-centre bbox nearly to the series rect, so the
`left/right/top/bottom` margins are deliberately generous (20/20/16/22%) to
leave room for the symbol radius + the `bottom`-positioned labels (a tighter
margin clipped the bottom node's label — caught in a headless screenshot).
`roam:true` lets an admin pan/zoom for dense topologies. Tooltip formatter
emits `name / url / message` per node.

**Bundle rebuild (the tree-shaking sibling rule).** `graph` is a new ECharts
series type → **`GraphChart` added to the vendored bundle's `use([...])` and
rebuilt** (echarts@6.0.0 + esbuild@0.24.0, the reusable `/tmp/echarts-bundle`;
666→702 KB raw / 221→239 KB gz), else a `type:'graph'` series renders nothing
(memory `project_misp_echarts_bundle_treeshaken`; same gotcha as PieChart in
DD-29). VENDORING.md table + recipe updated. New `NetworkGraph` glyph
(`thumbNetworkGraph`, a hub + 3 spokes) registered per the CLAUDE.md render-kind
rule.

**Cost note.** `runConnectionTest()` hits every sync server over the network on
each render, so **`autoRefreshDelay=false`** — the board scheduler must not
re-probe on a timer; the admin refreshes manually. Default size `3×2 → 4×5`
(roughly square so a full ring + labels fit).

**Verified.** Live session render → HTTP 200, `{nodes, links}` payload with the
`self` hub + 6 sync-server leaves (1 green `ok`, the rest red `error` —
"Authentication failed" on the dev box's test servers; no `warn` present in
this data). **Rendered client-side via headless Chrome over HTTP** (ESM modules
don't load over `file://`) → the hub-and-spoke graph draws with the rebuilt
bundle, colours + edges + labels correct, all 7 nodes fit after the margin
bump. `php -l` (`.ctp` + widget) + `node --check` (`charts.module.mjs` +
bundle + `render-thumbs.mjs`) clean. Additive; reverse by flipping `$render`
back to `SimpleList` (the bundle keeps `GraphChart`, harmless).

**Node styling (follow-up, same session).** The first cut drew nodes as plain
status-coloured ellipses; user asked for something more pleasing — "coloured
server icons". Nodes are now **server-rack glyphs** (a 2-unit rack with white
LEDs + vent bars) filled in the status colour, set as ECharts `image://` SVG
data-URI symbols (`serverSymbol(colour)`, base64-encoded). Chosen over a
`path://` symbol because `path://` fills a single shape one colour (no white
LED/vent detail without even-odd hole trickery); an `image://` data-URI carries
the full two-tone SVG. Theme-awareness is preserved because the symbol is built
at render time from the resolved `--misp-dash-*` token value (only 4 distinct
colours → 4 symbols, reused). `itemStyle` node fill dropped (the image owns its
colours); `symbolKeepAspect:true`; hub 44px / leaves 32px. Verified via the
same headless-Chrome render: blue hub + green/red server icons, edges + labels
intact.
