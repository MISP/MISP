# Dashboard v2 — Product Requirements Document

**Status:** Draft v0.1 (exploration + scoping; not yet approved)
**Author:** Andras Iklody + Claude
**Target branch:** `dashboards` (current)
**Supersedes:** the legacy Dashboard system — see §6 for the inventory.
**Implementation tracker:** [`dashboard-progress.md`](dashboard-progress.md) — checkbox list, one task ticked at a time. Live state of the project lives there, not in conversation context.
**Design-decision log:** [`dashboard-design-decisions.md`](dashboard-design-decisions.md) — created on first cross-phase decision worth recording. Absent if not yet needed.

## How to read these docs (session continuity)

The user runs this project in **alternating hitm and afk modes** and
will routinely **start fresh sessions** to control context creep. As
a consequence:

- Anything a future session needs to resume work lives in **this
  PRD plus `dashboard-progress.md`**, never in conversation context.
- `dashboard-progress.md` is the source of truth for *what's done /
  what's next / what's blocked*. The PRD is the spec; the progress
  file is the state.
- Implementation runs **strictly sequentially** — one task at a
  time, top to bottom of the progress file. Phases do not
  parallelise. (Research lookups during a task may parallelise; code
  writing does not.)
- Other planning docs in this directory are prefixed `dashboard-`
  (e.g. `dashboard-design-decisions.md`) so they don't collide with
  parallel projects.
- A fresh session should read, in order:
  1. This file's §§1–14 for scope, requirements, and architecture.
  2. `dashboard-progress.md` for state.
  3. `dashboard-design-decisions.md` (if present) for binding
     library/schema/URL/token decisions.
  4. Then act — pick up the next unchecked task.

## Local test instance

A live MISP instance running directly off this codebase
(`/var/www/MISP7`) is available at:

- **URL:** `http://localhost:5007`
- **Admin API key:** `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
  (test instance only, the user has confirmed it's safe to record here)

This means changes you make to the working tree are visible in the
running instance immediately — no separate deploy step. Use it
during Phase 0/1/2/3 development to:

- Verify that a v1 dashboard layout still renders correctly (open
  `/dashboards` in a browser before touching code; capture the
  baseline).
- Iterate on the new frame visually as you build it.
- Smoke-test widget-parity and surface-parity items in Phase 5.5
  by hitting the URLs directly.
- Drive REST checks (admin API key above) for the new
  `GET /dashboards/widgets` endpoint and the existing import /
  export / template endpoints.

If a v1-shape `UserSetting:dashboard` row needs seeding for testing
the per-widget on-read fix-ups (Phase 1), you can construct one via
`/dashboards/import` with a hand-crafted bare-array JSON.

---

## 1. Context and problem

MISP has had a per-user, widget-based dashboard for several years. The data
layer (the `*Widget.php` classes, ~35 of them) has been extended steadily and
covers a lot of useful ground: MISP status/notifications, trending tags,
sightings, MITRE ATT&CK heatmap, organisation maps, contributor toplists,
worker/system health, COVID widgets (legacy), etc.

The *layout, framing, and authoring UX* around these widgets has aged badly:

- The page is a single flat Gridstack canvas with a hardcoded blue 1px border
  per widget, no spacing system, no responsive breakpoints, no theme-awareness
  (still Bootstrap 2.3.2 styling baked into widget templates).
- Adding a widget is a select-dropdown + raw JSON config textarea in a modal.
  No previews, no schema-driven form, no live update — the user has to
  hand-craft a JSON blob from a `$placeholder` string.
- Per-user state is auto-saved on every drag/resize/edit with no
  undo / discard / reset-to-default surface, and a `console.log(...)` is still
  shipped in `saveDashboardState`.
- Auto-refresh is per-widget `setTimeout` with no global pause, no shared
  filter scope (every widget self-fetches; there is no dashboard-level "this
  pane is scoped to org X over the last 30 days").
- Only one dashboard per user. No tabs, no per-purpose boards (e.g.
  "ops console", "intake triage", "exec overview").
- Drill-down from a widget into a filtered events/attributes index is
  hand-coded inside individual widgets (some widgets have a hardcoded
  `(View)` link, most don't).
- Mid-rework artefacts already in the tree (`gridstack.all.js.bk`,
  `gridstack.min.css.bk`) suggest a previous partial attempt; we want to land
  this cleanly.

The user's stated goal: **keep most of the widget *content* (the `handler()`
data layer), replace the surrounding *frame* — layout, theming, authoring UX,
and per-user / per-template management.**

## 2. Goals / non-goals

### Goals

- **G1.** A modern, theme-native dashboard frame with consistent typography,
  spacing, and colour use across both the default Bootstrap 2.3.2 theme and
  Overmind / UiBeta. Look and feel should be the strongest reason a user
  visits the dashboard rather than going straight to the events index.
- ~~**G2.** Multiple named dashboards per user~~ — **dropped.** User
  decision (2026-05-04): keep persistence as-is (one
  `UserSetting:dashboard` blob per user). The "edit mode vs. view mode"
  separation and atomic save survive — they're not multi-board features.
- **G3.** Schema-driven widget configuration: each widget declares its
  parameters (type, default, enum values, help text); the add/edit form is
  generated from that schema with live preview, instead of the current free-
  form JSON textarea.
- **G4.** **Dashboard-level filter toolbar (bulk edit).** A
  lightweight, persistent toolbar at the top of the dashboard exposes
  controls for the canonical filter parameters defined in G13 (time
  window, tag filter, producer org, galaxy clusters, etc.). The
  toolbar is a **bulk-edit UI**: pulling a control walks every widget
  on the dashboard that declares the matching canonical type in
  `$schema` and writes the new value into each widget's saved config.
  Per-widget configs are the only source of truth — there is no
  separate "scope" persistence or inherit/pinned state. Widgets that
  don't declare a given canonical type simply aren't reached by the
  corresponding toolbar control (graceful no-op for system-resource
  and similar widgets). Toolbar pulls write immediately and persist
  in `UserSetting:dashboard`; edit mode is reserved for layout /
  structural changes only. See `dashboard-design-decisions.md` DD-05.
- **G5.** Drill-down by default: every widget cell that represents a count or
  category gets a click target that navigates to the equivalent filtered
  events / attributes / sightings view. This is implemented at the renderer
  layer, not per widget.
- **G6.** Keep the existing widget data contract (`handler($user, $options)`
  returning structured arrays) so the existing `*Widget.php` classes work
  with minimal migration. Widgets opt in to v2 features (schema, drill-down
  hints, scope awareness) by adding new optional properties.
- **G7.** Full REST exposure: list available widgets, list a user's boards,
  CRUD a board, render a widget. (Today only render + update-settings +
  template CRUD exist, with mixed REST coverage.)
- **G8.** Templates v2: site admin / org admin can curate a board template
  catalogue with previews, restricted to org / role / permission flags as
  today, but presented as a "gallery" rather than a list.
- **G9.** Accessibility: keyboard-reachable add/move/remove/configure;
  visible focus; semantic landmarks; respects prefers-reduced-motion.
- **G10.** Consolidate the chart stack onto **Apache ECharts** as the single
  charting library, replacing the current mix (D3 v3-era, jvectormap,
  Chart.js, hand-rolled HTML bars). Gives us one theme system, one set of
  interaction primitives (zoom, brush, tooltip), built-in geo maps, and a
  smaller net JS payload than the status quo. Renderers (`BarChart`,
  `MultiLineChart`, `WorldMap`, future heatmap/treemap/sankey) all become
  thin shims over ECharts options objects.
- **G11.** First-class compatibility with MISP's `app/View/Themed/`
  override system across the full intensity spectrum: from
  **CSS-only overlay** themes (no `.ctp` overrides — just a stylesheet
  swap) to **full conversion** themes (Overmind-style, replacing layout,
  generic elements, even individual widget renderers). Concretely:
  - Every styling decision (colour, spacing, border, radius, shadow,
    typography) is expressed through **design tokens** as CSS custom
    properties; the default theme defines them, light themes only
    redefine them, heavy themes can additionally override `.ctp`s.
  - **No inline styles, no hardcoded colour classes** (`class="blue"`,
    `style="border: 1px solid #0088cc;"`) in any v2 dashboard view file.
    Markup uses stable, namespaced BEM-ish class names that themes
    consume as hooks.
  - The dashboard view tree is decomposed into **small, single-purpose
    `.ctp` files** mirroring the override surface — a heavy theme should
    be able to swap just the widget wrapper, just the empty-state, or
    just the toolbar without copy-pasting the whole page.
  - ECharts integration reads its colour palette from the active design
    tokens (via `getComputedStyle(document.documentElement)`) so charts
    inherit the theme automatically. Themes can additionally register
    their own named ECharts theme JSON via the existing `assetLoader`
    pattern for full restyling without touching widget code.
- ~~**G12.** Persistence and sharing rework~~ — **dropped.** User
  decision (2026-05-04): reuse the existing persistence and sharing
  surface verbatim — the per-user `UserSetting:dashboard` blob and the
  `dashboards` template table with its `restrict_to_*` flags. v2 only
  *extends* the blob shape (additive: `{scope, widgets}` replaces a
  bare `[widgets]` array, with backward-compat read of the legacy
  shape) and *improves the gallery presentation* of the existing
  templates table — no schema changes, no clone/fork/publish
  lifecycle, no sharing-tier work, no soft-delete.
- **G13.** **Harmonised widget configuration.** Today every widget
  invents its own config key shape: `time_window: "7d"` (TrendingTags),
  `start_date / end_date` (UsageData), free-form mixed with widget-only
  knobs. v2 introduces a small **canonical parameter type catalogue**
  (`time_window`, `tag_filter`, `org_filter`, `sharing_group_filter`,
  `galaxy_cluster_filter`, `distribution_filter`,
  `threat_level_filter`, `analysis_filter`) with stable JSON shapes.
  Widgets opt into these types by name in their `$schema` rather than
  hand-rolling validators. Benefits: schema-driven configure forms get
  rich pickers (taxonomy-aware tag selector, org typeahead, galaxy
  cluster picker) for free; the board toolbar (G4) can address the
  whole catalogue uniformly; widgets not concerned with a given filter
  simply omit it from `$schema` and silently ignore board-level values.

### Non-goals (v1 of this rework)

- **No new widgets** added as part of this PRD. Widget *content* is out of
  scope; widgets are imported from the existing tree. New widgets are a
  follow-up project.
- **No persistence rework.** The `UserSetting:dashboard` blob and the
  `dashboards` template table stay as-is; v2 only extends the blob's
  internal JSON shape (additive, with backward-compat read of the
  legacy bare-array form). No new tables, no schema changes, no
  migration shells.
- **No real-time push / WebSocket-driven widgets.** Refresh remains
  poll-based; the only change is moving polling under a shared scheduler.
- **No cross-user / shared live dashboards** (presence cursors, etc.).
  Templates remain the sharing primitive.
- **No mobile-first redesign.** Responsive breakpoints down to tablet width
  are in scope; phone-sized layouts are explicitly deferred.
- **Gridstack is replaced** entirely. The new stack is **CSS Grid**
  for layout + **Pragmatic Drag and Drop** (Atlassian, Apache 2.0)
  for gestures, with snap / collision / resize-cascade as custom code
  we own (~200–400 lines, vendored at `webroot/js/dashboard-v2/grid/`).
  Decision recorded in `dashboard-design-decisions.md` DD-01.
- **No widget marketplace / signed widget bundles.** The `Custom/` drop-in
  pattern stays; we don't introduce a packaging or signing story.

## 3. Personas and key user journeys

### Personas

- **Operator / analyst** — logs in daily, wants a personalised at-a-glance
  view of what changed since they were last here, plus pinned shortcuts.
- **Org admin** — curates a "shared" board template their org's users can
  adopt as a starting point (e.g. "intake triage", "weekly review").
- **Site admin** — sets the default board for new users; manages cache /
  performance characteristics; can scope templates to roles or permission
  flags.
- **Widget author** — writes a `*Widget.php` against the data-layer contract,
  picks a renderer, optionally declares a parameter schema and a drill-down
  template.

### Journeys

**J1 — Returning analyst.** Logs in, lands on their dashboard. The
toolbar at the top shows the active filter scope (e.g. "last 7 days,
tags: tlp:amber+", "all orgs"). Each widget shows a "last updated N
seconds ago" tag and a refresh control. They drag the time-window
slider to "last 24h" — every widget that opted into `time_window`
re-renders in place; the system-resource widget (which doesn't declare
`time_window`) is unaffected. They click a tag count in TrendingTags →
land on the events index pre-filtered to that tag and the active
toolbar window.

**J2 — Reshaping the dashboard.** Click *Edit*. Layout chrome
appears (drag handles, resize grips, remove/configure on each
widget); a toolbar shows *Add widget*, *Save*, *Discard*. Add widget
opens a *gallery* — thumbnails grouped by category (status, events,
tagging, organisations, system) — pick one, get a schema-driven form
with sensible defaults and a live preview pane in a side panel. Save
adds it. When done editing, click *Save*: layout + per-widget configs
+ toolbar scope are persisted as one atomic write to
`UserSetting:dashboard`. *Discard* reverts.

**J3 — Org admin shares a template.** Builds a dashboard they like,
clicks "Save as template", picks "selectable by my org", names +
describes it. Others in the org see it in the gallery on "Reset from
template" with a preview. (The existing `dashboards` table semantics
are preserved verbatim; only the gallery presentation changes.)

**J4 — Site admin sets the default.** From the template gallery,
marks a template as default. New users get this template's layout as
their starting `UserSetting:dashboard` blob, instead of the hardcoded
MispStatusWidget fallback.

**J5 — Widget author adds a v2-aware widget.** Writes a class with
`handler()` plus a `$schema` array (parameter names → type/default/enum/help)
and a `$drilldown` callback returning a URL given `(user, options, datum)`.
Drops it in `app/Lib/Dashboard/Custom/`. It appears in the gallery with
schema-driven config and click-through drill-down.

## 4. Terminology

- **Dashboard** — the user's single, persisted layout: an ordered set
  of widget instances + a scope. Stored in `UserSetting:dashboard`,
  one per user (unchanged from today). The "v2" rework changes how
  it looks and how it's authored, not how many of them a user has.
- **Widget class** — a `*Widget.php` PHP class under `app/Lib/Dashboard/`
  (or `Custom/`) implementing the data contract. Unchanged concept.
- **Widget instance** — a placement of a widget class on the dashboard,
  with its position (x,y,w,h), parameter values, and optional alias.
- **Renderer** — a view template under `app/View/Elements/dashboard/Widgets/`
  that turns a widget's `handler()` output into HTML/SVG. Today: `SimpleList`,
  `BarChart`, `MultiLineChart`, `WorldMap`, `Index`, `OrgsPictures`,
  `Achievements`, `Attack`, `Button`, `Array`.
- **Template** — a layout saved to the existing `dashboards` table,
  optionally marked default and/or restricted to org/role/permission.
  Concept and storage are unchanged from today; v2 reworks the
  *presentation* (gallery + thumbnails) only.
- **Canonical parameter type** (new) — a named parameter shape from the
  fixed catalogue (§5.5) that widgets declare in `$schema`. Stable JSON
  representation, identical across widgets. Examples: `time_window`,
  `tag_filter`, `org_filter`. The toolbar (G4) addresses widgets via
  these declarations.
- **Edit mode / view mode** (new) — dashboard state for **layout /
  structural** edits (drag, resize, add, remove). Configure-form and
  toolbar changes are *not* gated by edit mode; they write immediately
  on save and on pull respectively (see DD-05). Edit mode is
  specifically for "I'm rearranging the dashboard now" workflows.

## 5. Functional requirements

### 5.1 The dashboard

One dashboard per user, persisted in `UserSetting:dashboard` (unchanged
from today). The blob is a bare array of widget instance objects, same
top-level shape as today:

```
[
  { "instance_id": "...", "widget": "...", "config": {...}, "position": {...}, ... },
  ...
]
```

The only on-read evolution is per-widget housekeeping: rename
`width/height → w/h` and mint an `instance_id` for any widget that
lacks one (both required by Pragmatic DnD's grid math per DD-01).
Promotion happens lazily — first save after upgrade writes the
canonical form back. **No `{scope, widgets}` envelope, no separate
`scope` persistence** (per DD-05).

- **F1.1** First-login behaviour: if no `UserSetting:dashboard` exists,
  load the default template from the `dashboards` table (`default = 1`);
  otherwise fall back to a hardcoded layout containing one
  `MispStatusWidget`. (Today's behaviour, preserved.)
- **F1.2** **Edit mode** is for layout / structural changes only —
  drag, resize, add widget, remove widget. Save / Discard show only in
  edit mode and apply only to layout changes. Auto-save-on-every-drag
  is gone (with the v1 `console.log`).
- **F1.3** **Configure-form changes save per-form.** Opening a widget's
  configure form, editing fields, clicking Save persists *that widget's*
  config to `UserSetting:dashboard` immediately. No global edit mode
  required.
- **F1.4** **Toolbar pulls save immediately** (see §5.6 / DD-05). No
  edit mode required; pulls bulk-edit applicable widgets' configs and
  persist on the same write.
- **F1.5** **Reset from template.** From the template gallery (§5.4),
  the user can replace their current `UserSetting:dashboard` blob with
  the JSON from a chosen template. Confirmation prompt if the user has
  unsaved layout edits.
- **F1.6** **Save as template.** Promotes the current dashboard
  into a new row in the `dashboards` table. Existing
  `restrict_to_org_id / role_id / permission_flag` semantics are
  preserved verbatim — admin curation, not peer-to-peer sharing.
- **F1.7** Import / export of the dashboard blob (JSON), preserving
  the existing endpoints' behaviour.

### 5.2 Widget instances

- **F2.1** Drag, resize, remove, configure — same primitives as today but
  staged (only persisted on Save).
- **F2.2** Configure form is generated from the widget's `$schema` (see §5.5).
  No raw JSON unless `$schema` is missing — in which case the legacy free-form
  textarea is shown as a fallback so existing custom widgets keep working.
- **F2.3** Live preview: the configure form has a preview pane that re-runs
  `renderWidget` on debounced input changes.
- **F2.4** Per-instance alias (already supported) survives unchanged.
- **F2.5** Per-instance refresh interval override, on top of the widget's
  `$autoRefreshDelay` default. UI in the configure form.
- **F2.6** Drill-down: the renderer wraps clickable elements with a link
  derived from `$drilldown` (when defined on the widget class) or from a
  per-renderer convention (e.g. BarChart auto-links bar labels through a
  user-supplied URL template). Clicks open the linked page; modifier-clicks
  open in a new tab.

### 5.3 Refresh and caching

- **F3.1** A single, board-level scheduler runs widget refreshes. Replaces
  N independent `setTimeout` chains.
- **F3.2** A "pause refresh" toggle on the board toolbar halts all timers.
- **F3.3** Per-widget Redis cache (today's `$cacheLifetime` mechanism) is
  preserved. Cache key continues to include user-or-orgScope and a hash of
  widget+config; v2 additionally folds in a hash of the active board scope
  so scope-aware widgets don't cross-pollute.
- **F3.4** Manual refresh on a single widget remains available.

### 5.4 Templates and gallery

- **F4.1** The "+ New board" entry opens a gallery showing all templates
  the user is eligible for (today's restrict_to_org / role /
  permission_flag rules, plus selectable=1).
- **F4.2** Each template card shows a preview screenshot or a rendered
  miniature, name, description, author org, and a "use this" action.
- **F4.3** Saving a board as template carries today's restriction options
  (org / role / permission flag / default). Site admin can mark a template
  as the global default — at most one.
- **F4.4** Templates remain identified by UUID and exportable / importable
  as JSON (today's import/export endpoints are reworked to round-trip with
  the new layout schema).

### 5.5 Canonical parameter type catalogue (G13)

A widget's `$schema` declares each parameter with a `type`. v2 ships a
fixed catalogue of canonical types whose JSON shape is stable across
widgets. This is the contract that makes the toolbar (§5.6) and the
schema-driven configure form (§5.2 F2.2) work.

| Canonical type | JSON shape | Toolbar-eligible | Notes |
|---|---|---|---|
| `time_window` | `{ kind: "rolling", duration: "<ISO8601>" }` or `{ kind: "absolute", from: "<ISO date>", to: "<ISO date>"|null }` | yes | Replaces today's mix of `time_window: "7d"`, `start_date/end_date`, raw integer seconds. `kind: "rolling"` accepts ISO durations (`P7D`, `P1M`) and the legacy `7d`/`30d`/`-1` shorthands for back-compat. |
| `tag_filter` | `{ include: string[], exclude: string[], taxonomies?: string[], match_event_tags?: bool, match_attribute_tags?: bool }` | yes | Strings are tag-name expressions (full match) or substrings (`tlp:` prefix). Taxonomy restriction lets the picker suggest only relevant tags. |
| `org_filter` | `{ orgs: { uuid?: string, id?: int, name?: string }[], role: "creator"|"distribution"|"any" }` | yes | `role` lets a widget say *which* org relationship it filters on — TrendingTags filters by orgc, OrgsContributorLastMonth filters by anyone touching the event. |
| `sharing_group_filter` | `{ sharing_group_ids: int[] }` | yes | Single shape across all widgets. |
| `galaxy_cluster_filter` | `{ clusters: { uuid?: string, tag_name?: string }[], galaxy_types?: string[] }` | yes | Cluster picker scopable by galaxy type (e.g. only `mitre-attack-pattern`). |
| `distribution_filter` | `{ levels: int[] }` (subset of `0..4`) | yes | |
| `threat_level_filter` | `{ levels: int[] }` (subset of `1..4`) | yes | |
| `analysis_filter` | `{ levels: int[] }` (subset of `0..2`) | yes | |
| `attribute_type_filter` | `{ types: string[], categories?: string[] }` | no | Widget-only; doesn't make sense at board level. |
| `event_id_filter` | `{ event_ids: int[]|"current" }` | no | Widget-only. |
| `string`, `int`, `bool`, `enum` | scalar | no | Free-form widget knobs (`threshold`, `over_time`, etc.). |

**Toolbar reachability (G4 bulk-edit toolbar).** Per DD-05, the
toolbar's relationship with widgets is binary:

- **Widget declares canonical type X in `$schema`** → toolbar control
  for X reaches this widget. Pulling the control writes the new value
  to this widget's `config[X]`.
- **Widget does not declare X** → toolbar control for X never touches
  this widget. Widget continues with whatever its `config` says (or
  its hardcoded default).

There is no inherit/pinned per-widget state, no `BoardScopeHelper`
inheritance resolution, no scope persistence layer. Widget classes
read their own `$options` exactly as today; the toolbar's effect is
realised by having already written to those configs.

### 5.6 Dashboard toolbar (G4 bulk edit)

- **F5.6.1** The toolbar exposes a control per canonical type that is
  declared by at least one widget on the dashboard. Unused canonical
  types are not shown — keeps the toolbar lightweight.
- **F5.6.2** **Computed display state.** Each toolbar control's value
  is computed at render time from the widgets that declare its
  canonical type:
  - all applicable widgets agree on a value → control shows that value;
  - values disagree → control shows a "(mixed)" indicator;
  - no applicable widgets on the dashboard → control is hidden.
- **F5.6.3** **Pulling writes immediately, in any mode.** A toolbar
  pull walks every widget that declares the matching canonical type,
  writes the new value into each widget's `config[<canonical_type>]`,
  saves the whole `UserSetting:dashboard` blob, and re-renders the
  affected widgets (debounced ~250ms). No edit mode required (per Q11
  resolution); toolbar pulls are functionally equivalent to opening
  every applicable widget's configure form and changing the value
  one by one.
- **F5.6.4** **New widgets inherit the current toolbar display.** When
  a widget is added to the dashboard and declares a canonical type
  for which the toolbar currently shows a non-mixed value, the new
  widget's `config[<canonical_type>]` initialises to that value. Avoids
  the "I just added a widget and it's showing 'all time' while the
  rest are showing 'last 7 days'" surprise.
- **F5.6.5** A **"Clear"** action per toolbar control unsets that
  canonical-typed value across all applicable widgets — equivalent
  to entering each widget's configure form and removing the field.
  Clearing makes the affected widgets fall back to their hardcoded
  default for that param.
- **F5.6.6** The toolbar is keyboard-reachable, collapsible to a single
  row, and mirrors the design tokens of the active theme (G11).

### 5.7 Widget contract

The existing contract is preserved and extended with optional properties.
A v1 widget keeps working as-is; opting in unlocks v2 features.

Existing (kept):
- `$title`, `$description`, `$render`, `$width`, `$height`,
  `$placeholder`, `$cacheLifetime`, `$autoRefreshDelay`, `$params`
  (an associative array of `param => help_text`).
- `handler($user, $options)` returns array.
- Optional `getRenderer($options)` for runtime renderer choice.
- Optional `checkPermissions($user)` for visibility gating.

New (optional):
- `$schema` — replacement for `$params` (which becomes a fallback). Each
  parameter declares `type` (one of the canonical types in §5.5, or a
  scalar fallback `string|int|bool|enum`), plus `default`, `enum` (when
  `type=enum`), `help`, and optional `required`. Drives the typed-fields
  tier of the configure form (DD-06) *and* toolbar reachability —
  the toolbar (§5.6) shows controls for canonical types declared by at
  least one widget on the dashboard.
- `$category` — gallery grouping ("status", "events", "tags", "orgs",
  "system", "custom").
- `$thumbnail` — relative URL to a static preview image used in the
  gallery.
- `$drilldown` — *(legacy/redundant — see DD-03)* — drilldown is a
  per-datum convention now, supplied in `handler()` return values via
  a `drilldown` key. No class-level property required.
- The toolbar's bulk-edit semantics (DD-05) write resolved canonical-typed
  values into each widget's `config` directly. Widget classes therefore
  read their own `$options` exactly as today — no inheritance helper,
  no `_scope` blob, no `$scopeAware` flag. The toolbar's effect is
  realised by *having already written* the canonical-typed values into
  each addressable widget's `config` before `handler()` is called.

### 5.8 REST API (target shape, exact paths TBD)

The persistence-side endpoints stay close to today's shape since
the persistence model is unchanged. Net additions are read-only
metadata endpoints (widgets, schemas) needed by the schema-driven
configure form (DD-06).

- `GET    /dashboards/widgets` — *new.* List available widgets with
  metadata (title, description, schema, category, default size,
  thumbnail).
- `POST   /dashboards/renderWidget/{instance_id}` — preserved
  unchanged. The request still carries the widget config; widgets
  read their own `$options` as today (per DD-05, the toolbar's
  effect is realised at write time, not at render time).
- `POST   /dashboards/updateSettings` — preserved; the persisted blob
  shape changes per §5.1 but the URL and verb do not.
- `GET    /dashboards/import`, `POST /dashboards/import` — preserved.
- `GET    /dashboards/export` — preserved; output adopts the new
  blob shape (legacy bare-array form still readable on import).
- `GET    /dashboards/listTemplates`, `GET /dashboards/saveTemplate`,
  `POST /dashboards/saveTemplate`, `POST /dashboards/deleteTemplate` —
  preserved verbatim.

The previous draft's `/dashboards/boards/...` resourceful surface is
withdrawn — there is no boards collection, only the singleton
`UserSetting:dashboard`. §13 Q8 ("REST URL shape") is therefore moot.

## 6. Existing system audit (where v2 plugs in)

This section is the read-out of the exploration. Files are pinned so the
implementation work has a starting map.

### 6.1 Server-side (PHP)

| Concern | File | Notes |
|---|---|---|
| Controller actions | `app/Controller/DashboardsController.php` | `index`, `getForm`, `updateSettings`, `getEmptyWidget`, `renderWidget`, `import`, `export`, `saveTemplate`, `listTemplates`, `deleteTemplate`. CSRF-unlocks `renderWidget` + `getForm`. |
| Model + table CRUD | `app/Model/Dashboard.php` | `loadWidget`, `loadAllWidgets`, `__extractMeta`, `import`, `export`, `getDashboardTemplate`, `saveDashboardTemplate`. |
| Per-user persistence | `app/Model/UserSetting.php` (key `dashboard`) | One layout per user, JSON list of `{widget, config, position{x,y,w,h}}`. |
| Templates table | `dashboards` (per `INSTALL/MYSQL.sql`) | Columns: id, uuid, name, description, default, selectable, user_id, restrict_to_org_id, restrict_to_role_id, restrict_to_permission_flag, value, timestamp. |
| Widget classes | `app/Lib/Dashboard/*Widget.php` (~30) | All retained. Examples: `MispStatusWidget`, `TrendingTagsWidget`, `UsageDataWidget`, `OrgEventsWidget`, `AttackWidget`, `OrganisationMapWidget`, `MispAdminWorkerWidget`. |
| Custom widgets | `app/Lib/Dashboard/Custom/` (incl. `widget-collection/` subdir loader) | Drop-in pattern preserved as-is. |
| Helpers | `app/Lib/Dashboard/Tools/WidgetToolkit.php` | Currently only `getCountryCodeMapping`. |
| Side menu wiring | `app/View/Elements/genericElements/SideMenu/side_menu.ctp` (case `dashboard`) | Entries: View, Add (modal), Import, Export, ListTemplates. |
| Side menu (UiBeta) | `app/View/Themed/UiBeta/Elements/genericElements/SideMenu/side_menu.ctp` | Mirror of the same entries — we update both. |

### 6.2 Client-side (views, JS, CSS)

| Concern | File |
|---|---|
| Board page | `app/View/Dashboards/index.ctp` (Gridstack init + hydration + add/render JS) |
| Widget wrapper | `app/View/Elements/dashboard/widget.ctp` (sprintf-built, hardcoded blue 1px border) |
| Widget render shell | `app/View/Dashboards/widget_loader.ctp` (uses `ScopedCSS` helper) |
| Empty widget bootstrap | `app/View/Dashboards/get_empty_widget.ctp` |
| Add / edit modals | `app/View/Dashboards/add.ctp`, `edit.ctp` |
| Template list | `app/View/Dashboards/list_templates.ctp` |
| Save-template form | `app/View/Dashboards/save_template.ctp` |
| Import/export | `app/View/Dashboards/import.ctp`, `export.ctp` |
| Renderers | `app/View/Elements/dashboard/Widgets/{SimpleList,BarChart,MultiLineChart,WorldMap,Index,OrgsPictures,Achievements,Attack,Button,Array}.ctp` — see §6.4 for the chart-library mix these renderers currently use |
| Dashboard JS | `app/webroot/js/misp.js` lines ~5592–5730 (`submitDashboardForm`, `saveDashboardState`, `resetDashboardGrid`, click handlers for edit/remove/export). Includes a stray `console.log`. |
| Grid library | `app/webroot/js/gridstack.all.js`, `app/webroot/css/gridstack.min.css` (`.bk` siblings present from a prior partial rework — to be removed). |

### 6.3 Observed pain points (informs §2 goals)

- **Authoring UX.** Add modal is a `<select>` of widget classes plus a raw
  JSON textarea seeded from `$placeholder`. Users must hand-edit JSON to
  change a threshold. (`getForm` action + `add.ctp` / `edit.ctp`.)
- **Persistence model.** Every drag/resize triggers `saveDashboardState`,
  which posts a fresh form to `updateSettings`. There is no transactional
  edit, no "discard changes", no undo, and no warning on navigation away.
- **Single board per user.** `UserSetting` key `dashboard` holds exactly
  one layout. Switching contexts means rebuilding the same board.
- **Look and feel.** `widget.ctp` hardcodes `border: 1px solid #0088cc;`
  and assembles the title bar via sprintf. `SimpleList.ctp` hardcodes
  `class="blue"` / `class="green bold"` etc. Themes don't get a clean
  override surface; the UiBeta theme has no dashboard overrides at all.
- **No shared scope.** Each widget reads its own time window from its
  own config. Two widgets on the same board can disagree on what
  "this week" means.
- **Drill-down.** Inconsistent: `MispStatusWidget` ships a hand-written
  `(View)` link in `html`, others ship none. No renderer-level convention.
- **Refresh.** Each widget schedules its own `setTimeout` in
  `widget_loader.ctp`. No global pause; refresh storms are possible.
- **Stray code.** `console.log($wrapper.attr('config'))` in
  `saveDashboardState`; `.bk` files in webroot.

### 6.4 Theme-override inventory (drives §G11 and §8)

`app/View/Themed/<Name>/` is a CakePHP-native override directory: any
`.ctp` placed there at the same relative path as a default-theme view
silently replaces it. Three themes ship today, sitting at very different
points on the intensity spectrum:

| Theme | `theme.php` label | Override count | Posture | Dashboard surface today |
|---|---|---|---|---|
| `Overmind` | "Overmind UI" (dev) | ~50+ files | **Full conversion** to Bootstrap 5. Ships a parallel `Elements/genericElementsBS5/` set, its own `Layouts/default.ctp`, its own navbar, footer, header. | None — dashboard is unstyled / inherits BS2.3 markup, looks broken. |
| `UiBeta` | "Beta UI" | 5 files | **Targeted overrides**: own `Layouts/default.ctp`, own `Elements/global_menu.ctp`, own side menu, plus `Events/index.ctp`. | Already overrides the side menu's `dashboard` case → dashboard URL still resolves but no view-level override yet. |
| `EventTest` | (test-only) | ~handful | **Narrow experiments** on Events pages only. | None. |

Implications the v2 frame must respect:

- A theme should be able to **drop in a single CSS file** and end up with
  a coherent dashboard look (CSS-only overlay theme — neither Overmind
  nor UiBeta does this today, but it's an explicit user requirement and
  simpler themes will arrive). That requires every styling decision to
  flow through CSS custom properties on a stable selector.
- A theme should be able to **override individual `.ctp`s surgically**
  without copying the whole page — Overmind already does this for
  layout, navbar, side menu. We don't want to force a theme author to
  fork `Dashboards/index.ctp` just to change the toolbar.
- A theme can ship a **parallel framework version** of generic elements
  (Overmind's `genericElementsBS5/` pattern). The dashboard's generic
  elements (widget wrapper, toolbar, empty state, gallery card) need to
  follow the same pattern so a BS5 theme can swap them without touching
  the dashboard logic.
- The dashboard's JavaScript must **not assume specific markup** beyond a
  small set of stable hook classes / data attributes, so a heavy theme
  rewriting the markup still gets working drag/resize/refresh behaviour.

### 6.5 Chart-library inventory (drives the §G10 consolidation)

The current dashboard renders charts using **three** separate libraries
plus hand-rolled HTML, none of which are aligned on theme or interaction
model:

| Renderer | Library | Notes |
|---|---|---|
| `BarChart.ctp` | None — hand-built | `<div>` bars with `width:%` and inline colour from data, `class="blue"` defaults. ~50 lines. No tooltip beyond `title`, no axes, no legend. |
| `MultiLineChart.ctp` | **D3 v3** (`/js/d3.js`) | ~600 lines. Uses `d3.scale.linear()`, `d3.time.format()`, `d3.svg.axis()` — all D3 v3 API, removed in v4 (2016). Hand-rolls tooltip, legend, picked-node selection overlays. Re-implements crosshair, zoom selection, etc. |
| `WorldMap.ctp` | **jquery-jvectormap-2.0.5** (`webroot/js/jquery-jvectormap-2.0.5.min.js` + `world-mill` GeoJSON) | jQuery plugin, last upstream activity ~2017. Loaded via `assetLoader` on demand. |
| `Chart.js` | **`Chart.min.js`** in `webroot/js/` plus `chartjs-adapter-moment.min.js` | Used elsewhere in the app (not in dashboard renderers today). Worth folding into the same migration so we don't keep three chart stacks side by side. |
| `Achievements.ctp`, `Attack.ctp`, `OrgsPictures.ctp`, `Index.ctp`, `SimpleList.ctp`, `Array.ctp`, `Button.ctp` | None | Plain HTML / Bootstrap markup; no chart library involved. Stay non-charting in v2. |

The replacement target is **Apache ECharts** for everything in the first
four rows: bar/line/multi-line, geo maps (built-in `world.json`),
heatmap (covers a future ATT&CK widget upgrade), treemap/sunburst (good
for tag distributions). One library, one theme system, ESM tree-shaken
build for the subset we actually use. Net effect: we *remove* D3 v3,
jvectormap, and the hand-rolled bar code; we *consolidate* Chart.js
usage into ECharts elsewhere in the codebase as a follow-up (out of
scope for this PRD but flagged so we don't relitigate the choice
later).

## 7. Data model

**No schema changes, no top-level blob shape change.** Persistence
was kept as-is (G12 dropped 2026-05-04); the toolbar bulk-edit model
(DD-05) collapsed any need for a separate scope envelope. Both
surfaces are reused verbatim.

### 7.1 `UserSetting:dashboard` (per-user singleton)

Existing model. The blob is a bare array of widget instances, same
top-level shape as today:

```json
[ {widget, config, position{x,y,width,height}}, ... ]
```

**On-read evolution (per-widget, lazy).** Two small fix-ups happen
when v2 reads a v1-shape blob:

1. **`width/height → w/h`** rename on each widget's position field
   (Pragmatic DnD's grid math uses the shorter names; DD-01).
2. **`instance_id` mint** on each widget that lacks one (used as the
   stable identity for widgets across re-renders and configure-form
   sessions).

Both are written back on the next save — no migration shell needed.
The v1 controller is being deleted (Q5 resolution), so there's no
v1 reader to surprise.

### 7.2 `dashboards` table (templates)

Existing schema. Unchanged in this PRD. The `value` column already
holds the same widget-instance array shape as `UserSetting:dashboard`;
the on-read fix-ups above apply here too.

### 7.3 No migration shells

No data migration is needed. Existing users keep their layout; the
fix-ups happen transparently on their next save.

## 8. Theming architecture

The dashboard frame is structured to be theme-able at four escalating
levels of intensity, matching the spread already present in
`app/View/Themed/` (see §6.4). A theme author opts into whichever level
solves their problem and never has to engage with the others.

### 8.1 Level 1 — CSS-only overlay (lightest)

The intended posture for "I just want a different colour scheme".

- All visual decisions (colour, spacing, border, radius, shadow,
  typography scale, density) flow through **CSS custom properties**
  defined on `:root` (and overridable on `.misp-dashboard`).
- The default theme ships a single stylesheet (e.g.
  `webroot/css/dashboard/dashboard.default.css`) that:
  1. defines the token set with default values,
  2. styles the dashboard markup using only those tokens.
- A CSS-only theme drops a single override stylesheet that **redefines
  the tokens** (and nothing else). No `.ctp` overrides, no JS, no
  markup surgery. Example:

  ```css
  :root[data-theme="midnight"] {
    --misp-dash-surface:        #0e0f12;
    --misp-dash-surface-raised: #161821;
    --misp-dash-border:         #2a2d36;
    --misp-dash-text:           #e6e8ee;
    --misp-dash-text-muted:     #8b8f99;
    --misp-dash-accent:         #5aa9ff;
    /* ... */
  }
  ```

- Token names are stable contract; we treat them as a public API and
  bump them only with a deprecation note.

### 8.2 Level 2 — ECharts theme JSON

Themes that go further than recolouring static UI also want the charts
themed.

- The default ECharts integration registers a theme named `"misp"` whose
  palette is derived at boot from the resolved CSS tokens (read via
  `getComputedStyle(document.documentElement)`). A CSS-only theme
  therefore gets themed charts for free — without writing any JS.
- A theme that wants finer chart control (different palette ramp, line
  style, axis treatment) ships an ECharts theme JSON next to its
  stylesheet and registers it via the existing `assetLoader` element.
  The dashboard frame picks it up by name from a theme-declared key
  (`MISP.theme_echarts_name` or equivalent).
- Widget renderers never set chart colours inline. They build an
  ECharts options object that omits explicit colours and relies on the
  active theme.

### 8.3 Level 3 — Targeted `.ctp` overrides (Overmind/UiBeta-style)

For themes that need to change *markup*, not just style.

The dashboard view tree is decomposed into small, single-purpose `.ctp`s
so an override can be surgical rather than total. The override-surface
inventory (each line is overridable independently under
`Themed/<Name>/...`):

```
View/Dashboards/
  index.ctp                           # board page shell
  edit.ctp                            # edit-mode view (separate from view mode)
  list_templates.ctp                  # template gallery
  save_template.ctp                   # save-as-template form

View/Elements/dashboard/
  toolbar.ctp                         # board toolbar (mode toggle, scope, save)
  board_switcher.ctp                  # tabs / dropdown for picking active board
  empty_board.ctp                     # zero-widget state
  scope_bar.ctp                       # board-level scope controls

  widget/
    wrapper.ctp                       # the per-widget frame
    title_bar.ctp                     # title + alias + actions
    actions_menu.ctp                  # configure / remove / export
    refresh_indicator.ctp             # last-updated chip + manual refresh
    config_form.ctp                   # schema-driven config form shell
    config_field.ctp                  # one row of the config form
    preview_pane.ctp                  # live preview during config

  gallery/
    card.ctp                          # one widget / template card
    grid.ctp                          # gallery layout
    category_header.ctp               # category divider

  Widgets/                            # renderer templates (existing)
    SimpleList.ctp                    # untouched semantics; v2 reskin
    BarChart.ctp                      # → ECharts shim
    MultiLineChart.ctp                # → ECharts shim
    WorldMap.ctp                      # → ECharts geo shim
    ...
```

A theme can override **any** of these in isolation. Concrete examples:

- Overmind needs BS5 markup for the widget wrapper → it ships
  `Themed/Overmind/Elements/dashboard/widget/wrapper.ctp` only. Logic,
  data, config form, renderers stay shared.
- A new compact theme wants a denser title bar → ships
  `Themed/<Name>/Elements/dashboard/widget/title_bar.ctp`.
- A heavy theme wants its own gallery presentation → ships its own
  `gallery/grid.ctp` and `gallery/card.ctp`.

### 8.4 Level 4 — Parallel generic-element variants

Mirroring Overmind's existing `Elements/genericElementsBS5/` pattern.

- If a theme has its *own* version of generic primitives (form input,
  modal, dropdown), the dashboard's `config_form.ctp`,
  `config_field.ctp`, and `actions_menu.ctp` invoke them through the
  CakePHP element-resolution path (relative element names), so the
  theme's parallel version is picked up automatically when present.
- The dashboard ships **its own generic elements** under
  `Elements/dashboard/generic/` (button, icon-button, dropdown,
  field-row) so heavy themes that diverge can override these without
  touching widget renderers or board logic.

### 8.5 JavaScript hook contract

A theme that rewrites markup heavily must not break drag/resize, refresh,
or save. The dashboard JS therefore binds to a stable, narrow set of
hook classes / data attributes — never to layout-specific selectors.

- `[data-misp-board-root]` — the board root element. Required.
- `[data-misp-widget]` — one widget. Required. Carries
  `data-widget-name`, `data-widget-instance-id`, and
  `data-widget-config` (JSON-encoded).
- `[data-misp-widget-content]` — where rendered HTML/SVG is injected.
- `[data-misp-widget-action="configure|remove|refresh|export-json|export-csv"]`
  — clickable controls. Themes can place these anywhere (or omit them
  in view mode) — the JS finds them via `closest('[data-misp-widget]')`.
- `[data-misp-board-action="add-widget|toggle-mode|save|discard|set-scope|pause-refresh"]`
  — board-level toolbar controls.
- Custom events fired on `[data-misp-board-root]`:
  `misp-board:mode-changed`, `misp-board:saved`, `misp-board:scope-changed`,
  `misp-board:widget-rendered`, `misp-board:widget-error`. Themes can
  listen to add their own behaviour without forking JS.

### 8.6 Look-and-feel principles (apply to every theme)

- Edit-mode chrome (drag handles, resize grips, remove/configure
  buttons) is overlay-only — invisible in view mode, clearly visible
  and large enough to hit in edit mode.
- Density: a comfortable default; per-board "compact" toggle that
  reduces padding and font scale for ops-console use. Implemented as a
  data attribute (`data-density="compact"`) so themes can react via
  CSS without JS work.
- Animations respect `prefers-reduced-motion`.
- Light/dark distinction is just a token swap, gated on `data-theme` or
  `prefers-color-scheme` per the host theme's choice.

## 9. Compatibility

### 9.1 Custom widgets (third-party drop-ins)

- All existing `app/Lib/Dashboard/*Widget.php` and
  `app/Lib/Dashboard/Custom/**/*Widget.php` continue to load and render,
  with the legacy `$placeholder` JSON textarea as fallback when no
  `$schema` is declared.
- Renderer templates under `app/View/Elements/dashboard/Widgets/*.ctp`
  continue to render; v2 wraps them with the new frame and overlays
  (drill-down link wrapping is opt-in per renderer, not retroactive).

### 9.2 REST clients

- The v1 endpoints (`updateSettings`, `getForm`, `getEmptyWidget`,
  `import`, `export`, `saveTemplate`, `listTemplates`, `deleteTemplate`)
  remain mounted for one release cycle as thin shims that translate to v2.
  The "official" surface is the §5.6 shape.

## 10. Performance and limits

- A board renders at most N widget instances; default cap N=24, configurable
  per instance via `Configure` setting.
- Initial render is server-side for the chrome and lazy for widget data
  (widget POSTs fire after the layout is in the DOM, as today).
- Cache hit rate on widget data is observable via existing Redis keys.
- The dashboard scheduler MUST throttle simultaneous renders to <= 4 in
  flight per board to avoid the refresh storms that today's
  setTimeout-per-widget can trigger.

## 11. Security and ACL

- All v2 endpoints require auth and respect `checkPermissions($user)` on
  each widget class.
- Per-user dashboard ownership: every user reads/writes only their own
  `UserSetting:dashboard` row (existing UserSetting ACL).
- Templates: read access is gated by the existing
  `restrict_to_org_id / role_id / permission_flag` rules on the
  `dashboards` table; admin-only write.
- CSRF: the `renderWidget` POST stays in `Security->unlockedActions` (it
  has no side effects); save endpoints follow the standard CSRF posture.

## 12. Migration strategy

**Straight replacement on the feature branch.** The work happens on
the `dashboards` branch (already cut from `2.5`, the current stable);
nothing reaches `develop` or downstream until the rework is complete.
There is therefore **no flag, no v2 path prefix, no parallel
mounting**. v1 controller actions, views, and JS are removed in place
as v2 replaces them. End users see one experience pre-merge (v1, on
all branches) and one experience post-merge (v2, on the merged
branch).

Decision recorded: §13 Q5 resolved 2026-05-04 in favour of straight
replacement. See also `dashboard-design-decisions.md` (DD-05 once
landed for the merge-gate spec).

**Three-parity merge gate.** Before the `dashboards` branch merges to
`develop`, all three of these must hold:

1. **Widget parity.** Every built-in widget under
   `app/Lib/Dashboard/*Widget.php` (the ~30 in-tree today) renders
   correctly in v2. Each gets explicit smoke-test coverage. Custom
   widgets (`Custom/`) need the loader path to still pick them up;
   per-widget rendering quality on third-party widgets is best-effort
   (the contract is "v1 widgets continue to load and run", not "every
   third-party widget looks pretty").
2. **Data parity.** Every existing user's `UserSetting:dashboard` row
   loads via the backward-compat read (§7.1). Every existing
   `dashboards` template row loads. Round-trip the legacy bare-array
   form through v2 and back to a v1 reader (during the branch's
   lifetime, before v1 is deleted) without data loss.
3. **Surface parity.** Every URL the side menu links to today
   resolves to a working v2 view. Import / export / `saveTemplate` /
   `listTemplates` / `deleteTemplate` all keep working on the same
   URLs with the same request shapes (the response shapes adopt the
   new `{scope, widgets}` blob form, with backward-compat read on
   import).

These three gates are checked off in Phase 5.5 (Widget Parity Sweep)
of the progress tracker.

**On data:** the `dashboards` table and `UserSetting:dashboard` rows
survive untouched through the merge. The blob-shape evolution
(`{scope, widgets}` replacing the bare array) is the *only* data
change, applied on a per-row basis on each row's next save (lazy
read-promote).

## 13. Open questions (need user input before Phase 0)

1. ~~Templates carry default scope?~~ **Resolved 2026-05-04, then
   superseded same day by Model 4 (DD-05).** Templates carry whatever
   per-widget configs they ship — including canonical-typed values on
   specific widget instances (e.g. a "Weekly review" template's
   TrendingTags instance can be pre-configured with `time_window: P7D`).
   Reset-from-template replaces the user's `UserSetting:dashboard`
   blob with the template's blob, full stop. There is no separate
   scope concept and no "Also apply default filters" checkbox.
2. ~~Tabs vs. dropdown vs. sidebar for board switcher.~~ **Moot** —
   multi-board (G2) was dropped 2026-05-04. One dashboard per user.
3. **Drill-down convention.** Should the renderer auto-wrap *all*
   labels, or only when the widget declares `$drilldown`? (Auto =
   better default coverage; explicit = no surprise navigations.)
4. ~~Gridstack v11 vs. Pragmatic DnD.~~ **Resolved 2026-05-04 — Pragmatic
   DnD + CSS Grid + custom snap/collision math.** See
   `dashboard-design-decisions.md` DD-01 for rationale, licence verdict,
   and the reversibility forcing function (>40% of Phase 1 effort on
   grid math triggers escalation).
5. ~~Posture on touching legacy.~~ **Resolved 2026-05-04 — straight
   replacement on the `dashboards` feature branch**, no flag, no v2
   path prefix, no parallel mounting. v1 is removed in place as v2
   replaces it; nothing reaches `develop` until the three-parity
   merge gate (§12) is met. The standing additive-only rule
   (`feedback_additive_only_posture.md`) is explicitly waived for
   this rework — branch isolation removes the user-facing risk that
   the rule was guarding against.
6. ~~Theme-native vs. one shared frame; frame's own CSS vs. inherit host BS variables.~~
   **Resolved 2026-05-04 — single shared frame parameterised by
   tokens (resolved earlier), shipping its own self-contained CSS file
   that does not depend on any Bootstrap version.** See
   `dashboard-progress.md` Resolved questions §Q6 for the
   "easy to integrate" practical constraints (typography inherits,
   scoped rules, theme overlays via the existing `additionalCss`
   mechanism).
7. ~~Widget `$schema` migration.~~ **Resolved 2026-05-04 — tiered
   (Option C).** Nine widgets get full-tier backfill (every param
   typed); the rest get canonical-only and keep the legacy JSON-textarea
   fallback for non-canonical params. Specific widget list pinned in
   `dashboard-progress.md` Resolved questions §Q7.
8. ~~REST URL shape.~~ **Moot** — the multi-board endpoints were
   withdrawn (§5.8). Existing verb-action endpoints are reused
   verbatim; only `GET /dashboards/widgets` is new and follows the
   same convention.
9. ~~Unified template gallery feed.~~ **Moot** — sharing tiers
   were dropped (G12). The gallery shows only the existing
   `dashboards` table.
10. ~~Toolbar inherit/pinned UI affordance.~~ **Moot under Model 4
    (DD-05).** No inherit/pinned state exists; the toolbar bulk-edits
    per-widget configs directly. The configure form is just the
    configure form (DD-06).
11. ~~Toolbar persistence in view mode.~~ **Resolved 2026-05-04 —
    toolbar pulls write immediately, in any mode.** Edit mode is
    reserved for layout / structural changes only (drag, resize, add,
    remove). Configure-form changes save per-form. Toolbar pulls save
    per-pull.
12. ~~Soft-delete retention.~~ **Moot** — soft-delete dropped with G12.
13. ~~Cross-instance UUID identity on import.~~ **Moot in this scope** —
    we keep today's import/export semantics (no UUID change).
    Whatever the existing system does, v2 inherits.

## 14. Phased plan (placeholder, locked in once §13 is resolved)

- **Phase 0 — Alignment + prototype.** Resolve §13. Build a throwaway
  prototype of the new frame against 2–3 representative widgets
  (MispStatus → SimpleList, TrendingTags → ECharts bar/line,
  OrganisationMap → ECharts geo). Prototype must validate **all four
  theme intensity levels** (§8.1–§8.4) end-to-end:
  - Level 1 — apply a CSS-only "midnight" overlay theme that swaps
    tokens only; confirm dashboard + charts both retheme without any
    `.ctp` or JS changes.
  - Level 3 — drop a `Themed/Overmind/Elements/dashboard/widget/wrapper.ctp`
    that uses BS5 markup; confirm drag, resize, configure, refresh, and
    save still work end-to-end via the JS hook contract (§8.5).
  Prototype must additionally validate the **canonical-type +
  toolbar plumbing** end-to-end: the three prototype widgets each
  declare `time_window` and (where meaningful) `tag_filter` /
  `org_filter` via `$schema`; the board toolbar exposes only those
  slots; flipping the toolbar value re-renders inheriting widgets;
  pinning a per-widget value successfully opts out. Also validates
  the Gridstack v11 bump, ECharts adoption, and the schema-driven
  configure form.
- **Phase 1 — Frame (in-place replacement).** Replace v1 controller
  actions, views, JS, and CSS with v2 equivalents on canonical
  `/dashboards/*` routes. v1 files are deleted as v2 takes over the
  same URL — there is no parallel mounting. Reads/writes the existing
  `UserSetting:dashboard` row using the new `{scope, widgets}` blob
  shape with backward-compat read of the legacy bare-array form. No
  widget migrations yet — legacy widget classes work as-is via the
  preserved data contract.
- **Phase 2 — Authoring UX.** Schema-driven configure form (side panel,
  not modal), gallery for Add Widget, edit-mode vs. view-mode toggle,
  atomic save with discard. Backfill `$schema` on the 5 highest-priority
  built-in widgets.
- **Phase 3 — Canonical-type toolbar.** Implement the canonical type
  catalogue (§5.5) and the toolbar (§5.6). Backfill canonical-type slots
  on the remaining built-in widgets where applicable. Inherit/pinned
  semantics per §13 Q10 resolution.
- **Phase 4 — Template gallery polish.** Replace today's
  `listTemplates` table view with the gallery surface (thumbnails,
  categories, search). Existing `dashboards` schema and
  `restrict_to_*` semantics preserved verbatim.
- **Phase 5 — Drill-down + scheduler.** Renderer-level drill-down
  wrapping with widget-declared targets; dashboard-level refresh
  scheduler with pause; per-instance refresh override; auto-pause on
  hidden tab.
- **Phase 5.5 — Widget Parity Sweep (merge gate).** The three-parity
  gate from §12 is checked off explicitly:
  - **Widget parity:** every built-in widget renders in v2; smoke-test
    matrix attached to the progress tracker. Custom-widget loader
    still resolves third-party widgets.
  - **Data parity:** legacy `UserSetting:dashboard` blob shape reads
    cleanly; legacy `dashboards.value` reads cleanly; round-trip via
    import/export preserves both shapes.
  - **Surface parity:** every URL on the side menu (View, Add, Import,
    Export, ListTemplates) resolves; `saveTemplate` /
    `listTemplates` / `deleteTemplate` /  `import` / `export` keep
    working on their existing URLs.
- **Phase 6 — Merge to `develop`.** With Phase 5.5 green, the
  `dashboards` branch merges to `develop` for the next 2.5 release
  cycle. No flag, no migration helper, no admin-runnable cleanup —
  the blob-shape evolution is transparent on first save per row.
  Whatever remains of v1 in the tree (`.bk` artefacts, unused chart
  libraries) is removed pre-merge during the parity sweep, not
  post-merge.

Per-task detail will live in `docs/dev/dashboard-progress.md` once Phase 0
is signed off.
