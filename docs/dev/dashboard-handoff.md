# Dashboard v2 — Session handoff (2026-05-06)

Brief read-out of where this work session ended, intended for a
fresh session to pick up cleanly. Authoritative state lives in:

- `dashboard-prd.md` — spec
- `dashboard-progress.md` — task state, Done notes
- `dashboard-design-decisions.md` — DD-01..DD-07 binding decisions

This file is the bridge: ephemeral session-level context that doesn't
fit the durable docs. Treat it as a one-off.

## Where we are

**Phase 0.3 — five of eleven tasks closed**, six remaining:

```
[-] Create dashboard-v2-proto branch        ← cancelled (stay on `dashboards`)
[x] Stand up Dashboards2Controller + view   ← done, with ACL + RestResponse follow-ups
[x] Vendor libraries (done in Phase 0.2)
[x] CSS token catalogue                     ← done
[x] JS hook contract (BoardModule)          ← done
[x] Render MispStatusWidget via SimpleList  ← done; user browser-verified 2026-05-06

[ ] Render TrendingTagsWidget via ECharts bar       ← NEXT
[ ] Render OrganisationMapWidget via ECharts geo
[ ] Schema-driven configure form for time_window
[ ] Dashboard toolbar with time_window slot
[ ] Demo Model 4 bulk edit
[ ] Demo per-widget on-read fix-ups
```

Live test instance is at `http://localhost:5007/dashboards2`. User
confirmed the page now renders with the v2 frame; CSS tokens apply,
GridModule loads, BoardModule binds the §8.5 hook contract, and the
MispStatusWidget paints through the v2 SimpleList renderer.

User flagged with debug mode on: **notice errors about some widgets
not having .ctp files to render**. That's expected — the v2 frame
calls into `View/Elements/dashboard-v2/Widgets/<renderer>.ctp`, but
only `SimpleList.ctp` exists today. `TrendingTagsWidget` wants
`BarChart.ctp` (next task). `OrganisationMapWidget` wants
`WorldMap.ctp` (task after that). Other widgets the prototype layout
doesn't reference yet will need their renderers as we widen scope.

## Commits this session

```
2305ec112 fix: use RestResponse instead of JsonView for REST output
225eab968 new: SimpleList renderer + render_widget dispatcher
ef1036e81 chg: rename DashboardsProto → Dashboards2 + ACL whitelist
7fd80afb3 new: BoardModule — JS hook contract per PRD §8.5
965f455bb new: CSS token catalogue + base stylesheet
c3bfd2cc7 new: DashboardsProtoController + index view (superseded by ef1036e81)
617a216ee chg: Phase 0.3 housekeeping
7f8a376c4 chg: formalise licence-compatibility audit (DD-07)
f7d2af11c chg: resolve uPlot question — ECharts only
970d776de new: vendor ECharts + world GeoJSON
c975caf13 chg: tick GridModule UX-verification
2f3b85648 new: GridModule prototype + demo, LOC under DD-01 threshold
878dc7038 new: vendor Pragmatic Drag and Drop bundle
f2c3e10fb chg: fix Phase 0.2 path references in progress tracker
41b0a9536 new: alignment phase docs (PRD, progress, decisions)
```

Working tree is clean for the dashboard-v2 work.

## Gotchas a fresh session needs to know

These bit me this session and aren't obvious from the regular docs:

1. **Every controller needs an entry in `ACLComponent::ACL_LIST`.**
   Located at `app/Controller/Component/ACLComponent.php`. Without it,
   any request to that controller — even with valid auth — returns a
   404 with body `{"name":"Invalid controller."}`. The 404 is *not*
   logged to `app/tmp/logs/error.log` because `AppExceptionRenderer`
   suppresses it. I burned ~30 min of context bisecting before finding
   this. Any new controller (e.g. when we eventually rename
   `Dashboards2` → `Dashboards`) needs the whitelist update.

2. **For REST/JSON responses, use `RestResponse->viewData(...)`,
   never JSON views.** MISP doesn't ship per-controller `json/` view
   directories. Branch on `$this->_isRest()` at the action level —
   matches the v1 dashboards `export()` pattern. Phase 0.3 commit
   `2305ec112` shows the fix. Same applies to save-style actions:
   `RestResponse->saveSuccessResponse()` / `saveFailResponse()`.

3. **New files I created landed as `iglocska:iglocska`** but
   MISP repo convention is `iglocska:www-data`. Apache reads via
   "other" perm bits so it usually works, but to match repo
   convention run `chgrp www-data <files>` on each new file before
   committing. Worth checking if the user's umask should be tweaked
   long-term so this doesn't keep happening per file.

4. **No JS build pipeline in MISP.** Vendored bundles (PDD, ECharts,
   future libs) are produced via `npx esbuild` in a temp dir and
   committed as single self-contained `.bundle.mjs` files. Recipes
   per-vendor live in each `vendor/VENDORING.md`. Reproducible
   byte-for-byte from a clean directory.

5. **Live instance & API key for curl smoke tests:**
   `http://localhost:5007` + admin auth key in PRD §"Local test
   instance". Use `Accept: application/json` to bypass session auth
   when poking REST endpoints from curl.

## Known shape of the next task

**Render TrendingTagsWidget via ECharts bar chart** — the
`TrendingTagsWidget` returns data shaped `{data: {<tag>: <count>}, colours: {<tag>: <hex>}}`
in its non-over-time path (and `{data: [{date, ...}]}` when `over_time` is set).
The v1 renderer is `Elements/dashboard/Widgets/BarChart.ctp` (~50 lines of
HTML divs). The v2 path:

- Create `app/View/Elements/dashboard-v2/Widgets/BarChart.ctp` that
  loads the vendored ECharts bundle (`/js/dashboard-v2/charts/vendor/echarts.bundle.mjs`),
  initialises an ECharts instance in a container with a unique id, and
  feeds it an option object derived from `$data`.
- Register a `"misp"` ECharts theme at boot (one-time per page) whose
  palette is derived from CSS custom properties (PRD §8.2: read
  `getComputedStyle(document.documentElement)` for `--misp-dash-accent`,
  `--misp-dash-success`, etc.). Best place: a small
  `app/webroot/js/dashboard-v2/charts/echarts-theme.mjs` that the
  BoardModule imports and runs on init.
- For data: respect the existing widget's `colours` map when present,
  but where it's missing, ECharts uses the registered theme palette.
- Resize: ECharts' `resize()` needs to be called when the widget tile
  resizes. The BoardModule already fires a `widget-resized` event we
  could listen for; we already do this in v1. Renderers should bind
  to it.

Probably ~80–120 LOC across the renderer + theme module. Stays well
under any forcing function.

After TrendingTags lands, the OrgMap renderer is similar but uses
`echarts.registerMap('world', worldGeoJson)` (the GeoJSON we vendored
at `world-110m.geojson`) and a `series: [{type: 'map', ...}]` setup.

## Open thread

The notice errors about missing widget `.ctp` files affect any
widget that the prototype layout references whose renderer we
haven't ported. As of this handoff, that's TrendingTags and OrgMap.
Once those land, the prototype's three-widget layout should render
clean. Other in-tree widgets (Achievements, Attack, etc.) only
matter when the parity sweep in Phase 5.5 walks the full list —
not now.
