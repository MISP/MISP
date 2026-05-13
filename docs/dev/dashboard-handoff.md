# Dashboard v2 — Session handoff (2026-05-13)

Brief read-out for a fresh session to pick up cleanly. Authoritative
state still lives in:

- `dashboard-prd.md` — spec
- `dashboard-progress.md` — task state, Done notes, Discovered work
- `dashboard-design-decisions.md` — DD-01..DD-07 binding decisions

This file is the bridge: ephemeral session-level context that doesn't
fit the durable docs. Replace it as work progresses.

## TL;DR

**Phase 0.3 is closed — all 11 implementation tasks done and
browser-verified.** What remains is Phase 0.4 sign-off (3 tasks,
mostly user-facing) and then Phase 1.

If the user opens the next session with "let's proceed to Phase 1",
the proto code IS the Phase 1 starting point. The hardcoded layout,
the routes, the CSS, the JS modules, the renderers — all carry
forward. Phase 1 is mostly **renames** + switching the standalone
view to use MISP's regular layout chrome.

## Where we are

```
Phase 0.3 — Build the throwaway prototype                         [x]
  Stand up Dashboards2Controller + view (with ACL whitelist)      [x]
  Vendor PDD + ECharts + world GeoJSON                            [x]
  CSS token catalogue                                             [x]
  JS hook contract (BoardModule §8.5)                             [x]
  MispStatusWidget via SimpleList                                 [x]
  TrendingTagsWidget via ECharts BarChart                         [x]
  OrganisationMapWidget via ECharts geo                           [x]
  Schema-driven two-tier configure form (DD-06)                   [x]
  Dashboard toolbar with time_window slot                         [x]
  Model 4 bulk edit end-to-end demo                               [x]
  Per-widget on-read fix-ups + persistence                        [x]
  Midnight Level 1 overlay theme                                  [x]
  Themed/Overmind Level 3 wrapper override                        [x]

Phase 0.4 — Sign-off                                              [ ]
  Walk-through with user; explicit approval to proceed            [ ]
  Lock §13 resolutions + DD-NN decisions into PRD                 [ ]
  Branch teardown decision (proto code → Phase 1 basis)           [ ]
```

Working tree is clean for v2 work; only the usual unrelated noise
(submodule drift in `app/Lib/cakephp`, `app/files/misp-galaxy`).

## Live test instance

- URL: `http://localhost:5007/dashboards2`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- Admin user id: 1 (`admin@admin.test`)
- DB creds: `mysql -u misp -pPassword1234 misp`

Useful URL switches (prototype-only, both filed as such in the
progress tracker):

- `?theme=midnight` — Level 1 dark token overlay
- `?ui_theme=Overmind` — Level 3 markup override
- Combine: `?theme=midnight&ui_theme=Overmind` works (token paths
  are orthogonal).

To force the proto's hardcoded layout to surface (e.g. after
toolbar pulls have rewritten the saved row):
```bash
mysql -u misp -pPassword1234 misp -e \
  "DELETE FROM user_settings WHERE user_id=1 AND setting='dashboard';"
```

## What Phase 0.3 actually built

The proto has four widgets on a 12-col grid:

```
+-----------+-----------------+--------+
| w_1       | w_2             | w_3    |
| MispStat. | TrendingTags    | OrgMap |
+-----------+-----------------+--------+
| w_4 OrgContributionToplist (full row)|
+--------------------------------------+
```

w_2 and w_4 both declare `time_window`, so the toolbar chip starts
in `(mixed)` on first load — pull it once and both bar charts sync.

Renderers shipped: `SimpleList.ctp`, `BarChart.ctp`, `WorldMap.ctp`.
Charts use a single shared `charts.module.mjs` that lazy-loads
`world-110m.geojson` only for geo widgets.

JS modules under `app/webroot/js/dashboard-v2/`:
- `board.module.mjs` — boot, AJAX-render, save (debounced), action wiring
- `grid/grid.module.mjs` — PDD-driven drag, raw-pointer resize, cascade
- `charts/charts.module.mjs` — option builders + lazy map registration
- `charts/echarts-theme.mjs` — "misp" theme derived from CSS tokens
- `canonical/time_window.mjs` — shared field builder + display helpers
- `configure.module.mjs` — DD-06 two-tier side panel
- `toolbar.module.mjs` — DD-05 bulk-edit chips + popovers

Persistence path:
- Read: `Dashboards2Controller::index` → `UserSetting:dashboard` →
  `LayoutFixup::applyReadFixups` → fallback to hardcoded proto if
  the row is empty.
- Write: every toolbar commit and configure save debounces
  `BoardModule._scheduleSave` (50ms) → `POST /dashboards2/updateSettings`
  → same fix-up → `UserSetting->setSetting`.

Drag/resize commits don't fire `_scheduleSave` yet — that's
deliberate, see "Open question" below.

## Commits this session (in order)

```
4d926b9ce new: BarChart renderer + ECharts theme module
23afe0c3c chg: use 7d in proto seed config; record canonical-type adapter as discovered
67c1d19cc chg: bump TrendingTags proto seed to time_window:-1
fa61f8fcf new: WorldMap renderer via ECharts geo
ae77b44b6 fix: gate widget drag by edit mode
d170ce04d fix: antimeridian-split world GeoJSON
96cf753af new: schema-driven two-tier configure side panel
edaedbd1f chg: time_window picker accepts custom values
7997e6f1b chg: file date_range canonical-type as Phase 3 follow-up
181f43369 new: toolbar bulk-edit chip + popover for time_window
0e1176cea fix: form inputs overflow popover + missing format hint
9683fafad new: seed second time_window declarer to demo Model 4
5c272cf6a new: persistence via UserSetting:dashboard + on-read fix-ups
10ef345c8 new: midnight overlay theme + ?theme proto activation
1edb62c56 fix: readability on midnight overlay (labels, countries, links)
1047d29db new: Overmind wrapper override demos Level 3 retheming
14185ad99 fix: ?ui_theme requires viewClass=Theme to trigger override
a1fd23b58 fix: Overmind title bar needs user-select:none to drag
```

## Gotchas a fresh session needs to know

These bit me this session. All of them are in the progress tracker
already but worth surfacing here so a fresh session doesn't re-step
on them.

1. **`$this->theme = 'X'` alone doesn't switch Cake's resolver.**
   You also need `$this->viewClass = 'Theme'`. MISP's `AppController::
   beforeFilter` flips both based on the user's saved `ui_theme`, but
   our proto path forces them independently. Without `viewClass`,
   `$this->element()` keeps resolving to the default location.

2. **MISP's `validate_json` UserSetting hook trips on PHP 8.3 when
   the value is a nested array.** Pass a JSON *string* to
   `UserSetting->setSetting` (`json_encode` the array in the
   controller). v1 worked because v1's JS submits a form-encoded
   string. beforeSave then passes the string through unmodified.

3. **`world-atlas@2.0.2` TopoJSON has Russia / Fiji / Antarctica
   encoded as single polygons crossing the antimeridian.** ECharts
   draws those as horizontal grey bands. The Phase 0.2 vendoring
   that used `topojson-client.feature()` directly inherited the bug.
   Fix is in `vendor/VENDORING.md`: a `polygon-clipping` post-pass
   splits antimeridian-crossing rings. **Re-applies on any
   re-vendoring**. `d3-geo-projection`'s `geoStitch` only handles
   the inverse direction.

4. **PDD's `draggable()` is registered once.** Edit-mode gating
   uses PDD's `canDrag` predicate that reads the board root's
   `data-misp-board-mode` attribute at gesture-start — no re-bind
   needed when the mode flips.

5. **`user-select: none` is required on any custom drag handle
   element.** Without it the browser starts a text selection on
   mousedown and PDD never sees the drag intent. Cost me one
   round-trip on the Overmind override.

6. **Form input `width: 100%` overflows its parent without
   `box-sizing: border-box`.** Common bug — added border-box to
   `.misp-field-input` / `.misp-field-select` / `.misp-kv-*` after
   the toolbar popover surfaced it.

7. **ECharts' default bar value-label colour is black + white
   stroke** (browser-style "contrasts against anything"). On a dark
   overlay both look wrong. Theme registration now drives
   `bar.label.color` from the text token + drops the stroke.

8. **Country fill on the world map can't use `--misp-dash-surface`.**
   That token is *page-bg* (always darker than the widget body =
   surface-raised), so non-active countries disappear on dark. Use
   `--misp-dash-border` for fill + `--misp-dash-border-strong` for
   outline; both stay one step apart in both themes.

9. **Existing-from-other-sessions row in `user_settings`.** This DB
   already has dashboard rows for users 183 and 187. Admin (user 1)
   may have one too if any test left it behind — delete it (see SQL
   above) to surface the proto's fallback layout.

## Open thread / next obvious work

**Phase 0.4 sign-off is mostly user-driven** — walk-through (effectively
done if the user approves at session start), PRD lock-in (folding
"Resolved questions" + "Discovered work" entries back into PRD §13
with strikethrough; also the PRD §8.1 wording correction), and the
branch-teardown decision (proto code IS the Phase 1 basis, so
"teardown" is really just a rename pass).

**Phase 1 transition (proto → in-place v2)** when the user
greenlights it:
1. `git mv app/Controller/Dashboards2Controller.php …/DashboardsController.php`
   (after removing or migrating v1). Update ACL whitelist key
   `dashboards2 → dashboards`. Update routes if any.
2. `git mv app/webroot/js/dashboard-v2 app/webroot/js/dashboard`
   and update import paths.
3. `git mv app/webroot/css/dashboard/dashboard.default.css` stays;
   only the directory naming follows from the rename.
4. `git mv app/View/Elements/dashboard-v2 app/View/Elements/dashboard`
   and `Themed/Overmind/Elements/dashboard-v2 → dashboard`.
5. `Dashboards2/index.ctp` → standalone test page is dropped;
   replace with `DashboardsController::index()` setting
   `$this->layout = 'default'` (the regular MISP layout) and a
   trimmed `index.ctp` that just emits the board markup + script
   tag. Theme inheritance happens automatically through Cake's
   active-theme chain.
6. The `?theme=midnight` / `?ui_theme=Overmind` proto switches
   are dropped — MISP's user-theme + `enable_themes` config drive
   activation in production.

**Discovered work parked for later phases** (full notes in
`dashboard-progress.md`):
- canonical→legacy `time_window` adapter (Phase 2)
- `date_range` as a separate canonical type (Phase 3 + PRD §5.5
  revision)
- PRD §8.1 wording: theme activation belongs to MISP's theme
  system, not a dashboard toggle (folds into Phase 0.4 PRD lock-in)
- drag/resize commit callback in `grid.module.mjs` so the
  BoardModule can fire `_scheduleSave()` on layout commits (Phase 1)
- `TrendingAttributesWidget` blows up on PHP 8.x via a CakePHP
  `Attribute` model name collision (pre-existing MISP issue, not
  v2; documented in the Model 4 demo Done note)

## Convention reminders

- Commit per progress-tracker task; never `git add -A`; reference
  the task in the commit body.
- New files land with `iglocska:iglocska` ownership; `chgrp www-data`
  before committing to match repo convention.
- The wrapper element + Themed override pattern from Phase 0.3 is
  the playbook for any future override surface (config form panel,
  toolbar, gallery cards). Stay attribute-driven; class names are
  themeable.
