# Dashboard v2 — Session handoff (2026-05-13, late)

Brief read-out for a fresh session to pick up cleanly. Authoritative
state still lives in:

- `dashboard-prd.md` — spec (now self-contained; §13 + §15 catalogue
  binding decisions inline)
- `dashboard-progress.md` — task state, Done notes, Discovered work
- `dashboard-design-decisions.md` — DD-01..DD-08 binding decisions
  (full rationale, alternatives, reversibility)

This file is the bridge: ephemeral session-level context that doesn't
fit the durable docs. Replace it as work progresses.

## TL;DR

**Phase 0.4 is closed.** All three sign-off tasks ticked — walk-through
(green from user), PRD lock-in (split across three sub-commits), and
branch-teardown decision (proto IS Phase 1 basis).

**Phase 1 is in flight.** v1-removal band is ~50% done: v1 controller
and view tree are gone, the five template carryover actions live
inside `Dashboards2Controller` already. Remaining v1-removal: strip
the dashboard JS block from `misp.js` (lines 5592–5728) and remove
the Gridstack vendored assets + `package.json` entries. After that:
the rename pass (proto → canonical paths), the new in-page header
chrome (per DD-08), and the smoke-test close-out.

**DD-08 is the new design call this session.** The dashboard does not
use MISP's side menu. It runs under a custom `app/View/Layouts/
dashboard.ctp` and hosts all its actions in the header bar: DD-05
toolbar chips + edit-mode toggle + "⋯ More" dropdown for the four
template actions (Import / Export / Save Template / List Templates).
"Add Widget" is deferred to Phase 2.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]
  Walk-through with user; explicit approval to proceed            [x]
  Lock §13 resolutions + DD-NN decisions into PRD                 [x]
  Branch teardown decision (proto code → Phase 1 basis)           [x]

Phase 1 — Frame (in-place replacement)                            [ ]
  v1 audit + removal:
    Audit pass (inventory + reverse-grep)                         [x]
    Copy carryover actions + views into Dashboards2               [x]
    Delete v1 DashboardsController.php                            [x]
    Delete v1 View/Dashboards/ tree                               [x]
    Remove v1 dashboard JS from misp.js                           [ ] ← NEXT
    Remove Gridstack vendored assets                              [ ]

  Rename pass (proto → canonical paths)                           [ ]
    7 tasks — see dashboard-progress.md

  New Phase 1 work (DD-08 + standard new work)                    [ ]
    Create app/View/Layouts/dashboard.ctp                         [ ]
    Header "⋯ More" dropdown (WAI-ARIA Menu Button)               [ ]
    Delete side_menu.ctp `case 'dashboard':` (default)            [ ]
    Delete side_menu.ctp `case 'dashboard':` (UiBeta)             [ ]
    First-load default + empty-state element                      [ ]
    DashboardURLValidator helper                                  [ ]
    Drag/resize commit callback → _scheduleSave()                 [ ]

  Smoke tests (close-out)                                         [ ]
    4 tasks — see dashboard-progress.md
```

Working tree is clean for v2 work; only the usual unrelated noise
(submodule drift, scratch files in repo root).

## Live test instance

- URL: `http://localhost:5007/dashboards2`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- Admin user id: 1 (`admin@admin.test`)
- DB creds: `mysql -u misp -pPassword1234 misp`

Useful URL switches (prototype-only — DD-08 retires these in the
rename pass):

- `?theme=midnight` — Level 1 dark token overlay
- `?ui_theme=Overmind` — Level 3 markup override
- Combine: both work simultaneously (orthogonal token paths)

To force the proto's hardcoded layout to surface (e.g. after toolbar
pulls have rewritten the saved row):
```bash
mysql -u misp -pPassword1234 misp -e \
  "DELETE FROM user_settings WHERE user_id=1 AND setting='dashboard';"
```

## What this session committed (in order)

```
04c2e308f fix:  grid drag/resize padding-aware math (regression caught
                during walk-through; ghost was misaligned + drop rejected
                because .misp-dashboard-main has 16/24px padding that
                _cellSize / _pointerToCell / _showGhost weren't accounting
                for)
0ca5782fe chg:  Phase 0.4 walk-through approved by user
868e0a7a1 chg:  Phase 0.4 step 1 — §13 lock-in (Q3 resolution inlined,
                Q6/Q7 pointers replaced with detail, Resolved questions
                section stripped from progress.md)
f1b045e14 chg:  Phase 0.4 step 2 — fold architectural Discovered work
                into PRD (§8.1 activation rewritten; §5.5 time_window /
                date_range split + canonical→legacy adapter para)
2f1ddfdcd chg:  Phase 0.4 step 3 — DD-01..DD-07 catalogued in new
                PRD §15 (one-row table per decision)
feceb32a1 chg:  Phase 0.4 task 3 — proto IS Phase 1 basis (greenlit)
b9d5db4c9 chg:  refresh Phase 1 task list for proto-as-basis reality
07e66794c new:  DD-08 — dashboard owns its chrome; side menu skipped
facaaf971 chg:  Phase 1 task list refresh #2 + audit task tick
                (incorporates DD-08: side menu DELETE instead of
                update; new custom layout task; "⋯ More" dropdown task)
742286a6d new:  carry 5 v1 template actions into Dashboards2Controller
                (import / export / saveTemplate / listTemplates /
                deleteTemplate) + 4 views byte-identical
ad6a22614 chg:  delete v1 DashboardsController.php
4a0432df1 chg:  delete v1 View/Dashboards/ tree (10 files)
```

12 commits. Total LoC: PRD grew ~150 lines (§13 detail + §15 +
§5.5 adapter para + DD-08 wording); progress.md shrank net ~300
lines (Resolved questions + 3 Discovered-work entries folded into PRD);
DD log gained DD-08 (~95 lines); v1 surface deleted: 1 controller
(444 L) + 10 views (584 L) gone, with 5 actions + 4 views (439 L)
duplicated into Dashboards2 as Phase 1 carryovers.

## Binding decisions added this session

**DD-08 (2026-05-13) — Dashboard owns its chrome; side menu skipped.**
Custom Cake layout `app/View/Layouts/dashboard.ctp` (mirror of
`default.ctp` minus the side-menu region). All actions live in the
dashboard's header bar: DD-05 canonical-type toolbar chips, edit-mode
toggle, future Phase 2 Add Widget, and a "⋯ More" dropdown grouping
the four low-frequency template actions (Import / Export / Save
Template / List Templates) wired to v1-carryover URLs. Side-menu
`case 'dashboard':` blocks deleted in Phase 1 from both
`Elements/genericElements/SideMenu/side_menu.ctp` and the
`Themed/UiBeta` mirror. A11y is binding: WAI-ARIA Menu Button pattern
on "⋯ More"; Tab-walkable header. Full rationale in
`dashboard-design-decisions.md`; PRD §15 row added.

User's framing on this: *"don't get hung up on the prior design,
I would like to go for something modern and pleasant to work with"*
(2026-05-13). This is the latitude for the new Phase 1 chrome.

## Gotchas a fresh session needs to know

These bit me this session.

1. **GPG agent times out the commit signature** if the pinentry dialog
   isn't completed promptly. Symptom: `signing failed: Timeout` from
   `gpg`. Fix: from the user's terminal, run
   `echo "test" | gpg --clearsign > /dev/null`, enter the passphrase
   to prime the agent, then retry the commit. The user explicitly
   wants signed commits — never `--no-gpg-sign` without asking first.

2. **The grid root `.misp-dashboard-main` has CSS padding** that the
   grid math has to account for (Phase 0.3 latent bug, fixed in
   `04c2e308f`). Symptom: ghost during drag misaligned to the right;
   drop rejected. Watch for this if Phase 1 introduces additional
   padding on the new layout — the math now reads padding off
   `getComputedStyle`, so as long as the padding lives on the same
   container (`data-misp-board-root`), it self-corrects.

3. **The proto's `?theme=` / `?ui_theme=` query-param activation**
   is going away in the rename pass. Production activation is MISP's
   theme system per PRD §8.1 (also DD-08-adjacent — the dashboard
   has no theme toggle of its own). If you're tempted to keep them
   for "developer convenience", don't — there are no other surfaces
   in MISP that do this and it's not worth the carry cost.

4. **`save_template.ctp:4` has `url => 'saveDashboardTemplate'`** —
   action-name mismatch (the action is `saveTemplate`). v1 has had
   this for years; carried verbatim into Dashboards2 per the carryover
   protocol. Phase 4 reimplementation fixes it. Don't "fix" it as a
   side-quest during Phase 1 — out of scope and harder to track.

5. **`Dashboards2Controller`'s `$components` doesn't declare
   `RestResponse` / `Flash` / `CRUD` / `IndexFilter`** explicitly —
   they come through `AppController` inheritance, verified in this
   session. The carryover actions rely on all four. If a fresh
   session sees an `Undefined property ::$CRUD` error, double-check
   AppController.php line 81+ first before adding to Dashboards2's
   own components list.

6. **`render_widget.ctp` is referenced by `Dashboards2Controller::
   renderWidget`** — it's the AJAX response template for widget
   re-renders. Don't accidentally delete it during the rename pass
   when you sweep `app/View/Dashboards2/`. It stays.

## Open thread / next obvious work

**Immediate next task:** strip the v1 dashboard JS block from
`app/webroot/js/misp.js`. Lines 5592–5728 (137 lines), self-contained,
reverse-grep clean per the audit Done note. Just delete the range
+ tick the task + commit.

**Then:** remove the four Gridstack assets (`gridstack.all.js`,
`gridstack.all.js.bk`, `gridstack.min.css`, `gridstack.min.css.bk`)
and clean the `gridstack` entries from `app/webroot/js/package.json`
and `package-lock.json`. That closes the v1-removal band.

**After the v1-removal band closes:** the rename pass starts. Seven
tasks total. Order matters — `Dashboards2/ → Dashboards/` for the view
tree only works after v1 is gone (which is now true). Same for the
controller. The standalone `<!DOCTYPE html>` in `Dashboards/index.ctp`
gets stripped and `$this->layout = 'dashboard'` is set as part of the
same rename-pass commit (DD-08).

**Phase 1's "⋯ More" dropdown is the design-heavy task.** User's
direction is "modern and pleasant" — favour generous whitespace,
soft visual weight, subtle shadows, icons in dropdown items, smooth
keyboard navigation. Stay away from Bootstrap-2.3-era dropdown styling
even though the host theme is BS2.3. Match the proto's existing
configure side panel aesthetic.

**Discovered work parked for later phases** (full notes in
`dashboard-progress.md`):
- Antimeridian splitting recipe in vendor/VENDORING.md (re-apply on
  any future world-atlas re-vendoring)
- `TrendingAttributesWidget` blows up on PHP 8.x via a CakePHP
  `Attribute` model name collision (pre-existing MISP issue, not
  v2-specific; documented in the Phase 0.3 Model 4 demo Done note)

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  the commit body references the task.
- New files land with `iglocska:iglocska` ownership; `chgrp www-data`
  before committing to match repo convention.
- The proto's wrapper-element + Themed-override pattern is the
  playbook for any future override surface. Stay attribute-driven;
  class names are themeable.
- User wants rigorous pushback, not yes-machine output — surface
  trade-offs, name alternatives, recommend a path, then go with the
  user's call.
- User alternates hitm / afk sessions; tracker docs are the
  ground truth between sessions. Tick one task at a time; the
  Done note carries the deciding context.
