# Dashboard v2 — Session handoff (2026-05-16, late)

Brief read-out for a fresh session to pick up cleanly. Authoritative
state still lives in:

- `dashboard-prd.md` — spec (self-contained; §13 + §15 catalogue
  binding decisions inline)
- `dashboard-progress.md` — task state, Done notes, Discovered work
- `dashboard-design-decisions.md` — DD-01..DD-08 binding decisions
  (full rationale, alternatives, reversibility)

This file is the bridge: ephemeral session-level context that doesn't
fit the durable docs. Replace it as work progresses.

## TL;DR

**Phase 1 v1-removal band is FULLY CLOSED.** Five tasks across this
session (plus one in the prior session). Net: ~190 LoC stripped from
misp.js, 4 gridstack assets gone, 18 lines of dead CSS out of main.css,
11 orphaned v1 widget renderers (1220 lines) deleted, and the v1
controller / view tree carryovers were already absorbed pre-session.

**Phase 1 rename pass is 6/7 done.** The remaining task — strip the
standalone `<!DOCTYPE html>` from `Dashboards/index.ctp` and set
`$this->layout = 'dashboard'` — is bundled per DD-08 with the new
`Layouts/dashboard.ctp` creation in the additive band. It'll land
together with the layout work, not standalone.

**Next session = additive band.** Design-heavy work per DD-08: custom
`app/View/Layouts/dashboard.ctp` mirroring `default.ctp` minus the
side-menu region, header bar with the DD-05 toolbar chips + edit
toggle + "⋯ More" dropdown for the four template actions, side-menu
`case 'dashboard':` deletions, first-load default + empty-state,
DashboardURLValidator helper, drag/resize commit callback wiring.

User's framing carries forward: *"don't get hung up on the prior
design, I would like to go for something modern and pleasant to work
with"* (2026-05-13). Favour generous whitespace, soft visual weight,
subtle shadows, smooth keyboard navigation. Match the proto's
existing configure side-panel aesthetic. Stay away from BS2.3-era
dropdown styling even though the host theme is BS2.3.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [/]
  v1 audit + removal (CLOSED):
    Audit pass (inventory + reverse-grep)                         [x]
    Copy carryover actions + views into Dashboards2               [x]
    Delete v1 DashboardsController.php                            [x]
    Delete v1 View/Dashboards/ tree                               [x]
    Remove v1 dashboard JS from misp.js                           [x]  this session
    Remove v1 dashboard CSS from main.css (discovered)            [x]  this session
    Remove Gridstack vendored assets                              [x]  this session
    Delete orphaned v1 widget renderers (discovered)              [x]  this session

  Rename pass (6/7):
    Controller rename + ACL                                       [x]  this session
    JS tree rename                                                [x]  this session
    Elements tree rename                                          [x]  this session
    Themed/Overmind Elements tree rename                          [x]  this session
    View/Dashboards2 → View/Dashboards rename                     [x]  this session
    Drop proto-only ?theme= / ?ui_theme= activation               [x]  this session
    Strip <!DOCTYPE> + set $this->layout = 'dashboard'            [ ]  bundled w/ layout creation per DD-08

  Additive band (new Phase 1 work):                               [ ]  ← NEXT
    Create app/View/Layouts/dashboard.ctp                         [ ]  marquee task
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
(submodule drift on `app/Lib/cakephp` + `app/files/misp-galaxy`,
scratch files in repo root, untracked side-projects in subdirs).

## Live test instance

- URL: `http://localhost:5007/dashboards`  ← renamed from `/dashboards2`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- Admin user id: 1 (`admin@admin.test`)
- DB creds: `mysql -u misp -pPassword1234 misp`

The proto-only `?theme=` / `?ui_theme=` query-param switches are
**gone** as of `6f45d2dbb`. Production theme activation is MISP's
regular per-user theme system in `AppController::beforeFilter()`.
There is no dashboard-specific theme toggle.

To force the hardcoded default layout to surface (e.g. after toolbar
pulls have rewritten the saved row):
```bash
mysql -u misp -pPassword1234 misp -e \
  "DELETE FROM user_settings WHERE user_id=1 AND setting='dashboard';"
```

## What this session committed (in order)

```
abec4d08d  chg: strip v1 dashboard JS from misp.js (137 lines + the
                trailing blank; reverse-grep clean across app/)

bd2fe63ee  chg: remove Gridstack vendored assets (2 tracked via git rm,
                4 untracked .bk + package.json + package-lock via plain
                rm; deviated from "clean entries" wording — deleted the
                package files outright since they were never tracked
                and v2 has no npm pipeline)

997438009  chg: strip v1 dashboard CSS leftover from main.css (18-line
                block at main.css:2752–2769; discovered work promoted
                into the v1-removal band)

abc68533e  chg: rename Dashboards2 → Dashboards (controller + view tree
                combined per the Cake convention coupling; **but only the
                bare git mv operations were staged — content edits were
                forgotten. HEAD broken at rest.**)

96a305ee5  fix: complete the rename — stage the content edits
                (fix-forward for abc68533e: class rename, PHPDoc trim,
                URL strings, ACL block merge including the discovered
                duplicate-key bug, board.module.mjs comment URL)

0276cc38c  chg: rename js/dashboard-v2/ → js/dashboard/ (13 files moved
                via git mv; all internal ESM imports are relative so no
                import statements changed; 7 absolute-path / external
                refs updated)

efa7e4b9f  chg: delete orphaned v1 widget renderers (discovered audit-
                miss surfaced by the next rename hitting a directory
                collision; 11 files / 1220 lines gone from
                app/View/Elements/dashboard/ — widget.ctp + Widgets/*)

3af9d320a  chg: rename Elements/dashboard-v2/ → Elements/dashboard/
                (default + Themed/Overmind override combined per the
                Cake theme-resolver coupling; 5 files renamed, 7 PHPDoc
                + comment updates)

6f45d2dbb  chg: drop proto-only ?theme= / ?ui_theme= activation paths
                from DashboardsController + Dashboards/index.ctp
```

9 commits + 1 fix-forward = 10 total this session. All signed
(`%G?` = `U` — good signature, unknown trust per the local GPG db).
Total LoC moved: ~190 lines of v1 misp.js gone, 18 lines of dead CSS
gone, 1220 lines of v1 widget renderers gone, 4 gridstack asset files
deleted (~280KB), 5 directories renamed across the controller / view
/ JS / Elements / Themed trees with full callsite + comment audit,
proto-only theme activation block stripped (~47 lines).

## Lessons from this session that the next session should bake in

These bit me; don't make me bite you twice.

1. **`git mv` does NOT auto-stage subsequent content edits to the moved
   file.** When you do `git mv X.php Y.php` then edit Y.php, the edit
   sits **unstaged** while the rename sits **staged**. `git status`
   shows `RM` for those files. If you `git commit` without an explicit
   `git add Y.php`, the commit lands the bare rename only — HEAD is
   broken at rest even though your working tree (and any test that
   reads from the working tree) is fine.

   Pattern to adopt: after editing renamed files, ALWAYS run
   `git status --short` and verify every modification you intend to
   commit shows in the LEFT column (`M ` or `R `, not ` M` or `RM`).
   Stage each explicitly by path. Never trust the state from a prior
   `git mv` to roll forward.

   I hit this on `abc68533e` — see the fix-forward in `96a305ee5`
   for the recovery path. Per the user's git rule (always create new
   commits, never amend), the fix is a follow-up commit, not a rewind.

2. **Rename-pass tasks are often functionally entangled and should
   land together.** CakePHP's convention couples the controller class
   name to the View/<Name>/ template directory: rename one without the
   other and Cake 500s looking for templates in the wrong place. Cake's
   theme resolver couples the default Elements/<path>/ directory to
   the Themed/<Name>/Elements/<path>/ override: rename one without the
   other and the override silently no-ops. Both pairings landed as
   single commits this session (`abc68533e` for controller+view tree,
   `3af9d320a` for Elements+Themed). Per the user's per-task convention
   the commit message should explicitly tick both tracker tasks and
   explain the coupling.

3. **Rename-pass collisions on existing target paths are usually
   v1-audit misses.** Twice this session a directory rename hit a
   pre-existing target — `Elements/dashboard/` carried 11 orphaned
   v1 widget renderers plus 2 active user-dashboard files. Same
   pattern as the `main.css` discovery from earlier (v1 CSS block the
   audit didn't enumerate). When a collision shows up, **first
   reverse-grep the existing target** for callers; if it's pure v1
   orphan, promote into the v1-removal band, delete in its own
   commit, then proceed with the rename in the next commit.

4. **The harness requires Read-after-rename before Edit.** When you
   `git mv` a file then try to Edit at the new path, the harness
   blocks the edit ("File has not been read yet"). Read the new path
   first (even just a few lines around the edit target), then Edit.
   This came up several times this session.

5. **ACL component duplicate-key bug after a key rename.** When the
   v2 ACL key `'dashboards2'` was renamed to `'dashboards'`, the v1
   `'dashboards'` ACL block (lines 175–186) hadn't been deleted in
   the v1-removal pass. PHP arrays silently keep only the last entry
   for duplicate keys, so the carryover actions would have lost their
   ACL. Merge the two blocks — narrow the action set to match the
   actual controller's surface (drop stale entries like `getForm` /
   `getEmptyWidget` that no longer have implementations). Confirmed
   on this session's commit `96a305ee5`.

The prior session's gotchas still apply:

6. **GPG agent times out the commit signature** if the pinentry dialog
   isn't completed promptly. Symptom: `signing failed: Timeout` from
   `gpg`. Fix: from the user's terminal, run
   `echo "test" | gpg --clearsign > /dev/null`, enter the passphrase
   to prime the agent, then retry the commit. The user explicitly
   wants signed commits — never `--no-gpg-sign` without asking.

7. **The grid root `.misp-dashboard-main` has CSS padding** that the
   grid math has to account for (Phase 0.3 latent bug, fixed in
   `04c2e308f`). Watch for this if Phase 1's new layout introduces
   additional padding on the new layout — the math now reads padding
   off `getComputedStyle`, so as long as the padding lives on the same
   container (`data-misp-board-root`), it self-corrects.

8. **`save_template.ctp:4` has `url => 'saveDashboardTemplate'`** —
   action-name mismatch (the action is `saveTemplate`). v1 has had
   this for years; carried verbatim into Dashboards2 per the carryover
   protocol. Phase 4 reimplementation fixes it. Don't "fix" it as a
   side-quest during Phase 1.

9. **`DashboardsController`'s `$components` doesn't declare
   `RestResponse` / `Flash` / `CRUD` / `IndexFilter`** explicitly —
   they come through `AppController` inheritance. If a fresh session
   sees an `Undefined property ::$CRUD` error, double-check
   AppController.php line 81+ first before adding to the controller's
   own components list.

10. **`render_widget.ctp` is referenced by `DashboardsController::
    renderWidget`** — it's the AJAX response template for widget
    re-renders. Don't accidentally delete it during any future view
    sweep. It stays.

## Discovered work parked for later (deferred)

- **Cosmetic naming sweep:** `// dashboard-v2 — …` header comments at
  the top of each `.mjs` file (8 files), `<title>dashboard-v2 prototype
  — MISP</title>` at `Dashboards/index.ctp:8`, `<title>` and `<h1>`
  in `webroot/js/dashboard/proto/demo.html`, and the headers of the
  two CSS files at `webroot/css/dashboard/dashboard.{default,midnight}.
  css:2`. None are functional refs; all are project-nickname mentions
  that can be cleaned up holistically once the rename pass closes.

- **Dormant `dashboard.midnight.css` loader:** `Dashboards/index.ctp:10`
  still unconditionally loads `dashboard.midnight.css` even though the
  `data-theme="midnight"` attribute is no longer emitted anywhere
  (proto activation stripped in `6f45d2dbb`). The CSS is gated entirely
  by `:root[data-theme="midnight"]` selectors so it's loaded-but-
  dormant on every dashboard page. Worth dropping the `<link>` (and
  possibly the file) once the new layout / DD-08 chrome lands. The
  file's own header documents that its production replacement is the
  Themed/<Name>/webroot/css/... pattern, not this overlay.

- **Antimeridian splitting recipe** in `vendor/VENDORING.md` (re-apply
  on any future world-atlas re-vendoring). Phase 0.3 detail.

- **`TrendingAttributesWidget` blows up on PHP 8.x** via a CakePHP
  `Attribute` model name collision (pre-existing MISP issue, not
  v2-specific; documented in the Phase 0.3 Model 4 demo Done note).

## Open thread / next obvious work

**The marquee task: create `app/View/Layouts/dashboard.ctp` per DD-08.**

Pattern: mirror `app/View/Layouts/default.ctp`'s chrome (CSS/JS
includes, top nav, flash messages, footer) with the side-menu region
omitted entirely. The view sits in the full content column. Then in
the same commit:

- Strip the standalone `<!DOCTYPE html><html>…</html>` markup from
  `Dashboards/index.ctp` — the layout now provides it.
- In `DashboardsController::index()`, change `$this->layout = false;`
  to `$this->layout = 'dashboard';`.
- The dashboard view emits only its own markup + the
  `<script type="module">` tag.

This closes the last rename-pass task (task 7) as a byproduct.

**The design-heavy task: header bar "⋯ More" dropdown per DD-08.**

Hosts the four template actions (Import / Export / Save Template /
List Templates), each pointing at the v1-carryover URLs. WAI-ARIA
Menu Button pattern: `aria-haspopup="menu"`, `aria-expanded`, Escape
closes, Up/Down navigates, Enter activates. Tab-walkable focus order
across the entire header (title row + DD-05 toolbar chips + Edit
toggle + ⋯ More).

User's direction is "modern and pleasant" — favour generous whitespace,
soft visual weight, subtle shadows, icons in dropdown items, smooth
keyboard navigation. Stay away from BS2.3-era dropdown styling even
though the host theme is BS2.3. Match the proto's existing configure
side-panel aesthetic.

**Side menu deletion (2 tasks).** Per DD-08: delete the
`case 'dashboard':` block in `app/View/Elements/genericElements/
SideMenu/side_menu.ctp` (lines 9–46 pre-delete) and the same in the
`Themed/UiBeta` mirror. The new layout doesn't render side_menu at
all, so a stale caller would silently no-op — but grep cleanly anyway
for `'menuList' => 'dashboard'` callers to make sure none remain.

**Lower-effort additive tasks** (good for ending a session cleanly):

- **`DashboardURLValidator` helper** under `app/Lib/Dashboard/Tools/`
  per DD-03. Phase 5 renderers will use it from day one; Phase 1
  introduces the helper + a smoke test so the contract is in place.
- **Drag/resize commit callback** in `grid.module.mjs` so
  `BoardModule._scheduleSave()` fires on layout commits. The proto
  deliberately omitted this — layout changes don't persist today.
- **First-load default + empty-state element** — load layout from
  `dashboards.default = 1` row if present; else hardcoded fallback
  (single MispStatusWidget). Empty-state element for when both the
  user's `UserSetting:dashboard` and any default template are empty.

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  the commit body references the task.
- **Always `git status --short` + explicit `git add` before commit**,
  especially after any `git mv` (see lesson #1 above).
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
- Surface context status when past 75% at task boundaries so the
  user can choose to restart.
