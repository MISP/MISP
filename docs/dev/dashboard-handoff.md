# Dashboard v2 — Session handoff (2026-05-16, evening)

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

**Phase 1 is functionally complete.** All three Phase 1 bands closed
this session — v1 removal (prior session), rename pass (7/7), additive
(7/7). Net for this session: ~580 LoC of new functionality across a
new layout + custom layout for Overmind + ⋯ More dropdown + WAI-ARIA
Menu Button JS + drag/resize/remove persistence + first-load priority
chain + empty-state element + DashboardURLValidator helper with 22
PHPUnit tests. Plus 2 user-reported regressions caught and fixed
inline (chrome typography leak; missing Overmind themed layout).

**Phase 1 close-out smoke tests: 1/4 done** (grep sanity, headless).
3 remain — all need a real browser pass: default-theme E2E,
Overmind-theme E2E, legacy v1-shape row migration on read+save.

**Next session: pick from**
1. Run the 3 interactive close-out smoke tests, then move to Phase 2.
2. UiBeta themed-dashboard-layout audit (UiBeta has its own side_menu
   but no themed `default.ctp` — does the dashboard need a themed
   override the same way Overmind did, or does UiBeta just inherit?)
3. Phase 2 work directly (Authoring UX — schema-driven configure
   form, widget gallery, Add/Edit flows).

User direction carries forward: *"modern and pleasant"* — generous
whitespace, soft visual weight, subtle shadows, no animation
flourish, smooth keyboard navigation.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [x]
  v1 audit + removal                                              [x] (prior)
  Rename pass                                                     [x] 7/7
  Additive band                                                   [x] 7/7
    Custom layout app/View/Layouts/dashboard.ctp                  [x] this session
    Header "⋯ More" dropdown (WAI-ARIA Menu Button)               [x] this session
    Delete case 'dashboard': (default + UiBeta side_menu)         [x] this session
    Drag/resize commit callback → _scheduleSave                   [x] this session
    Persist on widget remove (discovered)                         [x] this session
    First-load default + empty-state                              [x] this session
    DashboardURLValidator + PHPUnit (DD-03)                       [x] this session

  Close-out smoke tests                                           [/] 1/4
    [x] Grep sanity (Dashboards2Controller, dashboard-v2,
        ?theme= refs all gone — including cosmetic header sweep)
    [ ] Default theme E2E: chrome integration, MispStatusWidget
        renders, edit toggle, drag commit + persist regression
    [ ] Overmind theme E2E: BS5 navbar (just landed), title-bar
        drag, configure side panel, toolbar bulk-edit chip
    [ ] Legacy v1-shape row migration: width/height → w/h +
        instance_id mint on read, save canonicalises persisted
        shape, top-level stays bare array (DD-05)
```

Working tree is clean for v2 work; only the usual unrelated noise
(submodule drift on `app/Lib/cakephp` + `app/files/misp-galaxy`,
scratch files in repo root, untracked side-projects in subdirs).

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id: 1 (`admin@admin.test`), password `Password12345`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- **Admin user is currently on Overmind theme** (`UserSetting:ui_theme = "Overmind"`)
  — important for smoke tests; switch back to Default via the user
  profile page if needed.
- DB creds: `mysql -u misp -pPassword1234 misp`

To force the first-load default-template / empty-state surface
(after the new priority-chain logic):
```bash
# Force empty-state path:
mysql -u misp -pPassword1234 misp -e \
  "DELETE FROM user_settings WHERE user_id=1 AND setting='dashboard';"

# Force default-template path (admin has site-admin, bypasses
# selectable + restrict_to_*, so any row with default=1 wins):
mysql -u misp -pPassword1234 misp -e \
  "UPDATE dashboards SET \`default\`=1 WHERE id=<row_id> LIMIT 1;"
# … remember to reset default=0 after.
```

## What this session committed (in order)

```
20f25e642  chg: custom layout app/View/Layouts/dashboard.ctp + view
                scaffold removal + controller layout flag flip
                (bundled per lesson #2 — functionally inseparable)

c5949f222  chg: header "⋯ More" dropdown (WAI-ARIA Menu Button)
                — markup in index.ctp + new menu-button.module.mjs
                (~155 lines, idempotent hydrator) + initMenuButtons
                wiring in board.module.mjs + CSS in dashboard.default.css

d3af9d9c3  chg: drop side_menu `case 'dashboard':` from default
                + UiBeta mirror (bundled per lesson #2 — same theme-
                resolver-coupling pattern as the rename pass)

ff7389045  chg: Grid onCommit → Board._scheduleSave for drag/resize
                persistence (added opts.onCommit to Grid; gates the
                callback on actual x/y/w/h change so no-op drops
                don't trigger network round-trips)

a55db9046  fix: persist on widget remove (1-line follow-up to
                ff7389045 — removeTile bypasses _commit so the
                onCommit hook doesn't catch it; explicit
                _scheduleSave call added with comment)

af1d460e9  new: DashboardURLValidator helper + PHPUnit (DD-03)
                — under app/Lib/Dashboard/Tools/; 22 tests / 34
                assertions covering relative paths, MISP filter
                syntax (`tag:tlp:red`), absolute same/off host,
                scheme/port match, javascript:/data:/vbscript:/
                file: rejection, control chars, no-baseurl
                fallback. Phase 5 wiring deferred.

27b2d8a31  new: first-load priority chain + empty-state element
                (bundled per lesson #2 — same view path):
                UserSetting:dashboard → dashboards.default=1 → empty
                state. Switched to UserSetting::getValueForUser
                (distinguishes "no row" from "saved []", so a user
                who cleared their dashboard stays cleared instead
                of re-grabbing the default template). Deleted
                proto's _defaultProtoLayout helper. New empty_state
                element with soft 56x56 outline glyph + "No widgets
                yet" + hint at the ⋯ menu.

b6ea63df3  fix: scope dashboard typography off body (user-reported
                chrome leak) — moved color/font-size/line-height
                off body.misp-dashboard-page onto compound
                .misp-dashboard-{header,main,footer} + .misp-
                configure-panel selector. Proto's body-level rule
                was bleeding into MISP global_menu + footer text.

3b65111d7  chg: cosmetic sweep, retire dashboard-v2 nickname —
                11 single-line replacements across 10 files (7
                .mjs headers + 2 .css headers + proto/demo.html
                <title>/<h1>). Final grep for "dashboard-v2"
                across app/ returns zero matches. Closes the
                handoff doc's deferred "Cosmetic naming sweep"
                item AND the last sub-check of close-out smoke #4.

a540efdeb  fix: Themed/Overmind/Layouts/dashboard.ctp (user-
                reported BS5 navbar regression) — Phase 1 chrome
                work created Layouts/dashboard.ctp (default) but
                never the Overmind themed mirror, so Cake's
                Themed resolver fell back to the default and
                served BS2.3 global_menu under Overmind. New
                themed layout mirrors Overmind's BS5 chrome path
                (mainOvermind + navbar.ctp + footerBS5 + mispOvermind
                JS) unconditionally — the dashboard is a BS5
                surface by design (DD-08), so the $bootstrap5Pages
                whitelist isn't applicable here.
```

10 commits this session. All signed (`%G?` = `U` — good signature,
unknown trust per the local GPG db).

## Lessons from this session that the next session should bake in

These bit me; don't make me bite you twice.

1. **`Themed/<Name>/Layouts/<layout>.ctp` must exist for every new
   layout you introduce.** Cake's Themed resolver looks for
   `Themed/<active>/Layouts/<name>.ctp` first; if absent, falls back
   to the default. I created `Layouts/dashboard.ctp` but not
   `Themed/Overmind/Layouts/dashboard.ctp`, so under Overmind the
   resolver fell back to the default — which renders the BS2.3
   global_menu element. Overmind doesn't override `global_menu`
   either (it switches chrome at the *layout* level via its own
   `default.ctp`'s `$bootstrap5Pages` whitelist + `navbar.ctp`
   element), so the fallback path served legacy chrome instead of
   Overmind's BS5 chrome.

   Same pattern as the prior session's Themed Elements + Themed CSS
   override coupling. The fix is symmetric — for every new layout,
   audit `ls app/View/Themed/` and decide whether each theme needs
   its own override. UiBeta (next on the list) likely needs the
   same treatment.

2. **`AppController::beforeFilter` already activates Cake's Themed
   resolver from the user's `ui_theme` UserSetting.** Lines 282–294.
   The controller doesn't need to set `$this->theme` for dashboard-
   specific theming — it's already set globally. The only thing the
   dashboard needs is themed files in the right paths.

3. **Hard-refresh after CSS edits.** The `?v=185` cache-buster from
   `AppController::__queryVersion` is hardcoded — same value for
   every asset, doesn't bump per-file. After editing
   `dashboard.default.css`, the browser will serve its cached copy
   until Ctrl+Shift+R (or DevTools → Disable Cache). Hit this twice
   this session — once on the ⋯ dropdown popover (cached pre-CSS
   version had no `position: absolute` rule), once on the typography
   fix verification.

4. **Body-level CSS leaks into MISP chrome once the dashboard runs
   inside Layouts/dashboard.ctp.** The proto's `body.misp-dashboard-
   page { font-size; line-height; color; }` rule worked when the
   dashboard ran standalone but bled into MISP global_menu + footer
   text via inheritance. Fix: scope typography to dashboard-content
   surfaces (`.misp-dashboard-header,.misp-dashboard-main,.misp-
   dashboard-footer,.misp-configure-panel`), not body. Watch for
   other body-level rules that might still leak (background fills
   the inter-chrome gap harmlessly, but anything inheritance-driven
   needs to live below body).

5. **`UserSetting::getValueForUser` vs `getSetting` matters.**
   `getSetting` collapses "no row" and "row exists with empty
   value" to the same `[]`. Use `getValueForUser` directly when you
   need to distinguish — returns `null` for no row, decoded value
   otherwise. The first-load priority chain depends on this: a user
   who explicitly cleared their dashboard shouldn't get the default
   template silently re-imposed on next visit.

6. **MISP test convention is bare `app/Test/*.php`**, NOT Cake's
   `app/Test/Case/...` convention. Pure PHPUnit, no Cake bootstrap,
   no DB. Stub framework classes at the top of the test file via
   `if (!class_exists('Foo', false)) { class Foo { ... } }`. See
   `app/Test/EventTemplateValidatorTest.php` for the `App::uses`
   stub pattern; `DashboardURLValidatorTest.php` (this session)
   mirrors it for `Configure`. Run with
   `./app/Vendor/bin/phpunit app/Test/<Name>Test.php`.

7. **MISP login form has a full CSRF token set** —
   `data[_Token][key]`, `data[_Token][fields]`, `data[_Token][unlocked]`,
   `data[_Token][debug]`. Curl-based login dance needs all four
   extracted from the form's GET response, then POSTed back with
   the user credentials. Admin password is `Password12345`. (The
   handoff before me used `admin` — wrong.) Recipe:
   ```bash
   curl -s -c "$CJ" http://localhost:5007/users/login -o /tmp/form.html
   TKEY=$(grep -oP 'name="data\[_Token\]\[key\]" value="\K[^"]+' /tmp/form.html)
   TFIELDS=$(grep -oP 'name="data\[_Token\]\[fields\]" value="\K[^"]+' /tmp/form.html)
   TUNLOCKED=$(grep -oP 'name="data\[_Token\]\[unlocked\]" value="\K[^"]*' /tmp/form.html)
   TDEBUG=$(grep -oP 'name="data\[_Token\]\[debug\]" value="\K[^"]+' /tmp/form.html)
   curl -s -b "$CJ" -c "$CJ" -L -o /dev/null \
     --data-urlencode "_method=POST" \
     --data-urlencode "data[_Token][key]=$TKEY" \
     --data-urlencode "data[_Token][fields]=$TFIELDS" \
     --data-urlencode "data[_Token][unlocked]=$TUNLOCKED" \
     --data-urlencode "data[_Token][debug]=$TDEBUG" \
     --data-urlencode "data[User][email]=admin@admin.test" \
     --data-urlencode "data[User][password]=Password12345" \
     http://localhost:5007/users/login
   ```
   Then `curl -b "$CJ" /dashboards` works.

The prior session's gotchas still apply:

8. **`git mv` does NOT auto-stage subsequent content edits.** Always
   `git status --short` and verify every modification you intend to
   commit shows in the LEFT column (`M `/`R `, not ` M`/`RM`).
   Stage each by path. Hit this in the prior session; didn't hit
   it this session.

9. **Functionally-coupled tasks should land together.** Rename-pass
   items (controller + view tree, Elements + Themed override),
   first-load + empty-state (same view path), side_menu default +
   UiBeta deletions (theme-resolver coupling). Commit message
   explicitly ticks both tracker tasks and explains the coupling.
   Hit this lesson pattern three times this session — bundled
   accordingly each time.

10. **GPG agent times out the commit signature** if the pinentry
    dialog isn't completed promptly. Symptom: `signing failed:
    Timeout`. Fix: from the user's terminal, run `echo "test" |
    gpg --clearsign > /dev/null`, enter the passphrase to prime
    the agent, then retry. The user explicitly wants signed commits
    — never `--no-gpg-sign` without asking.

## Discovered work parked for later (deferred)

- **UiBeta themed dashboard layout audit.** `Themed/UiBeta/` exists
  and has its own side_menu (whose `case 'dashboard':` block we
  deleted in `d3af9d9c3`), but no `Themed/UiBeta/Layouts/default.ctp`.
  Under UiBeta theme, the dashboard currently uses my default
  `Layouts/dashboard.ctp`. Open question: does UiBeta have its own
  chrome conventions (a la Overmind's BS5 navbar) that would warrant
  a themed `dashboard.ctp` override? `ls app/View/Themed/UiBeta/`
  shows Elements but no Layouts dir at root. Likely no override
  needed, but worth verifying before declaring Phase 1 fully done.

- **Drop dormant `dashboard.midnight.css` loader.** Both
  `Layouts/dashboard.ctp` AND `Themed/Overmind/Layouts/dashboard.ctp`
  load it, but the `:root[data-theme="midnight"]` selector is never
  matched (the `data-theme` attribute is no longer emitted anywhere
  since the proto's `?theme=midnight` activation was stripped in
  `6f45d2dbb`). Loaded-but-dormant on every dashboard page. Could
  be removed from both layouts in a small cleanup. The midnight.css
  file's own header documents that its production replacement is
  the Themed/<Name>/webroot/css/... pattern, not this overlay —
  so dropping the loader doesn't lose anything.

- **Antimeridian splitting recipe** in `vendor/VENDORING.md`
  (re-apply on any future world-atlas re-vendoring). Phase 0.3 detail.

- **`TrendingAttributesWidget` blows up on PHP 8.x** via a CakePHP
  `Attribute` model name collision (pre-existing MISP issue, not
  v2-specific; documented in the Phase 0.3 Model 4 demo Done note).

- **Phase 5 wiring of DashboardURLValidator.** The helper landed
  in `af1d460e9` with tests; Phase 5 renderers (`SimpleList` /
  `BarChart` / `MultiLineChart` / `WorldMap`) need to call
  `DashboardURLValidator::validate($drilldownUrl)` before emitting
  `<a href>`. Not bundled with the helper per the task wording
  ("Phase 5 renderers will use it from day one").

- **`save_template.ctp:4` action-name mismatch** (`url =>
  'saveDashboardTemplate'` — the action is `saveTemplate`). v1 has
  had this for years; carried verbatim into v2 per the Phase 1
  carryover protocol. Phase 4 reimplements the template flows
  in-page per DD-08, fix the mismatch then.

## Open thread / next obvious work

**Option A: close out Phase 1 with the 3 interactive smoke tests.**

These need a real browser pass:

1. **Default theme E2E.** Switch admin's `ui_theme` to `Default`
   (or use a second user without `ui_theme` set). Visit `/dashboards`.
   Verify: dashboard renders inside MISP's BS2.3 chrome (global_menu
   top nav, footer); MispStatusWidget content fetches via AJAX; the
   ⋯ More dropdown opens as a popover (DD-08 WAI-ARIA pattern —
   click toggle, click-outside-closes, Esc returns focus to trigger,
   ArrowDown/Up navigates, Tab dismisses); the Edit-layout toggle
   flips `data-misp-board-mode` and exposes drag handles + resize
   handles; drag a widget to a new cell, drop, **reload the page**
   — new position should stick (regression check on `ff7389045`'s
   onCommit → _scheduleSave wiring); same for resize and remove.

2. **Overmind theme E2E.** Admin user is already on Overmind. Visit
   `/dashboards`. Verify: Overmind's BS5 navbar renders at the top
   (dark, BS5 dropdowns — not BS2.3 black bar); dashboard chrome
   below uses the dashboard's own header (title + toolbar + Edit +
   More); configure side panel opens when clicking a widget's ⚙
   button (DD-06 two-tier form); toolbar's `time_window` bulk-edit
   chip opens its popover on click; nothing visually broken; no
   JS console errors.

3. **Legacy v1-shape row migration.** Craft a UserSetting:dashboard
   row with v1 shape (`width`/`height` instead of `w`/`h`, no
   `instance_id` per widget):
   ```sql
   UPDATE user_settings SET value = '[{"widget":"MispStatusWidget",
   "config":[],"position":{"x":0,"y":0,"width":4,"height":3}}]'
   WHERE user_id=1 AND setting='dashboard';
   ```
   Visit `/dashboards` — `LayoutFixup::applyReadFixups` should
   normalise on read (mint `instance_id`, rename `width/height →
   w/h`). Widgets render. Drag the widget to a new cell, drop —
   the save POSTs back the canonicalised shape. Re-query the row,
   verify `w`/`h` + `instance_id` are present, top-level shape is
   still a bare array (no `{scope, widgets}` envelope per DD-05).

After all three pass, close out Phase 1 entirely and move to Phase 2.

**Option B: UiBeta themed dashboard layout audit.**

Mirror the Overmind investigation for UiBeta: check what chrome
UiBeta uses (if any — it has Elements but no Layouts/, suggesting
it inherits the default), decide whether a `Themed/UiBeta/Layouts/
dashboard.ctp` is needed. Quick (~30 min) given the Overmind
playbook.

**Option C: Phase 2 — Authoring UX.**

Tracker has 26 tasks under Phase 2. Marquee pieces:
- `$schema` property contract on widget classes (PRD §5.7)
- Full-tier `$schema` backfill on 9 widgets (per Q7 Option C)
- Two-tier configure form element (DD-06)
- Widget gallery + Add Widget flow
- Edit-mode vs. view-mode atomic save (DD-05)

Big chunk of work; would want to land the `$schema` contract +
backfill first since the configure form depends on it.

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  the commit body references the task.
- **Always `git status --short` + explicit `git add` before commit**.
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
  user can choose to restart. (This session ended at 32% — well
  inside the safe band; the user requested the handoff proactively.)
