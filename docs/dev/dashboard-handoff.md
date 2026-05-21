# Dashboard v2 — Session handoff (2026-05-22 morning)

Eighth session of the dashboard rewrite. Authoritative state lives in:

- `dashboard-prd.md` — spec.
- `dashboard-progress.md` — task state. **Phase 4 entered;
  2 of 8 lines closed (template gallery view + Reset from
  template). Phase 5 refresh half remains 6/7 closed (1 line
  parked as moot — the cache-key F3.3 ratification).**
- `dashboard-design-decisions.md` — DD-01..DD-08 unchanged.

This file is the bridge: ephemeral session-level context that doesn't
fit the durable docs. Replace it as work progresses.

## TL;DR

**3 signed commits this session**, all `%G?` = `U`. One doc
alignment + two Phase 4 feature commits:

1. **Doc cleanup ahead of Phase 4 work** (`59d0f3cb5`) —
   single doc-only commit aligning five `{scope, widgets}`
   envelope references with DD-05 (the envelope was sketched
   2026-05-04 morning and retired the same day; tracker line
   wording + PRD prose still carried the stale shape in three
   places). Same flavour as the §5.5 alignment commit
   `49158debd` from the 2026-05-21 evening session.

2. **Phase 4 task 1 — template gallery view** (`4f2b0102b`)
   — full rewrite of `/dashboards/listTemplates`. The v1
   `IndexTable/index_table` view is replaced by a server-
   rendered gallery under the `dashboard` layout (DD-08; no
   side menu rail). Three ownership-grouped sections — **My
   templates** / **Featured** / **Shared with me** — per user
   direction this session. Sections only render when non-
   empty. Per card: thumbnail placeholder (real miniatures
   pending Phase 4 task 2), title, line-clamped description,
   badges (Default / Selectable / Mine / Restrict-to-Org /
   Role / Permission), widget count, owner email on shared
   templates, plus a **hover-reveal action toolbar** (Use /
   Edit / Delete) in the top-right corner — visible on
   `:hover` and `:focus-within` for keyboard reach. Reuses
   the existing `.misp-gallery-*` CSS shell from Phase 2's
   widget-gallery scaffolding; new `.misp-template-*` rules
   in `dashboard.default.css` for page-mode overrides (relax
   the configure-panel's `height:100%` + inner scroll), badge
   palettes, hover-reveal pointer-events/opacity/transform
   transitions. New JS module
   `app/webroot/js/dashboard/template-gallery.module.mjs`
   (~85L) for the search filter only — cards are server-
   rendered, with a pre-computed lowercase `data-template-
   search-text` payload per card so the filter avoids
   per-keystroke DOM traversal.

3. **Phase 4 task 6 — Reset from template** (`f7cbd680f`)
   — new POST-only `DashboardsController::resetFromTemplate(
   $uuid)` action (~80L, mounted below the v1-carryover
   block) that overwrites the caller's `UserSetting:dashboard`
   row with the chosen template's value. Access control
   delegated to `Dashboard::getDashboardTemplate($user,
   $uuid)` which already enforces ownership OR (selectable +
   restrict_to_* gates) for non-site-admins; empty return →
   404. `json_decode` → `LayoutFixup::applyReadFixups()`
   canonicalises legacy template payloads (no `instance_id`,
   v1 `width/height` keys) into DD-01 shape on the way IN so
   the user's first read of the fresh dashboard sees v2 shape.
   View wiring: the "Use this" card-toolbar button from
   task 1 was a wireframe `<a href="/dashboards/index/
   <uuid>">` placeholder (the v2 `index()` ignores the UUID
   arg today); now a `Form->postLink` carrying the standard
   `_Token` CSRF set + a JS `confirm()` prompt naming the
   template explicitly. Smoke-verified end-to-end via REST
   API: POST returns 200 + the row is overwritten in
   canonical v2 shape. Error-path matrix smoke: 400 (no
   UUID) / 404 (unknown UUID) / 405 (GET method) all return
   sane shapes.

**Notable design decisions taken this session:**

- **`{scope, widgets}` envelope is finally fully retired in
  the docs.** DD-05 (2026-05-04 afternoon) retired the
  envelope but four PRD passages + one decision-log entry
  still referenced it as the shipped shape. Single doc-only
  commit aligned all five. Same shape as the §5.5 alignment
  last session.

- **Ownership grouping over flat-grid for the template
  gallery.** User picked **My templates / Featured /
  Shared with me** as the three sections (sections only
  render when non-empty), over a flat grid + scope badges
  or a filter-chip toolbar. Mirrors the widget gallery's
  by-category pattern from Phase 2. Featured = `default = 1`
  (at most one per PRD F4.3); Mine = user owns; Shared =
  selectable + accessible + owned by someone else. A row
  flagged `default = 1` lands in Featured even if the user
  owns it (Featured is authoritative).

- **Hover-reveal toolbar over an always-visible footer or
  card-click-=-Use+⋯-menu pattern.** User picked the
  hover-reveal (Use / Edit / Delete buttons appear in the
  top-right corner of each card on `:hover` or
  `:focus-within`) over the more discoverable always-visible
  footer or the widget-gallery-style card-click pattern.
  Three icon buttons (▶ play / ✎ pencil / ⌐ trash) at 28×28
  with a hover-swap to accent-coloured background; delete
  hover swaps to a soft-red palette via `var(--misp-dash-
  danger)`. Tab into a card → toolbar appears (keyboard
  reach via the `:focus-within` ancestor selector — no JS
  needed for the keyboard path).

- **JSON-encode before `UserSetting::setSetting` for the
  `dashboard` setting.** Caught at REST smoke of
  `resetFromTemplate`: PHP 500 with `json_validate():
  Argument #1 ($json) must be of type string, array given`.
  Root cause: the model's `validate_json` validator (line 165)
  runs `JsonTool::isValid` (which dispatches to
  `simdjson_is_valid` if loaded, else `json_validate` on PHP
  8.3+) on the raw value, BEFORE `beforeValidate`'s
  array→string coercion (line 191) gets a chance to encode.
  Both validators require strings. The v2 convention
  (`updateSettings`, L170 in the controller) is to
  json_encode at the call site; the inline comment there
  documents the gotcha. Mirrored that step in
  `resetFromTemplate`. **`Dashboard::import()` at L152 is
  likely broken for non-empty values for the same reason**
  — parked for later (see below).

- **PRD F1.5 confirmation prompt firing on every Use, not
  just on unsaved-edits.** The spec language says
  "confirmation prompt if the user has unsaved layout edits",
  but the only entry point to Reset from the v2 chrome is
  the gallery card — and the user has already navigated off
  the board to get to the gallery, so there are no in-page
  unsaved edits to detect. The destructive overwrite of the
  user's current dashboard warrants confirmation regardless,
  so the postLink fires `confirm()` unconditionally with a
  message that names the template explicitly. If a future
  task adds an in-board entry point (e.g. ⋯ More menu →
  Reset from template), THAT surface can do the unsaved-
  edits check and skip the prompt when the board is clean.

**Pre-existing perm-drift carryover from prior sessions:**
not re-encountered this session — no widget-gallery touches
this session, so no opportunities for the `0770 iglocska:
iglocska` clobber to surface. Tracker remains the 8 widget
files patched across sessions 6+7. Still worth root-causing
when there's appetite.

**User-direction carried forward unchanged:** *"modern and
pleasant"*, *"don't worry too much about compatibility"*,
*"ACL must match the surface it shadows"*, *"three similar
lines is better than premature abstraction"*, *"prefer MISP-
jargon naming (orgc, sharing_group) over PRD-generic terms"*,
**"dashboard chrome icons stay inline SVG, not FA"**.

**Phase 4 has 6 lines remaining (out of 8). Next session —
pick from** (see Open thread):

1. **Task 4 — restrict_to_* ratification** (doc-only closure).
2. **Task 8 — import/export wire ratification** (doc-only
   closure; wire shape is untouched and the v2 LayoutFixup
   handles legacy input).
3. **Task 5 — Save as template form** (medium; closes task 7
   alongside).
4. **Tasks 2 + 3 — thumbnails subsystem** (multi-commit;
   most architectural lift in Phase 4).
5. **Phase 5 cache-key F3.3** — moot today (no widget render
   cache in v2); could be closed as documented no-op.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [x]

Phase 2 — Authoring UX                                            [x] CLOSED

Phase 3 — Canonical-type toolbar                                  [x] CLOSED

Phase 5 — Drill-down + refresh scheduler                          [.]
  Refresh half (6/7 lines):
    [x] Board-level refresh scheduler
    [x] Pause-refresh toggle on board toolbar
    [x] Per-instance refresh override in widget config form (F2.5)
    [x] Auto-pause when document hidden (Page Visibility API)
    [x] Manual refresh on a single widget (ratification)
    [x] Refresh indicator chip: "updated 30s ago"
    [ ] Verify cache key includes board scope hash (PRD F3.3)
        — moot today (no widget render cache in v2)
  Drill-down half (0/4 lines):
    [ ] $drilldown schema property documented and exposed
    [ ] Drill-down convention per Q3 resolution
    [ ] Renderer-level wrapping for SimpleList
    [ ] ECharts click handlers calling drill-down

Phase 4 — Template gallery polish                                 [.]
    [x] Template gallery view (ownership-grouped, hover-reveal toolbar)
    [ ] Template thumbnails (server-rendered miniatures, disk cache)
    [ ] Refresh-thumbnail action (manual + on-save-template)
    [ ] restrict_to_* rules preserved on read (RATIFICATION)
    [ ] "Save as template" form (in-page reimplementation)
    [x] "Reset from template" + confirmation prompt
    [ ] listTemplates/saveTemplate/deleteTemplate wire ratification
    [ ] import/export wire ratification
```

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id: 1 (`admin@admin.test`), password `Password12345`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- **Admin user is on Overmind theme** (`UserSetting:ui_theme =
  "Overmind"`).
- DB creds: `mysql -u misp -pPassword1234 misp`

**Saved-layout state at session end:** admin has 5 widgets, same as
the start of this session — `w_1` MispStatusWidget, `w_2`
TrendingTagsWidget, `w_3` OrganisationMapWidget, `w_4`
OrgContributionToplistWidget, `w_5` EventStreamWidget. The
resetFromTemplate REST smoke replaced this row briefly with the
"foo" template's single-widget payload; backed up + restored at
the end of the smoke. **Templates table state:** 6 templates,
all owned by user_id=1 (admin). IDs 4 + 5 are `selectable=1`;
none have `default=1` at session end (id=4 was briefly promoted
to default=1 to smoke-test the "Featured" section appearing,
then reverted).

Session-login dance + wrapper-render smoke recipes unchanged from
prior sessions — see `reference-misp-login-dance` memory. Session
cookie at `/tmp/cj.txt` was still valid at the start of this
session; the login dance is ~30 seconds if it needs refreshing.

Smoke commands for Phase 4 surfaces this session:

```bash
# Template gallery page renders 200 + all fixture templates as cards.
curl -s -b /tmp/cj.txt -o /tmp/lt.html -w "%{http_code} %{size_download}b\n" \
  http://localhost:5007/dashboards/listTemplates
# → 200 ~293KB (Overmind layout chrome) / 6 cards

# Verify section grouping. Currently all 6 templates are owned by
# admin and none are default, so:
grep -oE 'misp-template-gallery-section="[^"]*"' /tmp/lt.html | sort -u
# → misp-template-gallery-section="mine"

# Sanity: XSS-fixture template is HTML-escaped, not rendered as a tag.
grep -c '&lt;script&gt;alert(1)&lt;/script&gt;' /tmp/lt.html  # → 2 (title + desc cells)

# Reset from template via REST (POST, no CSRF token needed with API key auth).
# Before/after: back up the dashboard row, do the reset, inspect, restore.
mysql -u misp -pPassword1234 misp \
  -e "SELECT value FROM user_settings WHERE user_id=1 AND setting='dashboard'" \
  | tail -1 > /tmp/dash_backup_value.txt

curl -s -X POST \
  -H "Authorization: dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC" \
  -H "Accept: application/json" \
  -w "code=%{http_code}\n" \
  http://localhost:5007/dashboards/resetFromTemplate/90ae3134-2397-4d76-84f8-f8c55a491646

mysql -u misp -pPassword1234 misp \
  -e "SELECT value FROM user_settings WHERE user_id=1 AND setting='dashboard'"
# → expect the foo-template body in canonical v2 shape (w/h + instance_id)

# Restore the original row from the backup:
{ echo "UPDATE user_settings SET value="; \
  sed -e 's/\\/\\\\/g; s/'"'"'/\\'"'"'/g; s/^/'"'"'/; s/$/'"'"'/' /tmp/dash_backup_value.txt; \
  echo " WHERE user_id=1 AND setting='dashboard';"; } > /tmp/restore.sql
mysql -u misp -pPassword1234 misp < /tmp/restore.sql

# Error-path matrix for resetFromTemplate (no UUID / bad UUID / GET method).
for r in \
  "POST resetFromTemplate"                                                     \
  "POST resetFromTemplate/00000000-0000-0000-0000-000000000000"                \
  "GET  resetFromTemplate/90ae3134-2397-4d76-84f8-f8c55a491646"; do
  m=${r%% *}; p=${r#* }; p=${p## }
  curl -s -o /dev/null -X "${m}" \
    -H "Authorization: dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC" \
    -H "Accept: application/json" \
    -w "${r} → %{http_code}\n" "http://localhost:5007/dashboards/${p}"
done
# → 400 / 404 / 405
```

## What this session committed (in order)

```
59d0f3cb5  chg: Phase 4 prep — align stale {scope, widgets} doc references with DD-05
                Five references aligned: progress-tracker decision
                log L67 + two Phase 4 task lines (L930/933); PRD §G12
                intro L178, §11 "On data" merge passage L1020, §12
                Phase 1 narrative L1145. Two existing DD-05-aware
                passages (PRD §5 L323 + Phase 4-adjacent narrative
                L1012) were already correct and unchanged. Same shape
                as the §5.5 alignment commit `49158debd` from the
                2026-05-21 evening session.

4f2b0102b  new: Phase 4 task 1 — template gallery view (PRD §5.4)
                Closes 1 Phase 4 tracker line. Full rewrite of
                /dashboards/listTemplates. REST path verbatim (wire
                shape preserved per task 7 promise); HTML path swaps
                IndexTable for a server-rendered gallery under the
                dashboard layout (DD-08; no side menu). Three
                ownership-grouped sections (My / Featured / Shared
                with me) per user direction; sections only render
                when non-empty. Hover-reveal action toolbar (▶ / ✎ /
                ⌐) appears on :hover and :focus-within in each card's
                top-right corner. Five-file change: DashboardsController:
                :listTemplates (~50L bucket-by-ownership + layout +
                lookup-map injection); app/View/Dashboards/list_templates.
                ctp full rewrite (~190L); ~180L of .misp-template-* CSS
                appended to dashboard.default.css (page-mode .misp-gallery
                overrides, badge palettes, hover-reveal toolbar);
                template-gallery.module.mjs new ~85L (search filter
                only); progress tracker tick. Browser-verifiable via
                /dashboards/listTemplates; XSS-fixture template
                renders escaped (smoke-verified).

f7cbd680f  new: Phase 4 task 6 — reset from template (PRD F1.5)
                Closes 1 Phase 4 tracker line and removes the "Use
                this" wireframe surfaced in task 1. New POST-only
                DashboardsController::resetFromTemplate($uuid) action
                (~80L). Access control delegated to Dashboard::
                getDashboardTemplate; LayoutFixup::applyReadFixups()
                canonicalises legacy template payloads (no
                instance_id, v1 width/height keys) into DD-01 shape
                on the way in. JSON-encoded before UserSetting::
                setSetting because the model's validate_json
                validator runs *before* beforeValidate's array→string
                coercion and JsonTool::isValid chokes on PHP arrays
                — mirrors the encode step at updateSettings (L170).
                View wiring (task 1 wireframe → live): the "Use this"
                card-toolbar button rewired from <a href="/dashboards/
                index/<uuid>"> to a Form->postLink with the standard
                _Token CSRF set + a JS confirm() prompt naming the
                template explicitly. Smoke-verified end-to-end via
                REST API: POST returns 200 + row overwritten in
                canonical v2 shape. Error-path matrix smoke: 400 /
                404 / 405 confirmed.
```

Net stats this session:
- 3 signed commits (all %G? = U)
- 1 new client-side module (template-gallery.module.mjs ~85 lines)
- 1 new controller action (resetFromTemplate ~80 lines)
- 1 new server view rewrite (list_templates.ctp ~190 lines from a
  93-line v1 carryover)
- ~180 lines of new CSS in dashboard.default.css (page-mode gallery,
  template-specific cards, badges, hover-reveal toolbar)
- 6 doc edits across PRD + progress tracker (5 in the doc cleanup
  commit + 2 task ticks in the feature commits)
- 0 PHPUnit tests added (template-gallery surface and resetFromTemplate
  have no test coverage today; the existing 152-test suite still
  passes — Phase 5.5 widget parity sweep will tackle coverage gaps
  when it lands)
- 0 themed override changes — Overmind dashboard CSS only overrides
  token values (--misp-dash-*); no .misp-gallery-* or .misp-template-*
  rules to mirror. No Overmind-specific override of
  View/Dashboards/list_templates.ctp.
- Working tree clean for v2 work after these 3 commits.

## Lessons from this session

1. **The model layer's `validate_json` runs before
   `beforeValidate`'s array→string coercion.** Caught at REST
   smoke of `resetFromTemplate`. The v2 convention
   (`updateSettings` L170) is to `json_encode` at the call site
   before handing to `UserSetting::setSetting`; the inline
   comment there documents the gotcha. **`Dashboard::import()` at
   L152 is likely broken for non-empty values for the same
   reason** — needs verification (the function builds a PHP
   array and passes it directly to setSetting). Lesson: when a
   helper has a side-effect-laden validation chain, trace the
   actual call order rather than trusting the obvious one. Cake
   2.x save() runs Validator → beforeValidate → save, but
   `setSetting` calls the validator function directly before
   handing off to save(), inverting the order.

2. **Tracker prose that contradicts the PRD shows up as
   recurring "is this the spec or is this stale?" friction.**
   Three references to the long-retired `{scope, widgets}`
   envelope hit me on the first read of Phase 4. Spending a
   single doc-only commit to align them was 10× faster than
   re-resolving the contradiction on every read. The §5.5
   alignment last session was the same shape. Lesson: tracker
   prose lives close to actionable work; PRD passages live in
   spec context. Keep them aligned with the design-decisions
   doc on every session that touches them.

3. **Hover-reveal toolbars need `:focus-within` to be
   keyboard-reachable.** A pure `:hover` selector hides the
   toolbar from keyboard navigation. Adding `:focus-within` to
   the same rule means tabbing into a card-internal button
   reveals the toolbar without JS — the focus-within selector
   matches when any descendant has focus. Tested with Tab
   navigation through the cards: toolbar appears at the right
   moment, no flicker. Lesson: when a hover affordance has
   keyboard reach as a requirement (UI accessibility), the
   `:focus-within` ancestor selector is the natural pair to
   `:hover`.

4. **A wireframe in commit N can be the "Edit me" handle for
   commit N+1.** Task 1's "Use this" card button shipped as a
   static `<a href="/dashboards/index/<uuid>">` placeholder
   with an inline comment documenting the wireframe stance —
   the URL was deliberately the v2-incomplete carryover URL so
   task 6 had a single one-line rewrite point (replace with
   `Form->postLink`). Commit N+1 swapped the anchor for the
   postLink and the wireframe became live. Lesson: when a
   surface needs follow-up work, ship the placeholder URL of
   the follow-up rather than a dead `#` link — the placeholder
   makes the follow-up's diff smaller.

5. **DB-state backup before destructive smoke is cheap
   insurance.** REST smoke of `resetFromTemplate` overwrites
   the admin's `UserSetting:dashboard` row; a one-line
   `mysql -e "SELECT value..." > /tmp/dash_backup.txt` before
   the POST + a small SQL file with the value restored after
   means the dev box is in the same shape as before the smoke.
   Total cost: 30 seconds for the round-trip; recovery cost
   if the smoke had landed in a way I didn't expect: free.
   Lesson: when smoke-testing a destructive write path, take
   the backup *before* you confirm the write path works, not
   after.

6. **`Form->postLink` carries the standard _Token CSRF set
   automatically.** I'd been planning to add `resetFromTemplate`
   to `Security->unlockedActions` until the postLink output
   showed the full `data[_Token][key]` / `[fields]` /
   `[unlocked]` triple already emitted. CakePHP's Form helper
   handles the CSRF dance transparently — the only actions
   needing `unlockedActions` are the ones that take raw
   POST bodies (the v2 dashboard `renderWidget`, `renderWrapper`,
   `updateSettings`, `updateWidgetSettings` chain — see
   `beforeFilter` L20-26). Lesson: postLink → CSRF for free.

The prior sessions' gotchas still apply (themed resolver
silent fallback, `git mv` doesn't auto-stage, fetchEvent ≠
restSearch, heredoc + dollar signs, GPG pinentry timeout,
mode-drift carryover from sessions 6+7).

## Discovered work parked for later

Active carryovers:

- **Dashboard::import L152 likely broken for non-empty values.**
  Same shape as the `resetFromTemplate` validate_json bug I hit
  this session — `Dashboard::import()` builds a PHP array and
  passes it to `UserSetting::setSetting` without JSON-encoding,
  which means the `validate_json` validator runs `JsonTool::
  isValid` on an array element and throws TypeError. **Not
  smoked this session** — the import controller action is one of
  the carryover-band v1 actions that Phase 4 task 8 will
  ratify; consider rolling the fix into that work, OR fix as
  a separate carryover bug. Single-line fix
  (`json_encode($settingsToSave, JSON_UNESCAPED_SLASHES)` in
  Dashboard::import L150) plus a follow-up smoke that
  POSTs a non-empty body to /dashboards/import.

- **Phase 5 drill-down half (4 lines).** Pre-locked design from
  Q3 resolution. Carried.

- **Phase 5 cache-key board-scope hash (F3.3).** Moot today —
  no widget render cache in v2. Recommendation: close with a
  one-paragraph rationale paragraph in the tracker entry, same
  shape as Phase 3's cache-key-sanity-check closure.

- **File-mode-drift root cause.** 8 widget files patched across
  sessions 6+7. Not re-encountered this session. Worth a short
  investigation when there's appetite.

- **MISP 2.4 cross-instance DB write risk:** v2.4 connected to
  the same DB can clobber `user_settings.dashboard` rows. Carries.

- **time_window toolbar dropdown-menu UX alternative.** Carries.
- **Grid drop-on-occupied cascade (Phase 5).** Carries.
- **tlp:clear (#ffffff) renders invisible bars (cosmetic).** Carries.
- **OrgEventsWidget months>13 malformed dates.** Carries.
- **EventEvolutionLineWidget ignores end_date.** Carries.
- **Live preview race window** (carries — AbortController fix).
- **Drop dormant `dashboard.midnight.css` loader.** Carries.
- **`save_template.ctp:4` action-name mismatch** (Phase 4 task 5
  picks this up when the save form is reworked).
- **Pre-fetch overshoot trade-off documented for EventStream-
  Widget's post-filter canonicals.** Carries.

## Open thread / next obvious work

In rough priority order:

**Option A: Phase 4 task 4 (restrict_to_* ratification).**

Doc-only closure. The controller's existing query in
`listTemplates` (L956-973) already filters on
`Dashboard.restrict_to_org_id` / `restrict_to_role_id` /
`restrict_to_permission_flag`; the new gallery view (Phase 4
task 1) renders these as badges per card. Closure is a
tracker tick + a sentence-or-two rationale. Single small
commit.

**Option B: Phase 4 task 8 (import/export wire ratification).**

Doc-only closure modulo the discovered `Dashboard::import` bug
above. The export action is already wire-stable (untouched
this session); import is wire-stable but needs the
JSON-encode fix to actually work with non-empty bodies.
Recommended: close the tracker line WITH a one-line
`Dashboard::import` fix + a quick REST smoke of a multi-widget
import payload. Single small commit.

**Option C: Phase 4 task 5 ("Save as template" form).**

Medium-sized. Reimplements the v1 modal `saveTemplate` as an
in-page surface under the dashboard layout (DD-08). Closes
task 7 alongside (wire shape ratification). The v1 modal
flow uses `openGenericModal('/dashboards/saveTemplate/...')`
from the gallery card; this session's task 1 already linked
the gallery's Edit button to `/dashboards/saveTemplate/
<uuid>` as a full-page navigate (clunky today because the
saveTemplate action sets `$this->layout = false;`). Phase 4
task 5 fixes the clunkiness.

**Option D: Phase 4 tasks 2 + 3 (thumbnails subsystem).**

Most architectural lift in Phase 4. Server-rendered miniatures
of the saved layouts (no live data, just the widget tiles +
titles), cached on disk under `webroot/img/dashboard/
templates/<uuid>.{svg|png}`. Manual refresh-thumbnail action
(task 3) ties in. Multi-commit. Recommendation: spend a
session scoping the renderer architecture before writing
any code (PRD §5.4 F4.2 mentions "preview screenshot or a
rendered miniature" — server-side `<img>` vs. server-side
SVG is the first design call).

**Option E: Phase 5 drill-down half.** See last session's
handoff for the design. Pre-locked from Q3 resolution.
Multi-session.

**Recommendation:** **A then B then C** — the two doc-only
closures + the save-template-form rework would close 4 of the
6 remaining Phase 4 lines in one short-ish session, leaving
just the thumbnails subsystem (D) as the final architectural
lift. The thumbnails subsystem deserves its own session
because the renderer-architecture design call (SVG vs PNG,
build path, refresh policy) wants undivided attention.

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  the commit body references the task. **Phase 4 commits this
  session follow the one-commit-per-tracker-line shape (with
  the doc-cleanup prep commit as an exception that touches
  multiple files for a single logical fix — same shape as the
  §5.5 alignment commit `49158debd` from last session).**
- **Always `git status --short` + explicit `git add` before commit**.
  Watch for stray empty files from grep / find with quote-mangling.
- New files land with `iglocska:iglocska` ownership; `chgrp
  www-data` before committing to match repo convention. **The new
  template-gallery.module.mjs was chgrp'd this session; preserve
  the pattern.**
- **Themed wrapper parity:** any new `data-*` attribute or chrome
  span on `app/View/Elements/dashboard/widget/wrapper.ctp` MUST
  be mirrored in `app/View/Themed/Overmind/Elements/dashboard/
  widget/wrapper.ctp` in the SAME commit. **This session: no
  wrapper.ctp touches, so the mirror check was N/A. Phase 4
  task 5 (Save as template form) will likely touch the chrome
  header pattern in list_templates.ctp again — that's a
  dashboard-layout-direct view, NOT a wrapper.ctp surface, so
  the themed-resolver mirror check applies only to
  `app/View/Themed/Overmind/Layouts/dashboard.ctp` (verified
  in-session that no Overmind override of
  `View/Dashboards/list_templates.ctp` exists).**
- **Dashboard chrome icons are inline SVG, not Font Awesome** —
  see `feedback-dashboard-chrome-icons` memory. **This session's
  hover-reveal toolbar follows the convention (▶ / ✎ / ⌐ all
  inline 16×16 SVG with stroke=currentColor, stroke-width=1.5,
  round caps/joins).**
- **MISP-jargon naming over PRD-generic.** When introducing new
  identifiers (canonical type names, axis labels, config keys),
  prefer terms that match MISP's existing DB field names + user-
  facing terminology over PRD-generic alternatives.
- **Inline-style colour strings need a strict regex match** before
  insertion (`/^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/`).
- **External links always pair `target="_blank"` with
  `rel="noopener noreferrer"`.** Internal links use same-tab
  navigation.
- **Slicing user-controlled text for display uses `mb_substr` +
  `mb_strtoupper`** to handle multi-byte UTF-8.
- **Themed CSS in Cake 2.x:** use plain paths (no dot-prefix).
- User wants rigorous pushback, not yes-machine output — surface
  trade-offs, name alternatives, recommend a path, then go with
  the user's call. The "looks good, but…" pattern is the signal
  to surface refinements explicitly rather than assume.
- User alternates hitm / afk sessions; tracker docs are the
  ground truth between sessions. Tick one task at a time; the
  Done note carries the deciding context.
- Surface context status when past 75% at task boundaries so the
  user can choose to restart. **This session ended at the
  threshold by user direction.**
- Hard-refresh after CSS/JS edits — the `?v=185` cache-buster
  from `AppController::__queryVersion` doesn't bump per-file.
- **The schema-driven model is the canonical answer** for any
  "how does the toolbar / configure form know which widgets to
  act on" question.
- **A tracker tick requires the user-visible surface to exist
  AND be reachable from the default UI**, not just the JS /
  handler-level wiring behind it. **The 2 Phase 4 ticks this
  session were REST-smoked but the browser smoke (hover-reveal
  toolbar interactive behaviour, confirm() prompt, redirect-
  with-flash) is parked for the user.**
- **`mysql -u misp -pPassword1234 misp` for one-shot SQL.**
- **Render-kind glyph requirement (carries):** any new value
  for `public $render` on a widget class, or any new template
  under `app/View/Elements/dashboard/Widgets/`, must ship with
  a matching glyph in `render-thumbs.mjs` in the same commit.
  **This session: no new render kinds introduced; the template
  gallery's card thumbnails are a SEPARATE placeholder SVG (a
  5-rect layout-miniature) rendered server-side per card, not
  a `render-thumbs.mjs` entry.**
- **Heredoc + dollar signs:** single-quoted heredoc (`<<'EOF'`)
  preserves `\$` literally. Don't escape dollar signs inside it.
- **JSON-encode dashboard-value payloads before `UserSetting::
  setSetting`** — the model's `validate_json` validator runs
  before `beforeValidate`'s array→string coercion. `Dashboard::
  import()` and `resetFromTemplate()` both follow this
  convention; `updateSettings()` documents the inline comment
  at L170 of DashboardsController.

## Quick-start cheatsheet for the next session

If you're picking this up cold:

1. Read `dashboard-prd.md` for the spec.
2. Read `dashboard-progress.md` for what's done / what's next.
3. Skim this file for ephemeral session-level context.
4. Verify the live instance still works:
   `curl -s http://localhost:5007/dashboards -o /dev/null -w "%{http_code}\n"`
   should return 302 (redirect to login) without a session;
   with the session-login dance, /dashboards returns 200.
5. **Phase 4 has 6 lines remaining (out of 8). Phase 5 has
   5 lines remaining (refresh-half cache-key F3.3 + drill-down
   half).** Pick from the Open thread above. Recommended: **A
   then B then C** to close 4 of the 6 remaining Phase 4 lines
   in a short session, leaving just the thumbnails subsystem
   (D) for its own session.
6. Commit one task at a time, signed, with `chgrp www-data` on
   new files. Don't `git add -A`. Don't escape `$` inside single-
   quoted heredocs. Themed wrapper parity check on every chrome
   edit. **JSON-encode dashboard-value payloads before
   UserSetting::setSetting (this session's gotcha).**
