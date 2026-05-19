# Dashboard v2 — Session handoff (2026-05-19, late session)

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

**Phase 1 is now fully closed.** All three close-out smoke tests
(Default theme E2E, Overmind theme E2E, legacy v1-shape migration)
completed end-to-end on the live dev instance under both themes. **6
signed commits this session, all `%G? = U`.** The per-widget POST
endpoint (DD-05 layout-only atomic save's missing companion) shipped
in `33dc1be18` and was verified at the DB level mid-smoke — a
configure-form Save during edit mode now patches only the affected
widget's config in the saved blob, leaving any staged drag/resize/
remove edits untouched. Three smoke-driven fixes also landed as
independent commits because the browser pass surfaced gaps automated
smoke couldn't see.

**Phase 2 ~17/22 done** (up from ~13/22 at session start). The
configure-form save path is now fully aligned with DD-05's "edit-mode
is a transaction" semantic. Save / Discard buttons in the edit-mode
toolbar finally surfaced (the prior session ticked the Save / Discard
tracker entries as Done with JS-only landings — the UI buttons
themselves never shipped; toggling Edit-layout off silently dropped
staged changes, which confused the user during smoke).

**Phase 3** unchanged at 2/11 canonical types (time_window +
date_range from the prior session). `tag_filter` is the next biggest
user-facing slot and pairs naturally with a chip-input picker
(Phase 2's still-open chip-input task).

**Discovered this session:**

- **Grid drop-on-occupied bounces back instead of auto-placing.**
  Smoke-driven user feedback: dragging onto an occupied cell turns
  the preview red and snaps back to origin. DD-01 deliberately chose
  PDD + custom grid math over Gridstack's cascading displacement;
  re-introducing it is half-day for push-down-on-drop or 1-2 days
  for predictive in-drag preview. Parked as Phase 5 UX polish — natural
  pairing with the widget-gallery Add Widget flow.

- **MultiLineChart renderer was orphaned at Phase 1 cleanup.** Commit
  `efa7e4b9f` deleted the v1 renderers but only BarChart / SimpleList
  / WorldMap got the ECharts port. TrendingTagsWidget's `over_time=
  true` path crashed with `Element Not Found: MultiLineChart.ctp`.
  Ported in `f6da5ab09`. Same shim pattern as BarChart (static
  container + JSON payload attribute + per-kind builder in
  `charts.module.mjs`).

- **TrendingTagsWidget `over_time` path ignored `threshold` AND
  swallowed the tag colours.** Pre-existing v1 bug — bar branch
  sliced to top-N and returned the colours dict; over_time path did
  neither. Fixed in `86f7a1c57`: rank tags by total count across the
  full window, slice top-$threshold, surface colours map via
  `array_intersect_key`. `tlp:clear` is literally `#ffffff` (white)
  which is why the BarChart bars are invisible on a white widget
  surface — separate cosmetic fix opportunity at the renderer level
  (border / fallback colour).

- **`cc6f2c22a` was a premature task tick.** Two Phase 2 tracker
  lines (`Layout-only atomic save` + `Discard`) were marked Done
  when the JS handlers existed but the UI buttons did not. Save /
  Discard surfaced today in `88d1a1c8a` with a body-attribute mode
  mirror so the header CSS can show/hide them based on `data-misp-
  board-mode`. Toggle-mode now confirm-if-dirty routes through
  `_discardEdit` instead of silently dropping staged work.

**Next session: pick from** (see Open thread below)

1. C+H paired: `tag_filter` adapter + chip-input picker — biggest
   user-facing canonical type, ~full day.
2. Widget gallery + Add Widget flow — largest remaining Phase 2
   surface, best as a dedicated session.
3. Phase 5 grid auto-place — half-day for push-down-only.
4. Chip input for arrays + flatten/reNest unit tests + console.log
   cleanup — ~half-day hygiene block.

User direction carries forward: *"modern and pleasant"* — generous
whitespace, soft visual weight, subtle shadows, no animation flourish,
smooth keyboard navigation.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [x]
  Themed/ audit loop                                              [x] 2/2
  Close-out smoke tests                                           [x] 4/4
    [x] Grep sanity
    [x] Default theme E2E
    [x] Overmind theme E2E
    [x] Legacy v1-shape row migration

Phase 2 — Authoring UX                                            [/] ~17/22
  [x] $schema property contract + WidgetSchema helper + 26 tests
  [x] 9 widget $schema backfills (Phase 2)
  [x] Two-tier configure form element — schema-driven
  [x] Live preview, 250ms debounced
  [x] Per-canonical-type field elements (time_window only;
      rest are Phase 3)
  [x] Key-value list component for the bottom tier
  [ ] Chip input component for array-typed values
  [x] Bottom-tier seeding from $placeholder
  [ ] Bottom-tier dot-notation flatten/reNest tests (code exists;
      unit tests missing)
  [x] Side-panel container for configure form
  [ ] Sticky preview pane in configure side-panel
  [ ] Widget gallery + Add Widget flow + Edit Widget flow
  [x] Edit-mode vs. view-mode toggle
  [x] Layout-only atomic save (DD-05)
  [x] Discard (edit mode) with confirm-if-dirty
  [x] Drag/resize/add/remove only fire in edit mode
  [x] Configure-form Save: per-widget POST (NEW this session)
  [x] Save/Discard UI buttons + body-attribute mode mirror
      (NEW this session — was a premature task tick that bit during
      smoke)
  [ ] Console.log cleanup

Phase 3 — Canonical-type toolbar                                  [/] 2/11 types
  [x] CanonicalTypeAdapter helper + 33 PHPUnit tests
  [x] Wire CanonicalTypeAdapter into renderWidget + canonical
      time_window defaults on 3 widgets
  [ ] Implement remaining canonical types (tag_filter / org_filter /
      sharing_group_filter / galaxy_cluster_filter /
      distribution_filter / threat_level_filter / analysis_filter /
      attribute_type_filter / event_id_filter — 9 still pending)
  [ ] Per-canonical-type form field elements (full set)
  [ ] Toolbar control logic + UI + bulk-edit write path
  [ ] New-widget toolbar inheritance + Clear action
  [ ] Canonical-only $schema sweep across remaining ~20 widgets
  [ ] Cache-key sanity check
```

Working tree is clean for v2 work; only the usual unrelated noise
(submodule drift on `app/Lib/cakephp` + `app/files/misp-galaxy`,
scratch files in repo root, untracked side-projects in subdirs).

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id: 1 (`admin@admin.test`), password `Password12345`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- **Admin user is on Overmind theme** (`UserSetting:ui_theme = "Overmind"`).
  Flipped to Default mid-session for Phase 1 E2E, then restored.
- DB creds: `mysql -u misp -pPassword1234 misp`

Saved-layout state at session end: admin has 4 widgets
(MispStatusWidget / TrendingTagsWidget / OrganisationMapWidget /
OrgContributionToplistWidget). w_1 sits at y=8 (was dragged
during the v1-shape migration smoke); other widgets at their
baseline positions. TrendingTagsWidget config is currently
`{time_window: '90d', threshold: 7, over_time: true}` — exercising
the new MultiLineChart renderer.

Force test paths:
```bash
# Force empty-state path:
mysql -u misp -pPassword1234 misp -e \
  "DELETE FROM user_settings WHERE user_id=1 AND setting='dashboard';"

# Force default-template path (admin has site-admin, bypasses
# selectable + restrict_to_*, so any row with default=1 wins):
mysql -u misp -pPassword1234 misp -e \
  "UPDATE dashboards SET \`default\`=1 WHERE id=<row_id> LIMIT 1;"
# … remember to reset default=0 after.

# Theme flip (revert after testing):
mysql -u misp -pPassword1234 misp -e \
  "UPDATE user_settings SET value='\"Default\"' WHERE user_id=1 \
   AND setting='ui_theme';"

# Inject v1-shape blob (for legacy-row migration test):
mysql -u misp -pPassword1234 misp <<'SQL'
SET @v1 = '[{"widget":"MispStatusWidget","alias":null,"config":[],
  "position":{"x":0,"y":0,"width":4,"height":4}}, ...]';
UPDATE user_settings SET value=@v1 WHERE user_id=1 AND setting='dashboard';
SQL
```

Session-login dance for HTML-page curls (REST endpoints use the
API key header per [[reference-misp-login-dance]]):
```bash
CJ=/tmp/cj.txt; rm -f "$CJ"
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
# Cookies in $CJ now carry a valid session.
```

Per-widget patch endpoint shape (new this session):
```bash
# Single-widget patch (configure-form Save shape):
curl -s -b /tmp/cj.txt -X POST \
  -H "Accept: application/json" \
  --data-urlencode 'patches=[{"instance_id":"w_2","config":{"threshold":5}}]' \
  http://localhost:5007/dashboards/updateWidgetSettings

# Bulk patch (toolbar bulk-edit shape — N entries applied atomically):
curl -s -b /tmp/cj.txt -X POST \
  -H "Accept: application/json" \
  --data-urlencode 'patches=[{"instance_id":"w_2","config":{...}},{"instance_id":"w_4","config":{...}}]' \
  http://localhost:5007/dashboards/updateWidgetSettings
# 404 on no-saved-blob (client falls back to whole-blob updateSettings).
# 404 on unknown instance_id (concurrent removal in another tab).
```

## What this session committed (in order)

```
33dc1be18  new: Phase 2 — per-widget POST closes edit-mode leak (DD-05)
                Server endpoint `POST /dashboards/updateWidgetSettings`
                accepts `data[patches]=<JSON array of {instance_id,
                config}>` and patches matching widgets' configs in the
                saved blob, leaving positions + other widgets untouched.
                Single-widget callers send one entry; toolbar bulk-edit
                sends N — all applied in one setSetting() write so
                partial failures can't leave the blob mixed. Client
                gains `_scheduleWidgetSave` with 50ms-debounced
                Map<instance_id, el> batching so the toolbar's N-
                declarer commit collapses to one round-trip. Configure-
                form `onSave` and toolbar `onWidgetChange` both switch
                from `_scheduleSave` to `_scheduleWidgetSave`. The
                `_stageOrSave` docblock's "Known limitation" para
                removed. 7 wire-shape smokes pass.

f6da5ab09  new: Phase 1 carryover — MultiLineChart renderer ported to ECharts
                Surfaced mid-smoke when over_time=true triggered an
                Element Not Found notice. v1 renderer was deleted in
                Phase 1 cleanup (efa7e4b9f) but only BarChart /
                SimpleList / WorldMap got ECharts ports. New
                renderer follows the BarChart shim shape (static
                container + JSON payload attribute) + `buildLineOption`
                builder + `line` registry entry in charts.module.mjs.
                Series collection is union-over-rows; legend in scroll
                mode with 28-char truncation; point markers only when
                ≤20 datapoints. Drilldown deferred to Phase 5.

86f7a1c57  fix: TrendingTagsWidget over_time honors threshold + returns colours
                Pre-existing v1 widget bug — bar branch sliced to
                top-N and returned the colours dict; over_time path
                did neither. Surfaced when smoke noticed the multi-
                line chart showed every tag in the window despite
                threshold=5. Rank tags by total count across the
                full window (per-row top-N would give a different
                set per date = meaningless line chart); slice to
                top-$threshold; surface colours via
                `array_intersect_key`. tlp:clear is literally
                `#ffffff` — also why BarChart's tlp:clear bar is
                invisible on white surface (separate cosmetic
                renderer fix worth chasing).

33b8c5647  chg: discovered work — grid drop-on-occupied cascade (Phase 5)
                User feedback during Round 3 smoke: dragging onto an
                occupied cell turns preview red + snaps back instead
                of cascading. DD-01 chose PDD + custom math over
                Gridstack's auto-displace; reversal is half-day for
                push-down-on-drop or 1-2 days for in-drag preview.
                Parked as Phase 5 UX polish with implementation
                outline + trade-off analysis.

88d1a1c8a  new: Phase 2 — Save/Discard buttons surface the edit-mode transaction
                Surfaced when user reported "no Discard button" mid-
                smoke. `_commitEdit` + `_discardEdit` JS handlers
                shipped in `cc6f2c22a` (last session) but the UI
                buttons never landed. Worse: toggling Edit-layout
                off silently dropped staged changes (setMode('view')
                clears snapshot + dirty flag without saving or
                reverting; the DOM still shows staged drag, so user
                perceives "saved" while DB has the original). Three
                coupled changes: index.ctp gains Save + Discard
                buttons alongside the existing toggle (with .misp-
                dashboard-modecontrols-edit / -view class flavours);
                dashboard.default.css adds visibility rules driven
                by `body[data-misp-board-mode]`; board.module.mjs
                setMode() mirrors the mode attr to body on every
                transition so the header (sibling of the board root,
                not an ancestor) can react via CSS. Defensive: the
                toggle-mode handler now routes through `_discardEdit`
                when landing in toggle while dirty (keyboard /
                devtools paths).

09b179ff5  chg: Phase 1 close-out — three smoke tracker entries ticked
                Default theme E2E + Overmind theme E2E + legacy v1-
                shape migration all marked done with full notes.
                Phase 1 is now structurally closed.
```

6 commits this session, all signed (`%G?` = `U`).

## Lessons from this session

These bit me; don't make me bite you twice.

1. **Don't tick a tracker entry as Done when only the JS landed and
   the UI hasn't.** `cc6f2c22a` ticked the Save / Discard Phase 2
   lines on the strength of the `_commitEdit` + `_discardEdit`
   handlers existing. The view template only had the Edit-layout
   toggle — no Save, no Discard. Toggling the toggle off in dirty-
   layout state silently dropped staged work. The smoke caught it
   on the first edit-mode pass. **Rule of thumb:** a Phase 2 task
   tick requires the user-visible surface (button / form / page)
   to exist AND be reachable from the default UI, not just the
   handler-level wiring behind it.

2. **Browser smokes surface things automated smokes structurally
   can't.** This session's automated wire-shape smokes for the
   per-widget POST passed 7/7. The browser pass surfaced three
   substantial follow-ups (MultiLineChart renderer port, threshold-
   in-over_time bug, Save/Discard UI gap). None of them would have
   appeared without a real human clicking through the flow.
   Schedule the browser smoke EARLY in the session, not as an
   afterthought — surfaced gaps may need their own commits and
   you want time for them.

3. **Per-widget POST + 50ms-debounce-batch generalises.** The
   toolbar's bulk-edit fires N synchronous `onWidgetChange`
   callbacks; Map<instance_id, el> keying collapses them to a
   single bulk POST naturally (Map overwrites on duplicate keys,
   so the same widget touched twice within the window keeps the
   latest config). Pattern works for any future bulk-action that
   touches multiple widgets' configs. Don't over-engineer with a
   coordinator object; the timer + Map is enough.

4. **Body-attribute mirror is the right pattern for header-state
   CSS.** The header is a sibling of the board root, not an
   ancestor, so CSS can't react to the board's `data-misp-board-
   mode` directly. Mirroring the attribute to `<body>` on every
   `setMode` transition lets header CSS use `body[data-misp-board-
   mode="edit"] .x { ... }`. Transferable to any future header-
   state needs (e.g. drag-in-progress indicator, saving spinner,
   ⋯ More dropdown open state).

5. **tlp:clear is literally white (#ffffff) on a white widget body.**
   The user surfaced this during Round 1 of the Overmind smoke as
   "white bars". MultiLineChart hides it because lines are 2px
   wide; BarChart bars are wide and disappear. Renderer-side fix
   needed: either a 1px border on each bar / line segment, or a
   contrast-aware fallback colour when the supplied colour is
   ≥ #f0f0f0 (or computed luminance is high). Parked as a separate
   renderer fix (worth doing alongside the chart-cell drilldown
   work in Phase 5).

6. **Edit-mode is a transaction — make the exits explicit.** Pattern
   that works: toggle button hidden in edit mode, only Save and
   Discard buttons can exit. The CSS visibility hooks (`.misp-
   dashboard-modecontrols-edit` / `-view`) declaratively express
   "show in this mode only". User can't accidentally exit edit
   mode without choosing what to do with their staged work.
   Defensive branch in `toggle-mode` action handler protects
   against bypass paths (keyboard, a11y, devtools).

7. **mysql LOAD_FILE() vs HEREDOC for SQL injection from shell.**
   `LOAD_FILE` requires `secure_file_priv` and file-system
   permissions matching the mysqld user; fails silently with NULL
   in many local setups. mysql stdin via heredoc with a SET @var
   bind is the more robust pattern for one-shot SQL with complex
   string payloads (used for the v1-shape blob injection during
   Round 5). Worth remembering.

The prior session's gotchas still apply:

8. **`git mv` does NOT auto-stage subsequent content edits.** Always
   `git status --short` and verify every modification you intend to
   commit shows in the LEFT column.

9. **GPG agent times out the commit signature** if pinentry isn't
   completed promptly. Symptom: `signing failed: Timeout`. Fix:
   from the user's terminal, run `echo "test" | gpg --clearsign >
   /dev/null`, enter the passphrase to prime the agent, then retry.

10. **`Themed/<Name>/Layouts/<layout>.ctp` must exist for every new
    layout you introduce.** This session: no new layouts, no new
    Themed override files needed. The Save/Discard buttons landed
    in the default `index.ctp` and there's no themed override of
    that view (confirmed by grep). Stay attribute-driven; class
    names are themeable.

## Discovered work parked for later (deferred)

Most this-session items are now in `dashboard-progress.md`'s
Discovered work section. Key ones to know about from a planning
perspective:

- **Grid drop-on-occupied cascade (Phase 5 — parked 2026-05-19).**
  PDD bounces back on collision; users expect Gridstack-style
  auto-displace. Half-day for push-down-on-drop with stable
  iteration (drop tile's height shifts colliding tiles down,
  iterate until stable); 1-2 days for predictive in-drag preview
  (tiles slide aside as the drag tile hovers). Pairs naturally
  with the Widget Gallery / Add Widget flow because placement
  logic for new widgets benefits from the same cascade.

- **tlp:clear (#ffffff) renders invisible bars (surfaced 2026-05-19).**
  Cosmetic renderer fix — add a 1px border to each bar / line
  segment, or detect high-luminance fill colours and substitute
  a contrast token. BarChart bars worst-hit; MultiLineChart less
  visible (lines are 2px). Tracked as cosmetic; not a blocker.

- **OrgEventsWidget months>13 malformed dates.** Wrap-around guard
  `if ($target_month < 1) { $target_month += 12; }` only adds 12
  once instead of looping → dates like `2025--1-01`. Quick fix
  (~15 min): convert to `while`. Carries from prior session.

- **TrendingAttributesWidget pre-existing PHP 8.x Attribute model
  crash.** Carries from prior session. MISP core fix needed.

- **Configure-form Save in edit mode leaks staged layout.** **CLOSED
  THIS SESSION** by `33dc1be18` per-widget POST + DB-level smoke
  verification. Discovered-work entry can be retired.

- **EventEvolutionLineWidget ignores end_date.** Carries from prior
  session.

- **Live preview race window.** Carries from prior session. Self-
  corrects on next pause; fix is an `AbortController` on
  `_renderWidget` scoped to the preview path.

- **Drop dormant `dashboard.midnight.css` loader.** Carries from
  prior session.

- **`save_template.ctp:4` action-name mismatch.** Phase 4 work.
  Carries.

## Open thread / next obvious work

Lots of small-ish options + a few bigger pieces. In rough priority
order:

**Option A: C+H paired — `tag_filter` end-to-end (~full day).**

Biggest remaining user-facing canonical type. Three pieces:
- `CanonicalTypeAdapter::translateTagFilter` translator (key
  restructuring — canonical `{include, exclude, taxonomies?,
  match_event_tags?, match_attribute_tags?}` → legacy widget-specific
  `include` / `exclude` / `filter_event_tags` slots).
- New `app/webroot/js/dashboard/canonical/tag_filter.mjs` builder
  with chip-input control for include/exclude (Phase 2's still-
  open chip-input task lands implicitly).
- Per-widget `$schema` backfill across the 5+ widgets that declare
  the legacy slots (TrendingTagsWidget, TrendingAttributesWidget,
  AttackWidget, maybe more — audit first).

Best paired commit pattern: helper + tests (commit 1) →
adapter wire + chip builder (commit 2) → one commit per per-widget
backfill (commits 3..N). 30+ PHPUnit tests for the translator
plausible.

**Option B: Phase 5 grid auto-place (half-day push-down-only).**

Modest scope, immediate UX win, unblocks the Widget Gallery's
Add Widget flow because new widgets can land on top of existing
layout cleanly. Risk: changes the Grid module which is otherwise
frozen Phase 1 vendored work. Approach: in `Grid._commit`'s
drop branch, detect colliding tile rectangles; for each colliding
tile, shift down by drop.h rows; iterate until stable. Commit
as one `_commit` so `onCommit` fires once.

**Option C: Widget gallery + Add Widget flow (multi-session).**

Largest remaining Phase 2 surface. Server endpoint per PRD §5.8
returning widget metadata; gallery grid + card elements; search +
category grouping; Add Widget state machine in board.module.mjs.
Best as its own dedicated multi-session block.

**Option D: Chip input + flatten/reNest tests + console.log cleanup
(~half-day hygiene block).**

Three small Phase 2 tracker entries that pair well. Chip-input
component for arrays in the bottom-tier kv list (and reusable
in canonical pickers per Option A); unit tests for the dot-
notation flatten/reNest round-trip; audit dashboard JS modules
for stray console.log statements. Lands as 2-3 commits.

**Option E: Sticky preview pane in configure side panel (~half-
day).**

Phase 2 task split out from "Side-panel container". Widen the
panel to two columns; left column hosts the form; right column
hosts a sticky preview. Trade-off: panel is already crowded on
narrow viewports; needs media-query collapsing for ~960px width.
The in-board live preview already covers the core DD-06 affordance
so this is a UX nice-to-have rather than a blocker.

**Option F: Per-widget POST + edit-mode visual indicator (~1 hour).**

When the per-widget POST fires (configure-form Save or toolbar
bulk-edit), the user gets no visual feedback that the save
happened. Could add a small "Saved" toast or a checkmark on the
affected widget's header for 1.5 seconds. Defensive: today's
`saved` custom event already fires with `perWidget: true` —
just need a listener that surfaces a transient indicator.

**Option G: Renderer-side colour-contrast safety (~half-day).**

Surfaced by the tlp:clear (#ffffff) discovery. Add to charts.
module.mjs's `buildBarOption` / `buildLineOption`: compute
luminance of supplied colour; if ≥ 0.85, use a fallback (e.g.
a contrast-aware muted accent) or add a 1px stroke. Applies
uniformly across all renderers. Pairs nicely with Option D.

**Recommendation:** A (tag_filter end-to-end) is the highest-value
Phase 3 progress. If you want a smaller chunk, D (hygiene block)
is a comfortable warm-up that also implicitly delivers the chip-
input needed by Option A. Save Option B for a dedicated Phase 5
session; save Option C for a multi-session block when you have
the appetite.

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
- User alternates hitm / afk sessions; tracker docs are the ground
  truth between sessions. Tick one task at a time; the Done note
  carries the deciding context.
- Surface context status when past 75% at task boundaries so the
  user can choose to restart. (This session ended at 25%, well
  under the threshold.)
- Hard-refresh after CSS/JS edits — the `?v=185` cache-buster from
  `AppController::__queryVersion` doesn't bump per-file.
- For canonical-type additions: ship adapter helper commit first
  (pure additive), then per-widget backfill commits (one per
  widget). Avoid bundling adapter+wire+defaults+backfills in a
  single commit — review-friendly split.
- **A tracker tick requires the user-visible surface to exist AND be
  reachable from the default UI, not just the JS / handler-level
  wiring behind it.** (Lesson #1 of this session — added to the
  conventions list because the same trap could fire on Add Widget,
  refresh scheduler, or any other Phase 2-3 task whose JS is easier
  to land than the UI.)
- **mysql -u misp -pPassword1234 misp` for one-shot SQL; for complex
  payloads with quotes / escapes, use stdin heredoc + `SET @var =
  '...'` bind. Avoid LOAD_FILE — secure_file_priv defeats it.**
  (Lesson #7 — useful for any future v1-shape / canonical-shape
  injection during smoke.)
