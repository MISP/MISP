# Dashboard v2 — Session handoff (2026-05-19, super-late-night session #2 continuation)

Third session of the day, continuing the second super-late-night
sweep. Authoritative state still lives in:

- `dashboard-prd.md` — spec (§5.7 amended this session: `$thumbnail`
  bullet now documents the render-kind glyph fallback + the
  standing requirement to add a glyph whenever a new `$render`
  kind lands)
- `dashboard-progress.md` — task state. Phase 2 closed sub-phase C
  (placement + live preview); Phase 3 advanced to 5/12 canonical
  types (distribution_filter landed paired with its first
  consumer, TrendingTagsWidget)
- `dashboard-design-decisions.md` — DD-01..DD-08 unchanged

This file is the bridge: ephemeral session-level context that
doesn't fit the durable docs. Replace it as work progresses.

## TL;DR

**Eight signed commits this session + one DB restore.** Phase 2
sub-phase C is closed end-to-end (Add Widget gallery → card click
→ schema form with live preview → Save → placement with auto-place
and F5.6.4 toolbar inheritance). Phase 3 advanced from 4/12 to
5/12 canonical types via the paired-with-consumer model — the
right shape for any future canonical-type sweep, per the
consumer audit findings.

**Phase 2 — ~26/26.** Up from ~24/26 at session start. The two
remaining-then-open lines both closed: "Add Widget — placement"
(placement orchestrator + new `/dashboards/renderWrapper` endpoint
with ACL parity) and "Sticky preview pane in configure side-panel"
(folded with "Add Widget — live preview on right" since they
described the same surface). Only the `Edit Widget flow`
verification line stays open — existing per-widget ⚙ path covers
all the technical work; the tick waits on a browser pass against
the new preview-pane render surface.

**Phase 3 — 5/12 canonical types.** `distribution_filter` landed
across three commits: server adapter + 10 PHPUnit tests; JS
toggle-button picker + registries + CSS; TrendingTagsWidget
consumer with post-filter on `$eventIds`. The user confirmed
end-to-end browser smoke ("works like a charm").

**Major non-canonical work:** the gallery cards now ship a
render-kind-shaped fallback glyph in their thumbnail slot
(commit `d46c56ce1`) — 9 explicit kinds (SimpleList, BarChart,
MultiLineChart, WorldMap, Index, Button, OrgsPictures, Attack,
Achievements) + a generic fallback. A standing rule landed in
CLAUDE.md, the file's docblock, and PRD §5.7: any new `$render`
value must ship with a matching glyph in `render-thumbs.mjs`.

**DB restore:** admin's `user_settings` row 34 was clobbered at
16:13:04 by a v2.4 instance writing to the same database
(stringified positions, `width`/`height` keys). The pre-clobber
state was recovered from `audit_logs` row 5295902 (the audit
record that captured the v2 → v2.4 transition). Layout fully
restored to 4 widgets in v2 shape; configs preserved on both
sides — only the wrapper shape was clobbered. **Risk:** as long
as a v2.4 instance is connected to this DB, future clobbers may
recur — see Open thread.

**User-direction carried forward unchanged:** *"modern and
pleasant"*, *"don't worry too much about compatibility"*, plus
new direction this session — **for any new endpoint, ACL must
match the surface it shadows** (specifically the existing
`renderWidget` checkPermissions gate).

**Next session — pick from** (see Open thread):

1. Phase 3 next canonical type (needs consumer audit + pairing).
2. Build the missing `Index` renderer template (unlocks
   EventStreamWidget + others; quick win).
3. Browser-verify Edit Widget against the new preview-pane
   render path (closes the last open Phase 2 line).
4. Other parked work (time_window dropdown, luminance check, etc.).

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [x]

Phase 2 — Authoring UX                                            [/] ~26/26
  [x] $schema property contract + WidgetSchema helper + 26 tests
  [x] 9 widget $schema backfills (Phase 2)
  [x] Two-tier configure form element — schema-driven
  [x] Live preview, 250ms debounced
  [x] Per-canonical-type field elements (time_window only;
      rest are Phase 3)
  [x] Key-value list component for the bottom tier
  [x] Chip input component for array-typed values
  [x] Bottom-tier seeding from $placeholder
  [x] Bottom-tier dot-notation flatten/reNest tests
  [x] Side-panel container for configure form
  [x] Sticky preview pane in configure side-panel              (NEW)
  [x] Widget gallery — $category prereq backfill
  [x] Widget gallery — metadata endpoint
  [x] Widget gallery — views + CSS (dormant templates)
  [x] Widget gallery — side-panel open from + Add widget
  [x] Add Widget — card click → draft form
  [x] Add Widget — placement                                    (NEW)
  [x] Add Widget — live preview on right                        (NEW)
  [ ] Edit Widget flow (existing per-widget ⚙ path covers most;
      task line stays open until verified against the new
      preview-pane render path interactively)
  [x] Edit-mode vs. view-mode toggle
  [x] Layout-only atomic save (DD-05)
  [x] Discard (edit mode) with confirm-if-dirty
  [x] Drag/resize/add/remove only fire in edit mode
  [x] Configure-form Save: per-widget POST
  [x] Save/Discard UI buttons + body-attribute mode mirror
  [x] Console.log cleanup

Phase 3 — Canonical-type toolbar                                  [/] 5/12 types
  [x] CanonicalTypeAdapter helper + 70 PHPUnit tests (was 60)
  [x] Wire CanonicalTypeAdapter into renderWidget
  [/] Canonical types: 5/12
        [x] time_window
        [x] date_range
        [x] tag_filter
        [x] org_meta_filter — PRD §5.5 amendment
        [x] distribution_filter — paired with TrendingTagsWidget (NEW)
        [ ] org_filter (no consumers today — needs pairing)
        [ ] sharing_group_filter (no real consumers — needs pairing)
        [ ] galaxy_cluster_filter (no real consumers — needs pairing)
        [ ] threat_level_filter (no real consumers — needs pairing)
        [ ] analysis_filter (no real consumers — needs pairing)
        [ ] attribute_type_filter (widget-only)
        [ ] event_id_filter (widget-only)
  [x] Toolbar control logic (schema-driven declarer scan)
  [x] Toolbar bulk-edit write path (readValue dispatch)
  [/] Toolbar UI: time_window + tag_filter + org_meta_filter +
      distribution_filter shipped
  [ ] Per-canonical-type validators
  [ ] New-widget toolbar inheritance + Clear action
      — F5.6.4 inheritance landed in the placement orchestrator
        this session; Clear action remains
  [ ] Canonical-only $schema sweep across remaining ~9 widgets
  [ ] Cache-key sanity check
```

Working tree clean for v2 work after this session's 8 commits.
Only the usual unrelated noise (submodule drift on
`app/Lib/cakephp` + `app/files/misp-galaxy`, scratch files in
repo root, untracked side-projects in subdirs).

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id: 1 (`admin@admin.test`), password `Password12345`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- **Admin user is on Overmind theme** (`UserSetting:ui_theme =
  "Overmind"`).
- DB creds: `mysql -u misp -pPassword1234 misp`

**Saved-layout state at session end:** admin has the 4-widget
layout restored from `audit_logs` row 5295902:
- `w_1` MispStatusWidget at (0,0) 4×4
- `w_2` TrendingTagsWidget at (4,0) 5×4
  — config: `time_window=90d, threshold=10, over_time=false,
    tag_filter={include:[],exclude:[]}`
- `w_3` OrganisationMapWidget at (9,0) 3×4
- `w_4` OrgContributionToplistWidget at (0,4) 12×4
  — config: `time_window=P30D, threshold=15`

TrendingTags now has a `distribution` slot in its `$schema` that
the configure form surfaces as a toggle-button row in the
typed-fields tier. Setting it (e.g., `[3]`) narrows the source
event set; the toolbar surfaces a "Distribution" chip across the
board when at least one declarer is non-mixed.

Force test paths (unchanged from prior session):
```bash
# Force empty-state path:
mysql -u misp -pPassword1234 misp -e \
  "DELETE FROM user_settings WHERE user_id=1 AND setting='dashboard';"

# Theme flip (revert after testing):
mysql -u misp -pPassword1234 misp -e \
  "UPDATE user_settings SET value='\"Default\"' WHERE user_id=1 \
   AND setting='ui_theme';"
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
```

Wrapper render smoke (Phase 2 placement endpoint, ACL-gated via
`Dashboard::loadWidget`):
```bash
curl -s -b "$CJ" -X POST \
  -H "Accept: text/html" -H "X-Requested-With: XMLHttpRequest" \
  --data-urlencode "widget=MispStatusWidget" \
  --data-urlencode "config={}" \
  --data-urlencode "w=4" --data-urlencode "h=3" \
  --data-urlencode "x=0" --data-urlencode "y=0" \
  http://localhost:5007/dashboards/renderWrapper/w_99 | head -5
# Returns Overmind-themed <div class="card misp-widget--overmind"> ...
```

## What this session committed (in order)

```
f9aa3c496  new: Phase 2 — Add Widget placement: free-slot autoplace
                + F5.6.4 inheritance
                Five pieces: (1) DashboardsController::renderWrapper
                — new POST endpoint that renders wrapper.ctp through
                Cake's themed view resolver. ACL parity with
                renderWidget — Dashboard::loadWidget gates on
                checkPermissions, so admin-only widgets cannot be
                probed via this endpoint. POST-body unlock + CSRF
                disable via the existing beforeFilter list. (2) New
                view template `app/View/Dashboards/render_wrapper.
                ctp` dispatches to the themed wrapper element.
                (3) `data-misp-board-wrapper-url` on the <main>
                board root. (4) `currentValues(boardEl)` exported
                from toolbar.module.mjs. (5) Placement orchestrator
                `_placeDraftWidget` in board.module.mjs: listens for
                `misp-board:add-widget-pending`, walks schema for
                F5.6.4 toolbar inheritance, mints `w_<N>` ID, picks
                a free slot via `_findFreeSlot`, fetches the wrapper
                HTML, Grid.addTile, _renderWidget, refreshToolbar,
                _stageOrSave, debug readout. New custom events
                `misp-board:add-widget-placed` /
                `misp-board:add-widget-failed`. Edit-mode Discard
                handles the newly-added tile naturally via the
                existing `current-but-not-snapshot → remove` branch.

b4dab0bd5  new: Phase 2 — Live preview pane in configure side-panel
                (Add + Edit)
                Closes BOTH "Sticky preview pane" AND "Add Widget
                live preview" tracker lines — one pane serves both
                flows. Panel widened 420 → min(820px, 100vw).
                `.misp-configure-content` flex-row wraps form
                (.misp-configure-body, 360px fixed col) + preview
                pane (.misp-configure-preview, fills). Preview pane
                is a sibling of the body, not a child, so gallery
                mode's body.replaceChildren() leaves it untouched.
                Gallery mode CSS-hides the preview pane AND restores
                the body to full width so the 38-card grid isn't
                squeezed. Responsive collapse below 720px (vertical
                stack, full-screen panel). configure.module.mjs
                gains a `previewProxy` state variable + a
                `buildPreviewProxy(widgetEl)` helper. Proxy is a
                detached <div data-misp-widget> mirroring openTarget's
                attributes + an inner [data-misp-widget-content] —
                no chrome (bare body, not a duplicate wrapper).
                openConfigure mounts the proxy and kicks off an
                immediate render. firePreview writes the new config
                to both openTarget AND previewProxy, dispatches
                onPreviewCallback(previewProxy). Live tile is never
                touched during preview — the dashboard behind the
                panel stays at its saved-config state until commit()
                fires; the panel is a true sandbox. board.module's
                Add Widget onPreview switched from no-op stub to
                `(el) => this._renderWidget(el)` (proxy handler).
                Edit Widget onPreview unchanged in code (same path;
                now operates on the proxy).

0348b1778  fix: Initial preview render uses form readback, not raw
                draft config
                Follow-up to b4dab0bd5. The initial preview kick
                at openConfigure called onPreviewCallback directly
                against the proxy, which then read the draft's raw
                data-widget-config='{}'. Most widgets render empty
                / "No data" for an empty config → gray box. Switch
                the initial kick to firePreview() which does
                readBack(panel) → writes form-current-state (kv
                placeholder seeds + canonical defaults) to proxy →
                dispatches. Add Widget preview now renders real
                content from the first tick. Edit Widget unchanged
                (form was built from saved config; readBack returns
                roughly the same).

d46c56ce1  new: Phase 2 — Render-kind fallback glyphs for gallery
                card thumbnails
                Empty 16:9 thumbnail slot in every gallery card gets
                a render-kind-shaped SVG glyph when the widget
                doesn't declare $thumbnail. Three pieces: (1) new
                `app/webroot/js/dashboard/gallery/render-thumbs.mjs`
                — exports `getRenderThumb(renderKind)` returning a
                fresh SVG element per call. 9 explicit kinds:
                SimpleList (3 rows), BarChart (4 bars),
                MultiLineChart (sloping polylines), WorldMap (globe),
                Index (table grid), Button (pill with dots),
                OrgsPictures (3 circles), Attack (5×3 dot matrix),
                Achievements (badge + star) + thumbGeneric fallback.
                Single-color (currentColor) so CSS drives the tint;
                viewBox 80x45 matches the slot's 16:9. (2) gallery.
                module.mjs — when widget.thumbnail is absent, mount
                getRenderThumb(widget.render) into the slot.
                (3) dashboard.default.css — thumbnail becomes a flex
                centring container; SVG sized 56% × max-height 78%;
                muted color by default, accent tint + raised surface
                on card hover/focus.

23f913550  chg: docs — Standing requirement: new widget render kind
                ⇒ new glyph in render-thumbs.mjs
                Three durable copies of the rule so future sessions
                can't miss it: CLAUDE.md "MISP Development" gains a
                "Dashboard v2 — widget render kinds" section with
                concrete steps; render-thumbs.mjs's top-of-file
                docblock gets an explicit "Adding a new render kind"
                block right next to the REGISTRY that needs
                extending; dashboard-prd.md §5.7 (Widget contract)
                appends a note to the $thumbnail bullet pointing at
                render-thumbs.mjs.

d207603bb  new: Phase 3 — distribution_filter canonical adapter
                + tests
                5th canonical type. Wire shape is an int array,
                subset of {0..5} matching MISP's 6 event-distribution
                levels. Event::fetchEvent already accepts both scalar
                and array under `distribution` (lines 2703-2707), so
                canonical → legacy is essentially identity.
                CanonicalTypeAdapter::translateDistributionFilter
                normalises to int[]: array passes through; scalar
                int / numeric-string wraps; mixed array coerces
                numeric, drops non-numeric; empty array passes
                through; null / unrecognised → null. Out-of-range
                values (>5) deliberately preserved (CakePHP's IN
                coercion matches no rows for unknown levels —
                louder than silent filtering). 10 PHPUnit tests
                covering: array passthrough, empty array, null,
                scalar int wrap, numeric string wrap, mixed coerce
                + drop, unrecognised shapes, idempotence, type-
                routed translate, coexistence with time_window.
                All 70 adapter tests pass (60 prior + 10 new).

fa4ff0bc3  new: Phase 3 — distribution_filter JS picker + registries
                + CSS
                New canonical/distribution_filter.mjs exporting
                KEY/LABEL/LEVELS/buildField/readValue/displayLabel/
                equal. Picker renders a toggle-button row over the
                6 levels with human labels (Org only, Community,
                Connected, All, Sharing grp, Inherit). aria-pressed
                is the source of truth (no hidden inputs).
                Order-insensitive equal() so [0,1] vs [1,0] read
                as equal for the toolbar's mixed-state detection.
                displayLabel collapses both empty AND full
                selection to "(all)" — both = "no filter".
                CANONICAL_BUILDERS (configure) + CANONICAL_REGISTRY
                (toolbar) grow the entry. New CSS for
                .misp-distribution-toggles flex row + pill
                buttons (outlined → accent-filled on pressed).
                F5.6.4 inheritance wired automatically through the
                existing placement orchestrator.

821e86e8d  new: Phase 3 — distribution_filter consumer:
                TrendingTagsWidget post-filter
                Final of 3 commits for distribution_filter. The
                consumer-pairing model — every Phase 3 canonical
                type lands with a real consumer so the toolbar
                chip is actually usable, per the org_filter
                "no consumers = dead code" lesson. Three changes
                on TrendingTagsWidget: $params adds distribution
                legacy help; $schema adds 'distribution' =>
                ['type' => 'distribution_filter', 'help' => ...]
                between tag_filter and threshold; handler()
                post-filters $eventIds via a find('list') against
                Event with the already-ACL-filtered eventIds as
                base + an IN clause on Event.distribution. ACL-safe
                — distribution can only narrow (never expand) the
                visible range. Why TrendingTags, not the originally-
                picked EventStreamWidget: ES declares $render =
                'Index' but Elements/dashboard/Widgets/Index.ctp
                doesn't exist (pre-existing renderer gap). End-to-end
                browser smoke confirmed by the user — "works like a
                charm".
```

8 commits this session, all signed (`%G?` = `U`). Plus one direct
DB write (admin user_settings restore — not committed; see "DB
restore" lesson below).

## Lessons from this session

1. **ACL parity for new endpoints is a hard requirement.** When
   adding a new endpoint that shadows or extends an existing one,
   the new endpoint's permission gate must be the same hook the
   existing endpoint uses — not a custom check, not "this looks
   safe enough". For `/dashboards/renderWrapper` (placement), the
   user-direction was explicit: use `Dashboard::loadWidget`'s
   `checkPermissions` gate (same as `renderWidget`) so admin-only
   widgets cannot be probed for existence via a different code
   path. **Probe-resistance is the metric:** a non-admin's 404
   must be indistinguishable across "unknown widget class" /
   "widget exists but you can't see it" — both surface as the
   same NotFoundException with identical wording.

2. **Configure form's "live preview" needs form readback at
   panel open, not raw widgetEl config.** For Edit Widget,
   widgetEl carries the saved (non-empty) config and the form is
   built from it — initial render produces real content. For
   Add Widget, the draft starts with config={} and buildForm
   visually seeds defaults (placeholder kv rows, canonical
   builder defaults) but those don't write back to config. Result
   was a gray-box preview for any widget that returns empty on
   empty config. The fix is one-line: switch the initial-render
   kick from `onPreviewCallback(previewProxy)` to `firePreview()`
   — firePreview does `readBack(panel)` first, capturing the
   form's as-built state. Pattern: **form is the source of
   truth for the initial preview, not the widgetEl attributes**.

3. **Render-kind glyphs beat category glyphs as gallery
   thumbnails.** Original design committed to a "category-shaped
   fallback glyph". User pushed back during implementation —
   render kind tells you the *output shape* (bars, lines, globe,
   list), which is what the thumbnail communicates; category
   tells you the *data domain* (status, events, orgs), which is
   already surfaced in the category chip. The bar chart is bars
   whether it's counting events or orgs. **Visual hint should
   evoke output shape, not data domain.** Companion lesson: when
   adding a property that drives downstream UI (here, $render),
   the file with the matching UI surface (render-thumbs.mjs)
   needs an explicit "adding a new <kind>" docblock so future
   sessions don't ship blank thumbnails for new render kinds.

4. **Consumer audit before canonical-type work, every time.** The
   handoff lesson from the org_filter mistake — "no consumers
   today, work is premature" — applies to every remaining Phase
   3 type. This session's distribution_filter audit found zero
   consumers AS FILTERS for distribution/threat_level/analysis/
   sharing_group_filter in the current widget set. EventStreamWidget
   *displays* threat_level / analysis as columns but doesn't
   filter by them; TrendingAttributesWidget uses sharing_group_id
   in SELECT, not WHERE. The corrected model is to **land the
   canonical type AND its first consumer widget in the same
   chunk** — three commits per type: adapter + tests, JS picker
   + registries, consumer widget. Without a consumer, the
   toolbar chip stays hidden (no declarers) and the canonical
   type is dead code on maintenance burden.

5. **Pre-existing renderer template gap is a separate liability.**
   5 of 9 declared render kinds (Index, OrgsPictures, Button,
   Attack, Achievements) have no `Elements/dashboard/Widgets/
   <Kind>.ctp` template — widgets using those kinds would 500.
   Surfaced during the distribution_filter consumer pivot
   (EventStreamWidget declares Index, which doesn't render).
   Workaround was to pick a working renderer (TrendingTags →
   BarChart). The renderer gap is parked — see Open thread.

6. **Audit logs are a feasible recovery path for clobbered
   `user_settings` rows.** The `audit_logs` table's `change` blob
   stores `{"value": [old_value, new_value]}` for every UserSetting
   edit. When a MISP 2.4 instance writing to the same database
   clobbered admin's dashboard at 16:13:04, the pre-clobber state
   was recoverable from row 5295902's `change` blob (the audit
   that captured the v2 → v2.4 transition at 16:07:00). Recovery
   procedure: read row, JSON-decode the blob (MySQL escapes
   backslashes — strip one level), parse `value[0]` as the old
   state, write back to user_settings with current timestamp.
   **Caveat:** v2.4's writes don't generate audit_logs entries
   (the final 16:13:04 clobber had no audit record). So the
   audit chain has a hole — you can recover *to* the last v2
   write but not see what happened after it. The hole isn't
   harmful for restore-from-snapshot but is interesting for
   diagnosing what v2.4 was doing.

7. **MISP 2.4 connected to the same DB is a risk surface.**
   v2.4's UserSetting save path writes a different shape (no
   `instance_id`, `width`/`height` keys, string positions) and
   appears to bypass `AuditLogBehavior`. As long as a v2.4
   instance is talking to this DB, dashboard layouts can be
   clobbered silently. See Open thread for mitigation options.

8. **GPG pinentry timeout hit again.** Same as prior session
   lesson #8 — first commit attempt of `d207603bb` failed because
   the pinentry prompt wasn't completed promptly. Retry worked.

The prior session's gotchas still apply:

9. **`git mv` does NOT auto-stage subsequent content edits.**
10. **`Themed/<Name>/Layouts/<layout>.ctp` must exist for every
    new layout you introduce.** No new layouts this session.
11. **Bundled commits for 5+ identical changes.** No bundles this
    session — distribution_filter consumer was a single widget.

## Discovered work parked for later

Newly parked this session:

- **Missing renderer templates (5 of 9 declared kinds):** Index,
  OrgsPictures, Button, Attack, Achievements have no
  `Elements/dashboard/Widgets/<Kind>.ctp`. Widgets declaring these
  kinds (EventStreamWidget → Index; OrgsContributor* → OrgsPictures;
  ButtonWidget → Button; AttackWidget → Attack; AchievementsWidget
  → Achievements) currently 500 on render. Discovered during the
  distribution_filter consumer pivot. **Estimated:** 1-2 commits
  per kind (each renderer is a thin .ctp around a `$data` shape;
  pattern matches BarChart/SimpleList). Highest value: Index
  (unlocks EventStreamWidget which is one of the most user-facing
  widgets and a natural distribution_filter consumer too).

- **MISP 2.4 cross-instance DB write risk:** v2.4 connected to
  the same DB can clobber `user_settings.dashboard` rows in a
  shape v2 has to read-fix-up but loses position fidelity.
  Mitigation options: (a) document the risk in the dev-only
  README; (b) add a schema migration that v2.4 won't recognise so
  it refuses the write; (c) version the dashboard blob (add a
  `__version: 2` top-level key, ignore writes that drop it).
  None blocking for now — just document the recovery procedure
  (audit_logs replay).

Previously parked items all still apply:

- time_window toolbar dropdown-menu UX alternative (surfaced
  2026-05-19, prior session).
- Grid drop-on-occupied cascade (Phase 5 — parked 2026-05-19).
- tlp:clear (#ffffff) renders invisible bars (cosmetic).
- OrgEventsWidget months>13 malformed dates (carries).
- TrendingAttributesWidget PHP 8.x Attribute model crash
  (carries — MISP core touch).
- EventEvolutionLineWidget ignores end_date (carries).
- Live preview race window (carries — AbortController fix).
- Drop dormant `dashboard.midnight.css` loader (carries).
- `save_template.ctp:4` action-name mismatch (Phase 4 — carries).

## Open thread / next obvious work

In rough priority order:

**Option A: Build the missing Index renderer template.**

Quick win. Pattern is well-established (BarChart.ctp / SimpleList.
ctp are ~30-50 lines each). Index is a tabular renderer — header
row with column names from `$widget->fields`, body rows from
`$data['data']`. Once Index lands, EventStreamWidget renders
again — and EventStreamWidget is the natural distribution_filter
consumer #2 (the F5.6.4 inheritance demo gets richer with a
second declarer). Half-day. After Index, four renderer kinds
still missing (OrgsPictures, Button, Attack, Achievements) —
those can land in subsequent sessions per their utility.

**Option B: Phase 3 next canonical type — needs consumer pairing.**

Per Lesson #4, every remaining type needs a consumer found OR
added. The best candidates by user value:
- `sharing_group_filter` (any sharing-group-aware widget would
  consume; need to add filtering to one). Higher complexity
  because sharing groups are user-specific.
- `threat_level_filter` / `analysis_filter` (small enums like
  distribution_filter; same toggle-button picker pattern; pair
  with EventStreamWidget once Index renderer lands → option A
  becomes a prerequisite).
- `galaxy_cluster_filter` (most complex — galaxy clusters are
  dynamic, need server-side autocomplete).

**Option C: Browser-verify Edit Widget against the new preview-
pane render path.**

Closes the last open Phase 2 line. No code work; tick depends on
a browser interaction. Should take 15 minutes.

**Option D: Phase 4 — Template library v2 native UI.**

Pure greenfield. Template browse/import currently uses v1
template-listing flow inside the v2 chrome. Reuses the gallery
infrastructure (card grid, search filter, side panel) we just
built. Larger scope — multi-session.

**Option E: Other parked work.**

time_window dropdown UX, renderer luminance check (tlp:clear bars
render invisible), midnight.css drop, TrendingAttributesWidget PHP 8
crash.

**Recommendation:** A then a paired round of B (threat_level_filter
+ EventStreamWidget consumer). A is small but unblocks B's
richest pairing, and EventStreamWidget is the canonical "let's
filter events by X" surface.

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  the commit body references the task. Bundle backfill commits
  when the pattern is identical across 5+ widgets; separate
  commits when the pattern diverges per widget. **For
  canonical-type additions: three-commit shape per type — adapter
  + tests, JS picker + registries, consumer widget. Same as
  distribution_filter this session.**
- **For mass file edits via script: preserve per-file line
  endings** (read binary, detect existing line-ending sequence,
  use same on write). Prior session hit it once on
  UsageDataWidget.php.
- **Always `git status --short` + explicit `git add` before
  commit**. Also watch for stray empty files from grep / find
  with quote-mangling — clean them out with `git status` before
  staging.
- New files land with `iglocska:iglocska` ownership; `chgrp
  www-data` before committing to match repo convention.
- The wrapper-element + Themed-override pattern is the playbook
  for any future override surface. In-panel widgets (gallery
  cards, configure proxy) don't need Themed mirrors because their
  containing chrome is theme-neutral. Visual theming flows
  through CSS-class overrides, not markup forks.
- User wants rigorous pushback, not yes-machine output — surface
  trade-offs, name alternatives, recommend a path, then go with
  the user's call. **New this session:** the org_filter "no
  consumers = dead code" lesson applies to every Phase 3 type —
  audit before committing to the work.
- User alternates hitm / afk sessions; tracker docs are the
  ground truth between sessions. Tick one task at a time; the
  Done note carries the deciding context.
- Surface context status when past 75% at task boundaries so the
  user can choose to restart. This session wrapped at ~39% with
  the user explicitly asking for the handoff.
- Hard-refresh after CSS/JS edits — the `?v=185` cache-buster from
  `AppController::__queryVersion` doesn't bump per-file.
- **For canonical-type additions (Phase 3):** adapter helper
  commit first, then JS picker commit, then per-widget consumer
  backfill commit. Mind the consumer audit — no consumers = park
  the type, don't ship dead code.
- **A tracker tick requires the user-visible surface to exist
  AND be reachable from the default UI, not just the JS / handler-
  level wiring behind it.** (Carries.)
- **`mysql -u misp -pPassword1234 misp` for one-shot SQL.**
- **The schema-driven model is the canonical answer** for any
  "how does the toolbar / configure form know which widgets to
  act on" question.
- **Panel-mode-piggyback pattern:** when a new module wants to
  use the configure side panel for a non-form view, flip
  `data-misp-configure-mode` to mark the new mode, populate the
  panel body via `body.replaceChildren()`, and use a
  MutationObserver on the panel's `hidden` attribute as the
  canonical close hook. CSS can use the mode attribute to hide
  form-only chrome.
- **Draft widget pattern:** for any "create a new widget" UX,
  construct a detached `<div data-misp-widget>` DOM node carrying
  the same `data-widget-*` attributes a wrapper.ctp would carry.
  Pass it through `openConfigure` like any real widget;
  orchestrate what happens on Save outside the configure module.
- **Preview-proxy pattern (NEW this session):** for any "show me
  what this widget would look like" surface that's NOT the live
  tile, build a bare proxy `<div data-misp-widget>` with the
  identifying attributes + a `[data-misp-widget-content]`
  container. `_renderWidget(proxy)` from the BoardModule does the
  rest. Decouples the preview render from the live tile so the
  configure panel can be a true sandbox.
- **Render-kind glyph requirement (NEW this session, documented
  in three places — CLAUDE.md, render-thumbs.mjs docblock,
  PRD §5.7):** any new value for `public $render` on a widget
  class, or any new template under `app/View/Elements/dashboard/
  Widgets/`, must ship with a matching glyph in `app/webroot/js/
  dashboard/gallery/render-thumbs.mjs` in the same commit.
  Otherwise the gallery card falls through to the generic block
  for every widget using the new render kind.
- **DB restore from audit_logs (NEW this session):** when a
  `user_settings` row is clobbered, the prior state lives in the
  most recent `audit_logs` row where `model='UserSetting' AND
  model_id=<row_id>`. The `change` blob is JSON with shape
  `{"value": [old_json, new_json]}`. MySQL escapes backslashes —
  strip one level when parsing. `value[0]` is the pre-write
  state — write back to `user_settings.value`, set `timestamp =
  UNIX_TIMESTAMP()`.
