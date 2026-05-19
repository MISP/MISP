# Dashboard v2 — Session handoff (2026-05-19, super-late-night session #2)

Second session of the day (after the prior 14-commit Phase 3
canonical-types push). Authoritative state still lives in:

- `dashboard-prd.md` — spec (§5.7 / §5.8 unchanged this session;
  §5.5 catalogue unchanged — no new canonical types)
- `dashboard-progress.md` — task state. Phase 2 widget-gallery line
  subdivided into 6 sub-tasks this session; 5 of those 6 ticked
  (browse-only complete + card→form transition)
- `dashboard-design-decisions.md` — DD-01..DD-08 unchanged

This file is the bridge: ephemeral session-level context that doesn't
fit the durable docs. Replace it as work progresses.

## TL;DR

**Sub-phase B complete + sub-phase C started.** Six signed commits,
all `%G? = U`. The widget gallery is now wired end-to-end as a
browse-only surface; the Add Widget card-click correctly transitions
the configure side panel from gallery view to draft-form view; the
draft's Save click fires a `misp-board:add-widget-pending`
CustomEvent — placement is the next listener that lands.

**Phase 2 — now ~24/26 done.** Up from ~20/22 at session start
(denominator grew by 4 when the original 2 gallery lines were
subdivided into 7). Remaining open: Add Widget placement (next
task), Add Widget live preview pane, Sticky preview pane in
configure side-panel (Phase 2 polish line that the preview-pane
sub-task may collapse into).

**Five of the seven gallery sub-tasks closed:**
1. `$category` backfill across 37 in-tree widgets (PRD §5.7
   buckets: status / events / tags / orgs / system / custom).
2. `GET /dashboards/widgets` metadata endpoint returning the
   38-entry list with `schema` / `category` / `thumbnail`.
3. Dormant gallery templates: `Elements/dashboard/gallery/grid.ctp`
   + `card.ctp` + gallery CSS in `dashboard.default.css`.
4. Side-panel open from `+ Add widget` button — `gallery.module.mjs`
   fetches, groups, search-filters, dispatches.
5. Card click → draft form: `_startDraftWidget` constructs a
   detached DOM node, hands off to `openConfigure`.

**Remaining two:**
6. Placement (Place / Cancel) — listen for `add-widget-pending`,
   find next free auto-place slot, insert via `Grid.addTile()`,
   wire to the edit-mode snapshot for Discard support, persist via
   `_scheduleSave`.
7. Live preview on right — render the draft widget body in a
   sticky pane while the user edits the form. May collapse into
   the standalone "Sticky preview pane in configure side-panel"
   Phase 2 task that's already on the tracker.

**The browse-only path is verifiable in a browser now:** Edit mode
→ click "+ Add widget" → see the 38-widget gallery grouped into 6
categories → search filters live → ESC / backdrop / ✕ closes. Card
clicks transition to the draft form (title flips to "Add <Title>",
schema-driven form renders with seed-from-placeholder rows). The
draft form's Save fires the placement event (no listener yet).
Cancel closes the panel entirely (no "back to gallery" affordance —
the user clicks `+ Add widget` again to re-browse).

**Next session — pick from** (see Open thread):

1. Add Widget placement (the next obvious step — half-day to full-
   day).
2. Add Widget live preview pane (~half-day, can land before or
   after placement).
3. Other parked work (canonical-type sweeps, time_window dropdown
   UX, renderer contrast, the pre-existing PHP 8 Attribute
   collision).

User direction carries forward unchanged: *"modern and pleasant"*,
*"don't worry too much about compatibility"* — gallery markup and
JS take advantage of the additive-only license.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [x]

Phase 2 — Authoring UX                                            [/] ~24/26
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
  [ ] Sticky preview pane in configure side-panel (likely collapses
      into the Add Widget live preview sub-task below)
  [x] Widget gallery — $category prereq backfill            (NEW)
  [x] Widget gallery — metadata endpoint                    (NEW)
  [x] Widget gallery — views + CSS (dormant templates)      (NEW)
  [x] Widget gallery — side-panel open from + Add widget    (NEW)
  [x] Add Widget — card click → draft form                  (NEW)
  [ ] Add Widget — placement (Place / Cancel)
  [ ] Add Widget — live preview on right
  [ ] Edit Widget flow (existing per-widget ⚙ path covers most;
      task line stays open until the new draft-form path is
      verified against it interactively)
  [x] Edit-mode vs. view-mode toggle
  [x] Layout-only atomic save (DD-05)
  [x] Discard (edit mode) with confirm-if-dirty
  [x] Drag/resize/add/remove only fire in edit mode
  [x] Configure-form Save: per-widget POST
  [x] Save/Discard UI buttons + body-attribute mode mirror
  [x] Console.log cleanup

Phase 3 — Canonical-type toolbar                                  [/] 4/12 types
  [x] CanonicalTypeAdapter helper + 33 PHPUnit tests
  [x] Wire CanonicalTypeAdapter into renderWidget
  [/] Canonical types: 4/12
        [x] time_window
        [x] date_range
        [x] tag_filter
        [x] org_meta_filter — PRD §5.5 amendment
        [ ] org_filter (no consumers today)
        [ ] sharing_group_filter
        [ ] galaxy_cluster_filter
        [ ] distribution_filter
        [ ] threat_level_filter
        [ ] analysis_filter
        [ ] attribute_type_filter (widget-only)
        [ ] event_id_filter (widget-only)
  [x] Toolbar control logic (schema-driven declarer scan)
  [x] Toolbar bulk-edit write path (readValue dispatch)
  [/] Toolbar UI: time_window + tag_filter + org_meta_filter shipped
  [ ] Per-canonical-type validators
  [ ] New-widget toolbar inheritance + Clear action
  [ ] Canonical-only $schema sweep across remaining ~10 widgets
  [ ] Cache-key sanity check
```

Working tree is clean for v2 work; only the usual unrelated noise
(submodule drift on `app/Lib/cakephp` + `app/files/misp-galaxy`,
scratch files in repo root, untracked side-projects in subdirs).

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id: 1 (`admin@admin.test`), password `Password12345`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- **Admin user is on Overmind theme** (`UserSetting:ui_theme =
  "Overmind"`).
- DB creds: `mysql -u misp -pPassword1234 misp`

Saved-layout state at session end: unchanged from prior session.
Admin still has 4 widgets (MispStatusWidget / TrendingTagsWidget /
OrganisationMapWidget / OrgContributionToplistWidget). No layout
changes this session — work was JS / view / CSS additions.

Expected gallery state on admin's dashboard after switching to edit
mode and clicking "+ Add widget":
- Configure side panel slides in from the right.
- Title: "Add widget".
- 38 cards distributed across 6 PRD-catalogue category sections
  (orgs 11 / system 9 / events 8 / status 4 / custom 4 / tags 1)
  + 1 uncategorised entry (HelloWorldWidget in Custom/).
- Search box up top; counter reads "38 widgets" initially.
- Clicking any card transitions the panel to the draft form for
  that widget (title flips to "Add <Title>", schema-driven form
  renders). Cancel closes the panel.

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

Gallery endpoint smoke (API-key auth works directly; no session
needed for this endpoint):
```bash
curl -s -H "Authorization: dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC" \
     -H "Accept: application/json" \
     "http://localhost:5007/dashboards/widgets" | jq '.[0]'
# → { widget: "APIActivityWidget", title: "API Activity", ...,
#     category: "system", schema: { ... }, thumbnail: "" }
```

## What this session committed (in order)

```
33ac34641  chg: Phase 2 — Widget gallery prereq: $category backfill
                across all in-tree widgets
                Lands `public $category` on 37 widget files
                (OrgsContributorsGeneric skipped — abstract base
                with no $title). Distribution: orgs 11 / system 9
                / events 8 / status 4 / custom 4 / tags 1. Edge
                calls documented (OrgEvents → events because the
                data axis is event counts; NewUsers → system per
                admin context; Attack → events per event-scoped
                restSearch). Single bundled commit (37 identical
                one-line additions, "5+ pattern → bundle" lesson).
                Also subdivided the Phase 2 widget-gallery task
                line into 7 sub-tasks.

6a2fd91b2  fix: Restore CRLF line endings on UsageDataWidget.php
                UsageDataWidget was the only widget pre-backfill
                with CRLF endings (522 CR lines); the Python script
                I used for the bundled $category insertion
                normalised it to LF. The +1 line addition is
                preserved verbatim; this commit only reverts the
                EOL normalisation. Net diff vs the pre-backfill
                commit (HEAD~2) is now +1 line, matching every
                other widget in the bundle.

535db0f5a  new: Phase 2 — Widget gallery metadata endpoint:
                GET /dashboards/widgets
                New DashboardsController::widgets() action
                returning a JSON list of every widget the calling
                user is eligible for (checkPermissions filter
                preserved via the existing Dashboard::loadAll
                Widgets enumeration), enriched with the three v2
                metadata properties per PRD §5.7 / §5.8: schema
                (normalised via WidgetSchema::getSchema), category
                (raw or empty), thumbnail (raw or empty). Legacy
                Dashboard::loadAllWidgets / __extractMeta kept
                untouched per the additive-only posture; controller
                enriches each entry by re-loading the widget via
                loadWidget(). Double-instantiation cost (~38
                widget classes constructed twice per gallery open)
                is acceptable for an on-demand endpoint. Wire
                shape is JSON-only; the gallery client is the sole
                consumer.

6f5037128  new: Phase 2 — Widget gallery views + CSS (dormant
                templates)
                Three pieces: (1) grid.ctp template — outer shell
                (HTML5 <template>) + per-category subtemplate.
                Carries the documented §8.5 hook attributes. (2)
                card.ctp template — single-card subtemplate; card
                root is <button type="button"> for keyboard reach;
                holds thumbnail slot + title + description + meta
                footer (category + size chips). (3) dashboard.
                default.css — gallery layout rules appended after
                the density-toggle block. Header is a flex row,
                body is a flex column with right-edge scroll
                bleed, per-category sections stack, card grid uses
                repeat(auto-fill, minmax(220px, 1fr)). No Overmind
                themed mirror — gallery renders inside `.misp-
                configure-panel` which is already theme-neutral
                chrome; visual theming flows through CSS-class
                overrides, not markup forks. Index.ctp emits both
                templates after the configure panel block — inert
                until JS clones them.

c06eb4997  new: Phase 2 — Widget gallery side-panel open from
                "+ Add widget" (browse-only)
                New gallery.module.mjs opens the gallery inside
                the configure side panel as a new "gallery" mode
                (distinguished from form mode via `data-misp-
                configure-mode` attribute on the panel root).
                Fetches /dashboards/widgets, clones the dormant
                <template> markup, groups cards by $category in
                PRD catalogue order, wires live search (case-
                insensitive substring across name / title /
                description / category) with a counter + empty-
                state; empty category sections auto-collapse.
                Search input gets keyboard focus on open. Browse-
                only — onPick is wired but dispatched as null.
                Coupling with configure.module.mjs is minimal:
                piggybacks on the existing panel chrome (open/
                close transitions, backdrop, ✕, Cancel, ESC). The
                panel's `hidden` attribute is the canonical close
                signal — a MutationObserver in gallery.module's
                init runs the gallery state cleanup whenever the
                panel hides. ESC needs its own listener in gallery
                mode because configure.module's ESC handler is
                gated on its private openTarget. Three additional
                touches: new "+ Add widget" button in `.misp-
                dashboard-modecontrols-edit` (edit-mode-only);
                new `data-misp-board-widgets-url` attribute on
                <main>; new `case 'add-widget'` in _wireBoard
                Actions; one-line CSS rule hides the configure
                footer in gallery mode.

0ee54fcd6  new: Phase 2 — Add Widget flow: card click → schema
                form for draft tile
                Three coupled pieces: (1) gallery.module.mjs gets
                a widgetMetaByName Map populated during
                renderGallery so the card-click handler can
                forward the full meta record (schema, placeholder,
                description) to onPick. (2) board.module.mjs new
                method _startDraftWidget(meta): flips panel mode
                from gallery → form (re-exposes the configure
                footer), constructs a detached <div data-misp-
                widget> DOM node carrying the picked widget's
                metadata as the same data-widget-* attributes a
                real wrapper.ctp carries, hands the draft to
                openConfigure(draftEl, {onSave, onPreview}).
                onSave fires a `misp-board:add-widget-pending`
                CustomEvent carrying the draft node + meta —
                placement consumes this. After openConfigure
                returns, overrides the title from "Configure
                <className>" to "Add <Title>" (additive — keeps
                openConfigure itself untouched). Companion
                _mintDraftInstanceId() produces `w_draft_<t36>_
                <r36>` IDs distinguishable from server-minted
                `w_<N>`. (3) board.module's case 'add-widget' now
                passes the real onPick callback.
```

6 commits this session, all signed (`%G?` = `U`).

## Lessons from this session

1. **Python scripts that read+write files normalise line endings.**
   The bundled `$category` backfill used a Python one-liner over
   37 widget files. One file (UsageDataWidget.php) had CRLF endings
   pre-backfill — the script silently normalised it to LF. The
   diff stat showed `1045 +/-` for that one file instead of the
   expected `+1`. Fix was a follow-up commit that restored CRLF
   while preserving the one-line addition. **For future mass file
   edits, snapshot line endings per file before writing and
   preserve them.** (Or use byte-level read/write in binary mode +
   regex insertion that tracks the existing line-ending sequence —
   what the fix-commit did.)

2. **`__extractMeta` re-instantiation cost is acceptable for the
   gallery.** The widgets() endpoint re-loads each widget via
   `loadWidget` after `loadAllWidgets` returns — that's 76
   constructor calls per gallery open. Verified at 39KB / sub-
   100ms response. Documented in the controller doc-string that
   the natural cleanup, if perf ever surfaces as a concern, is to
   fold the v2 enrichment into `__extractMeta` directly. Premature
   optimisation rejected; the trade-off is the additive-only
   posture (keep `loadAllWidgets` untouched so legacy callers like
   `listTemplates::accessible_widgets` are unaffected).

3. **MutationObserver on the panel's `hidden` attribute is a clean
   "close hook" for piggyback modules.** gallery.module needed to
   release state when the panel closed but didn't own the close
   path (configure.module's existing ✕/backdrop/Cancel handlers
   are the canonical close routes). Observing the `hidden`
   attribute lets us hook every close path without forking the
   listener race. Pattern reusable for any future panel-mode
   piggyback (e.g., a "Recent activity" mode, a "Template
   import" mode).

4. **Mode-switching panel: chrome stays neutral, body swaps.**
   The configure side panel is now a 2-mode surface (form, gallery)
   distinguished by `data-misp-configure-mode`. The CSS layer
   handles mode-specific rendering differences (hide the footer
   in gallery mode); the JS layer swaps the body contents via
   `body.replaceChildren()` — same primitive `openConfigure` uses
   when re-rendering for a different widget. Future modes plug in
   the same way.

5. **Draft widget = detached DOM node carrying the same
   `data-widget-*` attributes a real widget carries.** The
   configure module doesn't know or care that the widgetEl it
   receives isn't in the document — it reads attributes, builds
   the form, writes back to attributes. The draft node passes
   through `openConfigure` cleanly; on Save, the new config lives
   on the detached node and the orchestrator (board.module's
   `_startDraftWidget`) is responsible for what happens next
   (placement on Save, GC-release on Cancel). **Clean separation
   between "what's the form" and "what's the widget" — the form
   doesn't need to know about the grid.**

6. **Bundling guidance from prior session held up.** 37 widgets
   with identical one-line additions ($category backfill) was
   one bundled commit; the tracker Done note lists all 37 by
   name. Per-widget commits would have been 37 entries in the
   commit log saying the same thing.

The prior session's gotchas still apply:

7. **`git mv` does NOT auto-stage subsequent content edits.**
   Always `git status --short` and verify every modification you
   intend to commit shows in the LEFT column.

8. **GPG agent times out the commit signature** if pinentry isn't
   completed promptly. (Didn't hit it this session, but the rule
   stands.)

9. **`Themed/<Name>/Layouts/<layout>.ctp` must exist for every new
   layout you introduce.** No new layouts this session; gallery
   elements deliberately skip Overmind themed mirrors because
   their containing chrome (the configure side panel) is already
   theme-neutral and visual theming flows through CSS-class
   overrides.

## Discovered work parked for later

This session added no new parked items. The previously parked items
all still apply:

- time_window toolbar dropdown-menu UX alternative (surfaced
  2026-05-19, prior session).
- Grid drop-on-occupied cascade (Phase 5 — parked 2026-05-19,
  prior session).
- tlp:clear (#ffffff) renders invisible bars (surfaced 2026-05-19,
  prior session — cosmetic).
- OrgEventsWidget months>13 malformed dates (carries).
- TrendingAttributesWidget PHP 8.x Attribute model crash
  (carries — MISP core touch).
- EventEvolutionLineWidget ignores end_date (carries).
- Live preview race window (carries — AbortController fix).
- Drop dormant `dashboard.midnight.css` loader (carries).
- `save_template.ctp:4` action-name mismatch (Phase 4 — carries).

## Open thread / next obvious work

In rough priority order:

**Option A: Add Widget placement (the natural next step).**

The `misp-board:add-widget-pending` event fires today but has no
listener. Placement is the half-day-to-full-day piece that:

1. Listens for the event on the board root.
2. Auto-places the draft at the next free grid slot. Existing
   `Grid.serialize()` + an iteration over (x, y) cells looking for
   a free `meta.width × meta.height` rectangle works; the Phase 5
   push-down-on-collision task (parked) is a richer follow-up if
   the simple first-free-slot doesn't feel good.
3. Inserts the tile via `Grid.addTile(draftEl, {x, y, w, h})`.
4. Mints a real `w_<N>` ID to replace the `w_draft_*` placeholder
   (the LayoutFixup-style sequential mint pattern).
5. Wires to the edit-mode snapshot so Discard removes the tile
   (the existing `_editSnapshot.positions` check naturally handles
   "tiles in current-but-not-snapshot were added → remove them").
6. Calls `_stageOrSave()` so the addition persists on the next
   edit-mode Save (or immediately in view mode).
7. Calls `_renderWidget(draftEl)` to populate the new tile body.

**Option B: Add Widget live preview pane (~half-day).**

Sticky right-pane preview inside the configure panel that re-
renders the draft widget body via the renderWidget POST against
the in-memory draft config. Joint-task with the standalone Phase 2
"Sticky preview pane in configure side-panel" line — they describe
the same surface from different angles, and one chunk covers both.
The trade-off (panel already crowded on narrow viewports) is
unchanged from prior session.

**Option C: time_window toolbar dropdown UX (half-day).**

Surfaced prior session. Replace the popover with a dropdown-menu
(presets immediate, "Custom…" expands inline).

**Option D: Next canonical type (half-day each).**

The `*_filter` int-array trio (distribution / threat_level /
analysis) or `sharing_group_filter`. Need a consumer audit first
per the org_filter lesson.

**Option E: TrendingAttributesWidget PHP 8 Attribute collision.**

Pre-existing crash; needs a MISP-core touch.

**Option F: Renderer-side colour-contrast safety.**

tlp:clear (#ffffff) discovery. Add luminance check in chart
builders.

**Recommendation:** A then B closes sub-phase C and the Phase 2
gallery work. Both ride this session's gallery + draft-form
infrastructure cleanly.

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  the commit body references the task. **Bundle backfill commits**
  when the pattern is identical across 5+ widgets (the body lists
  the widgets by name); separate commits when the pattern diverges
  per widget. This session's $category backfill (37 widgets, single
  bundled commit) is the canonical example of the rule.
- **For mass file edits via script: preserve per-file line
  endings.** Reading + rewriting in text mode silently normalises
  CRLF → LF on files that originally had CRLF. The fix is to read
  in binary mode, detect the existing line-ending sequence per
  file, and use the same sequence when serialising the modified
  content back. (This session hit it once on UsageDataWidget.php
  and needed a follow-up restore commit.)
- **Always `git status --short` + explicit `git add` before
  commit**.
- New files land with `iglocska:iglocska` ownership; `chgrp
  www-data` before committing to match repo convention.
- The proto's wrapper-element + Themed-override pattern is the
  playbook for any future override surface. **Exception
  documented this session:** in-panel widgets like the gallery
  don't need Themed mirrors because their containing chrome (the
  configure side panel) is already theme-neutral; visual theming
  flows through CSS-class overrides rather than markup forks.
  The Themed-override is a wrapper-level concern, not an in-
  panel concern.
- User wants rigorous pushback, not yes-machine output — surface
  trade-offs, name alternatives, recommend a path, then go with
  the user's call.
- User alternates hitm / afk sessions; tracker docs are the ground
  truth between sessions. Tick one task at a time; the Done note
  carries the deciding context. Bundle commits don't tick more
  than one tracker line per commit — the commit IS the unit.
- Surface context status when past 75% at task boundaries so the
  user can choose to restart. This session ended at ~70-75% with
  the user opting to wrap rather than push through placement.
- Hard-refresh after CSS/JS edits — the `?v=185` cache-buster from
  `AppController::__queryVersion` doesn't bump per-file.
- For canonical-type additions (Phase 3 unchanged): ship adapter
  helper commit first, then JS picker commit, then per-widget
  backfill commits. The 4-6 commit shape of tag_filter and
  org_meta_filter from prior session is the template.
- **A tracker tick requires the user-visible surface to exist AND
  be reachable from the default UI, not just the JS / handler-
  level wiring behind it.** (Carries.)
- **mysql -u misp -pPassword1234 misp` for one-shot SQL.**
- **The schema-driven model is the canonical answer** for any
  "how does the toolbar / configure form know which widgets to
  act on" question.
- **Panel-mode-piggyback pattern (NEW this session):** when a new
  module wants to use the configure side panel for a non-form
  view, flip `data-misp-configure-mode` to mark the new mode,
  populate the panel body via `body.replaceChildren()`, and use a
  MutationObserver on the panel's `hidden` attribute as the
  canonical close hook. CSS can use the mode attribute to hide
  form-only chrome.
- **Draft widget pattern (NEW this session):** for any "create a
  new widget" UX, construct a detached `<div data-misp-widget>`
  DOM node carrying the same `data-widget-*` attributes a
  wrapper.ctp would carry. Pass it through `openConfigure` like
  any real widget; orchestrate what happens on Save outside the
  configure module. **Clean separation:** the form doesn't need
  to know about the grid or persistence.
