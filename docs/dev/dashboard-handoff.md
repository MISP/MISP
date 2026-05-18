# Dashboard v2 — Session handoff (2026-05-18, evening)

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

**Phase 1 fully closed; Phase 2 contract foundation + four headline
tasks landed.** This session opened with a Phase 1 cleanup (UiBeta
themed dashboard layout — closes the Themed audit loop) and then
worked through Phase 2 sequentially: WidgetSchema contract helper +
26 PHPUnit tests, all 9 widget `$schema` backfills (per Q7 Option C),
schema-driven two-tier configure form (data-widget-schema delivery +
client-side typed-tier iteration + scalar field rendering), and live
preview (250ms-debounced re-render with cancel-revert semantics).

**14 commits this session**, all signed (`%G?` = `U`). Net ~700+ LoC
of new code; **zero changes to any widget's `handler()` logic** —
fully consistent with the additive-only posture. The configure form
is now genuinely useful end-to-end: clicking ⚙ on a schema'd widget
opens a panel whose typed-fields tier reflects the widget's actual
contract, typing in any field re-renders the widget body after a
250ms pause, Cancel reverts the visible state cleanly.

**Phase 1 close-out smoke tests: still 1/4** — the three interactive
browser tests from the prior handoff carry forward unchanged. They
need a real browser pass that the LLM can't drive.

**Next session: pick from** (see Open thread below for details)
1. Phase 1 close-out: 3 interactive smoke tests (user-driven).
2. Phase 2 tracker hygiene: tick the prototype-already-done tasks
   (per-canonical-type field elements, key-value list, side-panel
   container) with brief Done notes.
3. Phase 2 bottom-tier seeding from `$placeholder`.
4. Phase 2 edit-mode Save/Discard toolbar actions (currently
   `console.info` stubs).
5. Phase 2 widget gallery + Add Widget flow (biggest remaining
   surface — pairs with the new `GET /dashboards/widgets` endpoint
   per PRD §5.8).
6. Phase 3 canonical-type adapter — start `CanonicalTypeAdapter`
   under `app/Lib/Dashboard/Tools/` per PRD §5.5; many widgets are
   now ready to use it.
7. Fix the three latent widget handler bugs surfaced during the
   backfill (logarithmic / isCumulative / dead `limit`).

User direction carries forward: *"modern and pleasant"* — generous
whitespace, soft visual weight, subtle shadows, no animation
flourish, smooth keyboard navigation.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [x]
  v1 audit + removal                                              [x]
  Rename pass                                                     [x] 7/7
  Additive band                                                   [x] 7/7
  Themed/ audit loop                                              [x]
    Themed/Overmind/Layouts/dashboard.ctp (prior session)         [x]
    Themed/UiBeta/Layouts/dashboard.ctp (this session)            [x]
  Close-out smoke tests                                           [/] 1/4
    [x] Grep sanity (prior session)
    [ ] Default theme E2E
    [ ] Overmind theme E2E
    [ ] Legacy v1-shape row migration

Phase 2 — Authoring UX                                            [/] 4 done + N done-by-proto
  [x] $schema property contract (this session)
  [x] 9 widget backfills (this session — see Phase 3 carry-forwards)
  [x] Two-tier configure form element — schema-driven (this session)
  [x] Live preview, 250ms debounced (this session)
  [ ] Per-canonical-type form field elements (time_window done; tag_filter/
      org_filter/etc. are Phase 3) — could tick
  [ ] Key-value list component (done in proto) — could tick
  [ ] Chip input component for array values (DD-06)
  [ ] Bottom-tier seeding from $placeholder
  [ ] Bottom-tier dot-notation flatten/reNest (done in proto, MISSING tests)
  [ ] Side-panel container (done in proto) + sticky preview pane
  [ ] Widget gallery + Add Widget flow + Edit Widget flow
  [ ] Edit-mode vs view-mode toggle (toggle exists; Save/Discard stubs)
  [ ] Layout-only atomic save (DD-05)
  [ ] Discard (edit mode)
  [ ] Drag/resize/add/remove only fire in edit mode (drag+remove gated;
      resize CSS-hidden via display:none in view mode)
  [ ] Configure-form Save (current whole-blob _scheduleSave matches design)
  [ ] Console.log cleanup
```

Working tree is clean for v2 work; only the usual unrelated noise
(submodule drift on `app/Lib/cakephp` + `app/files/misp-galaxy`,
scratch files in repo root, untracked side-projects in subdirs).

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id: 1 (`admin@admin.test`), password `Password12345`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- **Admin user is on Overmind theme** (`UserSetting:ui_theme = "Overmind"`).
- DB creds: `mysql -u misp -pPassword1234 misp`

Saved-layout state at session end: admin has 4 widgets
(MispStatusWidget / TrendingTagsWidget / OrganisationMapWidget /
OrgContributionToplistWidget). `TrendingTagsWidget` is the only one
in admin's layout with a populated `$schema` — handy as the smoke
target for the schema-driven configure form (its panel shows three
typed fields: time_window picker, threshold int, over_time bool).

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
```

## What this session committed (in order)

```
396a674e4  new: Phase 1 — Themed/UiBeta/Layouts/dashboard.ctp
                Closes the Phase 1 Themed audit loop. Mirrors the
                default dashboard layout with main-beta.css preload
                + beta-ui-enabled body class so UiBeta users see
                the 14px typography overlay on the dashboard's
                global_menu nav bar (was falling back to the
                default chrome path before this commit).

d5bb0d058  new: Phase 2 — WidgetSchema contract helper (PRD §5.7)
                Static helper under app/Lib/Dashboard/Tools/.
                CANONICAL_TYPES (11) / SCALAR_TYPES (4) /
                TOOLBAR_ELIGIBLE_TYPES (9) constants. getSchema()
                defensive getter (returns [] for missing/malformed),
                validate() catalogue-load-time validator,
                isToolbarEligible() predicate. 26 PHPUnit tests, 64
                assertions, runs in 70ms.

1a426b644  chg: Phase 2 — $schema backfill for MispStatusWidget
                One-line additive: public $schema = array();
                Declarative marker (parameterless widget).

9682fee4d  chg: Phase 2 — $schema backfill for TrendingTagsWidget
                3-entry schema: time_window (canonical, no default),
                threshold (int, default 10), over_time (bool,
                default false). Three params (exclude/include/
                filter_event_tags) stay in $params bottom-tier.

69e949713  chg: Phase 2 — $schema backfill for TrendingAttributesWidget
                2-entry schema: time_window + threshold. Five params
                stay in bottom-tier (type+category need Phase 3
                attribute_type_filter; org_filter is different shape;
                exclude/to_ids no canonical equivalent).

2bf81c919  chg: Phase 2 — $schema backfill for UsageDataWidget
                Empty schema = []. All three params Phase 3-gated
                (filter org-meta-data; start_date+end_date need
                date_range adapter).

636e55dcc  chg: Phase 2 — $schema backfill for OrgEventsWidget
                2-entry schema: months (int, default 6), logarithmic
                (bool, default true). Discovered latent bug in
                handler() string-compare against "true"/"1" — see
                Discovered work in dashboard-progress.md.

af86e08b1  chg: Phase 2 — $schema backfill for AttackWidget
                Empty schema = []. Single 'filters' param is a
                free-form restSearch dict — heterogeneous sub-keys,
                can't decompose without Phase 3 work.

b7baad278  chg: Phase 2 — $schema backfill for OrganisationMapWidget
                Empty schema = []. filter org-meta-data + start_date
                /end_date Phase 3-gated; limit is dead config in v1
                (declared in $params but never consumed).

4c7dc6c45  chg: Phase 2 — $schema backfill for RecentSightingsWidget
                2-entry schema: limit (int, default 10) + last
                (time_window, no default). **First genuinely
                full-tier widget** — both params typed, zero
                bottom-tier fallback.

afadd0530  chg: Phase 2 — $schema backfill for EventEvolutionLineWidget
                1-entry schema: cumulative (bool, default true).
                filter + start_date Phase 3-gated. Discovered
                inverted $isCumulative condition bug.

6e76175f5  chg: capture Phase 3 catalogue gaps + widget handler bugs
                Consolidated Discovered-work entries:
                  - Phase 3 list omits date_range (PRD §5.5
                    explicitly Phase 3) AND the CanonicalTypeAdapter
                    implementation itself (PRD §5.5 keystone)
                  - org_meta_filter as potential new canonical type
                    (4-widget recurring shape)
                  - 3 latent widget handler bugs

bdd8d51d4  chg: Phase 2 — schema-driven two-tier configure form
                Server: DashboardsController::index enriches $widgets
                with each widget's $schema. wrapper.ctp + Overmind
                themed mirror emit data-widget-schema='<json>'.
                Client: configure.module.mjs's buildForm() iterates
                schema entries; CANONICAL_BUILDERS registry routes
                to TimeWindow.buildField for canonical types,
                buildScalarField for scalar (string/int/bool/enum
                via native controls). Unbuilt canonical types fall
                through to bottom tier. readBack uses
                [data-schema-key] with data-type-driven coercion.
                "Filters" typed-tier section conditionally rendered.
                Backwards compat: time_window builder emits BOTH
                data-canonical (for toolbar) AND data-schema-key.

5ed3287b7  new: Phase 2 — live preview on configure-form edits (DD-06)
                openConfigure widened to {onSave, onPreview}.
                schedulePreview/firePreview pair drives 250ms
                debounce. originalConfigJson snapshot at open +
                dirty/savedThisSession flags drive cancel-revert in
                closeConfigure. input/change listeners on panel
                body via delegation. board.module.mjs passes
                onPreview = (el) => _renderWidget(el).
```

14 commits this session. All signed (`%G?` = `U` — good signature,
unknown trust per the local GPG db). One GPG-agent timeout caught
at commit #13 (recovered by priming the agent per lesson #10 from
the previous handoff).

## Lessons from this session

These bit me; don't make me bite you twice.

1. **"Full-tier" $schema backfill is aspirational, not literal.**
   Q7 Option C names 9 widgets for "full-tier" backfill, but only
   `RecentSightingsWidget` genuinely landed full-tier. The others
   hit one of three deferral patterns:
   - **Canonical type doesn't exist yet** (`date_range` is Phase 3
     landing per PRD §5.5 — gates UsageData / OrganisationMap /
     EventEvolutionLine).
   - **Same-name-but-different-shape** vs. canonical (`org_filter`
     in TrendingAttributes is org-meta-data based; canonical is
     org-identity-based).
   - **Key restructuring** (TrendingAttributes' `type` + `category`
     would canonically unify into one `attribute_type_filter` —
     migration + adapter dependency).
   Phase 3 needs an explicit "complete the 9 widget backfills to
   full-tier" line item alongside the canonical adapter work.

2. **Canonical-type schema defaults must be omitted in Phase 2.**
   The widget's `handler()` parses legacy formats (`Nd`, raw int
   seconds for time_window). If `$schema['time_window']['default']
   = 'P7D'` writes to a fresh saved config, the legacy handler
   does `(int)'P7D' = 0` → empty render. Phase 3 adds canonical
   defaults alongside the `CanonicalTypeAdapter` in one coupled
   commit. Scalar types (int/bool/enum) still get defaults — no
   adapter dependency.

3. **Schema delivery to client = enrich `$widgets` server-side +
   `data-*` attribute on wrapper.** Pattern established for
   `data-widget-schema`. Reusable for any future per-widget
   metadata the client needs (e.g. `$placeholder` for bottom-tier
   seeding, `$category` for the Add Widget gallery grouping,
   `$thumbnail` for gallery cards).

4. **Configure form input listener must live on `[data-misp-configure-body]`
   not on inner controls.** `body.replaceChildren(buildForm(...))`
   wipes inner-control listeners but the body container survives.
   Event delegation via input/change bubbling does the rest.
   Important for any future field-type addition.

5. **Cancel-revert order in closeConfigure matters.** Revert
   `data-widget-config` from snapshot + fire onPreview re-render
   BEFORE `setHidden(panel)`. The render is async; the panel hides
   immediately while the widget body updates ~100ms later. Reversing
   the order works too but the perceived UX is cleaner with revert
   first.

6. **Three latent widget handler bugs surfaced during the backfill,
   all flagged but NOT fixed** (additive-only scope). They'll bite
   when the configure form is the user's primary path:
   - `OrgEventsWidget` line 105-107: `=== "true"` / `=== "1"`
     string-compares — fails when the configure form writes a
     real PHP boolean.
   - `EventEvolutionLineWidget` line 52: `$isCumulative = isset(x)
     && empty(x)` — semantically inverted (true for falsy, false
     for truthy).
   - `OrganisationMapWidget`: `limit` declared in `$params` but
     never consumed in `handler()`. Stale help text references
     "tags" (copy-paste from TrendingTagsWidget).
   All three documented in dashboard-progress.md's Discovered work
   section. A "fix widget handler latent bugs" task is the natural
   bridge before the configure form goes mainstream.

7. **The configure form was already substantially built in the
   Phase 0.3 prototype.** Several Phase 2 tracker tasks are
   already-done in proto and just need to be ticked: per-canonical-
   type field elements (time_window done; rest Phase 3), key-value
   list component, side-panel container (chrome part). Worth a
   quick tracker-hygiene commit early next session before starting
   new work.

The prior session's gotchas still apply:

8. **`git mv` does NOT auto-stage subsequent content edits.** Always
   `git status --short` and verify every modification you intend to
   commit shows in the LEFT column.

9. **Functionally-coupled tasks should land together.** Hit this
   pattern at the schema-driven configure form commit (server
   enrichment + wrapper attribute + client refactor in one commit
   — splitting would leave a non-functional intermediate state).

10. **GPG agent times out the commit signature** if pinentry isn't
    completed promptly. Symptom: `signing failed: Timeout`. Hit
    this once this session at commit #13 (schema-driven configure
    form). Fix: from the user's terminal, run `echo "test" |
    gpg --clearsign > /dev/null`, enter the passphrase to prime
    the agent, then retry. The user explicitly wants signed commits
    — never `--no-gpg-sign` without asking.

11. **`Themed/<Name>/Layouts/<layout>.ctp` must exist for every new
    layout you introduce.** Carries from prior session. This
    session closed the loop for UiBeta (Overmind landed last
    session, UiBeta landed this session). `Themed/EventTest/` has
    no `Layouts/` directory so the dashboard falls back to the
    default — confirmed no override needed there.

## Discovered work parked for later (deferred)

Most this-session items are now in `dashboard-progress.md`'s
Discovered work section (commit `6e76175f5` consolidated them).
Key ones to know about from a planning perspective:

- **Phase 3 catalogue gaps**: `date_range` missing from Phase 3
  task list; `CanonicalTypeAdapter` implementation has no explicit
  task line; `org_meta_filter` decision (introduce a new canonical
  type for the recurring sector/type/nationality/name/uuid/local
  shape, or leave it permanent bottom-tier?). Three widgets gate
  on `date_range`, four on the org-meta-data shape — meaningful
  Phase 3 scope decision.

- **Phase 2 latent widget handler bugs**: see Lesson #6 above.

- **Live preview race window**: rapid pause-type-pause-type cycles
  can race two in-flight `_renderWidget` POSTs. Self-corrects on
  next pause. Fix is an `AbortController` on `_renderWidget`
  scoped to the preview path. Deferred — MVP behavior is fine in
  practice.

- **Drop dormant `dashboard.midnight.css` loader** (carryover from
  prior session). Both default and themed dashboard layouts load
  it; selector `:root[data-theme="midnight"]` never matches.

- **UiBeta `Themed/UiBeta/Layouts/default.ctp` & dashboard.ctp**:
  the docblock on the new dashboard.ctp documents the rationale
  (main-beta typography overlay only, structurally identical to
  default chrome unlike Overmind's BS5 swap). EventTest needs no
  override (verified — only Events-specific view overrides, no
  Layouts dir).

- **`TrendingAttributesWidget` PHP 8.x crash via `Attribute` model
  name collision** — pre-existing MISP issue, not v2-specific.

- **`save_template.ctp:4` action-name mismatch** — Phase 4 work.

## Open thread / next obvious work

Lots of small-ish options + a few bigger pieces. In rough
priority order:

**Option A: Phase 2 tracker hygiene (~30 min).**

Tick the tasks that are done-in-proto with brief Done notes pointing
at the relevant prototype commit. Candidates:
- "Per-canonical-type form field elements (only `time_window` for
  now)" — TimeWindow.buildField exists, enhanced in commit
  `bdd8d51d4` with `data-schema-key` + `data-type`.
- "Key-value list component for the bottom tier" — `buildKVRow` +
  add/remove handler exists from proto.
- "Side-panel container for configure form" — chrome part exists
  from proto (panel + backdrop + open/close + ESC). "Sticky preview
  pane" part remains unchecked.

Worth doing first so the tracker accurately reflects state before
the next substantive work picks up. Single bundled commit.

**Option B: Phase 1 close-out smoke tests (user-driven, ~30 min).**

The three interactive tests from the previous handoff carry forward
unchanged. Needs a real browser pass:

1. **Default theme E2E.** Switch admin's `ui_theme` to `Default`
   (mysql command in Live test instance above), visit `/dashboards`.
   Verify: chrome integration, MispStatusWidget content fetches via
   AJAX, ⋯ More dropdown WAI-ARIA, Edit-layout toggle, drag + drop +
   reload persistence.
2. **Overmind theme E2E.** Admin is already on Overmind. Visit
   `/dashboards`. Verify: BS5 navbar, dashboard chrome below, ⚙
   button opens configure side panel (this session's new typed-fields
   tier should be visible on TrendingTagsWidget), toolbar bulk-edit
   chip, no JS console errors.
3. **Legacy v1-shape row migration.** Craft `UserSetting:dashboard`
   with v1 shape (recipe in prior handoff), visit `/dashboards`,
   verify LayoutFixup normalises on read + save canonicalises the
   persisted shape.

LLM can prep the SQL/curl recipes; can't drive the browser.

**Option C: Phase 2 widget handler latent bug fixes (~1h).**

The three bugs from Lesson #6 will bite when users start hitting
the configure form's checkbox/numeric controls. Bundle as a single
commit ("fix: latent widget handler bugs surfaced during Phase 2
backfill"). Touches three existing widget files:

- `OrgEventsWidget.php` line 105: broaden `=== "true"` to accept
  booleans + legacy strings.
- `EventEvolutionLineWidget.php` line 52: fix the inverted
  `$isCumulative` condition.
- `OrganisationMapWidget.php`: either wire `limit` into `handler()`
  or remove from `$params`.

Strictly speaking this exceeds additive-only scope (modifying
widget handler() logic), but it's a bug-fix in service of Phase 2's
configure form — frame the commit as bug fixes, not refactor.

**Option D: Phase 2 bottom-tier seeding from `$placeholder` (~1h).**

DD-06's "seeded keys" requirement. When a widget's saved config is
empty (or when added fresh via the Add Widget flow once that lands),
the bottom-tier key-value list should seed from the widget's
`$placeholder` JSON. Implementation: server emits `data-widget-
placeholder` (parallel to `data-widget-schema`), client tries to
`JSON.parse` the placeholder, on success seeds the kv list from
`flatten()`d entries; on parse failure (some MISP placeholders are
malformed JSON with trailing commas) falls back to single empty row.

Useful even without Add Widget flow because admin-imported widgets
with empty config also benefit.

**Option E: Phase 2 edit-mode Save/Discard actions (~half-day).**

Currently `case 'save'` / `case 'discard'` in `board.module.mjs`'s
`_wireBoardActions` are `console.info` stubs. Wire them up:
- "Edit layout" toggle puts the board into edit mode.
- Drag/resize/remove fire only in edit mode (drag and remove
  already gated; resize is CSS-gated via `display:none` on the
  handle in view mode — sufficient but a JS belt-and-suspenders
  check on `_onResizeStart` would be cleaner).
- Layout changes stage in client memory (don't fire `_scheduleSave`).
- "Save layout" button commits the staged changes (one POST).
- "Discard" button reverts the staged changes from server state
  (re-fetch / re-render from the original layout).
- Closes "Layout-only atomic save", "Discard", "Drag/resize/add/
  remove only fire in edit mode" tracker entries together.

Bigger commit; restructures how `_scheduleSave` is invoked.

**Option F: Phase 2 widget gallery + Add Widget flow (~full day+).**

Biggest remaining Phase 2 surface. Requires:
- New `GET /dashboards/widgets` endpoint per PRD §5.8 returning
  widget metadata (title, description, schema, category, default
  size, thumbnail).
- `Elements/dashboard/gallery/grid.ctp` + `card.ctp`.
- Gallery search box + category grouping.
- Add Widget side-panel state: gallery card click → schema form
  pre-populated with widget's defaults + placeholder-seeded
  bottom tier → place/cancel.
- Wire `case 'add-widget'` in board.module.mjs (currently a
  `console.info` stub) to open the gallery.

**Option G: Start Phase 3 — `CanonicalTypeAdapter` (~half-day).**

PRD §5.5 keystone. Lives at `app/Lib/Dashboard/Tools/
CanonicalTypeAdapter.php`. Called from `DashboardsController::
renderWidget` *before* `$widget->handler($user, $config)`. Reads
`$widget->$schema` to know which slots are canonical; translates
canonical wire shapes back to the legacy shapes each widget's
handler currently parses. Start with `time_window` (PRD §5.5
translation table: `P<N>D → <N>d` etc.) since 4 of the 9 widgets
declared `time_window` in their backfill. Add canonical defaults
to those widgets in the same commit (the deferred `default: 'P7D'`
values).

Sets up Phase 3's full canonical-type sweep — once the adapter
exists, adding new canonical types is small per-type work.

**Recommendation:** A + C first (~1.5h total) to clean the tracker
state and fix the bugs the configure form will surface. Then either
D (small, scoped) or G (sets up a chunk of Phase 3). Option B
unblocks Phase 1 fully but needs user driving. Options E + F are
the big remaining UX pieces — pick when there's a multi-hour
session block.

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
  user can choose to restart. (This session ended at 35% — well
  inside the safe band; the user requested the handoff proactively.)
- Hard-refresh after CSS/JS edits — the `?v=185` cache-buster from
  `AppController::__queryVersion` doesn't bump per-file.
- `MISP login` curl recipe (when the LLM needs to smoke a session-
  authed page): see the prior handoff's full recipe — the 4-piece
  `_Token` set must be extracted from the form's GET response and
  POSTed back with `Password12345`.
