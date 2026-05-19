# Dashboard v2 — Session handoff (2026-05-19)

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

**Phase 2 nearly complete + Phase 3 keystone live with 2 of 11
canonical types fully landed.** 16 signed commits this session,
all `%G? = U`. The dashboard now has a real edit-mode transaction
(stage drag/resize/remove client-side; Save commits atomically;
Discard reverts to entry-time snapshot with confirm-if-dirty),
the bottom-tier of the configure form seeds from each widget's
`$placeholder`, and the canonical-type adapter (PRD §5.5 keystone)
translates ISO 8601 `time_window` and 1-to-N-expanding `date_range`
configs into the legacy shapes widget `handler()`s parse —
unchanged. 33 PHPUnit tests on the adapter pass in 53ms.

**Three widget handler bugs surfaced last session were addressed:**
OrgEventsWidget logarithmic now accepts real PHP booleans + closes
a silent fall-through gap; EventEvolutionLineWidget got a cosmetic
rewrite (re-trace showed the variable was misnamed but behavior
was correct end-to-end — not actually a bug); OrganisationMapWidget
`limit` is now alive (wired + stable order + smoke-driven PHP-side
cap after the SQL cap surprised on countries that don't map to
country codes).

**Phase 1 close-out smoke tests: still 1/4** — three interactive
browser tests from prior handoffs carry forward unchanged. They
need a real browser pass that the LLM can't drive.

**Discovered this session:** OrgEventsWidget produces malformed
dates like `2025--1-01` when `months > 13` because the wrap-around
only adds 12 once instead of looping. Out of scope today; parked
for follow-up. TrendingAttributesWidget hits the same pre-existing
PHP 8.x `Attribute` model-name collision as TrendingTagsWidget —
on every render, not just `over_time=true` — extended the
Discovered-work entry to cover both.

**Next session: pick from** (see Open thread below)
1. Phase 1 close-out: 3 interactive smoke tests (user-driven).
2. Add a third canonical type to the adapter (`tag_filter` is the
   biggest user-facing one and has 5+ widget candidates).
3. Configure-form per-widget POST — closes the documented
   "edit-mode + configure-save leaks layout" limitation.
4. Widget gallery + Add Widget flow (biggest remaining surface).
5. Chip input component for arrays in the bottom tier.
6. Console.log cleanup + bottom-tier flatten/reNest unit tests.
7. Phase 3 form-field elements for the canonical types just
   landed (`time_window` already done; date_range needs a date
   picker pair).

User direction carries forward: *"modern and pleasant"* — generous
whitespace, soft visual weight, subtle shadows, no animation
flourish, smooth keyboard navigation.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [x]
  Themed/ audit loop                                              [x] 2/2
  Close-out smoke tests                                           [/] 1/4
    [x] Grep sanity
    [ ] Default theme E2E
    [ ] Overmind theme E2E
    [ ] Legacy v1-shape row migration

Phase 2 — Authoring UX                                            [/] ~13/22
  [x] $schema property contract + WidgetSchema helper + 26 tests
  [x] 9 widget $schema backfills (Phase 2)
  [x] Two-tier configure form element — schema-driven
  [x] Live preview, 250ms debounced
  [x] Per-canonical-type field elements (time_window only;
      rest are Phase 3)
  [x] Key-value list component for the bottom tier
  [ ] Chip input component for array-typed values
  [x] Bottom-tier seeding from $placeholder (NEW this session)
  [ ] Bottom-tier dot-notation flatten/reNest tests (code exists;
      unit tests missing)
  [x] Side-panel container for configure form (was split from
      "container + sticky pane"; sticky pane is its own line now)
  [ ] Sticky preview pane in configure side-panel (split out)
  [ ] Widget gallery + Add Widget flow + Edit Widget flow
  [x] Edit-mode vs. view-mode toggle (NEW this session — full
      wiring, was just attribute-set before)
  [x] Layout-only atomic save (DD-05) (NEW this session)
  [x] Discard (edit mode) with confirm-if-dirty (NEW this session)
  [x] Drag/resize/add/remove only fire in edit mode (NEW this
      session — resize gained JS belt-and-suspenders)
  [ ] Configure-form Save: per-widget POST (documented leak from
      edit-mode commit — pending dedicated task)
  [ ] Console.log cleanup

Phase 3 — Canonical-type toolbar                                  [/] 2/11 types
  [x] CanonicalTypeAdapter helper + 33 PHPUnit tests
  [x] Wire CanonicalTypeAdapter into renderWidget + canonical
      time_window defaults on 3 widgets (TrendingTags, Trending
      Attributes, RecentSightings)
  [ ] Implement remaining canonical types (date_range done this
      session — 3 widgets backfilled; tag_filter / org_filter /
      sharing_group_filter / galaxy_cluster_filter /
      distribution_filter / threat_level_filter / analysis_filter /
      attribute_type_filter / event_id_filter still pending)
  [ ] Per-canonical-type form field elements (full set; only
      time_window done so far)
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
- DB creds: `mysql -u misp -pPassword1234 misp`

Saved-layout state at session end: admin has 4 widgets
(MispStatusWidget / TrendingTagsWidget / OrganisationMapWidget /
OrgContributionToplistWidget). After this session's Phase 3 work,
TrendingTagsWidget benefits from canonical-time_window default
injection if any of its time_window values get cleared; the
OrganisationMapWidget benefits from PHP-side limit and now has
both `limit` and `date_range` in $schema.

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

## What this session committed (in order)

```
32f621e6f  chg: Phase 2 tracker tick — per-canonical-type field elements
                Hygiene tick — proto already covered Phase 2 scope
                (time_window only; Phase 3 grows the registry one
                import + one entry per type).

d090005e6  chg: Phase 2 tracker tick — key-value list component
                Hygiene tick — buildKVRow factory + flatten/reNest
                helpers + delegated add/remove listeners exist from
                proto commit 96cf753af.

28f1cee55  chg: Phase 2 tracker tick — side-panel container
                Split the original task line "Side-panel container +
                sticky preview pane" into two — chrome ticked
                (96cf753af), sticky preview pane unchecked with
                a trade-off Done note for whoever picks it up.

736c94f2b  fix: OrgEventsWidget logarithmic check accepts booleans
                Broadened the truthy set to {true, 1, "1", "true"};
                collapsed the unreachable else-if to a plain else
                (was a silent fall-through gap for unrecognized
                values); used ?? to honor schema's `default: true`.

3122a4a03  chg: EventEvolutionLineWidget cumulative semantic
                Re-trace showed the prior handoff overstated the bug
                — the variable was misnamed but the consumption site
                was correspondingly inverted, so behavior was correct
                end-to-end. Cosmetic rewrite to canonical bool
                semantic. One real edge-case behavior diff: literal
                "no" was previously cumulative, now per-interval.

cc9ed0bd2  fix: OrganisationMapWidget limit wired + stable order
                limit was declared in $params but never read; help
                text referenced "tags" (copy-paste typo from
                TrendingTagsWidget). Wired into find() with stable
                ORDER BY frequency DESC + conditional LIMIT;
                promoted to $schema (now alive).

c59830428  fix: OrgMapWidget limit applies after country-code filter
                Smoke-driven follow-up: SQL-level LIMIT returned 1
                country for limit=3 because non-mapped nationalities
                (Krakhozia, International) consumed slots before the
                country-code filter dropped them. Pivot: drop SQL
                LIMIT, loop the ORDER-BY-frequency-DESC result-set in
                PHP, apply country-code filter, break at limit.

d9e384af6  new: Phase 2 — bottom-tier seeding from $placeholder (DD-06)
                Reuses the data-widget-schema delivery pattern.
                Server enrichment + wrapper attr + client
                seedFromPlaceholder helper with JSON.parse fallback
                (some MISP placeholders are malformed JSON).
                Schema-handled keys filtered out so kv rows don't
                shadow schema controls.

298646e90  chg: Phase 3 tracker — add explicit adapter + date_range lines
                Phase 3 list previously omitted the CanonicalType
                Adapter task and date_range; both flagged in
                Discovered work. New task lines added.

8756fa61e  new: Phase 3 — CanonicalTypeAdapter helper (PRD §5.5)
                Static helper that translates canonical wire shapes
                into legacy in-handler shapes, driven off
                $widget->$schema. Default-injection for missing-
                but-schema'd keys (Phase 2 deferred piece per
                lesson #2 of 2026-05-18 handoff). time_window
                translator ships first; 22 PHPUnit tests / 44
                assertions / 66ms.

fedf06451  new: Phase 3 — wire CanonicalTypeAdapter + canonical time_window defaults
                renderWidget calls translate() before handler().
                Canonical time_window defaults on TrendingTagsWidget,
                TrendingAttributesWidget, RecentSightingsWidget
                ('P7D', 'P7D', 'P1D'). 11-shape smoke confirmed
                P7D→7d, P2W→14d, PT12H→43200, legacy passthrough,
                sentinel passthrough, empty→defaults injected.

cc6f2c22a  new: Phase 2 — edit-mode Save/Discard + layout-only atomic save (DD-05)
                Full edit-mode transaction: _editSnapshot captures
                layout at view→edit; _stageOrSave routes layout
                commits (edit: stage; view: save); _commitEdit
                flushes and saves; _discardEdit restores via new
                Grid.updateTile + re-adds removed tiles held in
                _editSnapshot.removedTiles. Resize gained JS
                belt-and-suspenders gate. Closes 4 Phase 2
                tracker entries. Configure-form-save-during-edit-
                mode leak documented for the dedicated per-widget-
                POST task.

9352b3464  new: Phase 3 — CanonicalTypeAdapter date_range translator
                1-to-N expansion pattern: canonical {from, to|null}
                writes legacy start_date + end_date (when .to is
                non-null). 11 new tests / 21 new assertions; total
                33 tests / 65 assertions / 53ms. Canonical wins
                over stale legacy when both present.

cc559d87d  chg: Phase 3 — $schema date_range backfill for UsageDataWidget
                Promoted start_date/end_date legacy pair to declared
                canonical date_range. 5-shape smoke confirmed
                canonical → legacy expansion, open-ended to-null,
                pure-legacy passthrough, canonical-wins.

2bdd59d68  chg: Phase 3 — $schema date_range backfill for OrganisationMapWidget
                date_range alongside the existing `limit` entry.
                4-shape smoke: wide range → all 10 countries; narrow-
                future → 0 countries; canonical + limit=3 → 3
                countries.

12dc2efd2  chg: Phase 3 — $schema date_range backfill for EventEvolutionLineWidget
                Widget has only start_date legacy slot (no end_date —
                chart always runs through current month). Canonical
                `to: null` matches this naturally. Documented quirk:
                bounded to is dutifully written to end_date but
                handler() ignores it.
```

16 commits this session, all signed (`%G?` = `U`).

## Lessons from this session

These bit me; don't make me bite you twice.

1. **Re-verify handoff-described bugs before fixing.** The
   2026-05-18 handoff said EventEvolutionLineWidget's `$isCumulative`
   condition was inverted and a user toggling cumulative ON would get
   the non-cumulative branch. On re-trace, the variable was misnamed
   but the consumption site was correspondingly inverted, so behavior
   was correct end-to-end. The "fix" became a cosmetic rewrite. Always
   trace the full path before signing off on a fix, especially when
   the bug claim mentions "inverted" or "reversed" — two wrongs can
   make a right, and the fix has to either be cosmetic (rename for
   clarity) or address an actual behavior diff.

2. **Smoke surfaces real UX issues that pure logic review misses.**
   The OrganisationMapWidget limit fix (cc9ed0bd2) applied LIMIT at
   the SQL level — looked correct in isolation. Smoke against the
   live dev instance revealed that the top-2 nationalities by
   frequency (`Krakhozia`, `International`) don't map to country
   codes, so `limit=3` returned 1 country on the map. Smoke
   immediately after every adapter-or-handler-change paid for itself.

3. **The 1-to-N expansion pattern works cleanly for canonical types.**
   `date_range` canonical writes BOTH `start_date` and `end_date`
   legacy keys. Implemented as a per-type helper returning an
   associative array of legacy keys to inject. The switch case
   in `translate()` is a couple of lines. The pattern generalises
   to any future canonical type that maps to multiple legacy
   slots (e.g., `org_filter` with role/orgs subkeys, if those
   map back to multiple legacy widget params).

4. **`App::uses()` in a pure-data-shape helper needs stubbing in
   tests.** CanonicalTypeAdapter uses `App::uses('WidgetSchema',
   ...)` at file load to pull in the schema helper. PHPUnit tests
   (per `project_misp_test_convention`, bare app/Test/*.php with
   no Cake bootstrap) needed a stub `class App` with a no-op
   `uses()` static method before the `require_once`. Pattern:
   if-not-class_exists-define-stub at the top of the test file.

5. **Edit-mode staging requires careful ownership of detached DOM
   elements.** In edit mode, the Remove handler stashes the tile
   element in `_editSnapshot.removedTiles` Map(id → el) so Discard
   can re-add it. ECharts instances inside survive too (they don't
   auto-dispose when the DOM node leaves the document — they hold
   their own canvas references in a global registry). On Save
   commit, we explicitly `disposeChartsIn()` for each pending-
   removed tile before the snapshot is released, plugging what
   would otherwise be a slow ECharts global-map leak.

6. **`_saveLayout()` swallowing its own errors broke `_commitEdit`'s
   try/catch.** Refactored `_saveLayout` to return a success bool
   so `_commitEdit` can branch on outcome without depending on the
   swallow-and-dispatch pattern. The 'save-failed' event still
   fires for theme JS listeners.

7. **Per-widget POST is needed to close the configure-form-in-edit-
   mode leak cleanly.** The current `_saveLayout` is whole-blob.
   In edit mode, a configure-form Save would commit both the widget
   config change AND any staged layout edits. Documented the
   limitation in the `_stageOrSave` docblock and the Done note;
   landing the proper per-widget POST is the dedicated tracker
   task `"Configure-form Save: per-widget POST to /dashboards/
   updateSettings..."` that closes the loop.

8. **Canonical type defaults must omit the wire-format in widget
   $schema until the adapter ships.** Held over from lesson #2 of
   the 2026-05-18 handoff and exercised this session: canonical
   `time_window` defaults like `'P7D'` only safely landed once the
   adapter was wired in `renderWidget`. Until then `(int)'P7D' = 0`
   → empty render. The two-step pattern (adapter first, then
   defaults) is the right cadence for each new canonical type.

9. **Multi-commit per-widget backfills mirror Phase 2 style.** The
   date_range backfill across 3 widgets shipped as 3 separate
   commits (one per widget) — same per-widget convention as the
   Phase 2 $schema backfill. Easier to review one widget at a
   time; clearer Done notes; the adapter helper commit (one) +
   one-per-widget backfill commit pattern is the template.

The prior session's gotchas still apply:

10. **`git mv` does NOT auto-stage subsequent content edits.** Always
    `git status --short` and verify every modification you intend to
    commit shows in the LEFT column.

11. **GPG agent times out the commit signature** if pinentry isn't
    completed promptly. Symptom: `signing failed: Timeout`. Fix:
    from the user's terminal, run `echo "test" | gpg --clearsign >
    /dev/null`, enter the passphrase to prime the agent, then retry.

12. **`Themed/<Name>/Layouts/<layout>.ctp` must exist for every new
    layout you introduce.** Carries from prior session; not exercised
    this session (no new layouts), but the wrapper Overmind override
    needed the data-widget-placeholder attribute mirror update for
    the seeding work — same lesson at the element level.

## Discovered work parked for later (deferred)

Most this-session items are now in `dashboard-progress.md`'s
Discovered work section. Key ones to know about from a planning
perspective:

- **OrgEventsWidget months>13 malformed dates**: surfaced during
  the OrgEventsWidget logarithmic smoke. When config has `months
  > 13`, the wrap-around guard `if ($target_month < 1) { $target_
  month += 12; }` only adds 12 once instead of looping, producing
  dates like `2025--1-01`. Quick fix (~15 min): convert to
  `while ($target_month < 1) { $target_month += 12; $target_year
  -= 1; }`. Not added to the formal Discovered work section yet —
  worth a follow-up commit.

- **TrendingAttributesWidget pre-existing PHP 8.x Attribute model
  crash**: same root cause as TrendingTagsWidget's pre-existing
  `over_time=true` crash — `ClassRegistry::init('Attribute')`
  collides with PHP 8.0+'s built-in `Attribute` class. The
  existing Discovered-work entry was extended this session to
  cover both widgets. TrendingAttributesWidget always crashes
  (unconditional in handler() line 85); TrendingTagsWidget only
  crashes with over_time=true. MISP core fix needed.

- **Configure-form Save in edit mode leaks staged layout**:
  per DD-05, configure-form Save should be a per-widget POST.
  Today it's whole-blob via `_scheduleSave` → `_saveLayout`. In
  edit mode this means a configure-form Save commits both the
  widget config AND any staged layout edits. Documented; closes
  with the dedicated per-widget POST tracker task.

- **EventEvolutionLineWidget ignores end_date**: handler hardcodes
  `$end = new DateTime(date('Y-m') . '-01')`. Canonical date_range
  with bounded `to` is dutifully written to end_date by the adapter
  but ignored by handler(). Documented in the H4 commit. A future
  handler change could honor end_date but that's outside additive-
  only posture.

- **Live preview race window**: rapid pause-type-pause-type cycles
  can race two in-flight `_renderWidget` POSTs (carryover from
  2026-05-18). Self-corrects on next pause. Fix is an
  `AbortController` on `_renderWidget` scoped to the preview path.

- **Drop dormant `dashboard.midnight.css` loader** (carryover).
  Both default and themed dashboard layouts load it; selector
  `:root[data-theme="midnight"]` never matches.

- **`save_template.ctp:4` action-name mismatch** — Phase 4 work
  (carryover).

## Open thread / next obvious work

Lots of small-ish options + a few bigger pieces. In rough
priority order:

**Option A: Phase 1 close-out smoke tests (user-driven, ~30 min).**

The three interactive tests from prior handoffs carry forward
unchanged. Needs a real browser pass:

1. **Default theme E2E.** Switch admin's `ui_theme` to `Default`
   (mysql command in Live test instance above), visit `/dashboards`.
   Verify: chrome integration, MispStatusWidget content fetches via
   AJAX, ⋯ More dropdown WAI-ARIA, Edit-layout toggle (now also
   exercises the real edit-mode transaction — drag a tile, click
   Save vs Discard), drag + drop + reload persistence.
2. **Overmind theme E2E.** Admin is already on Overmind. Visit
   `/dashboards`. Verify: BS5 navbar, dashboard chrome below, ⚙
   button opens configure side panel (typed-fields tier visible
   on TrendingTagsWidget; bottom tier seeded from $placeholder
   for any widget with empty config), edit-mode Save/Discard
   buttons now do real work, toolbar bulk-edit chip.
3. **Legacy v1-shape row migration.** Craft `UserSetting:dashboard`
   with v1 shape, visit `/dashboards`, verify LayoutFixup
   normalises on read + save canonicalises the persisted shape.

LLM can prep the SQL/curl recipes; can't drive the browser.

**Option B: OrgEvents months>13 date wrap fix (~15 min).**

Quick, scoped, fixes a small but real correctness bug. Touches one
widget file. Pairs well with any larger block as a warm-up.

**Option C: Add a third canonical type to the adapter (~half-day).**

`tag_filter` is the biggest user-facing one (5+ widget candidates;
the canonical-bulk-edit toolbar exposes it). PRD §5.5 shape:
`{ include: string[], exclude: string[], taxonomies?: string[],
match_event_tags?: bool, match_attribute_tags?: bool }`. Existing
widgets like TrendingTagsWidget have `exclude`/`include`/
`filter_event_tags` as separate $params — adapter would need a
key-restructuring translator. Same scope shape as date_range
(adapter + per-widget backfill multi-commit) but the legacy shape
diff is bigger.

Alternative: `org_filter` (PRD §5.5 identity-based with role)
or `sharing_group_filter` (single-shape, simplest). Pick by
expected user value vs implementation complexity.

**Option D: Configure-form per-widget POST (~half-day).**

Closes the documented edit-mode leak. Two pieces:
- Server: extend `DashboardsController::updateSettings` (or new
  endpoint) to accept `{instance_id, config}` and patch only that
  widget's entry in the saved blob, leaving rest untouched.
- Client: configure-form Save fires the new per-widget endpoint
  instead of `_scheduleSave`. Toolbar bulk-edit gets the same
  treatment for consistency.

Closes the "Configure-form Save: per-widget POST" tracker entry +
removes the in-edit-mode leak.

**Option E: Widget gallery + Add Widget flow (~full day+).**

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

Best as its own dedicated session.

**Option F: Chip input component for arrays (~half-day).**

Replace the JSON-array-in-text-field UX for bottom-tier array
values with a chip input (type-and-Enter to add, click × to
remove). Also reusable in canonical pickers like tag_filter and
org_filter once those land. Detect arrays at flatten() time;
render with chip-input control; readBack collects chip values
back into an array.

**Option G: Console.log cleanup + bottom-tier flatten/reNest tests
(~half-day).**

Two tracker entries together. Audit all dashboard JS modules for
stray console.log/info statements that shouldn't ship. Add unit
tests for the flatten/reNest helpers that round-trip nested
objects / arrays / scalars / booleans (current implementation
relies on manual smoke).

**Option H: Per-canonical-type form field elements (~half-day per
type).**

Time_window already has `canonical/time_window.mjs` (the picker).
date_range needs `canonical/date_range.mjs` — two-date picker pair
that emits `{from, to}` JSON. tag_filter needs a chip-input-based
include/exclude pair with taxonomy autocomplete. Each gets a
`CANONICAL_BUILDERS` registry entry in configure.module.mjs and a
parallel toolbar.module.mjs entry. Recommend pairing with C (the
canonical type itself) so the widget gallery / configure form
exercises the new type end-to-end on the same commit cycle.

**Recommendation:** A (when the user is in front of a browser) +
B (warm-up fix) for the next session opener. Then either D (closes
the documented leak; needed before edit-mode goes mainstream) or
C+H paired (next canonical type + its picker, end-to-end). Option
E is best as its own multi-session block.

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
  user can choose to restart. (This session ended at ~37% — under
  the user's 40% guardrail.)
- Hard-refresh after CSS/JS edits — the `?v=185` cache-buster from
  `AppController::__queryVersion` doesn't bump per-file.
- Stub `class App { public static function uses() {} }` at the top
  of PHPUnit tests for any helper that uses `App::uses()` at file
  load — pattern shipped in `CanonicalTypeAdapterTest.php`.
- For canonical-type additions: ship adapter helper commit first
  (pure additive), then per-widget backfill commits (one per
  widget). Avoid bundling adapter+wire+defaults+backfills in a
  single commit — review-friendly split.
