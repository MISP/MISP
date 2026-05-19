# Dashboard v2 — Session handoff (2026-05-19, super-late session)

Brief read-out for a fresh session to pick up cleanly. Authoritative
state still lives in:

- `dashboard-prd.md` — spec (self-contained; §13 + §15 catalogue
  binding decisions inline; §5.5 catalogue **grew this session** with
  the addition of `org_meta_filter`)
- `dashboard-progress.md` — task state, Done notes, Discovered work
- `dashboard-design-decisions.md` — DD-01..DD-08 binding decisions
  (full rationale, alternatives, reversibility)

This file is the bridge: ephemeral session-level context that doesn't
fit the durable docs. Replace it as work progresses.

## TL;DR

**Massive Phase 2 + Phase 3 stretch this session — 14 signed commits,
all `%G? = U`.** Two complete canonical-type end-to-end roll-outs
(`tag_filter` + new `org_meta_filter`), one toolbar dispatch refactor
that generalises structured-type bulk-edit, three Phase 2 hygiene
items (chip-input, flatten/reNest tests, console.info cleanup), and
two pre-existing widget bug fixes (OrgContributionToplistWidget
IN(NULL) crash, TrendingAttributesWidget national→nationality typo).

**Phase 2 — now ~20/22 done.** Up from ~17/22 at session start. Three
of the still-open Phase 2 items closed: chip-input component,
flatten/reNest unit tests, console.log cleanup. Remaining: widget
gallery + Add Widget flow (largest remaining surface, multi-session)
and sticky preview pane in configure side-panel (half-day).

**Phase 3 — now 4/12 canonical types fully end-to-end.** Was 2/11
at session start. Added two new ones:
- `tag_filter` — adapter + JS chip-input picker + TrendingTagsWidget
  schema backfill. Toolbar-eligible end-to-end after the dispatch
  refactor (3rd commit below). 18 new PHPUnit tests.
- `org_meta_filter` — **brand new canonical type added to PRD §5.5**
  (catalogue grew by one). Pass-through translator, 6 chip-input
  rows in the picker (sector / type / nationality / name / uuid /
  local), backfilled across all 9 in-tree consumer widgets. 9 new
  PHPUnit tests.

The denominator changed from 11 → 12 because the PRD catalogue grew.
PRD's `org_filter` (org-identity) stays declared but has zero
consumers; `org_meta_filter` is the practical-MISP analogue every
widget actually uses today.

**Toolbar dispatch generalised** for structured canonical types in
`aab80eb77`. Now: declarer detection is `$schema`-driven (not config-
key-based — the prototype shortcut); mixed-state computation
dispatches through `canonical.equal()` (defaults to JSON.stringify
deep-equal for objects + String() compare for scalars); bulk-save
new-value capture dispatches through `canonical.readValue()` when
defined, falls back to scalar `.value` otherwise. Pattern means every
future canonical type ships toolbar-eligible with just a
`CANONICAL_REGISTRY` entry and a `readValue` export — no further
toolbar refactor.

**Two pre-existing widget bugs squashed:**
- `c034e760e` — OrgContributionToplistWidget crashed with SQL syntax
  error when the org-meta filter resolved to zero matching orgs
  (`IN (NULL)`). Sentinel `[-1]` guard.
- `5e2536670` — TrendingAttributesWidget's `$validOrgFilters` used
  `'national'` instead of `'nationality'`, contradicting its own
  `$params` doc string. One-word rename. Prereq for the
  TrendingAttributesWidget org_meta_filter backfill.

**Next session: pick from** (see Open thread below)

1. Widget gallery + Add Widget flow — largest remaining Phase 2
   surface; multi-session work.
2. Phase 5 grid auto-place push-down — half-day, UX paper-cut user
   surfaced during prior smoke.
3. Next canonical type — `sharing_group_filter` or one of the
   `*_filter` int-array trio (`distribution_filter`,
   `threat_level_filter`, `analysis_filter`). All have simple
   shapes; audit needed to confirm consumer widgets.
4. time_window toolbar dropdown-menu UX alternative — surfaced today,
   half-day refactor.
5. Sticky preview pane in configure side-panel — half-day Phase 2 polish.
6. Widget renderer drilldown / cosmetic fixes (tlp:clear white-on-
   white BarChart bars; carries from prior session).
7. TrendingAttributesWidget pre-existing PHP 8 Attribute model
   collision — needs a small MISP core touch, separate from v2 work.

User direction carries forward: *"modern and pleasant"* — generous
whitespace, soft visual weight, subtle shadows, no animation flourish,
smooth keyboard navigation. *"don't worry too much about compatibility
with the current implementation, none of v2 has made it to the
userbase yet"* — invited refactors of v2 internals where it helps.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [x]

Phase 2 — Authoring UX                                            [/] ~20/22
  [x] $schema property contract + WidgetSchema helper + 26 tests
  [x] 9 widget $schema backfills (Phase 2)
  [x] Two-tier configure form element — schema-driven
  [x] Live preview, 250ms debounced
  [x] Per-canonical-type field elements (time_window only;
      rest are Phase 3)
  [x] Key-value list component for the bottom tier
  [x] Chip input component for array-typed values         (NEW)
  [x] Bottom-tier seeding from $placeholder
  [x] Bottom-tier dot-notation flatten/reNest tests        (NEW)
  [x] Side-panel container for configure form
  [ ] Sticky preview pane in configure side-panel
  [ ] Widget gallery + Add Widget flow + Edit Widget flow
  [x] Edit-mode vs. view-mode toggle
  [x] Layout-only atomic save (DD-05)
  [x] Discard (edit mode) with confirm-if-dirty
  [x] Drag/resize/add/remove only fire in edit mode
  [x] Configure-form Save: per-widget POST (prior session)
  [x] Save/Discard UI buttons + body-attribute mode mirror
  [x] Console.log cleanup                                  (NEW)

Phase 3 — Canonical-type toolbar                                  [/] 4/12 types
  [x] CanonicalTypeAdapter helper + 33 PHPUnit tests (prior)
  [x] Wire CanonicalTypeAdapter into renderWidget (prior)
  [/] Canonical types: 4/12
        [x] time_window
        [x] date_range
        [x] tag_filter                                     (NEW)
        [x] org_meta_filter — NEW canonical, PRD §5.5      (NEW)
        [ ] org_filter (no consumers today)
        [ ] sharing_group_filter
        [ ] galaxy_cluster_filter
        [ ] distribution_filter
        [ ] threat_level_filter
        [ ] analysis_filter
        [ ] attribute_type_filter (widget-only)
        [ ] event_id_filter (widget-only)
  [x] Toolbar control logic (schema-driven declarer scan)  (NEW)
  [x] Toolbar bulk-edit write path (readValue dispatch)    (NEW)
  [/] Toolbar UI: time_window + tag_filter + org_meta_filter shipped;
      others land as each canonical ports
  [ ] Per-canonical-type validators (server-side shape check)
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
- **Admin user is on Overmind theme** (`UserSetting:ui_theme = "Overmind"`).
- DB creds: `mysql -u misp -pPassword1234 misp`

Saved-layout state at session end: admin still has the same 4 widgets
from prior sessions (MispStatusWidget / TrendingTagsWidget /
OrganisationMapWidget / OrgContributionToplistWidget). No layout
changes this session — all work was code/schema/test additions.

Expected toolbar state on admin's dashboard with the new dispatch:
- "Time window: 90d" chip (1 declarer — TrendingTagsWidget;
  OrgContributionToplistWidget has time_window in its config but no
  schema declaration → not a declarer per the schema-driven model)
- "Tag filter: (unset)" chip (1 declarer — TrendingTagsWidget)
- "Org meta filter: (none)" chip (2 declarers —
  OrgContributionToplistWidget + OrganisationMapWidget, neither has
  a saved filter)

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

Canonical-type renderWidget smoke (works for any widget that declares
the type in `$schema` — exercises the adapter end-to-end):
```bash
# Adapter pass-through for org_meta_filter (UsageDataWidget):
CONFIG='{"filter":{"sector":["Financial"],"type":["CIRCL","!Test"]},"start_date":"2024-01-01"}'
curl -sb /tmp/cj.txt -X POST -H "Accept: application/json" \
  --data-urlencode "widget=UsageDataWidget" \
  --data-urlencode "config=$CONFIG" \
  "http://localhost:5007/dashboards/renderWidget/w_1"

# Adapter 1-to-N expansion for tag_filter (TrendingTagsWidget):
CONFIG='{"time_window":"P7D","tag_filter":{"include":["tlp:white"],"exclude":["pap:"]},"threshold":5}'
curl -sb /tmp/cj.txt -X POST -H "Accept: application/json" \
  --data-urlencode "widget=TrendingTagsWidget" \
  --data-urlencode "config=$CONFIG" \
  "http://localhost:5007/dashboards/renderWidget/w_2"
# Returned config blob carries canonical tag_filter wire AND derived
# legacy include/exclude — handler() reads the legacy keys.
```

## What this session committed (in order)

```
b8539e0c7  new: Phase 2 — chip-input component for array-typed kv values
                New module app/webroot/js/dashboard/chips.module.mjs.
                Enter/Tab/comma commits; Backspace removes last on empty;
                click × removes; blur commits pending text. Type
                preservation via data-misp-chip-type so {local:[0,1]}
                round-trips lossless. Integrated into bottom-tier kv
                list: array-shape values auto-render as chip-input via
                asArray() detection. Reused later by tag_filter +
                org_meta_filter pickers — the foundational primitive.

ae293dc8f  new: Phase 2 — flatten/reNest unit tests + helpers extracted
                Pulled the pure shape helpers (flatten / reNest /
                asArray / seedFromPlaceholder) from configure.module.mjs
                into a new kvshape.module.mjs so they're testable
                without jsdom. configure.module.mjs imports back —
                ~70 lines shorter. New app/Test/js/KVShape.test.mjs
                with 55 node:test cases covering round-trip lossless
                for empty / scalar / nested / array / boolean / null
                / mixed-type / OrganisationMapWidget placeholder /
                strings that look like JSON tokens / etc. New JS-test
                subdir app/Test/js/ parallel to PHP app/Test/. Run:
                node --test app/Test/js/KVShape.test.mjs → 55/55.

8fc1fac9a  chg: Phase 2 — drop dead action-stub branches + console.info
                Audited every dashboard JS module. 5 console.warn at
                error boundaries kept (configure markup missing, save
                failure, unknown chart kind, malformed payload — all
                fire only on actual failure). 2 console.info stub
                markers removed along with their dead case branches
                (add-widget / set-scope / pause-refresh / export-json
                / export-csv — verified zero DOM triggers). board.
                module.mjs shrinks 24845B → 24189B.

591cd1124  new: Phase 3 — CanonicalTypeAdapter tag_filter translator
                translateTagFilter() implements the 1-to-N expansion:
                canonical tag_filter.include/exclude → top-level legacy
                include/exclude keys (mirrors date_range pattern).
                Empty canonical lists don't overwrite legacy entries
                so user's bottom-tier-set legacy values survive
                canonical-unset state. taxonomies / match_event_tags
                / match_attribute_tags forward-compat fields preserved
                in config[tag_filter] verbatim. String coercion is
                defensive (numeric tag names from JSON round-trip).
                18 new PHPUnit tests; suite 33 → 51.

e334aad76  new: Phase 3 — tag_filter JS picker + structured readBack
                New module app/webroot/js/dashboard/canonical/tag_filter.mjs.
                Two chip-input rows (include + exclude). readValue
                returns canonical object. Forward-compat fields
                round-trip via stashed root-element property. CSS
                .misp-tag-filter-row two-column grid. configure.module.
                mjs registry gains [TagFilter.KEY]: TagFilter; readBack
                dispatch through CANONICAL_BUILDERS[t].readValue when
                defined. The generalisation that lets future structured
                canonical types ship plug-and-play.

7f66d09d1  chg: Phase 3 — TrendingTagsWidget $schema backfill: tag_filter
                Adds tag_filter schema entry between time_window and
                threshold. The only widget today with literal
                include/exclude tag-substring slots (audit confirmed).
                filter_event_tags stays in $params bottom-tier (event
                pre-filter, different semantics). End-to-end smoke
                via three POST /dashboards/renderWidget shapes:
                canonical-only / legacy-only / canonical-empty-with-
                legacy — all 200 with adapter behaving correctly.

aab80eb77  new: Phase 3 — toolbar dispatch refactored for structured types
                Major refactor of toolbar.module.mjs.
                declarersFor walks data-widget-schema (schema-driven,
                not config-key-based) returning {el, schemaKey, value}
                tuples by entry.type === canonical.KEY. Handles widgets
                declaring under non-conventional schema keys (e.g.
                RecentSightingsWidget's `last` for time_window).
                computeState accepts canonical.equal hook; defaultEqual
                handles objects via JSON.stringify and scalars via
                String(). commitBulk writes cfg[d.schemaKey] (not
                cfg[canonical.KEY]); newValue capture via canonical.
                readValue when defined. time_window.mjs gained
                readValue export. TagFilter added to CANONICAL_REGISTRY.
                Pattern means future canonical types ship toolbar-
                eligible with one registry entry + readValue export.

ad0b9af94  new: Phase 3 — org_meta_filter canonical type (PRD §5.5 amendment)
                Introduces a brand-new canonical type to fill the gap
                between the PRD's org_filter (org-identity, zero
                consumers) and what 8 in-tree widgets actually use
                (org-meta-data filter under $params['filter']). PRD
                §5.5 catalogue grew by one row. Shape: {sector?, type?,
                nationality?, name?, uuid?, local?} with !-prefix
                negation. WidgetSchema CANONICAL_TYPES +
                TOOLBAR_ELIGIBLE_TYPES updated. Adapter case is
                pass-through (canonical and legacy shapes match;
                explicit case documents intent + future
                normalisation hook). 9 new PHPUnit tests; suite 51 → 60.

b81b480e5  new: Phase 3 — org_meta_filter JS picker + registry wiring
                New module app/webroot/js/dashboard/canonical/
                org_meta_filter.mjs. Six chip-input rows. readValue
                returns sparse object (empty rows omitted) to match
                handler's !empty()-guard. Custom equal() canonicaliser
                treats empty arrays as equivalent to missing keys.
                displayLabel emits "(none)" / "sector:2" / "sector:2,
                type:1" / "4 keys". Wired into both configure form's
                CANONICAL_BUILDERS and toolbar's CANONICAL_REGISTRY.
                CSS .misp-org-meta-row piggybacks on tag_filter row
                pattern.

35ab04ab5  chg: Phase 3 — $schema backfill: 6 widgets declare org_meta_filter
                OrgContributionToplistWidget, UsageDataWidget,
                EventEvolutionLineWidget, UserContributionToplistWidget,
                OrgEvolutionLineWidget, NewOrgsWidget — all use the
                full org-meta key set (sector / type / nationality /
                name / uuid). Each gets one schema entry. UsageData
                Widget + EventEvolutionLineWidget already had a
                $schema array (date_range / cumulative backfills);
                filter entry inserted alongside. Others gain a fresh
                $schema right after $params.

27b9f47ab  chg: Phase 3 — $schema backfill: 2 local-set widgets declare org_meta_filter
                OrganisationMapWidget + OrganisationListWidget — both
                restricted to sector/type/local via their private
                validFilterKeys. Schema entry's help text documents
                that toolbar-set name/nationality/uuid are silently
                dropped by these widgets (per design contract noted
                in PRD §5.5 amendment).

c034e760e  fix: OrgContributionToplistWidget guards against IN(NULL) on empty filter
                Pre-existing handler bug surfaced during the
                org_meta_filter smoke. When the filter matched zero
                orgs, array_keys($org_ids) was [] and Event.orgc_id IN
                () was malformed SQL (manifested as IN (NULL)).
                Sentinel [-1] guard mirroring
                TrendingAttributesWidget's pattern. 500 → 200.

5e2536670  fix: TrendingAttributesWidget org_filter accepts 'nationality' not 'national'
                Pre-existing typo. Widget's private $validOrgFilters
                used 'national' but $params doc says
                'Organisation.nationality' and every other widget uses
                'nationality'. One-word rename. Unblocks the
                TrendingAttributesWidget org_meta_filter backfill.

63d782f90  chg: Phase 3 — TrendingAttributesWidget $schema backfill: org_meta_filter
                Final org_meta_filter consumer. Schema key is
                'org_filter' (matches widget's legacy slot — the
                schema-driven dispatch handles non-conventional keys
                naturally). Note: this widget itself still has the
                pre-existing PHP 8 ClassRegistry::init('Attribute')
                collision crash so renderWidget can't actually render
                under PHP 8 — but the adapter pipeline runs to
                completion before the crash, so the schema-driven
                dispatch is verified.
```

14 commits this session, all signed (`%G?` = `U`).

## Lessons from this session

1. **Pre-existing widget bugs surface easily through canonical wire.**
   The OrgContributionToplistWidget IN(NULL) crash was always there —
   any user who set an org-meta filter that matched no orgs would hit
   it. But the canonical wire makes it easier to trigger (toolbar
   bulk-edit hands users a confident-feeling UI). When backfilling
   canonical types, **smoke each widget's renderWidget under the new
   shape** and watch for pre-existing bugs that surface. Fix or flag
   them; don't ignore.

2. **Pushback before plunging is worth the round-trip.** The user
   asked for "org_filter end-to-end". The PRD's canonical org_filter
   has zero consumers; plunging into it would have produced pure
   plumbing. The 2-minute pushback ("here are 3 options, with
   trade-offs") got us to the actually-useful work (`org_meta_filter`
   as a new canonical type) and a PRD amendment. Memory
   `feedback_rigorous_pushback` is doing its job.

3. **PRD amendments are fine when v2 hasn't shipped.** The catalogue
   grew by one type this session. The user's "don't worry about
   compat" was the explicit license. Memory tracks that this
   permission is scoped to v2 internals, not to arbitrary MISP-core
   code.

4. **Toolbar dispatch generalisation pays dividends fast.** The
   refactor in `aab80eb77` (~50 lines net change) made org_meta_filter
   ship toolbar-eligible with just **one CANONICAL_REGISTRY entry**
   plus a `readValue` export. Pattern: declarer scan, equality hook,
   readValue dispatch — three generalisations together unlock plug-
   and-play for every future structured canonical type.

5. **Bundle backfill commits when the pattern is identical.** I did
   the 6-widget bundle + 2-widget bundle vs one-commit-per-widget.
   Per-task-commit convention is for review-friendliness; when 6
   commits would each be three identical lines, bundling is the
   right call (the commit body lists the 6 widgets by name + audit
   results). The 8 widgets landed in 2 commits + 1 prereq fix + 1
   completing commit = 4 commits total instead of 9. Reasonable.

6. **`$schema`-driven everything.** The Phase 3 work today
   consistently chose `$schema` as the discovery surface — toolbar
   declarers via schema (not config-key presence); configure-form
   typed tier dispatch via schema; adapter translation via schema.
   The schema is now the single source of truth for "what canonical
   types does this widget participate in". Config-key-based shortcuts
   (the v1-style "if the user wrote this key, treat it as canonical")
   are gone everywhere they used to live.

The prior session's gotchas still apply:

7. **`git mv` does NOT auto-stage subsequent content edits.** Always
   `git status --short` and verify every modification you intend to
   commit shows in the LEFT column.

8. **GPG agent times out the commit signature** if pinentry isn't
   completed promptly. Symptom: `signing failed: Timeout`. Fix:
   from the user's terminal, run `echo "test" | gpg --clearsign >
   /dev/null`, enter the passphrase to prime the agent, then retry.
   (Hit this twice this session.)

9. **`Themed/<Name>/Layouts/<layout>.ctp` must exist for every new
   layout you introduce.** No new layouts this session — only JS/CSS/
   PHP additions, no new view templates. Themed override path
   untouched.

## Discovered work parked for later

Items found during implementation that didn't fit a planned task.
Most of this-session items are now in `dashboard-progress.md`'s
Discovered work section. Key ones to know about for planning:

- **time_window toolbar UX — dropdown-menu chip alternative** (surfaced
  2026-05-19). Current implementation is a full popover with text-
  input + 5 preset buttons + format hint + Cancel/Apply. A dropdown-
  menu chip (click → list of presets + "Custom…") would be faster
  for common-case preset switching. Half-day refactor. Surfaced today
  when refactoring the toolbar for structured-type dispatch — flagged
  for revisit after end-user smoke surfaces whether the current popover
  is acceptable.

- **Grid drop-on-occupied cascade (Phase 5 — parked 2026-05-19).**
  PDD bounces back on collision; users expect Gridstack-style
  auto-displace. Half-day for push-down-on-drop with stable
  iteration (drop tile's height shifts colliding tiles down,
  iterate until stable); 1-2 days for predictive in-drag preview
  (tiles slide aside as the drag tile hovers). Pairs naturally
  with the Widget Gallery / Add Widget flow.

- **tlp:clear (#ffffff) renders invisible bars (surfaced 2026-05-19).**
  Cosmetic renderer fix — add a 1px border to each bar / line
  segment, or detect high-luminance fill colours and substitute
  a contrast token. Carries from prior session.

- **OrgEventsWidget months>13 malformed dates.** Wrap-around guard
  only adds 12 once → dates like `2025--1-01`. Quick fix (~15 min):
  convert to `while`. Carries from prior session.

- **TrendingAttributesWidget pre-existing PHP 8.x Attribute model
  crash.** `ClassRegistry::init('Attribute')` collides with PHP 8.0+
  built-in Attribute class. The org_meta_filter backfill on this
  widget runs to completion through the adapter but handler() fatals
  at the model load. Carries from prior session — needs MISP core
  fix (rename the model usage or namespace-qualify).

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

In rough priority order:

**Option A: Widget gallery + Add Widget flow (multi-session).**

Largest remaining Phase 2 surface. Server endpoint per PRD §5.8
returning widget metadata; gallery grid + card elements; search +
category grouping; Add Widget state machine in board.module.mjs.
Best as its own dedicated multi-session block. Closes Phase 2.

**Option B: Phase 5 grid auto-place push-down (half-day).**

Modest scope, immediate UX win, unblocks the Widget Gallery's
Add Widget flow because new widgets can land on top of existing
layout cleanly. Approach: in `Grid._commit`'s drop branch, detect
colliding tile rectangles; for each colliding tile, shift down by
drop.h rows; iterate until stable.

**Option C: Next canonical type (half-day to ~full-day each).**

The `*_filter` int-array trio (`distribution_filter`,
`threat_level_filter`, `analysis_filter`) all have the same shape
`{ levels: int[] }`. Audit for consumers first — could be plumbing-
only if no widget declares them under their canonical name today.

`sharing_group_filter` is the other small canonical
(`{ sharing_group_ids: int[] }`). Same audit concern.

The bigger canonical types still pending — `galaxy_cluster_filter`,
the widget-only ones — need PRD-level review for the same
"actual-MISP shape vs PRD shape" question that org_filter raised.

**Option D: time_window toolbar dropdown-menu UX (half-day).**

Replace the full popover with a dropdown-menu (presets immediate-
write; "Custom…" expands inline). Surfaced today during the toolbar
refactor. Worth doing while toolbar code is fresh in memory.

**Option E: Sticky preview pane in configure side-panel (half-day).**

Phase 2 task. Widen the panel to two columns; left column hosts the
form; right column hosts a sticky preview. Trade-off: side panel is
already crowded on narrow viewports.

**Option F: TrendingAttributesWidget PHP 8 Attribute collision (small-
to-medium).**

Pre-existing crash that prevents the widget from rendering. Needs
either a model rename or namespace qualification of the
`ClassRegistry::init('Attribute')` call. MISP core touch — outside
strict v2 scope but unblocks end-user smoke of the widget's new
canonical wiring.

**Option G: Renderer-side colour-contrast safety (~half-day).**

The tlp:clear (#ffffff) discovery. Add luminance check in
`buildBarOption` / `buildLineOption`; if ≥ 0.85, use a fallback or
add a 1px stroke. Carries from prior session.

**Recommendation:** A or B for the most user-visible payoff. Save
the canonical-type plumbing (C, D) for sessions when you want
short focused chunks; A is the biggest remaining Phase 2 surface
and closes Phase 2 cleanly when it lands.

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  the commit body references the task. **Bundle backfill commits**
  when the pattern is identical across 5+ widgets (the body lists
  the widgets by name); separate commits when the pattern diverges
  per widget.
- **Always `git status --short` + explicit `git add` before commit**.
- New files land with `iglocska:iglocska` ownership; `chgrp www-data`
  before committing to match repo convention.
- The proto's wrapper-element + Themed-override pattern is the
  playbook for any future override surface. Stay attribute-driven;
  class names are themeable.
- User wants rigorous pushback, not yes-machine output — surface
  trade-offs, name alternatives, recommend a path, then go with the
  user's call. Today's `org_meta_filter` PRD amendment was a textbook
  example.
- User alternates hitm / afk sessions; tracker docs are the ground
  truth between sessions. Tick one task at a time; the Done note
  carries the deciding context. Bundle commits don't tick more than
  one tracker line per commit — the commit IS the unit.
- Surface context status when past 75% at task boundaries so the
  user can choose to restart. This session ended at ~38% — well
  under the threshold.
- Hard-refresh after CSS/JS edits — the `?v=185` cache-buster from
  `AppController::__queryVersion` doesn't bump per-file.
- For canonical-type additions: ship adapter helper commit first
  (pure additive), then JS picker commit, then per-widget backfill
  commits. The 4-6 commit shape of tag_filter and org_meta_filter
  this session is the template. Skip the toolbar-eligibility step
  for first-landing if the type has zero declarers (org_filter style);
  the pattern is "make sure the canonical-type-aware-widget can
  consume it before the toolbar needs to fire it".
- **A tracker tick requires the user-visible surface to exist AND be
  reachable from the default UI, not just the JS / handler-level
  wiring behind it.** (Lesson #1 from the 2026-05-18 session — still
  applies.)
- **mysql -u misp -pPassword1234 misp` for one-shot SQL; for complex
  payloads with quotes / escapes, use stdin heredoc + `SET @var =
  '...'` bind. Avoid LOAD_FILE — secure_file_priv defeats it.**
  (Lesson #7 from prior session.)
- **The schema-driven model is now the canonical answer** for any
  "how does the toolbar / configure form know which widgets to act
  on" question. Config-key-based shortcuts are gone. Future
  refactors should preserve the schema-as-source-of-truth invariant.
