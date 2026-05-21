# Dashboard v2 — Session handoff (2026-05-21 evening)

Seventh session of the dashboard rewrite. Authoritative state lives in:

- `dashboard-prd.md` — spec.
- `dashboard-progress.md` — task state. **Phase 2 + 3 fully closed.
  Phase 5: 6 of 11 lines closed this session (5 refresh-related
  + 1 manual-refresh ratification).** Drill-down half pending.
- `dashboard-design-decisions.md` — DD-01..DD-08 unchanged.

This file is the bridge: ephemeral session-level context that doesn't
fit the durable docs. Replace it as work progresses.

## TL;DR

**8 signed commits this session**, all `%G?` = `U`. Two structural
milestones + one cleanup batch:

1. **Two carryovers closed early in the session** — TrendingAttributes-
   Widget PHP 8 Attribute model collision (`ClassRegistry::init('Attr-
   ibute')` → `'MispAttribute'`) plus the two remaining stragglers
   (SharingGraphWidget + EventTemplateInstantiator). Codebase-wide
   grep for `ClassRegistry::init('Attribute')` now returns zero hits;
   45+ call sites use the post-rename name.

2. **PRD §5.5 alignment** (Option C) — half-day prose-only edit
   reflecting the three org_filter naming refinements (match_via /
   orgc / sharing_group / negate) and the bare-int-array convention
   for the four single-axis int-enum canonicals. Doc-only commit;
   closes the "Canonical wire shapes drift from PRD §5.5" tracker
   entry.

3. **Phase 5 — refresh half (6 of 11 lines closed).** The board-level
   refresh scheduler core + Page Visibility auto-pause + manual
   refresh ratification (commit `467c8c5ef`); a follow-up fix for
   the renderWrapper enrichment gap caught at browser smoke
   (`ce6815c31`); the pause-refresh toolbar toggle (`0c26b9a62`); the
   per-instance refresh override picker in the configure form
   (`cf0acb1ba`, PRD F2.5); the "updated Ns ago" relative-time chip
   on each tile titlebar (`02527bd62`). The drill-down half + cache
   key board-scope hash remain open (5 lines).

**Notable design decisions taken this session:**

- **Single-source-of-truth client-side delay resolution.** The
  initial scheduler sketch had server-side fold-in of class default
  + config override into a single resolved value emitted as
  `data-widget-refresh-delay`. Backed out mid-implementation in
  favour of: server emits CLASS DEFAULT only as
  `data-widget-refresh-delay`; client-side `resolveDelaySec`
  reads `data-widget-config['refresh_delay']` first, falls back
  to the attribute. Keeping the attribute IMMUTABLE per page-load
  means configure-save just calls `scheduler.enqueueWidget(savedEl)`
  and the resolution picks up the new config — no DOM mutation, no
  renderWrapper re-fetch.

- **`resolveDelaySec` extracted as a top-level export** of
  `scheduler.module.mjs` so both `Scheduler` and `RefreshIndicator`
  share the same priority logic. RefreshIndicator uses it for
  auto-refresh GATING — chips are hidden on tiles whose resolved
  delay is 0 (per user feedback at indicator smoke: static tiles
  shouldn't show "updated 4m ago" because there's no expectation
  of freshness).

- **Dashboard chrome icons stay inline SVG, not Font Awesome** —
  user surfaced the choice during the pause-toggle smoke; rationale
  recorded in the new `feedback-dashboard-chrome-icons` memory.
  PRD §G11 / DD-08 chrome theme-independence + intra-chrome
  consistency (existing More-menu icons all inline SVG) outweigh
  FA's "already loaded by the layout" argument.

- **Indicator chip semantics on `widget-error`** — timestamp NOT
  updated. Chip shows "time since last SUCCESSFUL render" so a
  stuck widget shows an ever-growing chip = diagnostic signal that
  matches user-facing meaning ("how stale is this?") rather than
  technical meaning ("when did we last try?").

**Pre-existing perm-drift carryover surfaced (again):** in this
session, 5 more widget files were caught at local mode `0770 iglocska:
iglocska` (`AuthenticationFailureWidget`, `CsseCovidMapWidget`,
`MispAdminResourceWidget`, `MispAdminWorkerWidget`, `ButtonWidget`).
Same flavour as the 3 files caught last session (SharingGraphWidget
+ 2 others). Git tracks all of them at `0644`. The gallery
endpoint (`/dashboards/widgets`) enumerates the directory and dies on
the first unreadable file with a CakePHP HTML warning that breaks the
JSON serialiser. **Something on the dev box keeps clobbering modes.**
Filesystem-only fixes today; not propagated to git. Worth investigating
when there's appetite, but doesn't block feature work.

**User-direction carried forward unchanged:** *"modern and
pleasant"*, *"don't worry too much about compatibility"*, *"ACL
must match the surface it shadows"*, *"three similar lines is
better than premature abstraction"*, *"prefer MISP-jargon naming
(orgc, sharing_group) over PRD-generic terms"*, **"dashboard chrome
icons stay inline SVG, not FA"** (new this session).

**Phase 5 refresh half done. Drill-down half pending. Next session — pick from** (see Open thread):

1. **Phase 5 — drill-down workstream** (4 lines: validator + SimpleList
   wrap + ECharts handlers + `$drilldown` metadata). Pre-locked design
   from Q3 resolution (PRD §13.3): per-datum drill-down in widget
   data, DashboardURLValidator helper sanitises every URL. Likely
   surfaces a natural consumer for the deferred `event_id_filter`
   picker.
2. **Phase 5 cache-key board-scope hash (F3.3)** — moot today
   (no widget render cache in v2); could be closed as "no-op
   rationale documented" or deferred to whenever a cache is wired.
3. **Phase 4 — template gallery polish** (greenfield, multi-session;
   thumbnail miniatures + restrict_to_* preserved).
4. **File-mode-drift investigation** — figure out what's clobbering
   widget files from `0644` to `0770 iglocska:iglocska`. Two
   filesystem-only patches today; will keep recurring otherwise.
5. **Other parked work** — time_window dropdown UX, midnight.css
   drop, EventEvolutionLine end_date, save_template action-name
   mismatch.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [x]
  All 9 v1 render kinds now have v2 .ctp templates.

Phase 2 — Authoring UX                                            [x] CLOSED

Phase 3 — Canonical-type toolbar                                  [x] CLOSED
  12/12 canonicals + all wrap-up lines.
  PRD §5.5 doc alignment landed 2026-05-21 (this session, Option C).

Phase 5 — Drill-down + refresh scheduler                          [.]
  Refresh half (6/7 lines):
    [x] Board-level refresh scheduler: single timer, max 4 concurrent
        renders in flight (PRD §10)
    [x] Pause-refresh toggle on board toolbar
    [x] Per-instance refresh override in widget config form (F2.5)
    [x] Auto-pause when document hidden (Page Visibility API)
    [x] Manual refresh on a single widget (ratification — existing ↻)
    [x] Refresh indicator chip: "updated 30s ago"; uses relative-
        time formatting that respects locale
    [ ] Verify cache key includes board scope hash (PRD F3.3)
        — moot today (no widget render cache in v2)
  Drill-down half (0/4 lines):
    [ ] $drilldown schema property documented and exposed
    [ ] Drill-down convention per Q3 resolution
    [ ] Renderer-level wrapping for SimpleList
    [ ] ECharts click handlers calling drill-down

Phase 4 — Template gallery polish                                 [ ]
```

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id: 1 (`admin@admin.test`), password `Password12345`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- **Admin user is on Overmind theme** (`UserSetting:ui_theme =
  "Overmind"`).
- DB creds: `mysql -u misp -pPassword1234 misp`

**Saved-layout state at session end:** admin has 5 widgets, same as
the start of this session — `w_1` MispStatusWidget, `w_2` TrendingTags-
Widget, `w_3` OrganisationMapWidget, `w_4` OrgContributionToplist-
Widget, `w_5` EventStreamWidget. EventStreamWidget keeps its
`threat_level=[3,4], analysis=[0,1]` config from prior session;
nothing added or removed this session via the dashboard chrome
(WhoamiWidget was added + removed during smoke testing).

Session-login dance + wrapper-render smoke recipes unchanged from
prior sessions — see `reference-misp-login-dance` memory. Session
cookie at `/tmp/cj.txt` may need refreshing; the login dance is
~30 seconds.

Smoke commands for Phase 5 surfaces:

```bash
# Confirm refresh-delay attribute emitted on auto-refresh widgets only
curl -s -b /tmp/cj.txt http://localhost:5007/dashboards | \
  grep -oE 'data-widget-refresh-delay="[^"]*"'
# → data-widget-refresh-delay="5"  (just EventStreamWidget)

# Confirm refresh_delay schema entry injected on widgets with auto-refresh
curl -s -b /tmp/cj.txt http://localhost:5007/dashboards | python3 -c "
import sys, re, html, json
m = re.search(r'data-widget-name=\"EventStreamWidget\".*?data-widget-schema=\'([^\']*)\'',
              sys.stdin.read(), re.DOTALL)
schema = json.loads(html.unescape(m.group(1)))
print('refresh_delay in schema:', 'refresh_delay' in schema)
print(schema.get('refresh_delay'))"

# Confirm indicator span emitted on every tile (5 in current layout)
curl -s -b /tmp/cj.txt http://localhost:5007/dashboards | \
  grep -oE 'data-misp-widget-refresh-indicator' | wc -l
# → 5

# Confirm scheduler module + indicator module served HTTP 200
for m in scheduler refresh-indicator; do
  curl -s -b /tmp/cj.txt "http://localhost:5007/js/dashboard/$m.module.mjs" \
    -o /dev/null -w "$m: %{http_code} %{size_download}b\n"
done
```

## What this session committed (in order)

```
4fa6bb496  fix: TrendingAttributesWidget PHP 8 Attribute collision
                Single call site rename: ClassRegistry::init('Attribute')
                → 'MispAttribute' (Attribute model was renamed to
                MispAttribute long ago, 45+ call sites already use it;
                3 stragglers remained). Stale @var Event docblock also
                fixed. End-to-end smoke for all 3 config shapes:
                bare, legacy `type:[...]`, canonical `attribute_filter:
                {types:[...]}` — adapter expansion verified.

0cb5288e4  fix: remaining 2 ClassRegistry::init('Attribute') stragglers
                SharingGraphWidget.php:108 + EventTemplateInstantiator.
                php:466. Codebase-wide grep for the old call now returns
                zero. SharingGraphWidget smoke verified; ETI not
                smoke-tested (server-side helper, no widget render entry
                point). Side observation surfaced: SharingGraphWidget
                was at mode 0770 owned by iglocska:iglocska on disk;
                git tracks 0644; normalised filesystem mode.

49158debd  chg: PRD §5.5 alignment with shipped canonical shapes
                Option C. Three edits in dashboard-prd.md §5.5:
                  1. org_filter row — `role` → `match_via`; `"creator"|
                     "distribution"|"any"` → `"orgc"|"sharing_group"|
                     "any"`; added per-entry `negate?: bool`; note
                     expanded with EventStreamWidget consumer reference
                     + legacy comma-string acceptance.
                  2. Four single-axis int-enum rows — wrapping objects
                     replaced with bare int[].
                  3. New "Single-axis int-enum canonical convention"
                     paragraph + "Additive `negate?: bool` primitive"
                     paragraph after the table.
                Tracker entry marked **fixed 2026-05-21**.

467c8c5ef  new: Phase 5 — board-level refresh scheduler core
                Closes 3 of 11 Phase 5 tracker lines. New module
                scheduler.module.mjs (~190 lines). Single 1s setInterval
                walks an instance-id keyed Map; in-flight cap = 4 (PRD
                §10). Tile delay reads `data-widget-refresh-delay`,
                populated server-side by DashboardsController::index
                from per-class $autoRefreshDelay. Last-render learnt
                via the existing widget-rendered event the board
                already dispatches. Page Visibility soft-pause; no
                flush on re-show. Wrapper template gains the new
                data-widget-refresh-delay attribute (default + Overmind
                override); §8.5 contract docblock updated. Browser-
                verified.

ce6815c31  fix: Phase 5 — renderWrapper enrichment gap
                Caught at user-driven browser smoke (test #4 — Add
                Widget WhoamiWidget didn't start ticking). The Add-
                Widget placement path fetches the new tile's wrapper
                HTML from POST /dashboards/renderWrapper, which builds
                its own $widgetData array separate from index()'s
                enrichment loop. Missed autoRefreshDelay in renderWrapper
                in the previous commit. One-line mirror fix.

0c26b9a62  new: Phase 5 — pause-refresh toggle on board toolbar
                Closes 1 Phase 5 line. Compact 32×32 icon button to
                the left of "Edit layout" in modecontrols. Two inline
                SVG glyphs (pause bars + play triangle); CSS swap on
                aria-pressed (no JS text/icon swap logic). Ephemeral
                by design (page reload → running). Page Visibility
                soft-pause orthogonal to user-pause. Icon style choice
                (SVG, not FA) recorded in the new feedback-dashboard-
                chrome-icons memory after the user questioned it
                during smoke and accepted SVG with the rationale.

cf0acb1ba  new: Phase 5 — per-instance refresh override (PRD F2.5)
                Closes 1 Phase 5 line. Schema-driven path:
                DashboardsController::index + renderWrapper inject a
                refresh_delay int schema entry on widgets with
                $autoRefreshDelay > 0; configure form renders it via
                the existing int builder. Architecture revised mid-
                implementation: server emits CLASS DEFAULT only as
                data-widget-refresh-delay (immutable); client-side
                resolveDelaySec reads config.refresh_delay first.
                Configure-save flow gains one line —
                scheduler.enqueueWidget(savedEl) — re-resolution
                happens automatically. Browser-verified: 5s default
                → override=10 → 10s; clear → reverts; 0 → stops.

02527bd62  new: Phase 5 — "updated Ns ago" refresh indicator chip
                Closes 1 Phase 5 line. New module refresh-indicator.
                module.mjs (~135 lines). Hooks widget-rendered event
                → per-instance timestamps; 1s setInterval reformats
                every chip via Intl.RelativeTimeFormat(navigator.
                language, {numeric:'auto', style:'narrow'}). Bucket
                cutoffs: <60s seconds, <3600s minutes, <86400s hours,
                else days. Auto-refresh gating per user feedback at
                smoke: chip hidden on tiles whose resolveDelaySec
                returns 0. Resolution helper extracted from Scheduler
                into a top-level export (single source of truth).
                widget-error events deliberately do NOT update the
                timestamp — chip shows "since last successful render",
                diagnostic signal for stuck widgets. Both wrapper
                templates + Overmind override gain the new
                data-misp-widget-refresh-indicator span (aria-live
                polite, aria-atomic true). CSS uses tabular-nums for
                steady chip width during ticks; :empty {display:none}
                hides the slot before first render and on
                auto-refresh-disabled tiles.
```

Net stats this session:
- 8 signed commits (all %G? = U)
- 2 new client-side modules (scheduler.module.mjs ~190 lines + refresh-
  indicator.module.mjs ~135 lines)
- 1 new server endpoint enrichment (autoRefreshDelay folded into
  index + renderWrapper)
- 2 new wrapper attributes (data-widget-refresh-delay,
  data-misp-widget-refresh-indicator) — added to BOTH default and
  Overmind wrapper templates
- 1 new chrome button (pause toggle, modecontrols block)
- 1 new schema-driven configure form field (refresh_delay int
  picker, only surfaces on auto-refresh widgets)
- 1 new memory entry (feedback-dashboard-chrome-icons)
- 0 PHPUnit tests added (none of the touched paths have test
  coverage today; the existing 152-test suite still passes)
- Working tree clean for v2 work after these 8 commits.

## Lessons from this session

1. **Server-side resolution is a foot-gun when client state can
   change.** The first cut of the scheduler had `DashboardsController::
   index` fold the class default + config override into a single
   resolved value emitted as `data-widget-refresh-delay`. F2.5 (per-
   instance override picker) immediately exposed the problem: after
   a configure save, the wrapper attribute was stale until page
   reload. Either the save flow had to mutate the attribute (or
   trigger a renderWrapper re-fetch) — both add round-trip
   complexity. Backing out the server-side fold-in and doing the
   resolution client-side in `resolveDelaySec` means configure-save
   just re-calls `scheduler.enqueueWidget` and the resolution picks
   up the new config without any DOM attribute mutation. Lesson:
   keep server-emitted attributes IMMUTABLE per page-load; do the
   client-state-dependent resolution at consumption time.

2. **User feedback on the "looks good but…" pattern is precious.**
   Two design refinements landed via that pattern this session:
   (a) FA-vs-SVG on the pause toggle ("looks good, but wouldn't
   FA be more prudent?" → my SVG choice held after surfacing the
   rationale); (b) refresh indicator gating ("works as expected,
   but if a widget has no refresh configured, it shouldn't show
   when it was refreshed" → originally I designed the chip to show
   on every tile because data staleness is useful even for static
   tiles; the user's instinct that "no expectation of freshness →
   no chip" is the right call). Pattern: surface the design call
   plainly, let the user override. Don't pre-empt with the safest
   choice — the user might want the bold choice.

3. **Themed wrapper parity is the single most-forgotten rule.**
   Two times this session I shipped a `wrapper.ctp` change and
   forgot the Overmind override (`data-widget-refresh-delay` first
   commit, `data-misp-widget-refresh-indicator` here). Both were
   caught at server smoke — admin's on Overmind theme, so the
   default wrapper edits literally don't reach the rendered DOM.
   The `project-misp-themed-resolver` memory is already filed; this
   session's adds reinforce that any new `data-*` attribute or
   chrome span needs the parallel Overmind edit in the SAME commit.

4. **Filesystem mode drift is real and recurring.** 3 widget files
   drifted last session, 5 more this session. Both batches were
   `0770 iglocska:iglocska` despite git tracking `0644`. Something
   on the dev box is touching modes outside git's view. Filesystem-
   only patches keep working but the carryover keeps growing — at
   some point this needs root-causing.

5. **The schema-driven configure form makes new typed-field
   additions trivial.** F2.5 (per-instance refresh override picker)
   shipped with ZERO new client-side picker code — server-side
   schema injection + the existing `int` builder did the whole UI.
   The 4-line server-side block in `index()` is the entire feature.
   Lesson: when the form-generation infrastructure is right, new
   typed UI lands almost for free.

6. **Single-source-of-truth helpers earn their keep on the second
   consumer.** `_resolveDelaySec` was a private method on Scheduler
   until RefreshIndicator needed the same priority logic to gate
   the chip. Extracted as a top-level export of `scheduler.module.
   mjs`; both modules import it. The extraction was free at this
   point (single call site → public export), would have been
   harder mid-implementation. Lesson: extract on the second
   consumer, not earlier; but DO extract.

The prior sessions' gotchas still apply (themed resolver silent
fallback, `git mv` doesn't auto-stage, fetchEvent ≠ restSearch,
heredoc + dollar signs, GPG pinentry timeout, mode-drift carryover
above).

## Discovered work parked for later

Active carryovers:

- **Phase 5 drill-down half (4 lines).** Pre-locked design from Q3
  resolution. Likely surfaces a natural consumer for the deferred
  `event_id_filter` picker. Multi-session.

- **Phase 5 cache-key board-scope hash (F3.3).** Moot today — no
  widget render cache in v2. Either close as "no-op rationale
  documented" or defer until a cache lands. Recommendation: close
  with a one-paragraph rationale paragraph in the tracker entry,
  same shape as Phase 3's cache-key-sanity-check closure.

- **File-mode-drift root cause.** 8 widget files patched across
  this session + last. Something is clobbering modes. Worth a
  short investigation: check editor save behaviour, any deploy
  scripts that chmod recursively, umask of the user's primary
  shell, any rsync/scp paths.

- **PRD §5.5 doc alignment** — landed 2026-05-21 (Option C). The
  active carryover from prior session is now CLOSED.

- **MISP 2.4 cross-instance DB write risk:** v2.4 connected to
  the same DB can clobber `user_settings.dashboard` rows. Carries.

- **time_window toolbar dropdown-menu UX alternative.** Carries.
- **Grid drop-on-occupied cascade (Phase 5).** Carries.
- **tlp:clear (#ffffff) renders invisible bars (cosmetic).** Carries.
- **OrgEventsWidget months>13 malformed dates.** Carries.
- **EventEvolutionLineWidget ignores end_date.** Carries.
- **Live preview race window** (carries — AbortController fix).
- **Drop dormant `dashboard.midnight.css` loader.** Carries.
- **`save_template.ctp:4` action-name mismatch** (Phase 4 — carries).
- **Pre-fetch overshoot trade-off documented for EventStream-
  Widget's post-filter canonicals.** Carries.

## Open thread / next obvious work

In rough priority order:

**Option A: Phase 5 drill-down half (4 lines).**

Greenfield, multi-session. Q3 resolution already locks the design
(per-datum drilldown in widget data, `DashboardURLValidator` helper
under `app/Lib/Dashboard/Tools/`, per-renderer wrapping in SimpleList /
BarChart / MultiLineChart / WorldMap). Modest scope per renderer
once the validator is built. A natural consumer for the deferred
`event_id_filter` picker may surface (event-view side-panel widgets
with `"current"` sentinel).

**Option B: Close out Phase 5 (cache-key F3.3 + drill-down).**

If the appetite is to fully ship Phase 5 in one push, the cache-key
line closes as a documented no-op + the drill-down workstream closes
the remaining 4 lines. Roughly 1 cleanup commit + 3-4 drill-down
commits.

**Option C: Phase 4 — template gallery polish.**

Greenfield, multi-session. Pure presentation-layer change plus a
thumbnail generator. Lower architectural risk than drill-down's
cross-cutting renderer touches.

**Option D: File-mode-drift investigation.**

Short detour. 60-minute scope at most. Closes a recurring carryover.

**Option E: Other parked work** — time_window dropdown UX,
midnight.css drop, EventEvolutionLine end_date, save_template
action-name mismatch.

**Recommendation:** **A** if continuing Phase 5 momentum makes
sense — drill-down is the natural pair to the refresh half (both
PRD-Phase-5 work, both client-cutting). **C** if pivoting to a
fresh phase feels right — Phase 4 is the only remaining greenfield
phase before merge-gate prep.

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  the commit body references the task. **Phase 5 commits follow a
  one-commit-per-tracker-line shape** — see the 6 Phase 5 commits
  this session.
- **Always `git status --short` + explicit `git add` before commit**.
  Watch for stray empty files from grep / find with quote-mangling.
- New files land with `iglocska:iglocska` ownership; `chgrp
  www-data` before committing to match repo convention. **The new
  refresh-indicator.module.mjs was chgrp'd this session; preserve
  the pattern.**
- **Themed wrapper parity:** any new `data-*` attribute or chrome
  span on `app/View/Elements/dashboard/widget/wrapper.ctp` MUST
  be mirrored in `app/View/Themed/Overmind/Elements/dashboard/
  widget/wrapper.ctp` in the SAME commit. Default wrapper edits
  literally don't reach the rendered DOM for an Overmind user
  (which the dev admin is). The themed-resolver memory has filed
  this; check for any third-party theme overrides too via
  `find app/View/Themed -path '*Elements/dashboard/widget*'`.
- **Dashboard chrome icons are inline SVG, not Font Awesome** —
  see `feedback-dashboard-chrome-icons` memory. The chrome was
  designed as a Bootstrap/FA-independent island per PRD §G11; FA
  belongs on surfaces outside the chrome.
- **Single-source-of-truth helpers earn their keep on the second
  consumer.** When two modules need the same logic, extract as a
  top-level export rather than duplicate (e.g. `resolveDelaySec` in
  scheduler.module.mjs).
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
  user can choose to restart.
- Hard-refresh after CSS/JS edits — the `?v=185` cache-buster
  from `AppController::__queryVersion` doesn't bump per-file.
- **The schema-driven model is the canonical answer** for any
  "how does the toolbar / configure form know which widgets to
  act on" question. F2.5 picker shipped with zero new client-
  side code because schema-injection drove the form generator.
- **A tracker tick requires the user-visible surface to exist
  AND be reachable from the default UI**, not just the JS /
  handler-level wiring behind it. Browser-verify every Phase 5
  line before ticking — both refresh half and drill-down half
  need real-browser smoke (the headless harness is not the
  source of truth per the visibility-quirk caveat).
- **`mysql -u misp -pPassword1234 misp` for one-shot SQL.**
- **Render-kind glyph requirement (carries):** any new value
  for `public $render` on a widget class, or any new template
  under `app/View/Elements/dashboard/Widgets/`, must ship with
  a matching glyph in `render-thumbs.mjs` in the same commit.
- **Heredoc + dollar signs:** single-quoted heredoc (`<<'EOF'`)
  preserves `\$` literally. Don't escape dollar signs inside it.

## Quick-start cheatsheet for the next session

If you're picking this up cold:

1. Read `dashboard-prd.md` for the spec.
2. Read `dashboard-progress.md` for what's done / what's next.
3. Skim this file for ephemeral session-level context.
4. Verify the live instance still works:
   `curl -s http://localhost:5007/dashboards -o /dev/null -w "%{http_code}\n"`
   should return 302 (redirect to login) without a session;
   with the session-login dance, /dashboards returns 200.
5. **Phase 5 refresh half closed (6/7 lines). Drill-down half open
   (4 lines).** Pick from the Open thread above. Recommended: Option A
   (continue Phase 5 with drill-down) or Option C (pivot to Phase 4
   template gallery).
6. Commit one task at a time, signed, with `chgrp www-data` on
   new files. Don't `git add -A`. Don't escape `$` inside single-
   quoted heredocs. Themed wrapper parity check on every chrome edit.
