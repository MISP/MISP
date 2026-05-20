# Dashboard v2 — Session handoff (2026-05-20, morning session #1)

Fourth session of the dashboard rewrite. Authoritative state lives in:

- `dashboard-prd.md` — spec.
- `dashboard-progress.md` — task state. Phase 2 closed (one open
  line — Edit Widget browser verification); Phase 3 advanced from
  5/12 → **7/12** canonical types (`threat_level_filter` +
  `analysis_filter`). Discovered work — "missing renderer
  templates" — shrunk from 5 → 4 (Index landed).
- `dashboard-design-decisions.md` — DD-01..DD-08 unchanged.

This file is the bridge: ephemeral session-level context that
doesn't fit the durable docs. Replace it as work progresses.

## TL;DR

**12 signed commits this session.** One renderer template, two
canonical types, and one user-reported visual bug fix. The two
canonicals landed in 5+5 commits because the third-copy trigger
fired and forced three long-flagged extractions; the second
canonical landed as a ~40-line shell over the new infrastructure.

**Phase 1 carryover.** `Index.ctp` renderer template — closes
the "missing renderer templates" gap from 5/9 → 4/9. Three
widgets that declared `$render = 'Index'` (EventStreamWidget,
NewUsersWidget, NewOrgsWidget) were 500'ing pre-this-session;
they all render cleanly now. Token-driven semantic table; covers
the five `element` types the in-tree consumers use (`links` /
`org` / `tags` / `array_lookup_field` / scalar default). XSS-safe
(verified against a real-world org-name payload). The decision
to build a fresh v2-native renderer rather than restore the v1
genericElements/IndexTable delegation was deliberate — v1
pulls in BS-classed markup + a script tail that collides across
multiple widgets on one page.

**Phase 3 — 6th canonical: `threat_level_filter`.** Three-commit
shape (adapter + tests, JS picker + registries + CSS, consumer)
matching the distribution_filter precedent. Crucial discovery
during smoke: `Event::fetchEvent` does NOT natively accept
`threat_level_id` as a filter option (the
`set_filter_threat_level_id` helper at Event.php:3868 is a
restSearch-dispatcher helper, not a fetchEvent option). The
prior commit's docblock got that wrong and was corrected in the
consumer commit. EventStreamWidget applies the filter as a PHP
post-filter against the ACL-filtered fetchEvent result set —
ACL-safe by construction, same pattern TrendingTagsWidget uses
for distribution_filter. Pre-fetch overshoot heuristic
(`max(200, declaredLimit * 10)`) preserves "filter-then-limit"
semantics by fetching a larger pool, then array_slicing back to
the declared limit after the post-filter.

**Phase 3 — 7th canonical: `analysis_filter`** — and the
extraction trio. The third copy of the int-enum-array picker
pattern (distribution + threat_level + analysis) forced three
long-flagged refactors:

- **PHP:** `_normaliseIntArray` shared private helper.
  `translateDistributionFilter` + `translateThreatLevelFilter`
  now delegate to it; `translateAnalysisFilter` is a one-line
  forwarder. The 20 prior PHPUnit cases passed against the
  refactored bodies BEFORE any analysis_filter code landed —
  confirms the extraction is a pure refactor. 10 new
  analysis-specific tests; 90/90 total.
- **JS:** `enum_picker.mjs` factory exports `makeEnumPicker({key,
  label, levels, valueAttr, rootClass, togglesClass, toggleClass,
  helpText})` returning the standard `{KEY, LABEL, LEVELS,
  equal, displayLabel, buildField, readValue}` surface.
  distribution_filter.mjs + threat_level_filter.mjs are now
  ~40-line shells; analysis_filter.mjs dropped in as ~40 more.
- **CSS:** `.misp-enum-toggles` / `.misp-enum-toggle` shared
  base; the two per-canonical class namespaces (which had
  byte-identical rule bodies) collapsed.

After the extractions, adding a 4th int-enum canonical would be
**one adapter delegate (`return self::_normaliseIntArray($value)`)
+ one ~40-line picker module shell + two registry entries**.
Infrastructure compounds.

**EventStreamWidget is now the most-populated canonical-type
consumer** — declares BOTH `threat_level_filter` AND
`analysis_filter`. The toolbar will surface two chips ("Threat
level" + "Analysis") on any board with EventStreamWidget present.

**User-reported bug fix: Overmind themed CSS never loaded.** Both
reported issues — invisible resize handle + content overflow
escaping the widget border — traced to the same root cause:
`Themed/Overmind/Layouts/dashboard.ctp` never loaded
`app/View/Themed/Overmind/webroot/css/dashboard/overmind.css`.
That file defines `.card.misp-widget--overmind { overflow:
hidden }` (clips overflow), `.misp-widget--overmind__body
{ overflow: auto }` (body scrolls), and
`.misp-widget--overmind__resize { position: absolute ... }` (the
handle). Without the file loaded, every `__resize` span
collapsed to a 0×0 inline element and content escaped the card
border. Fixed first via a manual `<link>` (commit `ceedfffb4`)
with a misleading docblock claiming Cake's `assetUrl` doesn't
resolve theme dot-notation — then refined (commit `fe0c4bbbe`)
to the idiomatic Cake 2.x pattern: a plain css-array entry
`'dashboard/overmind'`. `Helper::webroot()` IS theme-aware (it
falls back to `App::themePath($theme)/webroot/<path>` and emits
`/theme/<Theme>/<path>` URLs). The dot-notation
`'Overmind.dashboard/overmind'` doesn't work because
`pluginSplit` interprets the prefix as a plugin namespace, not a
theme namespace, and emits `/css/overmind/dashboard/overmind.css`
(which 404s). The wrapper.ctp docblock now warns future
contributors away from the dot-prefix trap.

**User-direction carried forward unchanged:** *"modern and
pleasant"*, *"don't worry too much about compatibility"*, *"ACL
must match the surface it shadows"*, *"three similar lines is
better than premature abstraction; the third copy forces the
refactor"*.

**Next session — pick from** (see Open thread):

1. Phase 3 next canonical type (pick from `sharing_group_filter`
   / `galaxy_cluster_filter` — both more complex than the
   int-enum trio that just landed).
2. Build the next missing renderer template (Button is smallest;
   OrgsPictures has the most consumers — three OrgsContributor
   widgets need it).
3. Pair an existing canonical with a 2nd consumer to demonstrate
   F5.6.4 inheritance with multi-declarer setups.
4. Browser-verify Edit Widget against the preview-pane render
   path (closes the last open Phase 2 line — ~15 min).
5. Phase 4 — Template gallery polish (greenfield multi-session).

## Where we are

```
Phase 0.4 — Sign-off                                              [x]

Phase 1 — Frame (in-place replacement)                            [x]

Phase 2 — Authoring UX                                            [/] ~26/26
  All ticked except:
  [ ] Edit Widget flow (existing per-widget ⚙ path covers most;
      task line stays open until verified against the new
      preview-pane render path interactively)

Phase 3 — Canonical-type toolbar                                  [/] 7/12 types
  [x] CanonicalTypeAdapter helper + 90 PHPUnit tests (was 70)
  [x] Wire CanonicalTypeAdapter into renderWidget
  [/] Canonical types: 7/12
        [x] time_window
        [x] date_range
        [x] tag_filter
        [x] org_meta_filter
        [x] distribution_filter
        [x] threat_level_filter             — NEW
        [x] analysis_filter                 — NEW
        [ ] org_filter (no consumers today — needs pairing)
        [ ] sharing_group_filter (no consumers — needs pairing)
        [ ] galaxy_cluster_filter (no consumers — needs pairing)
        [ ] attribute_type_filter (widget-only)
        [ ] event_id_filter (widget-only)
  [x] Toolbar control logic (schema-driven declarer scan)
  [x] Toolbar bulk-edit write path (readValue dispatch)
  [/] Toolbar UI: time_window + tag_filter + org_meta_filter +
      distribution_filter + threat_level_filter +
      analysis_filter shipped
  [ ] Per-canonical-type validators
  [ ] New-widget toolbar inheritance + Clear action
      — F5.6.4 inheritance landed in placement orchestrator;
        Clear action remains
  [ ] Canonical-only $schema sweep across remaining ~9 widgets
  [ ] Cache-key sanity check
```

**Discovered work — missing renderer templates: 4 of 9 remain.**
`Index` landed this session. Still missing: `OrgsPictures`
(three OrgsContributor* widgets), `Button` (ButtonWidget — link
shortcut primitive), `Attack` (AttackWidget — MITRE ATT&CK
matrix), `Achievements` (AchievementsWidget — badge + counter).
Each is a ~1-commit job following the BarChart/SimpleList
pattern.

Working tree clean for v2 work after this session's 12 commits.
Only the usual unrelated noise (submodule drift, scratch files
in repo root, untracked side-projects).

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id: 1 (`admin@admin.test`), password `Password12345`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- **Admin user is on Overmind theme** (`UserSetting:ui_theme =
  "Overmind"`). With this session's commit `fe0c4bbbe` landed,
  the Overmind dashboard CSS overrides now actually apply.
- DB creds: `mysql -u misp -pPassword1234 misp`

**Saved-layout state at session end:** admin still has the
4-widget layout from the prior session — unchanged (this session
didn't touch admin's saved dashboard, only adapter / renderer
infrastructure):

- `w_1` MispStatusWidget at (0,0) 4×4
- `w_2` TrendingTagsWidget at (4,0) 5×4
  — config: `time_window=90d, threshold=10, over_time=false,
    tag_filter={include:[],exclude:[]}`
- `w_3` OrganisationMapWidget at (9,0) 3×4
- `w_4` OrgContributionToplistWidget at (0,4) 12×4
  — config: `time_window=P30D, threshold=15`

To exercise the new canonicals end-to-end via the UI, add an
EventStreamWidget instance via the Add Widget gallery. Its
`$schema` declares both `threat_level_filter` and
`analysis_filter`, so the toolbar will surface two new chips and
the configure form's typed-fields tier will show two
toggle-button rows.

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

Session-login dance + wrapper-render smoke recipes unchanged
from prior session — see [[reference-misp-login-dance]] and the
prior handoff's "Wrapper render smoke" block.

Smoke commands for the new canonicals (admin user, session login
already established at /tmp/cj.txt):
```bash
# threat_level_filter (High only)
curl -s -b /tmp/cj.txt -X POST -H "X-Requested-With: XMLHttpRequest" \
  --data-urlencode 'widget=EventStreamWidget' \
  --data-urlencode 'config={"limit":5,"fields":["id","threat_level"],"threat_level":[1]}' \
  http://localhost:5007/dashboards/renderWidget/w_test

# analysis_filter (Initial only)
curl -s -b /tmp/cj.txt -X POST -H "X-Requested-With: XMLHttpRequest" \
  --data-urlencode 'widget=EventStreamWidget' \
  --data-urlencode 'config={"limit":5,"fields":["id","analysis"],"analysis":[0]}' \
  http://localhost:5007/dashboards/renderWidget/w_test

# Index renderer (NewUsersWidget) — exercises description + 5 columns
curl -s -b /tmp/cj.txt -X POST -H "X-Requested-With: XMLHttpRequest" \
  --data-urlencode 'widget=NewUsersWidget' \
  --data-urlencode 'config={"limit":3}' \
  http://localhost:5007/dashboards/renderWidget/w_test
```

## What this session committed (in order)

```
934d4146b  new: Phase 1 carryover — Index widget renderer template
                Closes the Discovered-work "missing renderer templates"
                item for Index (was 5/9 unrendered kinds; now 4/9).
                EventStreamWidget + NewUsersWidget + NewOrgsWidget
                all declared $render = 'Index' and 500'd before this
                commit. New app/View/Elements/dashboard/Widgets/Index.ctp
                interprets the established $fields contract (name,
                data_path dot-notation, optional element ∈ {links,
                org, tags, array_lookup_field}, plus url/
                url_params_data_paths/arrayData/scope hints) and emits
                a token-driven <table class="misp-index-table">.
                Element coverage: links (id columns, rawurlencoded
                URL suffix + SimpleList-style safe-URL check); org
                (name as link to /organisations/view/<id|uuid>; no
                logo — v2 compact text idiom); tags (static colored
                pill row with sanitised colours + Rec.601 luminance
                contrast); array_lookup_field; default scalar. Pattern
                follows SimpleList.ctp / BarChart.ctp — pure PHP, no
                Cake helpers besides Hash::get + h() + __() +
                Configure::read, inline _isSafeDashboardUrl. Companion
                CSS rules appended to dashboard.default.css under
                "Index renderer" (sticky <thead>, compact cell
                padding, .misp-index-link mirrors .misp-list-link
                hover behaviour, .misp-index-tag pill). Did NOT reuse
                v1's genericElements/IndexTable infrastructure —
                pulls in BS-classed markup + a script tag tail that
                would collide across multiple Index widgets on one
                page. XSS-safe (verified against `<img src=x
                onerror=alert(1)>` payload in an org name → escaped
                to text). Three Index consumers render cleanly;
                Discovered-work entry in progress.md updated with
                Index ticked and the 4 remaining kinds listed.

555c41c63  new: Phase 3 — threat_level_filter canonical adapter + tests
                6th canonical type. Wire shape is an int array (subset
                of {1..4}: 1=High, 2=Medium, 3=Low, 4=Undefined).
                translateThreatLevelFilter body byte-identical to
                translateDistributionFilter at this commit; the docblock
                explicitly flags it as a future-extract trigger when
                analysis_filter (third copy) lands. 10 PHPUnit tests
                mirror the distribution_filter block: array passthrough,
                empty, null, scalar wrap, numeric-string wrap, mixed
                coerce + drop, out-of-range preserved, non-array →
                null, idempotence, type-routed translate, coexists with
                other canonicals. 80/80 pass (70 prior + 10 new).
                Important: the adapter docblock at this commit claimed
                fetchEvent accepts threat_level_id directly via
                Event.php:3868 — that was WRONG (corrected in 783894190
                below; line 3868 is set_filter_threat_level_id which
                lives in the restSearch dispatcher, not fetchEvent).

bcde33697  new: Phase 3 — threat_level_filter JS picker + registries
                + CSS
                Toggle-button row over 4 levels (High/Medium/Low/
                Undefined) with per-level tooltips. aria-pressed is
                the source of truth; readValue scans
                [data-threat-level][aria-pressed="true"]. Order-
                insensitive equal() for toolbar mixed-state. CSS lived
                under .misp-threat-level-toggles/-toggle at this
                commit — distinct namespace from .misp-distribution-
                toggle, with a "fold into shared base when third
                copy lands" docblock note. CANONICAL_BUILDERS
                (configure) + CANONICAL_REGISTRY (toolbar) entries.

783894190  new: Phase 3 — threat_level_filter consumer:
                EventStreamWidget post-filter
                Third commit for the canonical. $params['threat_level']
                legacy help + $schema['threat_level'] => {type:
                'threat_level_filter', help: ...}. Handler applies the
                filter as a PHP post-filter on the ACL-filtered
                fetchEvent result set — fetchEvent does NOT accept
                threat_level_id natively (only as a SELECT column;
                the set_filter_* helper lives in restSearch). Pre-fetch
                overshoot heuristic: max(200, declaredLimit*10) when
                threat_level set, then array_slice to declaredLimit
                post-filter — otherwise the result count would shrink
                unpredictably depending on which threat levels happen
                to be most recent. Adapter docblock fix (the prior
                commit's claim that fetchEvent accepts threat_level_id
                was wrong — corrected here). Smoke: 5 configs verified
                (baseline, [1], [2,3], [99] out-of-range, scalar legacy).

2331dd370  chg: Phase 3 — tracker tick for threat_level_filter
                Should have been bundled into the consumer commit per
                the distribution_filter precedent; landed as a follow-
                up because amends are off the table. Single-line
                progress.md tick — closes the Phase 3 task line for
                threat_level_filter.

2250ce6b8  chg: Phase 3 — analysis_filter adapter; extract shared
                _normaliseIntArray
                Third copy of the int-enum-array pattern lands as
                the trigger for the long-flagged PHP extraction.
                _normaliseIntArray as a private static; translateDist-
                ributionFilter + translateThreatLevelFilter delegate to
                it; translateAnalysisFilter is a one-line forwarder.
                The 20 prior PHPUnit cases passed against the
                refactored bodies BEFORE the new code landed —
                confirms the extraction is a pure refactor. New
                'analysis_filter' case in translate() switch. 10 new
                tests; 90/90 total. The per-type translator docblocks
                now focus on enum-specific semantics + downstream
                consumption path (native fetchEvent for distribution
                vs. PHP post-filter for threat_level / analysis).

4d4dab2d6  chg: Phase 3 — extract shared enum_picker.mjs factory
                JS-side companion. New canonical/enum_picker.mjs
                exports makeEnumPicker({key, label, levels, valueAttr,
                rootClass, togglesClass, toggleClass, helpText})
                returning the standard {KEY, LABEL, LEVELS, equal,
                displayLabel, buildField, readValue} surface.
                distribution_filter.mjs + threat_level_filter.mjs
                migrate to ~40-line shells (down from ~180-200 each).
                Net JS lines: was ~400 duplicated; now ~290 total
                (206 factory + ~40 per shell). Configure + toolbar
                registries unchanged — same KEY/buildField/readValue
                exports on the same paths.

9dd06ab81  chg: Phase 3 — consolidate enum picker CSS into
                .misp-enum-toggle base
                Final extraction in the trio. .misp-distribution-
                toggles/-toggle + .misp-threat-level-toggles/-toggle
                (byte-identical bodies) fold into a single
                .misp-enum-toggles / .misp-enum-toggle block. Both
                existing modules switch their factory params to use
                the shared classes. rootClass deliberately stays
                per-canonical (.misp-distribution-filter /
                .misp-threat-level-filter) — leaves a hook for
                variant-specific styling.

71ae3e1a3  new: Phase 3 — analysis_filter JS picker + registries
                First picker to benefit from the factory + shared
                CSS. ~40-line shell over makeEnumPicker. Levels:
                {0=Initial, 1=Ongoing, 2=Complete}. CSS zero —
                shared base applies via the factory's class params.
                CANONICAL_BUILDERS + CANONICAL_REGISTRY entries.

bf1f243d9  new: Phase 3 — analysis_filter consumer: EventStreamWidget
                + tracker tick
                EventStreamWidget now declares BOTH threat_level_filter
                AND analysis_filter — the most populated canonical-type
                schema in the v2 catalogue. Handler factored the
                post-filter coercion into a $coerceLevels closure
                (replaces a prior `array_filter(... > 0)` pattern
                which would have wrongly dropped 0=Initial). Pre-fetch
                overshoot fires when EITHER filter is set; each
                filter runs independently in sequence; single
                array_slice truncates after both. Smoke: 5 configs
                verified incl. combined threat_level=[1] AND
                analysis=[0] (returns empty — DB-verified that the
                top-200 has zero events matching both; behaviour
                correct, not a bug). Progress tracker ticked.

ceedfffb4  fix: Overmind dashboard CSS overrides never loaded
                User-reported regressions on the Overmind theme: (1)
                resize handle invisible in edit mode; (2) widget
                content overflowed the card border instead of clipping
                / scrolling. Both bugs traced to one root cause:
                `Themed/Overmind/Layouts/dashboard.ctp` never loaded
                `app/View/Themed/Overmind/webroot/css/dashboard/
                overmind.css`. That file defines `.card.misp-widget--
                overmind { overflow: hidden }` (clips content),
                `.misp-widget--overmind__body { overflow: auto }`
                (body scrolls), `.misp-widget--overmind__resize
                { position: absolute; right:0; bottom:0; ...
                gradient ... }` (resize handle). Without the
                stylesheet, every `__resize` span collapsed to a 0×0
                inline element. Fix at this commit: emit a manual
                <link> after the assetLoader. Docblock claimed
                "this fork's HtmlHelper::assetUrl doesn't resolve
                Cake's theme dot-notation" — TRUE but irrelevant;
                see follow-up fe0c4bbbe.

fe0c4bbbe  chg: Overmind themed CSS via plain css-array entry, not
                manual <link>
                Follow-up to ceedfffb4. The prior fix worked but used
                the wrong idiom. Cake's `Helper::webroot()` IS
                theme-aware: when `$this->theme === 'Overmind'`, it
                falls back to `App::themePath($theme)/webroot/<path>`
                and emits `/theme/Overmind/<path>` URLs. So the
                correct fix is just to add a plain css-array entry
                `'dashboard/overmind'` — no dot-prefix needed. The
                dot-notation `'Overmind.dashboard/overmind'` doesn't
                work because `pluginSplit` treats the prefix as a
                PLUGIN namespace, not a theme namespace, and emits
                `/css/overmind/dashboard/overmind.css` (404). Manual
                <link> replaced with `['dashboard/overmind', ['preload'
                => true]]` in the natural position. wrapper.ctp
                docblock corrected with explicit "no dot-prefix"
                warning so future contributors don't trip the same
                wire. assetLoader.ctp itself is custom MISP code but
                it delegates theme-awareness to Cake's
                Helper::webroot(), so no MISP-side change was needed.
```

12 commits this session, all signed (`%G?` = `U`). Net stats:
- 4 new files (Index.ctp, enum_picker.mjs, threat_level_filter.mjs,
  analysis_filter.mjs)
- PHPUnit count: 70 → 90 (+20)
- JS lines net: distribution_filter + threat_level_filter went
  from ~400 lines duplicated → ~290 lines via factory; analysis_filter
  added ~40 more for a third picker. Total ~330 lines for three
  pickers vs ~600 had they all been written in the parallel-
  duplication style.
- CSS lines net: enum toggle styling went from ~60 duplicated lines
  → ~30 lines under one rule block.

## Lessons from this session

1. **Three copies forces extraction — and the third copy lands
   together with the extraction, not as a separate refactor pass.**
   distribution_filter shipped as a parallel-duplicate of
   nothing (it was first); threat_level_filter shipped as a
   parallel-duplicate of distribution_filter (two copies — the
   adapter docblocks explicitly flagged "extract on third copy").
   analysis_filter was the third copy. Rather than (a) ship a
   third parallel duplicate or (b) refactor first then add the
   third in a separate session, the cleanest shape was to **fold
   the extraction into the addition**: one commit per layer
   (PHP / JS / CSS) that both extracts the shared infrastructure
   AND moves the third copy onto it. Verification discipline:
   each refactor commit re-ran the existing test suite against
   the new shared code BEFORE adding the third copy's tests, so
   the "pure refactor, no behaviour change" claim is observable
   in the commit chain.

2. **Cake 2.x theme dot-notation is for PLUGINS, not THEMES.**
   `'Overmind.dashboard/overmind'` in a css-array entry runs
   through `pluginSplit` and produces a plugin-asset path
   (`/css/overmind/dashboard/overmind.css`), which 404s. Theme
   support in Cake 2.x is handled exclusively at
   `Helper::webroot()`'s theme fallback (`App::themePath($theme)
   . 'webroot/' . $file`), which IS exercised when you pass a
   plain path (no prefix) and `$this->theme` is set on the
   helper. **HelperCollection propagates `$theme` from the View
   automatically** (HelperCollection.php:138). So loading a
   themed asset is just `['dashboard/overmind']` — no special
   syntax. Documented in two places (the wrapper.ctp docblock +
   the layout's inline comment) so future contributors don't
   trip the same wire.

3. **Initial bug-fix docblocks aren't gospel — when you write a
   "this doesn't work because X" claim, prove X actively, not
   passively.** Commit `ceedfffb4` shipped with the claim that
   "this fork's HtmlHelper::assetUrl doesn't resolve Cake's
   theme dot-notation" — true (dot-notation goes through
   pluginSplit which doesn't know about themes), but the
   conclusion ("so we emit the <link> manually") was the wrong
   takeaway. The right takeaway is "use the plain path; webroot()
   handles themes". The user's question — "Isn't the asset
   loader custom code? Or is it part of cakePHP?" — was the
   forcing function that prompted the re-investigation.
   **Trust-but-verify a stated negative claim**: if you find
   that an idiom doesn't work and conclude the framework
   doesn't support what you want, check whether you reached for
   the right idiom.

4. **`fetchEvent` is not `restSearch`.** They take different
   options. distribution_filter happens to be a top-level
   fetchEvent option (line 125 in the fetchEvent body —
   `Event.distribution` IN coercion); threat_level_id and
   analysis are NOT. The `set_filter_*` helpers at Event.php:3868
   and similar are restSearch-dispatcher entries, not fetchEvent
   inputs. The adapter docblock for threat_level_filter initially
   claimed the wrong thing (fixed in the consumer commit); same
   trap caught analysis_filter early. When wiring a canonical-
   typed slot for a widget that uses `fetchEvent`, scan the
   fetchEvent BODY for the option's literal use, not the broader
   Event model for hits on the field name.

5. **The "infrastructure compounds" property is observable
   commit-by-commit, not just claimed in handoffs.** The
   analysis_filter trio of extraction commits each shrunk the
   per-canonical addition: PHP went from ~30 lines to 1 line,
   JS went from ~180 lines to ~40, CSS went from ~30 lines to
   0. A 4th int-enum canonical now costs:
   - One adapter delegate line (`return self::_normaliseIntArray($value);`).
   - One ~40-line picker shell + two registry entries.
   - The CSS already exists.
   - Plus a consumer-widget declaration (~10 lines) if/when one
     surfaces. (Without a consumer, the work is dead per
     Lesson #4 of the prior session.)

6. **Index renderer: v1 IndexTable infrastructure is heavyweight
   for v2's needs.** The deleted v1 Index.ctp delegated to
   `genericElements/IndexTable/index_table` which brings
   pagination + BS markup + a script tag tail that REDECLARES
   `var passedArgsArray` / `var url` on every render. With
   multiple Index widgets on one page, the script tail would
   collide. The fresh v2 Index.ctp covers all the in-tree
   `element` types (links/org/tags/array_lookup_field) in ~150
   lines, clip-safe, token-driven, no Cake helpers besides
   Hash::get/h/__/Configure::read. Pattern matches BarChart.ctp /
   SimpleList.ctp idiom.

7. **Pre-fetch overshoot is the standard cure for PHP-post-filter
   `LIMIT` shrinkage.** When the filter applies AFTER the SQL
   LIMIT clause, the user's declared limit becomes a "raw fetch"
   number that the post-filter narrows below. The fix:
   `max(200, declaredLimit * 10)` at fetch time, then
   `array_slice($data, 0, $declaredLimit)` after the post-filter.
   For uniform-distribution DBs this gives ≥80% of the declared
   limit even in the worst single-level case; users wanting
   guaranteed N matches can raise the widget's limit config.
   Both threat_level_filter and analysis_filter use this
   pattern in EventStreamWidget; a single bump applies when
   either filter is set (no double-bump).

8. **One root cause can produce two visible bugs.** The Overmind
   user-report had two symptoms (invisible resize handle +
   content overflow) that initially looked like two distinct
   CSS issues. Both traced to the same root: one CSS file not
   loading. **Fix the loader, both symptoms resolve.** Worth
   pausing on "two distinct symptoms" reports to ask whether
   they share infrastructure before debugging each separately.

The prior session's gotchas still apply:

9. **`git mv` does NOT auto-stage subsequent content edits.**
10. **Themed/<Name>/Layouts/<layout>.ctp must exist for every
    new layout.**
11. **GPG pinentry timeout** — same lesson #8 from the prior
    session. No incidents this session but worth keeping in
    mind for late nights.

## Discovered work parked for later

Newly parked this session: nothing — the Overmind CSS load bug
caught here is now closed.

Previously parked items still active:

- **Missing renderer templates (4 of 9 remain):** OrgsPictures
  (three OrgsContributor* widgets need it), Button (ButtonWidget),
  Attack (AttackWidget — MITRE ATT&CK matrix; non-trivial),
  Achievements (AchievementsWidget — badge + counter; small).
  Index landed this session. Highest user value among remaining:
  OrgsPictures (unlocks 3 widgets); Button (smallest, easiest);
  Attack is the most user-facing if MITRE matrices are a known
  user need.

- **MISP 2.4 cross-instance DB write risk:** v2.4 connected to
  the same DB can clobber `user_settings.dashboard` rows. Carries.

- **time_window toolbar dropdown-menu UX alternative.** Carries.
- **Grid drop-on-occupied cascade (Phase 5).** Carries.
- **tlp:clear (#ffffff) renders invisible bars (cosmetic).**
  Carries.
- **OrgEventsWidget months>13 malformed dates.** Carries.
- **TrendingAttributesWidget PHP 8.x Attribute model crash.**
  Carries — MISP core touch.
- **EventEvolutionLineWidget ignores end_date.** Carries.
- **Live preview race window** (carries — AbortController fix).
- **Drop dormant `dashboard.midnight.css` loader.** Carries.
- **`save_template.ctp:4` action-name mismatch** (Phase 4 —
  carries).

## Open thread / next obvious work

In rough priority order:

**Option A: Phase 3 — next canonical type.**

Per Lesson #4 of session #2, every remaining type needs a
consumer audit first. Best candidates:

- **`sharing_group_filter`** — would consume on any
  sharing-group-aware widget. Needs careful design because
  sharing groups are user-specific (filter dropdown can't be a
  static enum). Likely needs a server-side autocomplete or a
  picker that fetches the user's sharing groups from a new
  endpoint. ~5 commits including the endpoint.
- **`galaxy_cluster_filter`** — most complex of the remaining
  canonicals. Galaxy clusters are dynamic; needs a typeahead/
  picker. Could be a single canonical that takes significant
  effort, or a phased approach starting with a simpler
  "galaxy-type" enum.

Both are heavier than the int-enum trio. Not the natural
"keep momentum going" choice.

**Option B: Build another missing renderer template.**

`Button.ctp` is smallest — ButtonWidget is a link-shortcut
primitive (single button → drilldown URL). One commit.
`OrgsPictures.ctp` has the most consumers (three OrgsContributor*
widgets) but needs an org-logo grid renderer + the OrgImg helper
or an equivalent — medium effort, one commit.

**Option C: Pair an existing canonical with a 2nd consumer for
multi-declarer F5.6.4 demonstration.**

The toolbar's "mixed state" detection + F5.6.4 inheritance shine
brightest with ≥2 declarers of the same canonical. Today, every
new canonical has exactly one consumer (EventStreamWidget for
threat_level + analysis; TrendingTagsWidget for distribution).
Candidates for a 2nd consumer:

- **OrgEventsWidget** could declare threat_level_filter +
  analysis_filter (it's another `Event`-backed widget; the
  post-filter pattern transfers directly). Quick — ~2 commits
  total (one per filter).
- **TrendingTagsWidget** already has distribution_filter; adding
  threat_level_filter to it would make the existing dashboard
  layout (admin's saved state has TrendingTags + Org widgets)
  surface a second toolbar chip without needing to add new
  widgets.

**Option D: Browser-verify Edit Widget against the new preview-
pane render path.**

Closes the last open Phase 2 line. No code work; tick depends on
a browser interaction. ~15 minutes. The user is now ON Overmind
with working CSS (this session's bug fix), so the visual
verification is reliable.

**Option E: Phase 4 — Template gallery polish.**

Pure greenfield. Reuses the gallery infrastructure (card grid,
search filter, side panel) from Phase 2. Larger scope —
multi-session.

**Option F: Other parked work** — time_window dropdown UX,
renderer luminance check (tlp:clear bars render invisible),
midnight.css drop, TrendingAttributesWidget PHP 8 crash.

**Recommendation:** **B (Button renderer) then C (a 2nd consumer
for threat_level or analysis)**. Button is a quick visible win
that unlocks another widget; the 2nd-consumer pairing makes the
F5.6.4 inheritance + mixed-state UX observable. Alternative
recommendation: **D first** (15-min closeout of the Phase 2 line)
then onto B/C.

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  the commit body references the task. **For canonical-type
  additions: three-commit shape per type — adapter + tests, JS
  picker + registries, consumer widget — same as
  distribution_filter, threat_level_filter, analysis_filter
  this session.**
- **For the next "third copy" trigger of any pattern**: extract
  + add together (PHP / JS / CSS each in their own commit),
  rather than refactor-first-then-add. This session was the
  forcing-function precedent.
- **Always `git status --short` + explicit `git add` before
  commit**. Watch for stray empty files from grep / find with
  quote-mangling — clean them out before staging.
- New files land with `iglocska:iglocska` ownership; `chgrp
  www-data` before committing to match repo convention.
- The wrapper-element + Themed-override pattern is the playbook
  for any future override surface. The Overmind CSS-load bug
  this session is a reminder that themed CSS overrides need
  to be loaded explicitly — Cake's theme-aware `Helper::webroot()`
  resolves the URL but doesn't auto-include the asset.
- **Themed CSS in Cake 2.x:** use plain paths (no dot-prefix).
  `Helper::webroot()` does the theme resolution when
  `$this->theme` is set on the helper (HelperCollection
  propagates it from the View). The dot-prefix is for plugins,
  not themes.
- User wants rigorous pushback, not yes-machine output — surface
  trade-offs, name alternatives, recommend a path, then go with
  the user's call. **The user's question about whether the
  assetLoader is custom code was this session's example of the
  rigorous-pushback discipline working from the user side, not
  Claude's; pay attention when the user questions a stated
  premise.**
- User alternates hitm / afk sessions; tracker docs are the
  ground truth between sessions. Tick one task at a time; the
  Done note carries the deciding context.
- Surface context status when past 75% at task boundaries so the
  user can choose to restart. This session wrapped at ~36% with
  the user explicitly asking for the handoff at the natural
  pause after the Overmind bug fix.
- Hard-refresh after CSS/JS edits — the `?v=185` cache-buster
  from `AppController::__queryVersion` doesn't bump per-file.
- **The schema-driven model is the canonical answer** for any
  "how does the toolbar / configure form know which widgets to
  act on" question.
- **A tracker tick requires the user-visible surface to exist
  AND be reachable from the default UI, not just the JS / handler-
  level wiring behind it.** (Carries.)
- **`mysql -u misp -pPassword1234 misp` for one-shot SQL.**
- **Render-kind glyph requirement (carries):** any new value
  for `public $render` on a widget class, or any new template
  under `app/View/Elements/dashboard/Widgets/`, must ship with
  a matching glyph in `render-thumbs.mjs` in the same commit.
- **DB restore from audit_logs (carries):** documented procedure
  for clobbered `user_settings.dashboard` rows lives in the
  prior session's handoff.

## Quick-start cheatsheet for the next session

If you're picking this up cold:

1. Read `dashboard-prd.md` for the spec.
2. Read `dashboard-progress.md` for what's done / what's next.
3. Skim this file for ephemeral session-level context.
4. Verify the live instance still works:
   `curl -s http://localhost:5007/dashboards -o /dev/null -w "%{http_code}\n"`
   should return 302 (redirect to login) without a session;
   with the session-login dance above, /dashboards returns 200.
5. Pick from the Open thread above. Recommended: B (next
   renderer template) or D (15-min Edit Widget browser-verify).
6. Commit one task at a time, signed, with `chgrp www-data` on
   new files. Don't `git add -A`.
