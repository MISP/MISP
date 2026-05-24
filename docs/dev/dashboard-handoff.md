# Dashboard v2 — Session handoff (2026-05-25 — Phase 5.5 data-parity session)

Eleventh session of the dashboard rewrite. Authoritative state lives in:

- `dashboard-prd.md` — spec.
- `dashboard-progress.md` — task state. **Phase 5 fully closed
  (11/11). Phase 5.5 data-parity group now fully closed (5/5).**
  Remaining merge-gate work: Phase 5.5 widget parity (37 rows) +
  surface parity (10 rows) + pre-merge cleanup (7 rows), then
  Phase 6 merge.
- `dashboard-design-decisions.md` — DD-01..DD-08 unchanged.

This file is the bridge: ephemeral session-level context that doesn't
fit the durable docs. Replace it as work progresses.

## TL;DR

**5 signed commits this session**, all `%G?` = `U`. Picked up the
prior handoff's recommended Option A (Phase 5.5) and, per the user's
session-scope choice, took the **data-parity group** (5 rows) first —
it front-loads the riskiest "no-migration" assumption. All 5 rows
closed in tracker order. **Zero code changes** — every row is a
verification-only tracker close (the read/import/export/fix-up
machinery all shipped in Phase 1). One latent robustness gap surfaced
and parked (mixed-id mint collision).

1. **Data-parity row 1 — legacy `UserSetting:dashboard` bare-array
   loads into v2** (`3746ae3b2`). Wrote a synthetic v1-shape blob
   (`position{x,y,width,height}`, no `instance_id`, + a stale-`w`
   edge case) into admin's row; REST + HTML read-back confirmed the
   on-read fix-ups (`width/height → w/h`, no-overwrite branch,
   position-deterministic `instance_id` mint, `x/y` preserved).

2. **Data-parity row 2 — legacy `dashboards.value` templates load
   into v2** (`37f15a035`). Verified against **real legacy data** —
   all 6 live `dashboards` rows already store the v1 shape.
   `listTemplates` decoded every row (24 `TemplatePreview` SVGs);
   `resetFromTemplate/<uuid>` adopted template id=4 → read-back
   showed all 6 widgets in v2 shape (`w/h` + `instance_id`).

3. **Data-parity row 3 — v2 blob export/re-import round-trip
   preserves layout** (`77ee6fd52`). The import action's two-branch
   `if` is a deliberate wrapper-peeling chain (Dashboard.value
   JSON-decode → UserSetting.value unwrap → bare array). Both the
   REST path and the default-UI gesture (export modal → import form
   with session + 4 `_Token` fields → 302) preserve the 13-widget
   layout **exactly**.

4. **Data-parity row 4 — legacy v1 blob import + on-read/on-save
   fix-ups** (`137c5428d`). Full 5-step round-trip: import stores
   **verbatim** (DB still legacy) → REST read returns canonical
   (fix-ups are on-read) → first save via `updateSettings` (POSTing
   the *legacy* shape) → DB now **canonical** (`w/h` + `instance_id`,
   no `width/height` remnants), numeric values exact. Proves PRD
   §7.1's lazy-on-read + persist-on-next-save story end-to-end.

5. **Data-parity row 5 — no data loss across the fix-ups**
   (`190ed7eca`). 15-assertion pure-function PHP CLI smoke on
   `LayoutFixup::applyReadFixups()`: determinism (`===`-identical
   across reads, position-based ids), numeric preservation (int
   type-preserved, string-numeric uncast, **zeros not dropped**,
   large exact, x/y intact, legacy keys removed), idempotency,
   no-overwrite, id-preserved-when-present, defensive shapes. All
   pass. Closes the data-parity group.

**Notable design observations taken this session:**

- **`Dashboard::import()` does NOT fix up; it stores verbatim.** The
  fix-ups are strictly on-read (`index`, `resetFromTemplate`,
  `updateSettings` all call `applyReadFixups`). This is the correct
  shape for PRD §7.1's "lazy on-read" contract — a v1 blob imports
  unchanged, renders correctly via the read fix-up, and only the
  next *save* persists the canonical shape. Verified empirically in
  row 4 (DB-raw inspection at each step).

- **The import wrapper-peel chain handles the export format
  natively.** The export modal renders the full `UserSetting` row
  with `value` already decoded to an array (model `afterFind`). The
  import action's two `if`s peel `Dashboard.value` → object →
  `UserSetting.value` → bare array. So the naive copy-paste
  round-trip works without manual extraction — confirmed in row 3.

- **REST is the right tool for data-parity inspection.** `GET
  /dashboards` with the API key returns the post-fix-up widget array
  as JSON (no HTML parsing); REST POST with the API key bypasses
  CSRF for `import`/`resetFromTemplate`/`updateSettings`. HTML +
  session + `_Token` was reserved for the "reachable from default
  UI" gate (row 1 render smoke, row 3 import-form gesture).

**Parked this session (see Discovered work):**

- **`LayoutFixup` mixed-id mint collision.** The position-indexed
  `instance_id` mint (`w_<k+1>`) doesn't check against explicit ids
  already in the blob, so a *mixed* blob (some id-less, one with
  explicit `instance_id="w_1"`) can produce duplicate ids. **Cannot
  arise from real migration data** (v1 blobs uniformly id-less; v2
  blobs fully id'd) so it is NOT a merge-gate blocker, but it's a
  latent robustness gap — duplicate ids would break per-widget
  addressing in `updateWidgetSettings` + the toolbar bulk-edit. Fix
  shape logged (collision-free mint). Left for sign-off because it
  touches the shipped Phase 1 `LayoutFixup` and is out of the
  data-parity scope that surfaced it.

**User-direction carried forward unchanged:** *"modern and
pleasant"*, *"don't worry too much about compatibility"*, *"ACL
must match the surface it shadows"*, *"three similar lines is
better than premature abstraction"*, *"prefer MISP-jargon naming
(orgc, sharing_group) over PRD-generic terms"*, **"dashboard
chrome icons stay inline SVG, not FA"**, **JSON-encode dashboard-
value payloads before UserSetting::setSetting**, **URL validation
runs server-side; client trusts the payload**, **v2 parity =
information access, not feature-flag fidelity**.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]
Phase 1 — Frame (in-place replacement)                            [x]
Phase 2 — Authoring UX                                            [x] CLOSED
Phase 3 — Canonical-type toolbar                                  [x] CLOSED
Phase 4 — Template gallery polish                                 [x] CLOSED
Phase 5 — Drill-down + refresh scheduler                          [x] CLOSED

Phase 5.5 — Widget Parity Sweep (merge gate)
  Widget parity   (37 rows) — PENDING
  Data parity     ( 5 rows) — [x] CLOSED this session
  Surface parity  (10 rows) — PENDING
  Pre-merge clean ( 7 rows) — PENDING

Phase 6 — Merge to `develop` (post-Phase-5.5)
```

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id: 1 (`admin@admin.test`), password `Password12345`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- **Admin user is on Overmind theme** (`UserSetting:ui_theme =
  "Overmind"`).
- DB creds: `mysql -u misp -pPassword1234 misp`

**Saved-layout state at session end:** admin still has the same 13
widgets (w_1..w_13), `UserSetting:dashboard` value is 2066 bytes —
**byte-exact restored** after every data-parity smoke (a backup was
kept at `/tmp/dash_backup.json` during the session; the DB is back to
baseline). **Templates table:** unchanged (6 rows; all already
legacy-shape — `position{x,y,width,height}`, no `instance_id`). None
of admin's 13 widgets emit `drilldown` keys (drill-down machinery
still dormant on the live board — Phase 5.5 / migration follow-up).

Session-login dance + REST recipes unchanged from prior sessions —
see `reference-misp-login-dance` memory. Session cookie at
`/tmp/cj.txt` was refreshed this session.

### Data-parity smoke recipes (reusable for the next sweeps)

```bash
KEY=dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC
# Back up admin's dashboard before any DB write:
mysql -u misp -pPassword1234 misp -N --raw \
  -e "SELECT value FROM user_settings WHERE user_id=1 AND setting='dashboard';" \
  > /tmp/dash_backup.json
# Inspect post-fix-up layout (no HTML parsing):
curl -s -H "Authorization: $KEY" -H "Accept: application/json" \
  http://localhost:5007/dashboards | python3 -m json.tool
# Restore byte-exact afterwards:
ORIG=$(cat /tmp/dash_backup.json)
mysql -u misp -pPassword1234 misp \
  -e "UPDATE user_settings SET value='$ORIG' WHERE user_id=1 AND setting='dashboard';"
# Pure-function fix-up smoke (LayoutFixup is standalone static):
#   require the file directly in a /tmp/*.php script, no Cake bootstrap.
```

## What this session committed (in order)

```
3746ae3b2  chg: Phase 5.5 data-parity row 1 — legacy UserSetting:
                dashboard bare-array loads into v2
37f15a035  chg: Phase 5.5 data-parity row 2 — legacy dashboards.value
                templates load into v2
77ee6fd52  chg: Phase 5.5 data-parity row 3 — v2 blob export/re-import
                round-trip preserves layout
137c5428d  chg: Phase 5.5 data-parity row 4 — legacy v1 blob import +
                on-read/on-save fix-ups
190ed7eca  chg: Phase 5.5 data-parity row 5 — no data loss across
                per-widget fix-ups  (+ Discovered-work: mixed-id mint
                collision)
```

Net stats this session:
- 5 signed commits (all `%G?` = U)
- 0 code changes (all verification-only tracker closes)
- 5 progress-tracker lines closed (data-parity group 5/5)
- 1 Discovered-work entry added (mixed-id mint collision, parked)
- 0 new files committed (smoke harnesses in `/tmp/`, deleted)
- Working tree clean for v2 work after these commits

## Lessons from this session

1. **Verification-only tracker closes are a legitimate commit shape
   for a parity gate.** Same family as the prior session's doc-only
   closures. The commit body carries the smoke evidence (what was
   injected, what was observed, what was restored); no code diff.
2. **DB-raw inspection at each round-trip step is what proves the
   lazy-on-read contract.** REST read alone hides whether the fix-up
   ran on read vs at import — only reading the stored bytes
   before/after each step distinguishes them. Row 4 needed all five
   DB/REST checkpoints to prove "import verbatim → read fix-up →
   save canonical".
3. **A pure-function PHP CLI smoke is the fastest path to confidence
   for a standalone helper.** `LayoutFixup` has no Cake deps, so a
   `require` + assertion script (no PHPUnit, no bootstrap) covered 15
   cases in one run — mirrors the `node --test` pattern for JS
   helpers from the prior session.
4. **Always back up + byte-exact restore before DB-mutating smokes.**
   Every data-parity row mutated admin's `UserSetting:dashboard`;
   each was restored to the 2066-byte baseline and re-verified.

The prior sessions' gotchas still apply (themed resolver silent
fallback, `git mv` doesn't auto-stage, heredoc + dollar signs,
mode-drift carryover, `?v=185` cache-buster not per-file).

## Discovered work parked for later

New this session:
- **`LayoutFixup` mixed-id mint collision** (see Discovered work in
  progress doc; full rationale + fix shape there).

Active carryovers (unchanged from prior handoff):
- **Real widgets emit drilldown maps** (Phase 5 renderer contract in
  place; no in-tree widget consumes it — natural Phase 5.5 widget-row
  work: TrendingTags bars, OrganisationMap regions, MispStatus rows).
- Dashboard::import HTML form-paste string-foreach quirk.
- File-mode-drift root cause.
- MISP 2.4 cross-instance DB write risk.
- time_window toolbar dropdown-menu UX alternative.
- Grid drop-on-occupied cascade.
- tlp:clear (#ffffff) renders invisible bars (cosmetic).
- OrgEventsWidget months>13 malformed dates.
- EventEvolutionLineWidget ignores end_date.
- Live preview race window (AbortController fix).
- Drop dormant `dashboard.midnight.css` loader.
- Pre-fetch overshoot trade-off for EventStreamWidget post-filter
  canonicals.

Retired this session:
- Phase 5.5 data-parity group, all 5 rows closed.

## Open thread / next obvious work

In rough priority order:

**Option A: Phase 5.5 widget parity sweep (37 rows).** The bulk of
the remaining merge gate. Smoke each built-in widget loads + renders
+ honours config on default theme (single-tick), double-tick on
Overmind. Multi-session; tackle by category (status / events / tags /
orgs / system / custom). **Bundle real-widget drilldown migration
in** as a per-widget concern (the Phase 5 renderer contract is wired
+ smoked; nothing consumes it yet). **Recommended next.**

**Option B: Phase 5.5 surface parity sweep (10 rows).** Verify the 10
dashboard URLs resolve to working v2 views. One session covers them.
Several are already incidentally exercised (this session hit
`export`, `import`, `listTemplates`, `resetFromTemplate`,
`updateSettings`, `index` live) — surface parity could partly
ride on evidence already gathered.

**Option C: Phase 5.5 pre-merge cleanup (7 rows).** Remove dead deps
(gridstack `.bk` + originals, jvectormap, D3 v3), audit Chart.min.js,
drop the legacy JSON-textarea fallback if all widgets have `$schema`,
grep for stale v1 refs. Cleanup-only sweep.

**Option D: Promote the parked `LayoutFixup` collision fix.** Small,
contained; needs sign-off (touches Phase 1 helper). Standalone.

**Recommendation:** **A** — the widget rows are the largest remaining
block and the only multi-session group; starting them now de-risks
the merge timeline. Surface parity (B) can be partly back-filled from
evidence as it accrues. The remaining order is roughly: A → B → C →
Phase 6 merge. No Phase 7; the `dashboards` branch's life ends at the
merge.

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  the commit body references the task. **This session: five
  single-line commits in tracker order. No bundles.**
- **Always `git status --short` + explicit `git add` before commit.**
- New files land with `iglocska:iglocska` ownership; `chgrp
  www-data` before committing. **This session: zero new files
  landed (smoke harnesses lived in `/tmp/`).**
- **Themed wrapper parity:** any new `data-*` attribute or chrome
  span on `wrapper.ctp` MUST be mirrored in the Overmind themed
  wrapper in the SAME commit. **This session: no wrapper.ctp
  touches.**
- **Dashboard chrome icons are inline SVG, not Font Awesome.**
- **MISP-jargon naming over PRD-generic.**
- **Inline-style colour strings need a strict regex match**
  (`/^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/`).
- **External links pair `target="_blank"` with `rel="noopener
  noreferrer"`.** Internal links use same-tab navigation.
- **Themed CSS in Cake 2.x:** use plain paths (no dot-prefix).
- User wants rigorous pushback, not yes-machine — surface
  trade-offs, name alternatives, recommend a path, then go with the
  user's call. **This session: one AskUserQuestion round (session
  scope); the mixed-id collision was surfaced rather than silently
  fixed.**
- User alternates hitm / afk sessions; tracker docs are ground
  truth. Tick one task at a time; the Done note carries the
  deciding context.
- Surface context status when past 75% at task boundaries. **This
  session paced well under that threshold.**
- Hard-refresh after CSS/JS edits — `?v=185` doesn't bump per-file.
- **The schema-driven model is the canonical answer** for "how does
  the toolbar / configure form know which widgets to act on".
- **A tracker tick requires the user-visible surface to exist AND be
  reachable from the default UI**, not just the handler-level wiring.
  **This session: row 1 HTML render smoke + row 3 import-form
  gesture cover the UI-reachability gate; the REST checks cover the
  data-shape gate.**
- **`mysql -u misp -pPassword1234 misp` for one-shot SQL.** Always
  back up `UserSetting:dashboard` before a DB-mutating smoke and
  restore byte-exact.
- **Render-kind glyph requirement:** any new `$render` value or new
  template under `Widgets/` ships with a matching glyph in
  `render-thumbs.mjs` in the same commit. **No new render kinds
  this session.**
- **Heredoc + dollar signs:** single-quoted heredoc (`<<'EOF'`)
  preserves `\$` literally.
- **JSON-encode dashboard-value payloads before `UserSetting::
  setSetting`** — `import()`, `resetFromTemplate()`,
  `updateSettings()` all do.
- **When smoking a Cake form via curl in debug mode**, extract ALL
  FOUR `_Token` fields AND send every declared `data[Model][field]`.
- **URL validation runs server-side; client trusts the payload.**
- **`Dashboard::import()` stores verbatim — fix-ups are on-read
  only.** New this session: don't expect import to canonicalise; the
  first *save* after a read is where the canonical shape persists.

## Quick-start cheatsheet for the next session

If you're picking this up cold:

1. Read `dashboard-prd.md` for the spec.
2. Read `dashboard-progress.md` for what's done / what's next.
3. Skim this file for ephemeral session-level context.
4. Verify the live instance:
   `curl -s http://localhost:5007/dashboards -o /dev/null -w "%{http_code}\n"`
   → 302 without a session; 200 after the login dance.
5. **Phase 5 closed (11/11). Phase 5.5 data-parity closed (5/5).
   Remaining merge-gate: widget parity (37) + surface parity (10) +
   pre-merge cleanup (7) + Phase 6 merge.** Pick from the Open
   thread. Recommended: **A** (widget parity, bundling drilldown
   migrations into the widget rows).
6. Commit one task at a time, signed, `chgrp www-data` on new files.
   Don't `git add -A`. Back up + byte-exact restore admin's
   dashboard around any DB-mutating smoke.
