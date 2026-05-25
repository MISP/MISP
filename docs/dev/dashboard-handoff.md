# Dashboard v2 — Session handoff (2026-05-25 — Phase 5.5 CLOSED)

Eleventh session of the dashboard rewrite. Authoritative state lives in:

- `dashboard-prd.md` — spec.
- `dashboard-progress.md` — task state. **Phase 5 closed (11/11).
  Phase 5.5 now FULLY CLOSED** — widget parity 38/38, data parity 5/5,
  surface parity 10/10, pre-merge cleanup 7/7. **The only remaining
  merge-gate work is Phase 6 (the merge to `develop`).**
- `dashboard-design-decisions.md` — DD-01..DD-08 unchanged.

This file is the bridge: ephemeral session-level context that doesn't
fit the durable docs. Replace it as work progresses.

## TL;DR

**11 signed commits this session** (all `%G?` = `U`). Picked up
Option A (Phase 5.5) and closed the **entire phase** — all four
parity groups plus a mid-session handoff refresh. Two real code
changes landed (both surfaced by the sweep, both verified); the rest
were verification-only tracker closes.

Order of work:
1. **Data parity (5/5)** — `3746ae3b2`..`190ed7eca`. Legacy
   bare-array + legacy templates load into v2; export/import
   round-trip preserves layout; legacy-import → on-read fix-up →
   first-save-persists-canonical proven end-to-end; 15-assertion
   `LayoutFixup` no-data-loss smoke. Parked a mixed-id mint-collision
   edge (can't arise from real data).
2. **Handoff refresh** — `e7056b0e3` (mid-session, after data parity).
3. **MispAdminWorkerWidget PHP 8.x crash fix** — `fc3c4cd5b`. Surfaced
   by the widget render sweep (500 "Cannot increment array");
   pre-existing 2020 bug (`$workerIssueCount = array()` → `++` on PHP
   8). One-line fix to `0`, matching every other caller.
4. **Widget parity (38/38)** — `6bafe4041`. All 37 built-in widgets
   render (REST handler+renderer smoke + HTML render smoke, no error
   markers); config-honouring sampled (NewOrgs `limit`; TrendingTags
   `over_time` renderer-flip); both themes (no themed renderer
   overrides → theme-independent; synthetic all-9-render-kinds board
   loaded clean under Overmind + default); custom subdir loader
   (`HelloWorldWidget`) verified.
5. **Surface parity (10/10)** — `0ddeb4a75`. 6 endpoints already
   exercised by the data/widget sweeps; the 3 template-mutating ones
   via a self-cleaning create→rename→delete chain. `getForm/add`
   closed as deliberate obsolescence (404 fine — gallery replaces it;
   per user direction "build a useful replacement, not a 1:1 v1
   replica").
6. **timeframe schema for OrgsContributors\*** — `da819c16d`. The 3
   subclasses inherited an empty `$schema` despite real params; added
   `timeframe → int` to the base (matching the partial-schema norm —
   NewOrgsWidget schemas only 1 of ~12 params). `blocklist_orgs` left
   on the kv-tier (its `org_filter` canonical shape ≠ the handler's
   flat-name `in_array`). Surfaced by the user's question on the
   cleanup fallback row.
7. **Pre-merge cleanup (7/7)** — `62349cfb0`. Only one deletion: the
   dead jvectormap pair (zero live consumers; v2 WorldMap is ECharts).
   gridstack already gone; D3 (10+ consumers) + Chart.min.js
   (event pages) retained; JSON-textarea fallback row resolved (kv-tier
   stays per DD-06 custom-widget path); v1-ref audit clean.

**Notable findings (durable, now in the progress doc):**

- **`Dashboard::import()` stores blobs verbatim — fix-ups are on-read
  only.** A v1 blob imports unchanged, renders correctly via the
  read fix-up, and only the next *save* persists canonical. PRD §7.1's
  lazy-migration story, proven by DB-raw inspection at each step.
- **No themed widget-renderer overrides exist** → every
  `Widgets/<renderer>.ctp` is theme-independent by construction; the
  theme-variable layer is page CSS + ECharts tokens only.
- **The kv-tier (configure-form bottom tier) is load-bearing for
  third-party custom widgets** (DD-06) and is NOT removable just
  because in-tree widgets are schema'd — removal is an explicit
  future-PR call. The Q7 "remove fallback" cleanup row's gate was the
  wrong lever; the JSON-textarea it named was already superseded by
  the two-tier form.
- **Partial `$schema` is the in-tree norm** — widgets schema only the
  params that benefit from a rich picker; the rest ride the kv-tier
  (NewOrgsWidget: 1 schema'd of ~12 params).

**User-direction carried forward:** *"modern and pleasant"*,
*"don't worry too much about compatibility"*, *"build a useful
replacement, not a 1:1 v1 replica — obsolete v1 URLs may 404"* (new
2026-05-25), *"ACL must match the surface it shadows"*, *"three
similar lines beats premature abstraction"*, *"prefer MISP-jargon
naming"*, **"dashboard chrome icons stay inline SVG"**, **JSON-encode
dashboard-value payloads before UserSetting::setSetting**, **URL
validation server-side; client trusts the payload**, **v2 parity =
information access, not feature-flag fidelity**.

## Where we are

```
Phase 0.4 — Sign-off                                              [x]
Phase 1 — Frame (in-place replacement)                            [x]
Phase 2 — Authoring UX                                            [x] CLOSED
Phase 3 — Canonical-type toolbar                                  [x] CLOSED
Phase 4 — Template gallery polish                                 [x] CLOSED
Phase 5 — Drill-down + refresh scheduler                          [x] CLOSED

Phase 5.5 — Widget Parity Sweep (merge gate)                      [x] CLOSED
  Widget parity   (38/38) — [x]   Data parity    (5/5)  — [x]
  Surface parity  (10/10) — [x]   Pre-merge clean (7/7) — [x]

Phase 6 — Merge to `develop`                                      [ ] ← NEXT
  [ ] User-facing changelog entry (visual rework, canonical toolbar,
      no-action-needed migration story)
  [ ] Operator-facing release note (emphasise NO migration)
  [ ] PR opened against `develop` (link PRD + progress doc)
  [ ] Review feedback addressed
  [ ] Merge
  [ ] Branch `dashboards` deleted
```

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id: 1 (`admin@admin.test`), password `Password12345`
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`
- **Admin user is on Overmind theme** (`UserSetting:ui_theme = "Overmind"`).
- DB creds: `mysql -u misp -pPassword1234 misp`

**State at session end (all restored byte-exact):** admin has the
same 13 widgets, `UserSetting:dashboard` = 2066 bytes; `ui_theme` =
`"Overmind"`; `dashboards` table = 6 rows (all legacy-shape). Every
DB-mutating smoke this session backed up + restored to baseline; a
backup remains at `/tmp/dash_backup.json`. None of the 13 widgets emit
`drilldown` keys (drill-down machinery still dormant on the live board
— a migration follow-up, not a merge blocker).

Session-login dance + REST recipes unchanged — see
`reference-misp-login-dance`. The session cookie at `/tmp/cj.txt`
expires within a session; re-run the dance if `/dashboards` 302s.

### Reusable smoke recipes

```bash
KEY=dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC
# Render any widget (REST: handler+renderer; HTML: the .ctp markup):
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  --data-urlencode "widget=<Name>Widget" --data-urlencode "config={}" \
  http://localhost:5007/dashboards/renderWidget
# Widget metadata (schema/category/render) for the gallery:
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  http://localhost:5007/dashboards/widgets
# ALWAYS back up + byte-exact restore admin's dashboard around DB writes.
```

## What this session committed (in order)

```
3746ae3b2  data-parity row 1 (legacy UserSetting:dashboard)
37f15a035  data-parity row 2 (legacy templates)
77ee6fd52  data-parity row 3 (v2 export/import round-trip)
137c5428d  data-parity row 4 (legacy import + on-read/on-save fix-ups)
190ed7eca  data-parity row 5 (no data loss; +mixed-id collision parked)
e7056b0e3  handoff refresh (mid-session)
fc3c4cd5b  FIX: MispAdminWorkerWidget PHP 8.x 'Cannot increment array'
6bafe4041  widget parity (37 widgets + custom-loader)
0ddeb4a75  surface parity (10 URLs)
da819c16d  NEW: typed timeframe schema for OrgsContributors* widgets
62349cfb0  pre-merge cleanup (jvectormap removed; rest reviewed)
```

Net stats:
- 11 signed commits (all `%G?` = U)
- 2 code changes: 1 fix (MispAdminWorkerWidget, −/+ comment + `array()`→`0`),
  1 improvement (`OrgsContributorsGeneric` `$schema` + comment)
- 2 files deleted (the dead jvectormap pair)
- Phase 5.5: 60 tracker lines closed (38 widget + 5 data + 10 surface
  + 7 cleanup)
- 2 Discovered-work entries (MispAdminWorkerWidget fix; mixed-id mint
  collision, parked)
- Working tree clean for v2 work

## Lessons from this session

1. **The REST render path proves the handler runs; only the HTML path
   proves the renderer template exists.** The MispAdminWorkerWidget
   500 showed on both, but a missing `.ctp` would only show on HTML —
   always smoke both for widget parity.
2. **DB-raw inspection at each round-trip step is what distinguishes
   on-read vs on-import fix-up.** REST read alone hides it.
3. **Check the base class before concluding a widget "lacks `$schema`".**
   The file-level grep missed the empty inherited `$schema`; the real
   gap was an *empty* schema despite real params.
4. **A canonical type isn't a free drop-in.** Declaring a param as a
   canonical wires the client picker AND the server translation; the
   handler must consume the translated shape. `org_filter` →
   `{orgs,match_via}` would have broken `blocklist_orgs`' flat-name
   `in_array`. Match the type to what the handler reads.
5. **`git log -L` to date a line before fixing.** Confirmed the
   MispAdminWorkerWidget bug was a pre-existing 2020 line, not a v2
   regression — clarified the fix as parity work, not regression
   cleanup.

Prior gotchas still apply (themed resolver silent fallback, `git mv`
doesn't auto-stage, heredoc + dollar signs, `?v=185` cache-buster not
per-file, session cookie expiry).

## Discovered work parked for later

- **`LayoutFixup` mixed-id mint collision** (progress doc; can't arise
  from real data; fix shape logged; needs sign-off — touches Phase 1).
- **Real widgets emit drilldown maps** (Phase 5 renderer contract is
  wired + smoked; nothing in-tree consumes it — a per-widget migration,
  not a merge blocker).
- **`blocklist_orgs` rich picker** — would need a handler rewrite to
  consume the `org_filter` canonical shape; left on the kv-tier.
- **Chart.min.js / D3 v3 migration** — non-dashboard pages still
  consume both; out of scope, follow-up only.
- Carryovers: import HTML form-paste string-foreach quirk; file-mode-
  drift root cause; MISP 2.4 cross-instance DB write risk; time_window
  dropdown UX; grid drop-on-occupied cascade; tlp:clear invisible bars;
  OrgEventsWidget months>13 dates; EventEvolutionLineWidget end_date;
  live-preview race (AbortController); dormant `dashboard.midnight.css`
  loader; EventStreamWidget pre-fetch overshoot.

## Open thread / next obvious work

**Phase 6 — merge to `develop` is the ONLY remaining merge-gate work.**
The three-parity gate (§12) is green. Next session:

1. **Draft the user-facing changelog entry** — visual rework, the
   canonical-type toolbar, and the no-action-needed migration story
   (existing layouts keep working; per-widget on-read fix-ups apply
   transparently on first save).
2. **Operator-facing release note** — emphasise **no migration**.
3. **Open the PR against `develop`** linking the PRD + progress doc.
4. Address review; merge; delete the `dashboards` branch.

There is no Phase 7. The branch's life ends at the merge. Before
opening the PR, consider a final `git log 2.5..dashboards` review and
a `parallel-lint` pass over `app/` (per CLAUDE.md) so the PR lands
clean.

**Optional pre-merge:** promote the parked `LayoutFixup` mixed-id
collision fix (small, contained) if the user wants zero known latent
issues in the merge — but it's not gating.

## Convention reminders

- Commit per progress-tracker task completion; never `git add -A`;
  body references the task. **This session: per-row for data parity;
  per-group for widget/surface/cleanup (the doc lists widgets
  alphabetically, not by category, and each group was one batch
  sweep — one coherent commit per group reads more honestly than
  scattered per-line commits).**
- **Always `git status --short` + explicit `git add` before commit.**
- New files land `iglocska:iglocska`; `chgrp www-data` before commit.
  **This session: no new files (smoke harnesses lived in `/tmp/`).**
- **Themed wrapper parity** on any `wrapper.ctp` chrome edit (mirror in
  Overmind). **No wrapper touches this session.**
- **Dashboard chrome icons inline SVG, not FA.**
- **MISP-jargon naming over PRD-generic.**
- **External links pair `target=_blank` + `rel=noopener noreferrer`.**
- **Themed CSS in Cake 2.x: plain paths (no dot-prefix).**
- User wants rigorous pushback, not yes-machine. **This session: two
  AskUserQuestion rounds (session scope; jvectormap removal) + surfaced
  the mixed-id collision and the cleanup-row reasoning correction
  rather than papering over them; the user's getForm + schema pushes
  both improved the outcome.**
- Tracker docs are ground truth between hitm/afk sessions. Tick one
  task at a time; the Done note carries the deciding context.
- Surface context status past 75% at task boundaries. **Comfortably
  under this session.**
- Hard-refresh after CSS/JS edits (`?v=185` doesn't bump per-file).
- **Schema-driven model is the canonical answer** for "how does the
  toolbar / configure form know which widgets to act on".
- **A tracker tick needs the user-visible surface to exist AND be
  reachable from the default UI**, not just handler-level wiring.
- **`Dashboard::import()` stores verbatim — fix-ups are on-read only.**
- **The kv-tier is load-bearing for custom widgets (DD-06); don't
  remove it.**
- **Back up + byte-exact restore `UserSetting:dashboard` around every
  DB-mutating smoke.**
- **Render-kind glyph requirement:** any new `$render` value or new
  `Widgets/` template ships a matching glyph in `render-thumbs.mjs`.
  **No new render kinds this session.**

## Quick-start cheatsheet for the next session

1. Read `dashboard-prd.md` (spec) + `dashboard-progress.md` (state).
2. Skim this file for ephemeral context.
3. Verify the instance: `curl -s http://localhost:5007/dashboards
   -o /dev/null -w "%{http_code}\n"` → 302 without a session.
4. **Phase 5.5 is fully closed. The only remaining merge-gate work is
   Phase 6 (merge to `develop`).** Start with the changelog + release
   note, then open the PR. Consider promoting the parked `LayoutFixup`
   collision fix first if a clean merge is wanted.
5. Commit one task at a time, signed. Don't `git add -A`.
