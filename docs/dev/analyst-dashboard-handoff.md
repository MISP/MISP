# Analyst Dashboard — Session handoff (2026-06-02 — SPEC: AD-W5 heatmap REDESIGN brief captured + locked as **AD-15**; **Phase B7 UN-PARKED** with a concrete renderer-redesign spec. No build code written yet this session — the next unit is **building B7**. The roster is otherwise complete: W1/W2/W3/W4/W6/W7/W8 BUILT; W9 DEFERRED.)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (AD-W1..W8); §6 = **AD-NN** decision log (AD-01..**15**).
- `analyst-dashboard-progress.md` — the task tracker. Spec status, the
  **B1–B8 build backlog** (+ **B7 reopened**), and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (SPEC: reopened AD-W5 / Phase B7)
- **Picked up W5 (ATT&CK heatmap)** per the prior handoff's "needs a user steer."
  Captured the user's concrete dissatisfaction with the shipped static heatmap
  and locked the redesign as **AD-15**. **No build code yet — spec only.**
- **The brief (AD-15) — renderer redesign, 5 locked points:**
  1. **Hide inactive techniques** (zero-score) + empty tactic columns.
  2. **Larger, LABELED cells** — name + T-ID + count, readable without hover
     (must work on a static wall display). Kills the 8px hover-only bars.
  3. **Technique/sub-technique aggregation** — the shipped renderer flatly mixes
     them (**confirmed from live data: all 526 sub-techniques carry `kill_chain`
     → intermixed with the 673 techniques in tabs**). Group per tactic column by
     parent T-ID off `external_id` (`^T\d+$` technique / `^T\d+\.\d+$`
     sub-technique → strip `.\d+`). Parent cell = rolled-up aggregate; **click
     unfolds sub-techniques on demand**. **Parent heat = SUM** of own + sub
     counts (user fork: sum/max/true-distinct → chose SUM, renderer-only).
  4. **Single red gradient + small legend/scale** — drop the export's multi-hue
     `ColourGradientTool`; shade in-renderer from `score / max-parent-score`.
  5. **Fold in AD-12 `time_window`** (user reaffirmed) — add the canonical to
     `AttackWidget::$schema` + map to restSearch 'attack' `timestamp`. The only
     `AttackWidget.php` change.
- **Scope boundary (signed off):** **renderer + `AttackWidget` only — the data
  layer (`AttackExport`, `Galaxy::getMatrix`) stays UNTOUCHED.** The
  `tabs`+`scores` payload, with `external_id` already stamped on every cell
  (`getMatrix` line ~1222), suffices. The renderer rewrite (`Attack.ctp`) +
  `AttackWidget.php` edit are **beyond additive-only** and explicitly approved.
  The platform **read-only render posture is deviated** for the click-to-unfold
  (progressive disclosure of the widget's OWN data, not a filter/scope action —
  user-requested).
- **Docs updated + (to be) committed:** PRD roster row + §5 AD-W5 (redesign
  block prepended, old static spec marked SUPERSEDED) + **AD-15** in §6; tracker
  spec-status row, spec-log entry, build-order line, **Phase B7 rewritten with
  6 build steps**. This handoff replaced.

## What now exists in the tree (reuse it; don't re-derive)
- **`AttackWidget`** (`app/Lib/Dashboard/AttackWidget.php`) — `render='Attack'`,
  `$schema=[]` (only `filters` param), `cacheLifetime=1200`. `handler()` calls
  `Event->restSearch($user, 'attack', $options['filters'])`. **B7 adds the
  `time_window` canonical here** (the only data-side touch).
- **`Attack` renderer** (`app/View/Elements/dashboard/Widgets/Attack.ctp`) — the
  static heatmap **being redesigned in B7**. Today: tactic columns (110px), cells
  = 8px coloured bars (hit + muted no-hit), hover-only tooltips, multi-hue. CSS
  block "Attack renderer" in `dashboard.default.css` (~line 1716) + midnight.
- **Data shape (untouched by B7):** `AttackExport` → `Galaxy::getMatrix($user,
  $galaxy_id)` returns `tabs` (all clusters with `kill_chain`, organised
  tactic→technique), `scores` (per-`tag_name` **distinct-event count**),
  `colours` (multi-hue gradient — B7 IGNORES this), `maxScore`,
  `defaultTabName='attack-enterprise'`, `removeTrailing=2` (strips the trailing
  `- T####` from each cell `value` for display). **Each cell carries
  `external_id`** (the authoritative T-ID — `getMatrix` stamps it from the
  `external_id` GalaxyElement). The W4 "external_id is unreliable" caveat was
  about counting legacy `APP-NN` tags across all events, NOT the current matrix
  galaxy — for the matrix, `external_id` is clean (`T####` / `T####.##`).
- **All the BUILT widgets** (reuse, don't re-derive): `TrendingWidget` (+`Trending`
  render, 3 dims — see its `techniqueIdFromName()`/`parentTechniqueId()` for the
  parent-T-ID idiom, though B7 uses `external_id` not the tag name),
  `NewDataStatsWidget` (`StatGrid`), `EventStreamCardsWidget`+`EventCards`,
  `OverlapWithMyOrgWidget` (W8). `DashboardURLValidator`, `WidgetCache` `'org'`
  scope.

## NEXT — build Phase B7 (AD-W5 redesign), one step at a time
Spec is locked; the next unit is **building**. Tracker Phase B7 has 6 steps
(sequential — [[feedback_sequential_implementation]]). Suggested order:
1. **`time_window` wiring in `AttackWidget.php`** (smallest, self-contained;
   re-confirm restSearch 'attack' accepts the timestamp form — reuse
   `TrendingAttributesWidget`/`CanonicalTypeAdapter`).
2. **Aggregation + hide-inactive in `Attack.ctp`** (the core data-shape rework;
   group by parent T-ID, sum, drop zero-score groups/columns).
3. **Labeled cells + red ramp + legend** (`Attack.ctp` + CSS default + midnight).
4. **Unfold JS** (click parent → reveal sub-techniques; scope to widget
   container — find where dashboard widget JS hooks in; multi-widget-safe).
5. **Verify live** (real render path) + append to user 1's test dashboard.
Commit per step ([[feedback_commit_per_task]]); the renderer + CSS + JS steps may
share commits where tightly coupled (one done-note each).

## Verifying a widget (recipe in memory)
See [[reference-dashboard-widget-render-verification]]: `renderWidget` is
CSRF-unlocked → REST+APIkey returns the JSON `data` (validates the handler);
web-UI POST + session cookie returns the real `.ctp` HTML. For B7, the proof =
the rendered heatmap: inactive techniques absent, cells labeled + readable,
parent cells fold/unfold (needs a real browser/JS — snap-chromium with the JS
present), red ramp + legend visible, and `time_window` re-scopes the matrix.
**snap-chromium is `$HOME`-confined** — stage harness HTML + screenshots under
`/home/iglocska/`, NOT `/tmp`; inline `dashboard.default.css` for tokens.
**Session cookie** jar `/tmp/cj_stat.txt` — re-mint via [[reference-misp-login-dance]]
if a web-UI render 302s. **Clock caveat:** box clock 2026-06-02; corpus is stale
(newest event ~2026-05-29), so verify with `time_window=-1`. **Flush caches**
between checks (AttackWidget `cacheLifetime=1200`; changing config sidesteps a
stale key, and a fresh render is live).

## Conventions (carry)
- **AD-NN** decision numbering, cross-linked to parent `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + new
  render kinds = pure additions; existing-code touches need **sign-off**.
  Sign-offs granted: B4 DD-03 relaxation; B1.6 `WidgetCache` `'org'` scope;
  **B7/AD-15 — the `Attack.ctp` rewrite + `AttackWidget.php` `time_window` edit**
  (data layer is the scope boundary; true-distinct-count option declined).
- **Add built/touched widgets to user 1's test dashboard**
  ([[feedback_add_touched_widgets_to_dashboard]]): standing request — append
  (back up first; never replace the layout), then smoke-test. W5 already exists
  on dashboards generally; for the test board, dedupe by class (AttackWidget) —
  it may already be present; if so the redesign is verified in place, else append.
- **Sequential** ([[feedback_sequential_implementation]]): one task at a time;
  research may parallelise, code never.
- **Commit per task** ([[feedback_commit_per_task]]); **never `git add -A`** —
  explicit `git add` + `git status --short`; **sign** (`git commit -S`, `%G?`=U).
  If signing times out, the GPG passphrase lapsed — ask the user to run
  `! echo x | gpg --clearsign -o /dev/null`, then retry.
- **chgrp www-data** every edited web-served/app file incl. docs.
- `Attack` is an **existing** render kind ⇒ **no new glyph** (CLAUDE.md rule is
  for NEW kinds only); confirm the `Attack` glyph already exists in
  `render-thumbs.mjs`.
- One task close = tick the tracker checkbox + a 1–3 line **Done note**; commit
  body references the tracker task.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**, and to
  **re-verify rather than defend** when a premise is questioned. (AD-15's two
  forks — `time_window` in/out, parent-heat sum/max/distinct — came from this.)
- **Recomposing the analyst `template.json` is the USER's job** — we build
  widgets; the user arranges the board.

## Live test instance (shared with the main track)
- `http://localhost:5007/dashboards` (302 w/o session, 200 with). Admin user 1
  `admin@admin.test` / `Password12345` (**org_id = 1**), API key
  `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`, Overmind theme. Cookie jar
  `/tmp/cj_stat.txt` (re-mint via [[reference-misp-login-dance]] if it 302s).
- DB `mysql -u misp -pPassword1234 misp`; Redis `redis-cli -n 13` (data),
  db0 sessions. Correlation engine = **Default**. `MISP.cveurl` here =
  `http://cve.circl.lu/cve/`. Branch: `dashboards` — both tracks ship together.

## Quick-start for next session
1. Read this + PRD §5 **AD-W5 (redesign block)** + **AD-15** + tracker
   **Phase B7**. W1/W2/W3/W4/W6/W7/W8 BUILT; **W5 = BUILDING (B7, spec locked)**;
   W9 DEFERRED.
2. **Build B7 step by step** (order above). Renderer-only + the one
   `AttackWidget.php` `time_window` add; data layer untouched.
3. Verify via the real render path (REST + web-UI HTML, `-1` window) — the
   unfold needs JS present, so a real-browser/snap-chromium check, not a
   hand-built payload ([[project_dashboard_ctp_payload_passthrough]]). Append to
   user 1's test dashboard after.
