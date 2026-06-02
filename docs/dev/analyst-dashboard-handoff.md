# Analyst Dashboard — Session handoff (2026-06-02 — BUILD: AD-W5 heatmap REDESIGN (Phase B7) **BUILT + verified live** this session. Captured the rework brief → locked **AD-15** → built it end-to-end (time_window wiring + full Attack.ctp renderer rework). The roster is now **fully BUILT except W9 (DEFERRED)** — the only remaining unit, blocked on a user scope steer. Three signed commits this session: `8cd1dc7c2` (AD-15 spec), `87668cc1d` (B7 step 1 time_window), `efc0e1ae9` (B7 steps 2-6 renderer).)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (AD-W1..W8); §6 = **AD-NN** decision log (AD-01..**15**).
- `analyst-dashboard-progress.md` — the task tracker. Spec status, the
  **B1–B8 build backlog** (+ **B7 reopened**), and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (BUILD: AD-W5 heatmap REDESIGN, Phase B7 — COMPLETE)
- **Picked up W5** per the prior handoff's "needs a user steer," captured the
  dissatisfaction brief, locked it as **AD-15**, and **built + verified the whole
  redesign** this session (spec → step 1 → steps 2-6 → live verify → dashboard).
- **What shipped (AD-15, renderer-only + one AttackWidget.php add):**
  1. **Hide inactive** — zero-score techniques and empty tactic columns omitted.
  2. **Larger LABELED cells** — name + T-ID + count, readable without hover.
     Label = strip trailing " - <external_id>" (authoritative; never mangles).
  3. **Technique/sub-technique aggregation** — group per tactic column by parent
     T-ID off `external_id`; parent cell = **SUM** of own + sub event-counts;
     sub-techniques **unfold on click via native `<details>`/`<summary>` (NO JS)**
     — multi-widget-safe, accessible, minimal read-only-posture deviation.
     Orphan subs resolve via a global parent-name map; non-T ids → standalone.
  4. **Single red ramp + legend** — dropped the export's multi-hue colours;
     HSL(h=0) ramp **√-scaled** + normalised to the global max aggregate (the hit
     distribution is heavily skewed — 696 vs median <10 — so linear would wash
     out the mid-range); per-cell luminance-picked text (opaque ⇒
     theme-independent); legend bar sampled from the same ramp.
  5. **AD-12 `time_window` folded in** — `time_window` canonical on
     `AttackWidget::$schema` (default `-1`=all-time, back-compat) → restSearch
     `timestamp` lower bound; a finite window OVERRIDES a manual
     `filters.timestamp`, `-1` preserves it.
- **Verified live:** synthetic harness (all behaviours asserted) + real 34MB
  payload render (15 cols, 84 `<details>`, 168 leaf + 190 sub, 0 un-stripped
  labels) + **real web-UI POST render byte-identical (172692 B, http 200)** +
  snap-chromium screenshots **light + midnight**. `time_window` proven monotonic
  via REST probes (`30d`→0 / `3650d`→696 / `100000000s`→21 / `-1`→696).
- **Files (signed commits):** `8cd1dc7c2` AD-15 spec (3 docs); `87668cc1d`
  AttackWidget.php time_window + tracker; `efc0e1ae9` Attack.ctp +
  dashboard.default.css + dashboard.midnight.css + tracker. Data layer
  (`AttackExport`/`Galaxy::getMatrix`) **untouched** — the scope boundary held.
- **Dashboard (standing pref):** AttackWidget already on user 1's board as `w_8`
  (dedupe by class → no append); redesign verified in place. `w_8` carries a
  stale 2023 `filters.timestamp` + `time_window:"-1"`, so it scopes to Q1 2023
  (64 techniques) — left as-is (user's board), flagged for cleanup.

## What now exists in the tree (reuse it; don't re-derive)
- **`AttackWidget`** (`app/Lib/Dashboard/AttackWidget.php`) — `render='Attack'`,
  now declares the **`time_window` canonical** (`$schema`, default `-1`);
  `resolveTimeWindow()` → restSearch 'attack' `timestamp` lower bound. Runs live
  in v2 (legacy `cacheLifetime`, not `cache_duration` → `WidgetCache`
  pass-through), so the window always drives; no stale-cache concern.
- **`Attack` renderer** (`app/View/Elements/dashboard/Widgets/Attack.ctp`) —
  REDESIGNED (AD-15): per-tactic columns of **labeled** technique cells on a
  √-scaled single-red ramp, inactive hidden, sub-techniques rolled up + unfolded
  via `<details>`, a legend. Works off `tabs`+`scores`+per-cell `external_id`.
  CSS "Attack renderer" block in `dashboard.default.css` (~line 1715); the
  midnight theme needs **no** heatmap rule (opaque cells are theme-independent;
  chrome rides the `:root` token overrides).
- **Data shape (UNTOUCHED):** `AttackExport` → `Galaxy::getMatrix` returns `tabs`
  (all `kill_chain` clusters), `scores` (per-`tag_name` distinct-event count),
  `colours` (multi-hue — IGNORED by the renderer now), `defaultTabName`,
  `removeTrailing`. **Each cell carries `external_id`** (the authoritative T-ID,
  `getMatrix` ~line 1222) — `T####` technique / `T####.##` sub-technique.
- **All the BUILT widgets** (reuse, don't re-derive): `TrendingWidget`
  (+`Trending`, 3 dims), `NewDataStatsWidget` (`StatGrid`),
  `EventStreamCardsWidget`+`EventCards`, `OverlapWithMyOrgWidget` (W8),
  `AttackWidget`+`Attack` (W5). `DashboardURLValidator`, `WidgetCache` `'org'`.

## NEXT — only W9 (DEFERRED) remains; needs a user scope steer
The build backlog is **exhausted bar W9**. **W9 (AD-W9, sightings rework of
`RecentSightingsWidget`)** is DEFERRED — first-pass steer "maybe just a
look-and-feel rework" (sighting engine slow / unused by some communities; don't
over-invest). **Discuss scope before building.** No other unblocked unit.
Optional non-W9 follow-ups the user might want: clear `w_8`'s stale 2023
`filters.timestamp`; recompose the analyst `template.json` (user's job); a
default-width bump for the heatmap tile (labeled cells want more room than the
3×4 gallery default — the user resizes the board, so left alone).

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
1. Read this + tracker **Spec status** + **Phase B7 (BUILT)**.
   **W1/W2/W3/W4/W5/W6/W7/W8 all BUILT; only W9 DEFERRED.** The build backlog is
   exhausted bar W9.
2. **There is no unblocked build unit.** The only remaining roster item is **W9**
   (sightings rework) — **DEFERRED, blocked on a user scope steer**. Ask the user
   whether to take it up and, if so, scope it first ("look-and-feel rework"? the
   sighting engine is slow / unused by some — don't over-invest) before any code.
3. If W9 is taken up: **additive posture** holds (new widget / render kind = pure
   additions; existing-code touches need sign-off); verify via the real render
   path (REST handler JSON + web-UI HTML, `-1` window;
   [[reference-dashboard-widget-render-verification]]); add to user 1's test
   dashboard ([[feedback_add_touched_widgets_to_dashboard]]).
4. Optional non-W9 cleanups the user mentioned/left open: clear `w_8`'s stale
   2023 `filters.timestamp` so the heatmap shows all-time; recompose the analyst
   `template.json` (user's job).
