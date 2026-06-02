# Analyst Dashboard — Session handoff (2026-06-02 — **Phase B9 (widget settings canonization) COMPLETE + verified** this session. Promoted the three `$params`-only "advanced" knobs the track added to first-class typed `$schema` controls: `OverlapWithMyOrgWidget.exclude_own_org`→**bool/checkbox**, `TrendingWidget.dimension`→**enum/`<select>`**, `NewDataStatsWidget.country`/`sector`→**string/text**. Pure additive `$schema` edits — zero platform/JS/adapter change. Verified through the real `configure.module.mjs` (dump-dom + 3 screenshots). Commits: `055449873` (exclude_own_org), `9aef5a133` (dimension), `aed57a35e` (country/sector), `2189bd0f3` (sweep) + this session's finalize/verify commit and a **4th promotion under sign-off** — `EventStreamWidget.tags`/`published`/`limit` (fixing W6 `EventStreamCardsWidget` via verbatim inheritance; handler unchanged). The roster is **fully BUILT except W9 (DEFERRED)**.)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (AD-W1..W8); §6 = **AD-NN** decision log (AD-01..**15**).
- `analyst-dashboard-progress.md` — the task tracker. Spec status, the
  **B1–B8 build backlog** (+ **B7 reopened**), and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (Phase B9: widget settings canonization — COMPLETE)
- **Did Phase B9** per the prior handoff: promoted the three `$params`-only
  "advanced" knobs the track added into first-class **typed `$schema`** entries
  so the configure form's **Settings tier** renders real controls instead of
  raw-JSON keys. Pure additive `$schema` edits — **no platform/JS/adapter
  change** (the configure form already renders scalar types; `WidgetSchema`
  already whitelists them).
- **What shipped (3 promotions, one commit each):**
  1. `OverlapWithMyOrgWidget.exclude_own_org` → **`bool`** (default true) →
     a **checkbox** (`misp-field-checkbox`). `055449873`.
  2. `TrendingWidget.dimension` → **`enum`** (vulnerability / threat-actor /
     mitre-attack-pattern + `enum_labels`, default vulnerability) → a
     **`<select>`**. Enum values kept in lock-step with the `dimensions()`
     registry (reflection-asserted, no drift). `9aef5a133`.
  3. `NewDataStatsWidget.country` / `sector` → **`string`** (default `''`) →
     **labelled text inputs**; the `''` default keeps the `!empty()` override
     gate off → the auto-detect waterfall still engages. `aed57a35e`.
- **Sweep + posture (`2189bd0f3`):** all analyst-authored knobs now typed;
  `AttackWidget.filters` correctly **stays advanced** (freeform restsearch dict,
  no scalar type fits). **No-duplication** confirmed — a key in BOTH `$params`
  and `$schema` renders ONCE (the configure form's `handledKeys` filters the
  typed key out of the Advanced tier). **Posture held**: zero platform touches.
- **Verified through the real `configure.module.mjs`:** served the real webroot
  over http (so the module + relative imports resolve), fed each widget its real
  `data-widget-schema` JSON (byte-identical to `wrapper.ctp`'s `json_encode`).
  `--dump-dom` asserts the exact controls + attributes (checkbox `checked`,
  `<select>` w/ 3 `enum_labels` options + `vulnerability` selected, text inputs,
  number inputs) and **1 empty Advanced kv-row each** (no dup). Screenshots:
  `/home/iglocska/b9_configure_{overlap,trending,stats}.png`. Readback proven at
  the PHP layer (parseBool / dimension `isset` / `!empty` gate) + adapter
  default-injection + the JS `readBack()` coercion read in source.
- **Dashboard (standing pref):** all 4 touched widgets already on user 1's board
  (AttackWidget #7, TrendingWidget ×3 #8/#11/#13, NewDataStatsWidget #9,
  EventStreamCardsWidget #10, OverlapWithMyOrgWidget #14) — dedupe by class →
  verified in place, nothing to append. (Config-form-only change; widget bodies
  unchanged.)
- **4th promotion — `EventStreamWidget` inherited knobs (user signed off this
  session):** the B9 sweep flagged that W6 (`EventStreamCardsWidget`) inherits
  `tags`/`published`/`limit`/`fields` as `$params`-only from the main-track
  `EventStreamWidget`. **Re-verified the inherited `handler()` genuinely consumes
  `tags`/`published`/`limit`** (so they're real functional knobs, not dead
  config — my first "out of scope" read was too conservative); the user said
  "fix it." Promoted them on the **parent** `EventStreamWidget::$schema`
  (`tags`→string, `published`→bool default false, `limit`→int default 5) — fixes
  BOTH the original stream and the W6 cards via the verbatim inheritance, no
  subclass divergence. **`handler()` UNCHANGED** (already reads those keys) →
  pure additive. `fields` left advanced (array of column names, no scalar type;
  cards renderer ignores it); `tag_filter` chip-picker NOT taken (needs a handler
  change). Verified through the real `configure.module.mjs` (dump-dom +
  `/home/iglocska/b9_configure_eventstream.png`).

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
- **Typed settings (B9):** the analyst widgets' configurable knobs are now
  first-class `$schema` scalars rendered in the configure form's **Settings**
  tier — `exclude_own_org`(bool), `dimension`(enum), `country`/`sector`(string),
  plus the pre-existing `time_window`/`threshold`/`min_count`. To add a new knob,
  prefer a typed `$schema` entry (`bool`/`int`/`enum`/`string`) over a
  `$params`-only key; keep `$params` as the field help. Only `filters`
  (AttackWidget, freeform restsearch dict) legitimately stays raw/advanced.

## NEXT — the roster is fully BUILT except W9; pick from the open items below
**Phase B9 is COMPLETE** (this session — see TL;DR + tracker Phase B9). With B9
done, **every analyst widget W1–W8 is BUILT and verified**; the only roster unit
left is **W9 (DEFERRED)**. Choose with the user:

1. **W9 — Sightings rework (DEFERRED, needs a scope steer FIRST).** Look-and-feel
   reskin of `RecentSightingsWidget` (the sighting engine is slow / unused by
   some). Before any build: get the user's steer — "look-and-feel only" vs a
   deeper rework — so we don't over-invest. No spec exists yet (PRD §3 row =
   `DEFERRED`); this is the one widget still needing a spec pass.
2. **(DONE this session) `EventStreamWidget` inherited knobs** — promoted
   `tags`/`published`/`limit` to typed scalars on the parent (fixes W6 too); see
   the RESOLVED Discovered-work entry. A richer `tags`→`tag_filter` chip picker
   remains possible but needs a handler change (not additive) — raise on the main
   track if wanted.
3. **Optional housekeeping (no sign-off needed):** clear `w_8`'s stale 2023
   `filters.timestamp` for a full all-time heatmap; a default-width bump for the
   heatmap tile (labeled cells want >3×4); recompose the analyst `template.json`
   (**the USER's job** — we build widgets, the user arranges the board).

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
1. Read this + tracker **Phase B9 (COMPLETE)** + **Phase B7 (BUILT)**.
   **W1–W8 all BUILT + verified (incl. W5 redesign + B9 typed settings); only
   W9 DEFERRED.** Spec phase is closed; build phase is one widget from done.
2. **Decide with the user what's next** (the roster is fully built bar W9):
   - **W9 (sightings rework)** — get a **scope steer first** ("look-and-feel
     only"? deeper?); it's the only widget still needing a spec pass (PRD §3 =
     `DEFERRED`). Then spec → build like the others.
   - **`EventStreamWidget` inherited-knob promotion** — a flagged cross-track
     follow-up (Discovered work) that **needs sign-off** (main-track touch).
     Present the fork before touching it ([[feedback_additive_only_posture]]).
3. **Lower-priority housekeeping** (no sign-off): clear `w_8`'s stale 2023
   `filters.timestamp`; heatmap-tile width bump; the user recomposes the analyst
   `template.json` (their job).
4. **B9 verification recipe (reuse for any configure-form check):** serve the
   real webroot over http (`python3 -m http.server` rooted at `app/webroot`) so
   `configure.module.mjs` + its relative imports resolve; a tiny harness HTML
   under `app/webroot/js/dashboard/` (DELETE after) feeds a widget element its
   real `data-widget-schema` JSON and calls `openConfigure()`; headless chromium
   `--dump-dom` asserts the controls, `--screenshot` (write under `$HOME`) is the
   visual. The schema JSON is byte-identical to `wrapper.ctp`'s
   `json_encode($widget->schema, JSON_UNESCAPED_SLASHES)`.
