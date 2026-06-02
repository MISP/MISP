# Analyst Dashboard — Session handoff

**State (2026-06-02):** the analyst roster is **fully BUILT + verified EXCEPT
W9**. Last session closed **Phase B9** (widget settings canonization — four
`$params`→typed-`$schema` promotions). **NEXT focus: W9 — the sightings rework**,
which the user wants to tackle next. W9 is still **DEFERRED / un-spec'd** (the
only roster unit without a spec), so the next session **starts with a spec pass**
(scope steer → AD-16 → render decision) *before* building.

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge is
`dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track builds
the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (incl. **AD-W9** §5 stub); §6 = **AD-NN** decision log
  (AD-01..**15**; next = **AD-16**).
- `analyst-dashboard-progress.md` — the task tracker. Spec status, the
  **B1–B9 build backlog** (all done), and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — last session (Phase B9: widget settings canonization — COMPLETE)
Promoted every `$params`-only "advanced" knob the track added into a first-class
**typed `$schema`** entry, so the configure form's **Settings tier** renders a
real control instead of a raw-JSON key. **Pure additive `$schema` edits — zero
platform/JS/adapter/handler change** (the configure form already renders scalar
types; `WidgetSchema` already whitelists `bool`/`int`/`enum`/`string`). Four
promotions:
- `OverlapWithMyOrgWidget.exclude_own_org` → **bool** (checkbox). `055449873`
- `TrendingWidget.dimension` → **enum** `<select>` (3 values + `enum_labels`,
  kept in lock-step with the `dimensions()` registry). `9aef5a133`
- `NewDataStatsWidget.country`/`sector` → **string** text inputs (`''` default
  keeps the auto-detect waterfall). `aed57a35e`
- `EventStreamWidget.tags`/`published`/`limit` → **string/bool/int** (user
  signed off; re-verified the inherited `handler()` genuinely consumes them, so
  W6 `EventStreamCardsWidget` gains the controls via verbatim inheritance;
  handler unchanged; `fields` stays advanced). `9815d5f7c`
- Sweep + posture commit `2189bd0f3`. **No duplication** (a key in both `$params`
  and `$schema` renders once — the form's `handledKeys` filters it from the
  Advanced tier). Verified through the **real `configure.module.mjs`**
  (`--dump-dom` + screenshots `/home/iglocska/b9_configure_*.png`). Recipe now in
  [[reference-dashboard-widget-render-verification]] (configure-form path).

## What now exists in the tree (reuse it; don't re-derive)
- **Built analyst widgets** (W1–W8): `TrendingWidget` (+`Trending` render, 3
  dims), `NewDataStatsWidget` (`StatGrid`), `EventStreamCardsWidget`
  (+`EventCards` render), `OverlapWithMyOrgWidget` (W8, EventCards + overlap
  badge), `AttackWidget` (+`Attack` render, AD-15 heatmap redesign).
  Infra: `DashboardURLValidator`, `WidgetCache` `'org'` scope.
- **Render kinds available** (`app/View/Elements/dashboard/Widgets/`): Achievements,
  Attack, BarChart, Button, **EventCards**, HealthList, Index, MonitorLineChart,
  MultiLineChart, NetworkGraph, OrgsPictures, PewPewMap, PieChart, QueueList,
  **SimpleList**, **StatGrid**, **Trending**, UserList, WorldMap. A NEW render
  kind ⇒ a matching glyph in `render-thumbs.mjs` (CLAUDE.md rule).
- **Typed-settings convention (B9):** prefer a typed `$schema` entry
  (`bool`/`int`/`enum`/`string`) over a `$params`-only knob; keep `$params` as
  the field help. Only freeform dicts/arrays (AttackWidget `filters`,
  EventStream `fields`) legitimately stay raw/advanced.

## NEXT — W9: Sightings rework (spec FIRST, then build)
The user wants this next. **PRD §3 row = DEFERRED; PRD §5 AD-W9** records the
only steer so far: *"definitely rework, but maybe just a **look-and-feel**
rework — the sighting engine is slow and some communities don't use it, so don't
over-invest in a live 'are my IOCs sighted?' engine. Discuss scope at W9 time."*
So **step 1 is a spec pass** (capture the scope steer → record **AD-16** → flip
PRD §3 to DECIDED), then a build phase (**B10**).

### Recon already done (reuse — don't re-read from scratch)
- **`RecentSightingsWidget`** (`app/Lib/Dashboard/RecentSightingsWidget.php`, the
  PRD-named W9 target): `render='SimpleList'`, width 8/height 6. `handler()` calls
  `Sighting->restSearch($user,'json',['last'=>…,'includeAttribute'=>true,
  'includeEvent'=>true])` and emits raw string rows `value (id: X) in <info>
  (id: Y)` + an Event link in `html`. Already has typed `$schema`
  (`limit`:int=10, `last`:time_window=P1D). Sighting `type`: **0=Sighting,
  1=False positive, 2=Expiration**.
- **`ThresholdSightingsWidget`**: also `render='SimpleList'`, scores attributes
  (sighting −1 / false-positive +1) and lists those `>= threshold`. `threshold`
  is **`$params`-only** (empty `$schema`) — a leftover untyped knob if we touch it.
- **⚠ CRUX — both sightings widgets are SITE-ADMIN-ONLY** via
  `checkPermissions()` (`return false` unless `perm_site_admin`). An *analyst*-
  facing widget must not require site-admin. `Sighting->restSearch($user, …)` is
  **already ACL-aware** (user-scoped), so the site-admin gate looks vestigial /
  over-restrictive. **This is the key spec/ACL decision** (see forks below).
- **Dev-box data:** `sightings` table has **2849 rows** (2831 sightings / 18
  false-positives / 0 expirations), newest **2026-03-24** (~70d before the box
  clock 2026-06-02). So the default `last=1d` shows nothing — **verify W9 with a
  wide window** (e.g. `last=90d`/`120d` or all-time).

### Forks to put to the user at spec time (AskUserQuestion)
1. **Scope** — (a) pure look-and-feel reskin of the existing data (recommended
   per the steer; reuse `Sighting->restSearch`, no new engine); (b) a small
   aggregate/KPI view; (c) deeper "are my IOCs sighted" signal (the steer warns
   against over-investing here).
2. **ACL / where the code lives** — additive-only posture says **don't edit the
   site-admin-gated `RecentSightingsWidget`**; instead build a **NEW analyst
   sibling** (the proven W6 pattern: `EventStreamCardsWidget extends
   EventStreamWidget`). The new widget drops the site-admin gate and relies on
   `restSearch`'s per-user ACL. Confirm: new sibling vs editing the original
   (editing = existing-code touch → sign-off).
3. **Render kind** — reuse `SimpleList` (status quo, ugly), `StatGrid` (KPI
   counts: sightings / false-pos / expiration in window), `Trending` (most-sighted
   IOCs ranked), or a **NEW** sightings-feed/cards kind (→ needs a glyph). Pick by
   scope; "don't over-invest" favours reusing an existing kind.
4. **Cache** — the engine is slow → cache. The data is ACL'd per user, so
   `cache_scope='user'` (or none + a short `autoRefreshDelay`). NOT the `'org'`
   scope (its site-admin `sa:` bucket would leak across orgs — same trap as
   NewDataStats metrics 3/4).

### Then build (Phase B10)
Add the tracker spec-log entry (AD-16) + a Phase B10 build backlog, build per the
usual sequence (one task = one commit), verify via the real render path (the data
window must reach the 2026-03-24 sightings), append to user 1's board (standing
pref), screenshot.

## Verifying a widget — recipe in [[reference-dashboard-widget-render-verification]]
Two real paths: (1) **body render** — `renderWidget` is CSRF-unlocked → REST+APIkey
returns the JSON `data` (validates the handler); web-UI POST + session cookie
returns the real `.ctp` HTML; snap-chromium screenshot (the chrome is
**`$HOME`-confined** — stage harness + screenshots under `/home/iglocska/`, NOT
`/tmp`; inline/serve `dashboard.default.css` for tokens). (2) **configure-form
render** (a `$schema`→controls check) — serve the real webroot over http so
`configure.module.mjs` + its relative imports resolve; feed a synthetic widget el
the real `data-widget-schema` JSON; `--dump-dom` asserts the controls. **Session
cookie** jar `/tmp/cj_stat.txt` (re-mint via [[reference-misp-login-dance]] if it
302s). **Clock/data caveat:** box clock 2026-06-02; corpus is stale (sightings
newest 2026-03-24, events ~2026-05-29) — use wide / all-time windows.

## Conventions (carry)
- **AD-NN** decision numbering (next = **AD-16**), cross-linked to parent `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + new render
  kinds = pure additions; existing-code touches need **sign-off**. Sign-offs
  granted so far: B4 DD-03 relaxation; B1.6 `WidgetCache` `'org'` scope; B7/AD-15
  `Attack.ctp` rewrite + `AttackWidget` `time_window`; B9 `EventStreamWidget`
  schema. **For W9, prefer a new analyst sibling over editing the site-admin-gated
  `RecentSightingsWidget`** (avoids an existing-code touch).
- **Add built/touched widgets to user 1's test dashboard**
  ([[feedback_add_touched_widgets_to_dashboard]]): append (back up the layout
  first; never replace), dedupe by class, then smoke-test. Board backup convention:
  `/tmp/dash_backup.json`.
- **Sequential** ([[feedback_sequential_implementation]]): one task at a time;
  research may parallelise, code never.
- **Commit per task** ([[feedback_commit_per_task]]); **never `git add -A`** —
  explicit `git add` + `git status --short`; **sign** (`git commit -S`, `%G?`=U).
  If signing times out, the GPG passphrase lapsed — ask the user to run
  `! echo x | gpg --clearsign -o /dev/null`, then retry.
- **chgrp www-data** every edited web-served/app file incl. docs.
- A **NEW render kind ⇒ a matching glyph** in `render-thumbs.mjs` (CLAUDE.md).
  Reusing an existing kind ⇒ no glyph.
- One task close = tick the tracker checkbox + a 1–3 line **Done note**; commit
  body references the tracker task.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**, and to
  **re-verify rather than defend** when a premise is questioned
  ([[feedback_question_stated_premises]]). (B9's EventStreamWidget fix came from
  exactly this — the user questioned "out of scope" and the re-verify proved the
  filters were live.)
- **Recomposing the analyst `template.json` is the USER's job** — we build
  widgets; the user arranges the board.

## Live test instance (shared with the main track)
- `http://localhost:5007/dashboards` (302 w/o session, 200 with). Admin user 1
  `admin@admin.test` / `Password12345` (**org_id = 1**, site-admin), API key
  `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`, Overmind theme. Cookie jar
  `/tmp/cj_stat.txt` (re-mint via [[reference-misp-login-dance]] if it 302s).
- DB `mysql -u misp -pPassword1234 misp`; Redis `redis-cli -n 13` (data),
  db0 sessions. Correlation engine = **Default**. Branch: `dashboards` — both
  tracks ship together.

## Quick-start for next session
1. Read this + tracker (Phase B9 COMPLETE; B1–B8 BUILT) + **PRD §3 row AD-W9 +
   §5 AD-W9** (the only existing steer). The whole roster is BUILT except W9.
2. **W9 spec pass FIRST** — present the four forks above (scope / ACL-&-where /
   render kind / cache) to the user, capture the steer, record **AD-16**, flip
   PRD §3 W9 → DECIDED, add the Phase **B10** build backlog. The likely shape
   (subject to the steer): a **new analyst sibling widget** (not editing the
   site-admin-gated `RecentSightingsWidget`), reusing `Sighting->restSearch`
   (ACL-aware), a presentation-light reskin via an existing render kind.
3. **Then build B10** — sequential, commit-per-task, verify via the real render
   path (use a wide window so the 2026-03-24 sightings show), append to user 1's
   board, screenshot.
4. **Open (lower priority, no sign-off):** clear `w_8`'s stale 2023
   `filters.timestamp`; heatmap-tile width bump; `ThresholdSightingsWidget.threshold`
   is another untyped `$params` knob (only if W9 touches that widget). The user
   recomposes the analyst `template.json` (their job).
