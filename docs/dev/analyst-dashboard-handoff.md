# Analyst Dashboard — Session handoff (2026-06-02 — BUILD: Phase B8 (AD-W8 Overlap-with-my-org) COMPLETE + verified. The normal build backlog is now EXHAUSTED: every roster widget is BUILT except **W5/B7 PARKED** (heatmap rework) and **W9 DEFERRED** (sightings reskin). Next session = either reopen W5/B7 once the user details the heatmap rework, or pick up W9 — both need a user steer first.)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (AD-W1..W8); §6 = **AD-NN** decision log (AD-01..14).
- `analyst-dashboard-progress.md` — the task tracker. Spec status (all
  DECIDED), the **B1–B8 build backlog**, and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (BUILD B8 / AD-W8)
- **Built AD-W8 Overlap-with-my-org and verified it live.** Build order across
  the track: W1 ✅ → W7 ✅ → W6 ✅ → W2 ✅ → W3 ✅ → W4 ✅ → **W5 ⏸ PARKED** →
  **W8 ✅** → (W9 DEFERRED). **Build backlog now exhausted bar parked/deferred.**
- **`OverlapWithMyOrgWidget`** (`app/Lib/Dashboard/`, `render='EventCards'`):
  candidate set = ACL-visible events fetched top-200 by `Event.timestamp DESC`
  then window-filtered (= top-N recent in-window in both dense & sparse cases);
  `CANDIDATE_CAP=200`, `CakeLog::write('info', …)` when the fetch caps (no
  existing widget `log()` idiom — MISP log is the honest no-silent-truncation
  channel). For each candidate `Correlation->getRelatedEventIds($user,$id,$sgids)`
  (`$sgids` = `SharingGroup->authorizedIds`), self-id dropped; one **batched**
  `Event->find('list',[id,orgc_id])` over all related ids; keep iff a related
  event's `orgc_id` = my org; strength = #such events; `usort` strength desc →
  recency desc. Per-ORG cache (AD-04: `cache_scope='org'`, `cache_duration=1200`).
- **AD-14 (user fork "can you make it a setting?"):** `exclude_own_org` boolean
  config, **default `true`** — drops candidates my own org created so the widget
  is a pure "external affects-me" signal; `false` honours the literal AD-13
  candidate set (every ACL-visible window event). Lenient bool coercion.
- **EventCards badge (additive, sanctioned by the prior handoff):** new per-record
  `_analyst_overlap` payload key → `EventCards.ctp` renders an *"overlaps N of
  your events"* pill **only when present** (so the W6 Event Card Stream is
  untouched) + a `.misp-eventcards-overlap` token rule in
  `dashboard.default.css` (mirrors `.misp-trending-delta`). **No new render kind,
  no glyph** (reuses W6's `EventCards`).
- **Verified live (Default engine):** REST + web-UI HTML render — `exclude_own_org`
  false→44 / true→25 candidates, admin org 1 correctly excluded, strengths 1/2/5
  ranked correctly, **25/25 cards badged**; snap-chromium screenshot confirms the
  pill renders inline. Engine-agnostic by construction (all 3 correlation
  behaviours implement `fetchRelatedEventIds`).
- **Added to user 1's test dashboard** (standing preference): appended
  `OverlapWithMyOrgWidget` as `w_15` (`time_window=-1`) at the bottom (layout
  untouched; backup `/tmp/dash_backup.json`). Read-back verified — 15 tiles.
- Files touched (all additive): **new** `OverlapWithMyOrgWidget.php`; **edited**
  `EventCards.ctp` (optional badge) + `dashboard.default.css` (one pill rule).
  All `chgrp www-data`. **Committed (both signed, `%G?`=U):** `e634224ec`
  (code) + `178422e7c` (tracker/PRD/handoff). Working tree clean for this
  track — nothing left uncommitted from B8.

## ⏸ PARKED — attack heatmap (AD-W5 / AttackWidget), user concern (2026-06-02)
**The user is NOT happy with the rework on the attack heatmap and wants to
address it in the future.** **Phase B7 (AD-W5 — wire `AttackWidget`'s
`time_window`, AD-12) is PARKED** — do **not** pick it up in the normal build
order; its additive-only sign-off is **void** until the redesign is settled.
The heatmap needs a redesign discussion first; the specific dissatisfaction
wasn't detailed, so **capture what the user wants changed before touching
`AttackWidget`** (and re-confirm whether AD-12's in-place `time_window` wiring
is even still the plan).

## What now exists in the tree (reuse it; don't re-derive)
- **`OverlapWithMyOrgWidget`** (W8) — correlation-anchored "affects me" widget;
  `render='EventCards'`; per-org cache; `exclude_own_org` setting. **If another
  widget needs ACL-correct, engine-agnostic event correlation, call
  `Correlation->getRelatedEventIds($user,$id,$sgids)` — don't scan
  `default_correlations` by org_id (no index; org_id=visibility-not-creator; no
  table under OnDemand).**
- **`EventCards` render kind** (`EventCards.ctp` + `.misp-eventcards-*` CSS +
  glyph, W6) — flat reverse-chron event cards from the `fetchEvent` payload.
  Now carries an **optional `_analyst_overlap` badge** (W8); the key is absent
  for W6 so its stream is unchanged. Shared by W6 + W8.
- **`EventStreamCardsWidget`** (W6) — subclass of `EventStreamWidget`,
  `render='EventCards'`, full canonical-filter data layer; live / no cache.
- **`TrendingWidget`** + **`Trending` render kind** (W1) — parametrised
  "what's rising" engine, THREE dimensions: `vulnerability` (value arm),
  `threat-actor` + `mitre-attack-pattern` (tag arm, parent roll-up) on the
  shared ACL-correct `countDistinctEventsByTag(...)` union-distinct counter.
  Attack technique id parsed from the tag **NAME** (`techniqueIdFromName()` /
  `parentTechniqueId()`), **NOT** `galaxy_elements.external_id` (unreliable —
  legacy `APP-NN` ids).
- **`NewDataStatsWidget`** (W7) — `StatGrid`, 4 metrics + prior-window deltas.
- **`DashboardURLValidator`** (`app/Lib/Dashboard/Tools/`) — `cveBaseUrl()` +
  baseurl/cveurl-host allowlist; extend `allowedOrigins()` for a new external
  lookup.
- **`WidgetCache`** `'org'` scope (`o<org_id>:` key, `sa:` for site-admins) —
  declare `public $cache_scope='org'` + `$cache_duration`; framework caches via
  `WidgetCache::remember` in `DashboardsController::renderWidget` automatically.

## NEXT — no unblocked build unit; needs a user steer
The roster is BUILT except two items, **both blocked on the user**:
1. **W5 / B7 (attack heatmap)** — PARKED. Reopen only when the user details the
   rework. First step then: capture the concrete dissatisfaction + re-confirm
   AD-12 is still the approach; the old sign-off is void.
2. **W9 (AD-W9, sightings rework)** — DEFERRED. First-pass user steer: "maybe
   just a look-and-feel rework" of `RecentSightingsWidget` (sighting engine
   slow / unused by some communities — don't over-invest). **Discuss scope at
   W9 time** before building.
So: **confirm with the user which (if either) to take up**, and for W5 gather
the rework brief first. No code should start on either without that steer.

## Verifying a widget (recipe in memory)
See [[reference-dashboard-widget-render-verification]]: `renderWidget` is
CSRF-unlocked → REST+APIkey returns the JSON `data` (validates the handler);
web-UI POST + session cookie returns the real `.ctp` HTML. **W8 reuses
`EventCards`** so the proof was: REST handler shape (event count / orgc /
overlap strength) + an HTML grep for `misp-eventcards-overlap` / "overlaps N of
your events" + a screenshot for the NEW badge element. **snap-chromium is
`$HOME`-confined** — stage the harness HTML + screenshot output under
`/home/iglocska/`, NOT `/tmp` (it silently fails on `file:///tmp/...`); inline
`dashboard.default.css` into the harness for tokens. **Session cookie** jar
`/tmp/cj_stat.txt` — re-mint via [[reference-misp-login-dance]] (full `_Token`
set) if a web-UI render 302s. **Clock caveat:** box clock 2026-06-02; corpus is
stale (newest event ~2026-05-29; galaxy/vuln corpus older), so verify with
`time_window=-1`. **Flush the per-org cache between checks** — TrendingWidget
caches under `misp:trending_cache:*`; the generic `WidgetCache::remember` keys
each distinct config separately (changing config sidesteps stale), and a fresh
widget's first render is live.

## Conventions (carry)
- **AD-NN** decision numbering, cross-linked to parent `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + new
  render kinds = pure additions. Existing-code touches need **sign-off**.
  Sign-offs granted: B4 DD-03 relaxation; B1.6 `WidgetCache` `'org'` scope.
  B7 (AttackWidget `time_window`, AD-12) was signed off but is **PARKED** —
  sign-off void until the heatmap redesign is settled. **B8 was pure-additive**
  (new class + an OPTIONAL `EventCards`/CSS key that no-ops for W6).
- **Add built/touched widgets to user 1's test dashboard**
  ([[feedback_add_touched_widgets_to_dashboard]]): standing request — append
  (back up first; never replace the layout), then smoke-test. **Dedupe by
  class** in general; **by (class + dimension)** for `TrendingWidget` (multiple
  dimensions share the one class). W8 is a new class → plain append (`w_15`).
- **Sequential** ([[feedback_sequential_implementation]]): one task at a time;
  research may parallelise, code never.
- **Commit per task** ([[feedback_commit_per_task]]); **never `git add -A`** —
  explicit `git add` + `git status --short`; **sign** (`git commit -S`,
  `%G?`=U). Tightly-coupled tasks may share a commit with one done-note each.
  If signing times out, the GPG passphrase lapsed — ask the user to run
  `! echo x | gpg --clearsign -o /dev/null`, then retry.
- **chgrp www-data** every edited web-served/app file incl. docs (no
  passwordless sudo right now, but `iglocska` is in the `www-data` group, so a
  plain `chgrp www-data <file>` works).
- New render kind ⇒ glyph in `render-thumbs.mjs` (CLAUDE.md). W8 reuses
  `EventCards` → no glyph.
- One task close = tick the tracker checkbox + a 1–3 line **Done note**; commit
  body references the tracker task.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**, and to
  **re-verify rather than defend** when a premise is questioned. (AD-14 came
  from surfacing the my-org-candidate fork → user asked for a setting.)
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
1. Read this + `analyst-dashboard-prd.md` §3 roster + §6 decision log
   (AD-01..14) + `analyst-dashboard-progress.md`. **W1+W2+W3+W4+W6+W7+W8 BUILT;
   W5/B7 PARKED; W9 DEFERRED.** The normal build backlog is exhausted.
2. **There is no unblocked build unit.** Ask the user which to take up:
   - **W5/B7** — only after they brief the heatmap rework (old AD-12 sign-off
     void; capture the concrete concern first).
   - **W9** — scope discussion first ("maybe just a look-and-feel rework" of
     `RecentSightingsWidget`; don't over-invest in the slow sighting engine).
3. If picking up either, **additive posture** still holds; verify via the real
   render path (REST + web-UI HTML, `-1` window). For a NEW handler payload key
   on a shared render kind, add it to the `.ctp` too
   ([[project_dashboard_ctp_payload_passthrough]]).
