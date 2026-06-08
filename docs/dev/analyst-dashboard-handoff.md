# Analyst Dashboard — Session handoff

**State (2026-06-03, eod):** analyst surface **W1–W8 + W10–W12 BUILT + verified**;
**W9 DECLINED (AD-16)**. **Phase B15 — loose-end polish is now COMPLETE: all 4
tasks built, verified, committed (signed, `%G?`=U) on branch `dashboards`.** No
queued analyst-dashboard work remains. Authoritative state:
`analyst-dashboard-prd.md` (roster §3 · per-widget §5 · AD-NN log §6, now
**AD-01..25, all built**) + `analyst-dashboard-progress.md` (**Phase B15**
section, all 4 tasks ticked, header = COMPLETE). This file = the ephemeral
bridge. **Next free decision id = AD-26.** (AD-25 = post-B15 user tweak: W11
drilldown re-pointed to the note/opinion itself, superseding AD-23's
link-to-target.)

## TL;DR — Phase B15 (2026-06-03) — COMPLETE

User picked **"W11/W12 feature polish"** + two New-data-stats targeting-card
tweaks to finish the track. Build order ran: New-data rename → N/A tooltip → W11
drilldowns → W12 filter. **All 4 tasks done + committed (signed, `%G?`=U)** on
branch `dashboards`:

- `7c20e86c8` **AD-22 pt1 — rename "Targeting my org" → "Targeting similar
  orgs".** User-facing strings only; cache keys / method names / icon unchanged.
- `f076251c0` **AD-22 pt2 — N/A unset-meta tooltip.** Additive opt-in `tooltip`
  row key on the shared `StatGrid.ctp` (signed-off platform touch); set on the
  targeting N/A early-return. Verified two layers (`.ctp` harness + REST).
- `a9b239ae4` **AD-23 — W11 per-target-type drilldowns** (later superseded by
  AD-25, see below). Scope grew from the queued spec's 7 → all 11 target types
  (user confirmed "link all 11"): re-verification on build found BOTH the spec's
  exclusion premises were false — EventReport resolves a uuid (`simpleFetchById`
  :424), and Note/Opinion/Relationship DO have a standalone view
  (`AnalystDataController::view`). Const `VIEW_PATHS` map in `mapRow()`.
- **AD-25 (post-B15, user pref — not yet committed when this was written)**
  **W11 drilldown re-pointed to the note/opinion ITSELF.** The user preferred
  the row to open its own commentary record, so `mapRow()` now links to
  `/analystData/view/<Type>/<id>` (the row's own Note/Opinion id), not the
  target. The target type stays a chip. AD-23's `VIEW_PATHS` map + `$objUuid`
  removed (dead). Every row is now clickable. REST-verified: all rows emit
  `/analystData/view/{Note|Opinion}/<id>`, each resolves HTTP 200, bad id 404s.
  PRD AD-25 + AD-23-superseded note + §5 drilldown bullet + tracker updated.
- `6fa662c99` **AD-24 — W12 `galaxy_type` filter.** Optional typed `string`
  knob; case-insensitive match on galaxy `type` OR `name`; ids resolved in PHP
  off the 140-row `galaxies` table → `galaxy_id IN (…)`; blank = all. REST-
  verified 4 cases (type / name+case variants → 3 rows; bogus → empty; blank →
  all). Configure-form text input traced in source (B9 generic control).

**No queued analyst-dashboard tasks remain.** See "Open loose ends" for the
non-queued backlog (screenshots, CSS automation, UI nits) — none are committed
work.

## ⚠ Data note (carry forward — corrects a stale B14 observation)
- **Org-1 (`Iglocska`, the admin org) now has `nationality=Luxembourg`,
  `sector=Government`** (set by someone since the B2/B14 notes). So the targeting
  metric **resolves** (country=luxembourg → tag 1645, count 5), it does **not**
  read N/A as the B14 note claimed. The B14 "targeting N/A" line is stale, not a
  regression. To exercise the N/A branch, blank both org-meta fields (and restore
  them — Luxembourg/Government) as this session did, or use a user whose org has
  no country/sector + a non-ccTLD name.

## ✓ Phase B15 done — both queued tasks built this session

Tasks 3 (AD-23) + 4 (AD-24) are built, verified, and committed
(`a9b239ae4`, `6fa662c99`; signed, `%G?`=U). Full per-task detail in the TL;DR
above + the PRD AD-NN log + `analyst-dashboard-progress.md` Phase B15 (all 4
ticked). The three feed widgets were already on user-1's board (`w_16/17/18`)
and W11/W12 were in-place edits, so **no dashboard append was needed**
([[feedback_add_touched_widgets_to_dashboard]] satisfied).

**W11 drilldown — two design moves this session (both flagged in the AD log):**
1. Task 3 (AD-23) was specced to link **7** target types and leave 4 chip-only.
   On build, re-verifying the spec's premises ([[feedback_question_stated_premises]])
   showed **both exclusion reasons were factually wrong** — all 11
   `AnalystData::valid_targets` resolve a uuid in their `view()`; the user
   confirmed "link all 11".
2. **AD-25 (user follow-up): the drilldown was then re-pointed to the
   note/opinion ITSELF** (`/analystData/view/<Type>/<id>`), not the target —
   so the const map from move 1 was removed. Net result: every row links to its
   own commentary record; the target type stays a chip. The AD-23 recon record
   is kept (it documents *why* the targets were linkable) but its code is gone.

## What exists in the tree (reuse it; don't re-derive)
- **Analyst widgets (W1–W8, W10–W12):** `TrendingWidget` (3 dims),
  `NewDataStatsWidget` (`StatGrid`, **9 metrics**, labels-on, misp-iconify,
  targeting card now "Targeting similar orgs" + N/A tooltip),
  `EventStreamCardsWidget`, `OverlapWithMyOrgWidget`, `AttackWidget`
  (`Attack` heatmap), `RecentEventReportsWidget` / `RecentAnalystDataWidget`
  (W11) / `RecentGalaxyClustersWidget` (W12) (`FeedList`).
- **`StatGrid` platform capabilities (shared):** `$widget->statGridLabels`
  (glyph+label header), row `icon_class` (misp-iconify masked glyph), **row
  `tooltip` (NEW, AD-22 — overrides the card `title` attr).**
- **Render kinds** (`app/View/Elements/dashboard/Widgets/`): Achievements,
  Attack, BarChart, Button, EventCards, FeedList, HealthList, Index,
  MonitorLineChart, MultiLineChart, NetworkGraph, OrgsPictures, PewPewMap,
  PieChart, QueueList, SimpleList, StatGrid, Trending, UserList, WorldMap.
  A NEW render kind ⇒ a glyph in `render-thumbs.mjs` (CLAUDE.md). **Neither
  queued task adds a render kind** — both reuse existing ones.

## Verifying a widget — recipe in [[reference-dashboard-widget-render-verification]]
- **Handler/data:** REST `renderWidget` (CSRF-unlocked) — POST `widget=` +
  `config=` (JSON string) + named param `exportjson:1` for the bare rows (or
  plain `Accept: json` for the wrapped envelope) + `Authorization: <APIkey>`.
  Endpoint `http://localhost:5007/dashboards/renderWidget/exportjson:1`.
- **HTML render:** web-UI POST + session cookie → real `.ctp`. **Session re-mint
  still 400s on the Cake CSRF dance** — use REST + the offline `.ctp` harness
  instead (this session did exactly that for the tooltip; harness at
  `/home/iglocska/statgrid_tooltip_harness.php` — a clean template for a real-
  `.ctp` renderer assertion: shims `h`/`__`/`App::uses`/`StatGlyph`/
  `DashboardURLValidator`, includes the real `.ctp`, greps the output).
- **Clock/data:** box clock 2026-06-03; corpus stale — use wide / all-time
  (`time_window=-1`) windows. Analyst data ~2025-06; local clusters ~2026-04-14.

## Conventions (carry)
- **AD-NN** numbering (next free = **AD-25**), cross-linked to `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): both queued tasks are
  pure widget edits (no shared-renderer / handler-of-another-widget touch). The
  StatGrid `tooltip` key (AD-22) was the one shared-renderer touch this session —
  additive opt-in, user-requested = signed off.
- **Sequential** ([[feedback_sequential_implementation]]); **commit per task**
  ([[feedback_commit_per_task]]), **never `git add -A`**, **sign** (`-S`,
  `%G?`=U). If signing times out, GPG passphrase lapsed → ask the user to run
  `! echo x | gpg --clearsign -o /dev/null`, retry.
- **chgrp www-data** every edited web-served/app file incl. docs.
- One task close = tick the tracker checkbox + a 1–3 line Done note; commit body
  references the tracker task.
- **Rigorous pushback + genuine forks** ([[feedback_rigorous_pushback]]);
  **re-verify, don't defend** when a premise is questioned
  ([[feedback_question_stated_premises]]).
- **Recomposing the analyst `template.json` is the USER's job.**

## Live test instance (shared with the main track)
- `http://localhost:5007/dashboards`. Admin user 1 `admin@admin.test` /
  `Password12345` (**org_id = 1**, site-admin, `nationality=Luxembourg` /
  `sector=Government`), API key `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`,
  Overmind theme (FA7). Cookie jar `/tmp/cj_stat.txt` (re-mint via
  [[reference-misp-login-dance]] — currently 400s; use REST + harness).
- DB `mysql -u misp -pPassword1234 misp`; Redis `redis-cli -n 13` (data), db0
  sessions. Correlation engine = Default. Branch `dashboards` — both tracks ship
  together.

## Open loose ends (after the 2 queued B15 tasks)
1. **Live on-board screenshot** of the reworked New-data widget + FA action
   icons (still blocked on the session-cookie CSRF 400 + headless-FA7 caveat).
2. **misp-iconify CSS re-copy** automation — webroot copy drifts from the
   submodule on bump; a Makefile target would fix it.
3. **UI polish** — heatmap-tile default-width bump; filter-bar padding can go
   tighter. (User-declined for this round; pick up if asked.)
4. Board-config nit: `w_8`'s stale 2023 heatmap `filters.timestamp` scopes it to
   Q1-2023 (the user's call — board arrangement).
