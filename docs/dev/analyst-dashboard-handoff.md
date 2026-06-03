# Analyst Dashboard — Session handoff

**State (2026-06-03):** analyst surface **W1–W8 + W10–W12 BUILT + verified**;
**W9 DECLINED (AD-16)**. This session completed the **AD-W7 rework (Phase B14,
AD-21)** — the New-data `StatGrid` widget went **4 → 9 labelled KPI cards** on
the **misp-iconify** icon set — plus three **platform-polish** items on the
shared dashboard chrome. **No analyst-dashboard build work is queued.** Next
free decision id = **AD-22**. Authoritative state: `analyst-dashboard-prd.md`
(roster §3 · per-widget §5 · AD-NN log §6, now AD-01..21) +
`analyst-dashboard-progress.md` (Phase B14 closed). This file = the ephemeral
bridge; replace as work progresses.

## TL;DR — this session (2026-06-03)

Two threads, all committed on branch `dashboards` (signed, `%G?`=U):

**A. AD-W7 rework — Phase B14 (AD-21), COMPLETE + verified:**
- `dcee94143` **StatGrid opt-in labels.** A widget sets `public
  $statGridLabels = true` → `StatGrid.ctp` renders **glyph + label** together
  (`.misp-stat-head`, wider `.misp-stat-grid-labeled` columns, 2-line label)
  instead of the glyph-only DD-32 default. Admin `UsageDataWidget` leaves it
  unset → unchanged. Platform touch of the shared renderer, **signed off**.
- `76d2525b2` **+5 metrics → 9 cards.** `NewDataStatsWidget` added objects,
  event reports, **local** galaxy clusters (`default=0`), notes, opinions — all
  GLOBAL scale-counts (AD-06), windowed + prior-window delta like the original
  four. Dropped the "New " title prefix; default tile 3×4 → **4×6**. Notes/
  opinions use `Note`/`Opinion.modified` (a UTC datetime, no `deleted` col) via
  a new `timeConditionsDatetime()` gmdate helper. **REST-verified exact vs DB**
  (objects 48 697 · reports 435 · local clusters 441 · notes 53 · opinions 27 ·
  events 6088 · attributes 1 919 285 · targeting N/A · published 52).
- `06ced2bf7` **misp-iconify glyphs.** Added `MISP/misp-iconify` submodule (see
  "Infra" below); `StatGrid` gained `icon_class` support; all 9 cards use it.
- `6769590ae`→`29adfb379` hexagon variant, then **reverted to plain
  (`misp-simple`)** per the user (they changed their mind).
- `297bcfcf1` **Published-by-my-org reuses the `organisation` icon** (same as
  Targeting my org), was `sharing-group`.

**B. Platform polish (shared dashboard chrome — NOT analyst-specific, but ships
on `dashboards`):**
- `2a864d53a` **fix: dark-mode scrollbars.** Token `scrollbar-width:thin` +
  `scrollbar-color` on `.misp-dashboard-main`/`.misp-configure-panel` in
  `dashboard.default.css` (both themes) + `color-scheme:dark` scoped to
  `.misp-dashboard-main` in `dashboard.midnight.css` (so native scrollbar parts
  incl. the stepper arrow render dark). Verified light+midnight harness.
- `de27c10c7` **chg: tighter filter-bar padding.** `.misp-dashboard-header`
  block-padding space-3→space-2 (12→8px); `.misp-dashboard-toolbar`
  space-2→space-1 (8→4px). (User may want it tighter — easy tune.)
- `dfca61dd5` **chg: FontAwesome widget action icons.** The titlebar buttons
  (`↻ ⚙ ⬇ ✕`) → `fas fa-sync / fa-cog / fa-download / fa-times` in
  `widget/wrapper.ctp`. **Deliberate user-approved §G11 deviation** (chrome is
  otherwise inline SVG; see [[feedback_dashboard_chrome_icons]] — exception
  recorded there). FA5 names confirmed present in BOTH `font-awesome.css`
  (FA5/6) and `fontawesome7.min.css` (FA7, `--fa` codepoints + the
  `:is(.fas,…)::before{content:var(--fa)}` rule).

## ⚠ Verification caveats (carry forward)
- **Headless chromium can't paint FA7 webfont icons.** The snap
  `--headless=new` rig renders inline SVG + misp-iconify masked SVGs fine, but
  does NOT paint `fontawesome7.min.css`'s `content:var(--fa)/""` glyph syntax
  (font serves 200, budget 6s, still blank). So **verify FA chrome icons on the
  live board / a modern browser, not the offline harness.** The `dfca61dd5` FA
  action icons were verified by CSS-mechanism + codepoint existence + the
  identical `fas fa-<name>` markup already backing live Trending/FeedList — NOT
  a fresh screenshot. Worth an eyeball on the live board.
- **W7 live web-UI screenshot deferred.** The session re-mint of the dashboard
  cookie hit the **Cake SecurityComponent CSRF dance (400)** — login-dance
  recipe needs the exact `_Token` set and isn't reproducing here. B14 was
  verified via **REST `renderWidget` (exact DB match)** + the **real
  `StatGrid.ctp` harness** (real CSS + StatGlyph + misp-iconify CSS, light +
  midnight) instead. A live on-board screenshot is the one open confirmation.

## Infra added this session
- **`app/files/misp-iconify`** — new git submodule (`MISP/misp-iconify`),
  `.gitignore`-whitelisted like the sibling submodules. Its generated CSS
  (`exports/css/icons.css`) was **copied** to **`app/webroot/css/misp-iconify.css`**
  (app/files isn't web-served) and loaded in BOTH dashboard layouts
  (`app/View/Layouts/dashboard.ctp` + `Themed/Overmind/Layouts/dashboard.ctp`;
  Cake's theme resolver falls back to the main webroot, same as
  `dashboard.default.css`). **The webroot copy is a COPY — re-copy when the
  submodule bumps** (a Makefile target would automate it = noted follow-up).
- **Icon set:** 24×24 `currentColor` masked-SVG classes,
  `<span class="misp-icon misp-icon-<name> misp-simple">` (variants:
  `misp-simple` [in use] + `misp-hexagone`). Names: event, attribute, object,
  report, galaxy, analyst-note, analyst-opinion, organisation, sharing-group,
  sighting, tag, taxonomy, user1/2/3, misp.

## What now exists in the tree (reuse it; don't re-derive)
- **Analyst widgets (W1–W8, W10–W12):** `TrendingWidget` (+`Trending`, 3 dims),
  `NewDataStatsWidget` (`StatGrid`, **9 metrics**, labels-on, misp-iconify),
  `EventStreamCardsWidget` (+`EventCards`), `OverlapWithMyOrgWidget` (W8),
  `AttackWidget` (`Attack` heatmap, AD-15 redesign), `RecentEventReportsWidget`
  /`RecentAnalystDataWidget`/`RecentGalaxyClustersWidget` (W10–12, `FeedList`).
- **`StatGrid` platform capabilities (NEW, shared):**
  - `$widget->statGridLabels = true` → glyph **+** label header (else glyph-only
    DD-32). Admin `UsageDataWidget` opts out by omission.
  - row `icon_class` (a misp-icon name) → misp-iconify masked-SVG glyph; the
    StatGlyph `icon` key remains the inline-SVG path (admin widget).
- **Render kinds** (`app/View/Elements/dashboard/Widgets/`): Achievements,
  Attack, BarChart, Button, EventCards, FeedList, HealthList, Index,
  MonitorLineChart, MultiLineChart, NetworkGraph, OrgsPictures, PewPewMap,
  PieChart, QueueList, SimpleList, StatGrid, Trending, UserList, WorldMap.
  A NEW render kind ⇒ a matching glyph in `render-thumbs.mjs` (CLAUDE.md).

## Verifying a widget — recipe in [[reference-dashboard-widget-render-verification]]
- **Handler/data:** REST `renderWidget` (CSRF-unlocked) — POST `widget=` +
  `config=` (JSON string) + `Authorization: <APIkey>` + `Accept: json` → the
  bare `data` rows; cross-check vs the DB. (`exportjson=1` for the raw export.)
- **HTML render:** web-UI POST + **session cookie** (jar `/tmp/cj_stat.txt`) →
  real `.ctp` HTML. **Session re-mint currently 400s on the CSRF dance** — see
  caveat above; use the REST + offline-harness path when it does.
- **Offline harness:** render the real `.ctp` with faithful shims + the real
  CSS (inline it; snap-chrome is `$HOME`-confined, can't read `/var/www`),
  `--headless=new` screenshot under `/home/iglocska/`. Good for inline-SVG +
  misp-iconify masked SVGs; **NOT FA7 webfont glyphs** (caveat above).
- **Clock/data:** box clock 2026-06-03; corpus stale (events ~2026-05, reports
  newest 2026-04-26, analyst data ~2025-06, local clusters ~2026-04-14) — use
  wide / all-time (`time_window=-1`) windows.

## Conventions (carry)
- **AD-NN** decision numbering (next free = **AD-22**), cross-linked to `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + render
  kinds = pure additions; existing-code touches need **sign-off**. This session's
  signed-off touches: B14 StatGrid `statGridLabels` + `icon_class`; the platform
  polish trio (scrollbars / filter padding / FA action icons) were explicit user
  requests.
- **Add built/touched widgets to user 1's board** ([[feedback_add_touched_widgets_to_dashboard]]):
  append, dedupe by class, back up `/tmp/dash_backup.json` first. (NewDataStats
  is already on the board — the user reported issues with it — so the rework
  auto-applies; no append was needed.)
- **Sequential** ([[feedback_sequential_implementation]]); **commit per task**
  ([[feedback_commit_per_task]]), **never `git add -A`**, **sign** (`-S`,
  `%G?`=U). If signing times out, GPG passphrase lapsed → ask the user to run
  `! echo x | gpg --clearsign -o /dev/null`, retry.
- **chgrp www-data** every edited web-served/app file incl. docs.
- A **NEW render kind ⇒ a glyph** in `render-thumbs.mjs`; reusing a kind ⇒ none.
- One task close = tick the tracker checkbox + a 1–3 line Done note; commit body
  references the tracker task.
- **Rigorous pushback + genuine forks** ([[feedback_rigorous_pushback]]);
  **re-verify, don't defend**, when a premise is questioned
  ([[feedback_question_stated_premises]]). This session: surfaced the §G11
  inline-SVG-vs-FA conflict before the action-icon swap; the user chose FA.
- **Recomposing the analyst `template.json` is the USER's job.**

## Live test instance (shared with the main track)
- `http://localhost:5007/dashboards` (302 w/o session, 200 with). Admin user 1
  `admin@admin.test` / `Password12345` (**org_id = 1**, site-admin, has a logo
  at `app/files/img/orgs/1.png`), API key
  `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`, **Overmind theme (FA7)**. Cookie
  jar `/tmp/cj_stat.txt` (re-mint via [[reference-misp-login-dance]] — currently
  400s; needs the exact `_Token` CSRF set).
- DB `mysql -u misp -pPassword1234 misp`; Redis `redis-cli -n 13` (data), db0
  sessions. Correlation engine = Default. Branch `dashboards` — both tracks ship
  together.

## Quick-start for next session
**No queued analyst-dashboard work.** W1–W8 + W10–W12 built; W9 declined; the
W7 rework (B14/AD-21) is **done + committed**. Any new request is fresh — read
PRD §3 roster for as-built state, carry the Conventions above (additive-only,
commit-per-task signed, verify via the real render path, **AD-NN next = AD-22**).

**Open loose ends (none queued):**
1. **Live on-board screenshot** of the reworked New-data widget + the FA action
   icons (blocked on the session-cookie CSRF 400 + the headless-FA7 caveat).
2. **misp-iconify CSS re-copy** automation — the webroot copy drifts from the
   submodule on bump; a Makefile target would fix it.
3. Filter-bar padding can go tighter if the user wants.
4. Older follow-ups (still none queued): clear `w_8`'s stale 2023 heatmap
   `filters.timestamp`; heatmap-tile width bump; richer per-target-type
   drilldowns on W11; a `galaxy_type` filter on W12.
