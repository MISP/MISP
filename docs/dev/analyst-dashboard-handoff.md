# Analyst Dashboard — Session handoff (2026-06-02 — BUILD: Phase B4 (W2 trending vulnerabilities) COMPLETE + verified; next build unit = Phase B5 / AD-W3 trending threat actors — the first tag-arm count)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (AD-W1..W8); §6 = **AD-NN** decision log (AD-01..13).
- `analyst-dashboard-progress.md` — the task tracker. Spec status (all
  DECIDED), the **B1–B8 build backlog**, and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (BUILD)
- **Built W6 (event-stream rework) AND W2 (trending vulnerabilities); both
  verified live.** Build order: W1 ✅ → W7 ✅ → W6 ✅ → **W2 ✅** →
  (W3/W4) next → W5 → W8 → (W9 deferred).
- **W6 (Phase B3)** — 4 commits (`90b420fd6`/`002438ce3`/`cb2f37bad`/
  `8f07c679f`): new **`EventCards`** render kind (+ glyph) + new
  **`EventStreamCardsWidget extends EventStreamWidget`** (inherits the whole
  data layer; read-only/no-cache). Verified via REST + web-UI HTML + headless
  screenshot.
- **W2 (Phase B4)** — most of it already shipped in B1 (count/ACL/window/
  momentum/verbatim-label). The remaining piece — the **cveurl drill-down
  link** — surfaced a **conflict**: AD-09's external `{cveurl}{value}` link vs
  the dashboard's on-host-only DD-03 URL validator (it would silently drop the
  link). Surfaced the fork via AskUserQuestion; **user chose to relax DD-03**.
  2 commits:
  - `693222957` B4-a — `DashboardURLValidator` now allowlists the trusted CVE
    base alongside `MISP.baseurl`, via a shared `cveBaseUrl()` resolver
    (`MISP.cveurl` ?: documented default) so the emitter and the gate can't
    drift. Test suite → **29 tests / 42 assertions** (all original DD-03 cases
    preserved + cveurl host/scheme/port, off-host-still-rejected, default-trust).
  - `d479d45c4` B4-b — `labelsVulnerability()` sets
    `'drilldown' => DashboardURLValidator::cveBaseUrl() . $value`.
  - `b/handoff` B4-c — live verify: all rows render as `<a href="http://
    cve.circl.lu/cve/…">` (validator admits them end-to-end). AD-W2 → BUILT.

## What now exists in the tree (reuse it; don't re-derive)
- **`TrendingWidget`** + **`Trending` render kind** (W1). The parametrised
  "what's rising" engine. **`vulnerability` dimension complete** (W2): count
  `countVulnerability` (ACL-scoped, `Attribute.timestamp`-windowed), momentum,
  per-org cache, and `labelsVulnerability` (verbatim label + cveurl drilldown).
  **The tag-arm count does NOT exist yet** — W3/W4 must build it (see below).
- **`DashboardURLValidator`** (`app/Lib/Dashboard/Tools/`) — now exposes
  `cveBaseUrl()` (public) and allowlists baseurl **+ the configured cveurl
  host**. `validate()` still drops arbitrary off-host links / dangerous
  schemes. If another dimension ever needs a different external lookup (e.g.
  `MISP.cweurl` for CWE/weakness), extend `allowedOrigins()` the same way.
- **`EventCards` render kind** (`EventCards.ctp` + `.misp-eventcards-*` CSS +
  glyph, W6) — flat reverse-chron event cards from the `fetchEvent` payload
  (threat dot+label · org · relative time · #id · info · tag chips + attr
  count). **Reused by W8** (overlap widget, Phase B8) — built clean for it.
- **`EventStreamCardsWidget`** (W6) — subclass of `EventStreamWidget`,
  `render='EventCards'`, inherits the full canonical-filter data layer; live
  / no cache (per-user ACL'd).
- **`NewDataStatsWidget`** (W7) — `StatGrid`, 4 metrics + prior-window deltas.

## NEXT BUILD — Phase B5 = AD-W3 Trending Threat Actors (PRD §5 / AD-10)
**More substantial than B4** — it builds the engine's **first tag-arm count**
(the count machinery W1 deferred; B1.4's done-note: "the tag arms arrive with
their galaxy dimensions in B5/B6"). A new `dimension` entry + hooks on the W1
engine — NOT a new widget, NOT a new render kind (reuses `Trending`, no glyph).
- **Dimension config:** `threat-actor` galaxy only — tag-id set =
  `tags WHERE is_galaxy=1 AND name LIKE 'misp-galaxy:threat-actor="%'`.
- **The hard part — an ACL-correct union-distinct count** (`COUNT(DISTINCT
  event_id)` over **EventTag ∪ AttributeTag** for those tag_ids, scoped to the
  org's visible events). **Watch-out (AD-10): do NOT reuse
  `AttributeTag::countForTags`** — it skips ACL and counts occurrences, not
  distinct events. Build it on the **same mechanism `countVulnerability` uses**
  — candidate event ids from in-window connector rows → `aclVisibleEventIds()`
  → distinct-event count — but sourced from the two tag tables, not
  `Attribute.value1`. Anchors per AD-05 (event-tag→`Event.timestamp`,
  attr-tag→`Attribute.timestamp`); momentum AD-03; per-org cache (already on
  the widget).
- **Label resolver:** bulk-resolve top-N clusters → `value` + `Galaxy.icon` +
  synonyms (avoid N+1). Link = `/galaxy_clusters/view/<id>` (internal →
  on-host → passes DD-03 with no relaxation needed, unlike W2's cveurl).
- **W4 (Phase B6) then reuses B5's union-distinct count** with the
  attack-pattern tag set grouped by parent technique — so build B5's count
  cleanly/parametrically.

## Also still unblocked
- **W8 (AD-W8 overlap-with-my-org, Phase B8)** — depends on `EventCards`
  (exists). `OverlapWithMyOrgWidget` with `render='EventCards'` + overlap
  badge; PRD §5 / AD-13. Build whenever the order reaches it (after W5).

## Verifying a widget (recipe in memory)
See [[reference-dashboard-widget-render-verification]]: `renderWidget` is
CSRF-unlocked → REST+APIkey returns the JSON `data` (validates the handler);
web-UI POST + session cookie returns the real `.ctp` HTML; snap-chromium
screenshot needs inlined CSS in `$HOME`. **Screenshot only matters for a NEW
render kind** (W6 needed one; W2/W3/W4 reuse `Trending` so the HTML grep for
`<a>` vs `<div>` rows is the proof). **Session cookie expires** — re-mint
`/tmp/cj_stat.txt` via [[reference-misp-login-dance]] (it lapsed mid-session
this time; the full `_Token` set is required). **Clock caveat:** box clock is
2026-06-02; newest event ~2026-05-29 but newest *vulnerability* attr ~372 d
old, so verify trending with `time_window=-1` (all-time). **Flush per-org
cache between checks:** `redis-cli -n 13 --scan --pattern 'misp:dashboard:*'`
(TrendingWidget caches output per-org — a stale entry hides your change).

## Conventions (carry)
- **AD-NN** decision numbering, cross-linked to parent `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + new
  render kinds = pure additions. Existing-code touches need **sign-off** —
  granted so far: B7 (AttackWidget `time_window`, AD-12) and the **B4 DD-03
  relaxation** (user chose it over an internal drilldown). B5 is additive (new
  dimension hooks on TrendingWidget — same as B4's link builder, this track's
  own class; flag it but it's low-risk).
- **Sequential** ([[feedback_sequential_implementation]]): one task at a time;
  research may parallelise, code never.
- **Commit per task** ([[feedback_commit_per_task]]); **never `git add -A`** —
  explicit `git add` + `git status --short`; **sign** (`git commit -S`,
  `%G?`=U). Tightly-coupled tasks may share a commit with one done-note each
  (B3.3+B3.4 precedent). If signing times out, the GPG passphrase lapsed — ask
  the user to run `! echo x | gpg --clearsign -o /dev/null`, then retry.
- **chgrp www-data** every edited web-served/app file incl. docs.
- New render kind ⇒ glyph in `render-thumbs.mjs` (CLAUDE.md). W3/W4 reuse
  `Trending`, W8 reuses `EventCards` → none need a glyph.
- One task close = tick the tracker checkbox + a 1–3 line **Done note**; commit
  body references the tracker task.
- User wants **rigorous pushback + genuine forks via AskUserQuestion** (the B4
  DD-03 conflict is the model), and to **re-verify rather than defend** when a
  premise is questioned.
- **Recomposing the analyst `template.json` is the USER's job** — we build
  widgets; the user arranges the board.

## Live test instance (shared with the main track)
- `http://localhost:5007/dashboards` (302 w/o session, 200 with). Admin user 1
  `admin@admin.test` / `Password12345`, API key
  `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`, Overmind theme. Cookie jar
  `/tmp/cj_stat.txt` (re-mint via [[reference-misp-login-dance]] if it 302s).
- DB `mysql -u misp -pPassword1234 misp`; Redis `redis-cli -n 13` (data),
  db0 sessions. `MISP.cveurl` here = `http://cve.circl.lu/cve/`. Branch:
  `dashboards` — both tracks ship together next release.

## Quick-start for next session
1. Read this + `analyst-dashboard-prd.md` §5 **AD-W3** (+ §6 AD-10) +
   `analyst-dashboard-progress.md` (**Phase B5** backlog). W1+W2+W6+W7 BUILT.
2. **Start at Phase B5 = AD-W3 Trending Threat Actors** — a new `dimension`
   on `TrendingWidget` (reuses `Trending`, no glyph). The real work is the
   **ACL-correct EventTag ∪ AttributeTag union-distinct count** on the same
   mechanism `countVulnerability` uses (candidate ids → `aclVisibleEventIds()`
   → distinct-event count) — **do NOT reuse `AttributeTag::countForTags`**
   (skips ACL, counts occurrences). Label resolver = bulk cluster resolve
   (value + `Galaxy.icon` + synonyms, no N+1); link = internal
   `/galaxy_clusters/view/<id>` (on-host → no DD-03 relaxation needed). Build
   the count parametrically — **W4 (B6) reuses it**.
3. **Cross-cutting:** flag the TrendingWidget edit (additive, this track's own
   class). Verify via REST + web-UI HTML (`<a>` vs `<div>` rows), `-1` window,
   flush the per-org cache. W8 (overlap) still unblocked (EventCards exists).
4. **Confirm with the user before large work** (they may recompose the analyst
   `template.json` themselves — their job).
