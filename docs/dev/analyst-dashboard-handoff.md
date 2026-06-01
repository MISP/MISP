# Analyst Dashboard — Session handoff (2026-06-01 — BUILD: Phase B3 (W6 event-stream rework) COMPLETE + verified; next build unit = Phase B4 / AD-W2 vulnerability cveurl link)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (AD-W1..W8); §6 = **AD-NN** decision log (AD-01..13).
- `analyst-dashboard-progress.md` — the task tracker. Spec status (all
  DECIDED), the **B1–B8 build backlog**, and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (BUILD)
- **Built the ENTIRE W6 event-stream rework (Phase B3) and verified it live.**
  4 signed commits (`%G?`=U), fully additive (one new render kind + one new
  subclass; **no existing code touched**):
  - `90b420fd6` B3.1 — new **`EventCards`** render kind (`EventCards.ctp` +
    `.misp-eventcards-*` CSS block).
  - `002438ce3` B3.2 — `thumbEventCards()` glyph + REGISTRY entry
    (CLAUDE.md rule: new render kind ⇒ glyph).
  - `cb2f37bad` B3.3+B3.4 — new **`EventStreamCardsWidget extends
    EventStreamWidget`** (overrides only `$render`/`$title`/`$description`;
    inherits the whole data layer); read-only/no-cache confirmed by design.
  - `8f07c679f` B3.5 — live 3-layer verification; AD-W6 marked **BUILT**.
- **Build order (unchanged):** W1 ✅ → W7 ✅ → W6 ✅ → **(W2/W3/W4) next** → W5
  → W8 → (W9 deferred). Next build unit per order = **Phase B4 = AD-W2**.

## What now exists in the tree (reuse it; don't re-derive)
- **`EventCards` render kind** (`app/View/Elements/dashboard/Widgets/
  EventCards.ctp` + `.misp-eventcards-*` in `dashboard.default.css` + glyph,
  W6). Flat reverse-chron event cards straight from the inherited
  `fetchEvent` `{data:[...]}` payload (**ignores `fields`** — an Index
  column concept). Card anatomy: row1 = threat dot+label · `Orgc.name` ·
  relative time · `#id` (→`/events/view/<id>`); row2 = truncated `Event.info`
  (160 chars); row3 = tag chips (cap 5 + "+N more") + attr count. Threat
  dot+label derive from **`Event.threat_level_id`** (1/2/3/4 → High/Medium/
  Low/Undefined), dot colour mapped to MISP's palette via semantic tokens
  (High→danger, Medium→info, Low→success, Undefined→muted) — theme-independent.
  Reuses `Index.ctp`'s `_idxContrastColour` (guard-defined identically so the
  card renders standalone). Token-driven; only inline value = data-driven chip
  colours. **`EventCards` is reused by W8** (overlap widget, Phase B8) — it is
  intentionally built clean for that reuse.
- **`EventStreamCardsWidget`** (`app/Lib/Dashboard/EventStreamCardsWidget.php`,
  W6). `require_once 'EventStreamWidget.php'` + a 4-line subclass. Inherits
  `handler()` + `$schema` + all 9 `params` verbatim → every canonical filter
  (`tags`, `orgs` w/ `match_via`+negate, `published`, `threat_level`,
  `analysis`, `sharing_group`, `galaxy_cluster`) is toolbar-bulk-editable for
  free. No `cache_duration` → runs live (per-user ACL'd); `autoRefreshDelay=5`
  inherited → near-live.
- **`TrendingWidget`** + **`Trending` render kind** (Phase B1, W1) — the
  parametrised "what's rising" engine; **`vulnerability` dimension already
  fully wired** (count `countVulnerability` + label `labelsVulnerability` +
  momentum + per-org ACL cache, B1.4–B1.7). Dimensions W3/W4 are additive
  `dimensions()` entries (Phase B5/B6). See its docblock for the contract.
- **`NewDataStatsWidget`** (`app/Lib/Dashboard/NewDataStatsWidget.php`, W7) —
  `StatGrid` widget, 4 metrics + prior-window deltas + targeting waterfall +
  per-metric Redis cache.

## NEXT BUILD — Phase B4 = AD-W2 Trending Vulnerabilities (PRD §5 / AD-09)
**Smaller than the tracker checklist implies — most of it already shipped in
Phase B1.** The W1 engine's `vulnerability` dimension already does the
ACL-correct `COUNT(DISTINCT event_id)` over in-window `type='vulnerability'`
attrs grouped by `value1`, with momentum and the per-org cache, and a label
resolver returning the identifier verbatim. **The one remaining piece is the
drill-down link** — `labelsVulnerability()` (TrendingWidget.php ~L316) returns
`['label' => $v]` with a code comment "*The cveurl drill-down link is added in
B4*". So B4 ≈:
1. In `labelsVulnerability`, add `'drilldown' => <MISP.cveurl><value>` per row
   (default `cveurl` corrected per AD-09 to `vulnerability.circl.lu/vuln/`;
   read `Configure::read('MISP.cveurl')` with that fallback). Gate the URL
   through `DashboardURLValidator` posture in the renderer (already done —
   `Trending.ctp` validates `drilldown`).
2. **Diff the B4 task list against what B1 already covers** before writing
   anything — counting / ACL / window / momentum / verbatim-label are DONE;
   don't rebuild them. Tick those B4 sub-tasks with a "covered by B1" note.
3. Verify the link-out renders + is URL-safe via the real render path.
**This is the first work that EDITS an existing file in this track since the
AD-12 sign-off** — but it edits `TrendingWidget` (this track's own W1 class,
not platform code), adding a key to an existing hook. Still, flag it to the
user as a touch of already-shipped code before starting.

## Also now unblocked
- **W8 (AD-W8 overlap-with-my-org, Phase B8)** depends on the `EventCards`
  render kind, which now exists — it can be built whenever the order reaches
  it (`OverlapWithMyOrgWidget` with `render='EventCards'` + an overlap badge;
  PRD §5 / AD-13).

## Verifying a widget (recipe in memory)
See [[reference-dashboard-widget-render-verification]]: `renderWidget` is
CSRF-unlocked → REST+APIkey returns the JSON `data` (validates the handler);
web-UI POST + session cookie returns the real `.ctp` HTML; snap-chromium
screenshot needs inlined CSS in `$HOME`. **W6 used all three** (it's a NEW
render kind). Branches dev data can't reach (e.g. the W6 ">5 tags +N more"
overflow and long-info truncation — no dev event has either) are fair to
cover with a focused **renderer harness** (stub `Configure`/`h`/`__`/`__n`,
`include` the `.ctp` with a hand-built payload) — that tests presentation
logic only; the handler passthrough is already proven by the live REST/HTML
layers. **Clock caveat:** box clock is 2026-06-01; newest event ~2026-05-29,
newest *vulnerability* attr ~372 d old (so for the W2 link verify use
`time_window=-1` all-time, like B1.7 did). Flush `redis-cli -n 13 --scan
--pattern 'misp:dashboard:*'` between count cross-checks.

## Conventions (carry)
- **AD-NN** decision numbering, cross-linked to parent `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + new
  render kinds = pure additions (W6 was). Existing-code touches need
  **sign-off** — B7 (AttackWidget `time_window`, AD-12) is already signed off;
  **B4's cveurl link edits this track's own `TrendingWidget`** — confirm with
  the user before editing.
- **Sequential** ([[feedback_sequential_implementation]]): one task at a time;
  research may parallelise, code never.
- **Commit per task** ([[feedback_commit_per_task]]); **never `git add -A`** —
  explicit `git add` + `git status --short`; **sign** (`git commit -S`,
  `%G?`=U). Tightly-coupled tasks in one file may share a commit with one
  done-note each (B3.3+B3.4 precedent). If signing times out, the GPG
  passphrase lapsed — ask the user to run
  `! echo x | gpg --clearsign -o /dev/null` to re-cache, then retry.
- **chgrp www-data** every edited web-served/app file incl. docs.
- New render kind ⇒ glyph in `render-thumbs.mjs` (CLAUDE.md) — W6 added one;
  W2/W3/W4 reuse `Trending`, W8 reuses `EventCards`, so none of them need one.
- One task close = tick the tracker checkbox + a 1–3 line **Done note**; commit
  body references the tracker task.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**, and to
  **re-verify rather than defend** when a premise is questioned.
- **Recomposing the analyst `template.json` is the USER's job** — we build
  widgets; the user arranges the board.

## Live test instance (shared with the main track)
- `http://localhost:5007/dashboards` (302 w/o session, 200 with). Admin user 1
  `admin@admin.test` / `Password12345`, API key
  `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`, Overmind theme. Cookie jar
  `/tmp/cj_stat.txt` (re-mint via [[reference-misp-login-dance]] if it 302s).
- DB `mysql -u misp -pPassword1234 misp`; Redis `redis-cli -n 13` (data),
  db0 sessions. Branch: `dashboards` — both tracks ship together next release.

## Quick-start for next session
1. Read this + `analyst-dashboard-prd.md` §5 **AD-W2** (+ §6 AD-09) +
   `analyst-dashboard-progress.md` (**Phase B4** backlog). W1+W6+W7 are BUILT.
2. **Start at Phase B4 = AD-W2** — but FIRST open `TrendingWidget.php` and
   diff its `vulnerability` dimension (`countVulnerability` / momentum / cache
   / `labelsVulnerability`) against the B4 task list: counting/ACL/window/
   momentum/verbatim-label are already DONE (tick with a "covered by B1" note).
   The real B4 work is the **cveurl drill-down link** in `labelsVulnerability`
   (`MISP.cveurl` default `vulnerability.circl.lu/vuln/` per AD-09) — this
   edits this track's own W1 class, so **confirm with the user first**. Then
   verify the link-out via the real render path (`time_window=-1`, stale data).
3. **Cross-cutting:** W8 (overlap) is now unblocked (EventCards exists) for
   whenever the order reaches it. New trending dimensions reuse the `Trending`
   render kind (no new glyph); W8 reuses `EventCards` (no new glyph).
4. **Confirm with the user before large work** (they may recompose the analyst
   `template.json` themselves — their job).
