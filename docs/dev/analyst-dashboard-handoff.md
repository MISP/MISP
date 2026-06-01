# Analyst Dashboard — Session handoff (2026-06-01 — BUILD: Phase B2 (W7 new-data stats) COMPLETE + verified; next build unit = Phase B3 / W6 event-stream rework)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (AD-W1..W8); §6 = **AD-NN** decision log (AD-01..13).
- `analyst-dashboard-progress.md` — the task tracker. Spec status (all
  DECIDED), the **B1–B8 build backlog**, and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (BUILD)
- **Built the ENTIRE W7 new-data stats widget (Phase B2) and verified it
  live.** 2 signed commits (`%G?`=U), additive throughout (one new widget
  file; no existing code touched):
  - `50c371bcb` B2.1–B2.4 — new **`NewDataStatsWidget`** (`render='StatGrid'`,
    reuses the existing render kind → no new glyph). 4 metrics, prior-window
    deltas, targeting waterfall, per-metric Redis cache.
  - `4547427c2` B2.5 — live verification; AD-W7 marked **BUILT**.
- **Build order (unchanged):** W1 ✅ → W7 ✅ → **W6 (next)** → (W2/W3/W4) → W5
  → W8 → (W9 deferred). The next build unit is **Phase B3 = AD-W6 event-stream
  rework** — a new **`EventStreamCardsWidget`** subclass **+ a new `EventCards`
  render kind** (which, unlike W7, **DOES need a glyph** — CLAUDE.md rule).

## What now exists in the tree (reuse it; don't re-derive)
- **`TrendingWidget`** + **`Trending` render kind** (Phase B1, W1) — the
  parametrised "what's rising" engine; vulnerability dimension live. Dimensions
  W2/W3/W4 are additive `dimensions()` entries on it (Phase B4/B5/B6). See
  `TrendingWidget.php`'s docblock (or the W1 handoff at `4128a3b4f`) for its
  full contract if you build those next; W6 does NOT depend on it.
- **`NewDataStatsWidget`** (`app/Lib/Dashboard/NewDataStatsWidget.php`, W7).
  Standalone `StatGrid` widget — 4 cards, each `value`=current-window count,
  `change`=delta vs prior equal window (StatGrid renders >0 ▲, <0 ▼, 0 = none):
  - **m1 new events** / **m2 new attributes** — global scale-counts (no ACL,
    AD-06), `Event.timestamp` / `Attribute.timestamp`(+`deleted=0`) windows.
  - **m3 targeting my org** — `COUNT(DISTINCT Event.id)` over `EventTag` for the
    resolved `misp-galaxy:country` ∪ `sector` tag-ids, `Event.timestamp` window.
    **N/A when neither country nor sector resolves** (resolved-but-untagged = a
    real 0). Country/sector via the **targeting waterfall** (config →
    `org.nationality`/`org.sector` → org-name ccTLD (country only) → N/A),
    resolved **self-contained from `country.json`/`sector.json`** (`values`,
    `meta.tld`/`ISO`/`ISO3`) — note `AttributeGeoMapWidget` resolves the same
    data from the **DB** galaxy tables instead; W7 chose the file per AD-07.
  - **m4 published by my org** — `orgc_id`=me + `published=1` +
    `publish_timestamp` window (the one place `publish_timestamp` is OK — AD-05
    exception for own-org publish).
  - **`time_window` canonical** (default `P7D`, AD-12); parsed exactly like
    `TrendingWidget::parseWindow` (adapter `P7D`→`7d`→seconds).
  - **Cache (AD-06): per-metric in-handler Redis, NOT WidgetCache `org` scope.**
    The 4 metrics span 3 scopes (m1/m2 global, m3 `(country,sector)`, m4
    `orgc_id`) which one `cache_scope` can't express — and the `org` scope's
    site-admin `sa:` no-ACL bucket is **wrong** here (these counts aren't
    ACL-scoped; it'd share m3/m4 across different-org site admins). Keys carry
    the window **length** not the drifting `now` (~5 min TTL); degrades to live
    if Redis is down.

## AD-W6 — event-stream rework (NEXT BUILD, Phase B3; full spec PRD §5 / AD-08)
A **pure-additive** new widget **+ a new read-only render kind** —
`EventStreamWidget` is left untouched.
- **`EventStreamCardsWidget extends EventStreamWidget`** (in-tree subclassing
  precedent: `OrgsUsing*` extend `OrgsContributorsGeneric`; `Dashboard::
  loadWidget` loads by filename). **Override only `$render`='EventCards',
  `$title`, `$description`; inherit `handler()` + `$schema` VERBATIM** — that
  gives all canonical filters (`tags`, `orgs` w/ `match_via`+negate,
  `published`, `threat_level`, `analysis`, `sharing_group`, `galaxy_cluster`)
  toolbar-bulk-editable for free.
- **New render kind `EventCards`** — `EventCards.ctp`, flat reverse-chron cards
  straight from the inherited `fetchEvent` `{data}` payload (the `fields`
  column list is an `Index` concept, **ignored** by cards). Card anatomy (per
  AD-08): row1 = threat-level dot (colour by `threat_level_id`) + label ·
  `Orgc.name` · **relative time** (`Event.timestamp`, AD-05) · `#id`
  (→`/events/view/<id>`); row2 = `Event.info` (truncated); row3 = tag chips
  (capped + "+N more") + attr count (`Event.attribute_count`, in `fetchEvent`
  metadata). **Token-driven CSS, no inline styles** (mirror `Index.ctp` /
  `StatGrid.ctp`); **reuse `Index.ctp`'s tag-chip colour + contrast helper**.
- **Glyph REQUIRED** (CLAUDE.md — new render kind ⇒ glyph in
  `render-thumbs.mjs`): `thumbEventCards()` (stacked-cards shape) + REGISTRY
  entry. (W7 needed none because it reused `StatGrid`; W6 introduces a new kind.)
- **Read-only** (Fork B): no in-body controls; filter/scope via the toolbar
  bulk-edit. **No cache, near-live** — `fetchEvent` is per-user ACL'd; AD-04's
  per-org aggregate cache does NOT apply (`autoRefreshDelay=5` inherited).
- **EventCards is reused by W8** (overlap widget, Phase B8) — build it cleanly.

## Verifying a widget (recipe in memory)
See [[reference-dashboard-widget-render-verification]]: `renderWidget` is
CSRF-unlocked → REST+APIkey returns the JSON `data` (validates the handler);
web-UI POST + session cookie returns the real `.ctp` HTML; snap-chromium
screenshot needs inlined CSS in `$HOME`. **For a NEW render kind (W6) the
screenshot matters** (W7 skipped it — `StatGrid` was already proven). **Clock
caveat:** the box clock is 2026-06-01; events have recent data (newest
~2026-05-29) so finite windows work, but the newest *vulnerability* attr is
~372 d old. Cross-check counts against `mysql` with a **synchronised `now`**
(per-metric cache + a drifting `time()` will otherwise look off by a few on
dense tables — that's drift, not a bug; flush `redis-cli -n 13 --scan
--pattern 'misp:dashboard:*'` between checks).

## Conventions (carry)
- **AD-NN** decision numbering, cross-linked to parent `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + new
  render kinds = pure additions. Existing-code touches need **sign-off** —
  the one remaining planned touch is **B7 (AttackWidget `time_window`, AD-12,
  already signed off)**. W6 is fully additive (subclass + new render kind).
- **Sequential** ([[feedback_sequential_implementation]]): one task at a time;
  research may parallelise, code never.
- **Commit per task** ([[feedback_commit_per_task]]); **never `git add -A`** —
  explicit `git add` + `git status --short`; **sign** (`git commit -S`,
  `%G?`=U). Tightly-coupled tasks in one file may share a commit with one
  done-note each (B1.3+B1.4, B2.1–B2.4 precedent). If signing times out, the
  GPG passphrase lapsed — ask the user to run
  `! echo x | gpg --clearsign -o /dev/null` to re-cache, then retry.
- **chgrp www-data** every edited web-served/app file incl. docs.
- New render kind ⇒ glyph in `render-thumbs.mjs` (CLAUDE.md) — **applies to W6**.
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
1. Read this + `analyst-dashboard-prd.md` §5 **AD-W6** (+ §6 AD-08) +
   `analyst-dashboard-progress.md` (**Phase B3** backlog). W1+W7 are BUILT.
2. **Start at Phase B3 = AD-W6 event-stream rework** — `EventStreamCardsWidget
   extends EventStreamWidget` (override `$render`/`$title`/`$description`
   only) + a new **`EventCards`** render kind (`EventCards.ctp` + a glyph in
   `render-thumbs.mjs`). Read-only; reuse `Index.ctp`'s tag-chip colour helper;
   token-driven CSS. One task = one commit; chgrp; sign; verify via the real
   render path (incl. a screenshot — it's a NEW render kind).
3. **Cross-cutting reminders:** inherit the data layer VERBATIM (don't touch
   `handler()`); no cache (per-user ACL'd); EventCards will be reused by W8.
4. **Confirm with the user before large work** (they may recompose the analyst
   `template.json` themselves — their job).
