# Analyst Dashboard — Session handoff (2026-06-01 — BUILD STARTED: Phase B1 (W1 trending engine) COMPLETE + verified; next build unit = Phase B2 / W7 new-data stats)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (AD-W1..W8); §6 = **AD-NN** decision log (AD-01..13).
- `analyst-dashboard-progress.md` — the task tracker. Spec status (all
  DECIDED), the **B1–B8 build backlog**, and a **Discovered work** section
  (read it — it carries two live build notes).
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (BUILD; spec phase was already complete)
- **Built the ENTIRE W1 trending engine (Phase B1) and verified it live.**
  6 signed commits (`%G?`=U), one per tracker task, additive throughout
  except the one **signed-off** WidgetCache touch:
  - `667edbfc1` B1.1 — new **`Trending` render kind**: `Trending.ctp` +
    token-driven `.misp-trending-*` CSS in `dashboard.default.css`.
  - `5717620c5` B1.2 — `thumbTrending()` glyph + `REGISTRY` entry in
    `render-thumbs.mjs` (CLAUDE.md rule).
  - `2418b83f3` B1.3+B1.4 — **`TrendingWidget`** engine + ACL-correct
    distinct-event counting (vulnerability dimension).
  - `fee4faf2e` B1.5 — momentum (floored-% delta + `min_count` floor + `NEW`).
  - `d708867fc` B1.6 — **per-org `WidgetCache` scope** (user signed off) +
    wired the widget; `WidgetCacheTest` extended (19 tests green).
  - `b3d5715de` B1.7 — live verification; AD-W1 marked **BUILT**.
- **Build order (unchanged):** W1 ✅ → **W7 (next)** → W6 → (W2/W3/W4) → W5 →
  W8 → (W9 deferred). The next build unit is **Phase B2 = AD-W7 new-data
  stats** (a standalone `StatGrid` widget; does NOT depend on the engine).

## What now exists in the tree (reuse it; don't re-derive)
- **`Trending` render kind** (`app/View/Elements/dashboard/Widgets/Trending.ctp`).
  Server-rendered ranked-row list. **Data contract = a FLAT list of row dicts**
  (the bare `handler()` return, like StatGrid/SimpleList — no `{data:}`
  wrapper): `label` (req), `count` (req int), `delta` (int %, ▲/▼; 0/null →
  none), `badge` (string, e.g. `NEW`, takes the up-style), `drilldown`
  (DashboardURLValidator-gated), `title` (hover). Volume bar width is the only
  inline value, carried as the `--misp-trending-fill` custom property
  (data-driven, like `Index.ctp`'s chips). **A leading galaxy-icon slot is NOT
  built yet** — it's the planned additive extension for W3/W4.
- **`TrendingWidget`** (`app/Lib/Dashboard/TrendingWidget.php`). One
  parametrised engine, `render='Trending'`:
  - `dimension` is a **plain config key** (no `select`/`enum` canonical type
    exists; adding one would touch CanonicalTypeAdapter → deferred), defaulted
    to `vulnerability` in `handler()`. `time_window` (default `P7D`),
    `threshold` (10), `min_count` (3) are schema canonicals (toolbar-editable).
  - **Hook architecture:** `dimensions()` returns a registry mapping each
    dimension → `count`/`labels` method names. **A new dimension = one
    additive entry + its two methods.** Hook signatures:
    `count($user, $startTs, $endTs)` → `[valueKey => distinctEventCount]`
    (start incl / end excl / either null = unbounded); `labels($valueKeys,
    $options)` → `[valueKey => ['label'=>, 'title'=>?, 'drilldown'=>?]]`.
  - **Counting (AD-02/AD-09):** the built **value arm** = candidate event ids
    from in-window `vulnerability` attrs → `aclVisibleEventIds()` (reuses
    `Event::createEventConditions($user)`; site-admin → all) → `COUNT(DISTINCT
    Attribute.event_id)` grouped by `value1`, window-bounded both ends.
  - **Momentum (AD-03):** counts current `[now-w, now]` + prior `[now-2w,
    now-w]` via the same hook; per row (only if `count >= min_count`):
    `prior<=0` → `NEW`; else `floor((cur-prior)/prior*100)` → ▲/▼. All-time
    (`-1`) → no prior window → no momentum.
  - **Cache (AD-04):** `cache_scope='org'`, `cache_duration=1200` (~20 min).
- **`WidgetCache` `'org'` scope** (`app/Lib/Dashboard/Tools/WidgetCache.php`).
  Additive (user/global untouched): key segment `o<org_id>:`; **site admins
  share a `sa:` no-ACL bucket** (they see all events); `remember()` fails safe
  to a live compute without a usable bucket. Covered by 6 new cases in
  `app/Test/WidgetCacheTest.php`.

## How to add the remaining trending dimensions (W2/W3/W4 = B4/B5/B6)
They are **dimension configs on this engine, not new classes** — purely
additive. For each: add an entry to `dimensions()` + a `count`/`labels` pair.
- **B4 / W2 vulnerability:** mostly done (value arm). Remaining = the
  **cveurl** drill-down (`Configure::read('MISP.cveurl')` + value, no
  separator → `{cveurl}{value}`; default `https://vulnerability.circl.lu/vuln/`)
  and any CVE/GCVE/GHSA prefix segmentation. Wire it into `labelsVulnerability`.
- **B5 / W3 threat-actor & B6 / W4 attack-pattern:** the **tag arms** (EventTag
  ∪ AttributeTag) are **NOT built yet**. Build the same candidate→ACL→
  `COUNT(DISTINCT event_id)` shape over the connector tables (`AttributeTag`
  has `event_id` — no join). **Do NOT reuse `EventTag/AttributeTag::
  countForTags`** (occurrence count; AttributeTag skips ACL — AD-10). W4 rolls
  sub-techniques up to the parent (`T1566.001`→`T1566`). Galaxy label resolver
  = bulk `GalaxyCluster.value` + `Galaxy.icon` + synonyms (avoid N+1); add the
  **galaxy-icon slot to Trending.ctp** then (additive).

## AD-W7 — new-data stats (NEXT BUILD, Phase B2; full spec PRD §5 / AD-05..07)
A **standalone** `StatGrid` widget (`NewDataStatsWidget`) — independent of the
engine. **4 metrics**, each `value` = current-window count, `change` = delta vs
the prior equal window (AD-03 baseline; window anchor = `Event.timestamp`,
AD-05):
1. new events (`Event.timestamp` in window) — **global, no ACL** (AD-06);
2. new attributes (`Attribute.timestamp` in window, `deleted=0`) — global;
3. events targeting my org's country/sector (distinct events with
   `misp-galaxy:country=` ∪ `misp-galaxy:sector=`, via the **waterfall**:
   widget config → org `nationality`/`sector` → org-name ccTLD (country only,
   from `country.json` `meta.tld`/`ISO`) → N/A);
4. new events published by my org (`orgc_id`=me, `published=1`,
   `publish_timestamp` in window — the one place `publish_timestamp` is OK).
- **Declare the `time_window` canonical** on this widget (AD-12 — the toolbar
  drives the whole board). **Cache (AD-06):** metrics 1–2 global; metric 3 keyed
  by `(country,sector)`; metric 4 by `orgc_id`. These are NOT the per-org ACL
  scope — they're org-context/global counts, so the new `'org'` scope likely
  does NOT apply; the per-metric cache nuance is a B2 design call (see AD-06).
  `StatGrid` contract: rows of `title`/`icon`/`value`/`change`/`drilldown`
  (see `UsageDataWidget` + `StatGrid.ctp`). No new render kind, no glyph.

## Verifying a widget (recipe now in memory)
See [[reference-dashboard-widget-render-verification]]: `renderWidget` is
CSRF-unlocked → REST+APIkey returns the JSON `data` (validates the handler);
web-UI POST + session cookie returns the real `Trending.ctp` HTML; snap
chromium screenshot needs the CSS inlined into a `$HOME` harness. **Dev-DB
caveat:** the box clock is 2026-06-01 but the newest `vulnerability` attr is
~372 d old, so finite windows render "No data" — verify with `time_window=-1`
or a split window (a 4y `1460d` window exercised momentum: ▲500% / ▼58% / NEW).

## Conventions (carry)
- **AD-NN** decision numbering, cross-linked to parent `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + new
  render kinds = pure additions. Existing-code touches need **sign-off** —
  granted twice so far: AD-12 (AttackWidget, still TODO at B7) and the
  WidgetCache `'org'` scope (B1.6, done). B7 (AttackWidget `time_window`) is the
  remaining planned touch.
- **Sequential** ([[feedback_sequential_implementation]]): one task at a time;
  research may parallelise, code never.
- **Commit per task** ([[feedback_commit_per_task]]); **never `git add -A`** —
  explicit `git add` + `git status --short`; **sign** (`git commit -S`,
  `%G?`=U). If signing times out, the GPG agent passphrase has lapsed — ask the
  user to run `! echo x | gpg --clearsign -o /dev/null` to re-cache, then retry.
- **chgrp www-data** every edited web-served/app file incl. docs.
- New render kind ⇒ glyph in `render-thumbs.mjs` (CLAUDE.md).
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
1. Read this + `analyst-dashboard-prd.md` §5 **AD-W7** (+ §6 AD-05..07) +
   `analyst-dashboard-progress.md` (the **Phase B2** backlog + **Discovered
   work**). W1 is BUILT; the engine + render kind are reusable as described
   above.
2. **Start at Phase B2 = AD-W7 new-data stats** — a standalone `StatGrid`
   widget (`NewDataStatsWidget`), no engine dependency, no new render kind.
   One task = one commit; chgrp; sign; verify via the real render path.
3. **Cross-cutting reminders:** declare the `time_window` canonical on W7
   (AD-12); metrics 1–2 are global counts (AD-06), metric 3 = `(country,
   sector)` waterfall, metric 4 = `orgc_id`+`published`; `publish_timestamp` is
   OK *only* for metric 4 (own-org). The trending-dimension build (W2/W3/W4)
   comes later and is additive on the W1 engine (see the section above).
4. **Confirm with the user before large work** (they may recompose the analyst
   `template.json` themselves — their job).
