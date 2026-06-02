# Analyst Dashboard — Session handoff (2026-06-02 — BUILD: Phase B5 (W3 trending threat actors) COMPLETE + verified; next build unit = Phase B6 / AD-W4 trending ATT&CK techniques — reuses W3's union-distinct count, grouped by parent technique)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (AD-W1..W8); §6 = **AD-NN** decision log (AD-01..13).
- `analyst-dashboard-progress.md` — the task tracker. Spec status (all
  DECIDED), the **B1–B8 build backlog**, and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (BUILD)
- **Built W3 (trending threat actors) — the engine's first tag-arm count;
  verified live.** Build order: W1 ✅ → W7 ✅ → W6 ✅ → W2 ✅ → **W3 ✅** →
  **W4 (B6) next** (reuses W3's count) → **W5 ⏸ PARKED** (user reworking the
  heatmap — see below) → W8 → (W9 deferred).
- **`TrendingWidget` now has TWO dimensions:** `vulnerability` (W2, value arm)
  and `threat-actor` (W3, tag arm). The threat-actor count is the
  **ACL-correct EventTag ∪ AttributeTag union-distinct** count — the primary
  build risk AD-10 flagged — built parametrically so **W4 (B6) reuses it** for
  ATT&CK techniques (just a different tag set + parent-technique rollup).
- **`Trending` render kind gained a leading galaxy icon** (the W3/W4 extension
  the renderer header anticipated): optional `icon` row field → FontAwesome
  helper (`fas fa-user-secret`) + `.misp-trending-icon` token CSS. The value
  arm (CVEs) carries none; nothing else changed for it.
- **Added to user 1's test dashboard** (standing preference): appended
  `TrendingWidget` (`w_12`, `dimension=threat-actor`, `time_window=-1` for the
  stale corpus) below the existing 11 tiles (layout untouched; backup
  `/tmp/dash_backup.json`). Smoke-tested live.

## ⏸ PARKED — attack heatmap (AD-W5 / AttackWidget), user concern (2026-06-02)
**The user is NOT happy with the rework on the attack heatmap and wants to
address it in the future.** Consequence for this track: **Phase B7 (AD-W5 —
wire `AttackWidget`'s `time_window`, AD-12) is PARKED** — do **not** pick it up
in the normal build order. The heatmap needs a redesign discussion first; the
specific dissatisfaction wasn't detailed, so **capture what the user wants
changed before touching `AttackWidget`** (and re-confirm whether AD-12's
in-place `time_window` wiring is even still the plan). The build order skips
W5 for now: after W3/W4, go to **W8** (overlap, unblocked). Revisit W5/B7 only
when the user reopens the heatmap.
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
  "what's rising" engine, now with **TWO dimensions**:
  - `vulnerability` (W2, **value arm**): `countVulnerability` (ACL-scoped,
    `Attribute.timestamp`-windowed) + `labelsVulnerability` (verbatim label +
    cveurl drilldown).
  - `threat-actor` (W3, **tag arm — THE union-distinct count now EXISTS**):
    `threatActorTagIds()` (the `is_galaxy` + `threat-actor="%` tag set);
    `countThreatActor()` = ACL-correct `COUNT(DISTINCT event_id)` over
    **EventTag ∪ AttributeTag**, built parametrically — gather in-window
    `(tag_id,event_id)` pairs from both arms → `aclVisibleEventIds()` →
    per-tag event **set** (doubly-tagged event counts once). Row key = tag_id.
    `labelsThreatActor()` bulk-resolves cluster value+icon+synonyms (2 queries),
    dedupes the **non-1:1** tag→cluster mapping via `clusterOutranks()` (default
    desc, version desc, id desc), links `/galaxy_clusters/view/<id>` (relative
    → DD-03 admits, no relaxation). Orphan tags fall back to the bare name.
  - **W4 (B6) must REUSE `countThreatActor`'s shape** — it's the same
    union-distinct mechanism, just a different tag set (attack-pattern) rolled
    up to the parent technique. Parametrise rather than copy.
- **`Trending` render kind — leading galaxy icon** (W3 extension): optional
  `icon` row field (a FA icon NAME) → `Trending.ctp` renders it via the
  `FontAwesome` helper (`getClass()`), styled by `.misp-trending-icon` (token
  CSS in `dashboard.default.css`). Absent for the value arm. W4 reuses it.
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

## NEXT BUILD — Phase B6 = AD-W4 Trending ATT&CK Techniques (PRD §5 / AD-11)
**Mostly a REUSE of W3** — a third `dimension` on the W1 engine (reuses
`Trending` + the galaxy icon, no glyph), whose count is W3's union-distinct
count pointed at a different tag set. NOT a new class/render kind. Read AD-11
(PRD §6) + PRD §5 AD-W4 first.
- **Dimension config:** `mitre-attack-pattern` (Enterprise) cluster tag set =
  `tags WHERE is_galaxy=1 AND name LIKE 'misp-galaxy:mitre-attack-pattern="%'`
  (confirm the exact namespace on the box — there are several attack galaxies;
  AD-11 scopes to Enterprise attack-pattern, mirroring W3's native-galaxy-only).
- **The twist vs W3 — roll up sub-techniques to the parent technique** (AD-11
  Fork): `external_id` `T1566.001` → parent `T1566` (strip `.NNN`). So the
  trended key is the **parent technique**, and several cluster tags can map to
  one trended row. Cleanest path: resolve each attack tag_id → its cluster's
  `external_id` (a `galaxy_elements` `key='external_id'`, like the synonyms
  query), derive the parent id, then **group the per-tag distinct-event sets by
  parent** before counting — i.e. reuse `countThreatActor`'s pair-gather +
  ACL + set logic, but key the final event-set map by parent-technique instead
  of raw tag_id. Parametrise `countThreatActor` (e.g. an optional tag→bucket
  map) rather than copy-pasting it.
- **Label resolver:** parent cluster `value` + `external_id` + `Galaxy.icon`
  (bulk; same shape as `labelsThreatActor`); link =
  `/galaxy_clusters/view/<parent_cluster_id>`. Watch the same **non-1:1
  tag→cluster** dedup (`clusterOutranks`) W3 hit.
- **Verify** it reads DISTINCT from the W5 ATT&CK heatmap on the board (AD-11).
  Box clock caveat below ⇒ verify with `time_window=-1`.

## Also still unblocked
- **W8 (AD-W8 overlap-with-my-org, Phase B8)** — depends on `EventCards`
  (exists). `OverlapWithMyOrgWidget` with `render='EventCards'` + overlap
  badge; PRD §5 / AD-13. **The next widget after W4, since W5/B7 is parked**
  (above) — or pull it forward if W4's parent-rollup needs a design pass.

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
  granted so far: the **B4 DD-03 relaxation** (user chose it over an internal
  drilldown). B7 (AttackWidget `time_window`, AD-12) was signed off **but is
  now PARKED** (heatmap concern above) — that sign-off is void until the
  redesign is settled. B5 is additive (new dimension hooks on TrendingWidget —
  same as B4's link builder, this track's own class; flag it but low-risk).
- **Add built/touched widgets to user 1's test dashboard**
  ([[feedback_add_touched_widgets_to_dashboard]]): standing request — after
  building/touching a widget, append it to user 1's `dashboard` UserSetting if
  not present (dedupe by class; back up first; never replace the layout), then
  smoke-test it. Recipe + storage shape in that memory.
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
1. Read this + `analyst-dashboard-prd.md` §5 **AD-W4** (+ §6 AD-11) +
   `analyst-dashboard-progress.md` (**Phase B6** backlog). W1+W2+W3+W6+W7 BUILT.
2. **Start at Phase B6 = AD-W4 Trending ATT&CK Techniques** — a third
   `dimension` on `TrendingWidget` (reuses `Trending` + the W3 galaxy icon, no
   glyph). It's **W3's count machinery re-pointed**: `countThreatActor`'s
   gather-pairs → `aclVisibleEventIds()` → per-key event-set logic, but over the
   `mitre-attack-pattern` tag set and with the final event-set map **keyed by
   parent technique** (sub-technique `T1566.001` → `T1566`, AD-11). Parametrise
   `countThreatActor` (e.g. a tag→bucket map) rather than copy it. Label
   resolver mirrors `labelsThreatActor` (value + `external_id` + icon, bulk;
   same `clusterOutranks` dedup); link `/galaxy_clusters/view/<parent_id>`.
3. **Cross-cutting:** flag the TrendingWidget edit (additive, this track's own
   class). Verify via REST + web-UI HTML (`<a>` vs `<div>` rows), `-1` window,
   flush the per-org cache. Confirm W4 reads DISTINCT from the W5 heatmap.
   W8 (overlap) still unblocked (EventCards exists).
4. **Confirm with the user before large work** (they may recompose the analyst
   `template.json` themselves — their job).
