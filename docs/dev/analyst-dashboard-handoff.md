# Analyst Dashboard — Session handoff (2026-06-02 — BUILD: Phase B6 (W4 trending ATT&CK techniques) COMPLETE + verified; next build unit = Phase B8 / AD-W8 overlap-with-my-org — W5/B7 is PARKED, so W8 is next; reuses the W6 EventCards render)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail (AD-W1..W8); §6 = **AD-NN** decision log (AD-01..13).
- `analyst-dashboard-progress.md` — the task tracker. Spec status (all
  DECIDED), the **B1–B8 build backlog**, and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (BUILD)
- **Built W4 (trending ATT&CK techniques) — W3's count machinery re-pointed +
  sub-technique→parent roll-up; verified live.** Build order: W1 ✅ → W7 ✅ →
  W6 ✅ → W2 ✅ → W3 ✅ → **W4 ✅** → **W5 ⏸ PARKED** (user reworking the
  heatmap — see below) → **W8 (B8) next** (overlap; reuses W6 EventCards) →
  (W9 deferred).
  - 1 signed commit so far this session: `410b96d4a` (B6 code — dimension +
    shared counter refactor + parent roll-up + label resolver); a verify +
    tracker/handoff commit follows. Earlier B1–B5 detail lives in `git log` +
    the progress tracker's done-notes (trimmed from here).
- **`TrendingWidget` now has THREE dimensions:** `vulnerability` (W2, value
  arm), `threat-actor` (W3, tag arm) and `mitre-attack-pattern` (W4, tag arm,
  parent-technique roll-up). W3's count was **parametrised** into a shared
  `countDistinctEventsByTag($user,$s,$e,$tagIds,$bucketMap=null)` — the
  ACL-correct EventTag ∪ AttributeTag union-distinct counter — keyed by tag_id
  (W3, `$bucketMap=null`) or by an arbitrary bucket (W4: a tag_id → parent
  technique map, so sub-techniques fold into one parent row). No copy-paste.
- **⚠ W4 build deviation from AD-11's *suggested* mechanism** (which AD-11
  explicitly left "open at build"): the technique id is parsed from the tag /
  cluster **NAME** (`… - T1566.001` → strip `.NNN` → `T1566`), **NOT** the
  `galaxy_elements` `external_id` element — that element is unreliable on real
  data (carries legacy `APP-NN` Mobile ids for mobile-derived techniques whose
  name still bears the canonical `T<id>`; rows are also duplicated). 440/452
  tags parse a `T<id>`; the 12 that don't are 5 tactic `TA00NN` + 7 deprecated
  un-suffixed names — not techniques, correctly dropped. DECIDED spec (scope /
  parent roll-up / reuse-W3-count) is unchanged — only the *how-to-get-the-id*
  detail. Verified against a raw-SQL ground truth (T1190=696, T1095=580,
  T1566=101 ← the roll-up).
- **`Trending` galaxy-icon slot reused** (no change): W4 sets `icon='map'`
  (the mitre-attack-pattern `Galaxy.icon`) → `fas fa-map`. No new render kind,
  no glyph.
- **Added to user 1's test dashboard** (standing preference): appended
  `TrendingWidget` (`w_14`, `dimension=mitre-attack-pattern`, `time_window=-1`
  for the stale corpus) at the bottom (layout untouched; backup
  `/tmp/dash_backup.json`). Read-back verified — 14 tiles, all 3 Trending
  dimensions present.

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

## What now exists in the tree (reuse it; don't re-derive)
- **`TrendingWidget`** + **`Trending` render kind** (W1). The parametrised
  "what's rising" engine, now with **THREE dimensions**:
  - `vulnerability` (W2, **value arm**): `countVulnerability` (ACL-scoped,
    `Attribute.timestamp`-windowed) + `labelsVulnerability` (verbatim label +
    cveurl drilldown).
  - `threat-actor` (W3, **tag arm**) + `mitre-attack-pattern` (W4, **tag arm,
    parent roll-up**) both run on the **shared** ACL-correct union-distinct
    counter: `countDistinctEventsByTag($user,$start,$end,$tagIds,$bucketMap=null)`
    — gather in-window `(tag_id,event_id)` pairs from EventTag ∪ AttributeTag →
    `aclVisibleEventIds()` → per-**bucket** event **set** (any event reached
    more than once counts once). `$bucketMap=null` ⇒ bucket = tag_id (W3);
    a `tag_id→bucket` map ⇒ W4's parent roll-up. `countThreatActor` /
    `countAttackPattern` are thin delegations.
    - W3 tag set = `threatActorTagIds()`; label = `labelsThreatActor()`
      (cluster value+icon+synonyms, `clusterOutranks` dedup of the non-1:1
      tag→cluster, link `/galaxy_clusters/view/<id>`).
    - W4 tag set + bucket map = `attackPatternTagBuckets()` (the
      `mitre-attack-pattern="%` tag set; `tag_id → parent technique id`).
      **The technique id is parsed from the tag NAME** (`techniqueIdFromName()`
      → `parentTechniqueId()` strips `.NNN`), NOT `galaxy_elements.external_id`
      (unreliable — legacy `APP-NN` ids; see TL;DR ⚠). Label =
      `labelsAttackPattern()` → parent cluster matched by
      `galaxy_clusters.tag_name LIKE '% - T<id>"'` (resilient to no `tags` row;
      only ~⅓ of clusters have one), `attackLabel()` formats `Name (Txxxx)`,
      icon=`map`, link `/galaxy_clusters/view/<parent_cluster_id>`, same
      `clusterOutranks` dedup. **If a future galaxy dimension needs the same
      union-distinct count, call `countDistinctEventsByTag` — don't re-derive.**
- **`Trending` render kind — leading galaxy icon** (W3/W4): optional
  `icon` row field (a FA icon NAME) → `Trending.ctp` renders it via the
  `FontAwesome` helper (`getClass()`), styled by `.misp-trending-icon` (token
  CSS in `dashboard.default.css`). Absent for the value arm. W3=`user-secret`,
  W4=`map`.
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

## NEXT BUILD — Phase B8 = AD-W8 Overlap-with-my-org (PRD §5 / AD-13)
**A NEW widget that REUSES the W6 `EventCards` render kind** (no new render
kind, no glyph). W5/B7 is PARKED (heatmap concern above), so W8 is next. Read
AD-13 (PRD §6) + PRD §5 AD-W8 + the `analyst-dashboard-progress.md` Phase B8
backlog first.
- **`OverlapWithMyOrgWidget`** (`render='EventCards'`): candidate set =
  ACL-visible window events (`Event.timestamp` in window), capped top-N recent
  (`log()` if capped — no silent truncation).
- **Overlap test (the crux):** for each candidate,
  `Correlation->getRelatedEventIds($user, $id, $sgids)` (ACL-correct +
  engine-agnostic — reuses the OnDemand path for free); keep the candidate iff
  a related event's `orgc_id` = my org. Overlap strength = # of my-org events
  it correlates to; rank desc then recency.
- **Render:** reuse `EventCards` + an "overlaps N of your events" badge.
  Per-org cache (AD-04 — the widget already has the `org` cache scope pattern
  to copy from `TrendingWidget`). Window-anchored build — no `org_id` scan, no
  schema change (AD-13).
- **Verify** across correlation engines (Default at minimum). Box clock caveat
  below ⇒ verify with `time_window=-1`.
- If W8 stalls, the only remaining item is **W9** (DEFERRED — look-and-feel
  reskin of `RecentSightingsWidget`), or reopen **W5/B7** once the user details
  the heatmap rework.

## Verifying a widget (recipe in memory)
See [[reference-dashboard-widget-render-verification]]: `renderWidget` is
CSRF-unlocked → REST+APIkey returns the JSON `data` (validates the handler);
web-UI POST + session cookie returns the real `.ctp` HTML; snap-chromium
screenshot needs inlined CSS in `$HOME`. **Screenshot only matters for a NEW
render kind** (W6 needed one; W2/W3/W4 reuse `Trending` so the HTML grep for
`<a>` vs `<div>` rows + the icon/`href` is the proof). **Session cookie
expires** — re-mint `/tmp/cj_stat.txt` via [[reference-misp-login-dance]] if a
web-UI render 302s (the full `_Token` set is required); it stayed valid through
B6. **Clock caveat:** box clock is
2026-06-02; newest event ~2026-05-29 but the galaxy-tagged / vulnerability
corpus is stale (newest *vulnerability* attr ~372 d old; newest attack-tagged
event ~186 d old), so verify trending with `time_window=-1` (all-time); a
`1460d` split window exercises momentum across two non-empty halves. **Flush
the per-org cache between checks:**
`redis-cli -n 13 --scan --pattern 'misp:trending_cache:*' | xargs -r redis-cli -n 13 del`
(TrendingWidget caches output per-org under `misp:trending_cache:` — a stale
entry hides your change; NewDataStats uses `misp:dashboard:*` instead).

## Conventions (carry)
- **AD-NN** decision numbering, cross-linked to parent `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + new
  render kinds = pure additions. Existing-code touches need **sign-off** —
  granted so far: the **B4 DD-03 relaxation** (user chose it over an internal
  drilldown). B7 (AttackWidget `time_window`, AD-12) was signed off **but is
  now PARKED** (heatmap concern above) — that sign-off is void until the
  redesign is settled. B5/B6 shipped additively (new dimension hooks + the
  shared `countDistinctEventsByTag` refactor of this track's own
  `countThreatActor` — all this track's own class, no external touch); **B8 is
  the same posture** (a new widget reusing `EventCards` + the `org` cache
  scope).
- **Add built/touched widgets to user 1's test dashboard**
  ([[feedback_add_touched_widgets_to_dashboard]]): standing request — after
  building/touching a widget, append it to user 1's `dashboard` UserSetting if
  not present (back up first; never replace the layout), then smoke-test it.
  **Nuance for `TrendingWidget`:** dedupe by **(class + dimension)**, not class
  alone — multiple dimensions share the one class, so a vulnerability tile must
  not block adding a threat-actor tile (B5 added `w_12` alongside `w_9`). Recipe
  + storage shape in that memory.
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
1. Read this + `analyst-dashboard-prd.md` §5 **AD-W8** (+ §6 AD-13) +
   `analyst-dashboard-progress.md` (**Phase B8** backlog).
   W1+W2+W3+W4+W6+W7 BUILT; W5/B7 PARKED; W9 DEFERRED.
2. **Start at Phase B8 = AD-W8 Overlap-with-my-org** — a NEW
   `OverlapWithMyOrgWidget` (`render='EventCards'`, reuses the W6 render kind +
   the `org` cache scope; no new render kind / glyph). Candidate set =
   ACL-visible in-window events (top-N recent, `log()` if capped); for each,
   `Correlation->getRelatedEventIds($user,$id,$sgids)` and keep iff a related
   event's `orgc_id` = my org; overlap strength = # of my-org events it
   correlates to (rank desc, then recency). Render = `EventCards` + an
   "overlaps N of your events" badge. AD-13: correlation-based (ACL-correct,
   engine-agnostic), window-anchored, no schema change.
3. **Cross-cutting:** additive posture (a new class — no existing-code touch).
   Verify via REST + web-UI HTML through the real render path, `-1` window
   (stale corpus), flush `misp:trending_cache:*`/the widget's own cache. **A
   NEW handler payload key must also be added to the `EventCards.ctp` shim if
   the badge needs it** ([[project_dashboard_ctp_payload_passthrough]]) — the
   overlap badge is the likely new key; wire it through the .ctp or it never
   reaches the JS. Verify across correlation engines (Default at least).
4. **Confirm with the user before large work** (they may recompose the analyst
   `template.json` themselves — their job).

> **Last session (B6 / W4) note for the picker-upper:** W4's roll-up parses the
> technique id from the tag **name**, not `galaxy_elements.external_id` (proven
> unreliable — legacy `APP-NN` ids). If you extend the attack dimension, reuse
> `techniqueIdFromName()` / `parentTechniqueId()` and the shared
> `countDistinctEventsByTag()`; don't reach for `external_id`.
