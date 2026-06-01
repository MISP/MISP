# Analyst Dashboard — Session handoff (2026-05-31..06-01 — SPEC PHASE COMPLETE: W1–W8 all DECIDED (AD-01..13), W9 deferred; ready for build, first unit = W1)

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge
is `dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track
builds the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD (deviation/companion to
  `dashboard-prd.md`). §3 = 9-widget roster (status per widget); §5 =
  per-widget detail; §6 = **AD-NN** decision log.
- `analyst-dashboard-progress.md` — the task tracker (split out 2026-05-31;
  mirrors the parent PRD+progress split). Spec status + build backlog.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — this session (planning; no code; spec-first by user's choice)
- **Specced the ENTIRE roster this session: W2–W8 all reached DECIDED
  (AD-05..13), joining the pre-existing W1 (AD-01..04); W9 stays deferred.**
  Stayed in spec mode throughout (user chose to spec ahead of building).
  Decisions in order below.
- **AD-05** window anchor = `Event.timestamp` track-wide (resolves AD-W1's
  deferred anchor; `publish_timestamp` rejected — tracks sync-propagation to
  this instance, not newness). **AD-06** aggregate count metrics may skip ACL
  (global counts OK; refines AD-04). **AD-07** = the W7 spec.
- **AD-08** = the W6 spec: flat detailed cards, read-only (filters via the
  existing toolbar bulk-edit), additive `EventStreamCardsWidget extends
  EventStreamWidget` + new `EventCards` render kind.
- **AD-09** = the W2 spec (first W1 dimension): all `vulnerability` IDs
  (CVE/GCVE/GHSA), distinct-event count, cveurl link-out. **Big clarification:
  trending value-rankings MUST be ACL-scoped** (AD-04 per-org) — AD-06's
  skip-ACL is only for *scale*-counts (W7), never value-rankings.
- **AD-10** = the W3 spec (second W1 dimension): `threat-actor` galaxy only
  (sidesteps cross-galaxy identity merge); distinct-event count over EventTag ∪
  AttributeTag, ACL-scoped; per-cluster resolved label (value+icon+synonyms),
  link to `/galaxy_clusters/view/<id>`. **Gotcha:** `AttributeTag::countForTags`
  skips ACL + counts occurrences → unusable as-is; needs custom ACL-correct
  union-distinct count.
- **AD-11** = the W4 spec (third W1 dimension): `mitre-attack-pattern`
  (Enterprise) only; reuses W3's ACL-correct count with the tag-id set grouped
  by **parent technique** (sub-techniques roll up: T1566.001 → T1566); label =
  parent value + external_id + icon; DISTINCT from W5 (ranked list+momentum vs
  spatial matrix). **The W2/W3/W4 trending dimensions are now all DECIDED.**
- **AD-12** = the W5 spec: wire the existing `AttackWidget` to the global
  `time_window` canonical **in-place** (map it into the restSearch 'attack'
  timestamp filter; manual filters preserved). ⚠ **First additive-only touch
  of existing code — user signed off** (small schema/config change, not a
  rewrite). Confirms global window = the `time_window` canonical → W1 & W7
  should declare it too.
- **AD-13** = the W8 spec (the "affects me" payoff): correlation-based overlap
  — reuse `Correlation->getRelatedEventIds` (ACL-correct + engine-agnostic),
  reference set = events my org **created** (`orgc_id`). Build is **window-
  anchored** (per-event related lookups over the bounded window set; NO org_id
  scan, no schema change — `default_correlations` has no org_id/timestamp index
  and `org_id`≠creator). Render = reuse W6 `EventCards` + "overlaps N of your
  events" badge.
- **Split out `analyst-dashboard-progress.md`** (meta-Q2 resolved).
- **SPEC PHASE COMPLETE.** Build order: **W1 → W7 → W6 → (W2/W3/W4) → W5 → W8 →
  W9**. **All of W1–W8 are DECIDED (AD-01..13); W9 stays DEFERRED**
  (look-and-feel-only reskin of `RecentSightingsWidget`, after the render kinds
  land). The track is **ready for build — first unit = W1** (engine-first).

## Why this track (three analyst jobs)
The analyst board today is 5 v1-era widgets (TrendingAttributes/Tags, two
WorldMaps, RecentSightings) — all aggregate trends/maps, **no "what changed
since last login" surface**. This track delivers three jobs; every widget
must serve one:
1. **What's new** — event-stream rework (W6) + new-data stats (W7).
2. **What's rising** — parametrised trending engine (W1) + its dimensions
   (CVEs W2, threat actors W3, attack techniques W4) + ATT&CK heatmap (W5).
3. **What affects me** — overlap-with-my-org (W8); targeting-my-country/sector
   (a W7 metric).

**Recomposing the analyst `template.json` is the USER's job** — we build /
improve widgets; the user arranges the board.

## AD-W1 — the trending engine (DECIDED; reuse these facts verbatim)
- **One parametrised `Trending` widget** (AD-01), not N near-identical
  classes. `dimension` config; per-dimension hooks: counting strategy, label
  resolver, drill-down link builder. Dimensions: galaxy namespaces
  (threat-actor, attack-pattern, **+ free** malware/tool/sector), attribute
  types (CVE/vulnerability).
- **New render kind = ranked-row list** (AD-01): per row = label · inline
  volume bar · count · `▲/▼` delta badge (sparkline = later polish). **NOT
  BarChart** (can't carry the per-row badge). **Must add a glyph to
  `render-thumbs.mjs`** (CLAUDE.md rule).
- **Counting = distinct events containing the value, each event = 1** (AD-02).
  Union event-tag ∪ attribute/object-tag ∪ attribute-value →
  `COUNT(DISTINCT event_id)`. Off `EventTag`/`AttributeTag`/`Attribute`
  (connector tables; no event hydration). `AttributeTag.event_id` exists → no
  join needed. Resists per-org reporting process-noise (scanner dumping 10k
  identical CVEs = 1).
- **Momentum = floored-% delta vs prior equal window** (AD-03): volume-ranked
  list + per-row delta badge. Item must clear a configurable min
  current-window count before "rising" is flagged. **No spike detection**
  (cost; deferred).
- **Cache/ACL = per-org, lazy-loaded, all data** (AD-04): org = MISP's ACL
  atom → `cache_scope` by org (same-org users share visibility); site-admins =
  separate no-ACL bucket; NOT background-precomputed (cross-org leakage); NOT
  per-user; source = all events incl. unpublished; trending caches ~15–30
  min/org.

## Track-wide principle (carry to every widget)
**ACL-scoped aggregate widgets cache PER-ORG** (AD-04 generalises): never a
single shared blob, never per-user (org is the atom), site-admins bucketed
separately, lazy-loaded not background-precomputed. Freshness per-widget
(trending 15–30 min/org; event-stream near-live).

## AD-W7 — new-data stats (DECIDED this session; full spec PRD §5)
- **4 `StatGrid` metrics**, each `value` = current-window count, `change` =
  delta vs the immediately-preceding equal window (AD-03 baseline):
  1. new events (`Event.timestamp` in window, **global, no ACL**);
  2. new attributes (`Attribute.timestamp` in window, `deleted=0`, global);
  3. events targeting my org's country/sector (distinct events with
     `misp-galaxy:country=` ∪ `misp-galaxy:sector=`, via the **waterfall**);
  4. new events published by my org (`orgc_id`=me, `published=1`,
     `publish_timestamp` in window — the one place publish_timestamp is OK,
     since own-org events weren't sync-imported).
- **Targeting waterfall** (country & sector resolved independently, first hit):
  explicit widget config → org `nationality`/`sector` (case-folded to galaxy
  cluster `value`) → org **name's ccTLD** (country only; `post.lu`→`.lu`) →
  N/A. ccTLD→country is self-contained in `country.json` (`meta.tld`/`ISO`,
  252 clusters). **Widget option to set country/sector overrides everything.**
- **Cache (AD-06):** metrics 1–2 global-cached, metric 3 by `(country,sector)`,
  metric 4 by `orgc_id`; nothing ACL-filtered ⇒ site-admin bucket moot.

## Open per-widget circle-backs (carry — first-pass answers in PRD §5)
- **W2 (vulnerabilities): DECIDED (AD-09)** — see PRD §5. Grilled: plain
  distinct-event count on `vulnerability` values is right (CVEs aren't tags),
  ACL-scoped. All CVE/GCVE/GHSA. cveurl default corrected to
  `https://vulnerability.circl.lu/vuln/`, format `{cveurl}{value}`.
- **W3 (threat actors): DECIDED (AD-10)** — see PRD §5. `threat-actor` galaxy
  only; EventTag ∪ AttributeTag distinct-event count, ACL-scoped; per-cluster
  label (value+icon+synonyms); `/galaxy_clusters/view/<id>`.
- **W4 (techniques): DECIDED (AD-11)** — see PRD §5. `mitre-attack-pattern`
  only; parent-technique roll-up; reuses W3's ACL count; distinct from W5.
- **W5 (ATT&CK heatmap): DECIDED (AD-12)** — see PRD §5. Wire `time_window`
  canonical into AttackWidget in-place (additive sign-off granted); restSearch
  'attack' timestamp filter; manual filters preserved.
- **W6 (event stream): DECIDED (AD-08)** — see PRD §5. Flat read-only cards,
  additive subclass + `EventCards` render; filters via the existing toolbar
  bulk-edit; near-live, no cache (per-user ACL'd `fetchEvent`).
- **W8 (overlap-with-my-org): DECIDED (AD-13)** — see PRD §5. Correlation-based
  (reuse `getRelatedEventIds`); my-org-created reference set; window-anchored
  build; render = W6 EventCards + overlap badge.
- **W9 (sightings):** likely **look-and-feel rework only** — sighting engine
  is slow and unused by some communities, so don't over-invest in a live "are
  my IOCs sighted?" engine.

## Conventions (carry)
- **AD-NN** decision numbering (this track), cross-linked to parent `DD-NN`.
- **Per-org cache** for ACL aggregates (above).
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + one
  new render kind = pure additions; touching existing widgets needs sign-off.
- **Sequential** ([[feedback_sequential_implementation]]): one widget at a
  time.
- **Commit per task; never `git add -A`; explicit `git add` +
  `git status --short`; sign (`%G?`=U).**
- **chgrp www-data** every edited web-served/app file incl. docs.
- New render kind ⇒ glyph in `render-thumbs.mjs` (CLAUDE.md).
- User wants **rigorous pushback + genuine forks via AskUserQuestion**, and to
  **re-verify rather than defend** when a premise is questioned.

## Live test instance (shared with the main track)
- `http://localhost:5007/dashboards` (302 w/o session, 200 with). Admin
  user 1 `admin@admin.test` / `Password12345`, Overmind theme. Cookie jar
  `/tmp/cj_stat.txt` (re-mint via [[reference-misp-login-dance]] if it 302s).
- DB `mysql -u misp -pPassword1234 misp`; Redis `redis-cli -n 13` (data),
  db0 sessions. Branch: `dashboards` — **no separate track branch** (user,
  2026-05-31: building both tracks solo; shipping dashboard v2 + the analyst
  widgets/defaults together in the next release).

## Quick-start for next session
1. Read this + `analyst-dashboard-prd.md` (§3 roster, §5 AD-W1..W8, §6
   AD-01..13) + `analyst-dashboard-progress.md` (spec status + the B1–B8 build
   backlog).
2. **SPEC PHASE IS DONE** — W1–W8 all DECIDED; W9 deferred. **The work now is
   BUILD**, sequentially, starting at **Phase B1 (the W1 trending engine)**:
   the new `Trending` render kind + `Trending.ctp` + glyph in
   `render-thumbs.mjs` (CLAUDE.md), then `TrendingWidget` (dimension config +
   counting/momentum/per-org-ACL-cache). Build order: **W1 → W7 → W6 →
   W2/W3/W4 → W5 → W8** (then W9 if revisited). One task = one commit;
   chgrp www-data; sign; verify on the live instance via the real render path.
3. **Cross-cutting reminders for build:** trending value-rankings are
   ACL-scoped per-org (AD-09), NOT global like W7's scale-counts (AD-06);
   `Event.timestamp` is the window anchor (AD-05); the global window IS the
   `time_window` canonical (declare it on W1/W7 per AD-12); `AttributeTag::
   countForTags` skips ACL — don't reuse it (AD-10). New render kinds (Trending,
   EventCards) each need a glyph. W5 touches existing code (signed off, AD-12);
   everything else is additive.
4. **Confirm with the user before starting build** (they may want to recompose
   the analyst `template.json` themselves first — that's their job).
