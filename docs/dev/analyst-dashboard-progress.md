# Analyst Dashboard — Implementation Progress Tracker

**Source of truth for what's spec'd, what's built, what's next.** A fresh
session picks up the work by reading [`analyst-dashboard-prd.md`](analyst-dashboard-prd.md)
for the spec (roster §3, per-widget detail §5, **AD-NN** decision log §6) and
**this file** for state. This is the analyst-track sibling of
[`dashboard-progress.md`](dashboard-progress.md); the two tracks share the
`dashboards` branch and ship together (see [`analyst-dashboard-handoff.md`](analyst-dashboard-handoff.md)).

## How to use this file

- This track works in two stages: **spec** (discuss → decide → record an
  AD-NN; widget row reaches `DECIDED` in PRD §3) then **build** (the task
  checklist below). We are currently **spec-first**: speccing widgets ahead
  of writing any code, by the user's choice.
- Tasks are checked off **one at a time** as they complete — no batching, no
  pre-checking. **One task = one commit** (see `feedback_commit_per_task`).
  Stage only the files the task touched plus this tracker — never `git add -A`.
  Commit format:

  ```
  new: [analyst-dashboard] <short imperative summary>

  Closes <Wn build task / spec task> as it appears in this file.
  ```

  `new:` additions, `chg:` changes/refactors, `fix:` bug fixes (CLAUDE.md).
- Build phases run **strictly sequentially** (`feedback_sequential_implementation`);
  research/lookups may parallelise, code writing never.
- On task close, append a **Done note** (1–3 lines: what was done, paths
  touched, any surprise). Done note + commit hash = the audit trail.
- Blocked task → mark `[~]` + a `Blocked by:` line; don't check or commit it.
- **Additive-only** (`feedback_additive_only_posture`): new widgets + the one
  new render kind = pure additions; touching an existing widget needs sign-off.

## Live test instance

`http://localhost:5007/dashboards` — admin user 1 `admin@admin.test` /
`Password12345`, Overmind theme. DB `mysql -u misp -pPassword1234 misp`;
Redis `redis-cli -n 13` (data), db0 sessions. Full recipe in the handoff.

## Status legend

- `[ ]` not started
- `[~]` in progress / blocked (one at a time max)
- `[x]` done (Done note + commit hash follows)

## Spec status (mirrors PRD §3 roster)

| ID | Widget | Spec | Build |
|----|--------|------|-------|
| AD-W1 | Trending engine (parametrised) | `DECIDED` (AD-01..04) | `[ ]` not started — **first build unit** |
| AD-W2 | Trending CVEs (dim of W1) | `DISCUSSING` | — |
| AD-W3 | Trending threat actors (dim of W1) | `DISCUSSING` | — |
| AD-W4 | Trending attack techniques (dim of W1) | `DISCUSSING` | — |
| AD-W5 | ATT&CK matrix heatmap (existing) | `DISCUSSING` | — |
| AD-W6 | Event-stream rework | `DISCUSSING` | — **next spec target** |
| AD-W7 | New-data stats (StatGrid + deltas) | `DECIDED` (AD-05..07) | `[ ]` not started |
| AD-W8 | Overlap-with-my-org | `DISCUSSING` | — |
| AD-W9 | Sightings rework | `DEFERRED` | — |

## Spec log (this track's planning tasks)

- [x] **Track kick-off** — mini-PRD + handoff created; AD-W1 fully decided
  (AD-01..04). *(commit `e0453e3e0`)*
- [x] **AD-W7 spec → DECIDED** — anchor (AD-05), aggregate-count ACL
  relaxation (AD-06), full W7 spec (AD-07). Resolved AD-W1's deferred window
  anchor en route. Split this progress tracker out.
- [ ] **AD-W6 spec** — event-stream rework: grouped-digest vs ticker; detailed
  cards; inline filter/scope/exclude; near-live refresh. (Next spec target.)

## Build backlog (ordered by confirmed build order)

Build order: **W1 → W7 → W6 → (W2/W3/W4) → W5 → W8 → W9**. Engine first
(W2/W3/W4 are its dimensions); stats next (cheapest standalone win); then
event-stream; dimensions; heatmap wiring; the hard/soft pair last. No build
task starts until the user moves the track out of spec-first mode.

### Phase B1 — AD-W1 Trending engine (on deck; fully DECIDED)

- [ ] New render kind **`Trending`** — `Trending.ctp` ranked-row list (label ·
  inline volume bar · count · `▲/▼` delta badge). Token-driven CSS, no inline
  styles (mirror `StatGrid.ctp`).
- [ ] Glyph for `Trending` in `render-thumbs.mjs` (**CLAUDE.md rule** — new
  render kind ⇒ glyph): `thumbTrending()` + REGISTRY entry.
- [ ] `TrendingWidget` class — `dimension` config + per-dimension hooks
  (counting strategy, label resolver, drill-down link builder).
- [ ] Counting (AD-02): `COUNT(DISTINCT event_id)` over event-tag ∪
  attribute-tag ∪ attribute-value, off `EventTag`/`AttributeTag`/`Attribute`
  (no event hydration; `AttributeTag.event_id` confirmed present).
- [ ] Momentum (AD-03): floored-% delta vs prior equal window; configurable
  min current-window count before "rising" is flagged.
- [ ] Cache/ACL (AD-04): per-org `cache_scope`, site-admin no-ACL bucket,
  lazy-load on render, ~15–30 min/org, source = all events incl. unpublished.
- [ ] Visual verification on the live instance (real render path, not a
  hand-built payload — see `project_dashboard_ctp_payload_passthrough`).

### Phase B2 — AD-W7 New-data stats (DECIDED; build-deferred)

- [ ] `NewDataStatsWidget` (`render = 'StatGrid'`) — 4 metrics, `value` =
  window count, `change` = delta vs prior equal window (AD-07).
- [ ] Metrics 1–2 global counts (no ACL, AD-06); metric 3 targeting waterfall
  (config → org meta → org-name ccTLD → N/A); metric 4 `orgc_id`+`published`.
- [ ] ccTLD→country resolver from `country.json` (`meta.tld`/`ISO`).
- [ ] Cache split (AD-06): global / `(country,sector)` / `orgc_id` keys.
- [ ] Visual verification on the live instance.

*(Phases B3+ — W6, W2/W3/W4, W5, W8 — broken down when each reaches `DECIDED`
and the track enters build mode.)*

## Discovered work

*(none yet — file here with introduces-what / why / where-it-goes notes.)*
