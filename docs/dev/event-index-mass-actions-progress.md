# Event Index Mass Tag / Mass Cluster — Progress Tracker

PRD: `docs/dev/event-index-mass-actions-prd.md` (canonical copy of
`/home/iglocska/prds/misp_event_index_mass_tag_cluster.md`, signed off
2026-06-12). Branch: `feature-event-index-mass-actions` off `2.5`.

Working model: strictly sequential tasks, one commit per task, tick one
box at a time. A fresh session must be able to resume from this file
alone — keep the "state / next step" section honest.

## Tasks (PRD §10)

- [x] **T1** Regression-guard integration test for single-event
      `events/addTag` (PRD §9.1). `tests/testlive_event_addtag.py`,
      16 tests, all green against unmodified `addTag` (2026-06-12).
      Covers: single tag id (body+URL), JSON tag list, tag name,
      `collection_N`, `local:1`, duplicate (skip, incl. cross-local),
      local_only constraint, unpublish semantics, UUID/body event refs,
      no-permission (foreign-org tagger, global+local).
      Commit: `chg: [test] coverage for events/addTag single-event contract`
- [x] **T2** Backend: `events/addTag` `'selected'` support incl. D6
      global→local downgrade + `add_tag.ctp` `event_ids` field (§6.1).
      Done 2026-06-12: T1 suite still 16/16; bulk smoke verified
      attached/downgraded/skipped/failed + up-front local_only rejection
      + junk-ID handling + GET form field.
      Commit: `new: [event] mass tagging of selected events via addTag
      selected pattern`
- [x] **T3** Backend: `attachMultipleClusters` `event_ids` branch +
      skip-and-count + D6 downgrade + form field (§6.3). Done
      2026-06-12 via new private `__attachClustersToSelectedEvents()`
      (attribute/single-target branch byte-identical, throws preserved
      per D4). Smoke: attached/downgraded/skipped/failed counts,
      up-front local_only-galaxy rejection, junk IDs, both forms, and
      single-event + selected/attribute non-regression all verified.
      Commit: `new: [galaxy] attach clusters to multiple events via
      selected pattern`
- [x] **T4** Frontend: toolbar buttons, `listCheckboxesCheckedEventIndex`,
      `getSelectedEventIds`, `quickSubmitTagForm`/`quickSubmitGalaxyForm`
      branches (§6.2, §6.4). Done 2026-06-12. Verified via session-
      login curl: all 4 buttons render on /events/index with correct
      `data-popover-popup` URLs, `hidden mass-tag`/`mass-galaxy`
      classes; both picker endpoints respond for `selected/event`.
      Click-through E2E + non-tagger gating deferred to T6.
      Commit: `new: [UI] mass tag / mass cluster actions on event index`
- [x] **T5** Bulk integration tests incl. downgrade matrix + tamper check
      (§9.2–9.3). `tests/testlive_event_mass_actions.py`, 17 tests:
      16 pass + 1 conditional skip (`local_only` galaxy rejection —
      no such galaxy ships on this box; the path was live-verified in
      the T3 smoke with a temporarily flagged galaxy). T1 suite re-run
      green alongside. Covers: own-org/host-org/unrelated-org/site-
      admin × global/local, mixed selections, unpublish vs stays-
      published, both tamper vectors (forged body flag, /local:0
      param), up-front local_only batch rejection, junk/empty IDs.
      Commit: `chg: [test] mass tag and mass cluster integration coverage`
- [x] **T6** UI verification pass + attribute-flow non-regression
      (§9.4–9.5), screenshots for PR. Done 2026-06-12 via
      `tests/ui_event_mass_actions_check.py` (headless chromium over
      CDP, 19 checks, all green): buttons hidden/revealed on selection
      (computed visibility), picker opens from toolbar, full
      tag+cluster round-trips through the real JS path asserted via
      API, attribute mass tag/cluster non-regression, non-tagger
      button gating (Read Only role). Screenshots (debug off):
      `/home/iglocska/t6-shots/*.png` — attach to the PR.

## Key design anchors (don't re-derive)

- D6 downgrade: `effectiveLocal = preferLocal || !canModifyEvent(event)`;
  `local:1` URL param is preference only, never entitlement. ACL
  boundary stays: owners/creators global, host-org taggers local-only,
  non-host-org taggers fail (counted, loop continues).
- D4: skip-and-count in the NEW event paths only; existing attribute
  branch of `attachMultipleClusters` keeps its throw behavior.
- `local_only` tags/clusters under a global preference: reject the whole
  batch up front.
- Unpublish (`touch`) once per event, only when ≥1 effectively-global
  attach happened to it.
- Frontend: new `getSelectedEventIds()` collector — do NOT reuse
  `getSelected()` (bound to `.select_attribute`).

## State / next step

- 2026-06-12: **T1–T6 ALL DONE** in one session. Feature complete on
  `feature-event-index-mass-actions` (6 commits + 1 unrelated
  `fix: [tagCollection]`). Test instance:
  `http://localhost:5007/`; run tests with `HOST=localhost:5007
  AUTH=<site-admin key>` (or `tests/keys.py` fallback); the UI check
  additionally needs `MISP_ADMIN_EMAIL`/`MISP_ADMIN_PASSWORD`.
- **Next: PR.** Open PR from `feature-event-index-mass-actions` into
  `2.5` (PRD §10 says confirm 2.5 vs develop with the user first).
  Attach `/home/iglocska/t6-shots/*.png`. Surface in the PR
  description: the D6 ACL boundary, the T3 visibility asymmetry note,
  and the tagCollection fix being separable.

## Decisions & discoveries log

- 2026-06-12 (T1): found + fixed a latent 2019 bug — `TagCollection::
  cullBlockedTags()` checks `Tag.org_id/user_id/hide_tag` but
  `fetchTagCollection()`'s default contain only loaded `id, name`:
  cull was a no-op for non-admins + undefined-key warning broke JSON
  under debug. Fix = load the three fields (commit `515ae33c3`,
  separate `fix:` commit — review welcome).
- 2026-06-12 (T1): dev-box fossil removed — a leftover disabled
  "Workflow for trigger event-publish" (stop_execution node) still
  executed because the *trigger-level* setting
  `Plugin.Workflow_triggers_event-publish` was on (the per-workflow
  `enabled` column does not gate `executeWorkflowForTrigger`); it
  blocked ALL synchronous publishes on this instance. Disabled via
  `cake Admin setSetting "Plugin.Workflow_triggers_event-publish"
  false`. Possible upstream question (disabled workflow still
  executing) — not pursued in this branch.
- 2026-06-12 (T1): `tests/keys.py` had a stale API key; updated to the
  current admin key (untracked local file).
- 2026-06-12 (T2) bulk-contract decisions (refine §8.1):
  - JSON counters `attached`/`downgraded`/`skipped`/`failed` count
    **(event, tag) pairs**; the human message counts **events**
    (`eventsTagged` / `eventsDowngraded`). With one tag selected the two
    coincide (the PRD's example).
  - `saved: false` when nothing was attached, including the all-
    duplicates re-run case (matches attribute semantics: no attach →
    not saved).
  - `event_ids` accepts both a JSON-string (`"[1,2]"`, the form/UI
    encoding) and a native JSON array (API callers) — superset of the
    PRD contract.
  - Single-event path: permission check still precedes tag resolution
    (order preserved); per-tag find hoisted to one `Tag.id IN` query
    for both paths; unpublish now batched once per event (same end
    state, locked by the T1 unpublish test).
- 2026-06-12 (T3) pre-existing visibility asymmetry, kept as-is
  (additive posture): `addTag` resolves events with a raw find (host-
  org taggers can local-tag events they cannot VIEW — today's single-
  event semantic), while `attachMultipleClusters` resolves via
  `fetchSimpleEvent` (ACL view check — invisible events count as
  `failed`). Each bulk path inherits its endpoint's existing semantic.
  Irrelevant for the index UI (selection = visible events); T5's
  downgrade matrix must use distribution >= 1 events for the cluster
  case. Flag if the two should be unified instead.
- 2026-06-12 (T4, revised post-review): user disliked the single
  rebel/empire/tag/user icons — replaced with icon *pairs* via the
  `html` key of `element_simple.ctp`: globe+tag (global tag),
  user+tag (local tag), globe+book-open (global cluster),
  user+book-open (local cluster). All FA5 solid glyphs.
- 2026-06-12 (T4): on the index, `quickSubmitTagForm`/`GalaxyForm`
  `location.reload()` on success (house pattern from the attribute
  flow), which means the summary toast (incl. downgraded counts) is
  not seen — same UX gap as the existing attribute mass-cluster flow.
  Candidate follow-up alongside PRD §12.6 (persist summary across
  reload); not in v1 scope.
- 2026-06-12 (T3): cluster outcomes are mapped from
  `Galaxy::attachCluster()` return strings ('Cluster attached.' /
  'Cluster already attached.' / other = failed); unknown/invisible
  clusters throw NotFoundException → caught per pair → `failed`.
  attachCluster itself touches (unpublishes) per global attach and
  never on local — D6-compatible without model changes.
