# Event Index Mass Tag / Mass Cluster — Progress Tracker

PRD: `docs/dev/event-index-mass-actions-prd.md` (canonical copy of
`/home/iglocska/prds/misp_event_index_mass_tag_cluster.md`, signed off
2026-06-12). Branch: `feature-event-index-mass-actions` off `2.5`.

Working model: strictly sequential tasks, one commit per task, tick one
box at a time. A fresh session must be able to resume from this file
alone — keep the "state / next step" section honest.

## Tasks (PRD §10)

- [ ] **T1** Regression-guard integration test for single-event
      `events/addTag` (PRD §9.1). Covers: single tag id, JSON tag list,
      tag name, `collection_N`, `local:1`, duplicate (skip),
      no-permission cases. Must pass against *unmodified* `addTag`
      before T2 starts.
      Commit: `chg: [test] coverage for events/addTag single-event contract`
- [ ] **T2** Backend: `events/addTag` `'selected'` support incl. D6
      global→local downgrade + `add_tag.ctp` `event_ids` field (§6.1).
      Commit: `new: [event] mass tagging of selected events via addTag
      selected pattern`
- [ ] **T3** Backend: `attachMultipleClusters` `event_ids` branch +
      skip-and-count + D6 downgrade + form field (§6.3).
      Commit: `new: [galaxy] attach clusters to multiple events via
      selected pattern`
- [ ] **T4** Frontend: toolbar buttons, `listCheckboxesCheckedEventIndex`,
      `getSelectedEventIds`, `quickSubmitTagForm`/`quickSubmitGalaxyForm`
      branches (§6.2, §6.4).
      Commit: `new: [UI] mass tag / mass cluster actions on event index`
- [ ] **T5** Bulk integration tests incl. downgrade matrix + tamper check
      (§9.2–9.3).
      Commit: `chg: [test] mass tag and mass cluster integration coverage`
- [ ] **T6** UI verification pass + attribute-flow non-regression
      (§9.4–9.5), screenshots for PR.

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

- 2026-06-12: Branch created, PRD + tracker checked in. **Next: T1.**
  Test instance: `http://localhost:5007/`, admin API key in
  `tests/keys.py` convention / memory `reference-misp-test-instance`.

## Decisions & discoveries log

- (none yet)
