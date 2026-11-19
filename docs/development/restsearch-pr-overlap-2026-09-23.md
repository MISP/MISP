# MISP restSearch performance: upstream PR overlap audit

Audit date: 2026-09-23. Implementation base: MISP/MISP `2.5` at [`794511eabe96fbed34c76c990cfdc872b801421c`](https://github.com/MISP/MISP/tree/794511eabe96fbed34c76c990cfdc872b801421c).

## Scope and method

This was a bounded duplication audit before implementing six requested Attribute `restSearch` optimizations:

1. exporter-driven minimal fields/relations/processing;
2. a lean fetch path that preserves JSON output;
3. batched correlations and event tags;
4. a public cursor plus raw progress;
5. profile the current OR/query-plan alternatives;
6. a guarded SQL count.

I inspected all 232 currently open MISP/MISP PRs through the official GitHub Pulls API, the 500 most recent closed PRs, GitHub PR searches for `restSearch`, `fetchAttributes`, cursor, correlations, export fields, and count, and current path commit history for `MispAttribute.php`, `Event.php`, and `JsonExport.php`. Strong matches were checked at file-diff level. This is not a proof that no older, differently worded PR exists; it covers current open work, recent merged work, and full-history keyword matches returned by GitHub.

## Pre-publication refresh

Before opening the companion PRs, the open-PR inventory was fetched again: 236
open PRs. The additional work concerns sync/import fixes and unrelated features;
no new direct duplicate of these restSearch changes was found. Upstream `2.5`
remains at the implementation base above. This refresh does not expand the
original 500-closed-PR and historical keyword audit.

## Immediate collision ruling

| Requested work | Existing overlap | Ruling |
|---|---|---|
| 1. Minimal exporter fields/relations/processing | Open [#11135](https://github.com/MISP/MISP/pull/11135/files) edits the `MispAttribute::restSearch` parameter-building block; open [#10634](https://github.com/MISP/MISP/pull/10634/files) adds a separate minimal-looking exact-value endpoint | Real implementation gap. Expect textual conflict with #11135. #10634 is conceptual overlap but still calls ordinary `fetchAttributes` and manually projects the response after fetching. |
| 2. Lean enrichment while preserving JSON | No PR found implementing an exporter capability contract or a JSON-compatible lean path | Real gap. Coordinate with #11003's response snapshots to prove compatibility. |
| 3. Batch correlations/event tags | Merged #11085 batches sightings; open #11136 batches Event galaxies; #11054 batches Event related-attribute tags; #11139 batches a different `fetchRelated()` call site | Real gap for Attribute-restSearch `includeCorrelations` and `includeEventTags`. Do not duplicate sightings or the adjacent Event-only work. |
| 4. Public cursor + raw progress | Current upstream already has an internal ID cursor from direct commit `2254079`; merged #9846 already exposes skipped post-processing count | Extend current cursor behavior. Do not reimplement it. Define public cursor/raw-progress semantics around the existing `X-Skipped-Elements-Count` contract. |
| 5. Profile OR vs UNION | Direct commits `a66b68e` and `836cdcc` already removed the prior UNION-derived-table strategy and installed adaptive correlated `EXISTS` versus materialized `IN` | Adjacent tag-query work, not a duplicate exact-value UNION implementation. Preserve the current `EXISTS`/`IN` tag predicates when comparing candidate-ID strategies. |
| 6. Guarded SQL count | Closed-unmerged #4168 attempted an unconditional pre-pagination COUNT. Current `fetchAttributes` already accepts `$real_count` and runs COUNT only when `$result_count !== false && $real_count` | Build on the existing guard and avoid reviving #4168's unconditional count. No open PR found for a new externally controlled count mode. |

## Strong matches inspected

### Open PRs

#### [#11135 — `[medium] chg: [restSearch] de-duplicate the attribute/object restSearch filter massaging`](https://github.com/MISP/MISP/pull/11135)

- State: open.
- Author/head: `elhoim:chg-restsearch-attribute-level-massage`, head [`946bebe3eb92f97a4089f0e6b2249761381b7a65`](https://github.com/MISP/MISP/commit/946bebe3eb92f97a4089f0e6b2249761381b7a65).
- Files: `app/Model/Event.php` (+70); `app/Model/MispAttribute.php` (+5/-43); `app/Model/MispObject.php` (+5/-43). [Diff](https://github.com/MISP/MISP/pull/11135/files).
- Exact scope: moves the shared attribute/object filter massage to `Event::restSearchFilterMassageAttributeLevel()` and the 14 include flags to `Event::restSearchIncludeFlags()`. It claims no behavior change.
- Overlap: direct textual overlap with tasks 1/2 wherever exporter capabilities or lean flags are added to `MispAttribute::restSearch`.
- Gap: it does not reduce selected columns, associations, hydration, enrichment, serialization, correlation calls, counts, or pagination cost.
- Integration note: implement new behavior through a small post-massage capability/options layer so #11135 can be rebased without duplicating its helper extraction.

#### [#10634 — `feat(api): Add /attributes/searchByValue endpoint for value-based lookups`](https://github.com/MISP/MISP/pull/10634)

- State: open since 2026-02-09.
- Author/head: `louayykaltoum:feature/attribute-searchbyvalue`, head [`d8a22d7b96300408379d49d4e044d181e0d0a502`](https://github.com/MISP/MISP/commit/d8a22d7b96300408379d49d4e044d181e0d0a502).
- Files: `app/Controller/AttributesController.php` (+108), `app/webroot/doc/openapi.yaml` (+129). [Diff](https://github.com/MISP/MISP/pull/10634/files).
- Exact scope: adds POST `/attributes/searchByValue`, exact `value1 OR value2`, limit 100/1000, optional basic Event data, then manually emits ten Attribute fields.
- Overlap: same “fast/minimal IOC lookup” use case as task 1.
- Gap: separate API contract; calls ordinary `MispAttribute::fetchAttributes()` without a restricted `fields` set, so it fetches the normal default fields/relations and only trims after hydration. It does not preserve the established `restSearch` JSON shape or support its policy/filter surface.
- Collision: none if optimization stays inside existing `restSearch`; document why the general path makes this endpoint less necessary.

#### [#11003 — `[low] test: golden-snapshot contract for the restSearch API`](https://github.com/MISP/MISP/pull/11003)

- State: open.
- Author/head: `elhoim:test/live-restsearch-contract`, head [`2e525bcd6518f59b2630f8d99e9c160e80e66a40`](https://github.com/MISP/MISP/commit/2e525bcd6518f59b2630f8d99e9c160e80e66a40).
- Files: test harness plus 32 snapshots, including Attribute JSON, exact value, limits, `to_ids`, category/type, CSV/text/hashes and Event export formats. [Diff](https://github.com/MISP/MISP/pull/11003/files).
- Overlap: no production-code collision; it is the strongest existing compatibility oracle for tasks 1/2/4/6.
- Gap: no performance behavior. Reuse or port the Attribute JSON snapshots rather than creating a conflicting response contract.

#### [#11136 — `[medium] perf: [event] fetch galaxy clusters once per fetchEvent result set instead of once per event`](https://github.com/MISP/MISP/pull/11136)

- State: open.
- Author/head: `elhoim:fix-event-galaxy-cluster-cache`, head [`3824e48bd6ffad5c8ba50a2c1fb7ae580e17628b`](https://github.com/MISP/MISP/commit/3824e48bd6ffad5c8ba50a2c1fb7ae580e17628b).
- Files: `app/Model/Event.php` (+21/-7), `app/Test/EventGalaxyClusterCacheTest.php` (+266). [Diff](https://github.com/MISP/MISP/pull/11136/files).
- Exact scope: shares a tag-ID-to-cluster cache across the events in one `fetchEvent()` result and negative-caches missing clusters.
- Overlap: adjacent enrichment optimization; relevant if Event restSearch is changed.
- Gap/collision: no Attribute `fetchAttributes` correlation/event-tag batching. Keep task 3 in `MispAttribute.php` unless a shared primitive is necessary.

#### [#11054 — `[medium] perf: batch the AttributeTag lookups in Event::includeRelatedTags`](https://github.com/MISP/MISP/pull/11054)

- State: open.
- Author/head: `elhoim:perf/include-related-tags-batch`, head [`2f10d2d8aa66db8db37203bfd8711e577b79e686`](https://github.com/MISP/MISP/commit/2f10d2d8aa66db8db37203bfd8711e577b79e686).
- File: `app/Model/Event.php` (+59/-26). [Diff](https://github.com/MISP/MISP/pull/11054/files).
- Exact scope: bulk-fetches tags for attributes referenced by an Event's `RelatedAttribute` set and replaces a linear Attribute position scan with an ID map.
- Overlap: adjacent to correlation enrichment, but only the Event `includeRelatedTags` option after granular correlations.
- Gap: does not batch `MispAttribute::fetchAttributes()`'s per-attribute `Correlation::getRelatedAttributes()` calls or its per-event tag lookup.

#### [#11139 — `[medium] perf: batch the per-candidate related lookups in MispAttribute::fetchRelated()`](https://github.com/MISP/MISP/pull/11139)

- State: open.
- Author/head: `elhoim:fix-fetch-related-batching`, head [`f69fee1f5b27d6c59703a4828adc5413cb872e25`](https://github.com/MISP/MISP/commit/f69fee1f5b27d6c59703a4828adc5413cb872e25).
- Scope from inspected PR diff/body: batches freetext-import candidate rows 100 at a time into one ACL-scoped `fetchAttributes()`.
- Overlap: calls the same model method.
- Gap: `fetchRelated()` is a different consumer; it does not alter Attribute restSearch enrichment, correlations, event tags, cursor, or counts.

#### [#11088 — `[medium] perf: batch decay-score sightings fetch in MispAttribute::fetchAttributes`](https://github.com/MISP/MISP/pull/11088)

- State: open.
- Author/head: `elhoim:perf/decay-requires-sightings-listsightings-fetchattributes-per-attribute`, head [`65c9ff04337565c67a7e7ceef2184b3fd6d59d68`](https://github.com/MISP/MISP/commit/65c9ff04337565c67a7e7ceef2184b3fd6d59d68).
- Exact scope: batches the sightings timestamps used by decay formulas instead of invoking a full `fetchAttributes()` per attribute.
- Overlap: touches optional `includeDecayScore` work in the same per-attribute pipeline.
- Gap: no exporter field contract, lean default JSON path, correlation/event-tag batching, cursor, or count behavior. A lean path should bypass decay work when the option is false and remain compatible when true.

Open #10988 (head `ded43dd4904cf2efa925f8dec7b703cf2035506e`) and #10989 (head `4adb683a50243f89dae59d7d6c82814feba1a26e`) are Event-restSearch correctness/config fixes: honoring `$paramsOnly` and reading the correct event memory divisor. They are not implementation duplicates, but avoid editing those Event blocks unnecessarily: [#10988](https://github.com/MISP/MISP/pull/10988), [#10989](https://github.com/MISP/MISP/pull/10989).

### Merged or current upstream work

#### [#11085 — batch sightings in `MispAttribute::fetchAttributes`](https://github.com/MISP/MISP/pull/11085)

- State: merged 2026-09-03.
- Head [`5d2f11767c373835e1ffca2a07a77a9f0f602c06`](https://github.com/MISP/MISP/commit/5d2f11767c373835e1ffca2a07a77a9f0f602c06); merge commit [`454205e0c6d04ae3e9b265ca57804b66dc3de9d8`](https://github.com/MISP/MISP/commit/454205e0c6d04ae3e9b265ca57804b66dc3de9d8).
- Files: `app/Model/MispAttribute.php` (+7/-3), `app/Model/Sighting.php` (+88/-8). [Diff](https://github.com/MISP/MISP/pull/11085/files).
- Exact scope: `includeSightings` now calls one bulk `Sighting::attachToAttributes()` per Attribute batch rather than two queries per attribute.
- Ruling: task 3 must leave this batching intact. Correlations and event tags remain unbatched gaps.

#### [#9846 — add `X-Skipped-Elements-Count`](https://github.com/MISP/MISP/pull/9846)

- State: merged 2024-08-21.
- Head [`0ecbfe73b78bb6c45718ff94d139547d37980367`](https://github.com/MISP/MISP/commit/0ecbfe73b78bb6c45718ff94d139547d37980367); merge commit [`9b39e2156b2b0b1dcab0938862632d40080818c5`](https://github.com/MISP/MISP/commit/9b39e2156b2b0b1dcab0938862632d40080818c5).
- Files: `AppController.php`, then-`Attribute.php`; 26 production-line changes. [Diff](https://github.com/MISP/MISP/pull/9846/files).
- Exact scope: counts rows discarded by warninglist/proposal/decay post-processing and returns `X-Skipped-Elements-Count` alongside `X-Result-Count`.
- Ruling: task 4's “raw progress” must coexist with this header and clearly distinguish scanned/raw rows, skipped rows, and emitted rows.

#### Direct upstream commit [`2254079` — internal cursor pagination](https://github.com/MISP/MISP/commit/2254079f3f32b6365db74e5f3857f503ae0edc85)

- No associated PR was returned by GitHub.
- File: `app/Model/MispAttribute.php` (+21/-2).
- Exact scope: in `__iteratedFetch`, when MISP internally loops and no explicit order is requested, uses `Attribute.id > $lastId` plus ascending ID; falls back to OFFSET for explicit order.
- Ruling: task 4 is an API exposure/continuation feature, not a new cursor implementation. Preserve the explicit-order fallback and do not allow arbitrary cursor/order combinations.

#### Direct upstream commits [`a66b68e`](https://github.com/MISP/MISP/commit/a66b68e3b9fdbd455ed07af3b5a20c20d956e522) and [`836cdcc`](https://github.com/MISP/MISP/commit/836cdccb72a61f70b095334f60bbf4c4a36d2b14)

- Neither has an associated PR in GitHub's commit-to-PR endpoint.
- `a66b68e`, “chg: [attribute restsearch] rework,” changes only `MispAttribute.php` (+155/-222): simplifies tag filtering, replaces redundant Event ACL subqueries with conditions on the already-joined Event, and reorganizes `fetchAttributes`.
- `836cdcc`, “fix: [attribute search] performance improvement for certain cases,” changes only `MispAttribute.php` (+69/-9): detects selective Attribute filters and chooses correlated `EXISTS`; for tag-only queries it keeps uncorrelated materialized `IN`. This followed the reported regression where a UNION-derived-table approach performed badly.
- Ruling: task 5 should measure current `EXISTS` versus `IN` plans on representative cardinalities. The old `UNION ALL` strategy has already been removed from current upstream. Any new plan selection must be justified by EXPLAIN/benchmark results and database flavor.

#### Current guarded count and closed [#4168](https://github.com/MISP/MISP/pull/4168)

- #4168 state: closed unmerged 2019-02-19.
- Head [`7919e2cce355e08cdd83c4868c1adebebfa5ced2`](https://github.com/MISP/MISP/commit/7919e2cce355e08cdd83c4868c1adebebfa5ced2).
- File: then-`app/Model/Attribute.php` (+9/-3). [Diff](https://github.com/MISP/MISP/pull/4168/files).
- Exact scope: unconditionally cloned query parameters, removed limit, and ran `find('count')` for the pre-pagination `X-Result-Count`.
- Current source already guards the count behind `$result_count !== false && $real_count` in [`MispAttribute.php#L2289-L2301`](https://github.com/MISP/MISP/blob/794511eabe96fbed34c76c990cfdc872b801421c/app/Model/MispAttribute.php#L2289-L2301).
- Ruling: task 6 should expose/use this guard deliberately. It should not copy #4168's always-count behavior.

Merged [#10325](https://github.com/MISP/MISP/pull/10325) (head `34118cbfba51ca9c5fcd1abcb18317165c13c6c2`, merge `3a1100deba05a8ca63f35554d94a33d799e2a69d`) imposes server/role result limits at the controller. Public cursor/limit work must continue to honor that cap.

## Closed ideas that should not be revived verbatim

- [#9176](https://github.com/MISP/MISP/pull/9176), closed unmerged, head `b8760c9cdd89a1f8809e5e434fc81ffac128d3d5`: attempted to fill pages after post-processing skips. #9846 chose explicit skipped-count reporting instead. Public cursor semantics should account for skipped rows without silently changing the requested-page contract.
- [#3473](https://github.com/MISP/MISP/pull/3473), closed unmerged, head `f43c0ad7efc0baeb128fab6f093a82085d358601`: proposed `value_exact` to use value1/value2 indexes. Current `value` filtering already targets value1/value2, so it is historical context rather than a current gap.

## Implementation guidance

1. Keep task 1/2 changes localized behind exporter capability declarations and `fetchAttributes` options. This minimizes the inevitable rebase against #11135.
2. Preserve the full JSON response exactly and prove it with #11003-compatible snapshots. “Minimal” should mean SQL fields/associations and skipped processing, not a new response shape like #10634.
3. Batch only the two remaining hot paths in task 3: correlation resolution and event-tag resolution. Keep merged sighting batching and open decay/galaxy/related-tag work orthogonal.
4. Treat the public cursor as a continuation token for the existing ID cursor. Reject or fall back for explicit non-ID ordering. Report emitted, skipped, and scanned/raw progress unambiguously; preserve role REST limits.
5. Benchmark current adaptive `EXISTS`/`IN`, plus any proposed UNION alternative, with EXPLAIN and real distributions before changing the heuristic.
6. Make count opt-in and route it through the existing `$real_count` guard. Avoid COUNT for streaming/cursor calls unless the caller explicitly requests a total.
