# fastLookup: batched equality lookups and pruned IP prefixes

Status: approved design (2026-09-29). Follow-up PR stacked on MISP/MISP#11168
(branch `feature/attributes-fast-lookup-bloom`, head 0e4d22e5d).
New branch: `feature/attributes-fast-lookup-batched`.

## Goal

All-hit `POST /attributes/fastLookup` requests (10,000 values, every value
matches) take at most one quarter of their #11168 time **on every one of the 17
default types**, with results identical to #11168. Misses and expansions must
not regress.

Reference: #11168's run 3 (`FastLookupScale.php`, 17 types x 100,000
attributes, MariaDB 10.11, Redis 8.2), mean all-hit time 10.1 s. For example,
md5 is 10.2 s, so its target is at most 2.55 s. ip-dst is 12.7 s, so its target
is at most 3.2 s.

## Evidence (throwaway spike, 2026-09-28/29)

- Nearly all of today's time goes to per-batch and per-branch overhead:
  - BATCH_SIZE is 100, so a 10,000-value request makes 100 rounds.
  - Each round runs a `UNION ALL` weights query with about 200 branches, one
    Redis call, and an equality `UNION` with up to 200 full `SELECT`s. Each
    `SELECT` carries the three-table join, the ACL and the type list.
  - For md5 hits, MariaDB CPU was 11.1 s against 1.2 s for the batched form.
- With the batched form (approach A below), 12 or 13 of 17 types reached a
  quarter by CPU time. The four IP types reached only 0.30–0.37. They stay bound
  by about 4 s of PHP CPU, spent generating 33 (IPv4) or 129 (IPv6) prefix
  tokens per value, about 340k SHA-256 tokens per request.
- Generating tokens only for the prefix lengths that exist in the index brings
  every type to 0.12–0.23 of the reference (CPU). Wall-clock ratios agree
  except where load noise dominated.
- Results were byte-identical to #11168 for all 17 types x
  {hits, misses, expansions}, and on an edge set:
  - case variants;
  - trailing space, NBSP, tab and U+3000, and a leading space;
  - emoji;
  - whitespace-only and ignorable-only inputs.
- A temporary-table join (approach B) was not needed.
- Honest comparison: with the SQL written well, a plain batched `IN` lookup
  without Redis costs about the same as the Bloom path on exact types, and
  slightly less on domains. The Bloom index still wins clearly on IP
  containment: 2.0 vs 5.8 CPU s on hits and 0.9 vs 2.2–3.0 s on misses. The
  plain-SQL form also only finds CIDRs stored in canonical form.

Spike artefacts: `~/tmp/fl-spike/` (report.md, approach-a.diff, out/).

## Design

### 1. Batched equality lookup (`AttributeFastLookupTool`, `FastLookupValueTool`)

- **Batches.** `BATCH_SIZE` goes from 100 to 1,000 values. A batch also closes
  once the SQL-quoted size of its values would exceed 4 MiB, so neither the
  weights query nor an `IN` list can reach MariaDB's default 16 MiB
  `max_allowed_packet`. Redis calls keep their existing 1,024-token chunking.
- **Input weights.** `weights()` issues one single-row `SELECT` with one column
  per (value, component) pair, instead of the `UNION ALL`. Each column keeps
  exactly today's expression:
  `WEIGHT_STRING(RTRIM(<value converted to the column's charset and collation>))`,
  plus the pad weight handling. Pad stripping is unchanged.
- **Equality query.** For each batch and component (`value1`, `value2`), one
  query:

  ```
  SELECT Attribute.event_id, WEIGHT_STRING(RTRIM(Attribute.valueN)) AS weight
  FROM <from clause> WHERE Attribute.valueN IN (<values>) <common conditions> <unindexed restriction>
  ```

  - `<values>` holds only the values whose exact Bloom token may be present,
    plus the `fallback` values, as today.
  - PHP strips the pad weight from each returned `weight` and maps the row to
    every input index with the same stripped weight. That is exactly SQL
    collation equality.
- **Fallback.** The weight mapping applies only where `supportsWeights()` is
  true, the collation whitelist that already exists: single-level PAD SPACE
  `utf8`/`utf8mb3`/`utf8mb4` `_unicode_ci`, `_general_ci` and `_bin`. For any
  other collation, and for inputs `representable()` rejects, the current
  per-value `=` branch is kept unchanged.
- **Row limit.**
  - Matches are de-duplicated as (input, event) pairs across both components
    before they count toward `MAX_ROWS`, so the 100,000-row limit keeps
    meaning "result pairs".
  - The SQL `LIMIT` stays as a safety bound of `MAX_ROWS - rowCount + 1` rows
    per query.
  - The overflow error is unchanged.
- **Whitespace-only inputs.** An input whose stripped weight is empty for a
  component never matches that component. Today a lone NBSP matches every
  attribute with an empty `value2`, about 1M rows. This is a deliberate
  behaviour change, noted in the PR and docs.
- **Unchanged:** expansions (range and domain candidates fetched by
  `Attribute.id IN (...)` and re-checked live), the readiness and revision
  check after SQL, the response format.

### 2. Pruned IP prefix tokens (`FastLookupFilter`, `FastLookupValueTool`, `FastLookupIndexManager`)

- **What is recorded.** Each generation's `g:<gen>:info` hash records the set
  of IP prefix lengths its range tokens use, per family:
  - fields `p4` (IPv4, lengths 0–32) and `p6` (IPv6, lengths 0–128);
  - each field is a lowercase hex bitmask string, where bit *n* set means
    length *n* is present;
  - field `pv` is a counter, incremented whenever either mask gains a bit.
- **Writes.** The same Lua script that inserts range tokens ORs the new
  lengths into `p4`/`p6` and bumps `pv` when a mask changed. Because it is the
  same script, a posting and its length are never visible apart.
  - This covers the scan, the queue drain and incremental adds, into both the
    live and the building generation.
  - `reserve()` initialises `p4`/`p6` to empty masks and `pv` to `0`.
- **Reads.** A lookup reads `p4`, `p6` and `pv` of the live generation once,
  in the same call that reads the metadata it already needs.
  - `queryTokens()` then generates network tokens only for recorded lengths.
    Exact and domain tokens are unchanged.
  - The candidates script returns the current `pv`. If it differs from the
    value read at the start, the batch is recomputed with the new masks; if it
    changes again, the lookup returns the existing "index changed, retry"
    status.
  - So pruning adds no new way to miss a range beyond #11168's existing
    consistency guarantee.
- **Stale lengths.** Deleted attributes may leave lengths set. That is
  harmless: they cost only extra tokens, and a rebuild resets them.
- **Compatibility and failure handling.**
  - A generation without `p4`/`p6`/`pv` (built by #11168) means "all lengths":
    today's behaviour, with no rebuild required.
  - A present but malformed field (not hex, or wider than the family allows)
    fails closed with the same `FastLookupIndexCorruptException` path as other
    invalid metadata.

### 3. Benchmark and reporting (`tests/benchmarks/FastLookupScale.php`)

- Replace the `FL_SQL_BASELINE` query with the batched plain-SQL form: a
  1,000-value `IN` over each value plus its containment forms, with the same
  ACL and scope. This makes the baseline honest.
- Report CPU seconds next to wall time, from the containers' cgroup
  `cpu.stat`, per phase: PHP, MariaDB, Redis.
- **Acceptance gate:**
  - every type's all-hit wall time is at most 0.25x of the #11168 run 3
    number, with CPU ratios also at most 0.25x;
  - misses and expansions are not slower than #11168;
  - results are identical to #11168, via a comparison mode that runs the
    #11168 lookup on the same data;
  - the run happens on a quiet host (load average below the core count).
    If the host is busy, the run is reported as indicative only and repeated.

### 4. Docs and PR

- `docs/development/fastlookup.md`: batching, the prefix masks, the
  whitespace-only behaviour and new sizing numbers.
- The PR states the honest Bloom-vs-SQL comparison from the Evidence section:
  the index earns its keep on IP containment and misses, not on exact hits.

## Out of scope

- Skipping the `value2` query for pure hash types. It would need
  component-tagged exact tokens, an index format change that forces a rebuild.
- The #11168 parked follow-ups: hot-token posting appends, empty scan windows,
  `clearLastError`, a live-only metadata read, and old-generation cleanup.

## Tests

- **Weight mapping** (`AttributeFastLookupTest` plus the MariaDB-backed
  collation suite):
  - case variants in one batch map to the same rows;
  - trailing space and NBSP match the plain value, while tab and U+3000 do not
    (as SQL `=`);
  - a leading space is distinct;
  - a value over 255 characters that shares a 255-character prefix with
    another value matches only itself;
  - a non-whitelisted collation takes the `=` fallback.
- **Batching:** 1,000-value batches, the 4 MiB byte cap closes a batch early,
  and duplicate inputs.
- **Row limit:** duplicate (input, event) pairs across `value1` and `value2`
  count once, and overflow still raises at the limit.
- **Whitespace-only inputs:** NBSP, zero-width space and space-only inputs
  return no match and issue no `IN` entry.
- **Prefix masks** (`FastLookupFilterTest`, Redis contract):
  - a range insert sets the bit and bumps `pv`;
  - a repeated length does not bump `pv`;
  - both generations are updated during a rebuild;
  - a generation with no mask means all lengths;
  - a malformed mask fails closed;
  - a `pv` change mid-lookup recomputes the batch;
  - a lookup for an IP inside a /13 range still matches when only /13 and
    /32 are recorded.
- **End to end:** `FastLookupIntegration.php` still passes, and the scale
  benchmark gate above passes.
