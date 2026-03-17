# Attribute restSearch Benchmark Guide

Benchmark suite for `POST /attributes/restSearch`.  Measures execution
time and hit count for a catalogue of queries that exercise different
filter paths and join strategies inside `MispAttribute::fetchAttributes()`.

## Files

| File | Purpose |
|---|---|
| `attribute_search_bench.py` | Benchmark runner — executes queries and prints timing/hit counts |
| `attribute_search_bench_diff.py` | Comparison tool — takes two benchmark text outputs and highlights regressions/improvements |
| `attribute_search_bench.md` | This guide |

## Usage

```bash
python3 tests/attribute_search_bench.py [BASE_URL]
```

| Environment variable | Default | Description |
|---|---|---|
| `KEY_ADMIN` | *(hardcoded dev key)* | Site-admin API key |
| `BENCH_RUNS` | `3` | Repetitions per query; median/min/max reported |
| `BENCH_OUTPUT` | *(unset)* | If set, writes a JSON file with `{name: {hits, median_s}}` for automated diffing |

### Comparing branches

Save the text output from each branch, then use the diff tool to
compare them:

```bash
# 1. Run on the baseline branch
git checkout main
python3 tests/attribute_search_bench.py > /tmp/bench_before.txt

# 2. Run on the feature branch
git checkout feature-branch
python3 tests/attribute_search_bench.py > /tmp/bench_after.txt

# 3. Compare
python3 tests/attribute_search_bench_diff.py /tmp/bench_before.txt /tmp/bench_after.txt
```

The diff tool (`attribute_search_bench_diff.py`) parses the text
output from two runs and reports:

- **Hit count differences** — any query where the result count changed
  (flags a possible correctness regression)
- **FASTER** — queries whose median time improved by >= 50%
- **SLOWER** — queries whose median time regressed by >= 50%
- **Full comparison table** — all queries side-by-side with before/after
  medians, percentage change, and hit counts

Example output:

```
========================================================================
 Benchmark Comparison
  Before: /tmp/bench_before.txt  (48 queries)
  After:  /tmp/bench_after.txt   (48 queries)
========================================================================

No hit count differences — results are consistent.

FASTER (3 queries, >= 50% improvement):

   Query                                      Before    After   Change
   ---------------------------------------- -------- -------- --------
   heavy_type_timestamp_tags                   4.210s   0.055s     -99%
   tag_and_two                                 2.150s   0.793s     -63%
   jo_eventtag_bigtype                         0.340s   0.083s     -76%

No queries regressed by >= 50%.

------------------------------------------------------------------------
 Full comparison
------------------------------------------------------------------------
   ...
```

The diff tool also handles missing queries (present in one file but not
the other) and reports a total median time comparison at the bottom.

Alternatively, the benchmark can write machine-readable JSON for custom
tooling:

```bash
BENCH_OUTPUT=/tmp/before.json python3 tests/attribute_search_bench.py
# switch branch …
BENCH_OUTPUT=/tmp/after.json  python3 tests/attribute_search_bench.py
```

## Correctness

There is no automated correctness check.  The benchmark prints hit
counts so you can compare them manually between runs.  The same query
on the same dataset **must** return the same hit count regardless of
the code path — a count change after a refactor indicates a
behavioural regression.

The `limit` is set to **500** on most queries to force the database to
do real work (scanning, joining, sorting) rather than short-circuiting
after a handful of rows.

## Query Catalogue

### 1–5: Single attribute-table filters (baseline)

These touch only the `attributes` table (plus the implicit `events`
JOIN for ACL).  They establish a timing baseline for the simplest
possible query path.

| # | Name | What it tests |
|---|---|---|
| 1 | `type_domain` | Index lookup on `type` column.  `domain` is a mid-cardinality type (~155K rows). |
| 2 | `type_ip-dst` | Same index, lower cardinality (~81K). |
| 3 | `type_sha256` | Same index, highest cardinality type (~780K). Exercises how well the query handles a very large candidate set. |
| 4 | `category_network` | Index lookup on `category`.  `Network activity` is the second-largest category (~554K). |
| 5 | `to_ids_only` | Boolean filter.  Low selectivity (large fraction of rows have `to_ids=1`), so this mostly measures full-scan overhead. |

**Assumption:** These types and categories exist in any non-trivial MISP instance.

### 6–9: Value / wildcard filters

These exercise the `value1`/`value2` LIKE conditions and reveal
whether the optimizer can use the value index.

| # | Name | What it tests |
|---|---|---|
| 6 | `value_exact` | Exact match on `value1` (`8.8.8.8`).  Should be a fast index seek. |
| 7 | `value_wildcard_suffix` | Leading wildcard (`%.example.com`).  MySQL **cannot** use the value index — forces a full table scan. This is expected to be one of the slowest queries. |
| 8 | `value_wildcard_prefix` | Trailing wildcard (`192.168.%`).  MySQL **can** use the index as a range scan, so this should be fast despite being a LIKE. |
| 9 | `value_wildcard_middle` | Double wildcard (`%google%`).  Full scan, but the matching set is larger than suffix-wildcard so it returns more rows. |

**Assumption:** The value `8.8.8.8` exists in the dataset.  The
wildcard queries are generic enough to produce hits on any instance
with network indicators.

### 10–12: Timestamp filters

These filter on `Attribute.timestamp` using relative time strings.
They test the range-scan efficiency of the timestamp index under
different selectivity levels.

| # | Name | What it tests |
|---|---|---|
| 10 | `timestamp_7d` | Very narrow window — few rows.  Fastest possible range scan. |
| 11 | `timestamp_30d` | Moderate window. |
| 12 | `timestamp_365d` | Wide window — approaches a full scan on active instances. |

**Assumption:** The instance has had data ingestion within the last
year.

### 13–14: Event-table filters

These filter only on columns in the `events` table, which is joined
via `contain` in `fetchAttributes()`.  They test the cost of pushing
conditions across the join.

| # | Name | What it tests |
|---|---|---|
| 13 | `published_only` | Boolean on `Event.published`.  Most events are published, so this is nearly unfiltered — measures join overhead. |
| 14 | `threat_level_1` | Enum filter on `Event.threat_level_id`.  Moderate selectivity. |

### 15–22: Tag filters

Tag filtering is the most complex code path.  Tags live in separate
`attribute_tags` and `event_tags` tables and are resolved via
subqueries or joins in `set_filter_tags()`.

| # | Name | What it tests |
|---|---|---|
| 15 | `tag_single` | Single positive tag (`tlp:white`).  Resolves tag name → tag ID, then checks both `attribute_tags` and `event_tags` via OR subqueries. `tlp:white` has ~80K attribute tags and ~3.3K event tags — a broad match. |
| 16 | `tag_or_multi` | OR of two tags (`tlp:white`, `tlp:green`).  Tests whether the `IN (tag_id_1, tag_id_2)` path scales linearly. |
| 17 | `tag_wildcard` | Wildcard tag (`tlp:%`).  The tag name is first resolved via `LIKE` on the `tags` table to get a set of matching tag IDs, then used as an `IN` list.  Tests the two-step resolution. |
| 18 | `tag_not_single` | Negative tag (`NOT tlp:red`).  Uses `NOT EXISTS` against `event_tags` and `NOT IN` / `NOT EXISTS` against `attribute_tags`.  Negative conditions cannot drive a join — the optimizer must scan from another table and then anti-join. |
| 19 | `tag_not_wildcard` | Negative wildcard (`NOT tlp:%`).  Combines the wildcard resolution step with the anti-join.  More tag IDs in the exclusion list than #18. |
| 20 | `tag_and_two` | AND of two tags.  Requires both tags to be present on the same attribute (or its event).  Generates one subquery per tag in the AND group — the most expensive tag pattern. |
| 21 | `tag_combined_not_or` | Mixed: `!tlp:red` (negative) combined with `tlp:%` (positive wildcard) in a single OR array using the `!` prefix syntax.  Tests the parser's splitting of positive/negative within a flat tag list. |
| 22 | `tag_combined_not_and_type` | Negative tag + attribute type filter.  Tests whether the optimizer can use the type index to reduce candidates before applying the anti-join. |

**Assumption:** TLP tags (`tlp:white`, `tlp:green`, `tlp:red`) are
present.  These are standard and exist on virtually every MISP
instance.

### 23–26: Cross-table combined filters

These pair an attribute-table filter with an event-table filter (and
sometimes a tag filter) to test how well the generated SQL handles
multi-table conditions.

| # | Name | What it tests |
|---|---|---|
| 23 | `cross_type_published` | `type` (attribute table) + `published` (event table).  Basic two-table join. |
| 24 | `cross_type_tag_published` | Three-way: attribute type + tag subquery + event published.  The query touches `attributes`, `events`, `attribute_tags`, and `event_tags`. |
| 25 | `cross_type_timestamp_tag` | Type + timestamp + tag.  All three filter axes have moderate selectivity, so the optimizer's choice of leading table matters. |
| 26 | `cross_type_toids_timestamp` | Type + `to_ids` + timestamp.  All filters on the attribute table — tests compound condition pushdown. |

### 27–30: Heavy combined queries

Realistic "worst case" queries inspired by the GitHub issue that
reported 5–7 minute execution times.

| # | Name | What it tests |
|---|---|---|
| 27 | `heavy_type_timestamp_tags` | Multi-type array + 90d timestamp + OR tags.  This is the exact query pattern from the reported performance issue.  Pre-optimisation this generated correlated subqueries that caused minutes-long execution. |
| 28 | `heavy_multi_type_neg_tag` | Multi-type + published + negative tag.  Tests the anti-join under a broad candidate set. |
| 29 | `heavy_wildcard_tag_timestamp` | Wildcard tag + timestamp + `to_ids`.  All three conditions have moderate-to-low selectivity. |
| 30 | `heavy_combined_and_not` | AND tag + NOT tag + type + published.  Maximum tag complexity combined with cross-table filters. |

### 31–48: Join-order-sensitive queries

These are the core of the benchmark.  Each query is designed so that
one filter axis is **highly selective** and another is **very broad**.
The optimal execution plan depends on which table the query starts
scanning from.  If the algorithm picks the wrong driving table, the
query will be disproportionately slow.

The naming convention is `jo_<what_should_lead>_<what_is_broad>`.

#### Attribute-tag selectivity vs attribute-table breadth (31–32)

| # | Name | What it tests | Optimal plan |
|---|---|---|---|
| 31 | `jo_attrtag_deleted` | Narrow attribute tag (`type:OSINT`, ~10 attr tags) + `deleted:0` (nearly all rows). | Scan `attribute_tags` first (tiny), then probe `attributes`. |
| 32 | `jo_broadtag_deleted` | Broad attribute tag (`tlp:white`, ~80K attr tags) + `deleted:0`. | Tag is no longer selective — attribute table scan may be equally fast. |

**Compare 31 vs 32:** Both have the same structure but the tag
selectivity differs by ~8000x.  A good algorithm adapts; a naive one
treats them identically.

#### Value selectivity vs tag breadth (33–34)

| # | Name | What it tests | Optimal plan |
|---|---|---|---|
| 33 | `jo_value_broadtag` | Exact value (`8.8.8.8`, index seek) + broad wildcard tag (`tlp:%`). | Value index first (few rows), then verify tag. |
| 34 | `jo_wildval_narrowtag` | Leading-wildcard value (`%google%`, full scan) + narrow attribute tag (`type:OSINT`). | Tag first (tiny), then LIKE-filter the joined attributes. |

**Compare 33 vs 34:** Swapped selectivity.  In #33 the value is the
needle; in #34 the tag is the needle.

#### Event-tag selectivity vs attribute-table breadth (35–37)

| # | Name | What it tests | Optimal plan |
|---|---|---|---|
| 35 | `jo_eventtag_bigtype` | Event-only tag (`workflow:state="draft"`, 312 events, 0 attr tags) + huge type (`sha256`, 780K rows). | Resolve event_tags → event IDs first, then filter attributes by `event_id IN (...) AND type`. |
| 36 | `jo_eventtag_noattr` | Same event-only tag with no attribute filter.  Pure event_tags scan baseline. | N/A — single filter axis. |
| 37 | `jo_raretype_broadevttag` | Very rare type (`twitter-id`, 1 row) + broad event tag (`tlp:white`, 3.3K events). | Type index first (1 row), then verify event tag. |

**Compare 35 vs 37:** Both combine an event tag with a type filter,
but the selectivity is inverted.  #35 should start from event_tags;
#37 should start from the type index.

**Assumption:** `workflow:state="draft"` exists as an event-only tag
(no attribute-level associations).  `twitter-id` is a very rare
attribute type.  Both may produce zero hits on some instances — that is
fine; the benchmark measures query execution time, not result count.

#### Timestamp selectivity vs tag breadth (38–39)

| # | Name | What it tests | Optimal plan |
|---|---|---|---|
| 38 | `jo_timestamp_broadtag` | Narrow timestamp (7d) + broad wildcard tag (`tlp:%`). | Timestamp range scan first. |
| 39 | `jo_widetimestamp_narrowevttag` | Wide timestamp (365d, most rows) + narrow event tag (`type:OSINT`, ~1.9K events). | Event tag first, then filter by timestamp. |

**Compare 38 vs 39:** Same two filter types, opposite selectivity.

#### Multi-table pile-ups (40–44)

These combine 3–4 filter axes to create situations where no single
table is an obvious leader.

| # | Name | What it tests | Optimal plan |
|---|---|---|---|
| 40 | `jo_3way_ts_evttag_type` | 7d timestamp + event tag (`type:OSINT`) + broad type (`domain`). | Either timestamp or event tag could lead — both are selective. |
| 41 | `jo_3way_val_ts_tag` | Exact value + 365d timestamp + broad tag. | Value first (index seek), timestamp and tag are irrelevant. |
| 42 | `jo_4way_evttag_pub_type_ids` | Event-only tag + published + type + `to_ids`. Four conditions across three tables. | Event tag narrows to ~312 events; the rest are secondary. |
| 43 | `jo_and_not_timestamp` | AND[`tlp:white`, `tlp:green`] + NOT[`tlp:red`] + 30d.  Most complex tag expression combined with timestamp. | Timestamp (30d) is selective; AND/NOT tags are secondary filters. |
| 44 | `jo_wildval_evttag_pub` | Wildcard value (`%malware%`) + event-only tag + published. | Event tag narrows to ~312 events; wildcard LIKE runs only within those events' attributes — much cheaper than scanning all 2M rows. |

**Key watchpoint:** Query #44 is expected to be one of the slowest
because it combines two expensive operations (LIKE full-scan and
event_tags subquery).  The relative slowness tells you whether the
event_tags filter is being applied before or after the LIKE scan.

#### Deleted attribute edge cases (45–46)

| # | Name | What it tests | Optimal plan |
|---|---|---|---|
| 45 | `jo_deleted_all_tag` | `deleted:1` (include soft-deleted) + broad tag. | The `deleted` condition changes from `deleted=0` (default, vast majority) to no filter on deleted — increases the candidate set and may change index choice. |
| 46 | `jo_deleted_only_type` | `deleted:2` (deleted only) + type. | Very small candidate set (few rows are deleted).  Tests whether the soft-delete filter can act as a leading condition. |

**Assumption:** `deleted:1` means "include all" and `deleted:2` means
"deleted only" per the `fetchAttributes()` convention.

#### Category cardinality extremes (47–48)

| # | Name | What it tests | Optimal plan |
|---|---|---|---|
| 47 | `jo_tinycat_broadtag` | Tiny category (`Person`, 12 rows) + broad wildcard tag. | Category first (12 rows), tag is irrelevant. |
| 48 | `jo_hugecat_narrowevttag` | Huge category (`Payload delivery`, 1.1M rows) + narrow event tag (`type:OSINT`). | Event tag first, then filter category within matched events. |

**Compare 47 vs 48:** Same filter types, opposite selectivity.

## Attribute Search Pipeline

See [app/docs/dev/attribute_search_pipeline.md](../../app/docs/dev/attribute_search_pipeline.md)
for the full pipeline diagram tracing a request from HTTP entry through
query building, ACL enforcement, SQL execution, and post-query
enrichment to the final response.

## Tables involved per query

For reference, the tables that each filter axis touches:

| Filter | Primary table | Secondary table(s) |
|---|---|---|
| `type`, `category`, `to_ids`, `value`, `deleted` | `attributes` | — |
| `timestamp` | `attributes` | — |
| `published`, `threat_level_id` | `events` (joined) | — |
| Positive tags | `attribute_tags` OR `event_tags` | `tags` (name→ID resolution) |
| Negative tags | `attribute_tags` AND `event_tags` (anti-join) | `tags` |
| AND tags | `attribute_tags` OR `event_tags` (per tag) | `tags` |

## What to look for when comparing runs

Use `attribute_search_bench_diff.py` to automate the comparison (see
"Comparing branches" above).  The diff tool flags these automatically,
but here is what each signal means:

1. **Hit count changes** — Same query, same data, different code path
   must return the same count.  A change means a behavioural
   regression.  The diff tool marks these with `!!` in the full table
   and lists them in a dedicated section at the top.

2. **Median time shifts in the jo_ section** — These are the canary
   queries.  If `jo_eventtag_bigtype` gets 3x slower, the algorithm
   is probably scanning 780K sha256 rows before filtering by event
   tag.  The diff tool surfaces any query with >= 50% change in the
   FASTER/SLOWER sections.

3. **Relative order within pairs** — For example, `jo_attrtag_deleted`
   should be faster than `jo_broadtag_deleted`.  If they converge, the
   algorithm may be ignoring tag selectivity.  Check the full
   comparison table in the diff output to spot these.

4. **Outlier max times** — A high max with a low median suggests the
   query occasionally hits a cold cache or lock contention.  Multiple
   runs (`BENCH_RUNS=5`) help distinguish real regressions from noise.

5. **Total median time** — The diff tool reports the aggregate at the
   bottom.  A single slow query can dominate the total, so always
   check the per-query breakdown if the total shifts.
