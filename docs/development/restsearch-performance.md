# Attribute restSearch performance work

Base: MISP 2.5 at `794511eabe96fbed34c76c990cfdc872b801421c`.
Implemented and evaluated on 2026-09-23.

The production changes are submitted as three separate companion PRs:

- [#11161: lean exports and SQL counts](https://github.com/MISP/MISP/pull/11161)
- [#11162: batched correlations and event tags](https://github.com/MISP/MISP/pull/11162)
- [#11163: public cursor pagination](https://github.com/MISP/MISP/pull/11163)

This evidence PR contains their combined integration harness and the standalone
exact-value benchmark. The integration harness and focused test commands below
require all three companion changes; the exact-value benchmark can run on the
base above.

## Changes

Text, cache, hashes and count exporters declare `fetch_requirements`: selected
fields and whether attribute tags, organisations and threat levels are consumed.
The attribute fetcher retains ID, event ID and the composite value needed by
iteration and allowedlists. Its SQL filters, Event/Object joins and ACLs remain
the same. Exporters without a declaration retain their existing complete rows,
including the default JSON contract.

Complex include options and post-filters conservatively retain the full fetch
plan. In particular, warninglists, decay scoring and enabled proposal blocking
continue to receive their existing inputs. A future exporter can opt in without
changing the default behavior of other consumers of `fetchAttributes()`.

Unpaginated count exports use SQL aggregation through the same assembled query
when there are no allowedlist entries or other PHP filtering dependencies. The
controller's unrestricted `limit=0`/`page=1` defaults permit this path. Positive
role/request limits, cursors, unsupported grouping and post-filters retain the
normal filtered count path. The result body remains an integer.

Default and NoAcl correlation engines load two directions and hydrate shared
targets in source batches of 100, preserving each engine's existing permissions
and response structure. OnDemand and custom engines retain their existing
lookup paths. Event tags are loaded for missing event IDs in batches of 100,
including negative cache entries and the existing inherited/exportable flags.
Correlation fanout remains unlimited, as in the existing API; source batching
does not impose a new response limit.

Attribute restSearch accepts `after_id` with a positive `limit` for JSON, text,
cache, hashes and count, in ascending attribute ID order. The cursor advances
using SQL rows before warninglist, decay, proposal and allowedlist removal.
Internal iteration therefore continues through batches with no surviving output
and never passes zero as a chunk limit. Explicit page offsets remain supported.
See [the API documentation](../API_Doc.md) for examples and continuation headers.
`X-Has-More` is conservative: a full scanned page may require an empty final
continuation. It is not a snapshot or a guarantee that further visible rows exist.

## Existing pull requests

The [duplication audit](restsearch-pr-overlap-2026-09-23.md) inspected all 232 open
PRs, 500 recently closed PRs, targeted history searches and relevant diffs. A
pre-publication refresh inspected the current 236 open PRs without finding a
new direct duplicate.
No direct implementation duplicate was found. Existing sightings batching was
preserved. The work extends the existing internal cursor and avoids recreating
the cleanup in [#11135](https://github.com/MISP/MISP/pull/11135), though that PR
touches nearby code and may need a textual rebase. The audit records other
adjacent work and the scope of the search.

## Exact-value SQL experiment

**Decision: retain the production OR query.** A deduplicating ID UNION produced
the same ordered IDs in all 26 cases in each of two index configurations, but
its speed advantage was not consistent. In particular, retaining selective tag
predicates made materializing
the additional candidate set substantially slower in this fixture.

The benchmark invokes the real `generic_add_filter()`, `fetchAttributes()` ACL
and condition construction, and `MysqlExtended` SQL renderer. It compares the
existing `value1 IN (...) OR value2 IN (...)` with an ID UNION joined to the same
outer filters, joins, projection and ordering. Existing tag `EXISTS`/`IN`
predicates are retained. Those tag strategies are separate from the candidate
ID UNION being evaluated here.

MariaDB 10.11.19, 100,000 synthetic attributes, 2,000 events and objects each;
MISP schema column types and nullability, clustered `PRIMARY KEY (id)`,
`utf8mb3_unicode_ci` value collation and 255-character value index prefixes.
The standard-index run follows `db_schema.json`; a second run adds the optional
historical `deleted` index. Five alternating timed repetitions after a discarded
warmup; query cache disabled. Measurements are server-side `ANALYZE FORMAT=JSON`
execution times on a shared development host, not end-to-end API latency.
Concurrent host activity was not controlled; use the individual samples when
assessing variability. The pinned CakePHP revision
`1c2da20cbe3f1e2a91458fe9a017823b7273fdac` produces the same query pairs.

Standard indexes:

| Query | Returned rows | OR median (ms) | UNION median (ms) |
|---|---:|---:|---:|
| 10 exact values, ACL | 1 | 0.339 | 0.444 |
| 100 exact values, ACL | 23 | 3.441 | 2.787 |
| 1,000 exact values, ACL | 236 | 33.147 | 30.501 |
| 1,000 exact values, admin | 466 | 22.169 | 20.553 |
| Common value, admin, limit 500 | 500 | 17.370 | 12.787 |
| Common value, admin, all matches | 942 | 36.657 | 20.945 |
| Composite second values, admin | 94 | 2.640 | 2.741 |
| Common value with tag EXISTS | 12 | 3.779 | 9.082 |
| Common value with tag IN | 12 | 3.553 | 6.913 |

Cases also cover missing values, duplicate inputs, a value in both columns,
case/accent-insensitive matching and collisions beyond an index prefix.
See [all measurements and access paths](restsearch-value-profile-2026-09-23.json)
and [an actual rendered query pair](restsearch-value-query-example.sql).
These results do not establish a universal winner: production distributions,
MySQL versions, concurrency, storage and other filter combinations can differ.
No production schema changes or automatic query heuristic were introduced.

The legacy-index run exposes a separate existing problem. For 1,000 exact
values, OR scanned 94,118 rows using the `deleted` index: medians were
1,496.867 ms with ACLs and 1,002.199 ms as admin. UNION selected 496 candidate
IDs using the value indexes: 30.242 ms and 20.152 ms respectively. Without that
legacy index, the corresponding OR medians were 33.147 ms and 22.169 ms.
`fetchAttributes()` supplies `ignoreIndexHint`, but the current
[`MysqlExtended::renderStatement()`](../../app/Model/Datasource/Database/MysqlExtended.php)
SELECT template omits it. This pre-existing renderer issue is documented here;
it was not changed as part of the requested OR/UNION profiling. That distinction
matters: the roughly 50-fold improvement in the legacy-index case is not a
general speedup attributable to replacing OR on a standard installation.

To reproduce, provision a **fresh disposable MariaDB database** named
`misp_restsearch_test`, install its CLI and PHP CLI, and initialise CakePHP:

```sh
python3 tests/benchmarks/restsearch_value_lookup.py \
  --cake app/Lib/cakephp/lib/Cake \
  --mysql-command 'mariadb --database=misp_restsearch_test' \
  --output /tmp/restsearch-profile --rows 100000 --repeats 5
```

The runner refuses a different database or an existing fixture unless
`--reuse-fixture` is explicitly supplied. Reuse validates primary keys,
nullability, value index prefixes and the legacy-index setting; it assumes the
generated synthetic rows have not been changed. To include the
optional historical index in a fresh run, pass `--legacy-deleted-index`.
The runner never drops existing tables.
The output contains the fixture SQL, exact query pairs, plans and timing samples.
Authentication can be supplied through the MariaDB client's normal configuration.

## Verification

Run the focused PHPUnit files separately because their framework stubs differ:

```sh
php app/Vendor/bin/phpunit app/Test/RestSearchExportPlanTest.php
php app/Vendor/bin/phpunit app/Test/RestSearchCountTest.php
php app/Vendor/bin/phpunit app/Test/AttributeBatchRelationsTest.php
php app/Vendor/bin/phpunit app/Test/AttributeRestSearchCursorTest.php
php app/Vendor/bin/phpunit app/Test/RestResponseCursorCorsTest.php
php app/Vendor/bin/phpunit app/Test/RestResponseSandboxInlineFileTest.php
```

The final focused run passed **95 tests / 308 assertions** on PHP 8.3.33 and
PHPUnit 8.5.55. PHP syntax and OpenAPI YAML checks also passed.

The independent real-ORM fixture in
`tests/benchmarks/RestSearchSqlIntegration.php` exercises CakePHP, Containable and
MariaDB for projection/count ACL equivalence and legacy/batch correlation
parity. Its **120 assertions passed** with the pinned CakePHP revision and
MariaDB 10.11.19. Run its disposable container launcher with locally available
PHP (PDO MySQL) and MariaDB images:

```sh
MISP_PHP_IMAGE=your-local-php-image \
  bash tests/benchmarks/RestSearchSqlIntegration.sh app/Lib/cakephp/lib/Cake
```

It supplements the focused tests; it does not boot the complete MISP web
application, optional plugins or external services. High-fanout memory stress
and production end-to-end throughput remain installation-specific measurements.
