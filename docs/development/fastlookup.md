# Attribute fastLookup: integration and performance validation

`POST /attributes/fastLookup` maps literal submitted IOC strings to all distinct
visible event IDs. Enable `MISP.fast_lookup_enabled` explicitly to expose the
endpoint. The request is `{"value":["example.org"]}`; `maxAge` is an optional
integer from 0 through the configured `MISP.fast_lookup_cache_ttl`. Omitting it
uses that setting. An empty result is `{}`. Event IDs are decimal
strings sorted numerically, and output keys preserve the original input spelling.

The lookup compares either stored component (`value1` or `value2`) using SQL
equality and the column's collation. Composite strings are not reconstructed;
`example.org|443` only matches if it is itself a stored component. `%`, `_`, `!`
and `&&` have no search-operator meaning. IPv6 inputs are compressed before
comparison. There are no implicit `to_ids`, tag, allowed-list, or publication
filters beyond standard visibility checks, including `MISP.unpublishedprivate`.

## Cache and resource contract

Redis stores complete candidate attribute ID sets, including negative results,
independently of the requesting user. Every positive response runs SQL again to
check the current value, attribute deletion, event existence, and standard
event/attribute/object visibility. A permission revocation or changed/deleted
attribute therefore cannot remain visible because of a cache hit. Sharing-group
membership is evaluated for the current request.

`MISP.fast_lookup_cache_ttl` configures the cache duration in seconds. Its default
is **10800 seconds (180 minutes / 3 hours)**; administrators can set a nonnegative
integer, with `0` disabling caching. New matching attributes can take up to this
duration to enter the cached candidate set. This applies to both previous misses
and additional matches for an existing IOC. Expiry is measured from the start of
discovery, not from the last hit. The optional request `maxAge` defaults to the
configured duration and can narrow that age: for example, `maxAge:60` accepts
candidates younger than one minute when the configured duration is at least 60
seconds. `maxAge:0` bypasses cache reads and writes entirely, and values above the
configured duration are rejected.
Unavailable, unsupported, or malformed Redis entries fall back to SQL. Redis
contains no final, authorized response cache.

Requests are limited to 1,000 values, 4,096 UTF-8 bytes per value, and 1 MiB of
combined input. SQL batches contain at most 100 values. Candidate sets larger
than 10,000 IDs are returned completely when within the request budget, but are
not cached. A request consuming more than 100,000 candidate/result rows fails
explicitly; it does not publish truncated results or partial new cache entries.
This budget includes cached candidate IDs and discovery/live result rows, so a
large request can exceed it before reaching 100,000 distinct response events.

## Running the isolated harness

The runner requires Podman and local PHP, MariaDB, and Redis images. It never
pulls images, publishes ports, or uses an application database. Each invocation
creates uniquely named containers with `--network=none`, a disposable MariaDB
data directory, private Unix-socket directories, and a unique database. Cleanup
removes containers and temporary directories on completion or interruption.

```sh
bash tests/benchmarks/FastLookupIntegration.sh /path/to/cakephp/lib/Cake
```

The validation environment used CakePHP commit `1c2da20`, matching the pinned
fixture used for the earlier SQL benchmark. The harness is self-contained on
this branch and does not import that benchmark or require its changes. Default
images are `localhost/misp-live:tmp`, `docker.io/library/mariadb:10.11`, and
`docker.io/library/redis:7`; override them with `MISP_PHP_IMAGE`,
`MISP_MARIADB_IMAGE`, and `MISP_REDIS_IMAGE`. PHP needs PDO MySQL and phpredis.

The PHP entry point accepts the Cake directory, disposable MySQL socket and
disposable Redis socket. Prefer the shell runner: the PHP test intentionally
flushes Redis database 13 and must never receive a production Redis socket.

Fixtures use column types from `db_schema.json`, with nullable unrelated fields,
and the production `value1`/`value2` collation from `INSTALL/MYSQL.sql`
(`utf8mb3_unicode_ci`). The value-prefix, event-ID, and deleted indexes are
present. Standard Cake models, `MysqlExtended`, `buildConditions`, and SQL joins
execute against MariaDB. Unrelated behaviors are disabled, and sharing-group
membership comes from a fixture provider. Each simulated request creates a new
attribute model, matching the lifetime of permission-condition caches in HTTP
requests.

The harness checks:

- Cold, warm, and fresh parity for normal, site-admin, sync, organization-admin,
  publisher, read-only, owning-organization, and unrelated-organization users,
  including private/unpublished events and
  event/attribute/object sharing groups.
- Both value components, duplicate events, numeric IOC keys, IPv6 spelling,
  SQL case/accent/trailing-space equality, literal operator characters, and
  accepted four-byte UTF-8 input against the production column character set,
  and a stored four-byte match after migrating only one component to utf8mb4.
- Immediate exclusion after attribute/value/permission/event changes, plus
  the permitted delay for positive and negative cache additions.
- Real Redis TTL bounds, no hit refresh, narrower `maxAge`, real expiry,
  malformed payloads, and a disconnected phpredis connection.
- More than 100 inputs, more than 10,000 candidates, and explicit resource
  failures for more than 100,000 distinct events/candidates.
- Actual lookup SQL counts: cold discovery plus live visibility, and only the
  candidate-constrained live visibility query after warming.

The JSON report includes assertion count, runtime versions, fixture row count,
lookup query counts, median/p95 timings, and limitations. Timings cover model
construction and SQL/Redis calls but exclude HTTP, authentication, startup and
fixture creation. They compare repeated 100-value lookups and never-before-seen
100-value misses against `maxAge:0`, and also measure repeated negative hits,
with the same indexed synthetic background
data. These measurements describe this local fixture, not production throughput
or concurrency. A cache miss can cost more than a fresh lookup; judge deployment
benefit using the actual hit ratio, data distribution, latency and concurrency.

## Configurable-duration validation

The updated isolated runner passed **208 checks** with the configurable duration.
Real Redis tests verify the default 10800-second lifetime, custom 120- and
300-second lifetimes, and rejection of older positive and negative entries when
the setting is reduced. A zero setting performs fresh SQL without updating or
creating cache entries; request ages above the configured limit are rejected.
The existing eight-user visibility matrix still uses two cold lookup statements
and one warm lookup statement. The model-level limitations below still apply.

## Observed local run (2026-09-23, original 60-second cache duration)

The following measurements were taken before cache duration became configurable,
using the original 60-second duration. The full runner passed **158 assertions**
with PHP 8.3.33, MariaDB 10.11.19-MariaDB-ubu2204, Redis 7.4.11, and 110,151 attribute
rows. All eight user categories used two lookup SQL statements when cold and one
when warm. The warm
statement was checked for its candidate-ID restriction and event-ID projection;
the global value-discovery query was absent. Repeated cached misses needed no
lookup SQL. These counts exclude model/schema metadata queries.

Each timing scenario below ran 40 sequential requests of 100 values. The repeated
mixed scenario contained 50 matches and 50 misses; the miss scenarios contained
only absent values. The same indexed background fixture remained present.

| Scenario | Median (ms) | p95 (ms) | Lookup SQL/request |
| --- | ---: | ---: | ---: |
| Repeated mixed values, warm cache | 60.327 | 215.069 | 1 |
| Repeated mixed values, `maxAge:0` | 178.935 | 315.714 | 1 |
| New misses, cache enabled | 32.633 | 119.140 | 1 |
| New misses, `maxAge:0` | 163.065 | 402.752 | 1 |
| Repeated misses, warm cache | 4.625 | 8.331 | 0 |

An independent rerun passed the same 158 assertions with the same versions,
fixture row count, and query counts. Its median/p95 times in milliseconds were
182.839/609.057 for repeated mixed values with a warm cache,
282.642/711.287 for mixed values with `maxAge:0`, 39.162/121.363 for new misses
with caching, 150.654/277.180 for fresh new misses, and 4.242/38.409 for repeated
cached misses. Both mixed-value runs had lower median and p95 times with a warm
cache, but the substantial run-to-run variation reinforces that these are local
fixture measurements and support no production performance claim.

The spread between median and p95 reflects this shared local environment. The
fresh path includes visibility joins even for absent values; discovery can avoid
those joins for a miss. Thus the two one-statement miss scenarios execute
different SQL, despite having equal query counts. Neither the relative timings
nor their absolute values establish performance for a production dataset.

The run also verified the Unicode regression against the original utf8mb3 value
columns, a stored match with only `value2` migrated to utf8mb4, and cache namespace
separation across the schema change. In that run, the TTL test observed an initial
expiry no longer than 60 seconds, then shortened it to exercise real expiry
without waiting a full minute. HTTP authentication, endpoint routing, rate limiting,
real sharing-group membership queries, concurrent traffic, and production table
statistics are outside this model-level harness.
