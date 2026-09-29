# Persistent fastLookup index

`POST /attributes/fastLookup` returns a scoped envelope containing visible event
IDs and matching IP ranges/parent domains. See [API examples](../API_Doc.md#fastlookup).
The feature is disabled by default and requires Redis. It does not expire IOC
postings or cache permissions. The old `maxAge` request parameter and
`MISP.fast_lookup_cache_ttl` setting have been removed.

## Requirements

Fast lookup needs Redis 8 or Redis Stack for the RedisBloom module (`BF.*`
commands). Without it the endpoint answers HTTP 503 with `Fast lookup requires
the RedisBloom module (Redis 8 or Redis Stack).`. When Redis cannot be reached
at all, the 503 message says so instead (`The IOC index is unavailable: Redis
cannot be reached. Its SQL queue has been retained.`), so an outage is not
mistaken for a missing module. The
index only supports MySQL/MariaDB.

## Configuration and operation

| Setting | Default | Effect |
| --- | --- | --- |
| `MISP.fast_lookup_enabled` | `false` | Allow the API. Existing indexes continue tracking mutations while the endpoint is disabled. |
| `MISP.fast_lookup_attribute_types` | IPs, domains, hostnames and common hashes, including relevant composite types | Comma-separated MISP type names. Changing membership requires a new backfill. |
| `MISP.fast_lookup_published_only` | `true` | Include only published events; changing this policy requires a backfill. |
| `MISP.fast_lookup_max_values` | `10000` | Positive maximum submitted values per request. Changing this limit does not rebuild the index. |
| `MISP.fast_lookup_false_positive_rate` | `0.001` | Target Bloom filter false-positive rate, `0.0001`-`0.05`. Part of the index fingerprint: changing it requires a rebuild. |

The exact default types are `domain`, `domain|ip`, `hostname`, `hostname|port`,
`ip-src`, `ip-dst`, `ip-src|port`, `ip-dst|port`, `md5`, `sha1`, `sha256`, `sha512`,
`filename|md5`, `filename|sha1`, `filename|sha256`, `filename|sha512` and
`malware-sample`. Responses report the actual configured list.

Some types can never be added to the scope, because an exact log lookup makes no
sense for them. `FastLookupConfig::EXCLUDED_TYPES` lists them, and a setting
that names one is rejected:

- free text and payloads: `comment`, `text`, `other`, `hex`, `anonymised`,
  `email-body`, `email-header`, `attachment`;
- rules, patterns and key material: `snort`, `suricata`, `bro`, `zeek`, `yara`,
  `sigma`, `stix2-pattern`, `kusto-query`, `pattern-in-file`,
  `pattern-in-traffic`, `pattern-in-memory`, `filename-pattern`,
  `pgp-public-key`, `pgp-private-key`, `dkim-signature`, `cortex`,
  `email-mime-boundary`;
- scalars and dates, which would create huge postings: `float`, `integer`,
  `counter`, `boolean`, `size-in-bytes`, `port`, `datetime`,
  `whois-creation-date`, `http-method`, `mime-type`, `process-state`, `gender`;
- fuzzy hashes, which only make sense for similarity matching: `ssdeep`, `tlsh`,
  `impfuzzy`, `vhash` and their `filename|` composites.

Use **Administration → Fast lookup index** (`/servers/fastLookup`) to inspect
scope, progress and the filter status (tokens inserted, capacity, stale entries
and configured false-positive rate), always shown with a warning once the
filter holds more entries than its capacity; Redis memory statistics are shown
on request. With background jobs enabled, the dashboard queues rebuild/resume jobs. Otherwise,
run these commands as the MISP service user from the installation root:

```bash
app/Console/cake Admin rebuildFastLookup
app/Console/cake Admin resumeFastLookup
app/Console/cake Admin processFastLookup
```

`rebuildFastLookup [jobId] [batchSize=100]` starts a fresh generation and completes
the scan. `resumeFastLookup [jobId] [batchSize=100]` continues an interrupted scan
and pending mutations. `processFastLookup [jobId] [batchSize=25]` processes pending
mutations. Job IDs are optional CLI integration details; normal manual invocation
needs no arguments.

Every event publication is covered by Event save callbacks, including direct
published-field saves. Attribute saves/deletes and event deletion also mark their
events for refresh. Dispatch is deferred until request shutdown so workers see
committed child attributes. Background workers process the queue; without
background jobs a bounded batch is processed at shutdown. Schedule
`processFastLookup` regularly when background jobs are disabled, and after an
outage use `resumeFastLookup` to drain work. An uncleared queue refuses lookups;
it never quietly serves a partial index.

Build progress reports processed/total attributes (`processed_attributes` and
`total_attributes`), percentage and an estimate derived from elapsed time and
processed attributes. The total is an estimate taken before the scan, including
deleted and unpublished attributes, until the scan completes. The estimate is
null until progress is available; an uneven spread of in-scope attributes over
attribute IDs can make it change substantially. During backfill,
pending updates, failed writes or scope changes, the API returns HTTP 503 and no
`results` field. Clients should honor `Retry-After` and retry when ready.

## Storage and consistency

`FastLookupConfig` owns membership settings and the database/configuration
fingerprint. `FastLookupValueTool` maps database values and request values into
compact exact/network/domain tokens. `FastLookupFilter` owns Redis data;
`FastLookupIndexManager` owns SQL checkpoints, backfill and mutation delivery.

Redis holds one RedisBloom filter per generation (key prefix
`misp:fast_lookup:bf1:<sha256(namespace)>:`, no TTL). The filter is a single
`NONSCALING` `BF.RESERVE` holding every exact, range and domain token, sized to
`max(1,000,000, 1.5 × 2 × in-scope attributes)`: two tokens per attribute
headroom at 1.5x, with a 1,000,000-token floor. `BF.MEXISTS`/`BF.MADD` only
prove absence; a token the filter cannot rule out still goes to SQL for exact
values, or reads its postings for range/domain values, which SQL then
revalidates. Range and domain attribute IDs live in listpack-sized bucket
hashes (about 64 fields per bucket); a posting over 64 bytes moves out to an
overflow key `<bucket>:<hex token>` holding `<generation>|<ids>`, capped at
8 MiB and 500,000 IDs, so one popular value never inflates its bucket. Edits
and deletions leave stale filter entries behind — the filter only grows, so a
removed or changed value's old token is never cleared — and SQL revalidation
drops them from results. A rebuild is scheduled automatically once the filter
has inserted at least 80% of its capacity, or once it holds at least 10,000
tokens with 10% or more of them stale; run `Admin rebuildFastLookup` nightly
where automatic scheduling is not enough.

Internal rows in the existing `admin_settings` table contain the SQL checkpoint and
per-event dirty revision tokens; no schema migration or runtime dependency is
added. Mutation callbacks use the model's existing database connection and join
its transaction. They never commit a caller-owned transaction. Hard attribute/event deletion and
quick-delete child removal wrap deletion and the dirty marker in one Cake transaction.
Workers take the checkpoint row `FOR UPDATE` only for their short drain,
checkpoint and activation transactions; the rebuild scan itself runs outside
that lock, using its own attribute cursor. Dirty acknowledgements are
conditional on the observed revision, preserving concurrent changes.

Whole-batch exclusivity between workers is a Redis lease (`SET NX PX` with a
random token; released by a compare-and-delete on that token), not the row
lock, so it holds across every Galera node and every MISP server sharing the
index, not just one process. The lease has a 60 s TTL (`WORKER_LEASE_TTL_MS`)
and is renewed before every scan chunk and before progress is recorded. Each
scan query covers at most 20,000 attribute IDs past the cursor
(`SCAN_WINDOW`) and returns at most 2,000 rows (`SCAN_CHUNK_SIZE`), so the rows
one query examines stay bounded however sparse the in-scope attributes are
(excluded types, deleted attributes, unpublished events), and no single query
can outlast the lease.
`rebuildFastLookup`/`resumeFastLookup` wait up to 5 s (`WORKER_LOCK_WAIT`) for
a busy lease before giving up for that invocation. Request-shutdown dispatch
(`processPending`) makes a single, non-waiting attempt and leaves its markers
queued if another worker holds the lease; a web request that marks an event
dirty therefore never waits for a worker. A worker that loses its lease
mid-scan (its renewal fails) stops immediately without recording progress or
a failure state — the SQL progress already committed stays valid, and
whichever worker holds the lease next continues from it.

Every mutation callback takes a shared lock on the checkpoint row. A writer
therefore never reads an empty generation while a drain, checkpoint or
activation transaction is committing, so it never skips its dirty marker. No
writer holds an uncommitted dirty marker while a worker decides readiness, so
the scan-complete and empty-queue check is authoritative. As a result,
attribute and event writes wait only for a drain, checkpoint or activation
transaction, never for the rebuild scan itself. The `batchSize` argument still
sizes that wait for a drain of many dirty events; it no longer bounds scan
length, since the scan runs outside the row lock.

The durable pending revision is recorded before a Redis batch begins. It is
committed together with a distinct next revision. Redis only receives the next
revision after the batch completes, so a Redis snapshot taken partway through a
batch never matches the SQL checkpoint. Readiness
requires agreement between the SQL and Redis generation/revision, no incomplete
write and no dirty events. This detects interrupted writes and a Redis instance
restored from an older backup. Backfill traverses attribute IDs up to a
high-water mark taken when the generation is reserved, one ID window per query;
a window that returns fewer rows than asked moves the cursor to the window's
end, and the scan is complete once the cursor reaches the high-water mark. It
then replays the dirty queue before declaring readiness. Lookup repeats the
readiness fence after checking live SQL permissions. Every Redis operation first
checks the filter key, the generation state and the bucket sentinels, so an
evicted or missing key fails closed rather than reporting absence. A later
rebuild runs beside the live generation, fenced by its own attribute cursor,
and replaces the live generation atomically once it catches up: lookups keep
being served by the old generation apart from the short activation batch
(activation sets Redis `ready=0` until the batch commits, and lookups answer
503 meanwhile), and only a broken or interrupted build fails. The first activation after a rebuild also removes the
previous format's `misp:fast_lookup:v3:` keys and its `fastLookupIndex:state:v2`
state row.

Each generation records which IP prefix lengths its range tokens use: `p4`
(33 characters) and `p6` (129 characters) hold a `0`/`1` flag per length, and
`pv` counts how often either mask changed. A new length's flag is set, and
`pv` incremented, in its own script before any token of that length becomes
visible, so every visible range token's length is always in the mask. A lookup
reads the masks once, probes only the flagged lengths, and passes `pv` along
with its range tokens; if the masks changed meanwhile it re-reads them once,
and a second change answers 503. Requests without range tokens never check
`pv`. A generation built by an earlier release has no masks: it is served with
every prefix length, and adding to it never creates them. Masks present on
only some of the three fields, or malformed, make the generation corrupt.

Reserving a generation with masks stamps the namespace metadata schema as
`bloom-2`; earlier releases know only `bloom-1` and fail closed on it rather
than adding ranges without updating the masks. `bloom-1` namespaces keep being
served until the next rebuild replaces their generation. All MISP servers
sharing one Redis must run the same release: after a downgrade the older
release treats the index as invalid and rebuilds it from scratch, and so does
the newer release after upgrading again.

Redis persistence and a suitable memory policy are operationally important: no
fastLookup key expires except the worker lease. Evicted or lost keys cause
unavailability, requiring repair or rebuild. Initial scope changes make
lookups unavailable until the first generation finishes building; a rebuild of
an already-live index does not, since lookups keep being served by the current
generation apart from the short activation batch that swaps the new one in.
A rebuild resets the Redis namespace, or drops the live generation from the
SQL checkpoint, only when Redis itself reports the index metadata or a
generation as missing or invalid (for example an evicted filter). A timeout,
`BUSY` reply or other transport error never counts as a lost index: that
rebuild attempt fails and the live generation keeps serving. The lease key,
`misp:fast_lookup:bf1:<sha256(namespace)>:worker`, is the one exception: it
carries the 60 s TTL described above, and its expiry between batches, or after
a crashed worker, is normal operation, not an index failure.

## Matching and authorization

Exact candidates use database collation weights for supported MySQL/MariaDB
`utf8`, `utf8mb3` and `utf8mb4` Unicode/general/binary collations. Database version,
column collations and normalization version participate in the membership
fingerprint. Unsupported collations/dialects use indexed SQL exact discovery
after the complete-index readiness gate, retaining SQL equality semantics; they
may be slower. Candidate revalidation always uses SQL equality; no
approximation of authorization is stored in Redis.

An input whose collation weight, with trailing pad weights stripped, is empty
for a component — whitespace only, or only characters the collation ignores
such as U+200B ZERO WIDTH SPACE or U+00A0 NO-BREAK SPACE — never matches that
component. The same rule applies when indexing, so a stored attribute whose
value consists entirely of ignorable characters is not findable through
fastLookup; search for it with the regular attribute search instead.

Lookups run in batches of at most 1,000 values or 4 MiB of SQL-quoted values,
whichever is reached first. Weights of ASCII-only values are
derived in PHP from a per-collation table of the 128 ASCII code points, fetched
once per lookup in the first weights query. That query also weighs a probe
string covering every ASCII code point; if the table does not reproduce it, the
table is rejected, a warning is logged and SQL weights are used for that
collation. Non-ASCII or unrepresentable values get their weights from one wide
single-row query per batch, and later all-ASCII batches issue no weights query.
For each batch, one `candidates()` call answers every token, and each
component (`value1`, `value2`) is resolved by a single `IN (…)` query holding
one representative value per distinct weight. Rows come back with their own
weight and are mapped to every input that shares it; a row whose weight
matches no input fails the request rather than being dropped, since SQL
equality is the correctness bar. Columns with a collation outside the
supported list keep one equality query per value, combined with `UNION`.

IP containment masks CIDR host bits and probes canonical prefixes for IPv4 and
IPv6, including `/0` and single-address ranges. Only the prefix lengths some
indexed range actually uses are probed (see the prefix masks below), so a
request for one address usually costs a handful of range tokens rather than
33 (IPv4) or 129 (IPv6). Domain suffix matching uses label
boundaries and only domain-bearing attributes (`domain`, `domain|ip`). Hostname
attributes are exact-only. The port half of `ip-src|port`, `ip-dst|port` and
`hostname|port` is never indexed or matched: a bare port would match most of those
attributes, and one popular port would exceed the posting limit at scale. No external DNS lookup is made. Current SQL rows supply
returned range/domain strings only after permission and scope checks.

Live queries apply `MispAttribute::buildConditions`, current publication/type scope,
nondeleted attributes and an existing event. Standard event, attribute, object and
sharing-group ACLs remain authoritative. Every missing/invisible input is omitted.
Responses contain only IDs and visible matched ranges/domains, never attribute
records. HTTP responses are noncacheable.

## Limits and observability

Requests have a configurable value count, 4096-byte per-value limit, 16 MiB combined
string limit and a 100000 candidate/result-row budget. Overflows produce errors
without partial results. Very popular tokens are bounded to 500000 IDs and 8 MiB per
posting; exceeding a storage bound prevents readiness rather than truncating the
index. Use a narrower type scope if a deployment exceeds those storage limits.

Batching keeps every weights query and `IN (…)` list well under a 16 MiB
`max_allowed_packet`. The per-value `UNION` path used for unsupported
collations is larger; a statement the server refuses fails the request rather
than returning partial results.

### Sizing

`tests/benchmarks/FastLookupScale.php` loads synthetic attributes across the
default types into homogeneous events, backfills the index, and measures
Redis memory growth (total and per key class), build time and lookup
throughput. It classifies every index key it finds as the Bloom filter, its
global/generation metadata, listpack postings or overflow postings, so Redis
memory can be split between the filter itself and the range/domain postings
rather than reported as one number. With `FL_SQL_BASELINE` set, each lookup
batch also runs the same values through a plain-SQL search (the strongest
`LIKE`/range form, without the filter), so filtered and unfiltered timings are
reported side by side for hits, misses and range/domain expansion matches.
`measured_false_positive_rate` compares filter membership for values known to
be absent against the true absence, giving an observed rate to set next to the
configured `MISP.fast_lookup_false_positive_rate`.

Measured at 1.7M attributes (17 default types, 100,000 attributes each,
10,000-value lookup requests per type; MariaDB 10.11.19, Redis 8.2.10, PHP
8.3.33, one 6-core host): Redis grew by about **9.2 bytes per attribute**
(filter 9,165,968 bytes in 1 shared key at a 5,100,000-token capacity with
1,813,731 tokens inserted; range/domain postings 4,960,128 bytes across 3,516
keys, plus 147.8 KB of overflow postings in 2 keys). A full rebuild took
**43.9 s**. The measured false-positive rate over the sampled absent values
was 0, against an estimated rate of about 2.55e-07 at that fill level
(configured target 0.001 — the filter is far under capacity at 1.7M
attributes).

For context, the per-type postings index this replaced measured about 161
bytes per attribute and a 1,175 s full rebuild at the same 1.7M-attribute
scale: the Bloom filter is roughly 17.5× smaller and, after bounding the
rebuild scan to primary-key reads in 20,000-ID windows (2,000-row chunks per
query, so a sparse stretch or the final partial window can no longer run past
the worker lease), about 26.8× faster to build.

Because the filter's capacity is `max(1,000,000, 1.5 × 2 × in-scope
attributes)`, its size scales with the in-scope attribute count rather than
with events or duplicate values; postings scale with the number of distinct
range/domain values and how many attribute IDs each carries. Linearly
extrapolating the measured 1.7M-attribute point to 100M attributes (×58.82,
not an independent measurement): build time projects to about **2,582 s
(~43.0 minutes, ~0.72 hours)**, and Redis memory to about **920 MB
(~0.86 GiB)**, versus the old postings index's projected ~16.1 GB at the same
scale (about 17.5× smaller). RedisBloom/Redis/MariaDB behavior at that scale
— key-count effects, the scan's I/O pattern against a much larger table —
may not stay linear, so treat this as an order-of-magnitude estimate, not a
commitment.

Redis `MEMORY USAGE` support is required for memory measurements; unsupported
measurement is shown as unavailable, never replaced by an invented estimate.
The dashboard polls inexpensive status every five seconds; memory scans are
explicit and timestamped. Statistics and rebuild operations require site
administrator access. These are single-host synthetic figures, not capacity
guarantees; a deployment's real type mix, duplicate rate, event sizes and
database/Redis latency will differ.

#### Latency at 1.7M attributes

Same data set and host as above, 10,000-value requests, median of three
warm runs. Each cell is the previous per-100-value implementation, then the
current batched one. Results were byte-identical between the two for every
type and request kind. Expansions apply only to types with a range or domain
form.

| Type | Hits (s) | Ratio | Misses (s) | Expansions (s) | Plain SQL hits (s) |
|---|---:|---:|---:|---:|---:|
| `domain` | 9.76 → 2.20 | 0.23 | 1.12 → 0.65 | 2.58 → 1.75 | 0.66 |
| `domain\|ip` | 8.89 → 2.18 | 0.24 | 1.17 → 0.71 | 3.20 → 1.69 | 0.61 |
| `hostname` | 10.43 → 1.99 | 0.19 | 1.63 → 1.00 | — | 1.15 |
| `hostname\|port` | 10.39 → 2.16 | 0.21 | 1.52 → 0.89 | — | 1.02 |
| `ip-src` | 10.08 → 1.21 | 0.12 | 2.91 → 0.53 | 1.17 → 0.45 | 2.21 |
| `ip-dst` | 11.79 → 1.31 | 0.11 | 3.06 → 0.48 | 1.15 → 0.26 | 1.97 |
| `ip-src\|port` | 10.75 → 1.24 | 0.12 | 3.37 → 0.49 | 1.41 → 0.24 | 2.05 |
| `ip-dst\|port` | 10.55 → 1.31 | 0.12 | 2.80 → 0.61 | 1.14 → 0.24 | 2.13 |
| `md5` | 10.75 → 1.40 | 0.13 | 1.33 → 0.49 | — | 0.93 |
| `sha1` | 10.36 → 1.53 | 0.15 | 1.03 → 0.48 | — | 0.87 |
| `sha256` | 9.96 → 1.66 | 0.17 | 1.14 → 0.55 | — | 0.87 |
| `sha512` | 10.72 → 2.16 | 0.20 | 1.23 → 0.71 | — | 0.96 |
| `filename\|md5` | 9.28 → 1.39 | 0.15 | 1.13 → 0.43 | — | 0.71 |
| `filename\|sha1` | 9.23 → 1.45 | 0.16 | 1.22 → 0.46 | — | 0.76 |
| `filename\|sha256` | 9.52 → 1.48 | 0.15 | 1.12 → 0.52 | — | 0.85 |
| `filename\|sha512` | 9.60 → 1.82 | 0.19 | 1.51 → 0.61 | — | 0.95 |
| `malware-sample` | 9.93 → 1.44 | 0.15 | 1.15 → 0.44 | — | 0.79 |

All-hit requests take 0.11–0.24 of their previous time. Misses and expansions
are faster on every type. The last column is a batched plain-SQL `IN` lookup
with the same ACL and no Redis. It is faster than the index for hash, filename,
hostname and domain hits: the index pays for itself on IP containment (network ranges)
and on misses, which never reach the database.

## Verification

The repository includes isolated PHPUnit tests for input/configuration, matching,
HTTP responses, admin access, model hooks, lifecycle and CLI behavior, plus real
Redis and SQL integration runners. PHPUnit child processes isolate framework
doubles so test discovery cannot replace other suites' global classes.

```bash
app/Vendor/bin/phpunit app/Test/
MISP_FASTLOOKUP_LIFECYCLE_SOCKET=/path/to/disposable/mysql.sock app/Vendor/bin/phpunit --filter 'FastLookup(DeletionIntegration|IndexLifecycleIntegration|SqlCollation)Test' app/Test/
bash tests/benchmarks/FastLookupIntegration.sh /path/to/cakephp/lib/Cake
php tests/benchmarks/FastLookupFilterRedisContract.php /path/to/disposable/redis.sock
FL_PER_TYPE=100000 php tests/benchmarks/FastLookupScale.php /path/to/cakephp/lib/Cake /path/to/disposable/mysql.sock /path/to/disposable/redis.sock
```

`FastLookupFilterRedisContract.php` (replacing `FastLookupIndexRedisContract.php`)
needs Redis 8 or Redis Stack, since it exercises the RedisBloom `BF.*` commands
directly. The shell runner's default Redis image (`redis:8`) bundles RedisBloom;
if you override `MISP_REDIS_IMAGE`, point it at an image that provides
RedisBloom rather than plain Redis.

Use disposable databases and Redis only. The shell runner starts socket-only
MariaDB/Redis containers with no published ports and uses existing local images.
Its defaults are `localhost/misp-live:tmp`, `mariadb:10.11` and `redis:8`; override
`MISP_PHP_IMAGE`, `MISP_MARIADB_IMAGE`, `MISP_REDIS_IMAGE` as needed. Large SIEM
workloads should be benchmarked with the deployment's type distribution, ACLs,
event sizes and database/Redis latency. Fixture timings are not production capacity
estimates.
