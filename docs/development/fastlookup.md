# Persistent fastLookup index

`POST /attributes/fastLookup` returns a scoped envelope containing visible event
IDs and matching IP ranges/parent domains. See [API examples](../API_Doc.md#fastlookup).
The feature is disabled by default and requires Redis. It does not expire IOC
postings or cache permissions. The old `maxAge` request parameter and
`MISP.fast_lookup_cache_ttl` setting have been removed.

## Configuration and operation

| Setting | Default | Effect |
| --- | --- | --- |
| `MISP.fast_lookup_enabled` | `false` | Allow the API. Existing indexes continue tracking mutations while the endpoint is disabled. |
| `MISP.fast_lookup_attribute_types` | IPs, domains, hostnames and common hashes, including relevant composite types | Comma-separated MISP type names. Changing membership requires a new backfill. |
| `MISP.fast_lookup_published_only` | `true` | Include only published events; changing this policy requires a backfill. |
| `MISP.fast_lookup_max_values` | `10000` | Positive maximum submitted values per request. Changing this limit does not rebuild the index. |

The exact default types are `domain`, `domain|ip`, `hostname`, `hostname|port`,
`ip-src`, `ip-dst`, `ip-src|port`, `ip-dst|port`, `md5`, `sha1`, `sha256`, `sha512`,
`filename|md5`, `filename|sha1`, `filename|sha256`, `filename|sha512` and
`malware-sample`. Responses report the actual configured list.

Use **Administration → Fast lookup index** (`/servers/fastLookup`) to inspect
scope, progress and per-type attribute/token membership counts and Redis memory.
With background jobs enabled, the dashboard queues rebuild/resume jobs. Otherwise,
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

Build progress reports processed/total events, percentage and an estimate derived
from elapsed time and completed events. The estimate is null until progress is
available; varying event sizes can make it change substantially. During backfill,
pending updates, failed writes or scope changes, the API returns HTTP 503 and no
`results` field. Clients should honor `Retry-After` and retry when ready.

## Storage and consistency

`FastLookupConfig` owns membership settings and the database/configuration
fingerprint. `FastLookupValueTool` maps database values and request values into
compact exact/network/domain tokens. `FastLookupIndex` owns Redis data;
`FastLookupIndexManager` owns SQL checkpoints, backfill and mutation delivery.

The namespace is derived from database identity. Type-partitioned sharded Redis
hashes use 17-byte binary fields (one kind byte plus a 128-bit digest), with compact
decimal attribute ID postings. There is no Redis key per IOC and no plaintext IOC
in Redis keys or fields. Hash collisions only broaden candidates: SQL/value
revalidation prevents false matches. Reverse event manifests permit removing,
replacing or retrying event updates. Reads use direct batched hash lookups, without
scanning the index for each requested IOC. Writes and cleanup are bounded.

Internal rows in the existing `admin_settings` table contain the SQL checkpoint and
per-event dirty revision tokens; no schema migration or runtime dependency is
added. Mutation callbacks use the model's existing database connection and join
its transaction. They never commit a caller-owned transaction. Hard attribute/event deletion and
quick-delete child removal wrap deletion and the dirty marker in one Cake transaction.
Workers own their
transactions and lock the checkpoint while changing Redis. Dirty acknowledgements
are conditional on the observed revision, preserving concurrent changes.

Every mutation callback takes a shared lock on the checkpoint row, and a worker
holds the exclusive lock for its whole batch. A writer therefore never reads an
empty generation while a rebuild is committing, so it never skips its dirty
marker. No writer holds an uncommitted dirty marker while the worker decides
readiness, so the scan-complete and empty-queue check is authoritative. As a
result, attribute and event writes wait for at most one worker batch. Size that wait with the `batchSize` argument, and
run large backfills with a small batch size or outside peak hours.

The durable pending revision is recorded before a Redis batch begins. It is
committed together with a distinct next revision. Redis only receives the next
revision after the batch completes, so a Redis snapshot taken partway through a
batch never matches the SQL checkpoint. Readiness
requires agreement between the SQL and Redis generation/revision, no incomplete
write and no dirty events. This detects interrupted writes and a Redis instance
restored from an older backup. Backfill traverses event IDs with a high-water mark,
then replays the dirty queue before declaring readiness. Lookup repeats the
readiness fence after checking live SQL permissions. Missing bucket sentinels,
corruption, restored state and Redis failures refuse results. Rebuild a missing or
stale index; resume an interrupted generation when its checkpoint remains valid.

Redis persistence and a suitable memory policy are operationally important for an
index without expiry. Evicted or lost keys cause unavailability, requiring repair
or rebuild. Initial scope changes and rebuilds deliberately make lookups unavailable
until the replacement is complete. This implementation does not maintain an older
servable generation during rebuild.

## Matching and authorization

Exact candidates use database collation weights for supported MySQL/MariaDB
`utf8`, `utf8mb3` and `utf8mb4` Unicode/general/binary collations. Database version,
column collations and normalization version participate in the membership
fingerprint. Unsupported collations/dialects and empty/ignorable weight cases
use indexed SQL exact discovery after the complete-index readiness gate, retaining
SQL equality semantics. They may be slower. Candidate revalidation always uses
SQL equality; no approximation of authorization is stored in Redis.

IP containment masks CIDR host bits and probes canonical prefixes for IPv4 and
IPv6, including `/0` and single-address ranges. Domain suffix matching uses label
boundaries and only domain-bearing attributes (`domain`, `domain|ip`). Hostname
attributes are exact-only. No external DNS lookup is made. Current SQL rows supply
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

Per-type measured memory includes posting buckets, ownership bookkeeping, event
registries and reverse manifests. Shared metadata is reported separately. Counts
are indexed attributes and token memberships, not unique IOC strings. The dashboard
polls inexpensive status every five seconds; memory scans are explicit and
timestamped. Redis `MEMORY USAGE` support is required for memory measurements;
unsupported measurement is shown as unavailable, never replaced by an invented
estimate. Statistics and rebuild operations require site administrator access.

## Verification

The repository includes isolated PHPUnit tests for input/configuration, matching,
HTTP responses, admin access, model hooks, lifecycle and CLI behavior, plus real
Redis and SQL integration runners. PHPUnit child processes isolate framework
doubles so test discovery cannot replace other suites' global classes.

```bash
app/Vendor/bin/phpunit app/Test/
MISP_FASTLOOKUP_LIFECYCLE_SOCKET=/path/to/disposable/mysql.sock app/Vendor/bin/phpunit --filter 'FastLookup(DeletionIntegration|IndexLifecycleIntegration|SqlCollation)Test' app/Test/
bash tests/benchmarks/FastLookupIntegration.sh /path/to/cakephp/lib/Cake
php tests/benchmarks/FastLookupIndexRedisContract.php /path/to/disposable/redis.sock
```

Use disposable databases and Redis only. The shell runner starts socket-only
MariaDB/Redis containers with no published ports and uses existing local images.
Its defaults are `localhost/misp-live:tmp`, `mariadb:10.11` and `redis:7`; override
`MISP_PHP_IMAGE`, `MISP_MARIADB_IMAGE`, `MISP_REDIS_IMAGE` as needed. Large SIEM
workloads should be benchmarked with the deployment's type distribution, ACLs,
event sizes and database/Redis latency. Fixture timings are not production capacity
estimates.
