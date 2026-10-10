# Event index pull pagination

The pull index must advance independently of the number of events left after
protected-event filtering or local blocklist/timestamp filtering. An empty
response page can have later eligible events.

## Default compatibility path

The first numbered page is fetched with an empty ETag validator to obtain a fresh
`X-Result-Count`. The count establishes the page range for this enumeration.
Subsequent page bodies can be revalidated with their cached ETags. Short and empty
responses do not end enumeration before that range has been covered. Cached
counts from earlier pulls are never used to establish a new scan's page range.

For remotes without a valid count, or remotes that ignore page numbers, the
client uses the historical unpaginated minimal-index request and emits a sync
debug message. That fallback has the historical whole-index memory cost on both
peers. It cannot acquire cursor-query performance without upgrading the remote.

The upgraded server applies instance-key eligibility before counting and
numbered-page queries. An `EXISTS` predicate avoids duplicate events when several
matching keys exist, and a missing/unusable instance key excludes protected
events. Existing authorization, sharing-group and pull filters remain in effect.
Ordinary requests still return the existing event array and `X-Result-Count`.
This also fixes pagination for unchanged older pulling clients.

## Optional cursor optimization

Enable `MISP.event_index_cursor_pagination` on the pulling instance to use cursor
pagination when the remote advertises `event_index_cursor_v1`. The setting is
disabled by default. Non-supporting peers continue through the compatibility
path. Servers advertise the capability only to sync users; the new response
format requires an explicit `sync_cursor=1`, a minimal JSON index and sync
permissions.

An initial request has `minimal=1`, `published=1`, `sync_cursor=1` and `limit=N`.
Continuation requests use the same filters and `cursor=<next_cursor>`. Other
sort/page parameters do not control cursor queries: order is always event ID
ascending. Limits are positive integers, capped at 10000.

```json
{
  "events": [],
  "pagination": {
    "version": 1,
    "limit": 10000,
    "after": 10000,
    "upper_bound": 830000,
    "has_more": true,
    "next_cursor": "<signed cursor>"
  }
}
```

The first request obtains a high-water event ID under the query's existing
access/filter conditions. Every page uses `id > after AND id <= upper_bound`,
with `LIMIT N+1`, and no `OFFSET` or total count. The extra row establishes
continuation and is removed before the page is processed. `after` is the final
candidate ID consumed, before protected events are removed. Therefore an empty
event array can still advance. Only `has_more=false` ends the scan.

Cursors contain the scan bounds and a canonical request/user scope, authenticated
with HMAC-SHA256 using the instance security salt. Tokens are deterministic for
unchanged state so they do not prevent ETag hits. They provide integrity, not
confidentiality or authorization: every request re-applies access rules. Invalid
cursors, changed request context and non-advancing continuation fail explicitly.

## Cache behavior

The v2 Redis namespace stores ETag, response body and legacy count in one
compressed, atomic entry, keyed by server, URL, authentication-key digest and
canonical request. Cursor pulls reuse cache slots by scan position across
high-water bounds: the full bound remains in the response body/ETag and is always
revalidated. This avoids multiplying page entries for each newly captured bound.
Old split-cache entries are not reused; they expire normally.
All entries retain a 24-hour lifetime and require remote revalidation.

The cursor envelope's complete serialized body participates in the ETag,
including continuation metadata when `events=[]`. A `304` restores that complete
envelope. Missing/corrupt cache data triggers a request with an empty validator;
an unexpected `304` without cached content is retried once and then fails.
Both normal and file-backed `304` responses retain their ETag header.

Conditional requests save response transfer and client parsing of new payloads.
They still execute the remote query/filter pipeline to validate the ETag; this
change does not introduce a reliable early database-cache invalidation mechanism.
Changing the high-water bound changes cursor envelopes and invalidates their
ETags, even when their event lists are unchanged. Reused cache slots bound Redis
growth across such scans, but cannot preserve those bandwidth savings. The
optional cursor mode trades this revalidation cost for avoiding deep offsets and
repeated total counts; the default legacy mode retains body-only page validators.

## Limits and verification

The cursor scan is bounded, not a transaction snapshot. New higher-ID events are
considered on the next pull. Events whose filter membership changes behind the
cursor may also require the next pull. Numbered-page compatibility scans retain
the effects of concurrent inserts/deletions on offset pagination.

Page hydration is bounded by the configured size, capped at 10000, with one extra
lookahead row. The accumulated UUID result still grows with the number of pull
targets. Complex access/tag filters can dominate query time; inspect query plans
on representative data before adding indexes.

Run `app/Vendor/bin/phpunit app/Test/EventIndexPaginationTest.php`, or run the
isolated production-method harness directly with
`php app/Test/fixtures/event_index_sync.php`. The scenarios exercise filtered and
empty pages, fresh/cache parity, malformed continuation, compatibility fallback,
old-client response shape and cache misses/corruption.
