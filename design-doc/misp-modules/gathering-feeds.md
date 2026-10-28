# Gathering modules as feed sources (initial integration)

This draft adds a generic misp-modules input source to the existing MISP-format
feed importer. Source-specific collection and conversion live in misp-modules;
MISP retains its manifest filters, UUID/timestamp comparison, event merge logic,
distribution settings and background feed jobs. No database migration is needed:
`Feed.input_source` stores `misp-modules` and existing JSON settings hold the
module name and parameters.

## Setup

1. Install the companion misp-modules gathering implementation.
2. Give that service durable revision storage using
   `MISP_MODULES_GATHERING_STATE_DIR`. Preserve it across restarts and upgrades.
3. Enable `Plugin.Gathering_services_enable`, configure its URL/port, then enable
   the individual producer, initially `Plugin.Gathering_withaname_enabled`.
4. Add a feed with input source **MISP modules**, select the gathering module,
   and enter its collection parameters as a JSON object. Both Classic and
   Overmind feed forms discover producers through normal module enablement and
   organisation restrictions. Future gathering producers need no source-specific
   changes in MISP.

Example WithAName parameters (exclusive end date):

```json
{
  "date_from": "2023-06-24",
  "date_to": "2023-06-25",
  "max_events": 20,
  "deduplicate_entries": true
}
```

Omit the dates for WithAName's rolling window from yesterday through today in
UTC. The source filename timestamps are interpreted as UTC by this first module.
Overlapping collection windows are safe: unchanged UUIDs and timestamps are
skipped by the existing feed importer. For historical backfills, use explicit,
bounded date ranges. Nothing advances an implicit checkpoint after a failed run.

REST configuration uses the same feed fields:

```json
{
  "Feed": {
    "name": "WithAName configurations",
    "provider": "WithAName",
    "input_source": "misp-modules",
    "source_format": "misp",
    "enabled": true,
    "caching_enabled": false,
    "distribution": "0",
    "settings": {
      "gathering": {
        "module": "withaname",
        "parameters": {"date_from": "2023-06-24", "date_to": "2023-06-25"}
      }
    }
  }
}
```

The model sets a synthetic `misp-modules://<module>` URL and MISP source format;
this URL is never used for an outbound HTTP request. Service credentials use the
normal per-module settings, separately from the feed's collection parameters.

## Contract and import path

`Module::queryGathering()` checks the module's type, enablement, organisation
restriction and `gathering_version` before calling `/query` on the Gathering
service. Normal per-module and family execution timeouts apply. The request is:

```json
{"module":"withaname","operation":"prepare","parameters":{},"config":{}}
```

The version 1 answer contains `gathering_version: 1`, `source_format: "misp"`,
`manifest` and `events`. The manifest is exactly the contents of `manifest.json`;
each `events[uuid]` is the contents of the standard `<uuid>.json` file with an
`Event` wrapper. The complete response is limited to 100 events and 32 MiB.

`GatheringFeedTool` rejects failed, oversized, incomplete or inconsistent
responses before any event is imported. The Feed model holds one generated
snapshot for manifest and event reads during a job. Starting another import job
clears that snapshot, including when a queue worker reuses the model. Existing
`getNewEventUuids()` and event import methods consume these files directly.

The WithAName module emits one event per source snapshot and one `ddos-config`
object per target rule, with deterministic UUIDv5 identifiers. These describe
victim targets, so the module explicitly disables IDS export and correlation.
The original configuration's information, including random substitution rules,
is preserved in a canonical JSON attachment.

## Draft scope and review points

- Collection is synchronous and bounded. Too many source events fail the run;
  callers must narrow the date range. There is no pagination or automatic
  historical checkpoint yet.
- Parameter entry is generic JSON. The module exposes a parameter schema, but
  rendering schema-driven controls is deferred.
- Feed preview and import are supported. Feed caching/lookup and protected-event
  signatures are deferred; caching must remain disabled.
- Generated timestamps depend on the producer's persistent revision index.
  Losing that index can prevent historical corrections from being selected.
- Source corrections use normal MISP feed merge semantics. The initial producer
  assigns changed rule versions new object UUIDs and emits no deletion
  tombstones, so old rules may remain after a historical correction.
- Unit tests cover producer discovery, restrictions, bundle validation, snapshot
  reuse, and the existing add/update/skip decision. A cross-repository test can
  consume a real Python-produced response through `GATHERING_TEST_BUNDLE`.
  Full browser and database-backed worker acceptance testing remains before
  marking this MISP PR ready for review.

Run the pure contract tests with:

```sh
./app/Vendor/bin/phpunit app/Test/GatheringFeedTest.php
GATHERING_TEST_BUNDLE=/path/to/python-response.json ./app/Vendor/bin/phpunit app/Test/GatheringFeedTest.php
```
