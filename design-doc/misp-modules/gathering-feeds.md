# Gathering ZIP feed ingestion

Gathering modules generate a standard MISP feed directory containing
`manifest.json` and one `<event-uuid>.json` per event, ZIP it, and return it as a
binary artifact. MISP streams the ZIP to a private local workspace, extracts it,
and reuses the existing single-event feed importer. No ad hoc Feed row is inserted
or deleted, so repeated pulls do not consume feed IDs. The configured gathering
feed is retained for scheduling and parameters.

Companion producer/framework: https://github.com/MISP/misp-modules/pull/1026.

## Setup and example

Enable `Plugin.Gathering_services_enable`, configure the module service URL/port,
and enable an individual producer such as `Plugin.Gathering_withaname_enabled`.
Classic and Overmind feed forms discover enabled contract-version-2 producers
through normal organisation restrictions. Keep feed caching disabled. No schema
migration is required; `Feed.input_source=misp-modules` and the existing JSON
settings store the module name and parameters.

```json
{
  "Feed": {
    "name": "WithAName configurations", "provider": "WithAName",
    "input_source": "misp-modules", "source_format": "misp",
    "enabled": true, "caching_enabled": false, "distribution": "0",
    "settings": {"gathering": {"module": "withaname", "parameters": {
      "date_from": "2023-06-24", "date_to": "2023-06-25",
      "max_events": 0, "deduplicate_entries": true
    }}}
  }
}
```

WithAName's end date is exclusive. Without explicit dates it collects yesterday
and today in UTC. `max_events=0` selects every matching snapshot; a positive
budget fails if exceeded. Source timestamps are interpreted as UTC. Further
producers have their own parameter schemas and need no converter code in MISP.

## Generation and ingestion lifecycle

1. `Module::queryGathering()` verifies type, enablement, restrictions and version,
   then submits `{"module":"...","operation":"prepare","parameters":{},"config":{}}`
   through `/query`. The response is a small job descriptor, never an event bundle.
2. MISP polls `GET /gathering/jobs/<job_id>` until ready/failed, using separate
   short HTTP requests. Generation runs independently of those request timeouts.
3. Ready metadata provides archive size and SHA256. MISP constructs the download
   path on its configured module service and streams `/feed.zip` to
   `APP/tmp/gathering-<random identifier>/feed.zip`. Arbitrary remote URLs are not
   accepted. PHP's curl and zip extensions are required.
4. MISP verifies the ZIP size and SHA256, then extracts flat feed entries in
   64 KiB chunks to the workspace's `feed/` directory. It rejects path traversal,
   symlinks, encrypted entries, duplicate filenames, corrupt CRCs and size-budget
   violations. The ZIP is deleted immediately after successful extraction.
5. The Feed model makes an in-memory local connector using the configured feed's
   import policy and private workspace path. It iterates event filenames, loads
   one event, and calls the existing feed preparation and save methods. Existing
   filters, distribution settings and UUID/timestamp add/edit/skip rules apply.
   It never loads the whole manifest or an event/action list for this import.
6. A finally block removes the workspace and sends DELETE for the module job.
   Failure and timeout paths also clean up. The persistent configured feed remains.
   Module retention handles an unreachable cleanup request; a lock-aware local
   janitor removes abandoned workspaces from killed workers after two days.

The previous unmerged version-1 JSON bundle contract is replaced by version 2.
This removes its 100-event / 32 MiB collection ceiling. Event-content memory is
proportional to the largest event, with ZIP-directory and producer source-listing
metadata still proportional to file count. Standard manifest previews can still
load manifest metadata; the ingestion path does not. Allow disk space for the
ZIP and expanded feed together. Gathering imports return a boolean status for
the existing scheduled and interactive callers: true when no events failed,
false when any event failed. Bounded aggregate counts are available separately
through `Feed::getGatheringImportCounts()` for the latest attempt; no per-event
result array is retained.

## Long generation and operator budgets

Use MISP's existing background feed jobs for long collections; PHP worker and
queue execution limits must permit the intended duration. `Plugin.Gathering_timeout`
and per-module execution timeouts cover submission, not the whole generation.
`Plugin.Gathering_generation_timeout` controls MISP's polling budget (default
86400 seconds). A timeout requests cancellation and cleans up the workspace.

The producer has bounded background workers/queue, cancellation checks, artifact
retention and configurable generation/disk budgets; see its gathering guide.
With durable producer storage, ready ZIPs survive module service restarts.
Interrupted generation is reported failed and partial files are removed; it is
retried from the source rather than resumed mid-file. Persistent UUIDs and
revision timestamps make overlapping windows and retries safe. The producer's
revision index must survive upgrades and restarts.

MISP defaults to 10 GiB compressed and expanded archive budgets and 256 MiB per
file. Operators can change `Plugin.Gathering_max_archive_bytes`,
`Plugin.Gathering_max_expanded_bytes` and `Plugin.Gathering_max_event_bytes`.
These are disk/input budgets, not full-feed memory allocations.

## Draft scope and checks

WithAName emits one event per snapshot, `ddos-config` objects for target rules,
and a canonical JSON attachment preserving random definitions. Victim targets
explicitly disable IDS export and correlation. Normal MISP merge semantics apply;
there are no deletion tombstones. Daily aggregation, feed caching/lookup,
protected-event signatures and schema-rendered parameter forms remain follow-ups.

Tests cover lifecycle polling, checksum/path/type validation, cleanup and timeout,
normal add/edit/skip ingestion, and the absence of transient Feed-row operations.
A 160-event fixture over 40 MiB imports in a separate process under a 40 MiB PHP
memory limit. The Python writer has a matching regression under an 8 MiB traced
peak. Cross-repository validation uses a real Python-generated ZIP:

```sh
./app/Vendor/bin/phpunit app/Test/GatheringFeedTest.php
GATHERING_TEST_ARCHIVE=/path/to/feed.zip ./app/Vendor/bin/phpunit app/Test/GatheringFeedTest.php
```

This remains a draft pending browser and database-backed scheduled-worker
acceptance tests. Requests and generation status are separate: the existing
module query statistics measure job submission, while job status reports the
actual generation outcome.
