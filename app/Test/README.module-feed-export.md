# Collection feed export validation

Requires PHP ZIP support, the repository's PHPUnit 8.5 dependency and the companion misp-modules `misp_feed`
module. The production flow uses a native cache worker, one-event module requests,
private on-disk staging and an atomic final ZIP. It does not keep a generation
HTTP request open. See the companion module's
[operator guide](https://github.com/MISP/misp-modules/blob/feat/misp-feed-export/documentation/export_mod/misp_feed.md).

The controller/model and disk-writer tests run without a database or network.
Run the full PHP directory, as CI does, to check compatibility with the other
tests' shared framework stubs:

```sh
php app/Vendor/bin/phpunit app/Test/
node app/Test/module_feed_export_ui_test.js
```

For a focused run, use
`php app/Vendor/bin/phpunit --filter '(CollectionModuleExport|ModuleFeedExportTool)Test' app/Test/`.
PHPUnit 8 accepts one positional test path; supplying two filenames does not run
both files. The feed tests use the shared `ClassRegistry::$instances` contract
and restore registry/configuration state after each test.

To include cross-language native ZIP fixtures, generate a one-event
`misp_feed.handler` response with `feed_chunk: true` and set
`MISP_FEED_TEST_PART` to that response's JSON file. The original bounded ZIP
bridge test also accepts `MISP_FEED_TEST_ARTIFACT`.

The reproducible large-feed benchmark uses actual Python serialization and the
actual PHP disk writer. From misp-modules:

```sh
PYTHONPATH=. python tests/benchmark_misp_feed.py --events 5000 --context-kib 64 --parts /tmp/feed-parts.jsonl
```

Then, from MISP:

```sh
php -d max_execution_time=1 app/Test/benchmark_module_feed_export.php /tmp/feed-parts.jsonl 5000 /tmp/feed-benchmark
```

The PHP benchmark disables the execution limit exactly as the production CLI
worker does. It adds a small per-part latency to make the collection take longer
than a web deadline, validates the final manifest/file count and reports archive
size, checksum, elapsed time and PHP peak heap. Use an external process RSS
measurement when comparing full process memory (native libzip allocations are
not included in PHP's heap counter).

Observed on the development environment: 5000 events, 21 attributes each,
361,162,786 bytes of per-event feed data, 194,404,858-byte ZIP. Python took 24.59 s
and peaked at 104,256 KiB RSS (the same peak for 100 events); PHP took 33.45 s,
27,536 KiB peak RSS and 10 MiB peak PHP heap. The final archive contained all 5000
event files plus a combined manifest and hash index. Event bodies, indexes and
ZIP content stay on disk; the selected ID list and ZIP directory still grow with
file count. Real MISP database/network performance and unusually large single
events depend on the deployment.

Job storage is `app/tmp/module_feed_exports`, shared by web and worker processes.
Ready artifacts expire after 24 hours. Use `cake event purgeModuleFeeds` for
scheduled cleanup when no new submissions arrive. Workers must have enough disk
for the uncompressed event files plus the ZIP; configured aggregate and per-event
limits fail cleanly rather than publish a partial feed.
