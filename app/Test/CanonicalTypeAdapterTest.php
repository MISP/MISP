<?php
/**
 * CanonicalTypeAdapter unit tests (PRD §5.5 keystone).
 *
 * Pure PHPUnit — follows the convention used by WidgetSchemaTest and
 * the rest of app/Test/: no CakePHP bootstrap, no DB. The adapter is
 * a pure data-shape translator with one framework touchpoint
 * (`App::uses` at file load to pull in WidgetSchema); we stub the
 * `App` class so the require succeeds, then load WidgetSchema
 * directly via require_once.
 */

if (!class_exists('App')) {
    class App
    {
        public static function uses($class, $path) {
            // No-op stub — tests provide WidgetSchema via require_once below.
        }
    }
}

require_once __DIR__ . '/../Vendor/autoload.php';
require_once __DIR__ . '/../Lib/Dashboard/Tools/WidgetSchema.php';
require_once __DIR__ . '/../Lib/Dashboard/Tools/CanonicalTypeAdapter.php';

use PHPUnit\Framework\TestCase;

class CanonicalTypeAdapterTest extends TestCase
{
    // -------- translateTimeWindow() ISO 8601 happy paths --------

    public function testTimeWindowIsoDayDuration(): void
    {
        $this->assertSame('7d',   CanonicalTypeAdapter::translateTimeWindow('P7D'));
        $this->assertSame('1d',   CanonicalTypeAdapter::translateTimeWindow('P1D'));
        $this->assertSame('30d',  CanonicalTypeAdapter::translateTimeWindow('P30D'));
        $this->assertSame('365d', CanonicalTypeAdapter::translateTimeWindow('P365D'));
    }

    public function testTimeWindowIsoWeekDurationExpandsToDays(): void
    {
        $this->assertSame('7d',  CanonicalTypeAdapter::translateTimeWindow('P1W'));
        $this->assertSame('14d', CanonicalTypeAdapter::translateTimeWindow('P2W'));
        $this->assertSame('28d', CanonicalTypeAdapter::translateTimeWindow('P4W'));
    }

    public function testTimeWindowIsoHourDurationConvertsToSeconds(): void
    {
        $this->assertSame(3600,  CanonicalTypeAdapter::translateTimeWindow('PT1H'));
        $this->assertSame(43200, CanonicalTypeAdapter::translateTimeWindow('PT12H'));
        $this->assertSame(86400, CanonicalTypeAdapter::translateTimeWindow('PT24H'));
    }

    // -------- translateTimeWindow() passthrough paths --------

    public function testTimeWindowAllTimeSentinelPassesThrough(): void
    {
        $this->assertSame('-1', CanonicalTypeAdapter::translateTimeWindow('-1'));
        $this->assertSame(-1,   CanonicalTypeAdapter::translateTimeWindow(-1));
    }

    public function testTimeWindowLegacyDaysFormPassesThrough(): void
    {
        // Existing saved configs still have "Nd" string — handler() parses
        // it directly. The adapter must not re-parse.
        $this->assertSame('7d',  CanonicalTypeAdapter::translateTimeWindow('7d'));
        $this->assertSame('30d', CanonicalTypeAdapter::translateTimeWindow('30d'));
        $this->assertSame('1d',  CanonicalTypeAdapter::translateTimeWindow('1d'));
    }

    public function testTimeWindowIntegerSecondsPassThrough(): void
    {
        $this->assertSame(604800, CanonicalTypeAdapter::translateTimeWindow(604800));
        $this->assertSame(0,      CanonicalTypeAdapter::translateTimeWindow(0));
        $this->assertSame(1,      CanonicalTypeAdapter::translateTimeWindow(1));
    }

    public function testTimeWindowNullStaysNull(): void
    {
        $this->assertNull(CanonicalTypeAdapter::translateTimeWindow(null));
    }

    public function testTimeWindowUnrecognizedShapesPassThrough(): void
    {
        // Anything the adapter doesn't know how to translate goes through
        // unchanged so the legacy handler's empty()-fallback or partial
        // parse path can handle it.
        $this->assertSame('garbage', CanonicalTypeAdapter::translateTimeWindow('garbage'));
        $this->assertSame('',        CanonicalTypeAdapter::translateTimeWindow(''));
        $this->assertSame('P7',      CanonicalTypeAdapter::translateTimeWindow('P7')); // missing unit
        $this->assertSame('PT5M',    CanonicalTypeAdapter::translateTimeWindow('PT5M')); // minutes not supported
    }

    public function testTimeWindowNonScalarPassesThrough(): void
    {
        // Bool / array / object aren't ISO 8601 — passthrough so the
        // handler's own type-check decides what to do.
        $this->assertTrue(CanonicalTypeAdapter::translateTimeWindow(true));
        $this->assertFalse(CanonicalTypeAdapter::translateTimeWindow(false));
        $this->assertSame([1, 2], CanonicalTypeAdapter::translateTimeWindow([1, 2]));
    }

    // -------- translate() driven off $schema --------

    public function testTranslateLeavesConfigUntouchedWhenNoSchema(): void
    {
        $widget = new stdClass();
        $config = ['time_window' => 'P7D', 'threshold' => 10];
        $this->assertSame($config, CanonicalTypeAdapter::translate($widget, $config));
    }

    public function testTranslateRoutesTimeWindowKeyByType(): void
    {
        $widget = new stdClass();
        $widget->schema = [
            'time_window' => ['type' => 'time_window'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, ['time_window' => 'P7D']);
        $this->assertSame(['time_window' => '7d'], $out);
    }

    public function testTranslateRoutesByTypeNotKey(): void
    {
        // RecentSightingsWidget declares time_window under the key `last`.
        $widget = new stdClass();
        $widget->schema = [
            'last' => ['type' => 'time_window'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, ['last' => 'PT12H']);
        $this->assertSame(['last' => 43200], $out);
    }

    public function testTranslatePassesThroughScalarTypes(): void
    {
        // bool/int/enum/string types don't have canonical translation —
        // their values stay as-is.
        $widget = new stdClass();
        $widget->schema = [
            'threshold'  => ['type' => 'int'],
            'over_time'  => ['type' => 'bool'],
            'label'      => ['type' => 'string'],
        ];
        $config = ['threshold' => 10, 'over_time' => true, 'label' => 'foo'];
        $this->assertSame($config, CanonicalTypeAdapter::translate($widget, $config));
    }

    public function testTranslateIgnoresKeysWithoutSchemaEntry(): void
    {
        $widget = new stdClass();
        $widget->schema = ['time_window' => ['type' => 'time_window']];
        $out = CanonicalTypeAdapter::translate($widget, [
            'time_window' => 'P14D',
            'blocklist_orgs' => ['A', 'B'], // not in schema — untouched
        ]);
        $this->assertSame('14d', $out['time_window']);
        $this->assertSame(['A', 'B'], $out['blocklist_orgs']);
    }

    public function testTranslateInjectsDefaultsForMissingKeys(): void
    {
        $widget = new stdClass();
        $widget->schema = [
            'time_window' => ['type' => 'time_window', 'default' => 'P7D'],
            'threshold'   => ['type' => 'int',         'default' => 10],
        ];
        $out = CanonicalTypeAdapter::translate($widget, []);
        $this->assertSame('7d', $out['time_window']); // injected + translated
        $this->assertSame(10,   $out['threshold']);   // injected, scalar untouched
    }

    public function testTranslateDoesNotOverwriteExplicitValuesWithDefaults(): void
    {
        $widget = new stdClass();
        $widget->schema = [
            'time_window' => ['type' => 'time_window', 'default' => 'P7D'],
        ];
        // User explicitly set a different value — default does not win.
        $out = CanonicalTypeAdapter::translate($widget, ['time_window' => 'P30D']);
        $this->assertSame('30d', $out['time_window']);
    }

    public function testTranslateHonorsExplicitNullValue(): void
    {
        // Null is an explicit user choice (the key is present in config),
        // not "missing" — the adapter passes it through to the handler
        // unchanged so the handler's empty()-fallback engages.
        $widget = new stdClass();
        $widget->schema = [
            'time_window' => ['type' => 'time_window', 'default' => 'P7D'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, ['time_window' => null]);
        $this->assertNull($out['time_window']);
    }

    public function testTranslatePassesThroughLegacyValues(): void
    {
        // The whole point of decoupling the schema from the canonical wire
        // format in Phase 2: existing saved configs with legacy "Nd"
        // strings keep working without any user-side migration.
        $widget = new stdClass();
        $widget->schema = [
            'time_window' => ['type' => 'time_window'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, ['time_window' => '7d']);
        $this->assertSame('7d', $out['time_window']);

        $out2 = CanonicalTypeAdapter::translate($widget, ['time_window' => 604800]);
        $this->assertSame(604800, $out2['time_window']);
    }

    public function testTranslateIsIdempotent(): void
    {
        // Running the adapter twice on the same config produces the
        // same result — translation is one-shot canonical → legacy and
        // legacy values pass through on the second pass unchanged.
        $widget = new stdClass();
        $widget->schema = [
            'time_window' => ['type' => 'time_window'],
        ];
        $once  = CanonicalTypeAdapter::translate($widget, ['time_window' => 'P7D']);
        $twice = CanonicalTypeAdapter::translate($widget, $once);
        $this->assertSame($once, $twice);
        $this->assertSame('7d', $twice['time_window']);
    }

    public function testTranslateHandlesEmptyConfig(): void
    {
        $widget = new stdClass();
        $widget->schema = [
            'time_window' => ['type' => 'time_window'],
            'threshold'   => ['type' => 'int'],
        ];
        $this->assertSame([], CanonicalTypeAdapter::translate($widget, []));
    }

    public function testTranslateSkipsMalformedSchemaEntries(): void
    {
        // Defensive: a schema entry without a `type` field or with
        // non-array shape is skipped, not error'd. Catalogue-load-time
        // validation (WidgetSchema::validate) is where dev errors surface.
        $widget = new stdClass();
        $widget->schema = [
            'time_window' => ['type' => 'time_window'],
            'bad_no_type' => ['default' => 7],
            'bad_string'  => 'not an array',
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'time_window' => 'P7D',
            'bad_no_type' => 'whatever',
        ]);
        $this->assertSame('7d', $out['time_window']);
        $this->assertSame('whatever', $out['bad_no_type']);
    }

    public function testTranslateHandlesWidgetWithoutSchemaProperty(): void
    {
        $widget = new stdClass();
        $config = ['time_window' => 'P7D'];
        // No schema → no translation; the legacy handler is left to
        // parse the raw value (presumably it doesn't speak ISO 8601,
        // but that's an upstream call to make canonical adoption).
        $this->assertSame($config, CanonicalTypeAdapter::translate($widget, $config));
    }

    // -------- translateDateRange() per-type helper --------

    public function testDateRangeFromToBothPresent(): void
    {
        $this->assertSame(
            ['start_date' => '2026-01-01', 'end_date' => '2026-03-31'],
            CanonicalTypeAdapter::translateDateRange([
                'from' => '2026-01-01',
                'to'   => '2026-03-31',
            ])
        );
    }

    public function testDateRangeToNullEmitsOnlyStartDate(): void
    {
        // PRD §5.5: `to: null` is the "open-ended" sentinel. Widgets
        // like EventEvolutionLineWidget that have only start_date in
        // legacy params engage their own "now" fallback when end_date
        // is absent.
        $this->assertSame(
            ['start_date' => '2025-10-01'],
            CanonicalTypeAdapter::translateDateRange([
                'from' => '2025-10-01',
                'to'   => null,
            ])
        );
    }

    public function testDateRangeFromMissingReturnsNull(): void
    {
        // No usable keys → null so caller leaves config untouched.
        $this->assertNull(CanonicalTypeAdapter::translateDateRange([]));
        $this->assertNull(CanonicalTypeAdapter::translateDateRange(['to' => null]));
    }

    public function testDateRangeEmptyStringsAreSkipped(): void
    {
        // Empty-string from a UI control means "user cleared the
        // field" — treat as absent so the handler's own empty()-
        // fallback engages, not "send a literal empty string as
        // start_date".
        $this->assertSame(
            ['end_date' => '2026-12-31'],
            CanonicalTypeAdapter::translateDateRange([
                'from' => '',
                'to'   => '2026-12-31',
            ])
        );
    }

    public function testDateRangeNonArrayInputReturnsNull(): void
    {
        $this->assertNull(CanonicalTypeAdapter::translateDateRange(null));
        $this->assertNull(CanonicalTypeAdapter::translateDateRange('not a range'));
        $this->assertNull(CanonicalTypeAdapter::translateDateRange(42));
    }

    public function testDateRangeNonStringValuesAreSkipped(): void
    {
        // Defensive: if the value coming in via canonical isn't a
        // string (some malformed save?), pass through cleanly without
        // injecting non-string legacy values.
        $this->assertNull(CanonicalTypeAdapter::translateDateRange([
            'from' => 123,
            'to'   => true,
        ]));
    }

    // -------- translate() routing for date_range --------

    public function testTranslateExpandsDateRangeIntoLegacyKeys(): void
    {
        $widget = new stdClass();
        $widget->schema = [
            'date_range' => ['type' => 'date_range'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'date_range' => ['from' => '2026-01-01', 'to' => '2026-03-31'],
        ]);
        $this->assertSame('2026-01-01', $out['start_date']);
        $this->assertSame('2026-03-31', $out['end_date']);
        // Canonical key passes through too; harmless — handler ignores
        // unknown keys.
        $this->assertSame(
            ['from' => '2026-01-01', 'to' => '2026-03-31'],
            $out['date_range']
        );
    }

    public function testTranslateDateRangeOpenEndedEmitsStartOnly(): void
    {
        $widget = new stdClass();
        $widget->schema = [
            'date_range' => ['type' => 'date_range'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'date_range' => ['from' => '2025-10-01', 'to' => null],
        ]);
        $this->assertSame('2025-10-01', $out['start_date']);
        $this->assertArrayNotHasKey('end_date', $out);
    }

    public function testTranslateDateRangeCanonicalWinsOverLegacy(): void
    {
        // When both canonical and legacy keys are present, canonical
        // wins on translate. The configure form / toolbar are expected
        // to write canonical going forward; stale legacy values
        // alongside should be overwritten on translate.
        $widget = new stdClass();
        $widget->schema = [
            'date_range' => ['type' => 'date_range'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'date_range' => ['from' => '2026-01-01', 'to' => '2026-12-31'],
            'start_date' => '2020-01-01', // stale legacy
            'end_date'   => '2020-12-31',
        ]);
        $this->assertSame('2026-01-01', $out['start_date']);
        $this->assertSame('2026-12-31', $out['end_date']);
    }

    public function testTranslateDateRangeLeavesLegacyAloneWhenNoCanonical(): void
    {
        // Pure legacy config (no canonical date_range key present) —
        // adapter leaves start_date / end_date untouched. The schema
        // declares date_range but the user hasn't migrated yet.
        $widget = new stdClass();
        $widget->schema = [
            'date_range' => ['type' => 'date_range'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'start_date' => '2025-06-01',
            'end_date'   => '2025-09-30',
        ]);
        $this->assertSame('2025-06-01', $out['start_date']);
        $this->assertSame('2025-09-30', $out['end_date']);
        $this->assertArrayNotHasKey('date_range', $out);
    }

    public function testTranslateDateRangeUnderNonConventionalSchemaKey(): void
    {
        // Hypothetical widget that declares date_range under a key
        // other than 'date_range' (e.g. 'window'). The adapter still
        // routes by *type*, not by key name. The resulting legacy
        // keys are still start_date / end_date (the convention used
        // by every existing consumer).
        $widget = new stdClass();
        $widget->schema = [
            'window' => ['type' => 'date_range'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'window' => ['from' => '2026-02-01', 'to' => '2026-02-28'],
        ]);
        $this->assertSame('2026-02-01', $out['start_date']);
        $this->assertSame('2026-02-28', $out['end_date']);
    }

    // -------- translateTagFilter() happy paths --------

    public function testTagFilterIncludeOnlyEmitsLegacyInclude(): void
    {
        $this->assertSame(
            ['include' => ['tlp:', 'misp-galaxy:']],
            CanonicalTypeAdapter::translateTagFilter([
                'include' => ['tlp:', 'misp-galaxy:'],
            ])
        );
    }

    public function testTagFilterExcludeOnlyEmitsLegacyExclude(): void
    {
        $this->assertSame(
            ['exclude' => ['admiralty-scale:', 'sofacy']],
            CanonicalTypeAdapter::translateTagFilter([
                'exclude' => ['admiralty-scale:', 'sofacy'],
            ])
        );
    }

    public function testTagFilterBothIncludeAndExclude(): void
    {
        $this->assertSame(
            ['include' => ['tlp:white'], 'exclude' => ['tlp:red']],
            CanonicalTypeAdapter::translateTagFilter([
                'include' => ['tlp:white'],
                'exclude' => ['tlp:red'],
            ])
        );
    }

    public function testTagFilterCoercesNumericEntriesToStrings(): void
    {
        // JSON round-trips can sneak numeric entries (a tag literally
        // named "123" becomes int 123 after JSON.parse). The adapter
        // coerces to string so legacy `strpos($tag, $include)` doesn't
        // fatal on a non-string argument.
        $result = CanonicalTypeAdapter::translateTagFilter([
            'include' => [123, 'tlp:', true, false],
        ]);
        $this->assertSame(['include' => ['123', 'tlp:', '1', '']], $result);
    }

    public function testTagFilterIgnoresTaxonomiesField(): void
    {
        // taxonomies is a UI-picker hint — no legacy widget consumes
        // it; the translator drops it on the floor. Forward-compat:
        // canonical adopters can read it directly from
        // config['tag_filter']['taxonomies'].
        $this->assertSame(
            ['include' => ['tlp:white']],
            CanonicalTypeAdapter::translateTagFilter([
                'include'    => ['tlp:white'],
                'taxonomies' => ['tlp', 'admiralty-scale'],
            ])
        );
    }

    public function testTagFilterIgnoresMatchEventTagsAndMatchAttributeTags(): void
    {
        // Same forward-compat treatment as taxonomies — neither is
        // consumed by today's tag-filtering widgets.
        $this->assertSame(
            ['exclude' => ['stale']],
            CanonicalTypeAdapter::translateTagFilter([
                'exclude'              => ['stale'],
                'match_event_tags'     => true,
                'match_attribute_tags' => false,
            ])
        );
    }

    // -------- translateTagFilter() empty / null paths --------

    public function testTagFilterEmptyArrayReturnsNull(): void
    {
        $this->assertNull(CanonicalTypeAdapter::translateTagFilter([]));
    }

    public function testTagFilterEmptyIncludeAndExcludeReturnsNull(): void
    {
        // Both lists explicitly empty → no legacy keys derived → null.
        // Caller leaves config untouched (legacy include/exclude
        // survives if it was set via the bottom-tier or a previous
        // canonical write).
        $this->assertNull(CanonicalTypeAdapter::translateTagFilter([
            'include' => [],
            'exclude' => [],
        ]));
    }

    public function testTagFilterIncludeOnlyEmptyDropsThatHalf(): void
    {
        // Only exclude has content → result contains exclude only.
        // include stays out of result so legacy include survives.
        $this->assertSame(
            ['exclude' => ['stale']],
            CanonicalTypeAdapter::translateTagFilter([
                'include' => [],
                'exclude' => ['stale'],
            ])
        );
    }

    public function testTagFilterNonArrayInputReturnsNull(): void
    {
        $this->assertNull(CanonicalTypeAdapter::translateTagFilter(null));
        $this->assertNull(CanonicalTypeAdapter::translateTagFilter('tlp:white'));
        $this->assertNull(CanonicalTypeAdapter::translateTagFilter(42));
        $this->assertNull(CanonicalTypeAdapter::translateTagFilter(true));
    }

    public function testTagFilterNonArrayIncludeFieldIsSkipped(): void
    {
        // include must be an array — a scalar `include: "tlp:white"` is
        // treated as not-set, exclude carries the result.
        $this->assertSame(
            ['exclude' => ['stale']],
            CanonicalTypeAdapter::translateTagFilter([
                'include' => 'tlp:white',
                'exclude' => ['stale'],
            ])
        );
    }

    // -------- translate() integration with tag_filter --------

    public function testTranslateExpandsTagFilterIntoLegacyKeys(): void
    {
        // Widget declares tag_filter on the canonical key 'tag_filter';
        // adapter sprays the legacy include / exclude keys alongside.
        // The canonical wire stays in config for forward-compat
        // (same pattern as date_range).
        $widget = new stdClass();
        $widget->schema = [
            'tag_filter' => ['type' => 'tag_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'tag_filter' => [
                'include' => ['tlp:white', 'tlp:green'],
                'exclude' => ['admiralty-scale:'],
            ],
        ]);
        $this->assertSame(['tlp:white', 'tlp:green'], $out['include']);
        $this->assertSame(['admiralty-scale:'], $out['exclude']);
        // Canonical wire survives in config — handler() ignores
        // unknown keys; future canonical adopters can read it.
        $this->assertSame(
            ['include' => ['tlp:white', 'tlp:green'], 'exclude' => ['admiralty-scale:']],
            $out['tag_filter']
        );
    }

    public function testTranslateTagFilterCanonicalWinsOverLegacy(): void
    {
        // Both canonical tag_filter AND legacy include/exclude set —
        // canonical wins (DD-05 "toolbar pulls write immediately to
        // per-widget configs"). The user's stale legacy values are
        // overwritten by the canonical-derived ones.
        $widget = new stdClass();
        $widget->schema = [
            'tag_filter' => ['type' => 'tag_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'include'    => ['stale_include'],
            'exclude'    => ['stale_exclude'],
            'tag_filter' => [
                'include' => ['fresh_include'],
                'exclude' => ['fresh_exclude'],
            ],
        ]);
        $this->assertSame(['fresh_include'], $out['include']);
        $this->assertSame(['fresh_exclude'], $out['exclude']);
    }

    public function testTranslateTagFilterLeavesLegacyAloneWhenNoCanonical(): void
    {
        // Pure legacy config (no canonical tag_filter key present) —
        // adapter leaves include / exclude untouched. The schema
        // declares tag_filter but the user hasn't migrated yet.
        $widget = new stdClass();
        $widget->schema = [
            'tag_filter' => ['type' => 'tag_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'include' => ['legacy_include'],
            'exclude' => ['legacy_exclude'],
        ]);
        $this->assertSame(['legacy_include'], $out['include']);
        $this->assertSame(['legacy_exclude'], $out['exclude']);
        $this->assertArrayNotHasKey('tag_filter', $out);
    }

    public function testTranslateTagFilterEmptyLeavesLegacyAlone(): void
    {
        // Canonical tag_filter explicitly empty — translator returns
        // null, caller skips, legacy survives. Symmetric with the
        // date_range empty behavior.
        $widget = new stdClass();
        $widget->schema = [
            'tag_filter' => ['type' => 'tag_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'include'    => ['legacy_include'],
            'tag_filter' => ['include' => [], 'exclude' => []],
        ]);
        $this->assertSame(['legacy_include'], $out['include']);
        $this->assertArrayNotHasKey('exclude', $out);
    }

    public function testTranslateTagFilterPartialOverwriteSemantics(): void
    {
        // Canonical sets only include — legacy include is overwritten,
        // legacy exclude survives because canonical exclude is empty.
        $widget = new stdClass();
        $widget->schema = [
            'tag_filter' => ['type' => 'tag_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'include'    => ['stale_include'],
            'exclude'    => ['legacy_exclude'],
            'tag_filter' => ['include' => ['fresh_include']],
        ]);
        $this->assertSame(['fresh_include'], $out['include']);
        $this->assertSame(['legacy_exclude'], $out['exclude']);
    }

    public function testTranslateTagFilterIdempotent(): void
    {
        // Running translate() twice on the same widget+config yields
        // the same shape — the canonical key persists, and the second
        // pass overwrites legacy keys with the same values.
        $widget = new stdClass();
        $widget->schema = [
            'tag_filter' => ['type' => 'tag_filter'],
        ];
        $config = [
            'tag_filter' => [
                'include' => ['tlp:white'],
                'exclude' => ['admiralty-scale:'],
            ],
        ];
        $once  = CanonicalTypeAdapter::translate($widget, $config);
        $twice = CanonicalTypeAdapter::translate($widget, $once);
        $this->assertSame($once, $twice);
    }

    public function testTranslateTagFilterUnderNonConventionalSchemaKey(): void
    {
        // Widget declares tag_filter under a non-conventional key
        // (e.g. 'event_tag_prefilter'). The adapter routes by type,
        // so the canonical → legacy expansion still emits the
        // standard `include` / `exclude` legacy keys. This is the
        // same behavior date_range has — the legacy key names are
        // the widget-handler-side convention, not derived from the
        // schema key.
        $widget = new stdClass();
        $widget->schema = [
            'event_tag_prefilter' => ['type' => 'tag_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'event_tag_prefilter' => ['include' => ['tlp:white']],
        ]);
        $this->assertSame(['tlp:white'], $out['include']);
    }

    // -------- translateOrgMetaFilter() pass-through paths --------

    public function testOrgMetaFilterPassesArrayThrough(): void
    {
        // Canonical and legacy shapes match — translator is identity
        // for valid input.
        $value = [
            'sector' => ['Financial', 'Healthcare'],
            'type'   => ['CSIRT'],
            'local'  => [1],
        ];
        $this->assertSame($value, CanonicalTypeAdapter::translateOrgMetaFilter($value));
    }

    public function testOrgMetaFilterNegationPrefixPreserved(): void
    {
        // The `!` negation prefix is part of the wire format and the
        // legacy widget's parsing logic strips it; the translator
        // must pass it through unmodified.
        $value = ['nationality' => ['!US', 'DE', 'FR']];
        $this->assertSame($value, CanonicalTypeAdapter::translateOrgMetaFilter($value));
    }

    public function testOrgMetaFilterUnknownKeysPreserved(): void
    {
        // Unknown / forward-compat keys pass through; each widget's
        // private $validFilterKeys array filters down to its subset.
        $value = [
            'sector' => ['Financial'],
            'future_key' => ['anything'],
        ];
        $this->assertSame($value, CanonicalTypeAdapter::translateOrgMetaFilter($value));
    }

    public function testOrgMetaFilterEmptyArrayPassesThrough(): void
    {
        $this->assertSame([], CanonicalTypeAdapter::translateOrgMetaFilter([]));
    }

    public function testOrgMetaFilterNullPassesThrough(): void
    {
        // The handler's !empty()-guard skips empty values without
        // exception — translator preserves the null verbatim.
        $this->assertNull(CanonicalTypeAdapter::translateOrgMetaFilter(null));
    }

    public function testOrgMetaFilterNonArrayInputPassesThrough(): void
    {
        // Defensive: scalar values pass through unchanged. The
        // legacy widget's `!empty($options['filter']) && is_array(...)`
        // guard skips them at the handler level.
        $this->assertSame('garbage', CanonicalTypeAdapter::translateOrgMetaFilter('garbage'));
        $this->assertSame(42, CanonicalTypeAdapter::translateOrgMetaFilter(42));
    }

    public function testTranslateOrgMetaFilterUnderConventionalSchemaKey(): void
    {
        // Widget declares org_meta_filter under the conventional key
        // 'filter' (matches the 8 in-tree widgets). The adapter case
        // is no-op pass-through.
        $widget = new stdClass();
        $widget->schema = [
            'filter' => ['type' => 'org_meta_filter'],
        ];
        $value = ['sector' => ['Financial'], 'local' => [0, 1]];
        $out = CanonicalTypeAdapter::translate($widget, ['filter' => $value]);
        $this->assertSame($value, $out['filter']);
    }

    public function testTranslateOrgMetaFilterUnderNonConventionalSchemaKey(): void
    {
        // Widget declares org_meta_filter under 'org_filter' (matches
        // TrendingAttributesWidget's legacy slot name). The adapter
        // pass-through writes back to the same schema key.
        $widget = new stdClass();
        $widget->schema = [
            'org_filter' => ['type' => 'org_meta_filter'],
        ];
        $value = ['type' => ['CIRCL', '!Test']];
        $out = CanonicalTypeAdapter::translate($widget, ['org_filter' => $value]);
        $this->assertSame($value, $out['org_filter']);
    }

    public function testTranslateOrgMetaFilterCoexistsWithTimeWindow(): void
    {
        // Widget declares both — time_window translates (P7D → 7d);
        // org_meta_filter passes through. Both schema entries
        // independently translate per their case.
        $widget = new stdClass();
        $widget->schema = [
            'time_window' => ['type' => 'time_window'],
            'filter'      => ['type' => 'org_meta_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'time_window' => 'P7D',
            'filter'      => ['sector' => ['Financial']],
        ]);
        $this->assertSame('7d', $out['time_window']);
        $this->assertSame(['sector' => ['Financial']], $out['filter']);
    }

    // -------- translateDistributionFilter() unit tests --------

    public function testDistributionFilterIntArrayPassesThrough(): void
    {
        $this->assertSame([0, 1, 2], CanonicalTypeAdapter::translateDistributionFilter([0, 1, 2]));
        $this->assertSame([3], CanonicalTypeAdapter::translateDistributionFilter([3]));
        $this->assertSame([0, 1, 2, 3, 4, 5], CanonicalTypeAdapter::translateDistributionFilter([0, 1, 2, 3, 4, 5]));
    }

    public function testDistributionFilterEmptyArrayPassesThrough(): void
    {
        // Empty array = "no filter applied" (fetchEvent's truthiness
        // guard skips the WHERE clause). Adapter preserves the shape
        // rather than collapsing to null so the widget can distinguish
        // "user cleared the filter" from "user never set it".
        $this->assertSame([], CanonicalTypeAdapter::translateDistributionFilter([]));
    }

    public function testDistributionFilterNullPassesThrough(): void
    {
        $this->assertNull(CanonicalTypeAdapter::translateDistributionFilter(null));
    }

    public function testDistributionFilterScalarIntWrapsToArray(): void
    {
        // Legacy callers (a hand-edited UserSetting blob from before
        // canonical existed) may have stored `'distribution' => 3`
        // as a scalar — fetchEvent accepts both shapes but downstream
        // code is cleaner with a uniform int[]. Wrap.
        $this->assertSame([0], CanonicalTypeAdapter::translateDistributionFilter(0));
        $this->assertSame([3], CanonicalTypeAdapter::translateDistributionFilter(3));
        $this->assertSame([5], CanonicalTypeAdapter::translateDistributionFilter(5));
    }

    public function testDistributionFilterScalarNumericStringWrapsToArray(): void
    {
        // JSON-decoded user input sometimes lands as a string ("3"
        // rather than 3). Coerce + wrap.
        $this->assertSame([3], CanonicalTypeAdapter::translateDistributionFilter('3'));
        $this->assertSame([0], CanonicalTypeAdapter::translateDistributionFilter('0'));
    }

    public function testDistributionFilterMixedArrayCoercesAndDrops(): void
    {
        // Numeric strings / floats coerce to int; non-numeric entries
        // silently drop. Out-of-range values are PRESERVED — see
        // translateDistributionFilter's docblock for why (typo
        // diagnostics > silent filtering).
        $this->assertSame(
            [0, 1, 2],
            CanonicalTypeAdapter::translateDistributionFilter([0, '1', 2.0])
        );
        $this->assertSame(
            [3],
            CanonicalTypeAdapter::translateDistributionFilter([3, 'bad', null, []])
        );
        $this->assertSame(
            [99],
            CanonicalTypeAdapter::translateDistributionFilter([99])
        );
    }

    public function testDistributionFilterUnrecognisedShapesReturnNull(): void
    {
        // Non-array, non-int, non-numeric-string, non-null → null
        // (defensive fallback — fetchEvent skips on truthiness).
        $this->assertNull(CanonicalTypeAdapter::translateDistributionFilter('not-a-number'));
        $this->assertNull(CanonicalTypeAdapter::translateDistributionFilter(true));
        $this->assertNull(CanonicalTypeAdapter::translateDistributionFilter(false));
        $this->assertNull(CanonicalTypeAdapter::translateDistributionFilter(new stdClass()));
    }

    public function testDistributionFilterIsIdempotent(): void
    {
        // Running an already-translated value through again is a
        // no-op — required so the adapter can be called multiple
        // times without surprises (renderWidget + a hypothetical
        // future revalidate hook).
        $once  = CanonicalTypeAdapter::translateDistributionFilter([0, '1', 2]);
        $twice = CanonicalTypeAdapter::translateDistributionFilter($once);
        $this->assertSame($once, $twice);
    }

    public function testTranslateRoutesDistributionFilterByType(): void
    {
        // End-to-end: a widget declares distribution_filter under any
        // schema key; the adapter walks config, finds the matching
        // type, and writes the translated value back under the same
        // schema key (matches the org_meta_filter pattern).
        $widget = new stdClass();
        $widget->schema = [
            'distribution' => ['type' => 'distribution_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'distribution' => [0, '1', 2],
        ]);
        $this->assertSame([0, 1, 2], $out['distribution']);
    }

    public function testTranslateDistributionFilterCoexistsWithTimeWindow(): void
    {
        // Both canonical types translate independently per the
        // switch case — EventStreamWidget's expected shape post-
        // backfill.
        $widget = new stdClass();
        $widget->schema = [
            'time_window'  => ['type' => 'time_window'],
            'distribution' => ['type' => 'distribution_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'time_window'  => 'P7D',
            'distribution' => [1, 2, 3],
        ]);
        $this->assertSame('7d', $out['time_window']);
        $this->assertSame([1, 2, 3], $out['distribution']);
    }

    // -------- translateThreatLevelFilter() unit tests --------
    //
    // Identical shape vocabulary to distribution_filter; the cases
    // below mirror it deliberately so the parity is easy to see in
    // diff form. When analysis_filter lands as the third int-enum-
    // array canonical type, these three test blocks are the right
    // pair to fold into a parametric helper.

    public function testThreatLevelFilterIntArrayPassesThrough(): void
    {
        $this->assertSame([1, 2, 3], CanonicalTypeAdapter::translateThreatLevelFilter([1, 2, 3]));
        $this->assertSame([2], CanonicalTypeAdapter::translateThreatLevelFilter([2]));
        $this->assertSame([1, 2, 3, 4], CanonicalTypeAdapter::translateThreatLevelFilter([1, 2, 3, 4]));
    }

    public function testThreatLevelFilterEmptyArrayPassesThrough(): void
    {
        // Empty array = "no filter applied" — Event::fetchEvent's
        // existing `if (isset($params['threat_level_id']))` enters
        // the branch but Cake's IN coercion on an empty array still
        // produces `IS NULL` (no rows) — slightly different from
        // distribution_filter where empty means "no WHERE". The
        // EventStreamWidget consumer guards this with a defensive
        // !empty() check before passing through.
        $this->assertSame([], CanonicalTypeAdapter::translateThreatLevelFilter([]));
    }

    public function testThreatLevelFilterNullPassesThrough(): void
    {
        $this->assertNull(CanonicalTypeAdapter::translateThreatLevelFilter(null));
    }

    public function testThreatLevelFilterScalarIntWrapsToArray(): void
    {
        // Hand-edited UserSetting may carry `'threat_level' => 2`
        // as a scalar; wrap so downstream SQL has a uniform shape.
        $this->assertSame([1], CanonicalTypeAdapter::translateThreatLevelFilter(1));
        $this->assertSame([2], CanonicalTypeAdapter::translateThreatLevelFilter(2));
        $this->assertSame([4], CanonicalTypeAdapter::translateThreatLevelFilter(4));
    }

    public function testThreatLevelFilterScalarNumericStringWrapsToArray(): void
    {
        $this->assertSame([3], CanonicalTypeAdapter::translateThreatLevelFilter('3'));
        $this->assertSame([1], CanonicalTypeAdapter::translateThreatLevelFilter('1'));
    }

    public function testThreatLevelFilterMixedArrayCoercesAndDrops(): void
    {
        $this->assertSame(
            [1, 2, 3],
            CanonicalTypeAdapter::translateThreatLevelFilter([1, '2', 3.0])
        );
        $this->assertSame(
            [2],
            CanonicalTypeAdapter::translateThreatLevelFilter([2, 'bad', null, []])
        );
        // Out-of-range preserved on the array path (typo diagnostics).
        $this->assertSame(
            [99],
            CanonicalTypeAdapter::translateThreatLevelFilter([99])
        );
    }

    public function testThreatLevelFilterUnrecognisedShapesReturnNull(): void
    {
        $this->assertNull(CanonicalTypeAdapter::translateThreatLevelFilter('not-a-number'));
        $this->assertNull(CanonicalTypeAdapter::translateThreatLevelFilter(true));
        $this->assertNull(CanonicalTypeAdapter::translateThreatLevelFilter(false));
        $this->assertNull(CanonicalTypeAdapter::translateThreatLevelFilter(new stdClass()));
    }

    public function testThreatLevelFilterIsIdempotent(): void
    {
        $once  = CanonicalTypeAdapter::translateThreatLevelFilter([1, '2', 3]);
        $twice = CanonicalTypeAdapter::translateThreatLevelFilter($once);
        $this->assertSame($once, $twice);
    }

    public function testTranslateRoutesThreatLevelFilterByType(): void
    {
        // End-to-end: widget declares threat_level_filter under
        // any schema key; adapter routes through translate().
        $widget = new stdClass();
        $widget->schema = [
            'threat_level' => ['type' => 'threat_level_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'threat_level' => [1, '2', 3],
        ]);
        $this->assertSame([1, 2, 3], $out['threat_level']);
    }

    public function testTranslateThreatLevelFilterCoexistsWithOtherCanonicals(): void
    {
        // EventStreamWidget's expected shape post-backfill: a
        // widget declares both time_window and threat_level_filter
        // (and potentially distribution_filter); each translator
        // runs independently through the switch case.
        $widget = new stdClass();
        $widget->schema = [
            'time_window'  => ['type' => 'time_window'],
            'distribution' => ['type' => 'distribution_filter'],
            'threat_level' => ['type' => 'threat_level_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'time_window'  => 'P7D',
            'distribution' => [0, 3],
            'threat_level' => [1, 2],
        ]);
        $this->assertSame('7d', $out['time_window']);
        $this->assertSame([0, 3], $out['distribution']);
        $this->assertSame([1, 2], $out['threat_level']);
    }

    // -------- translateAnalysisFilter() unit tests --------
    //
    // Same shape vocabulary as distribution_filter / threat_level_filter
    // — the three share `_normaliseIntArray` per the third-copy
    // refactor trigger. The independent tests here exist to lock
    // the analysis_filter wire contract (so a future change to the
    // shared helper doesn't silently break analysis-specific
    // expectations) AND to verify the translate() switch routes
    // correctly by type.

    public function testAnalysisFilterIntArrayPassesThrough(): void
    {
        // MISP's analysis enum is {0=Initial, 1=Ongoing, 2=Complete}.
        $this->assertSame([0, 1, 2], CanonicalTypeAdapter::translateAnalysisFilter([0, 1, 2]));
        $this->assertSame([1], CanonicalTypeAdapter::translateAnalysisFilter([1]));
        $this->assertSame([0], CanonicalTypeAdapter::translateAnalysisFilter([0]));
    }

    public function testAnalysisFilterEmptyArrayPassesThrough(): void
    {
        $this->assertSame([], CanonicalTypeAdapter::translateAnalysisFilter([]));
    }

    public function testAnalysisFilterNullPassesThrough(): void
    {
        $this->assertNull(CanonicalTypeAdapter::translateAnalysisFilter(null));
    }

    public function testAnalysisFilterScalarIntWrapsToArray(): void
    {
        // 0 = Initial. Important edge case — Initial events are the
        // most common (just-created), and the scalar shape mirrors
        // how a hand-edited UserSetting may carry `'analysis' => 0`.
        $this->assertSame([0], CanonicalTypeAdapter::translateAnalysisFilter(0));
        $this->assertSame([1], CanonicalTypeAdapter::translateAnalysisFilter(1));
        $this->assertSame([2], CanonicalTypeAdapter::translateAnalysisFilter(2));
    }

    public function testAnalysisFilterScalarNumericStringWrapsToArray(): void
    {
        $this->assertSame([0], CanonicalTypeAdapter::translateAnalysisFilter('0'));
        $this->assertSame([2], CanonicalTypeAdapter::translateAnalysisFilter('2'));
    }

    public function testAnalysisFilterMixedArrayCoercesAndDrops(): void
    {
        $this->assertSame(
            [0, 1, 2],
            CanonicalTypeAdapter::translateAnalysisFilter([0, '1', 2.0])
        );
        $this->assertSame(
            [1],
            CanonicalTypeAdapter::translateAnalysisFilter([1, 'bad', null, []])
        );
        // Out-of-range preserved (3 is not in {0..2} but Cake's IN
        // coercion / post-filter's in_array matches no rows).
        $this->assertSame(
            [3],
            CanonicalTypeAdapter::translateAnalysisFilter([3])
        );
    }

    public function testAnalysisFilterUnrecognisedShapesReturnNull(): void
    {
        $this->assertNull(CanonicalTypeAdapter::translateAnalysisFilter('not-a-number'));
        $this->assertNull(CanonicalTypeAdapter::translateAnalysisFilter(true));
        $this->assertNull(CanonicalTypeAdapter::translateAnalysisFilter(false));
        $this->assertNull(CanonicalTypeAdapter::translateAnalysisFilter(new stdClass()));
    }

    public function testAnalysisFilterIsIdempotent(): void
    {
        $once  = CanonicalTypeAdapter::translateAnalysisFilter([0, '1', 2]);
        $twice = CanonicalTypeAdapter::translateAnalysisFilter($once);
        $this->assertSame($once, $twice);
    }

    public function testTranslateRoutesAnalysisFilterByType(): void
    {
        $widget = new stdClass();
        $widget->schema = [
            'analysis' => ['type' => 'analysis_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'analysis' => [0, '1', 2],
        ]);
        $this->assertSame([0, 1, 2], $out['analysis']);
    }

    public function testTranslateAnalysisFilterCoexistsWithThreatLevelAndTimeWindow(): void
    {
        // EventStreamWidget's expected post-backfill shape: declares
        // analysis_filter alongside the existing threat_level_filter +
        // time_window. Each translator runs independently.
        $widget = new stdClass();
        $widget->schema = [
            'time_window'  => ['type' => 'time_window'],
            'threat_level' => ['type' => 'threat_level_filter'],
            'analysis'     => ['type' => 'analysis_filter'],
        ];
        $out = CanonicalTypeAdapter::translate($widget, [
            'time_window'  => 'P14D',
            'threat_level' => [1],
            'analysis'     => [0, 1],
        ]);
        $this->assertSame('14d', $out['time_window']);
        $this->assertSame([1], $out['threat_level']);
        $this->assertSame([0, 1], $out['analysis']);
    }
}
