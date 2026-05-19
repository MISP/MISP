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
}
