<?php
/**
 * AttackFlowMapWidget unit tests (DD-45 Phase B3).
 *
 * Pure PHPUnit per the MISP test convention (no CakePHP bootstrap,
 * no DB).  AttackFlowMapWidget uses `ClassRegistry::init('EventTag')
 * ->find('all', ...)` and reads `WWW_ROOT . js/dashboard/charts/
 * vendor/iso-centroids.json` server-side — both stubbed at the top
 * of this file before the widget class is loaded.
 *
 * The stub controls which rows the widget sees from each `find()`
 * call (the widget makes two: one for victims, one for attackers).
 * `setUp()` resets the stub's response queue + writes a small
 * iso-centroids.json fixture under sys_get_temp_dir, and points
 * `WWW_ROOT` at that temp directory's root.
 *
 * Fixture centroids cover the ISOs used across the test suite
 * (US, RU, IR, GB, DE, FR, CN, JP, KR).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

// ---- Framework class stubs --------------------------------------

if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = [];
        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new AttackFlowFakeModel();
            }
            return self::$instances[$name];
        }
        public static function reset()
        {
            self::$instances = [];
        }
    }
}

class AttackFlowFakeModel
{
    /** @var array<int,array> queue of responses to return from find() */
    public $responses = [];

    public function find($type, $opts = [])
    {
        if (empty($this->responses)) {
            return [];
        }
        return array_shift($this->responses);
    }
}

// ---- WWW_ROOT setup ---------------------------------------------
//
// The widget hard-codes the centroid path relative to WWW_ROOT.
// We point it at a per-test temp dir; setUp() writes the centroid
// fixture into the expected sub-path.

if (!defined('DS')) {
    define('DS', '/');
}
if (!defined('AFM_TEST_WWW_ROOT')) {
    define('AFM_TEST_WWW_ROOT', sys_get_temp_dir() . '/afm-test-' . uniqid() . '/');
    @mkdir(AFM_TEST_WWW_ROOT . 'js/dashboard/charts/vendor', 0700, true);
    define('WWW_ROOT', AFM_TEST_WWW_ROOT);
}

require_once __DIR__ . '/../Lib/Dashboard/AttackFlowMapWidget.php';


class AttackFlowMapWidgetTest extends TestCase
{
    /** @var AttackFlowFakeModel */
    private $eventTag;

    /** @var AttackFlowMapWidget */
    private $w;

    protected function setUp(): void
    {
        ClassRegistry::reset();
        $this->eventTag = ClassRegistry::init('EventTag');
        // Centroid fixture covers all ISOs used across tests.
        $centroids = [
            'US' => [-100.0, 40.0],
            'RU' => [97.0, 62.0],
            'IR' => [54.0, 32.0],
            'GB' => [-3.0, 54.0],
            'DE' => [10.0, 51.0],
            'FR' => [2.0, 47.0],
            'CN' => [104.0, 36.0],
            'JP' => [138.0, 36.0],
            'KR' => [128.0, 36.0],
        ];
        file_put_contents(
            WWW_ROOT . 'js/dashboard/charts/vendor/iso-centroids.json',
            json_encode($centroids)
        );
        $this->w = new AttackFlowMapWidget();
    }

    /**
     * Helper: build a fake find() result row.  Cake's find('all')
     * returns each row as `['Alias' => ['field' => value], ...]`.
     */
    private function row($eventId, $value)
    {
        return [
            'EventTag' => ['event_id' => $eventId],
            'GalaxyElement' => ['value' => $value],
        ];
    }

    // -- Empty paths ---------------------------------------------------

    public function testEmptyVictimsReturnsEmptyFlows(): void
    {
        $this->eventTag->responses = [
            [],  // victim query: no rows
            // attacker query won't run; widget short-circuits
        ];
        $out = $this->w->handler(['Role' => []], []);
        $this->assertSame('2d', $out['mode']);
        $this->assertSame([], $out['flows']);
    }

    public function testVictimsPresentButNoAttackersReturnsEmpty(): void
    {
        $this->eventTag->responses = [
            [$this->row(101, 'US')],  // victim query: event 101 → US
            [],                        // attacker query: nothing
        ];
        $out = $this->w->handler(['Role' => []], []);
        $this->assertSame([], $out['flows']);
    }

    // -- Single-arc path ----------------------------------------------

    public function testSingleEventSingleArc(): void
    {
        $this->eventTag->responses = [
            [$this->row(101, 'US')],          // victim: 101 → US
            [$this->row(101, 'IR')],          // attacker: 101 → IR
        ];
        $out = $this->w->handler(['Role' => []], []);
        $this->assertCount(1, $out['flows']);
        $this->assertSame('IR', $out['flows'][0]['src_iso']);
        $this->assertSame('US', $out['flows'][0]['dst_iso']);
        $this->assertSame(1, $out['flows'][0]['value']);
        // assertEquals (==), not assertSame (===): json_decode of
        // whole-number values like 54.0 produces int 54, not float.
        $this->assertEquals([54, 32], $out['flows'][0]['src']);
        $this->assertEquals([-100, 40], $out['flows'][0]['dst']);
    }

    // -- Self-loop skip ------------------------------------------------

    public function testSelfLoopSkipped(): void
    {
        $this->eventTag->responses = [
            [$this->row(101, 'RU')],
            [$this->row(101, 'RU')],
        ];
        $out = $this->w->handler(['Role' => []], []);
        $this->assertSame([], $out['flows']);
    }

    public function testSelfLoopSkippedDoesNotPoisonOtherArcs(): void
    {
        // event 101: IR → IR (self, skipped); event 102: IR → US (arc)
        $this->eventTag->responses = [
            [$this->row(101, 'IR'), $this->row(102, 'US')],
            [$this->row(101, 'IR'), $this->row(102, 'IR')],
        ];
        $out = $this->w->handler(['Role' => []], []);
        $this->assertCount(1, $out['flows']);
        $this->assertSame('IR', $out['flows'][0]['src_iso']);
        $this->assertSame('US', $out['flows'][0]['dst_iso']);
    }

    // -- Multi-event aggregation --------------------------------------

    public function testRepeatedPairAggregates(): void
    {
        // Two events, both yielding the same IR → US arc:
        $this->eventTag->responses = [
            [$this->row(101, 'US'), $this->row(102, 'US')],
            [$this->row(101, 'IR'), $this->row(102, 'IR')],
        ];
        $out = $this->w->handler(['Role' => []], []);
        $this->assertCount(1, $out['flows']);
        $this->assertSame(2, $out['flows'][0]['value']);
    }

    public function testCrossProductWithinEvent(): void
    {
        // event 101: RU + IR attackers × US + GB victims = 4 arcs
        $this->eventTag->responses = [
            [$this->row(101, 'US'), $this->row(101, 'GB')],
            [$this->row(101, 'RU'), $this->row(101, 'IR')],
        ];
        $out = $this->w->handler(['Role' => []], []);
        $this->assertCount(4, $out['flows']);
        $seen = [];
        foreach ($out['flows'] as $f) {
            $seen[] = $f['src_iso'] . '→' . $f['dst_iso'];
        }
        sort($seen);
        $this->assertSame(['IR→GB', 'IR→US', 'RU→GB', 'RU→US'], $seen);
    }

    // -- ISO dedupe within event --------------------------------------

    public function testIsoDedupedWithinEvent(): void
    {
        // Same victim listed twice on the same event (e.g. multiple
        // tag rows pointing at the same country cluster) — should
        // count once.
        $this->eventTag->responses = [
            [$this->row(101, 'US'), $this->row(101, 'US')],
            [$this->row(101, 'IR'), $this->row(101, 'IR')],
        ];
        $out = $this->w->handler(['Role' => []], []);
        $this->assertCount(1, $out['flows']);
        $this->assertSame(1, $out['flows'][0]['value']);
    }

    // -- max_arcs truncation ------------------------------------------

    public function testMaxArcsTruncatesValueDesc(): void
    {
        // Six events: three contribute IR→US (value 3), one IR→GB,
        // one IR→DE, one IR→FR. With max_arcs=2, the IR→US pair
        // (value 3) must survive; one of the singletons survives
        // too.
        $vs = [];
        $as = [];
        foreach ([101, 102, 103] as $eid) {
            $vs[] = $this->row($eid, 'US');
            $as[] = $this->row($eid, 'IR');
        }
        $vs[] = $this->row(104, 'GB');
        $as[] = $this->row(104, 'IR');
        $vs[] = $this->row(105, 'DE');
        $as[] = $this->row(105, 'IR');
        $vs[] = $this->row(106, 'FR');
        $as[] = $this->row(106, 'IR');
        $this->eventTag->responses = [$vs, $as];

        $out = $this->w->handler(['Role' => []], ['max_arcs' => 2]);
        $this->assertCount(2, $out['flows']);
        $this->assertSame('US', $out['flows'][0]['dst_iso']);
        $this->assertSame(3, $out['flows'][0]['value']);
        $this->assertSame(1, $out['flows'][1]['value']);
    }

    public function testMaxArcsZeroFallsBackToDefault(): void
    {
        // max_arcs=0 should fall back to default 500 (any positive
        // cap >= flow count behaves the same as no cap here).
        $this->eventTag->responses = [
            [$this->row(101, 'US')],
            [$this->row(101, 'IR')],
        ];
        $out = $this->w->handler(['Role' => []], ['max_arcs' => 0]);
        $this->assertCount(1, $out['flows']);
    }

    // -- Invalid ISO drop ---------------------------------------------

    public function testInvalidIsoDropped(): void
    {
        // 'XYZ' isn't [A-Z]{2}; 'gb' lowercase gets uppercased and
        // accepted; '' empty dropped.
        $this->eventTag->responses = [
            [
                $this->row(101, 'XYZ'),
                $this->row(102, 'gb'),
                $this->row(103, ''),
            ],
            [
                $this->row(101, 'IR'),
                $this->row(102, 'IR'),
                $this->row(103, 'IR'),
            ],
        ];
        $out = $this->w->handler(['Role' => []], []);
        // Only event 102's IR → GB arc survives (101 has invalid
        // victim XYZ → no victim collected; 103 has empty → none).
        $this->assertCount(1, $out['flows']);
        $this->assertSame('GB', $out['flows'][0]['dst_iso']);
    }

    // -- Missing centroid drop ----------------------------------------

    public function testMissingCentroidDropsArc(): void
    {
        // ZW (Zimbabwe) is not in the test fixture's centroid map —
        // the arc resolves to no flow.
        $this->eventTag->responses = [
            [$this->row(101, 'ZW')],
            [$this->row(101, 'IR')],
        ];
        $out = $this->w->handler(['Role' => []], []);
        $this->assertSame([], $out['flows']);
    }

    // -- Mode normalisation -------------------------------------------

    public function testDefaultModeIs2d(): void
    {
        $this->eventTag->responses = [[], []];
        $out = $this->w->handler(['Role' => []], []);
        $this->assertSame('2d', $out['mode']);
    }

    public function testBogusModeFallsBackTo2d(): void
    {
        $this->eventTag->responses = [[], []];
        $out = $this->w->handler(['Role' => []], ['mode' => 'lol']);
        $this->assertSame('2d', $out['mode']);
    }

    public function test3dGlobeModePreserved(): void
    {
        $this->eventTag->responses = [[], []];
        $out = $this->w->handler(['Role' => []], ['mode' => '3d-globe']);
        $this->assertSame('3d-globe', $out['mode']);
    }
}
