<?php
/**
 * EventReport::referencedElements(): the UUIDs a report's content cites, which
 * is all the referenced proxy (getProxyMISPElements?scope=referenced) fetches.
 * Missing one renders a pill as invalid in the read-only preview.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}

require_once __DIR__ . '/../Model/EventReport.php';

class EventReportReferencedElementsTest extends TestCase
{
    const A = '5cfca8e3-183e-4e79-b4a2-3202075867be';
    const B = '8bed0620-5cd8-4269-a1b8-b2abce9e40c4';
    const O = 'cc5b158c-a45d-4f08-aa32-8a5124da4506';
    const G = 'c4e851fa-775f-11e7-8163-b774922098cd';

    public function testNothingCitedIsNothingToFetch()
    {
        $this->assertSame(
            ['attribute' => [], 'object' => [], 'galaxymatrix' => []],
            EventReport::referencedElements("# Notes\n\nNo element here, only @[tag](tlp:clear).")
        );
        $this->assertSame(
            ['attribute' => [], 'object' => [], 'galaxymatrix' => []],
            EventReport::referencedElements(null)
        );
    }

    public function testEachScopeIsCollectedOnce()
    {
        $content = '@[attribute](' . self::A . ') then @[attribute](' . self::A . ")\n"
            . '@[object](' . self::O . ') and @[galaxymatrix](' . self::G . ')';
        $this->assertSame(
            ['attribute' => [self::A], 'object' => [self::O], 'galaxymatrix' => [self::G]],
            EventReport::referencedElements($content)
        );
    }

    public function testAPictureCitesItsAttribute()
    {
        $references = EventReport::referencedElements('@![attribute](' . self::B . ')');
        $this->assertSame([self::B], $references['attribute']);
    }

    public function testWhatTheRendererRejectsIsNotFetched()
    {
        $content = '@[attribute](not-a-uuid) @[event](' . self::A . ') @[attribute]( ' . self::B . ' )'
            . ' @[tag](' . self::A . ')';
        $this->assertSame(
            ['attribute' => [], 'object' => [], 'galaxymatrix' => []],
            EventReport::referencedElements($content)
        );
    }
}
