<?php
/**
 * The pure helpers of the AI indicator extraction (A4, round 2): the counts
 * of a module answer and the sentence a direct apply answers with.
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

        public static function import($type = null, $name = null, $parent = true)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}
if (!function_exists('__')) {
    function __($text, ...$args)
    {
        return $args ? vsprintf($text, $args) : $text;
    }
}
if (!function_exists('__n')) {
    function __n($singular, $plural, $count, ...$args)
    {
        return vsprintf($count == 1 ? $singular : $plural, $args ?: [$count]);
    }
}

require_once __DIR__ . '/../Model/Module.php';
require_once __DIR__ . '/../Model/Tag.php';
require_once __DIR__ . '/../Model/Event.php';

class EventAiExtractionTest extends TestCase
{
    private static function answer()
    {
        return [
            'Attribute' => [
                ['type' => 'domain', 'value' => 'a.example'],
                ['type' => 'ip-dst', 'value' => '198.51.100.23'],
            ],
            'Object' => [
                ['name' => 'file', 'Attribute' => [['type' => 'filename', 'value' => 'x'], ['type' => 'md5', 'value' => 'd41d8cd98f00b204e9800998ecf8427e']]],
                ['name' => 'vulnerability', 'Attribute' => [['type' => 'vulnerability', 'value' => 'CVE-2026-1']]],
            ],
            'rejected' => [['type' => 'url', 'value' => 'x', 'reason' => 'not-in-source']],
        ];
    }

    public function testCountsIncludeTheAttributesInsideObjects()
    {
        $this->assertSame(['attributes' => 5, 'objects' => 2, 'rejected' => 1], Event::aiExtractionCounts(self::answer()));
    }

    public function testCountsOfAnEmptyAnswer()
    {
        $this->assertSame(['attributes' => 0, 'objects' => 0, 'rejected' => 0], Event::aiExtractionCounts([]));
        $this->assertSame(['attributes' => 0, 'objects' => 1, 'rejected' => 0], Event::aiExtractionCounts(['Object' => [['name' => 'file']]]));
    }

    public function testTheMessageNamesWhatWasAddedAndRejected()
    {
        $this->assertSame(
            '5 indicators added by the AI module (2 objects). 1 candidate rejected by the module.',
            Event::aiExtractionMessage(['attributes' => 5, 'objects' => 2, 'rejected' => 1, 'message' => '5 attributes created. 2 objects created.'])
        );
        $this->assertSame('1 indicator added by the AI module.', Event::aiExtractionMessage(['attributes' => 1, 'objects' => 0, 'rejected' => 0]));
        $this->assertSame('3 indicators added by the AI module (1 object).', Event::aiExtractionMessage(['attributes' => 3, 'objects' => 1]));
    }

    public function testTheMessageForNothingNew()
    {
        $this->assertSame("The AI module found no new indicator in the event's reports.", Event::aiExtractionMessage(['attributes' => 0, 'objects' => 0, 'rejected' => 0]));
        $this->assertSame(
            "The AI module found no new indicator in the event's reports. 4 candidates rejected by the module.",
            Event::aiExtractionMessage(['attributes' => 0, 'objects' => 0, 'rejected' => 4])
        );
    }

    public function testTheSaverIsQuotedOnlyWhenSomethingCouldNotBeSaved()
    {
        $fine = Event::aiExtractionMessage(['attributes' => 2, 'objects' => 0, 'rejected' => 0, 'message' => '2 attributes created.']);
        $this->assertStringNotContainsString('created', $fine);
        $broken = Event::aiExtractionMessage(['attributes' => 2, 'objects' => 0, 'rejected' => 0, 'message' => '1 attribute created. 1 attribute could not be saved. Reason for the failure: {"value":["x"]}']);
        $this->assertStringEndsWith('could not be saved. Reason for the failure: {"value":["x"]}', $broken);
    }
}
