<?php
/**
 * Event::handleModuleResult(): a result row from an enrichment module in the
 * simple format may carry `remove_tags` next to `values`/`types` — the tags the
 * module wants taken off the attribute the row points at. This checks that the
 * key survives the translation into the rows the resolution screen renders, in
 * both the list and the single-string spelling, and that a row without it is
 * left with `remove_tags` false rather than missing.
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
if (!class_exists('ComplexTypeTool', false)) {
    // Only reached by freetext rows, which these cases do not use.
    class ComplexTypeTool
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

class ModuleResultRemoveTagsTest extends TestCase
{
    /** @var Event */
    private $event;

    protected function setUp(): void
    {
        $this->event = new Event();
    }

    public function testRemoveTagsListIsCarriedOverToEveryValueOfTheRow()
    {
        $result = [
            'results' => [
                [
                    'types' => ['ip-dst'],
                    'values' => ['198.51.100.10', '198.51.100.11'],
                    'remove_tags' => ['false-positive', 'tlp:red'],
                ],
            ],
        ];

        $rows = $this->event->handleModuleResult($result, 42);

        $this->assertCount(2, $rows);
        foreach ($rows as $row) {
            $this->assertSame(['false-positive', 'tlp:red'], $row['remove_tags']);
        }
    }

    public function testASingleRemoveTagIsNormalisedIntoAList()
    {
        $result = [
            'results' => [
                [
                    'types' => ['ip-dst'],
                    'values' => ['198.51.100.10'],
                    'remove_tags' => 'false-positive',
                ],
            ],
        ];

        $rows = $this->event->handleModuleResult($result, 42);

        $this->assertSame(['false-positive'], $rows[0]['remove_tags']);
    }

    public function testRowWithoutRemoveTagsKeepsTheKeyFalse()
    {
        $result = [
            'results' => [
                [
                    'types' => ['ip-dst'],
                    'values' => ['198.51.100.10'],
                    'tags' => ['tlp:green'],
                ],
            ],
        ];

        $rows = $this->event->handleModuleResult($result, 42);

        $this->assertArrayHasKey('remove_tags', $rows[0]);
        $this->assertFalse($rows[0]['remove_tags']);
        $this->assertSame(['tlp:green'], $rows[0]['tags']);
    }
}
