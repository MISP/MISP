<?php
/**
 * IF :: Tag with the "all" operators: tag order and a tag repeated across
 * attributes must not change the branch taken.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB: the module is built without its
 * constructor (which reads the tag and galaxy cluster models).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!function_exists('__')) {
    function __($text, ...$args)
    {
        return $args ? vsprintf($text, $args) : $text;
    }
}
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}
if (!class_exists('Hash', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Hash.php';
}
if (!class_exists('WorkflowRoamingData', false)) {
    class WorkflowRoamingData
    {
        private $data;

        public function __construct(array $data = [])
        {
            $this->data = $data;
        }

        public function getData()
        {
            return $this->data;
        }
    }
}

require_once __DIR__ . '/../Model/WorkflowModules/logic/Module_tag_if.php';

class WorkflowTagIfTest extends TestCase
{
    const SELECTED = ['tlp:red', 'pap:red'];

    private function run_(array $event, $condition, $scope)
    {
        $module = (new ReflectionClass('Module_tag_if'))->newInstanceWithoutConstructor();
        $values = [
            'scope' => $scope,
            'condition' => $condition,
            'tags' => self::SELECTED,
            'clusters' => [],
        ];
        $module->params = [];
        foreach ($values as $id => $value) {
            $module->params[] = ['id' => $id, 'value' => $value, 'default' => $value];
        }
        $node = ['data' => ['indexed_params' => $values]];
        $errors = [];
        return $module->exec($node, new WorkflowRoamingData(['Event' => $event]), $errors);
    }

    private function tags(array $names)
    {
        return array_map(function ($name) {
            return ['name' => $name];
        }, $names);
    }

    private function eventTagged(array $names)
    {
        return ['Tag' => $this->tags($names)];
    }

    private function attributesTagged(array ...$perAttribute)
    {
        return ['_AttributeFlattened' => array_map(function ($names) {
            return ['Tag' => $this->tags($names)];
        }, $perAttribute)];
    }

    private function assertAll(bool $expected, array $event, $scope)
    {
        $this->assertSame($expected, $this->run_($event, 'in_and', $scope), 'in_and');
        $this->assertSame(!$expected, $this->run_($event, 'not_in_and', $scope), 'not_in_and');
    }

    public function testAllTagsInSelectionOrder()
    {
        $this->assertAll(true, $this->eventTagged(['tlp:red', 'pap:red']), 'event');
    }

    public function testAllTagsInReverseOrder()
    {
        $this->assertAll(true, $this->eventTagged(['pap:red', 'tlp:red']), 'event');
    }

    public function testAllTagsAmongOthers()
    {
        $this->assertAll(true, $this->eventTagged(['pap:red', 'osint', 'tlp:red']), 'event');
    }

    public function testOneTagMissing()
    {
        $this->assertAll(false, $this->eventTagged(['tlp:red', 'osint']), 'event');
    }

    public function testTagRepeatedAcrossAttributes()
    {
        $event = $this->attributesTagged(['tlp:red', 'pap:red'], ['tlp:red']);
        $this->assertAll(true, $event, 'attribute');
    }

    public function testTagsSpreadOverAttributes()
    {
        $event = $this->attributesTagged(['pap:red'], ['tlp:red']);
        $this->assertAll(true, $event, 'attribute');
    }

    public function testRepeatedTagWithOneMissing()
    {
        $event = $this->attributesTagged(['tlp:red'], ['tlp:red']);
        $this->assertAll(false, $event, 'attribute');
    }
}
