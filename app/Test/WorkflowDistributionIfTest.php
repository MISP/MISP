<?php
/**
 * IF :: Distribution in the attribute scope: the condition must hold for every
 * attribute, object attributes included.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB: the module is built without its
 * constructor (which reads the attribute and sharing group models).
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

require_once __DIR__ . '/../Model/WorkflowModules/logic/Module_distribution_if.php';

class WorkflowDistributionIfTest extends TestCase
{
    private function run_(array $event, $condition, $distribution, array $sgs = [], &$errors = [], $scope = 'attribute')
    {
        $module = (new ReflectionClass('Module_distribution_if'))->newInstanceWithoutConstructor();
        $module->params = [];
        foreach ([
            'scope' => $scope,
            'condition' => $condition,
            'distribution' => (string)$distribution,
            'sharing_group_id' => $sgs,
        ] as $id => $value) {
            $module->params[] = ['id' => $id, 'value' => $value, 'default' => $value];
        }
        $node = ['data' => ['indexed_params' => [
            'scope' => $scope,
            'condition' => $condition,
            'distribution' => (string)$distribution,
            'sharing_group_id' => $sgs,
        ]]];
        return $module->exec($node, new WorkflowRoamingData(['Event' => $event]), $errors);
    }

    private function attr($distribution, $sg = 0)
    {
        return ['distribution' => (string)$distribution, 'sharing_group_id' => (string)$sg];
    }

    private function event(array $attributes, array $objects = [], $distribution = 3)
    {
        return [
            'distribution' => (string)$distribution,
            'sharing_group_id' => '0',
            'Attribute' => $attributes,
            'Object' => $objects,
        ];
    }

    public function testLaterRestrictiveAttributeFailsTheCondition()
    {
        $event = $this->event([$this->attr(3), $this->attr(0)]);
        $this->assertFalse($this->run_($event, 'more_permissive_or_equal_than', 1));
    }

    public function testAllConformingAttributesPass()
    {
        $event = $this->event([$this->attr(2), $this->attr(3)]);
        $this->assertTrue($this->run_($event, 'more_permissive_or_equal_than', 1));
    }

    public function testObjectAttributeAloneIsEvaluated()
    {
        $object = ['distribution' => '3', 'sharing_group_id' => '0', 'Attribute' => [$this->attr(3)]];
        $event = $this->event([], [$object]);
        $this->assertTrue($this->run_($event, 'more_permissive_or_equal_than', 1));
        $this->assertFalse($this->run_($event, 'more_restrictive_or_equal_than', 1));
    }

    public function testObjectDistributionIsPropagatedToItsAttributes()
    {
        $object = ['distribution' => '0', 'sharing_group_id' => '0', 'Attribute' => [$this->attr(3)]];
        $event = $this->event([$this->attr(3)], [$object]);
        $this->assertFalse($this->run_($event, 'more_permissive_or_equal_than', 1));
    }

    public function testNoAttributeAtAllIsFalse()
    {
        $this->assertFalse($this->run_($this->event([]), 'more_permissive_or_equal_than', 0));
    }

    public function testSharingGroupsAreCheckedPerAttribute()
    {
        $event = $this->event([$this->attr(4, 1), $this->attr(4, 2)], [], 4);
        $event['sharing_group_id'] = '1';
        $this->assertFalse($this->run_($event, 'equals', 4, [1]));
        $this->assertTrue($this->run_($event, 'equals', 4, [1, 2]));
    }

    public function testUnsupportedDistributionIsAnError()
    {
        $errors = [];
        $event = $this->event([$this->attr(3), $this->attr(5)], [], 5);
        $this->assertFalse($this->run_($event, 'equals', 3, [], $errors));
        $this->assertNotEmpty($errors);
    }

    public function testEventScopeIsUnchanged()
    {
        $errors = [];
        $event = $this->event([$this->attr(0)], [], 3);
        $this->assertTrue($this->run_($event, 'equals', 3, [], $errors, 'event'));
    }
}
