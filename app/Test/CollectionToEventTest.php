<?php
/**
 * A selection of a collection made into an event: what a copy is capped at,
 * a record taking a node's place on the graph, and the new event's fields.
 *
 * Pure PHPUnit, no CakePHP bootstrap and no database, as the other tests
 * under app/Test/. The framework classes touched are stubbed below, each
 * guarded so that a full-suite run sharing one process keeps whichever stub
 * loaded first.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!function_exists('__')) {
    function __($string)
    {
        $args = func_get_args();
        $format = array_shift($args);
        return empty($args) ? $format : vsprintf($format, $args);
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $id = false;
        public $data = array();
        public $validationErrors = array();
    }
}

require_once __DIR__ . '/../Lib/Tools/AnalystGraphDocumentTool.php';
require_once __DIR__ . '/../Lib/Tools/DistributionLevel.php';
require_once __DIR__ . '/../Lib/Tools/NewEventFormTool.php';
require_once __DIR__ . '/../Model/CollectionToEvent.php';

class ToEventSharingGroups
{
    public $usable = array();

    public function canUse($user, $id)
    {
        return in_array((int)$id, $this->usable, true);
    }
}

class ToEventThreatLevels
{
    public function hasAny($conditions)
    {
        return in_array((int)$conditions['ThreatLevel.id'], array(1, 2, 3, 4), true);
    }
}

class ToEventEvents
{
    public $distributionLevels = array(0 => 'org', 1 => 'community', 2 => 'connected', 3 => 'all', 4 => 'group');
    public $analysisLevels = array(0 => 'Initial', 1 => 'Ongoing', 2 => 'Completed');
    public $SharingGroup;
    public $ThreatLevel;

    public function __construct()
    {
        $this->SharingGroup = new ToEventSharingGroups();
        $this->ThreatLevel = new ToEventThreatLevels();
    }
}

class CollectionToEventTest extends TestCase
{
    const A = '11111111-1111-4111-8111-111111111111';
    const B = '22222222-2222-4222-8222-222222222222';

    private static function document(array $nodes, array $groups = array())
    {
        return array('version' => 1, 'nodes' => $nodes, 'groups' => $groups, 'hidden_edges' => array(), 'view' => array());
    }

    public function testRecordTakesTheNodesPlace()
    {
        $sha = hash('sha256', 'evil.example');
        $document = self::document(array(
            array('type' => 'Value', 'value' => 'evil.example', 'sha256' => $sha, 'x' => 10, 'y' => 20, 'pinned' => true),
            array('type' => 'Event', 'uuid' => self::B, 'x' => 0, 'y' => 0),
        ));
        list($out, $report) = AnalystGraphDocumentTool::replaceNodes($document, array(
            'Value:' . $sha => array('type' => 'Attribute', 'uuid' => strtoupper(self::A)),
        ));
        $this->assertSame(array('Value:' . $sha => 'Attribute:' . self::A), $report['replaced']);
        $this->assertSame(
            array('type' => 'Attribute', 'uuid' => self::A, 'x' => 10, 'y' => 20, 'pinned' => true),
            $out['nodes'][0]
        );
        $this->assertSame('Event', $out['nodes'][1]['type']);
    }

    public function testGroupsFollowTheRecord()
    {
        $document = self::document(
            array(
                array('type' => 'StandaloneObject', 'uuid' => self::A, 'x' => 1, 'y' => 1),
                array('type' => 'Event', 'uuid' => self::B, 'x' => 2, 'y' => 2),
            ),
            array(array('id' => 'g1', 'label' => 'hosting', 'members' => array('StandaloneObject:' . self::A, 'Event:' . self::B)))
        );
        $object = '33333333-3333-4333-8333-333333333333';
        list($out) = AnalystGraphDocumentTool::replaceNodes($document, array(
            'StandaloneObject:' . self::A => array('type' => 'Object', 'uuid' => $object),
        ));
        $this->assertSame(array('Object:' . $object, 'Event:' . self::B), $out['groups'][0]['members']);
    }

    public function testRecordAlreadyOnTheGraphStaysWhereItIs()
    {
        $document = self::document(array(
            array('type' => 'ModuleAnswer', 'uuid' => self::A, 'x' => 5, 'y' => 5, 'module' => 'm', 'modules' => array('m'), 'origins' => array(), 'content' => array('kind' => 'attribute', 'type' => 'domain', 'value' => 'a.example')),
            array('type' => 'Attribute', 'uuid' => self::B, 'x' => 50, 'y' => 60),
        ));
        list($out, $report) = AnalystGraphDocumentTool::replaceNodes($document, array(
            'ModuleAnswer:' . self::A => array('type' => 'Attribute', 'uuid' => self::B),
        ));
        $this->assertCount(1, $out['nodes']);
        $this->assertSame(50, $out['nodes'][0]['x']);
        $this->assertSame('Attribute:' . self::B, $report['replaced']['ModuleAnswer:' . self::A]);
    }

    public function testNothingToReplaceLeavesTheDocument()
    {
        $document = self::document(array(array('type' => 'Event', 'uuid' => self::B, 'x' => 0, 'y' => 0)));
        list($out, $report) = AnalystGraphDocumentTool::replaceNodes($document, array(
            'Value:' . hash('sha256', 'gone') => array('type' => 'Attribute', 'uuid' => self::A),
        ));
        $this->assertSame($document, $out);
        $this->assertSame(array('Value:' . hash('sha256', 'gone')), $report['absent']);
        $this->assertSame(array(), $report['replaced']);
    }

    public function testReachOrder()
    {
        $order = array(array(0, null), array(4, 7), array(1, null), array(2, null), array(3, null));
        for ($i = 1; $i < count($order); $i++) {
            $this->assertTrue(DistributionLevel::reachesFewer($order[$i - 1], $order[$i]));
            $this->assertFalse(DistributionLevel::reachesFewer($order[$i], $order[$i - 1]));
        }
        $this->assertFalse(DistributionLevel::reachesFewer(array(1, null), array(1, null)));
        $this->assertFalse(DistributionLevel::reachesFewer(array(4, 7), array(4, '7')));
        $this->assertTrue(DistributionLevel::reachesFewer(array(4, 7), array(4, 8)));
    }

    public function testReachDefersInheritedLevelsOutward()
    {
        $event = function ($d, $g = null) {
            return array('distribution' => $d, 'sharing_group_id' => $g);
        };
        $this->assertSame(array(1, null), CollectionToEvent::reach(array(
            'Event' => $event(1), 'Object' => array('id' => 3) + $event(5), 'Attribute' => $event(5),
        )));
        $this->assertSame(array(1, null), CollectionToEvent::reach(array(
            'Event' => $event(3), 'Object' => array('id' => 3) + $event(1), 'Attribute' => $event(5),
        )));
        $this->assertSame(array(4, 9), CollectionToEvent::reach(array(
            'Event' => $event(3), 'Object' => array('id' => null, 'distribution' => null, 'sharing_group_id' => null), 'Attribute' => $event(4, 9),
        )));
        $this->assertSame(array(4, 2), CollectionToEvent::reach(array(
            'Event' => $event(4, 2), 'Attribute' => $event(1),
        )));
        $this->assertSame(array(0, null), CollectionToEvent::reach(array(
            'Event' => $event(2), 'Object' => array('id' => 3) + $event(0),
        )));
    }

    public function testNewEventFields()
    {
        $events = new ToEventEvents();
        $events->SharingGroup->usable = array(5);
        $user = array('id' => 1);
        $good = array('info' => ' Hunt ', 'date' => '2026-11-19', 'distribution' => '1', 'threat_level_id' => 4, 'analysis' => 1);

        list($fields, $errors) = NewEventFormTool::fields($user, $good, $events);
        $this->assertSame(array(), $errors);
        $this->assertSame(array('info' => 'Hunt', 'date' => '2026-11-19', 'distribution' => 1, 'threat_level_id' => 4, 'analysis' => 1, 'published' => 0), $fields);

        list($fields, $errors) = NewEventFormTool::fields($user, array('distribution' => 4, 'sharing_group_id' => 5) + $good, $events);
        $this->assertSame(5, $fields['sharing_group_id']);

        list($fields, $errors) = NewEventFormTool::fields($user, array('distribution' => 4, 'sharing_group_id' => 6) + $good, $events);
        $this->assertNull($fields);
        $this->assertArrayHasKey('sharing_group_id', $errors);

        list($fields, $errors) = NewEventFormTool::fields($user, array('info' => '', 'date' => '2026-02-30', 'threat_level_id' => 9, 'analysis' => 7) + $good, $events);
        $this->assertSame(array('info', 'date', 'threat_level_id', 'analysis'), array_keys($errors));

        list($fields, $errors) = NewEventFormTool::fields($user, 'not a form', $events);
        $this->assertArrayHasKey('info', $errors);
    }
}
