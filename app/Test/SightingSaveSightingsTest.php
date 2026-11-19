<?php
/**
 * Sighting::saveSightings() unit tests.
 *
 * Pure PHPUnit - follows the convention used by every other test under
 * app/Test/: no CakePHP bootstrap, no DB. The Sighting model only needs
 * `App` and `AppModel` to exist before it can be defined, and the methods
 * saveSightings() reaches (find/create/save/deleteAll, plus the Attribute
 * and Event associations) are supplied by the TestableSighting double
 * below.
 *
 * These pin the options array introduced in place of the six optional tail
 * parameters: every key has to land exactly where the matching positional
 * argument used to, and an omitted key has to keep the old default.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

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
        public $useTable = null;

        public function __construct($id = false, $table = null, $ds = null)
        {
        }
    }
}

require_once __DIR__ . '/../Model/Sighting.php';

use PHPUnit\Framework\TestCase;

class SightingAttributeDouble
{
    public function fetchAttributesSimple(array $user, array $options)
    {
        return array(array('Attribute' => array('id' => 42, 'event_id' => 7)));
    }
}

class SightingEventDouble
{
    public $published = array();

    public function publishSightingsRouter($eventId, array $user)
    {
        $this->published[] = $eventId;
    }
}

class TestableSighting extends Sighting
{
    public $Attribute;
    public $Event;
    public $saved = array();
    public $existingSightings = 0;

    public function __construct($id = false, $table = null, $ds = null)
    {
        $this->Attribute = new SightingAttributeDouble();
        $this->Event = new SightingEventDouble();
    }

    public function find($type, $query = array())
    {
        return $this->existingSightings;
    }

    public function create($data = array(), $filterKey = false)
    {
        return true;
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $this->saved[] = $data;
        return true;
    }

    public function deleteAll($conditions, $cascade = true, $callbacks = false)
    {
        return true;
    }
}

class SightingSaveSightingsTest extends TestCase
{
    public function testOptionsAreReadFromTheOptionsArray(): void
    {
        $sighting = new TestableSighting();
        $result = $sighting->saveSightings(1, array('1.2.3.4'), 1234567, array('org_id' => 5), array(
            'type' => 1,
            'source' => 'unit-test',
            'sighting_uuid' => '11111111-2222-3333-4444-555555555555',
            'publish' => true,
            'saveOnBehalfOf' => 9,
        ));
        $this->assertSame(1, $result);
        $this->assertCount(1, $sighting->saved);
        $this->assertSame(array(
            'attribute_id' => 42,
            'event_id' => 7,
            'org_id' => 9,
            'date_sighting' => 1234567,
            'type' => 1,
            'source' => 'unit-test',
            'uuid' => '11111111-2222-3333-4444-555555555555',
        ), $sighting->saved[0]);
        $this->assertSame(array(7), $sighting->Event->published);
    }

    public function testOmittedOptionsKeepTheOldDefaults(): void
    {
        $sighting = new TestableSighting();
        $result = $sighting->saveSightings(1, array('1.2.3.4'), 5, array('org_id' => 5));
        $this->assertSame(1, $result);
        $this->assertSame(false, $sighting->saved[0]['type']);
        $this->assertSame(false, $sighting->saved[0]['source']);
        $this->assertSame(5, $sighting->saved[0]['org_id']);
        $this->assertArrayNotHasKey('uuid', $sighting->saved[0]);
        $this->assertSame(array(), $sighting->Event->published);
    }

    public function testInvalidTypeIsStillRejected(): void
    {
        $sighting = new TestableSighting();
        $result = $sighting->saveSightings(1, array('1.2.3.4'), 5, array('org_id' => 5), array('type' => 7));
        $this->assertSame('Invalid type, please change it before you POST 1000000 sightings.', $result);
        $this->assertCount(0, $sighting->saved);
    }

    public function testAlreadyKnownSightingUuidIsSkipped(): void
    {
        $sighting = new TestableSighting();
        $sighting->existingSightings = 1;
        $result = $sighting->saveSightings(1, array('1.2.3.4'), 5, array('org_id' => 5), array(
            'type' => 0,
            'sighting_uuid' => '11111111-2222-3333-4444-555555555555',
        ));
        $this->assertSame(0, $result);
        $this->assertCount(0, $sighting->saved);
    }

    public function testFalseFiltersBehaveLikeNoFilters(): void
    {
        $sighting = new TestableSighting();
        $result = $sighting->saveSightings(1, array('1.2.3.4'), 5, array('org_id' => 5), array(
            'type' => 0,
            'source' => '',
            'publish' => false,
            'filters' => false,
        ));
        $this->assertSame(1, $result);
        $this->assertSame(0, $sighting->saved[0]['type']);
    }
}
