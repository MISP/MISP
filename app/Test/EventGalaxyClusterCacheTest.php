<?php
/**
 * Event::__attachGalaxies() galaxy cluster cache tests.
 *
 * fetchEvent() attaches galaxies event by event, so before the cache every event
 * of a result set triggered its own GalaxyCluster::getClustersByTags() round trip,
 * even though the events of a result set share most of their galaxy tags. The
 * lookup cannot simply be hoisted in front of the loop, because the Tag data it
 * reads is only filled in by __attachTags(), which runs inside the same loop.
 * Instead fetchEvent() hands __attachGalaxies() a cache that lives for the
 * duration of the fetch, and only the tags that are not in it are fetched.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB — the convention used by every other
 * test under app/Test/ (see CollectionPullTest / PewPewMapWidgetTest). The
 * framework classes Event.php needs are stubbed at the top (guarded with
 * class_exists so a full-suite run shares whichever file loaded them first), the
 * real Model/Event.php is then loaded and __attachGalaxies() is driven through
 * reflection the way fetchEvent() drives it: once per event, with one shared
 * cache. fetchEvent() itself is not exercised here, it needs a database.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

// -------- framework stubs (must exist BEFORE the model loads) --------

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new EventGalaxyClusterCacheFakeModel();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

if (!class_exists('EventGalaxyClusterCacheFakeModel', false)) {
    class EventGalaxyClusterCacheFakeModel
    {
        public $responses = array();

        public function find($type, $opts = array())
        {
            return empty($this->responses) ? array() : array_shift($this->responses);
        }
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        // Kept byte-identical to the stub in the Collection tests, whichever file wins the
        // race to define it; this test never reads $alias.
        public $alias = 'Collection';
        public $id = false;
        public $data = array();
        public $validationErrors = array();

        public function create($data = array())
        {
            $this->id = false;
        }

        public function save($data = null, $validate = true, $fieldList = array())
        {
            return true;
        }

        public function find($type, $options = array())
        {
            return array();
        }
    }
}

require_once __DIR__ . '/../Model/Event.php';

use PHPUnit\Framework\TestCase;

/**
 * GalaxyCluster stand-in: records every getClustersByTags() call and answers from
 * a static cluster list, the way the model does (tag_name IN (...)).
 */
class EventGalaxyClusterCacheFakeGalaxyCluster
{
    /** @var array<int,array> tag name sets of every getClustersByTags() call */
    public $calls = array();

    /** @var array<string,array> cluster row indexed by tag name */
    public $clusters = array();

    public function getClustersByTags(array $tagNames, array $user, $postProcess = true, $fetchFullCluster = true, $fetchFullRelationship = false)
    {
        $this->calls[] = $tagNames;
        $result = array();
        foreach ($tagNames as $tagId => $tagName) {
            if (isset($this->clusters[$tagName])) {
                $cluster = $this->clusters[$tagName];
                $cluster['GalaxyCluster']['tag_id'] = $tagId;
                $result[] = $cluster;
            }
        }
        return $result;
    }
}

/** Event with the GalaxyCluster association declared, so that no dynamic property is created. */
class EventGalaxyClusterCacheTestableEvent extends Event
{
    public $GalaxyCluster;
}

class EventGalaxyClusterCacheTest extends TestCase
{
    /** @var EventGalaxyClusterCacheFakeGalaxyCluster */
    private $galaxyCluster;

    /** @var EventGalaxyClusterCacheTestableEvent */
    private $event;

    /** @var ReflectionMethod */
    private $attachGalaxies;

    protected function setUp(): void
    {
        ClassRegistry::reset();
        $this->galaxyCluster = new EventGalaxyClusterCacheFakeGalaxyCluster();
        $this->galaxyCluster->clusters = array(
            'misp-galaxy:mitre-attack-pattern="Phishing"' => array(
                'GalaxyCluster' => array(
                    'id' => 10,
                    'tag_name' => 'misp-galaxy:mitre-attack-pattern="Phishing"',
                    'value' => 'Phishing',
                    'Galaxy' => array('id' => 1, 'name' => 'Attack Pattern'),
                ),
            ),
            'misp-galaxy:threat-actor="Sofacy"' => array(
                'GalaxyCluster' => array(
                    'id' => 11,
                    'tag_name' => 'misp-galaxy:threat-actor="Sofacy"',
                    'value' => 'Sofacy',
                    'Galaxy' => array('id' => 2, 'name' => 'Threat Actor'),
                ),
            ),
        );
        ClassRegistry::$instances['GalaxyCluster'] = $this->galaxyCluster;

        $this->event = new EventGalaxyClusterCacheTestableEvent();
        $this->attachGalaxies = new ReflectionMethod('Event', '__attachGalaxies');
        $this->attachGalaxies->setAccessible(true);
    }

    /** Build an event carrying the given galaxy tags, one on the event, one on an attribute. */
    private function makeEvent($eventTagId, $eventTagName, $attributeTagId = null, $attributeTagName = null)
    {
        $event = array(
            'Event' => array('id' => 1),
            'EventTag' => array(
                array(
                    'id' => 100 + $eventTagId,
                    'local' => false,
                    'relationship_type' => null,
                    'Tag' => array('id' => $eventTagId, 'name' => $eventTagName, 'is_galaxy' => true),
                ),
            ),
            'Attribute' => array(),
        );
        if ($attributeTagId !== null) {
            $event['Attribute'][] = array(
                'id' => 7,
                'AttributeTag' => array(
                    array(
                        'id' => 200 + $attributeTagId,
                        'local' => false,
                        'relationship_type' => null,
                        'Tag' => array('id' => $attributeTagId, 'name' => $attributeTagName, 'is_galaxy' => true),
                    ),
                ),
            );
        }
        return $event;
    }

    private function attach(array &$event, array &$cache)
    {
        $user = array('Role' => array('perm_site_admin' => 1));
        $this->attachGalaxies->invokeArgs($this->event, array(&$event, $user, false, true, false, &$cache));
    }

    public function testClustersAreFetchedOncePerResultSetNotOncePerEvent()
    {
        $cache = array();
        $first = $this->makeEvent(5, 'misp-galaxy:mitre-attack-pattern="Phishing"');
        $second = $this->makeEvent(5, 'misp-galaxy:mitre-attack-pattern="Phishing"');
        $this->attach($first, $cache);
        $this->attach($second, $cache);

        $this->assertCount(1, $this->galaxyCluster->calls);
        $this->assertSame(array(5 => 'misp-galaxy:mitre-attack-pattern="Phishing"'), $this->galaxyCluster->calls[0]);
    }

    public function testCachedEventsGetTheSameGalaxiesAsUncachedOnes()
    {
        $cache = array();
        $first = $this->makeEvent(5, 'misp-galaxy:mitre-attack-pattern="Phishing"', 6, 'misp-galaxy:threat-actor="Sofacy"');
        $second = $this->makeEvent(5, 'misp-galaxy:mitre-attack-pattern="Phishing"', 6, 'misp-galaxy:threat-actor="Sofacy"');
        $this->attach($first, $cache);
        $this->attach($second, $cache);

        $freshCache = array();
        $reference = $this->makeEvent(5, 'misp-galaxy:mitre-attack-pattern="Phishing"', 6, 'misp-galaxy:threat-actor="Sofacy"');
        $this->attach($reference, $freshCache);

        $this->assertSame('Attack Pattern', $second['Galaxy'][0]['name']);
        $this->assertSame(10, $second['Galaxy'][0]['GalaxyCluster'][0]['id']);
        $this->assertSame('Threat Actor', $second['Attribute'][0]['Galaxy'][0]['name']);
        $this->assertSame(11, $second['Attribute'][0]['Galaxy'][0]['GalaxyCluster'][0]['id']);
        $this->assertEquals($reference['Galaxy'], $second['Galaxy']);
        $this->assertEquals($reference['Attribute'][0]['Galaxy'], $second['Attribute'][0]['Galaxy']);
    }

    public function testGalaxyTagsWithoutAClusterAreNotLookedUpAgain()
    {
        $cache = array();
        $first = $this->makeEvent(9, 'misp-galaxy:unknown="Nothing"');
        $second = $this->makeEvent(9, 'misp-galaxy:unknown="Nothing"');
        $this->attach($first, $cache);
        $this->attach($second, $cache);

        $this->assertCount(1, $this->galaxyCluster->calls);
        $this->assertSame(array(), $first['Galaxy']);
        $this->assertSame(array(), $second['Galaxy']);
    }

    public function testOnlyTagsMissingFromTheCacheAreFetched()
    {
        $cache = array();
        $first = $this->makeEvent(5, 'misp-galaxy:mitre-attack-pattern="Phishing"');
        $second = $this->makeEvent(5, 'misp-galaxy:mitre-attack-pattern="Phishing"', 6, 'misp-galaxy:threat-actor="Sofacy"');
        $this->attach($first, $cache);
        $this->attach($second, $cache);

        $this->assertCount(2, $this->galaxyCluster->calls);
        $this->assertSame(array(6 => 'misp-galaxy:threat-actor="Sofacy"'), $this->galaxyCluster->calls[1]);
        $this->assertSame('Attack Pattern', $second['Galaxy'][0]['name']);
        $this->assertSame('Threat Actor', $second['Attribute'][0]['Galaxy'][0]['name']);
    }
}
