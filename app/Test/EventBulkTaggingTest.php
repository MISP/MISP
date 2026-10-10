<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

/**
 * EventsController::addTag() bulk branch - query shape and tag bookkeeping.
 *
 * The bulk branch used to ask the database twice for every (event, tag) pair:
 * an EventTag::hasAny() duplicate probe and an EventTag find('column') fetch of
 * the tag names the taxonomy exclusivity check needs. Both answers only depend
 * on the event, so they are now fetched once per event and kept up to date in
 * memory as tags are attached.
 *
 * The regression guard is the call log of the EventTag model: one find per
 * event, no hasAny at all. The remaining tests pin the semantics the in-memory
 * bookkeeping has to reproduce - a duplicate is still skipped, a tag attached
 * earlier in the same request still feeds the exclusivity check, and the
 * exclusivity check still only sees the tags matching the effective `local`
 * flag.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB - the convention used by every other
 * test under app/Test/ (see DashboardCsvExportTest for the controller variant).
 * The framework stubs are guarded with class_exists so a full-suite run shares
 * whichever file loaded them first; the contracts below are compatible with the
 * ones the other test files declare.
 */

if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        $arguments = func_get_args();
        return vsprintf($singular, array_slice($arguments, 1));
    }
}

if (!function_exists('__n')) {
    function __n($singular, $plural, $count, $args = null)
    {
        $arguments = func_get_args();
        $format = $count === 1 ? $singular : $plural;
        return vsprintf($format, array_slice($arguments, 3));
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

if (!class_exists('AppController', false)) {
    class AppController
    {
    }
}

if (!class_exists('CakeResponse', false)) {
    class CakeResponse
    {
        public $headers = [];

        public $options = [];

        public function __construct($options = [])
        {
            $this->options = $options;
        }

        public function header($header = null, $value = null)
        {
            $this->headers[$header] = $value;
            return $this->headers;
        }

        public function body()
        {
            return isset($this->options['body']) ? $this->options['body'] : null;
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
                self::$instances[$name] = new EventBulkTaggingFakeLog();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

if (!class_exists('RequestRearrangeTool', false)) {
    require_once __DIR__ . '/../Lib/Tools/RequestRearrangeTool.php';
}

require_once __DIR__ . '/../Controller/EventsController.php';

/** Log::createLogEntry() is fire and forget here. */
class EventBulkTaggingFakeLog
{
    public $entries = array();

    public function createLogEntry($user, $action, $model, $modelId, $title = '', $change = '')
    {
        $this->entries[] = array($action, $model, $modelId, $title);
    }
}

/**
 * The EventTag model, backed by an array of rows shaped the way find('all')
 * with `contain => Tag` returns them. Every call is recorded so a test can
 * assert how often the controller talks to the database.
 */
class EventBulkTaggingFakeEventTag
{
    /** @var array<int,array> the rows in the event_tags table */
    public $rows = array();

    /** @var array<int,string> every model call, in order */
    public $calls = array();

    /** @var array<int,string> tag id => tag name, so save() can grow $rows */
    public $tagNames = array();

    public $Tag;

    public function __construct($tagNames = array())
    {
        $this->tagNames = $tagNames;
        $this->Tag = new EventBulkTaggingFakeTag();
    }

    public function find($type, $options = array())
    {
        $this->calls[] = "find:$type";
        $conditions = isset($options['conditions']) ? $options['conditions'] : array();
        $rows = array();
        foreach ($this->rows as $row) {
            if ($row['EventTag']['event_id'] != $conditions['EventTag.event_id']) {
                continue;
            }
            if (isset($conditions['EventTag.local'])) {
                if ((int)$row['EventTag']['local'] !== (int)$conditions['EventTag.local']) {
                    continue;
                }
            }
            $rows[] = $row;
        }
        if ($type === 'column') {
            // The 'column' find type returns a flat list of the single field asked for.
            $column = array();
            foreach ($rows as $row) {
                $column[] = $row['Tag']['name'];
            }
            return $column;
        }
        return $rows;
    }

    public function hasAny($conditions = array())
    {
        $this->calls[] = 'hasAny';
        foreach ($this->rows as $row) {
            if (
                $row['EventTag']['event_id'] == $conditions['event_id'] &&
                $row['EventTag']['tag_id'] == $conditions['tag_id']
            ) {
                return true;
            }
        }
        return false;
    }

    public function create($data = array())
    {
        $this->calls[] = 'create';
    }

    public function save($data = null)
    {
        $this->calls[] = 'save';
        $this->rows[] = array(
            'EventTag' => array(
                'event_id' => $data['event_id'],
                'tag_id' => $data['tag_id'],
                // tinyint(1), so the datasource hands back 0/1
                'local' => $data['local'] ? 1 : 0,
            ),
            'Tag' => array('name' => $this->tagNames[$data['tag_id']]),
        );
        return true;
    }
}

/** The tag catalogue the controller resolves $tag_id_list against. */
class EventBulkTaggingFakeTag
{
    public $tags = array();

    public function createConditions($user)
    {
        return array();
    }

    public function find($type, $options = array())
    {
        $rows = array();
        foreach ($this->tags as $tag) {
            if (in_array($tag['id'], $options['conditions']['Tag.id'])) {
                $rows[] = array('Tag' => $tag);
            }
        }
        return $rows;
    }
}

class EventBulkTaggingFakeEvent
{
    public $events = array();

    public $unpublished = array();

    public $EventTag;

    public function __construct($eventTag)
    {
        $this->EventTag = $eventTag;
    }

    public function find($type, $options = array())
    {
        $id = $options['conditions']['Event.id'];
        return isset($this->events[$id]) ? array('Event' => $this->events[$id]) : array();
    }

    public function unpublishEvent($event)
    {
        $this->unpublished[] = $event['Event']['id'];
    }
}

/**
 * Stands in for Taxonomy::checkIfNewTagIsAllowedByTaxonomy(): every tag here
 * belongs to an exclusive taxonomy, so a tag is refused as soon as another tag
 * with the same namespace is already on the event.
 */
class EventBulkTaggingFakeTaxonomy
{
    public $seen = array();

    public function checkIfNewTagIsAllowedByTaxonomy($newTagName, array $tagNameList = array())
    {
        $this->seen[$newTagName] = $tagNameList;
        $namespace = strstr($newTagName, ':', true);
        if ($namespace === false) {
            return true;
        }
        foreach ($tagNameList as $tagName) {
            if (strstr($tagName, ':', true) === $namespace) {
                return false;
            }
        }
        return true;
    }
}

class EventBulkTaggingFakeRequest
{
    public $data = array();

    public function is($what)
    {
        return $what === 'post';
    }
}

class EventBulkTaggingFakeAuth
{
    public function user($field = null)
    {
        return array('id' => 1, 'org_id' => 1, 'Role' => array('perm_tagger' => 1));
    }
}

/**
 * The controller with everything the bulk tagging branch needs injected, and
 * the ACL helpers answered from a list instead of from a user's role.
 */
class EventBulkTaggingTestableController extends EventsController
{
    public $request;

    public $params = array('named' => array());

    public $Auth;

    public $Event;

    public $Taxonomy;

    public $autoRender = true;

    public $layout = null;

    /** @var array<int,int> the events the acting user may modify */
    public $modifiableEventIds = array();

    public function __construct()
    {
    }

    public function loadModel($modelClass = null, $id = null)
    {
        return true;
    }

    protected function __canModifyEvent(array $event, $user = null)
    {
        return in_array($event['Event']['id'], $this->modifiableEventIds);
    }

    protected function __canModifyTag(array $event, $isTagLocal = false)
    {
        return true;
    }
}

class EventBulkTaggingTest extends TestCase
{
    /** @var EventBulkTaggingTestableController */
    private $controller;

    /** @var EventBulkTaggingFakeEventTag */
    private $eventTag;

    /** @var EventBulkTaggingFakeEvent */
    private $event;

    protected function setUp(): void
    {
        $tagNames = array(1 => 'tlp:red', 2 => 'tlp:green', 3 => 'course-of-action:passive');
        $this->eventTag = new EventBulkTaggingFakeEventTag($tagNames);
        $this->eventTag->Tag->tags = array(
            array('id' => 1, 'name' => 'tlp:red', 'local_only' => 0),
            array('id' => 2, 'name' => 'tlp:green', 'local_only' => 0),
            array('id' => 3, 'name' => 'course-of-action:passive', 'local_only' => 0),
        );
        $this->event = new EventBulkTaggingFakeEvent($this->eventTag);
        $this->event->events = array(
            10 => array('id' => 10, 'info' => 'first', 'orgc_id' => 1, 'org_id' => 1),
            11 => array('id' => 11, 'info' => 'second', 'orgc_id' => 1, 'org_id' => 1),
        );

        $this->controller = new EventBulkTaggingTestableController();
        $this->controller->request = new EventBulkTaggingFakeRequest();
        $this->controller->Auth = new EventBulkTaggingFakeAuth();
        $this->controller->Event = $this->event;
        $this->controller->Taxonomy = new EventBulkTaggingFakeTaxonomy();
        $this->controller->modifiableEventIds = array(10, 11);

        ClassRegistry::$instances['Log'] = new EventBulkTaggingFakeLog();
    }

    /**
     * @param array $eventIds
     * @param array $tagIds
     * @return array the decoded JSON body of the response
     */
    private function addTags(array $eventIds, array $tagIds)
    {
        $this->controller->request->data = array(
            'event_ids' => json_encode($eventIds),
            'tag' => json_encode($tagIds),
        );
        $response = $this->controller->addTag('selected');
        return json_decode($response->options['body'], true);
    }

    /**
     * @param array $row
     */
    private function attach(array $row)
    {
        $this->eventTag->rows[] = array(
            'EventTag' => $row,
            'Tag' => array('name' => $this->eventTag->tagNames[$row['tag_id']]),
        );
    }

    public function testExistingTagsAreFetchedOncePerEventAndNotOncePerTag()
    {
        $body = $this->addTags(array(10, 11), array(1, 3));

        $this->assertTrue($body['saved']);
        $this->assertSame(4, $body['attached']);

        $finds = array_values(array_filter($this->eventTag->calls, function ($call) {
            return strpos($call, 'find:') === 0;
        }));
        $this->assertSame(array('find:all', 'find:all'), $finds, 'one fetch per event, not per (event, tag) pair');
        $this->assertNotContains('hasAny', $this->eventTag->calls, 'the duplicate probe is answered in memory');
    }

    public function testAlreadyAttachedTagIsSkippedRegardlessOfItsLocalFlag()
    {
        $this->attach(array('event_id' => 10, 'tag_id' => 1, 'local' => 1));

        $body = $this->addTags(array(10), array(1, 3));

        $this->assertSame(1, $body['skipped']);
        $this->assertSame(1, $body['attached']);
    }

    public function testTagAttachedEarlierInTheSameRequestFeedsTheExclusivityCheck()
    {
        // tlp:red lands first, so tlp:green must be refused by the exclusivity
        // check even though it was not on the event when the request started.
        $body = $this->addTags(array(10), array(1, 2));

        $this->assertSame(1, $body['attached']);
        $this->assertSame(1, $body['failed']);
        $this->assertSame(array('tlp:red'), $this->controller->Taxonomy->seen['tlp:green']);
    }

    public function testExclusivityOnlySeesTheTagsMatchingTheEffectiveLocalFlag()
    {
        // A local tlp:red must not block a global tlp:green, exactly as the
        // `EventTag.local` condition of the removed per-pair query did.
        $this->attach(array('event_id' => 10, 'tag_id' => 1, 'local' => 1));

        $body = $this->addTags(array(10), array(2));

        $this->assertSame(1, $body['attached']);
        $this->assertSame(array(), $this->controller->Taxonomy->seen['tlp:green']);
        $this->assertSame(array(10), $this->event->unpublished);
    }
}
