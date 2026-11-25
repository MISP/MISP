<?php
/**
 * The workspace: the active collection's setting and recency
 * (ActiveWorkspaceTool), the collection edit rule on a row, adds and
 * removals in one request with who and when, and who staying inside the
 * collection's organisation.
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

if (!class_exists('CakeText', false)) {
    class CakeText
    {
        private static $counter = 0;

        public static function uuid()
        {
            self::$counter++;
            return sprintf('00000000-0000-4000-8000-%012d', self::$counter);
        }
    }
}

if (!class_exists('CakeLog', false)) {
    class CakeLog
    {
        public static $lines = array();

        public static function write($level, $message)
        {
            self::$lines[] = array($level, $message);
        }

        // Other suites loaded after this one log through debug(), warning()…
        public static function __callStatic($name, $args)
        {
            self::$lines[] = array($name, $args[0] ?? '');
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
                throw new RuntimeException("No fake registered for $name.");
            }
            return self::$instances[$name];
        }
    }
}

// The real Hash, not a stub: a partial one would shadow it for every test
// file loaded after this one.
if (!class_exists('Hash', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Hash.php';
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

require_once __DIR__ . '/../Lib/Tools/ComplexQueryTool.php';
require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Lib/Tools/AnalystGraphDocumentTool.php';
require_once __DIR__ . '/../Lib/Tools/DistributionLevel.php';
require_once __DIR__ . '/../Model/CollectionElement.php';
require_once __DIR__ . '/../Model/Collection.php';
require_once __DIR__ . '/../Lib/Tools/ActiveWorkspaceTool.php';

/** Records the legacy log being switched off and on. */
class WorkspaceTestBehaviors
{
    public $log = array();
    private $on;

    public function __construct($on)
    {
        $this->on = $on;
    }

    public function enabled($name)
    {
        return $this->on;
    }

    public function disable($name)
    {
        $this->log[] = array('disable', $name);
        $this->on = false;
    }

    public function enable($name)
    {
        $this->log[] = array('enable', $name);
        $this->on = true;
    }
}

/** Holds settings by name and records each write. */
class WorkspaceTestUserSetting
{
    public $Behaviors;
    public $values = array();
    public $writes = array();
    public $failOn = null;

    public function __construct($logged = true)
    {
        $this->Behaviors = new WorkspaceTestBehaviors($logged);
    }

    public function getValueForUser($userId, $setting)
    {
        return $this->values[$setting] ?? null;
    }

    public function setSettingInternal($userId, $setting, $value)
    {
        if ($this->failOn === $setting) {
            throw new RuntimeException('database gone');
        }
        $this->writes[] = array($setting, $value);
        $this->values[$setting] = $value;
        return array('UserSetting' => array('id' => 1));
    }
}

/** Answers workspaceSummaries() from fixed rows, matched by uuid. */
class WorkspaceTestCollection
{
    public $rows = array();
    public $calls = array();

    public function workspaceSummaries(array $user, array $conditions, $limit = null)
    {
        $this->calls[] = array($conditions, $limit);
        $uuids = self::uuidsIn($conditions);
        $out = array();
        foreach ($this->rows as $row) {
            if ($uuids === null || in_array($row['uuid'], array_map('strtolower', $uuids), true)) {
                $out[] = $row;
            }
        }
        return $limit ? array_slice($out, 0, $limit) : $out;
    }

    private static function uuidsIn(array $conditions)
    {
        foreach ($conditions as $key => $value) {
            if ($key === 'Collection.uuid') {
                return (array)$value;
            }
            if (is_array($value)) {
                $found = self::uuidsIn($value);
                if ($found !== null) {
                    return $found;
                }
            }
        }
        return null;
    }
}

/** Answers Graph::summaries() from fixed rows. */
class WorkspaceTestGraph
{
    public $rows = array();
    public $calls = array();

    public function summaries(array $user, array $conditions, array $options = array())
    {
        $this->calls[] = array($conditions, $options);
        return $this->rows;
    }
}

/** Records the parent collection being touched. */
class WorkspaceTestParent
{
    public $touched = array();
    public $distribution = 0;

    public function field($field, $conditions = null)
    {
        return $this->distribution;
    }

    public function updateAll($fields, $conditions)
    {
        $this->touched[] = $conditions['Collection.id'];
        return true;
    }

    public function markChanged(array $conditions)
    {
        $this->touched[] = $conditions['Collection.id'];
    }
}

/** A CollectionElement with its storage in memory. */
class WorkspaceTestElement extends CollectionElement
{
    public $id = false;
    public $readable = array();
    public $readableAsked = array();
    public $stored = array();
    public $saved = array();
    public $deleted = array();
    public $savedFields = array();
    public $failSave = false;

    public function __construct()
    {
        $this->Collection = new WorkspaceTestParent();
    }

    public function readableUuids(array $user, $type, array $uuids)
    {
        $this->readableAsked[$type] = $uuids;
        return array_values(array_intersect($this->readable[$type] ?? array(), $uuids));
    }

    public function create($data = array(), $filterKey = false)
    {
        $this->id = false;
        $this->data = array();
    }

    public function find($type = 'first', $query = array())
    {
        $column = null;
        $addresses = array();
        foreach ($query['conditions'] as $key => $value) {
            if ($key !== 'CollectionElement.collection_id') {
                $column = substr($key, strlen('CollectionElement.'));
                $addresses = $value;
            }
        }
        $out = array();
        foreach ($this->stored as $id => $row) {
            // As the address columns compare: case by case
            if (isset($row[$column]) && in_array($row[$column], (array)$addresses, true)) {
                $out[$id] = $row[$column];
            }
        }
        return $out;
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $this->data = $data;
        $this->beforeValidate();
        if ($this->failSave) {
            $this->validationErrors = array('element_type' => array('Invalid object type.'));
            return false;
        }
        $row = $this->data['CollectionElement'];
        $this->saved[] = $row;
        $this->savedFields[] = array($this->id, $fieldList);
        if ($this->id) {
            $row += $this->stored[$this->id];
            $this->stored[$this->id] = $row;
        } else {
            $this->stored[count($this->stored) + 100] = $row;
        }
        if (!$this->skipCollectionModifiedBump) {
            $this->Collection->updateAll(array(), array('Collection.id' => $row['collection_id']));
        }
        return $data;
    }

    public function delete($id = null, $cascade = true)
    {
        $this->deleted[] = $id;
        unset($this->stored[$id]);
        return true;
    }
}

/** A collection's members in memory, read as drawnMembers() asks for them. */
class WorkingTestElement extends CollectionElement
{
    public $rows = array();
    public $rowsRead = 0;
    /** @var array SHA-256 => the text an attribute the user can read holds */
    public $readableTexts = array();

    public function __construct()
    {
    }

    public function find($type = 'first', $query = array())
    {
        $out = array();
        foreach ($this->rows as $id => $row) {
            $keep = true;
            foreach ($query['conditions'] as $key => $wanted) {
                if ($key === 'CollectionElement.created >') {
                    $keep = $keep && $row['created'] > $wanted;
                } elseif ($key === 'CollectionElement.collection_id') {
                    $keep = $keep && in_array($row['collection_id'], (array)$wanted, false);
                } else {
                    $keep = $keep && in_array($row[substr($key, strlen('CollectionElement.'))], (array)$wanted, true);
                }
            }
            if ($keep) {
                $out[$id] = array('CollectionElement' => $row);
            }
        }
        ksort($out);
        if (isset($query['limit'])) {
            $out = array_slice($out, 0, $query['limit'], true);
        }
        $this->rowsRead += count($out);
        return array_values($out);
    }

    public function attachTargets(array $user, array $elements)
    {
        foreach ($elements as $i => $element) {
            if (isset($this->readableTexts[$element['element_sha256']])) {
                $elements[$i]['AttributeValue'] = array('value' => $this->readableTexts[$element['element_sha256']]);
            }
        }
        return $elements;
    }
}

/** captureElements() on an empty collection: every element it is sent is new. */
class WorkspaceTestCaptureElement extends WorkspaceTestElement
{
    public function find($type = 'first', $query = array())
    {
        return array();
    }
}

class CollectionWorkspaceTest extends TestCase
{
    const C1 = '9b000000-0000-4000-8000-000000000001';
    const C2 = '9b000000-0000-4000-8000-000000000002';
    const C3 = '9b000000-0000-4000-8000-000000000003';
    const G1 = '9b000000-0000-4000-8000-0000000000a1';
    const ORG = '9b000000-0000-4000-8000-0000000000f1';
    const EVENT = '9b000000-0000-4000-8000-0000000000e1';
    const ATTRIBUTE = '9b000000-0000-4000-8000-0000000000e2';

    /** @var WorkspaceTestUserSetting */
    private $settings;
    /** @var WorkspaceTestCollection */
    private $collections;
    /** @var WorkspaceTestGraph */
    private $graphs;
    private $registered = array();

    protected function setUp(): void
    {
        $this->settings = $this->register('UserSetting', new WorkspaceTestUserSetting());
        $this->collections = $this->register('Collection', new WorkspaceTestCollection());
        $this->graphs = $this->register('Graph', new WorkspaceTestGraph());
    }

    protected function tearDown(): void
    {
        foreach ($this->registered as $name) {
            unset(ClassRegistry::$instances[$name]);
        }
    }

    private function register($name, $fake)
    {
        ClassRegistry::$instances[$name] = $fake;
        $this->registered[] = $name;
        return $fake;
    }

    private static function user(array $role = array())
    {
        return array(
            'id' => 3,
            'org_id' => 1,
            'email' => 'analyst@example.test',
            'Role' => $role + array('perm_site_admin' => 0, 'perm_modify' => 1, 'perm_modify_org' => 1, 'perm_sync' => 0),
            'Organisation' => array('id' => 1, 'uuid' => self::ORG),
        );
    }

    private static function collection($uuid, $canEdit = true, $name = 'APT28 campaign')
    {
        return array('id' => 7, 'uuid' => $uuid, 'name' => $name, 'element_count' => 12, '_canEdit' => $canEdit);
    }

    private static function graph($on = self::C1, $org = self::ORG, $type = 'Collection')
    {
        return array('uuid' => self::G1, 'name' => 'Delivery chain', 'object_type' => $type, 'object_uuid' => $on, 'orgc_uuid' => $org);
    }

    // ------------------------------------------------------------ the setting

    public function unusableStoredValues()
    {
        return array(
            'never set' => array(null),
            'empty' => array(array()),
            'cleared' => array(array('collection_uuid' => null, 'graph_uuid' => null)),
            'the Early Access shape' => array(array('workspace_uuid' => self::G1)),
            'not a uuid' => array(array('collection_uuid' => 'zz')),
            'not a string' => array(array('collection_uuid' => 5)),
        );
    }

    /**
     * @dataProvider unusableStoredValues
     */
    public function testNoWorkspaceWithoutAUsableStoredCollection($stored)
    {
        $this->settings->values[ActiveWorkspaceTool::SETTING] = $stored;

        $this->assertNull(ActiveWorkspaceTool::stored(self::user()));
        $this->assertSame(array('Collection' => null, 'Graph' => null), ActiveWorkspaceTool::forUser(self::user()));
        $this->assertSame(array(), $this->collections->calls, 'nothing is looked up');
        $this->assertSame(array(), $this->settings->writes);
    }

    public function testTheStoredUuidsAreReadInLowerCase()
    {
        $this->settings->values[ActiveWorkspaceTool::SETTING] = array('collection_uuid' => strtoupper(self::C1), 'graph_uuid' => 'not a uuid');

        $this->assertSame(array('collection_uuid' => self::C1, 'graph_uuid' => null), ActiveWorkspaceTool::stored(self::user()));
    }

    public function testTheWorkspaceIsTheCollectionAndItsGraph()
    {
        $this->settings->values[ActiveWorkspaceTool::SETTING] = array('collection_uuid' => self::C1, 'graph_uuid' => self::G1);
        $this->collections->rows = array(self::collection(self::C1));
        $this->graphs->rows = array(self::graph());

        $workspace = ActiveWorkspaceTool::forUser(self::user());

        $this->assertSame(self::C1, $workspace['Collection']['uuid']);
        $this->assertSame(self::G1, $workspace['Graph']['uuid']);
        $this->assertSame(array(), $this->settings->writes, 'a valid setting is not rewritten');
    }

    public function testACollectionThatIsGoneEndsTheWorkspace()
    {
        $this->settings->values[ActiveWorkspaceTool::SETTING] = array('collection_uuid' => self::C1, 'graph_uuid' => self::G1);

        $this->assertSame(array('Collection' => null, 'Graph' => null), ActiveWorkspaceTool::forUser(self::user()));
        $this->assertSame(array(array(ActiveWorkspaceTool::SETTING, array('collection_uuid' => null, 'graph_uuid' => null))), $this->settings->writes);
    }

    public function testACollectionTheUserCanNoLongerEditEndsTheWorkspace()
    {
        $this->settings->values[ActiveWorkspaceTool::SETTING] = array('collection_uuid' => self::C1, 'graph_uuid' => null);
        $this->collections->rows = array(self::collection(self::C1, false));

        $this->assertSame(array('Collection' => null, 'Graph' => null), ActiveWorkspaceTool::forUser(self::user()));
        $this->assertSame(array(array(ActiveWorkspaceTool::SETTING, array('collection_uuid' => null, 'graph_uuid' => null))), $this->settings->writes);
    }

    public function graphsThatNoLongerLayItOut()
    {
        return array(
            'gone' => array(array()),
            'another organisation\'s' => array(array(self::graph(self::C1, '9b000000-0000-4000-8000-0000000000f2'))),
            'on another collection' => array(array(self::graph(self::C2))),
            'on an event' => array(array(self::graph(self::C1, self::ORG, 'Event'))),
        );
    }

    /**
     * @dataProvider graphsThatNoLongerLayItOut
     */
    public function testAGraphThatNoLongerLaysItOutLeavesTheCollectionWithout(array $graphRows)
    {
        $this->settings->values[ActiveWorkspaceTool::SETTING] = array('collection_uuid' => self::C1, 'graph_uuid' => self::G1);
        $this->collections->rows = array(self::collection(self::C1));
        $this->graphs->rows = $graphRows;

        $workspace = ActiveWorkspaceTool::forUser(self::user());

        $this->assertSame(self::C1, $workspace['Collection']['uuid']);
        $this->assertNull($workspace['Graph']);
        $this->assertSame(array(array(ActiveWorkspaceTool::SETTING, array('collection_uuid' => self::C1, 'graph_uuid' => null))), $this->settings->writes);
    }

    // ------------------------------------------------------------ choosing

    public function testChoosingStoresItAndPutsItFirstAmongTheUsed()
    {
        $this->collections->rows = array(self::collection(self::C1));
        $this->graphs->rows = array(self::graph());
        $this->settings->values[ActiveWorkspaceTool::RECENT_SETTING] = array(
            array('collection_uuid' => self::C2, 'at' => 200),
            array('collection_uuid' => self::C1, 'at' => 100),
        );

        list($workspace, $refusal) = ActiveWorkspaceTool::choose(self::user(), strtoupper(self::C1), self::G1);

        $this->assertNull($refusal);
        $this->assertSame(self::G1, $workspace['Graph']['uuid']);
        $this->assertSame(array(ActiveWorkspaceTool::SETTING, array('collection_uuid' => self::C1, 'graph_uuid' => self::G1)), $this->settings->writes[0]);
        $recent = $this->settings->values[ActiveWorkspaceTool::RECENT_SETTING];
        $this->assertSame(array(self::C1, self::C2), array_column($recent, 'collection_uuid'), 'moved first, not repeated');
        $this->assertGreaterThan(200, $recent[0]['at']);
    }

    public function testAGraphLeftOutIsTheOrganisationsNewestOnIt()
    {
        $this->collections->rows = array(self::collection(self::C1));
        $this->graphs->rows = array(self::graph());

        list($workspace) = ActiveWorkspaceTool::choose(self::user(), self::C1, null, false);

        $this->assertSame(self::G1, $workspace['Graph']['uuid']);
        $newest = $this->graphs->calls[0];
        $this->assertSame('Collection', $newest[0]['Graph.object_type']);
        $this->assertSame(self::ORG, $newest[0]['Graph.orgc_uuid']);
        $this->assertSame(1, $newest[1]['limit']);
        $this->assertFalse($newest[1]['counts'], 'no document is read to pick it');
        $this->assertFalse($this->graphs->calls[1][1]['counts'], 'nor to check it');
    }

    public function testANullGraphMeansNone()
    {
        $this->collections->rows = array(self::collection(self::C1));
        $this->graphs->rows = array(self::graph());

        list($workspace) = ActiveWorkspaceTool::choose(self::user(), self::C1, null, true);

        $this->assertNull($workspace['Graph']);
        $this->assertSame(array(), $this->graphs->calls);
    }

    public function testRefusalsWriteNothing()
    {
        $this->collections->rows = array(self::collection(self::C1, false), self::collection(self::C2));

        $this->assertSame('collection', ActiveWorkspaceTool::choose(self::user(), self::C3)[1]);
        $this->assertSame('edit', ActiveWorkspaceTool::choose(self::user(), self::C1)[1]);
        $this->assertSame('graph', ActiveWorkspaceTool::choose(self::user(), self::C2, self::G1)[1]);
        $this->assertSame('collection', ActiveWorkspaceTool::choose(self::user(), 'not a uuid')[1]);
        $this->assertSame(array(), $this->settings->writes);
    }

    public function testANullCollectionEndsTheWorkspace()
    {
        list($workspace, $refusal) = ActiveWorkspaceTool::choose(self::user(), null);

        $this->assertNull($refusal);
        $this->assertSame(array('Collection' => null, 'Graph' => null), $workspace);
        $this->assertSame(array(array(ActiveWorkspaceTool::SETTING, array('collection_uuid' => null, 'graph_uuid' => null))), $this->settings->writes);
    }

    public function testTheChoiceStaysOutOfTheLegacyLog()
    {
        $this->collections->rows = array(self::collection(self::C1));

        ActiveWorkspaceTool::choose(self::user(), self::C1, null);

        $this->assertSame(array(
            array('disable', 'SysLogLogable.SysLogLogable'),
            array('enable', 'SysLogLogable.SysLogLogable'),
            array('disable', 'SysLogLogable.SysLogLogable'),
            array('enable', 'SysLogLogable.SysLogLogable'),
        ), $this->settings->Behaviors->log);
    }

    public function testAFailedRecencyWriteIsDroppedAndTheLogComesBack()
    {
        $this->settings->failOn = ActiveWorkspaceTool::RECENT_SETTING;

        ActiveWorkspaceTool::used(self::user(), self::C1);

        $this->assertSame(array('enable', 'SysLogLogable.SysLogLogable'), end($this->settings->Behaviors->log));
        $this->assertStringContainsString('database gone', end(CakeLog::$lines)[1]);
    }

    public function testRecencyKeepsTwentyWellFormedEntries()
    {
        $stored = array(array('collection_uuid' => 'zz', 'at' => 1), 'nonsense');
        for ($i = 0; $i < 25; $i++) {
            $stored[] = array('collection_uuid' => sprintf('9b000000-0000-4000-8000-%012d', $i), 'at' => 1000 - $i);
        }
        $this->settings->values[ActiveWorkspaceTool::RECENT_SETTING] = $stored;

        $recent = ActiveWorkspaceTool::recent(self::user());

        $this->assertCount(ActiveWorkspaceTool::RECENT_CAP, $recent);
        $this->assertSame(1000, reset($recent));
    }

    // ------------------------------------------------------------ the chooser

    public function testTheChooserListsTheUsedOnesFirstThenTheRest()
    {
        $this->settings->values[ActiveWorkspaceTool::RECENT_SETTING] = array(
            array('collection_uuid' => self::C2, 'at' => 300),
            array('collection_uuid' => self::C1, 'at' => 100),
        );
        $this->collections->rows = array(
            self::collection(self::C1),
            self::collection(self::C3),
            self::collection(self::C2),
            self::collection('9b000000-0000-4000-8000-000000000004', false),
        );

        $list = ActiveWorkspaceTool::editable(self::user(), 'org');

        $this->assertSame(array(self::C2, self::C1, self::C3), array_column($list, 'uuid'), 'used newest first, then the rest; read-only left out; each once');
        $this->assertSame(array(300, 100, null), array_column($list, 'used'));
    }

    public function testMineIsWhatTheUserCreated()
    {
        ActiveWorkspaceTool::editable(self::user(), 'mine');

        $this->assertSame(array(array('Collection.user_id' => 3)), $this->collections->calls[0][0]);
    }

    public function testNoChooserWithoutTheRightToModify()
    {
        $this->assertSame(array(), ActiveWorkspaceTool::editable(self::user(array('perm_modify' => 0)), 'org'));
        $this->assertSame(array(), $this->collections->calls);
    }

    // ------------------------------------------------------------ the edit rule

    public function editRule()
    {
        $row = array('org_id' => '1', 'orgc_id' => '1', 'user_id' => '9');
        return array(
            'site admin' => array(array('perm_site_admin' => 1, 'perm_modify' => 0), array('orgc_id' => '5') + $row, true),
            'no perm_modify' => array(array('perm_modify' => 0), $row, false),
            'creator organisation' => array(array(), $row, true),
            'another organisation' => array(array(), array('org_id' => '5', 'orgc_id' => '5') + $row, false),
            'sync user, owning organisation' => array(array('perm_sync' => 1), array('orgc_id' => '5') + $row, true),
            'own collection, no perm_modify_org' => array(array('perm_modify_org' => 0), array('user_id' => '3') + $row, true),
            'organisation\'s, no perm_modify_org' => array(array('perm_modify_org' => 0), $row, false),
        );
    }

    /**
     * @dataProvider editRule
     */
    public function testTheCollectionRuleOnARow(array $role, array $row, $expected)
    {
        $this->assertSame($expected, (new Collection(false, null, null))->canModify(self::user($role), $row));
    }

    public function testWhoAddedAMemberStaysWithTheCollectionsOrganisation()
    {
        $this->assertTrue(Collection::showsAdders(self::user(), array('orgc_id' => '1')));
        $this->assertFalse(Collection::showsAdders(self::user(), array('orgc_id' => '5')));
        $this->assertTrue(Collection::showsAdders(self::user(array('perm_site_admin' => 1)), array('orgc_id' => '5')));

        $stripped = Collection::withoutAdders(array(
            array('uuid' => 'a', 'user_id' => 3, 'created' => '2026-10-28 10:00:00'),
            array('uuid' => 'b', 'user_id' => null, 'created' => null),
        ));
        $this->assertSame(array(
            array('uuid' => 'a', 'created' => '2026-10-28 10:00:00'),
            array('uuid' => 'b', 'created' => null),
        ), $stripped);
    }

    // ------------------------------------------------------------ items

    public function testItemsAreNamedAsGraphDocumentsNameThem()
    {
        $value = hash('sha256', 'evil.example');
        $this->assertSame(
            array('key' => 'Event:' . self::EVENT, 'element_type' => 'Event', 'column' => 'element_uuid', 'address' => self::EVENT),
            CollectionElement::itemTarget(array('type' => 'Event', 'uuid' => strtoupper(self::EVENT)))
        );
        $this->assertSame(
            array('key' => 'Value:' . $value, 'element_type' => 'AttributeValue', 'column' => 'element_sha256', 'address' => $value, 'text' => 'evil.example'),
            CollectionElement::itemTarget(array('type' => 'Value', 'value' => ' evil.example '))
        );
        $this->assertSame('Value:' . $value, CollectionElement::itemTarget(array('type' => 'Value', 'sha256' => strtoupper($value)))['key']);
        $this->assertSame('Attribute:' . self::ATTRIBUTE, CollectionElement::itemTarget('Attribute:' . self::ATTRIBUTE)['key'], 'a reported key');
        foreach (array(null, 'Event', array('type' => 'Note', 'uuid' => self::EVENT), array('type' => 'Event', 'uuid' => 'nope'),
                       array('type' => 'Value', 'value' => '  '), array('type' => 'Value', 'sha256' => 'abc'), array('type' => 'AttributeValue', 'sha256' => $value)) as $bad) {
            $this->assertNull(CollectionElement::itemTarget($bad), json_encode($bad));
        }
    }

    public function testAnAddAnswersPerItemAndRecordsWhoAndWhen()
    {
        $elements = new WorkspaceTestElement();
        $value = hash('sha256', 'held.example');
        $elements->readable = array('Event' => array(self::EVENT, strtoupper('9b000000-0000-4000-8000-0000000000e3')), 'AttributeValue' => array($value));
        $elements->stored[1] = array('collection_id' => 7, 'element_type' => 'Event', 'element_uuid' => self::EVENT);

        $report = $elements->addItems(self::user(), 7, array(
            array('type' => 'Event', 'uuid' => self::EVENT),
            array('type' => 'Event', 'uuid' => strtoupper('9b000000-0000-4000-8000-0000000000e3')),
            array('type' => 'Event', 'uuid' => '9b000000-0000-4000-8000-0000000000e3'),
            array('type' => 'Value', 'value' => 'held.example'),
            array('type' => 'Value', 'value' => 'never.example'),
            array('type' => 'Attribute', 'uuid' => self::ATTRIBUTE),
            array('type' => 'Note', 'uuid' => self::ATTRIBUTE),
        ), 'from the hunt');

        $this->assertSame(array('Event:9b000000-0000-4000-8000-0000000000e3', 'Value:' . $value, 'Value:' . hash('sha256', 'never.example')), $report['added']);
        $this->assertSame(array('Event:' . self::EVENT), $report['present']);
        $this->assertSame(array(6, 5), array_column($report['refused'], 'index'));
        $errors = array_column($report['refused'], 'error', 'index');
        $this->assertSame('Not a record a collection can hold.', $errors[6]);
        $this->assertSame('Not found or not authorised.', $errors[5]);
        $this->assertContains('9B000000-0000-4000-8000-0000000000E3', $elements->readableAsked['Event'], 'looked up as stored, either case');

        foreach ($elements->saved as $row) {
            $this->assertSame(3, $row['user_id']);
            $this->assertRegExp('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $row['created']);
            $this->assertSame('from the hunt', $row['description']);
        }
        $this->assertSame('element_sha256', array_keys(array_filter($elements->saved[1], function ($v) use ($value) { return $v === $value; }))[0]);
        $this->assertSame(array(7), $elements->Collection->touched, 'the collection is touched once');
    }

    public function testNothingAddedTouchesNothing()
    {
        $elements = new WorkspaceTestElement();
        $elements->readable = array('Event' => array(self::EVENT));
        $elements->stored[1] = array('collection_id' => 7, 'element_type' => 'Event', 'element_uuid' => self::EVENT);

        $report = $elements->addItems(self::user(), 7, array(array('type' => 'Event', 'uuid' => self::EVENT)));

        $this->assertSame(array(), $report['added']);
        $this->assertSame(array(), $elements->Collection->touched);
    }

    public function testAFailedSaveIsRefusedWithItsReason()
    {
        $elements = new WorkspaceTestElement();
        $elements->readable = array('Event' => array(self::EVENT));
        $elements->failSave = true;

        $report = $elements->addItems(self::user(), 7, array(array('type' => 'Event', 'uuid' => self::EVENT)));

        $this->assertSame(array(array('index' => 0, 'key' => 'Event:' . self::EVENT, 'error' => 'Invalid object type.')), $report['refused']);
    }

    public function testARequestCannotSayWhoAddedAMemberOrWhen()
    {
        $elements = new WorkspaceTestElement();
        $elements->current_user = self::user();

        $elements->save(array('CollectionElement' => array(
            'collection_id' => 7, 'element_type' => 'Event', 'element_uuid' => self::EVENT,
            'user_id' => 1, 'created' => '2001-01-01 00:00:00', 'published' => true,
        )));

        $this->assertSame(3, $elements->saved[0]['user_id']);
        $this->assertNotSame('2001-01-01 00:00:00', $elements->saved[0]['created']);
        $this->assertFalse($elements->saved[0]['published'], 'partners lack it until the next publish');
    }

    public function testACaptureFromAnotherInstanceNamesNobodyAndKeepsWhen()
    {
        $elements = new WorkspaceTestCaptureElement();
        $elements->current_user = self::user();

        $elements->captureElements(array('Collection' => array('id' => 7, 'CollectionElement' => array(
            array('uuid' => 'e1', 'element_type' => 'Event', 'element_uuid' => self::EVENT, 'user_id' => 42, 'created' => '2026-10-01 09:00:00'),
            array('uuid' => 'e2', 'element_type' => 'Attribute', 'element_uuid' => self::ATTRIBUTE, 'created' => 'yesterday'),
            array('uuid' => 'e3', 'element_type' => 'GalaxyCluster', 'element_uuid' => '9b000000-0000-4000-8000-0000000000e4'),
        ))), false, true);

        $this->assertSame(array(null, null, null), array_column($elements->saved, 'user_id'));
        $this->assertSame(array('2026-10-01 09:00:00', null, null), array_column($elements->saved, 'created'));
        $this->assertSame(array(true, true, true), array_column($elements->saved, 'published'), 'what another instance sends, it published');

        $elements->saved = array();
        $elements->save(array('CollectionElement' => array('collection_id' => 7, 'element_type' => 'Event', 'element_uuid' => self::EVENT)));
        $this->assertSame(3, $elements->saved[0]['user_id'], 'a local save after it names its user again');
    }

    public function testANestedElementSavedLocallyNamesItsUser()
    {
        $elements = new WorkspaceTestCaptureElement();
        $elements->current_user = self::user();

        $elements->captureElements(array('Collection' => array('id' => 7, 'CollectionElement' => array(
            array('element_type' => 'Event', 'element_uuid' => self::EVENT, 'user_id' => 42, 'created' => '2001-01-01 00:00:00'),
        ))));

        $this->assertSame(3, $elements->saved[0]['user_id']);
        $this->assertNotSame('2001-01-01 00:00:00', $elements->saved[0]['created']);
    }

    public function testAMemberSavedWithCapitalsIsFoundAsAnyOther()
    {
        $elements = new WorkspaceTestElement();
        $elements->readable = array('Event' => array(self::EVENT));
        $elements->current_user = self::user();
        // The legacy form and a REST edit save the uuid as they are given it
        $elements->save(array('CollectionElement' => array(
            'collection_id' => 7, 'element_type' => 'Event', 'element_uuid' => strtoupper(self::EVENT),
        )));
        $this->assertSame(self::EVENT, $elements->saved[0]['element_uuid']);

        $report = $elements->addItems(self::user(), 7, array(array('type' => 'Event', 'uuid' => self::EVENT)));
        $this->assertSame(array('Event:' . self::EVENT), $report['present']);
        $this->assertCount(1, $elements->saved, 'nothing written');

        $held = $elements->heldItems(self::user(), 7, array(array('type' => 'Event', 'uuid' => strtoupper(self::EVENT))));
        $this->assertSame(array('Event:' . self::EVENT), $held['present']);

        $removed = $elements->removeItems(7, array('Event:' . self::EVENT));
        $this->assertSame(array('Event:' . self::EVENT), $removed['removed']);
        $this->assertSame(array(), $elements->stored);
    }

    public function testACapturedMemberIsStoredLowercase()
    {
        $elements = new WorkspaceTestCaptureElement();

        $elements->captureElements(array('Collection' => array('id' => 7, 'CollectionElement' => array(
            array('uuid' => 'e1', 'element_type' => 'Event', 'element_uuid' => strtoupper(self::EVENT)),
        ))), false, true);

        $this->assertSame(self::EVENT, $elements->saved[0]['element_uuid']);
    }

    /**
     * A collection of 2,300 members of every kind, and a graph holding 25 of
     * them (some joined early, some past the first 2,000) and 15 extras.
     *
     * @return array [WorkingTestElement, graph nodes]
     */
    private static function bigCollection()
    {
        $elements = new WorkingTestElement();
        $types = array('Event', 'Attribute', 'Object', 'GalaxyCluster', 'StandaloneObject');
        for ($i = 1; $i <= 2300; $i++) {
            $row = array(
                'uuid' => sprintf('row-%04d', $i), 'collection_id' => 7, 'element_type' => null, 'element_uuid' => null,
                'element_sha256' => null, 'element_value' => null, 'description' => 'why ' . $i, 'user_id' => $i % 3,
                'created' => sprintf('2026-11-%02d %02d:%02d:00', 1 + intdiv($i, 1000), intdiv($i % 1000, 60) % 24, $i % 60),
                'origin' => null,
            );
            if ($i % 4 === 0) {
                $text = 'value-' . $i . '.example';
                $row['element_type'] = 'AttributeValue';
                $row['element_sha256'] = hash('sha256', $text);
                if ($i % 8 === 0) {
                    $row['element_value'] = $text;
                } elseif ($i % 3 === 0) {
                    $elements->readableTexts[$row['element_sha256']] = $text;
                }
            } else {
                $row['element_type'] = $types[$i % 5];
                $row['element_uuid'] = sprintf('9b000000-0000-4000-8000-%012d', $i);
            }
            $elements->rows[$i] = $row;
        }
        $graph = array();
        foreach (array(3, 4, 8, 12, 50, 51, 52, 99, 400, 1000, 1500, 1999, 2000, 2001, 2002, 2050, 2100, 2200, 2296, 2297, 2298, 2299, 2300, 7, 9) as $i) {
            $row = $elements->rows[$i];
            $graph[] = $row['element_type'] === 'AttributeValue'
                ? array('type' => 'Value', 'value' => 'v', 'sha256' => $row['element_sha256'], 'x' => $i)
                : array('type' => $row['element_type'], 'uuid' => $row['element_uuid'], 'x' => $i);
        }
        for ($i = 1; $i <= 15; $i++) {
            $graph[] = array('type' => 'Event', 'uuid' => sprintf('9c000000-0000-4000-8000-%012d', $i));
        }
        return array($elements, $graph);
    }

    /**
     * The members drawn as the working view drew them before it read in
     * bounds: every member, then those the graph lacks while there is room.
     *
     * @return array [nodes, every member's element by key, left out]
     */
    private static function drawnReadingEveryMember(WorkingTestElement $elements, array $graph, $since = null)
    {
        $held = array();
        foreach ($graph as $node) {
            $held[AnalystGraphDocumentTool::nodeKey($node)] = true;
        }
        $room = max(0, AnalystGraphDocumentTool::MAX_NODES - count($graph));
        $byKey = array();
        $nodes = array();
        $leftOut = 0;
        foreach ($elements->rows as $element) {
            if ($since !== null && !($element['created'] > $since)) {
                continue;
            }
            $target = CollectionElement::itemTarget($element['element_type'] === 'AttributeValue'
                ? array('type' => 'Value', 'sha256' => $element['element_sha256'])
                : array('type' => $element['element_type'], 'uuid' => $element['element_uuid']));
            $byKey[$target['key']] = $element;
            if (isset($held[$target['key']])) {
                continue;
            }
            if (count($nodes) >= $room) {
                $leftOut++;
                continue;
            }
            $held[$target['key']] = true;
            if ($target['element_type'] === 'AttributeValue') {
                $text = $element['element_value'] ?? ($elements->readableTexts[$target['address']] ?? null);
                $nodes[] = $text === null ? null : array('type' => 'Value', 'value' => $text, 'sha256' => $target['address']);
            } else {
                $nodes[] = array('type' => $element['element_type'], 'uuid' => $target['address']);
            }
        }
        return array(array_values(array_filter($nodes)), $byKey, $leftOut);
    }

    public function testAWorkingViewDrawsWhatItDidReadingAtMostMaxNodesBesidesTheGraph()
    {
        list($elements, $graph) = self::bigCollection();
        list($nodes, $byKey, $leftOut) = self::drawnReadingEveryMember($elements, $graph);

        $drawn = $elements->drawnMembers(self::user(), 7, $graph);

        $this->assertSame($nodes, $drawn['nodes']);
        $this->assertSame(25, $drawn['in_graph']);
        $this->assertSame($leftOut, count($elements->rows) - $drawn['in_graph'] - $drawn['room'], 'members left out');
        $drawnKeys = array();
        foreach (array_merge($graph, $drawn['nodes']) as $node) {
            $drawnKeys[AnalystGraphDocumentTool::nodeKey($node)] = true;
        }
        $expected = array_intersect_key($byKey, $drawnKeys);
        ksort($expected);
        $got = $drawn['elements'];
        ksort($got);
        $this->assertSame($expected, $got, 'the elements the marks read: every member drawn, no other');
        $this->assertLessThanOrEqual(AnalystGraphDocumentTool::MAX_NODES + count($graph), $elements->rowsRead);
    }

    public function testMembersJoinedSinceAreDrawnAsBefore()
    {
        list($elements, $graph) = self::bigCollection();
        $since = $elements->rows[1200]['created'];
        list($nodes) = self::drawnReadingEveryMember($elements, $graph, $since);

        $drawn = $elements->drawnMembers(self::user(), 7, $graph, $since);

        $this->assertSame($nodes, $drawn['nodes']);
        $this->assertLessThanOrEqual(AnalystGraphDocumentTool::MAX_NODES, $elements->rowsRead, 'the graph\'s own are not looked up');
    }

    public function testAFullGraphLeavesNoRoomAndReadsNoNewMember()
    {
        list($elements) = self::bigCollection();
        $graph = array();
        for ($i = 1; $i <= AnalystGraphDocumentTool::MAX_NODES; $i++) {
            $graph[] = array('type' => 'Event', 'uuid' => sprintf('9c000000-0000-4000-8000-%012d', $i));
        }

        $drawn = $elements->drawnMembers(self::user(), 7, $graph);

        $this->assertSame(array(), $drawn['nodes']);
        $this->assertSame(0, $drawn['room']);
        $this->assertSame(0, $elements->rowsRead);
    }

    public function testRemovingTakesKeysAndSaysWhatWasNotThere()
    {
        $elements = new WorkspaceTestElement();
        $elements->stored[1] = array('collection_id' => 7, 'element_type' => 'Event', 'element_uuid' => self::EVENT);

        $report = $elements->removeItems(7, array('Event:' . self::EVENT, array('type' => 'Attribute', 'uuid' => self::ATTRIBUTE), 'Nope:1'));

        $this->assertSame(array('Event:' . self::EVENT), $report['removed']);
        $this->assertSame(array('Attribute:' . self::ATTRIBUTE), $report['absent']);
        $this->assertSame(array(2), array_column($report['refused'], 'index'));
        $this->assertSame(array(1), $elements->deleted);
        $this->assertSame(array(7), $elements->Collection->touched);
    }

    public function testDescribingSavesWhyAloneOnTheMemberItNames()
    {
        $elements = new WorkspaceTestElement();
        $value = hash('sha256', 'held.example');
        $elements->stored[1] = array('collection_id' => 7, 'element_type' => 'Event', 'element_uuid' => self::EVENT);
        $elements->stored[2] = array('collection_id' => 7, 'element_type' => 'AttributeValue', 'element_sha256' => $value);

        $key = $elements->describeItem(7, array('type' => 'Value', 'value' => ' held.example '), 'Seen in the phishing wave');

        $this->assertSame('Value:' . $value, $key);
        $this->assertSame(array(array(2, array('description'))), $elements->savedFields);
        $this->assertSame('Seen in the phishing wave', $elements->saved[0]['description']);
        $this->assertArrayNotHasKey('user_id', $elements->saved[0], 'who added it stays');
        $this->assertArrayNotHasKey('created', $elements->saved[0], 'when it was added stays');
        $this->assertSame(array(7), $elements->Collection->touched, 'the collection has a change partners lack');

        $this->assertNull($elements->describeItem(7, 'Attribute:' . self::ATTRIBUTE, 'not a member'));
        $this->assertNull($elements->describeItem(7, 'Nope:1', 'not a record'));
        $this->assertCount(1, $elements->saved);
    }

    public function testHeldItemsAnswersOnlyForWhatTheUserCanRead()
    {
        $elements = new WorkspaceTestElement();
        $value = hash('sha256', 'held.example');
        $hidden = '9b000000-0000-4000-8000-0000000000e4';
        $elements->readable = array('Event' => array(self::EVENT, $hidden), 'Attribute' => array(self::ATTRIBUTE), 'AttributeValue' => array($value));
        $elements->stored[1] = array('collection_id' => 7, 'element_type' => 'Event', 'element_uuid' => self::EVENT);
        $elements->stored[2] = array('collection_id' => 7, 'element_type' => 'AttributeValue', 'element_sha256' => $value);
        $elements->stored[3] = array('collection_id' => 7, 'element_type' => 'Object', 'element_uuid' => self::C3);

        $report = $elements->heldItems(self::user(), 7, array(
            array('type' => 'Event', 'uuid' => strtoupper(self::EVENT)),
            array('type' => 'Value', 'value' => ' held.example '),
            array('type' => 'Attribute', 'uuid' => self::ATTRIBUTE),
            array('type' => 'Object', 'uuid' => self::C3),
            array('type' => 'Event', 'uuid' => $hidden),
            'Nope:1',
        ));

        $this->assertSame(array('Event:' . self::EVENT, 'Value:' . $value), $report['present']);
        $this->assertSame(array('Attribute:' . self::ATTRIBUTE, 'Object:' . self::C3, 'Event:' . $hidden), $report['absent'], 'an unreadable member is answered absent');
        $this->assertSame(array(), $elements->saved);
        $this->assertSame(array(), $elements->deleted);
        $this->assertSame(array(), $elements->Collection->touched);
    }
}
