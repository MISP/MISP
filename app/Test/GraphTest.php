<?php
/**
 * Analyst graphs: the document validator and its caps, edit rights, the
 * audit summary, and graphs staying out of embedded analyst data.
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

if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function check($key)
        {
            return isset(self::$values[$key]);
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
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

if (!class_exists('Model', false)) {
    class Model
    {
    }
}

if (!class_exists('ModelBehavior', false)) {
    class ModelBehavior
    {
        public function __construct()
        {
        }
    }
}

if (!class_exists('Validation', false)) {
    class Validation
    {
        public static function uuid($check)
        {
            return is_string($check) && (bool)preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[0-5][a-f0-9]{3}-[089ab][a-f0-9]{3}-[a-f0-9]{12}$/i', $check);
        }
    }
}

if (!class_exists('AuditLog', false)) {
    class AuditLog
    {
        const ACTION_ADD = 'add';
        const ACTION_EDIT = 'edit';
        const ACTION_SOFT_DELETE = 'soft_delete';
        const ACTION_UNDELETE = 'undelete';
        const ACTION_DELETE = 'delete';
    }
}

require_once __DIR__ . '/../Lib/Tools/AnalystGraphDocumentTool.php';
require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Model/Graph.php';
require_once __DIR__ . '/../Model/Behavior/AnalystDataParentBehavior.php';
require_once __DIR__ . '/../Model/Behavior/AuditLogBehavior.php';
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueUrlTool.php';
require_once __DIR__ . '/../Model/AnalystGraphData.php';

class GraphTestGraph extends Graph
{
    public $alias = 'Graph';
    public $name = 'Graph';

    public function __construct()
    {
    }
}

class GraphTestModel extends Model
{
    public $name = 'Graph';
    public $alias = 'Graph';
    public $primaryKey = 'id';
    public $id = 1;
    public $data = array();
    public $includeAnalystDataRecursive = false;
    public $graph;

    public function __construct()
    {
        $this->graph = new GraphTestGraph();
    }

    public function schema($field = false)
    {
        $fields = array();
        foreach (array('id', 'content_size', 'node_count', 'revision') as $name) {
            $fields[$name] = array('type' => 'integer');
        }
        foreach (array('uuid', 'name', 'content') as $name) {
            $fields[$name] = array('type' => 'string');
        }
        return $fields;
    }

    public function auditLogSummary($field, $old, $new)
    {
        $this->graph->data = $this->data;
        return $this->graph->auditLogSummary($field, $old, $new);
    }
}

class GraphTestRecorder
{
    public $calls = array();
    public $fetchRecursive;

    public function fetchForUuids($uuids, $user = null)
    {
        $this->calls[] = $uuids;
        return array();
    }

    public function insert(array $row)
    {
        $this->calls[] = $row;
    }
}

class GraphTestDataSource
{
    public $log = array();
    public $rows = array();

    public function begin()
    {
        $this->log[] = 'begin';
        return true;
    }

    public function commit()
    {
        $this->log[] = 'commit';
        return true;
    }

    public function rollback()
    {
        $this->log[] = 'rollback';
        return true;
    }

    public function name($field)
    {
        return '`' . $field . '`';
    }

    public function fullTableName($model)
    {
        return '`analyst_graphs`';
    }

    public function fetchAll($sql, $params = array(), $options = array())
    {
        $this->log[] = array($sql, $params, $options);
        return $this->rows;
    }
}

class GraphTestWritableGraph extends GraphTestGraph
{
    public $db;
    public $saves = array();
    public $refuse = false;

    public function getDataSource()
    {
        return $this->db;
    }

    public function create($data = array())
    {
        $this->id = false;
        $this->data = array();
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $this->saves[] = array($data, $validate);
        if ($this->refuse) {
            $this->validationErrors = array('content' => array('nodes[0]: unknown node type.'));
            return false;
        }
        $this->db->log[] = 'save';
        return array('Graph' => $data['Graph'] + array('revision' => 6, 'node_count' => 1, 'content_size' => 99));
    }
}

class GraphTestActiveGraph extends GraphTestGraph
{
    public $summaryCalls = array();
    public $summaryRows = array();

    public function summaries(array $user, array $conditions, array $options = array())
    {
        $this->summaryCalls[] = array($conditions, $options);
        return $this->summaryRows;
    }

    public $authors = array();

    public function find($type = 'first', $query = array())
    {
        return array_intersect_key($this->authors, array_flip($query['conditions']['Graph.id']));
    }
}

class GraphTestCountedGraph extends GraphTestGraph
{
    public $contents = array();
    public $asked = array();

    public function storedContents(array $ids)
    {
        $this->asked[] = $ids;
        return array_intersect_key($this->contents, array_flip($ids));
    }
}

class GraphTestBehaviors
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
    }

    public function enable($name)
    {
        $this->log[] = array('enable', $name);
    }
}

/**
 * A model fake answering whatever the test registers for each method.
 */
class GraphTestFake
{
    public $calls = array();
    private $handlers = array();

    public function on($method, callable $handler)
    {
        $this->handlers[$method] = $handler;
        return $this;
    }

    public function __call($method, $args)
    {
        $this->calls[] = array($method, $args);
        if (!isset($this->handlers[$method])) {
            throw new RuntimeException("No handler for $method.");
        }
        return call_user_func_array($this->handlers[$method], $args);
    }
}

class GraphTestUserSetting extends GraphTestFake
{
    public $Behaviors;
}

class GraphTest extends TestCase
{
    const ATTRIBUTE = '5D34E7F4-0000-4000-8000-000000000001';
    const EVENT = '5d34e7f4-0000-4000-8000-000000000002';

    private static function node($type, $uuid, array $extra = array())
    {
        return array('type' => $type, 'uuid' => $uuid) + $extra;
    }

    private static function valueNode($value)
    {
        return array('type' => 'Value', 'value' => $value);
    }

    private static function uuid($i)
    {
        return sprintf('00000000-0000-4000-8000-%012d', $i);
    }

    private static function documentWithNodes($count)
    {
        $nodes = array();
        for ($i = 1; $i <= $count; $i++) {
            $nodes[] = self::node('Attribute', self::uuid($i));
        }
        return array('version' => 1, 'nodes' => $nodes);
    }

    private static function stored(array $nodes)
    {
        list($document) = AnalystGraphDocumentTool::normalise(array('nodes' => $nodes));
        return AnalystGraphDocumentTool::encode($document);
    }

    // ----------------------------------------------------------- validation

    public function testDocumentIsNormalised()
    {
        list($document, $errors) = AnalystGraphDocumentTool::normalise(array(
            'nodes' => array(
                self::node('Attribute', self::ATTRIBUTE, array('x' => 120, 'y' => -40.5, 'pinned' => true, 'label' => 'dropped')),
                array('type' => 'Value', 'value' => ' 8.8.8.8 ', 'uuid' => self::EVENT),
            ),
            'hidden_edges' => array('relationship:a', 'relationship:a'),
            'view' => array('layout' => 'force', 'zoom' => 1.5, 'center' => array(0, 0), 'theme' => 'dropped'),
            'extra' => 'dropped',
        ));

        $this->assertSame(array(), $errors);
        $this->assertSame(array(
            'version' => 1,
            'nodes' => array(
                array('type' => 'Attribute', 'uuid' => strtolower(self::ATTRIBUTE), 'x' => 120, 'y' => -40.5, 'pinned' => true),
                array('type' => 'Value', 'sha256' => hash('sha256', '8.8.8.8'), 'value' => '8.8.8.8'),
            ),
            'groups' => array(),
            'hidden_edges' => array('relationship:a'),
            'view' => array('layout' => 'force', 'zoom' => 1.5, 'center' => array(0, 0)),
        ), $document);
    }

    public function testGroupsAreNormalised()
    {
        list($document, $errors) = AnalystGraphDocumentTool::normalise(array(
            'nodes' => array(
                self::node('Event', self::EVENT, array('pulled_out' => 1)),
                self::node('Attribute', self::ATTRIBUTE),
                self::valueNode('8.8.8.8'),
                self::node('Attribute', self::uuid(1)),
                self::node('Attribute', self::uuid(2)),
            ),
            'groups' => array(
                array('title' => '  C2  ', 'members' => array('Attribute:' . self::ATTRIBUTE, self::valueNode('8.8.8.8'), 'Event:' . self::uuid(9)),
                      'x' => 10, 'y' => -2.5, 'open' => 1, 'rule' => 'dropped'),
                array('title' => '', 'members' => array(self::node('Attribute', self::uuid(1)), 'Attribute:' . self::uuid(2))),
                array('members' => array('Event:' . self::EVENT, 'Event:' . self::uuid(9))),
            ),
            'view' => array('rules' => array('neighbours' => false, 'chains' => true)),
        ));

        $this->assertSame(array(), $errors);
        $this->assertSame(array('type' => 'Event', 'uuid' => self::EVENT, 'pulled_out' => true), $document['nodes'][0]);
        $this->assertSame(array(
            array('title' => 'C2', 'members' => array('Attribute:' . strtolower(self::ATTRIBUTE), 'Value:' . AnalystGraphDocumentTool::valueAddress('8.8.8.8')),
                  'x' => 10, 'y' => -2.5, 'open' => true),
            array('members' => array('Attribute:' . self::uuid(1), 'Attribute:' . self::uuid(2))),
        ), $document['groups']);
        $this->assertSame(array('neighbours' => false, 'chains' => true), $document['view']['rules']);
    }

    public function testNotesAreNormalised()
    {
        list($document, $errors) = AnalystGraphDocumentTool::normalise(array(
            'nodes' => array(self::node('Attribute', self::ATTRIBUTE)),
            'notes' => array(
                array('id' => self::uuid(1), 'content' => '**C2**', 'x' => 10, 'y' => -2.5, 'width' => 220, 'height' => 160,
                      'color' => '#FDE68A', 'surface' => 'terminal', 'node' => 'Attribute:' . strtoupper(self::ATTRIBUTE), 'visible' => false),
                array('id' => 'note-2', 'node' => self::valueNode(' 8.8.8.8 ')),
                array('id' => 'note-3', 'content' => '', 'edge' => 'relationship:a'),
            ),
        ));

        $this->assertSame(array(), $errors);
        $this->assertSame(array(
            array('id' => self::uuid(1), 'content' => '**C2**', 'x' => 10, 'y' => -2.5, 'width' => 220, 'height' => 160,
                  'color' => '#FDE68A', 'surface' => 'terminal', 'node' => 'Attribute:' . strtolower(self::ATTRIBUTE)),
            array('id' => 'note-2', 'content' => '', 'node' => 'Value:' . AnalystGraphDocumentTool::valueAddress('8.8.8.8')),
            array('id' => 'note-3', 'content' => '', 'edge' => 'relationship:a'),
        ), $document['notes']);
    }

    public function testDocumentWithoutNotesLeavesThemOut()
    {
        list($document) = AnalystGraphDocumentTool::normalise(array('notes' => array()));
        $this->assertArrayNotHasKey('notes', $document);
    }

    public function testWithNodesNarrowsGroups()
    {
        list($document) = AnalystGraphDocumentTool::normalise(array(
            'nodes' => array(self::node('Event', self::EVENT), self::node('Attribute', self::uuid(1)), self::node('Attribute', self::uuid(2))),
            'groups' => array(
                array('members' => array('Event:' . self::EVENT, 'Attribute:' . self::uuid(1))),
                array('members' => array('Attribute:' . self::uuid(2), 'Event:' . self::uuid(9))),
            ),
        ));
        $this->assertCount(1, $document['groups']);

        $narrowed = AnalystGraphDocumentTool::withNodes($document, array_slice($document['nodes'], 1));
        $this->assertSame(array(), $narrowed['groups']);
        $this->assertCount(2, $narrowed['nodes']);

        list($removed) = AnalystGraphDocumentTool::removeNodes($document, array('Attribute:' . self::uuid(2)));
        $this->assertCount(1, $removed['groups']);
        list($removed) = AnalystGraphDocumentTool::removeNodes($document, array('Attribute:' . self::uuid(1)));
        $this->assertSame(array(), $removed['groups']);
    }

    public function testJsonStringIsAccepted()
    {
        list($document, $errors) = AnalystGraphDocumentTool::normalise('{"version":1,"nodes":[{"type":"Event","uuid":"' . self::EVENT . '"}]}');
        $this->assertSame(array(), $errors);
        $this->assertSame(self::EVENT, $document['nodes'][0]['uuid']);
    }

    public function testEmptyDocumentEncodesViewAsAnObject()
    {
        $this->assertSame(
            '{"version":1,"nodes":[],"groups":[],"hidden_edges":[],"view":{}}',
            AnalystGraphDocumentTool::encode(AnalystGraphDocumentTool::emptyDocument())
        );
    }

    /**
     * @dataProvider invalidDocuments
     */
    public function testInvalidDocumentIsRefused($content)
    {
        list($document, $errors) = AnalystGraphDocumentTool::normalise($content);
        $this->assertNull($document);
        $this->assertNotEmpty($errors);
    }

    public static function invalidDocuments()
    {
        return array(
            'not JSON' => array('{"nodes": ['),
            'not an object' => array(42),
            'unknown version' => array(array('version' => 2)),
            'nodes not a list' => array(array('nodes' => array('a' => self::node('Event', self::EVENT)))),
            'unknown node type' => array(array('nodes' => array(self::node('Tag', self::EVENT)))),
            'bad uuid' => array(array('nodes' => array(self::node('Event', 'not-a-uuid')))),
            'duplicate node' => array(array('nodes' => array(self::node('Event', self::EVENT), self::node('Event', strtoupper(self::EVENT))))),
            'duplicate value' => array(array('nodes' => array(self::valueNode('8.8.8.8'), self::valueNode(' 8.8.8.8')))),
            'empty value' => array(array('nodes' => array(self::valueNode('  ')))),
            'oversized value' => array(array('nodes' => array(self::valueNode(str_repeat('a', 1025))))),
            'non-numeric position' => array(array('nodes' => array(self::node('Event', self::EVENT, array('x' => '12'))))),
            'hidden edge not a string' => array(array('hidden_edges' => array(array('id' => 1)))),
            'view as a list' => array(array('view' => array(1, 2))),
            'bad zoom' => array(array('view' => array('zoom' => 0))),
            'groups not a list' => array(array('groups' => array('a' => array()))),
            'group members not a list' => array(array('groups' => array(array('members' => 'Event:' . self::EVENT)))),
            'group member not a node' => array(array('nodes' => array(self::node('Event', self::EVENT)), 'groups' => array(array('members' => array('Event:' . self::EVENT, 'Tag:1'))))),
            'member in two groups' => array(array(
                'nodes' => array(self::node('Event', self::EVENT), self::node('Attribute', self::ATTRIBUTE), self::node('Attribute', self::uuid(1))),
                'groups' => array(
                    array('members' => array('Event:' . self::EVENT, 'Attribute:' . self::ATTRIBUTE)),
                    array('members' => array('Event:' . self::EVENT, 'Attribute:' . self::uuid(1))),
                ),
            )),
            'group title not a string' => array(array('groups' => array(array('members' => array(), 'title' => 3)))),
            'group title too long' => array(array('groups' => array(array('members' => array(), 'title' => str_repeat('a', 256))))),
            'group position not a number' => array(array('groups' => array(array('members' => array(), 'x' => '1')))),
            'rules as a list' => array(array('view' => array('rules' => array(true)))),
            'rule not a boolean' => array(array('view' => array('rules' => array('neighbours' => 1)))),
            'notes not a list' => array(array('notes' => array('a' => array('id' => 'n')))),
            'note without id' => array(array('notes' => array(array('content' => 'x')))),
            'note id with markup' => array(array('notes' => array(array('id' => '<b>')))),
            'duplicate note' => array(array('notes' => array(array('id' => 'n'), array('id' => 'n')))),
            'note content not a string' => array(array('notes' => array(array('id' => 'n', 'content' => array('x'))))),
            'note content too large' => array(array('notes' => array(array('id' => 'n', 'content' => str_repeat('a', 65536))))),
            'note size not positive' => array(array('notes' => array(array('id' => 'n', 'width' => 0)))),
            'note colour not hex' => array(array('notes' => array(array('id' => 'n', 'color' => 'url(x)')))),
            'unknown note surface' => array(array('notes' => array(array('id' => 'n', 'surface' => 'glass')))),
            'note anchor not a node' => array(array('notes' => array(array('id' => 'n', 'node' => 'Tag:1')))),
            'note on a node and an edge' => array(array('notes' => array(array('id' => 'n', 'node' => 'Event:' . self::EVENT, 'edge' => 'e')))),
        );
    }

    public function testSameUuidUnderTwoTypesIsNotADuplicate()
    {
        list(, $errors) = AnalystGraphDocumentTool::normalise(array(
            'nodes' => array(self::node('Event', self::EVENT), self::node('Attribute', self::EVENT)),
        ));
        $this->assertSame(array(), $errors);
    }

    public function testValueAtTheByteCapIsAccepted()
    {
        list(, $errors) = AnalystGraphDocumentTool::normalise(array('nodes' => array(self::valueNode(str_repeat('a', 1024)))));
        $this->assertSame(array(), $errors);
    }

    public function testErrorsNameTheNode()
    {
        list(, $errors) = AnalystGraphDocumentTool::normalise(array(
            'nodes' => array(self::node('Event', self::EVENT), self::node('Tag', self::EVENT)),
        ));
        $this->assertSame(array('nodes[1]: unknown node type.'), $errors);
    }

    // ----------------------------------------------------------------- caps

    public function testNodeCap()
    {
        list(, $errors) = AnalystGraphDocumentTool::normalise(self::documentWithNodes(2000));
        $this->assertSame(array(), $errors);

        list($document, $errors) = AnalystGraphDocumentTool::normalise(self::documentWithNodes(2001));
        $this->assertNull($document);
        $this->assertSame(array('A graph holds at most 2000 nodes.'), $errors);
    }

    public function testByteCap()
    {
        $edges = array();
        for ($i = 0; $i < 66000; $i++) {
            $edges[] = str_pad('relationship:' . $i, 255, 'x');
        }
        list($document, $errors) = AnalystGraphDocumentTool::normalise(array('hidden_edges' => $edges));
        $this->assertNull($document);
        $this->assertSame(array('A graph document is at most 16777216 bytes.'), $errors);
    }

    public function testMeasure()
    {
        $content = self::stored(array(self::node('Event', self::EVENT), self::valueNode('8.8.8.8')));
        $this->assertSame(
            array('content_size' => strlen($content), 'node_count' => 2),
            AnalystGraphDocumentTool::measure($content)
        );
    }

    // ---------------------------------------------------------- model glue

    public function testModelStoresTheNormalisedDocument()
    {
        $graph = new GraphTestGraph();
        $graph->data = array('Graph' => array('content' => array('nodes' => array(self::node('Attribute', self::ATTRIBUTE)))));

        $this->assertTrue($graph->validDocument(array('content' => $graph->data['Graph']['content'])));
        $this->assertSame(
            '{"version":1,"nodes":[{"type":"Attribute","uuid":"' . strtolower(self::ATTRIBUTE) . '"}],"groups":[],"hidden_edges":[],"view":{}}',
            $graph->data['Graph']['content']
        );
    }

    public function testModelReportsDocumentErrors()
    {
        $graph = new GraphTestGraph();
        $result = $graph->validDocument(array('content' => array('nodes' => array(self::node('Tag', self::EVENT)))));
        $this->assertSame('nodes[0]: unknown node type.', $result);
    }

    public function testGraphIsAnAnalystDataTypeButNotEmbedded()
    {
        $this->assertContains('Graph', AnalystData::TYPES);
        $this->assertNotContains('Graph', AnalystData::ANALYST_DATA_TYPES);
        $this->assertContains('Graph', AnalystData::valid_targets);
        $this->assertContains('AttributeValue', AnalystData::valid_targets);
        $this->assertSame(AnalystData::GRAPH, (new GraphTestGraph())->current_type_id);
    }

    public function testGraphsHaveNoLanguage()
    {
        $this->assertNotContains('language', (new GraphTestGraph())->getEditableFields());
    }

    public function testDistributionIsRequiredOnCreateOnly()
    {
        $this->assertSame('create', (new GraphTestGraph())->validate['distribution']['required']);
    }

    // ---------------------------------------------------------- edit rights

    private static function user($orgUuid, $siteAdmin = false, $permAnalystData = true)
    {
        return array(
            'Role' => array('perm_site_admin' => $siteAdmin, 'perm_analyst_data' => $permAnalystData),
            'Organisation' => array('uuid' => $orgUuid),
        );
    }

    /**
     * @dataProvider editRights
     */
    public function testEditRights(array $user, $expected)
    {
        $graph = new GraphTestGraph();
        $record = array('Graph' => array('orgc_uuid' => self::uuid(1)));
        $this->assertSame($expected, $graph->canEditAnalystData($user, $record, 'Graph'));
    }

    public static function editRights()
    {
        return array(
            'creator org' => array(self::user(self::uuid(1)), true),
            'creator org without analyst-data permission' => array(self::user(self::uuid(1), false, false), false),
            'other org' => array(self::user(self::uuid(2)), false),
            'site admin of another org' => array(self::user(self::uuid(2), true, false), true),
        );
    }

    // -------------------------------------------------------- audit summary

    public function testAuditSummaryOfAnEdit()
    {
        $old = self::stored(array(self::node('Event', self::EVENT), self::node('Attribute', self::uuid(1))));
        $new = self::stored(array(self::node('Event', self::EVENT), self::node('Attribute', self::uuid(2)), self::valueNode('8.8.8.8')));

        $this->assertSame(array(
            'node_count' => array(2, 3),
            'content_size' => array(strlen($old), strlen($new)),
            'nodes_added_count' => 2,
            'nodes_added' => array('Attribute:' . self::uuid(2), 'Value:' . AnalystGraphDocumentTool::valueAddress('8.8.8.8')),
            'nodes_removed_count' => 1,
            'nodes_removed' => array('Attribute:' . self::uuid(1)),
        ), AnalystGraphDocumentTool::summariseChange($old, $new));
    }

    public function testAuditSummaryWithoutAPreviousDocument()
    {
        $content = self::stored(array(self::node('Event', self::EVENT)));
        $this->assertSame(
            array('node_count' => 1, 'content_size' => strlen($content)),
            AnalystGraphDocumentTool::summariseChange(null, $content)
        );
    }

    public function testAuditSummaryOfANotesEdit()
    {
        $old = self::storedWithNotes(array(
            array('id' => 'n1', 'content' => 'a', 'node' => 'Event:' . self::EVENT),
            array('id' => 'n2', 'content' => 'b', 'x' => 0),
            array('id' => '42', 'content' => 'gone'),
        ));
        $new = self::storedWithNotes(array(
            array('id' => 'n1', 'content' => 'a, edited', 'node' => 'Event:' . self::EVENT),
            array('id' => 'n2', 'content' => 'b', 'x' => 50, 'color' => '#FCA5A5'),
            array('id' => 'n3', 'content' => 'c'),
        ));

        $summary = AnalystGraphDocumentTool::summariseChange($old, $new);
        $this->assertSame(array(3, 3), $summary['note_count']);
        $this->assertSame(array('n3'), $summary['notes_added']);
        $this->assertSame(array('42'), $summary['notes_removed']);
        $this->assertSame(array('n1'), $summary['notes_edited']);
        $this->assertSame(1, $summary['notes_edited_count']);
        $this->assertSame(0, $summary['nodes_added_count']);
    }

    public function testAuditSummaryCountsNotesOfANewDocument()
    {
        $content = self::storedWithNotes(array(array('id' => 'n1', 'content' => 'a')));
        $this->assertSame(1, AnalystGraphDocumentTool::summariseChange(null, $content)['note_count']);
    }

    private static function storedWithNotes(array $notes)
    {
        list($document) = AnalystGraphDocumentTool::normalise(array('nodes' => array(self::node('Event', self::EVENT)), 'notes' => $notes));
        return AnalystGraphDocumentTool::encode($document);
    }

    public function testAuditSummaryListsAreCapped()
    {
        $new = AnalystGraphDocumentTool::encode(self::documentWithNodes(150) + array('hidden_edges' => array(), 'view' => array()));
        $summary = AnalystGraphDocumentTool::summariseChange(self::stored(array()), $new);
        $this->assertSame(150, $summary['nodes_added_count']);
        $this->assertCount(100, $summary['nodes_added']);
    }

    public function testModelSummarisesOnlyTheContentAndAddsTheRevision()
    {
        $graph = new GraphTestGraph();
        $graph->data = array('Graph' => array('revision' => 4));
        $content = self::stored(array(self::node('Event', self::EVENT)));

        $this->assertNull($graph->auditLogSummary('name', 'old', 'new'));
        $this->assertSame(
            array('revision' => 4, 'node_count' => 1, 'content_size' => strlen($content)),
            $graph->auditLogSummary('content', null, $content)
        );
    }

    public function testAuditLogRecordsTheSummaryInPlaceOfTheDocument()
    {
        Configure::write('MISP.log_new_audit', true);
        $recorder = new GraphTestRecorder();
        ClassRegistry::$instances['AuditLog'] = $recorder;

        $old = self::stored(array(self::node('Event', self::EVENT)));
        $new = self::stored(array(self::node('Event', self::EVENT), self::valueNode('8.8.8.8')));
        $model = new GraphTestModel();
        $model->data = array('Graph' => array('id' => 1, 'name' => 'Campaign', 'content' => $new, 'revision' => 3));

        $behavior = new AuditLogBehavior();
        $behavior->setup($model);
        $beforeSave = new ReflectionProperty(AuditLogBehavior::class, 'beforeSave');
        $beforeSave->setAccessible(true);
        $beforeSave->setValue($behavior, array('Graph' => array('id' => 1, 'name' => 'Campaign', 'content' => $old, 'revision' => 2)));

        $behavior->afterSave($model, false, array('fieldList' => array()));

        $this->assertCount(1, $recorder->calls);
        $row = $recorder->calls[0];
        $this->assertSame('Graph', $row['model']);
        $this->assertSame('Campaign', $row['model_title']);
        $this->assertSame(array('content'), array_keys($row['change']));
        $this->assertSame(3, $row['change']['content']['revision']);
        $this->assertSame(array(1, 2), $row['change']['content']['node_count']);
        $this->assertSame(array('Value:' . AnalystGraphDocumentTool::valueAddress('8.8.8.8')), $row['change']['content']['nodes_added']);
    }

    // ----------------------------------------------------------- embed skip

    private function registerEmbedFakes()
    {
        $fakes = array();
        foreach (array('Note', 'Opinion', 'Relationship', 'Graph', 'User') as $type) {
            $fakes[$type] = new GraphTestRecorder();
            ClassRegistry::$instances[$type] = $fakes[$type];
        }
        return $fakes;
    }

    public function testBulkFetchNeverLoadsGraphs()
    {
        $fakes = $this->registerEmbedFakes();
        $behavior = new AnalystDataParentBehavior();

        $behavior->fetchAnalystDataBulk(new GraphTestModel(), array(self::EVENT), array('Note', 'Graph'));

        $this->assertCount(1, $fakes['Note']->calls);
        $this->assertSame(array(), $fakes['Graph']->calls);
    }

    public function testBulkAttachNeverLoadsGraphs()
    {
        $fakes = $this->registerEmbedFakes();
        $behavior = new AnalystDataParentBehavior();

        $behavior->attachAnalystDataBulk(new GraphTestModel(), array(array('uuid' => self::EVENT)), array('Graph', 'Opinion'));

        $this->assertCount(1, $fakes['Opinion']->calls);
        $this->assertSame(array(), $fakes['Graph']->calls);
    }

    // ------------------------------------------------------------ API output

    public function testDecodeKeepsAnEmptyViewAnObject()
    {
        $decoded = AnalystGraphDocumentTool::decode('{"version":1,"nodes":[],"hidden_edges":[],"view":[]}');

        $this->assertStringContainsString('"view":{}', json_encode($decoded));
        $this->assertNull(AnalystGraphDocumentTool::decode('not json'));
    }

    // ------------------------------------------------------- locked write

    private function writableGraph($storedRevision)
    {
        $graph = new GraphTestWritableGraph();
        $graph->db = new GraphTestDataSource();
        if ($storedRevision !== null) {
            $graph->db->rows = array(array('analyst_graphs' => array(
                'revision' => (string)$storedRevision,
                'content' => self::stored(array(self::node('Event', self::EVENT))),
            )));
        }
        return $graph;
    }

    public function testWriteLocksTheRowBeforeReadingTheRevision()
    {
        $graph = $this->writableGraph(5);

        $graph->writeContent(7, function (array $stored) {
            return $stored;
        }, 5);

        $this->assertSame('begin', $graph->db->log[0]);
        list($sql, $params, $options) = $graph->db->log[1];
        $this->assertStringEndsWith('FOR UPDATE', $sql);
        $this->assertSame(array(7), $params);
        $this->assertSame(array('cache' => false), $options);
    }

    public function testStaleWriteIsAConflictAndSavesNothing()
    {
        $graph = $this->writableGraph(5);
        $called = false;

        $result = $graph->writeContent(7, function () use (&$called) {
            $called = true;
            return array();
        }, 4);

        $this->assertSame('conflict', $result['status']);
        $this->assertSame(5, $result['revision']);
        $this->assertFalse($called);
        $this->assertSame(array(), $graph->saves);
        $this->assertSame('rollback', end($graph->db->log));
    }

    public function testCurrentWriteSavesTheChangedDocumentAndCommits()
    {
        $graph = $this->writableGraph(5);
        $seen = null;

        $result = $graph->writeContent(7, function (array $stored) use (&$seen) {
            $seen = $stored;
            $stored['nodes'][] = array('type' => 'Value', 'value' => '8.8.8.8');
            return $stored;
        }, '5');

        $this->assertSame('Event', $seen['nodes'][0]['type']);
        $this->assertSame('saved', $result['status']);
        $this->assertSame(6, $result['revision']);
        $this->assertSame(1, $result['node_count']);
        list($data, $options) = $graph->saves[0];
        $this->assertSame(7, $data['Graph']['id']);
        $this->assertCount(2, $data['Graph']['content']['nodes']);
        $this->assertSame(array('fieldList' => array('content', 'modified')), $options);
        $this->assertSame(array('save', 'commit'), array_slice($graph->db->log, -2));
    }

    public function testWriteWithoutABaseRevisionAppliesToTheStoredOne()
    {
        $graph = $this->writableGraph(5);

        $result = $graph->writeContent(7, function (array $stored) {
            return $stored;
        });

        $this->assertSame('saved', $result['status']);
    }

    public function testInvalidWriteRollsBack()
    {
        $graph = $this->writableGraph(5);
        $graph->refuse = true;

        $result = $graph->writeContent(7, function () {
            return array('nodes' => array(array('type' => 'Tag')));
        }, 5);

        $this->assertSame('invalid', $result['status']);
        $this->assertArrayHasKey('content', $result['errors']);
        $this->assertSame('rollback', end($graph->db->log));
        $this->assertNotContains('commit', $graph->db->log);
    }

    public function testWriteThatChangesNothingSavesNothing()
    {
        $graph = $this->writableGraph(5);

        $result = $graph->writeContent(7, function () {
            return null;
        });

        $this->assertSame('unchanged', $result['status']);
        $this->assertSame(5, $result['revision']);
        $this->assertSame(1, $result['node_count']);
        $this->assertSame(array(), $graph->saves);
        $this->assertSame('commit', end($graph->db->log));
    }

    // ------------------------------------------------- add / remove nodes

    public function testAddNodesAppendsAndReportsEachItem()
    {
        $document = json_decode(self::stored(array(self::node('Event', self::EVENT))), true);

        list($document, $report) = AnalystGraphDocumentTool::addNodes($document, array(
            self::node('Event', self::EVENT),
            self::node('Attribute', self::ATTRIBUTE),
            self::valueNode(' 8.8.8.8 '),
            self::valueNode('8.8.8.8'),
            array('type' => 'Tag', 'uuid' => self::EVENT),
            self::node('Attribute', strtolower(self::ATTRIBUTE)),
        ));

        $attribute = 'Attribute:' . strtolower(self::ATTRIBUTE);
        $value = 'Value:' . AnalystGraphDocumentTool::valueAddress('8.8.8.8');
        $this->assertSame(array($attribute, $value), $report['added']);
        $this->assertSame(array('Event:' . self::EVENT, $value, $attribute), $report['present']);
        $this->assertSame(array(array('index' => 4, 'error' => 'unknown node type.')), $report['refused']);
        $this->assertSame(array('Event:' . self::EVENT, $attribute, $value), array_map(array('AnalystGraphDocumentTool', 'nodeKey'), $document['nodes']));
        $this->assertSame('8.8.8.8', $document['nodes'][2]['value']);
    }

    public function testAddNodesStopsAtTheNodeCap()
    {
        $document = self::documentWithNodes(AnalystGraphDocumentTool::MAX_NODES - 1);

        list($document, $report) = AnalystGraphDocumentTool::addNodes($document, array(
            self::valueNode('a'),
            self::valueNode('b'),
        ));

        $this->assertCount(1, $report['added']);
        $this->assertSame(1, $report['refused'][0]['index']);
        $this->assertCount(AnalystGraphDocumentTool::MAX_NODES, $document['nodes']);
    }

    public function testRemoveNodesByNodeOrByKey()
    {
        $document = json_decode(self::stored(array(
            self::node('Event', self::EVENT),
            self::node('Attribute', self::ATTRIBUTE),
            self::valueNode('8.8.8.8'),
        )), true);

        list($document, $report) = AnalystGraphDocumentTool::removeNodes($document, array(
            'Attribute:' . self::ATTRIBUTE,
            self::valueNode(' 8.8.8.8 '),
            'Event:' . self::uuid(9),
            'nonsense',
            array('type' => 'Object'),
        ));

        $this->assertSame(array('Attribute:' . strtolower(self::ATTRIBUTE), 'Value:' . AnalystGraphDocumentTool::valueAddress('8.8.8.8')), $report['removed']);
        $this->assertSame(array('Event:' . self::uuid(9)), $report['absent']);
        $this->assertSame(array(3, 4), array_column($report['refused'], 'index'));
        $this->assertSame(array('Event:' . self::EVENT), array_map(array('AnalystGraphDocumentTool', 'nodeKey'), $document['nodes']));
    }

    public function testWriteToAMissingGraph()
    {
        $graph = $this->writableGraph(null);

        $result = $graph->writeContent(7, function () {
            return array();
        }, 1);

        $this->assertSame('missing', $result['status']);
        $this->assertSame('rollback', end($graph->db->log));
    }

    // ------------------------------------------------------------ resolve

    const E1 = 'e1000000-0000-4000-8000-000000000001';
    const E2 = 'e2000000-0000-4000-8000-000000000002';
    const O1 = 'b1000000-0000-4000-8000-000000000021';
    const O2 = 'b2000000-0000-4000-8000-000000000022';
    const A1 = 'a1000000-0000-4000-8000-000000000031';
    const A_CHILD1 = 'ac100000-0000-4000-8000-000000000041';
    const A_CHILD2 = 'ac200000-0000-4000-8000-000000000042';
    const A3 = 'a3000000-0000-4000-8000-000000000033';
    const A_HIDDEN = 'aa000000-0000-4000-8000-000000000099';
    const A_UNDRAWN = 'ad000000-0000-4000-8000-000000000098';
    const C1 = 'c1000000-0000-4000-8000-000000000051';
    const C2 = 'c2000000-0000-4000-8000-000000000052';
    const C1_TAG = 'misp-galaxy:threat-actor="X"';

    private $registered = array();

    protected function tearDown(): void
    {
        foreach ($this->registered as $name) {
            unset(ClassRegistry::$instances[$name]);
        }
        $this->registered = array();
    }

    private function fake($name)
    {
        $fake = new GraphTestFake();
        ClassRegistry::$instances[$name] = $fake;
        $this->registered[] = $name;
        return $fake;
    }

    private static function inList($uuid, array $uuids)
    {
        return in_array(strtolower($uuid), array_map('strtolower', $uuids), true);
    }

    private function registerResolveFakes(array $readable)
    {
        $childAttributes = array(
            array('id' => 41, 'uuid' => self::A_CHILD1, 'object_id' => 21, 'event_id' => 11, 'type' => 'ip-dst', 'value' => '8.8.8.8', 'value1' => '8.8.8.8', 'value2' => '', 'Tag' => array()),
            array('id' => 42, 'uuid' => self::A_CHILD2, 'object_id' => 21, 'event_id' => 11, 'type' => 'domain', 'value' => 'example.org', 'value1' => 'example.org', 'value2' => '',
                'Tag' => array(array('name' => self::C1_TAG, 'relationship_type' => 'attributed-to'))),
        );
        $objects = array(
            strtoupper(self::O1) => array('id' => 21, 'uuid' => strtoupper(self::O1), 'event_id' => 11, 'template_uuid' => null, 'Attribute' => $childAttributes),
            self::O2 => array('id' => 22, 'uuid' => self::O2, 'event_id' => 11, 'template_uuid' => null, 'Attribute' => array()),
        );
        $attributes = array(
            array('id' => 31, 'uuid' => self::A1, 'object_id' => 0, 'event_id' => 11, 'type' => 'attachment', 'value' => 'a.png', 'Tag' => array()),
            $childAttributes[0],
            array('id' => 33, 'uuid' => self::A3, 'object_id' => 0, 'event_id' => 12, 'type' => 'ip-dst|port', 'value' => '1.2.3.4|80', 'value1' => '1.2.3.4', 'value2' => '80', 'Tag' => array()),
        );
        $this->fake('CollectionElement')->on('readableUuids', function ($user, $type, $uuids) use ($readable) {
            return array_values(array_filter($uuids, function ($uuid) use ($readable) {
                return self::inList($uuid, $readable);
            }));
        });
        $this->fake('MispObject')->on('fetchGraphObjects', function ($user, $conditions) use ($objects) {
            $found = array();
            foreach (array_reverse($objects, true) as $uuid => $object) {
                if (self::inList($uuid, $conditions['Object.uuid'])) {
                    $found[$uuid] = $object;
                }
            }
            return $found;
        });
        $this->fake('MispAttribute')->on('fetchGraphAttributes', function ($user, $conditions) use ($attributes) {
            return array_values(array_filter($attributes, function ($a) use ($conditions) {
                return self::inList($a['uuid'], $conditions['Attribute.uuid']);
            }));
        });
        $this->fake('GalaxyCluster')->on('fetchGalaxyClusters', function ($user, $options) {
            $rows = array();
            foreach (array(self::C1 => self::C1_TAG, self::C2 => 'misp-galaxy:tool="Y"') as $uuid => $tag) {
                if (self::inList($uuid, $options['conditions']['GalaxyCluster.uuid'])) {
                    $rows[] = array('GalaxyCluster' => array('uuid' => $uuid, 'tag_name' => $tag), 'Galaxy' => array('type' => 'threat-actor'));
                }
            }
            return $rows;
        });
        $this->fake('Event')
            ->on('find', function ($type, $query) {
                return self::inList(self::E1, $query['conditions']['Event.uuid']) ? array(self::E1 => '11') : array();
            })
            ->on('correlatedEventCards', function ($user, $ids) {
                $cards = array(
                    '11' => array('id' => '11', 'uuid' => self::E1, 'Galaxy' => array(array('type' => 'threat-actor', 'GalaxyCluster' => array(array('uuid' => self::C1, 'tag_name' => self::C1_TAG))))),
                    '12' => array('id' => '12', 'uuid' => self::E2, 'Galaxy' => array()),
                );
                return array_intersect_key($cards, array_flip($ids));
            });
        $this->fake('ObjectTemplate')->on('uiPrioritiesFor', function () {
            return array();
        });
        $this->fake('ObjectReference')->on('find', function () {
            return array(
                array('ObjectReference' => array('uuid' => 'r1', 'object_id' => 22, 'referenced_uuid' => strtoupper(self::O1), 'referenced_type' => '1', 'relationship_type' => 'co-worker')),
                array('ObjectReference' => array('uuid' => 'r2', 'object_id' => 21, 'referenced_uuid' => self::A1, 'referenced_type' => '0', 'relationship_type' => 'child')),
                array('ObjectReference' => array('uuid' => 'r3', 'object_id' => 22, 'referenced_uuid' => self::A_UNDRAWN, 'referenced_type' => '0', 'relationship_type' => 'child')),
            );
        });
        $this->fake('Relationship')
            ->on('buildConditions', function () {
                return array();
            })
            ->on('find', function () {
                $row = function ($uuid, $fromType, $from, $toType, $to) {
                    return array('Relationship' => array(
                        'uuid' => $uuid, 'object_type' => $fromType, 'object_uuid' => $from, 'object_sha256' => null,
                        'related_object_type' => $toType,
                        'related_object_uuid' => $toType === 'AttributeValue' ? null : $to,
                        'related_object_sha256' => $toType === 'AttributeValue' ? $to : null,
                        'relationship_type' => 'related-to', 'authors' => 'a@b', 'orgc_uuid' => 'o', 'distribution' => '1',
                    ));
                };
                return array(
                    $row('rel1', 'Attribute', self::A1, 'AttributeValue', AnalystGraphDocumentTool::valueAddress('8.8.8.8')),
                    $row('rel2', 'Attribute', self::A1, 'Event', self::E2),
                );
            });
        $this->fake('GalaxyClusterRelation')->on('fetchRelations', function () {
            return array(array('GalaxyClusterRelation' => array(
                'galaxy_cluster_uuid' => self::C1, 'referenced_galaxy_cluster_uuid' => self::C2, 'referenced_galaxy_cluster_type' => 'uses',
            )));
        });
        // The dictionary: each group lists its stored spellings, by id
        $groups = array(
            array(1 => '8.8.8.8'),
            array(2 => 'example.org', 3 => 'EXAMPLE.ORG', 4 => 'exämple.org'),
            array(5 => '1.2.3.4'),
        );
        $this->fake('AttributeValue')
            ->on('resolveCi', function ($terms) use ($groups) {
                $out = array();
                foreach ($terms as $term) {
                    $out[$term] = array();
                    foreach ($groups as $group) {
                        $folded = array_map(function ($s) {
                            return str_replace('ä', 'a', mb_strtolower($s));
                        }, $group);
                        if (in_array(str_replace('ä', 'a', mb_strtolower($term)), $folded, true)) {
                            $out[$term] = array_keys($group);
                        }
                    }
                }
                return $out;
            })
            ->on('fetchValues', function ($ids) use ($groups) {
                $all = array_replace(...$groups);
                return array_intersect_key($all, array_flip($ids));
            });
    }

    private function resolveFixture()
    {
        $this->registerResolveFakes(array(self::E1, self::O1, self::O2, self::A1, self::A_CHILD1, self::A3, self::C1, self::C2));
        list($document) = AnalystGraphDocumentTool::normalise(array('nodes' => array(
            self::node('Event', self::E1),
            self::node('Object', self::O1),
            self::node('Object', self::O2),
            self::node('Attribute', self::A1),
            self::node('Attribute', self::A_HIDDEN),
            self::node('Attribute', self::A_CHILD1),
            self::node('Attribute', self::A3),
            self::node('GalaxyCluster', self::C1),
            self::node('GalaxyCluster', self::C2),
            self::valueNode(' 8.8.8.8 '),
            self::valueNode('1.2.3.4'),
            self::valueNode('EXAMPLE.ORG'),
        )));
        $data = new AnalystGraphData();
        return $data->resolve(array('id' => 1), $document);
    }

    public function testResolveLeavesOutWhatTheUserCannotRead()
    {
        $resolved = $this->resolveFixture();

        $keys = array_map(array('AnalystGraphDocumentTool', 'nodeKey'), $resolved['document']['nodes']);
        $this->assertNotContains('Attribute:' . self::A_HIDDEN, $keys);
        $this->assertCount(11, $keys);
        $this->assertSame(11, $resolved['meta']['nodes']);
        $this->assertSame(11, $resolved['meta']['drawn']);
        $this->assertSame(array(), $resolved['meta']['skipped']);
        $this->assertStringContainsString('"view":{}', json_encode($resolved['document']));
    }

    public function testResolvedRecordsFollowTheDocumentOrder()
    {
        $resolved = $this->resolveFixture();

        $this->assertSame(array(21, 22), array_column($resolved['Object'], 'id'));
        $this->assertSame(array(31, 41, 33), array_column($resolved['Attribute'], 'id'));
        $this->assertSame(array(self::C1, self::C2), array_column($resolved['GalaxyCluster'], 'uuid'));
        $this->assertSame(array('8.8.8.8', '1.2.3.4', 'EXAMPLE.ORG'), array_column($resolved['Value'], 'value'));
        $this->assertSame(base64_encode('8.8.8.8'), $resolved['Value'][0]['b64']);
        $this->assertSame(array(11, 12), array_keys($resolved['events']));
    }

    public function testResolvedEdges()
    {
        $resolved = $this->resolveFixture();

        $edges = array();
        foreach ($resolved['edges'] as $edge) {
            $edges[$edge['id']] = array($edge['kind'], $edge['from'], $edge['to']);
        }
        ksort($edges);
        $value = function ($v) {
            return AnalystGraphDocumentTool::valueAddress($v);
        };
        $expected = array(
            'object-reference:r1' => array('object-reference', 'Object:' . self::O2, 'Object:' . self::O1),
            'object-reference:r2' => array('object-reference', 'Object:' . self::O1, 'Attribute:' . self::A1),
            'relationship:rel1' => array('relationship', 'Attribute:' . self::A1, 'Value:' . $value('8.8.8.8')),
            'contains:' . self::A_CHILD1 => array('contains', 'Object:' . self::O1, 'Attribute:' . self::A_CHILD1),
            'in-event:' . self::O1 => array('in-event', 'Object:' . self::O1, 'Event:' . self::E1),
            'in-event:' . self::O2 => array('in-event', 'Object:' . self::O2, 'Event:' . self::E1),
            'in-event:' . self::A1 => array('in-event', 'Attribute:' . self::A1, 'Event:' . self::E1),
            'tagged:' . self::E1 . '>' . self::C1 => array('tag', 'Event:' . self::E1, 'GalaxyCluster:' . self::C1),
            'tagged:' . self::A_CHILD2 . '>' . self::C1 => array('tag', 'Attribute:' . self::A_CHILD2, 'GalaxyCluster:' . self::C1),
            'cluster-relation:' . self::C1 . '>' . self::C2 . ':uses' => array('cluster-relation', 'GalaxyCluster:' . self::C1, 'GalaxyCluster:' . self::C2),
            'value:' . $value('8.8.8.8') . '>' . self::A_CHILD1 => array('value', 'Value:' . $value('8.8.8.8'), 'Attribute:' . self::A_CHILD1),
            'value:' . $value('1.2.3.4') . '>' . self::A3 => array('value', 'Value:' . $value('1.2.3.4'), 'Attribute:' . self::A3),
            'value:' . $value('EXAMPLE.ORG') . '>' . self::A_CHILD2 => array('value', 'Value:' . $value('EXAMPLE.ORG'), 'Attribute:' . self::A_CHILD2),
        );
        ksort($expected);
        $this->assertSame($expected, $edges);
    }

    public function testValueNodesLinkEverySpellingOfTheirGroupAndSaySo()
    {
        $this->registerResolveFakes(array(self::E1, self::O1, self::O2, self::A1, self::A_CHILD1, self::A3, self::C1, self::C2));
        list($document) = AnalystGraphDocumentTool::normalise(array('nodes' => array(
            self::node('Event', self::E1),
            self::node('Object', self::O1),
            self::node('Object', self::O2),
            self::valueNode('EXAMPLE.ORG'),
            self::valueNode('example.org'),
            self::valueNode('exämple.org'),
            self::valueNode('8.8.8.8'),
        )));
        $resolved = (new AnalystGraphData())->resolve(array('id' => 1), $document);

        $valueEdges = array();
        foreach ($resolved['edges'] as $edge) {
            if ($edge['kind'] === 'value') {
                $valueEdges[$edge['from'] . ' > ' . $edge['to']] = $edge['label'] ?? null;
            }
        }
        ksort($valueEdges);
        $to = ' > Attribute:' . self::A_CHILD2;
        $expected = array(
            'Value:' . AnalystGraphDocumentTool::valueAddress('EXAMPLE.ORG') . $to => 'spelled example.org',
            'Value:' . AnalystGraphDocumentTool::valueAddress('example.org') . $to => null,
            'Value:' . AnalystGraphDocumentTool::valueAddress('exämple.org') . $to => 'spelled example.org',
            'Value:' . AnalystGraphDocumentTool::valueAddress('8.8.8.8') . ' > Attribute:' . self::A_CHILD1 => null,
        );
        ksort($expected);
        $this->assertSame($expected, $valueEdges);
    }

    public function testThumbnailFoldsAnObjectsAttributesAndKeepsTheLayout()
    {
        $this->registerResolveFakes(array(self::E1, self::O1, self::O2, self::A1, self::A_CHILD1, self::A3, self::C1, self::C2));
        list($document) = AnalystGraphDocumentTool::normalise(array(
            'nodes' => array(
                self::node('Event', self::E1) + array('x' => -320, 'y' => 0, 'pinned' => true),
                self::node('Object', self::O1) + array('x' => 12.345, 'y' => 40),
                self::node('Object', self::O2),
                self::node('Attribute', self::A1),
                self::node('Attribute', self::A_HIDDEN),
                self::node('Attribute', self::A_CHILD1),
                self::node('Attribute', self::A3),
                self::node('GalaxyCluster', self::C1),
                self::node('GalaxyCluster', self::C2),
                self::valueNode(' 8.8.8.8 '),
                self::valueNode('1.2.3.4'),
                self::valueNode('EXAMPLE.ORG'),
            ),
            'hidden_edges' => array('in-event:' . self::O2),
        ));

        $thumb = (new AnalystGraphData())->thumbnail(array('id' => 1), $document);

        $keys = array_column($thumb['nodes'], 'key');
        $this->assertNotContains('Attribute:' . self::A_HIDDEN, $keys, 'unreadable');
        $this->assertNotContains('Attribute:' . self::A_CHILD1, $keys, 'drawn as its object');
        $this->assertCount(10, $keys);
        $this->assertSame(11, $thumb['total'], 'every readable node is counted');
        $this->assertSame(array('key' => 'Event:' . self::E1, 'type' => 'Event', 'x' => -320.0, 'y' => 0.0, 'pinned' => true), $thumb['nodes'][0]);
        $this->assertSame(12.3, $thumb['nodes'][1]['x']);
        $this->assertArrayNotHasKey('x', $thumb['nodes'][2], 'no saved position, none given');

        $value = function ($v) {
            return 'Value:' . AnalystGraphDocumentTool::valueAddress($v);
        };
        $pairs = array();
        foreach ($thumb['edges'] as list($from, $to, $kind)) {
            $pairs[] = $keys[$from] . ' ' . $keys[$to] . ' ' . $kind;
        }
        sort($pairs);
        $o1 = 'Object:' . self::O1;
        $expected = array(
            'Object:' . self::O2 . ' ' . $o1 . ' object-reference',
            $o1 . ' Attribute:' . self::A1 . ' object-reference',
            'Attribute:' . self::A1 . ' ' . $value('8.8.8.8') . ' relationship',
            $o1 . ' Event:' . self::E1 . ' in-event',
            'Attribute:' . self::A1 . ' Event:' . self::E1 . ' in-event',
            'Event:' . self::E1 . ' GalaxyCluster:' . self::C1 . ' tag',
            $o1 . ' GalaxyCluster:' . self::C1 . ' tag',
            'GalaxyCluster:' . self::C1 . ' GalaxyCluster:' . self::C2 . ' cluster-relation',
            $value('8.8.8.8') . ' ' . $o1 . ' value',
            $value('1.2.3.4') . ' Attribute:' . self::A3 . ' value',
            $value('EXAMPLE.ORG') . ' ' . $o1 . ' value',
        );
        sort($expected);
        $this->assertSame($expected, $pairs, 'no contains edge, the hidden one left out, child ends on their object');
    }

    public function testThumbnailDrawsItsBudget()
    {
        $this->registerResolveFakes(array());
        $nodes = array();
        for ($i = 0; $i <= AnalystGraphData::THUMBNAIL_BUDGET; $i++) {
            $nodes[] = self::valueNode('v' . $i);
        }
        list($document) = AnalystGraphDocumentTool::normalise(array('nodes' => $nodes));

        $thumb = (new AnalystGraphData())->thumbnail(array('id' => 1), $document);

        $this->assertCount(AnalystGraphData::THUMBNAIL_BUDGET, $thumb['nodes']);
        $this->assertSame(AnalystGraphData::THUMBNAIL_BUDGET + 1, $thumb['total']);
        $this->assertSame('Value:' . AnalystGraphDocumentTool::valueAddress('v0'), $thumb['nodes'][0]['key'], 'in document order');
    }

    public function testResolveDrawsTheBudgetAndListsTheRest()
    {
        $this->registerResolveFakes(array());
        $nodes = array();
        for ($i = 0; $i <= AnalystGraphData::NODE_BUDGET; $i++) {
            $nodes[] = self::valueNode('v' . $i);
        }
        list($document) = AnalystGraphDocumentTool::normalise(array('nodes' => $nodes));
        $data = new AnalystGraphData();

        $resolved = $data->resolve(array('id' => 1), $document);

        $this->assertSame(AnalystGraphData::NODE_BUDGET + 1, $resolved['meta']['nodes']);
        $this->assertSame(AnalystGraphData::NODE_BUDGET, $resolved['meta']['drawn']);
        $this->assertSame(array('Value:' . AnalystGraphDocumentTool::valueAddress('v' . AnalystGraphData::NODE_BUDGET)), $resolved['meta']['skipped']);
        $this->assertCount(AnalystGraphData::NODE_BUDGET, $resolved['Value']);
        $this->assertCount(AnalystGraphData::NODE_BUDGET + 1, $resolved['document']['nodes']);
    }

    // ------------------------------------------------------------ active graph

    const G1 = '9a000000-0000-4000-8000-000000000061';

    private static function analyst(array $role = array('perm_analyst_data' => 1))
    {
        return array(
            'id' => 3,
            'Role' => $role + array('perm_site_admin' => 0, 'perm_analyst_data' => 0),
            'Organisation' => array('uuid' => 'org-1'),
        );
    }

    private function storedActive($stored)
    {
        $this->fake('UserSetting')->on('getValueForUser', function ($userId, $setting) use ($stored) {
            return $setting === Graph::ACTIVE_SETTING ? $stored : null;
        });
    }

    private function settingWriter($loggedBefore, $fail = false)
    {
        $behaviors = new GraphTestBehaviors($loggedBefore);
        $setting = new GraphTestUserSetting();
        $setting->Behaviors = $behaviors;
        $setting->on('setSettingInternal', function ($userId, $name, $value) use ($behaviors, $fail) {
            $behaviors->log[] = array('save', $userId, $name, $value);
            if ($fail) {
                throw new RuntimeException('database gone');
            }
            return array('UserSetting' => array('id' => 1));
        });
        ClassRegistry::$instances['UserSetting'] = $setting;
        $this->registered[] = 'UserSetting';
        return $behaviors;
    }

    public function unusableStoredValues()
    {
        return array(
            'never set' => array(null),
            'empty' => array(array()),
            'cleared' => array(array('graph_uuid' => null)),
            'not a uuid' => array(array('graph_uuid' => 'zz')),
            'not a string' => array(array('graph_uuid' => 5)),
            'not an object' => array('9a000000-0000-4000-8000-000000000061'),
        );
    }

    /**
     * @dataProvider unusableStoredValues
     */
    public function testNoActiveGraphWithoutAUsableStoredUuid($stored)
    {
        $this->storedActive($stored);
        $graph = new GraphTestActiveGraph();
        $this->assertNull($graph->activeFor(self::analyst()));
        $this->assertSame(array(), $graph->summaryCalls);
    }

    public function testActiveGraphIsLookedUpByItsLowercaseUuid()
    {
        $this->storedActive(array('graph_uuid' => strtoupper(self::G1)));
        $graph = new GraphTestActiveGraph();
        $graph->summaryRows = array(array('uuid' => self::G1, '_canEdit' => true));

        $this->assertSame(self::G1, $graph->activeFor(self::analyst(), false)['uuid']);
        $this->assertSame(array(array(array('Graph.uuid' => self::G1), array('targets' => false))), $graph->summaryCalls);
    }

    public function testAnActiveGraphTheUserCanNoLongerEditIsNone()
    {
        $this->storedActive(array('graph_uuid' => self::G1));
        $graph = new GraphTestActiveGraph();
        $graph->summaryRows = array(array('uuid' => self::G1, '_canEdit' => false));
        $this->assertNull($graph->activeFor(self::analyst()));

        $graph->summaryRows = array();
        $this->assertNull($graph->activeFor(self::analyst()));
    }

    public function testStoringTheActiveGraphKeepsItOutOfTheLegacyLog()
    {
        $behaviors = $this->settingWriter(true);
        $this->assertTrue((new GraphTestActiveGraph())->storeActive(self::analyst(), self::G1));
        $this->assertSame(array(
            array('disable', 'SysLogLogable.SysLogLogable'),
            array('save', 3, Graph::ACTIVE_SETTING, array('graph_uuid' => self::G1)),
            array('enable', 'SysLogLogable.SysLogLogable'),
        ), $behaviors->log);
    }

    public function testClearingStoresNoGraphAndALogAlreadyOffStaysOff()
    {
        $behaviors = $this->settingWriter(false);
        $this->assertTrue((new GraphTestActiveGraph())->storeActive(self::analyst(), null));
        $this->assertSame(array(
            array('disable', 'SysLogLogable.SysLogLogable'),
            array('save', 3, Graph::ACTIVE_SETTING, array('graph_uuid' => null)),
        ), $behaviors->log);
    }

    public function testTheLegacyLogComesBackAfterAFailedWrite()
    {
        $behaviors = $this->settingWriter(true, true);
        try {
            (new GraphTestActiveGraph())->storeActive(self::analyst(), self::G1);
            $this->fail('The write failure was swallowed.');
        } catch (RuntimeException $e) {
            $this->assertSame('database gone', $e->getMessage());
        }
        $this->assertSame(array('enable', 'SysLogLogable.SysLogLogable'), end($behaviors->log));
    }

    public function testOnlyAnalystsAndSiteAdminsHaveEditableGraphs()
    {
        $graph = new GraphTestActiveGraph();
        $this->assertSame(array(), $graph->editableBy(self::analyst(array())));
        $this->assertSame(array(), $graph->summaryCalls);

        $graph->editableBy(self::analyst(array('perm_site_admin' => 1)));
        $this->assertCount(1, $graph->summaryCalls);
    }

    public function testEditableGraphsAreTheOrganisationsOwnThatTheUserCanEdit()
    {
        $graph = new GraphTestActiveGraph();
        $graph->summaryRows = array(
            array('uuid' => 'a', '_canEdit' => true),
            array('uuid' => 'b', '_canEdit' => false),
            array('uuid' => 'c', '_canEdit' => true),
        );

        $editable = $graph->editableBy(self::analyst());

        $this->assertSame(array('a', 'c'), array_column($editable, 'uuid'));
        $this->assertSame(array(array(
            array('Graph.orgc_uuid' => 'org-1'),
            array('limit' => Graph::EDITABLE_LIMIT),
        )), $graph->summaryCalls);
    }

    public function testMineKeepsTheGraphsNamingTheUserAmongTheirAuthors()
    {
        $graph = new GraphTestActiveGraph();
        $graph->summaryRows = array(
            array('id' => 1, 'uuid' => 'a', '_canEdit' => true),
            array('id' => 2, 'uuid' => 'b', '_canEdit' => true),
            array('id' => 3, 'uuid' => 'c', '_canEdit' => true),
            array('id' => 4, 'uuid' => 'd', '_canEdit' => false),
        );
        $graph->authors = array(
            1 => 'Some_One@example.test',
            2 => 'xsome_one@example.test, colleague@example.test',
            3 => 'colleague@example.test; some_one@example.test',
            4 => 'some_one@example.test',
        );
        $user = self::analyst() + array('email' => 'some_one@example.test');

        $mine = $graph->editableBy($user, true);

        $this->assertSame(array('a', 'c'), array_column($mine, 'uuid'));
        $this->assertSame(array(array(
            array('Graph.orgc_uuid' => 'org-1', 'Graph.authors LIKE' => '%some\_one@example.test%'),
            array('limit' => Graph::EDITABLE_LIMIT),
        )), $graph->summaryCalls);
        $this->assertSame(array(), $graph->editableBy(self::analyst(), true));
    }

    public function testTargetsAreLabelledOnlyWhereTheUserCanReadThem()
    {
        $collection = 'c0000000-0000-4000-8000-000000000071';
        $hiddenEvent = 'e9000000-0000-4000-8000-000000000079';
        $this->fake('Event')->on('fetchSimpleEvents', function ($user, $params) {
            $this->assertSame(array(self::E1, 'e9000000-0000-4000-8000-000000000079'), $params['conditions']['Event.uuid']);
            return array(array('Event' => array('id' => '11', 'uuid' => strtoupper(self::E1), 'info' => 'Phishing wave')));
        });
        $this->fake('GalaxyCluster')->on('fetchGalaxyClusters', function ($user, $options) {
            return array(array('GalaxyCluster' => array('id' => '51', 'uuid' => self::C1, 'value' => 'APT29')));
        });
        $this->fake('Collection')
            ->on('buildConditions', function ($userId) {
                return array('Collection.org_id' => 1);
            })
            ->on('find', function ($type, $query) use ($collection) {
                $this->assertSame(array('Collection.org_id' => 1), $query['conditions']['AND'][1]);
                return array(array('Collection' => array('id' => '7', 'uuid' => $collection, 'name' => 'Campaign')));
            });
        $graphs = array(
            array('uuid' => 'g1', 'object_type' => 'Event', 'object_uuid' => self::E1),
            array('uuid' => 'g2', 'object_type' => 'Event', 'object_uuid' => strtoupper($hiddenEvent)),
            array('uuid' => 'g3', 'object_type' => 'GalaxyCluster', 'object_uuid' => self::C1),
            array('uuid' => 'g4', 'object_type' => 'Collection', 'object_uuid' => $collection),
            array('uuid' => 'g5', 'object_type' => 'Event', 'object_uuid' => self::E1),
        );

        $labelled = (new AnalystGraphData())->labelTargets(array('id' => 3), $graphs);

        $this->assertSame(array('type' => 'Event', 'uuid' => self::E1, 'id' => 11, 'label' => 'Phishing wave'), $labelled[0]['target']);
        $this->assertSame(array('type' => 'Event', 'uuid' => $hiddenEvent, 'id' => null, 'label' => null), $labelled[1]['target']);
        $this->assertSame(array('type' => 'GalaxyCluster', 'uuid' => self::C1, 'id' => 51, 'label' => 'APT29'), $labelled[2]['target']);
        $this->assertSame(array('type' => 'Collection', 'uuid' => $collection, 'id' => 7, 'label' => 'Campaign'), $labelled[3]['target']);
        $this->assertSame($labelled[0]['target'], $labelled[4]['target']);
    }

    // --------------------------------------------------------- viewer counts

    public function testVisibleCountsAskOncePerTypeForEveryGraph()
    {
        $asked = array();
        $this->fake('CollectionElement')->on('readableUuids', function ($user, $type, $uuids) use (&$asked) {
            $asked[] = array($type, $uuids);
            return array_values(array_diff($uuids, array(self::A_HIDDEN)));
        });

        $counts = (new AnalystGraphData())->visibleCounts(array('id' => 3), array(
            7 => self::stored(array(self::node('Attribute', self::A1), self::node('Attribute', self::A_HIDDEN), self::valueNode('8.8.8.8'))),
            8 => json_decode(self::stored(array(self::node('Attribute', self::A1), self::node('Event', self::E1))), true),
            9 => 'not json',
        ));

        $this->assertSame(array(7 => 2, 8 => 2, 9 => 0), $counts);
        $this->assertSame(array(
            array('Attribute', array(self::A1, self::A_HIDDEN)),
            array('Event', array(self::E1)),
        ), $asked);
    }

    public function testSummariesCountOnlyWhatTheUserMayRead()
    {
        $this->fake('CollectionElement')->on('readableUuids', function ($user, $type, $uuids) {
            return array_values(array_diff($uuids, array(self::A_HIDDEN)));
        });
        ClassRegistry::$instances['AnalystGraphData'] = new AnalystGraphData();
        $this->registered[] = 'AnalystGraphData';
        $graph = new GraphTestCountedGraph();
        $graph->contents = array(
            1 => self::stored(array(self::node('Attribute', self::A1), self::node('Attribute', self::A_HIDDEN))),
            2 => self::stored(array()),
        );

        $out = $graph->withVisibleCounts(self::analyst(), array(
            array('id' => 1, 'node_count' => 2),
            array('id' => 2, 'node_count' => 0),
        ));

        $this->assertSame(array(1, 0), array_column($out, 'node_count'));
        $this->assertSame(array(array(1, 2)), $graph->asked);
        $this->assertSame(array(), $graph->withVisibleCounts(self::analyst(), array()));
        $this->assertCount(1, $graph->asked);
    }

    // ------------------------------------------------------- module answers

    const ORG_ONLY = 'f1000000-0000-4000-8000-000000000061';
    const OPEN = 'f2000000-0000-4000-8000-000000000062';
    const GONE = 'f3000000-0000-4000-8000-000000000063';
    const RAN = 1791100000;

    private static function answer($type, $value, array $origins, $module = 'dns', array $extra = array())
    {
        return array(
            'type' => 'ModuleAnswer',
            'module' => $module,
            'origins' => $origins,
            'content' => array('kind' => 'attribute', 'type' => $type, 'value' => $value, 'category' => 'Network activity', 'comment' => '', 'to_ids' => false),
        ) + $extra;
    }

    private static function origin($node, $type, $value, $module = 'dns')
    {
        return array('node' => $node, 'module' => $module, 'type' => $type, 'value' => $value, 'ran_at' => self::RAN);
    }

    private static function answerKey($type, $value)
    {
        return 'ModuleAnswer:' . AnalystGraphDocumentTool::answerUuidFor($type, $value);
    }

    private static function keys(array $nodes)
    {
        return array_map(array('AnalystGraphDocumentTool', 'nodeKey'), $nodes);
    }

    private static function normalised(array $nodes, array $groups = array())
    {
        list($document, $errors) = AnalystGraphDocumentTool::normalise(array('nodes' => $nodes, 'groups' => $groups));
        if (!empty($errors)) {
            throw new RuntimeException(implode(' ', $errors));
        }
        return $document;
    }

    /**
     * Readable attributes, modules reserved away from the user's
     * organisation, and the attribute uuids the instance still holds.
     */
    private function registerAnswerFakes(array $readable, array $reserved = array(), ?array $existing = null)
    {
        $this->fake('CollectionElement')->on('readableUuids', function ($user, $type, $uuids) use ($readable) {
            return array_values(array_filter($uuids, function ($uuid) use ($readable) {
                return self::inList($uuid, $readable);
            }));
        });
        $this->fake('Module')->on('canUse', function ($user, $family, $module) use ($reserved) {
            return !in_array($module['name'], $reserved, true);
        });
        $existing = $existing === null ? $readable : $existing;
        $this->fake('MispAttribute')->on('find', function ($type, $query) use ($existing) {
            return array_values(array_filter($query['conditions']['Attribute.uuid'], function ($uuid) use ($existing) {
                return self::inList($uuid, $existing);
            }));
        });
    }

    private function registerAnswerResolveFakes(array $readable)
    {
        $this->registerResolveFakes($readable);
        $this->fake('ObjectReference')->on('find', function () {
            return array();
        });
    }

    public function testAnAnswerIsStoredWithADerivedUuid()
    {
        $document = self::normalised(array(
            self::answer('ip-dst', '203.0.113.7', array(
                self::origin('Attribute:' . strtoupper(self::ORG_ONLY), 'domain', 'example.com'),
                self::origin('Value:anything', 'domain', ' example.org ', 'circl_passivedns'),
            ), 'dns', array('uuid' => self::uuid(1), 'x' => 1.5, 'y' => 2, 'pinned' => 1, 'modules' => array('circl_passivedns', 'dns'), 'extra' => 'dropped')),
        ));

        $node = $document['nodes'][0];
        $this->assertSame(self::answerKey('ip-dst', '203.0.113.7'), AnalystGraphDocumentTool::nodeKey($node), 'the client uuid is ignored');
        $this->assertSame(array('type', 'uuid', 'x', 'y', 'pinned', 'module', 'modules', 'origins', 'content'), array_keys($node));
        $this->assertSame(array('dns', 'circl_passivedns'), $node['modules'], 'the stored module first');
        $this->assertSame('Attribute:' . self::ORG_ONLY, $node['origins'][0]['node']);
        $this->assertSame('Value:' . AnalystGraphDocumentTool::valueAddress('example.org'), $node['origins'][1]['node'], 'a Value origin is named by its value');
        $this->assertSame(array('kind' => 'attribute', 'type' => 'ip-dst', 'value' => '203.0.113.7', 'category' => 'Network activity', 'comment' => '', 'to_ids' => false), $node['content']);
    }

    public function testAnswerIdentityFollowsTheExplorersMerging()
    {
        $element = self::normalised(array(array(
            'type' => 'ModuleAnswer', 'module' => 'legacy', 'origins' => array(self::origin('Value:', 'domain', 'a.example')),
            'content' => array('kind' => 'element', 'types' => array('ip-dst', 'ip-src'), 'value' => '192.0.2.1'),
        )))['nodes'][0];
        $this->assertSame(self::answerKey('ip-dst', '192.0.2.1'), AnalystGraphDocumentTool::nodeKey($element), 'an element is its first type');

        $object = function (array $attributes) {
            return self::normalised(array(array(
                'type' => 'ModuleAnswer', 'module' => 'whois', 'origins' => array(self::origin('Value:', 'domain', 'a.example', 'whois')),
                'content' => array('kind' => 'object', 'name' => 'whois', 'attributes' => $attributes),
            )))['nodes'][0];
        };
        $a = array('relation' => 'registrar', 'type' => 'whois-registrar', 'value' => 'R');
        $b = array('relation' => 'creation-date', 'type' => 'datetime', 'value' => '2020');
        $this->assertSame($object(array($a, $b))['uuid'], $object(array($b, $a))['uuid'], 'attribute order does not matter');
        $this->assertNotSame($object(array($a))['uuid'], $object(array($a, $b))['uuid']);
        $this->assertSame(array('relation' => 'registrar', 'type' => 'whois-registrar', 'value' => 'R', 'category' => '', 'comment' => '', 'to_ids' => false), $object(array($a))['content']['attributes'][0]);
    }

    public function testAnAnswerOriginOnAnotherAnswerIsNamedByWhatWasAsked()
    {
        $node = self::normalised(array(
            self::answer('domain', 'b.example', array(self::origin('ModuleAnswer:' . self::uuid(9), 'ip-dst', '192.0.2.1'))),
        ))['nodes'][0];

        $this->assertSame(self::answerKey('ip-dst', '192.0.2.1'), $node['origins'][0]['node']);
    }

    public function testAnAnswerIsNotItsOwnOrigin()
    {
        $node = self::normalised(array(self::answer('ip-dst', '192.0.2.1', array(
            self::origin('ModuleAnswer:', 'ip-dst', '192.0.2.1'),
            self::origin('Value:', 'domain', 'a.example'),
            self::origin('Value:', 'domain', 'a.example'),
        ))))['nodes'][0];

        $this->assertSame(array('Value:' . AnalystGraphDocumentTool::valueAddress('a.example')), array_column($node['origins'], 'node'), 'and an origin is listed once');
    }

    public function invalidAnswers()
    {
        $origin = self::origin('Attribute:' . self::OPEN, 'domain', 'example.com');
        $base = self::answer('ip-dst', '192.0.2.1', array($origin));
        $content = function (array $change) use ($base) {
            return array('content' => $change + $base['content']) + $base;
        };
        $origins = array();
        for ($i = 0; $i <= AnalystGraphDocumentTool::MAX_ANSWER_ORIGINS; $i++) {
            $origins[] = self::origin('Value:', 'domain', 'v' . $i . '.example');
        }
        $attributes = array_fill(0, AnalystGraphDocumentTool::MAX_ANSWER_ATTRIBUTES + 1, array('relation' => 'r', 'type' => 'text', 'value' => 'v'));
        $noRanAt = $origin;
        unset($noRanAt['ran_at']);
        $tooLong = str_repeat('a', AnalystGraphDocumentTool::MAX_ANSWER_STRING_BYTES + 1);
        return array(
            'no module' => array(array_diff_key($base, array('module' => 1))),
            'a dotted module' => array(array('module' => 'a.b') + $base),
            'no origin' => array(array('origins' => array()) + $base),
            'an event origin' => array(array('origins' => array(self::origin('Event:' . self::E1, 'domain', 'x'))) + $base),
            'an origin with no ran_at' => array(array('origins' => array($noRanAt)) + $base),
            'an origin with a bad uuid' => array(array('origins' => array(self::origin('Attribute:nope', 'domain', 'x'))) + $base),
            'too many origins' => array(array('origins' => $origins) + $base),
            'an unknown kind' => array($content(array('kind' => 'note'))),
            'an empty value' => array($content(array('value' => ''))),
            'a value too long' => array($content(array('value' => $tooLong))),
            'a comment too long' => array($content(array('comment' => $tooLong))),
            'too many object attributes' => array(array('content' => array('kind' => 'object', 'name' => 'o', 'attributes' => $attributes)) + $base),
            'an element without types' => array(array('content' => array('kind' => 'element', 'types' => array(), 'value' => 'v')) + $base),
            'modules not a list' => array(array('modules' => 'dns') + $base),
        );
    }

    /**
     * @dataProvider invalidAnswers
     */
    public function testInvalidAnswerIsRefused(array $node)
    {
        list($document, $errors) = AnalystGraphDocumentTool::normalise(array('nodes' => array($node)));

        $this->assertNull($document);
        $this->assertNotEmpty($errors);
        $this->assertStringStartsWith('nodes[0]', $errors[0]);
    }

    public function testAStringAtTheAnswerLimitIsKept()
    {
        $value = str_repeat('a', AnalystGraphDocumentTool::MAX_ANSWER_STRING_BYTES);
        $node = self::normalised(array(self::answer('text', $value, array(self::origin('Value:', 'domain', 'a.example')))))['nodes'][0];

        $this->assertSame($value, $node['content']['value']);
    }

    public function testAddNodesTakesNoAnswers()
    {
        list($document, $report) = AnalystGraphDocumentTool::addNodes(AnalystGraphDocumentTool::emptyDocument(), array(
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Value:', 'domain', 'a.example'))),
            self::valueNode('a.example'),
        ));

        $this->assertCount(1, $document['nodes']);
        $this->assertSame(0, $report['refused'][0]['index']);
    }

    public function testRemoveNodesLeavesWhatItIsToldToKeep()
    {
        $document = self::normalised(array(
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Value:', 'domain', 'a.example'))),
            self::valueNode('a.example'),
        ));
        $key = self::answerKey('ip-dst', '192.0.2.1');

        list($after, $report) = AnalystGraphDocumentTool::removeNodes($document, array($key, 'Value:' . AnalystGraphDocumentTool::valueAddress('a.example')), array($key => true));

        $this->assertSame(array($key), self::keys($after['nodes']));
        $this->assertSame(array($key), $report['absent'], 'reported as if the document did not hold it');
    }

    public function testAnAnswerIsSeenThroughAnOriginTheReaderCanSee()
    {
        $this->registerAnswerFakes(array(self::OPEN));
        $document = self::normalised(array(
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::OPEN, 'domain', 'open.example'))),
            self::answer('ip-dst', '192.0.2.2', array(self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'))),
            self::answer('ip-dst', '192.0.2.3', array(self::origin('Value:', 'domain', 'value.example'))),
        ));

        $seen = (new AnalystGraphData())->visibleNodes(self::analyst(), $document['nodes']);

        $this->assertSame(array(self::answerKey('ip-dst', '192.0.2.1'), self::answerKey('ip-dst', '192.0.2.3')), self::keys($seen));
    }

    public function testAReservedModuleHidesItsAnswerAndItsLinks()
    {
        $this->registerAnswerFakes(array(self::OPEN), array('reserved'));
        $document = self::normalised(array(
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::OPEN, 'domain', 'open.example', 'reserved')), 'dns'),
            self::answer('ip-dst', '192.0.2.2', array(self::origin('Attribute:' . self::OPEN, 'domain', 'open.example')), 'reserved'),
            self::answer('ip-dst', '192.0.2.3', array(
                self::origin('Attribute:' . self::OPEN, 'domain', 'open.example', 'reserved'),
                self::origin('Value:', 'domain', 'open.example'),
            ), 'dns', array('modules' => array('reserved'))),
        ));

        $seen = (new AnalystGraphData())->visibleNodes(self::analyst(), $document['nodes']);

        $this->assertSame(array(self::answerKey('ip-dst', '192.0.2.3')), self::keys($seen));
        $this->assertStringNotContainsString('reserved', json_encode($seen), 'no module the reader may not use is named');
    }

    public function testAChainOrALoopIsSeenOnlyFromAVisibleRoot()
    {
        $this->registerAnswerFakes(array(self::OPEN));
        $document = self::normalised(array(
            // a visible root, then a, then b
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::OPEN, 'domain', 'open.example'))),
            self::answer('domain', 'b.example', array(self::origin('ModuleAnswer:', 'ip-dst', '192.0.2.1'))),
            // a hidden root, then c, then d
            self::answer('ip-dst', '192.0.2.3', array(self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'))),
            self::answer('domain', 'd.example', array(self::origin('ModuleAnswer:', 'ip-dst', '192.0.2.3'))),
            // e and f asked about each other, no root
            self::answer('ip-dst', '192.0.2.5', array(self::origin('ModuleAnswer:', 'domain', 'f.example'))),
            self::answer('domain', 'f.example', array(self::origin('ModuleAnswer:', 'ip-dst', '192.0.2.5'))),
        ));

        $seen = (new AnalystGraphData())->visibleNodes(self::analyst(), $document['nodes']);

        $this->assertSame(array(self::answerKey('ip-dst', '192.0.2.1'), self::answerKey('domain', 'b.example')), self::keys($seen));
    }

    public function testAReaderGetsOnlyTheOriginsTheyPass()
    {
        $this->registerAnswerFakes(array(self::OPEN));
        $document = self::normalised(array(self::answer('ip-dst', '192.0.2.1', array(
            self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'),
            self::origin('Attribute:' . self::OPEN, 'domain', 'open.example'),
        ))));

        $seen = (new AnalystGraphData())->visibleNodes(self::analyst(), $document['nodes']);

        $this->assertCount(1, $seen);
        $this->assertSame(array('Attribute:' . self::OPEN), array_column($seen[0]['origins'], 'node'));
        $this->assertStringNotContainsString(self::ORG_ONLY, json_encode($seen));
        $this->assertStringNotContainsString('secret.example', json_encode($seen));
    }

    public function testRestReadKeepsRecordsAsStoredAndFiltersAnswers()
    {
        $this->registerAnswerFakes(array(self::OPEN));
        $document = self::normalised(array(
            self::node('Attribute', self::ORG_ONLY),
            self::answer('ip-dst', '192.0.2.2', array(self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'))),
        ));
        $data = new AnalystGraphData();

        $rest = $data->documentFor(self::analyst(), $document, true);
        $read = $data->documentFor(self::analyst(), $document);

        $this->assertSame(array('Attribute:' . self::ORG_ONLY), self::keys($rest['nodes']));
        $this->assertSame(array(), $read['nodes']);
    }

    public function testCountsIncludeTheAnswersTheReaderSees()
    {
        $this->registerAnswerFakes(array(self::OPEN));
        $counts = (new AnalystGraphData())->visibleCounts(self::analyst(), array(1 => self::stored(array(
            self::node('Attribute', self::OPEN),
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::OPEN, 'domain', 'open.example'))),
            self::answer('ip-dst', '192.0.2.2', array(self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'))),
        ))));

        $this->assertSame(array(1 => 2), $counts);
    }

    public function testResolveDrawsAnEnrichmentEdgeFromEachOriginTheReaderPasses()
    {
        $this->registerAnswerResolveFakes(array(self::O1, self::A_CHILD1, self::A1));
        $this->fake('Module')->on('canUse', function () {
            return true;
        });
        $document = self::normalised(array(
            self::node('Object', self::O1),
            self::valueNode('a.example'),
            self::answer('ip-dst', '192.0.2.1', array(
                self::origin('Attribute:' . self::A_CHILD1, 'ip-dst', '8.8.8.8'),
                self::origin('Value:', 'domain', 'a.example', 'passive'),
                self::origin('Attribute:' . self::A1, 'domain', 'not.drawn'),
            )),
        ));

        $resolved = (new AnalystGraphData())->resolve(array('id' => 1), $document);

        $answer = self::answerKey('ip-dst', '192.0.2.1');
        $enrichment = array_values(array_filter($resolved['edges'], function ($e) {
            return $e['kind'] === 'enrichment';
        }));
        $this->assertSame(array(
            array('Attribute:' . self::A_CHILD1, $answer, 'dns'),
            array('Value:' . AnalystGraphDocumentTool::valueAddress('a.example'), $answer, 'passive'),
        ), array_map(function ($e) {
            return array($e['from'], $e['to'], $e['label']);
        }, $enrichment), 'from an attribute inside a drawn object, from a Value; none from what is not drawn');
        $this->assertSame(3, $resolved['meta']['nodes']);
    }

    public function testAThumbnailDrawsAnswersAsTheirOwnType()
    {
        $this->registerAnswerResolveFakes(array(self::O1, self::A_CHILD1));
        $this->fake('Module')->on('canUse', function () {
            return true;
        });
        $document = self::normalised(array(
            self::node('Object', self::O1),
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::A_CHILD1, 'ip-dst', '8.8.8.8'))),
        ));

        $thumb = (new AnalystGraphData())->thumbnail(array('id' => 1), $document);

        $this->assertSame(array('Object', 'ModuleAnswer'), array_column($thumb['nodes'], 'type'));
        $this->assertCount(1, $thumb['edges']);
        list($from, $to, $kind) = $thumb['edges'][0];
        $this->assertSame(array(0, 1, 'enrichment'), array(min($from, $to), max($from, $to), $kind), 'joined to the object holding its origin');
    }

    public function testANewAnswerKeepsOnlyOriginsTheWriterCanName()
    {
        $this->registerAnswerFakes(array(self::OPEN), array(), array(self::OPEN, self::ORG_ONLY));
        $incoming = self::normalised(array(
            self::answer('ip-dst', '192.0.2.1', array(
                self::origin('Attribute:' . self::OPEN, 'domain', 'open.example'),
                self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'),
            )),
            self::answer('ip-dst', '192.0.2.2', array(self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'))),
            self::answer('domain', 'c.example', array(self::origin('ModuleAnswer:', 'ip-dst', '198.51.100.1'))),
        ));

        $out = (new AnalystGraphData())->documentForWrite(self::analyst(), $incoming);

        $this->assertSame(array(self::answerKey('ip-dst', '192.0.2.1')), self::keys($out['nodes']));
        $this->assertSame(array('Attribute:' . self::OPEN), array_column($out['nodes'][0]['origins'], 'node'));
        $this->assertArrayNotHasKey('_new', $out['nodes'][0]);
    }

    public function testAStoredAnswerKeepsItsContentAndGainsOrigins()
    {
        $this->registerAnswerFakes(array(self::OPEN));
        $stored = self::normalised(array(
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Value:', 'domain', 'a.example')), 'dns', array('x' => 1, 'y' => 1, 'pinned' => true)),
        ));
        $sent = self::answer('ip-dst', '192.0.2.1', array(
            self::origin('Value:', 'domain', 'a.example'),
            self::origin('Attribute:' . self::OPEN, 'domain', 'open.example', 'passive'),
        ), 'other', array('x' => 5, 'y' => 6));
        $sent['content']['comment'] = 'rewritten';

        $out = (new AnalystGraphData())->documentForWrite(self::analyst(), self::normalised(array($sent)), json_decode(json_encode($stored), true));

        $node = $out['nodes'][0];
        $this->assertSame('', $node['content']['comment'], 'the stored content wins');
        $this->assertSame('dns', $node['module']);
        $this->assertSame(array('dns', 'passive'), $node['modules']);
        $this->assertSame(array('Value:' . AnalystGraphDocumentTool::valueAddress('a.example'), 'Attribute:' . self::OPEN), array_column($node['origins'], 'node'));
        $this->assertSame(array(5, 6), array($node['x'], $node['y']));
        $this->assertArrayNotHasKey('pinned', $node, 'the layout is the writer\'s');
    }

    public function testAWriteKeepsTheAnswersItsWriterCannotSee()
    {
        $this->registerAnswerFakes(array(self::OPEN), array(), array(self::OPEN, self::ORG_ONLY));
        $stored = self::normalised(array(
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::OPEN, 'domain', 'open.example'))),
            self::answer('ip-dst', '192.0.2.2', array(self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'))),
            self::node('Attribute', self::OPEN),
        ));

        $out = (new AnalystGraphData())->documentForWrite(self::analyst(), self::normalised(array(self::node('Attribute', self::OPEN))), $stored);

        $this->assertSame(array('Attribute:' . self::OPEN, self::answerKey('ip-dst', '192.0.2.2')), self::keys($out['nodes']),
            'the seen answer left out is removed, the hidden one put back');
    }

    public function testAReadNarrowsGroupsToWhatTheReaderSees()
    {
        $this->registerAnswerFakes(array(self::OPEN));
        $document = self::normalised(array(
            self::node('Attribute', self::OPEN),
            self::node('Attribute', self::ORG_ONLY),
            self::valueNode('a.example'),
            self::answer('ip-dst', '192.0.2.2', array(self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'))),
            self::valueNode('b.example'),
        ), array(
            array('title' => 'Seen', 'members' => array('Attribute:' . self::OPEN, 'Attribute:' . self::ORG_ONLY, self::valueNode('a.example'))),
            array('title' => 'Unseen', 'members' => array(self::answerKey('ip-dst', '192.0.2.2'), self::valueNode('b.example'))),
        ));
        $data = new AnalystGraphData();

        $read = $data->documentFor(self::analyst(), $document);
        $rest = $data->documentFor(self::analyst(), $document, true);

        $this->assertSame(array(
            array('title' => 'Seen', 'members' => array('Attribute:' . self::OPEN, 'Value:' . AnalystGraphDocumentTool::valueAddress('a.example'))),
        ), $read['groups']);
        $this->assertStringNotContainsString(self::ORG_ONLY, json_encode($read));
        $this->assertStringNotContainsString('Unseen', json_encode($read), 'a group left with one member goes, title and all');
        $this->assertSame(array('Seen'), array_column($rest['groups'], 'title'));
        $this->assertCount(3, $rest['groups'][0]['members'], 'records as stored');
    }

    public function testAWriteKeepsTheHiddenAnswersInTheirGroups()
    {
        $this->registerAnswerFakes(array(self::OPEN), array(), array(self::OPEN, self::ORG_ONLY));
        $shown = self::answerKey('ip-dst', '192.0.2.1');
        $unshown = self::answerKey('ip-dst', '192.0.2.2');
        $stored = self::normalised(array(
            self::node('Attribute', self::OPEN),
            self::valueNode('a.example'),
            self::valueNode('b.example'),
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'))),
            self::answer('ip-dst', '192.0.2.2', array(self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'secret.example'))),
        ), array(
            array('title' => 'Shown', 'members' => array('Attribute:' . self::OPEN, self::valueNode('a.example'), $shown)),
            array('title' => 'Unshown', 'x' => 4, 'members' => array(self::valueNode('b.example'), $unshown)),
        ));
        $nodes = array(self::node('Attribute', self::OPEN), self::valueNode('a.example'), self::valueNode('b.example'));
        $data = new AnalystGraphData();

        $out = $data->documentForWrite(self::analyst(), self::normalised($nodes, array(
            array('title' => 'Renamed', 'members' => array('Attribute:' . self::OPEN, self::valueNode('a.example'))),
        )), $stored);

        $this->assertSame(array(
            array('title' => 'Renamed', 'members' => array('Attribute:' . self::OPEN, 'Value:' . AnalystGraphDocumentTool::valueAddress('a.example'), $shown)),
            array('title' => 'Unshown', 'members' => array('Value:' . AnalystGraphDocumentTool::valueAddress('b.example'), $unshown), 'x' => 4),
        ), $out['groups'], 'a shown group follows the write; one the writer was not shown stays as stored');

        $out = $data->documentForWrite(self::analyst(), self::normalised($nodes), $stored);

        $this->assertSame(array('Unshown'), array_column($out['groups'], 'title'), 'a shown group the writer ungrouped stays ungrouped');
    }

    public function testAnAnswerGoesWithTheLastOfItsOrigins()
    {
        // ORG_ONLY is still held (soft-deleted, say); GONE was deleted for good
        $this->registerAnswerFakes(array(self::OPEN, self::ORG_ONLY), array(), array(self::OPEN, self::ORG_ONLY));
        $stored = self::normalised(array(
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::GONE, 'domain', 'gone.example'))),
            self::answer('domain', 'b.example', array(self::origin('ModuleAnswer:', 'ip-dst', '192.0.2.1'))),
            self::answer('ip-dst', '192.0.2.2', array(
                self::origin('Attribute:' . self::GONE, 'domain', 'gone.example'),
                self::origin('Attribute:' . self::ORG_ONLY, 'domain', 'kept.example'),
            )),
            self::answer('ip-dst', '192.0.2.3', array(self::origin('Value:', 'domain', 'v.example'))),
        ));

        $out = (new AnalystGraphData())->documentForWrite(self::analyst(), $stored, $stored);

        $this->assertSame(array(self::answerKey('ip-dst', '192.0.2.2'), self::answerKey('ip-dst', '192.0.2.3')), self::keys($out['nodes']),
            'the chain off a deleted origin goes; one live origin keeps an answer; a Value origin never goes');
        $this->assertCount(2, $out['nodes'][0]['origins'], 'a stored origin stays once gone');
    }

    const PUSH_COMMUNITY = 'f4000000-0000-4000-8000-000000000064';
    const PUSH_ORG_ONLY = 'f5000000-0000-4000-8000-000000000065';
    const PUSH_GROUP = 'f6000000-0000-4000-8000-000000000066';
    const PUSH_IN_OBJECT = 'f7000000-0000-4000-8000-000000000067';

    /**
     * Attributes as a push sees them: in an all-communities event, one
     * inheriting, one org-only, one shared with a group the server is in, one
     * inside a community-only object. The remote organisation is 9.
     */
    private function registerPushFakes(array &$asked = array())
    {
        $attributes = array(
            array('uuid' => self::PUSH_COMMUNITY, 'event_id' => 1, 'object_id' => 0, 'distribution' => 5, 'sharing_group_id' => 0),
            array('uuid' => self::PUSH_ORG_ONLY, 'event_id' => 1, 'object_id' => 0, 'distribution' => 0, 'sharing_group_id' => 0),
            array('uuid' => self::PUSH_GROUP, 'event_id' => 1, 'object_id' => 0, 'distribution' => 4, 'sharing_group_id' => 7),
            array('uuid' => self::PUSH_IN_OBJECT, 'event_id' => 1, 'object_id' => 3, 'distribution' => 5, 'sharing_group_id' => 0),
        );
        $this->fake('MispAttribute')->on('find', function ($type, $query) use ($attributes) {
            return array_map(function ($a) {
                return array('Attribute' => $a);
            }, array_values(array_filter($attributes, function ($a) use ($query) {
                return self::inList($a['uuid'], $query['conditions']['Attribute.uuid']);
            })));
        });
        $this->fake('Event')
            ->on('find', function () {
                return array(array('Event' => array('id' => 1, 'distribution' => 3, 'sharing_group_id' => 0)));
            })
            ->on('checkDistributionForPush', function ($object, $server) {
                $distribution = $object['Event']['distribution'];
                if ($distribution === 4) {
                    return in_array($server['Server']['id'], array_column($object['SharingGroup']['SharingGroupServer'], 'server_id'));
                }
                return $distribution >= 2;
            });
        $this->fake('MispObject')->on('find', function () {
            return array(array('Object' => array('id' => 3, 'distribution' => 1, 'sharing_group_id' => 0)));
        });
        $this->fake('SharingGroup')->on('find', function () {
            return array(array('SharingGroup' => array('id' => 7, 'roaming' => 0), 'SharingGroupServer' => array(array('server_id' => 2, 'all_orgs' => 1))));
        });
        $this->fake('Module')->on('canUse', function ($user, $family, $module) use (&$asked) {
            $asked[] = $user['org_id'];
            return $module['name'] !== 'reserved';
        });
    }

    private static function pushServer()
    {
        return array('Server' => array('id' => 2, 'remote_org_id' => 9, 'internal' => 0), 'RemoteOrg' => array('uuid' => 'org-9'));
    }

    public function testAPushCarriesTheAnswersWhoseOriginsGoToo()
    {
        $asked = array();
        $this->registerPushFakes($asked);
        $document = self::normalised(array(
            self::node('Attribute', self::PUSH_ORG_ONLY),
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::PUSH_COMMUNITY, 'domain', 'c.example'))),
            self::answer('ip-dst', '192.0.2.2', array(self::origin('Attribute:' . self::PUSH_ORG_ONLY, 'domain', 'secret.example'))),
            self::answer('ip-dst', '192.0.2.3', array(self::origin('Attribute:' . self::PUSH_GROUP, 'domain', 'g.example'))),
            self::answer('ip-dst', '192.0.2.4', array(self::origin('Attribute:' . self::PUSH_IN_OBJECT, 'domain', 'o.example'))),
            self::answer('ip-dst', '192.0.2.5', array(self::origin('Value:', 'domain', 'v.example'))),
            self::answer('ip-dst', '192.0.2.6', array(self::origin('Value:', 'domain', 'v.example')), 'reserved'),
            self::answer('domain', 'chain.example', array(self::origin('ModuleAnswer:', 'ip-dst', '192.0.2.2'))),
            self::answer('ip-dst', '192.0.2.8', array(
                self::origin('Attribute:' . self::PUSH_ORG_ONLY, 'domain', 'secret.example'),
                self::origin('Attribute:' . self::PUSH_COMMUNITY, 'domain', 'c.example'),
            )),
        ));
        $document['view'] = new stdClass();

        $pushed = (new AnalystGraphData())->documentForServer($document, self::pushServer());

        $this->assertSame(array(
            'Attribute:' . self::PUSH_ORG_ONLY,
            self::answerKey('ip-dst', '192.0.2.1'),
            self::answerKey('ip-dst', '192.0.2.3'),
            self::answerKey('ip-dst', '192.0.2.5'),
            self::answerKey('ip-dst', '192.0.2.8'),
        ), self::keys($pushed['nodes']), 'records as stored; answers whose origin goes there, never a reserved module\'s');
        $this->assertSame(array('Attribute:' . self::PUSH_COMMUNITY), array_column($pushed['nodes'][4]['origins'], 'node'));
        $this->assertStringNotContainsString('secret.example', json_encode($pushed));
        $this->assertSame(array(9), array_values(array_unique($asked)), 'the module test is the remote organisation\'s');
        $this->assertInstanceOf('stdClass', $pushed['view']);
    }

    public function testAPushNarrowsGroupsToTheAnswersThatGo()
    {
        $asked = array();
        $this->registerPushFakes($asked);
        $document = self::normalised(array(
            self::node('Attribute', self::PUSH_ORG_ONLY),
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::PUSH_COMMUNITY, 'domain', 'c.example'))),
            self::answer('ip-dst', '192.0.2.2', array(self::origin('Attribute:' . self::PUSH_ORG_ONLY, 'domain', 'secret.example'))),
            self::answer('domain', 'x.example', array(self::origin('Attribute:' . self::PUSH_ORG_ONLY, 'domain', 'secret.example'))),
            self::valueNode('v.example'),
        ), array(
            array('members' => array(self::answerKey('ip-dst', '192.0.2.1'), self::answerKey('ip-dst', '192.0.2.2'), self::valueNode('v.example'))),
            array('title' => 'Org only', 'members' => array('Attribute:' . self::PUSH_ORG_ONLY, self::answerKey('domain', 'x.example'))),
        ));

        $pushed = (new AnalystGraphData())->documentForServer($document, self::pushServer());

        $this->assertSame(array(
            array('members' => array(self::answerKey('ip-dst', '192.0.2.1'), 'Value:' . AnalystGraphDocumentTool::valueAddress('v.example'))),
        ), $pushed['groups']);
        $this->assertStringNotContainsString(self::answerKey('ip-dst', '192.0.2.2'), json_encode($pushed));
        $this->assertStringNotContainsString('Org only', json_encode($pushed));
    }

    public function testAPushedGraphIsReceivedWithItsAnswers()
    {
        $document = self::normalised(array(
            self::answer('ip-dst', '192.0.2.1', array(self::origin('Attribute:' . self::GONE, 'domain', 'not.here.yet'))),
        ));

        $graph = new GraphTestGraph();
        $graph->data = array('Graph' => array());
        $this->assertTrue($graph->validDocument(array('content' => $document)), 'an origin this instance does not hold yet is no reason to refuse it');
        $this->assertSame(array(self::answerKey('ip-dst', '192.0.2.1')), self::keys(json_decode($graph->data['Graph']['content'], true)['nodes']));
    }

    public function testTheAfterSaveWorkflowGetsAnswerKeysOnly()
    {
        $graph = new GraphTestTriggerGraph();
        $stored = self::stored(array(self::answer('ip-dst', '192.0.2.1', array(self::origin('Value:', 'domain', 'a.example')))));

        $data = $graph->triggerData(array('id' => 1, 'content' => $stored));

        $this->assertSame(array(array('type' => 'ModuleAnswer', 'uuid' => AnalystGraphDocumentTool::answerUuidFor('ip-dst', '192.0.2.1'))), json_decode($data['content'], true)['nodes']);
        $this->assertStringNotContainsString('a.example', $data['content']);
    }

    public function testPhpSizesReadAsBytes()
    {
        $this->assertSame(8388608, AnalystGraphDocumentTool::iniBytes('8M'));
        $this->assertSame(524288, AnalystGraphDocumentTool::iniBytes('512k'));
        $this->assertSame(1073741824, AnalystGraphDocumentTool::iniBytes('1G'));
        $this->assertSame(2048, AnalystGraphDocumentTool::iniBytes('2048'));
        $this->assertSame(0, AnalystGraphDocumentTool::iniBytes('0'));
        $this->assertSame(0, AnalystGraphDocumentTool::iniBytes(false));
    }

    public function testTheSaveLimitIsTheSmallerOfTheDocumentCapAndTheRequestCap()
    {
        $limits = AnalystGraphDocumentTool::limits();
        $post = AnalystGraphDocumentTool::iniBytes(ini_get('post_max_size'));
        $expected = $post > 0
            ? min(AnalystGraphDocumentTool::MAX_BYTES, $post - AnalystGraphDocumentTool::REQUEST_OVERHEAD)
            : AnalystGraphDocumentTool::MAX_BYTES;

        $this->assertSame(array('nodes' => 2000, 'bytes' => $expected, 'document_bytes' => AnalystGraphDocumentTool::MAX_BYTES), $limits);
    }

    public function testTheAuditLogNamesAnswersByKey()
    {
        $summary = AnalystGraphDocumentTool::summariseChange(
            self::stored(array()),
            self::stored(array(self::answer('ip-dst', '192.0.2.1', array(self::origin('Value:', 'domain', 'a.example')))))
        );

        $this->assertSame(array(self::answerKey('ip-dst', '192.0.2.1')), $summary['nodes_added']);
        $this->assertStringNotContainsString('192.0.2.1', json_encode($summary));
    }
}

class GraphTestTriggerGraph extends GraphTestGraph
{
    public function triggerData(array $data)
    {
        return $this->workflowTriggerData($data);
    }
}
