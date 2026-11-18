<?php
/**
 * Collection members MISP does not hold: values kept as text, standalone
 * objects, where a member came from, and what sync does with them.
 *
 * Pure PHPUnit, no CakePHP bootstrap and no database, as the other tests
 * under app/Test/. The framework classes touched are stubbed below, each
 * guarded so that a full-suite run sharing one process keeps whichever stub
 * loaded first; the models under test run against in-memory storage.
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

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

if (!class_exists('Hash', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Hash.php';
}

if (!class_exists('Validation', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Validation.php';
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

require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Lib/Tools/AnalystGraphDocumentTool.php';
require_once __DIR__ . '/../Lib/Tools/DistributionLevel.php';
require_once __DIR__ . '/../Model/CollectionElement.php';
require_once __DIR__ . '/../Model/StandaloneObject.php';

/** The parent collection: its distribution, and what is touched. */
class MembersOutsideParent
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
}

/** A CollectionElement with its storage in memory. */
class MembersOutsideElement extends CollectionElement
{
    public $stored = array();
    public $saved = array();
    public $failSave = false;
    public $readableAsked = array();

    public function __construct()
    {
        $this->Collection = new MembersOutsideParent();
    }

    public function readableUuids(array $user, $type, array $uuids)
    {
        $this->readableAsked[$type] = $uuids;
        return array();
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
            if (isset($row[$column]) && in_array(strtolower($row[$column]), $addresses, true)) {
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
            $this->validationErrors = array('element_uuid' => array('Not savable.'));
            return false;
        }
        $row = $this->data['CollectionElement'];
        $this->saved[] = $row;
        $this->stored[count($this->stored) + 100] = $row;
        return $data;
    }
}

/** A StandaloneObject with its storage in memory. */
class MembersOutsideStandalone extends StandaloneObject
{
    public $alias = 'StandaloneObject';
    public $stored = array();
    public $saves = array();
    public $deleteAlls = array();
    public $unheldAsked = array();
    public $failSave = false;
    public $spyUnheld = true;

    public function __construct()
    {
    }

    public function hasAny($conditions = null)
    {
        return isset($this->stored[strtolower($conditions['StandaloneObject.uuid'])]);
    }

    public function create($data = array(), $filterKey = false)
    {
        $this->id = false;
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        if ($this->failSave) {
            $this->validationErrors = array('uuid' => array('The uuid provided is not unique'));
            return false;
        }
        $row = $data['StandaloneObject'];
        $this->saves[] = $row;
        $this->stored[strtolower($row['uuid'])] = $row;
        return $data;
    }

    public function find($type = 'first', $query = array())
    {
        $uuids = $query['conditions']['StandaloneObject.uuid'];
        $rows = array();
        foreach ($this->stored as $uuid => $row) {
            if (in_array($uuid, $uuids, true)) {
                $rows[] = array('StandaloneObject' => $row);
            }
        }
        return $this->afterFind($rows);
    }

    public function deleteAll($conditions, $cascade = true, $callbacks = false)
    {
        $this->deleteAlls[] = $conditions;
        unset($this->stored[$conditions['StandaloneObject.uuid']]);
        return true;
    }

    public function deleteIfUnheld($uuid)
    {
        if ($this->spyUnheld) {
            $this->unheldAsked[] = $uuid;
            return;
        }
        parent::deleteIfUnheld($uuid);
    }
}

/** Object templates by name, uuid or id, with the conformity rules that need no database. */
class MembersOutsideTemplates
{
    public $templates = array();

    public function find($type, $query = array())
    {
        $conditions = $query['conditions'];
        foreach ($this->templates as $template) {
            $t = $template['ObjectTemplate'];
            if (isset($conditions['ObjectTemplate.name'])) {
                if ($t['name'] === $conditions['ObjectTemplate.name'] && !empty($conditions['ObjectTemplate.active'])) {
                    return array('ObjectTemplate' => array('uuid' => $t['uuid'], 'version' => $t['version']));
                }
            } elseif (isset($conditions['ObjectTemplate.uuid'])) {
                if (in_array($t['uuid'], (array)$conditions['ObjectTemplate.uuid'], true)) {
                    return $template;
                }
            } elseif (isset($conditions['ObjectTemplate.id']) && $t['id'] == $conditions['ObjectTemplate.id']) {
                return $template;
            }
        }
        return array();
    }

    public function checkTemplateConformity($template, $attributes)
    {
        $relations = array_column($attributes['Attribute'], 'object_relation');
        foreach ($template['ObjectTemplate']['requirements']['required'] ?? array() as $field) {
            if (!in_array($field, $relations, true)) {
                return 'Could not save the object as a required attribute is not set (' . $field . ')';
            }
        }
        return true;
    }
}

class MembersOutsideAttributeValues
{
    public $texts = array();

    public function fetchValues(array $ids)
    {
        return array_intersect_key($this->texts, array_flip($ids));
    }
}

class MembersOutsideAttributes
{
    public $typeDefinitions = array(
        'domain' => array('default_category' => 'Network activity', 'to_ids' => 1),
        'ip-dst' => array('default_category' => 'Network activity', 'to_ids' => 1),
    );
    public $values;
    public $wide = array();
    public $reachAsked = null;

    public function __construct()
    {
        $this->values = new MembersOutsideAttributeValues();
    }

    public function loadAttributeValue()
    {
        return $this->values;
    }

    public function visibleValueIds(array $user, array $valueIds, $limit, array $reach = null)
    {
        $this->reachAsked = $reach;
        return array_values(array_intersect($valueIds, $this->wide));
    }
}

/** The values a user can see, by SHA-256 => value id. */
class MembersOutsideAnalystData
{
    public $visible = array();

    public function visibleValuesBySha256(array $user, array $hexes)
    {
        return array_intersect_key($this->visible, array_flip($hexes));
    }
}

class MembersOutsideHeld
{
    public $held = false;

    public function hasAny($conditions)
    {
        return $this->held;
    }
}

/** captureElements() over rows in memory. */
class MembersOutsideCapture extends CollectionElement
{
    public $rows = array();
    public $deleted = array();
    public $logged = array();
    private $nextId = 1;

    public function nextIdFrom($id)
    {
        $this->nextId = $id;
    }

    public function find($type = 'first', $options = array())
    {
        $out = array();
        foreach ($this->rows as $row) {
            if ($row['collection_id'] == $options['conditions']['CollectionElement.collection_id']) {
                $out[] = array('CollectionElement' => $row);
            }
        }
        return $out;
    }

    public function create($data = array(), $filterKey = false)
    {
        $this->id = false;
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $row = $data['CollectionElement'] ?? $data;
        $id = $row['id'] ?? null;
        if (!$id) {
            $row['id'] = $id = $this->nextId++;
        }
        $this->rows[$id] = array_merge($this->rows[$id] ?? array(), $row);
        return array('CollectionElement' => $this->rows[$id]);
    }

    public function delete($id = null, $cascade = true)
    {
        $this->deleted[] = $id;
        unset($this->rows[$id]);
        return true;
    }

    public function log($message, $type = LOG_ERR, $scope = null)
    {
        $this->logged[] = $message;
        return true;
    }
}

class CollectionMembersOutsideMispTest extends TestCase
{
    const COLLECTION = 7;
    const MODULE = 'circl_passivedns';
    const EVENT = '9b000000-0000-4000-8000-0000000000e1';
    const TEMPLATE = '9b000000-0000-4000-8000-0000000000a1';

    private $registered = array();
    /** @var MembersOutsideTemplates */
    private $templates;
    /** @var MembersOutsideAttributes */
    private $attributes;
    /** @var MembersOutsideAnalystData */
    private $analystData;
    /** @var MembersOutsideStandalone */
    private $standalone;

    protected function setUp(): void
    {
        $this->templates = $this->register('ObjectTemplate', new MembersOutsideTemplates());
        $this->attributes = $this->register('MispAttribute', new MembersOutsideAttributes());
        $this->analystData = $this->register('AnalystData', new MembersOutsideAnalystData());
        $this->standalone = $this->register('StandaloneObject', new MembersOutsideStandalone());
        $this->templates->templates = array(array(
            'ObjectTemplate' => array(
                'id' => 5, 'uuid' => strtoupper(self::TEMPLATE), 'name' => 'domain-ip', 'version' => '4',
                'meta-category' => 'network', 'description' => 'A domain and its address',
                'requirements' => array('required' => array('domain')),
            ),
            'ObjectTemplateElement' => array(
                array('object_relation' => 'domain', 'type' => 'domain', 'categories' => array('External analysis', 'Network activity'), 'multiple' => true),
                array('object_relation' => 'ip', 'type' => 'ip-dst', 'categories' => array(), 'multiple' => true),
            ),
        ));
        $this->templates->templates[0]['ObjectTemplate']['uuid'] = self::TEMPLATE;
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

    private static function user()
    {
        return array('id' => 3, 'org_id' => 1, 'Role' => array('perm_site_admin' => 0), 'Organisation' => array('id' => 1));
    }

    private static function origin(array $override = array())
    {
        return $override + array('module' => self::MODULE, 'type' => 'domain', 'value' => 'evil.example', 'ran_at' => 1700000000);
    }

    private static function content($name = 'domain-ip', $value = 'evil.example')
    {
        return array(
            'kind' => 'object', 'name' => $name, 'meta_category' => 'network', 'description' => '', 'comment' => '',
            'attributes' => array(array('relation' => 'domain', 'type' => 'domain', 'value' => $value, 'category' => 'Network activity', 'comment' => '', 'to_ids' => false)),
        );
    }

    private static function answered($module = self::MODULE, $name = 'domain-ip', $value = 'evil.example')
    {
        $errors = array();
        $content = AnalystGraphDocumentTool::normaliseObjectContent(self::content($name, $value), $errors);
        return array($module, $content, AnalystGraphDocumentTool::answerUuid($content, $module));
    }

    /** A record as sync carries it. */
    private static function remoteRecord($module = self::MODULE, array $override = array())
    {
        list($module, $content, $uuid) = self::answered($module);
        return $override + array(
            'uuid' => $uuid, 'module' => $module, 'name' => $content['name'], 'template_uuid' => null, 'template_version' => null,
            'meta_category' => $content['meta_category'], 'description' => '', 'comment' => '', 'attributes' => $content['attributes'],
        );
    }

    // ------------------------------------------------------------ itemTarget

    public function testAValueKeepsItsTrimmedText()
    {
        $hex = hash('sha256', 'evil.example');

        $target = CollectionElement::itemTarget(array('type' => 'Value', 'value' => "  evil.example\n"));

        $this->assertSame('evil.example', $target['text']);
        $this->assertSame($hex, $target['address']);
        $this->assertSame('Value:' . $hex, $target['key']);
        $this->assertArrayNotHasKey('error', $target);
    }

    public function testAValueOverTheStringLimitIsATargetWithAnError()
    {
        $text = str_repeat('a', AnalystGraphDocumentTool::MAX_ANSWER_STRING_BYTES + 1);

        $target = CollectionElement::itemTarget(array('type' => 'Value', 'value' => $text));

        $this->assertSame('A value holds at most 65535 bytes.', $target['error']);
        $this->assertSame('Value:' . hash('sha256', $text), $target['key']);
        $limit = CollectionElement::itemTarget(array('type' => 'Value', 'value' => str_repeat('a', AnalystGraphDocumentTool::MAX_ANSWER_STRING_BYTES)));
        $this->assertArrayNotHasKey('error', $limit, 'the limit itself fits');
    }

    public function testAValueNamedByItsSha256AloneHasNoText()
    {
        $hex = hash('sha256', 'evil.example');

        $target = CollectionElement::itemTarget(array('type' => 'Value', 'sha256' => strtoupper($hex)));

        $this->assertSame($hex, $target['address']);
        $this->assertArrayNotHasKey('text', $target);
    }

    public function testAStandaloneObjectFromAContentIsAddressedByWhatItSays()
    {
        list($module, $content, $uuid) = self::answered();

        $target = CollectionElement::itemTarget(array('type' => 'StandaloneObject', 'module' => $module, 'content' => self::content()));

        $this->assertSame($uuid, $target['address']);
        $this->assertSame('StandaloneObject:' . $uuid, $target['key']);
        $this->assertSame('StandaloneObject', $target['element_type']);
        $this->assertSame('element_uuid', $target['column']);
        $this->assertSame(array('module' => $module, 'content' => $content), $target['build']);
        $again = CollectionElement::itemTarget(array('type' => 'StandaloneObject', 'module' => $module, 'content' => self::content()));
        $this->assertSame($target['key'], $again['key'], 'the same answer is the same member');
        $other = CollectionElement::itemTarget(array('type' => 'StandaloneObject', 'module' => 'another_module', 'content' => self::content()));
        $this->assertNotSame($target['key'], $other['key'], 'the module is part of the name');
    }

    public function testAnAnswerWithoutAModuleOrWithABadContentIsRefused()
    {
        $this->assertNull(CollectionElement::itemTarget(array('type' => 'StandaloneObject', 'content' => self::content())));
        $this->assertNull(CollectionElement::itemTarget(array('type' => 'StandaloneObject', 'module' => 'bad module!', 'content' => self::content())));

        $target = CollectionElement::itemTarget(array('type' => 'StandaloneObject', 'module' => self::MODULE, 'content' => array('kind' => 'attribute')));

        $this->assertNull($target['key']);
        $this->assertStringContainsString('content is an object', $target['error']);
    }

    public function testAStandaloneObjectFromATemplateGetsAFreshUuidEachTime()
    {
        $item = array('type' => 'StandaloneObject', 'template' => self::TEMPLATE, 'attributes' => array(array('relation' => 'domain', 'value' => 'a.example')), 'comment' => 'why');

        $first = CollectionElement::itemTarget($item);
        $second = CollectionElement::itemTarget($item);

        $this->assertNotSame($first['address'], $second['address']);
        $this->assertSame(strtolower($first['address']), $first['address']);
        $this->assertTrue(Validation::uuid($first['address']));
        $this->assertSame('StandaloneObject:' . $first['address'], $first['key']);
        $this->assertSame(array('template' => self::TEMPLATE, 'attributes' => $item['attributes'], 'comment' => 'why'), $first['build']);
    }

    public function testAnOriginIsKeptNormalisedOnValuesAndStandaloneObjects()
    {
        $origin = self::origin(array('ran_at' => '1700000000', 'node' => 'Value:ignored'));
        $expected = self::origin();

        $value = CollectionElement::itemTarget(array('type' => 'Value', 'value' => 'evil.example', 'origin' => $origin));
        list($module) = self::answered();
        $object = CollectionElement::itemTarget(array('type' => 'StandaloneObject', 'module' => $module, 'content' => self::content(), 'origin' => $origin));
        $event = CollectionElement::itemTarget(array('type' => 'Event', 'uuid' => self::EVENT, 'origin' => $origin));

        $this->assertSame($expected, $value['origin']);
        $this->assertSame($expected, $object['origin']);
        $this->assertArrayNotHasKey('origin', $event, 'only what MISP does not hold says where it came from');
    }

    public function badOrigins()
    {
        return array(
            'not an object' => array('somewhere', 'an origin is an object.'),
            'no module' => array(array('type' => 'domain', 'value' => 'x', 'ran_at' => 1), 'an origin names the module asked.'),
            'bad module' => array(self::origin(array('module' => 'a b')), 'an origin names the module asked.'),
            'no value' => array(array('module' => 'm', 'type' => 'domain', 'ran_at' => 1), 'value: must be a string.'),
            'empty type' => array(self::origin(array('type' => '')), 'type: must not be empty.'),
            'no time' => array(self::origin(array('ran_at' => 'yesterday')), 'ran_at must be a timestamp.'),
        );
    }

    /**
     * @dataProvider badOrigins
     */
    public function testABadOriginGivesTheTargetAnError($origin, $reason)
    {
        $target = CollectionElement::itemTarget(array('type' => 'Value', 'value' => 'evil.example', 'origin' => $origin));

        $this->assertSame('origin: ' . $reason, $target['error']);
        $this->assertSame('Value:' . hash('sha256', 'evil.example'), $target['key']);
    }

    // ------------------------------------------------------------ addItems

    public function testAValueNoAttributeHoldsIsAddedWithItsText()
    {
        $elements = new MembersOutsideElement();
        $hex = hash('sha256', 'new.example');

        $report = $elements->addItems(self::user(), self::COLLECTION, array(array('type' => 'Value', 'value' => ' new.example ')), 'seen once');

        $this->assertSame(array('Value:' . $hex), $report['added']);
        $this->assertSame(array(), $report['refused']);
        $this->assertSame('AttributeValue', $elements->saved[0]['element_type']);
        $this->assertSame($hex, $elements->saved[0]['element_sha256']);
        $this->assertSame('new.example', $elements->saved[0]['element_value']);
        $this->assertNull($elements->saved[0]['origin']);
        $this->assertSame(array(), $elements->readableAsked, 'a value is not looked up');
        $this->assertSame(array(self::COLLECTION), $elements->Collection->touched);
    }

    public function testATooLongValueIsRefusedWithItsReason()
    {
        $elements = new MembersOutsideElement();

        $report = $elements->addItems(self::user(), self::COLLECTION, array(
            array('type' => 'Value', 'value' => str_repeat('a', AnalystGraphDocumentTool::MAX_ANSWER_STRING_BYTES + 1)),
        ));

        $this->assertSame(array(), $report['added']);
        $this->assertSame(array(0), array_column($report['refused'], 'index'));
        $this->assertSame('A value holds at most 65535 bytes.', $report['refused'][0]['error']);
        $this->assertSame(array(), $elements->saved);
    }

    public function testAValueNamedByItsSha256AloneNoVisibleAttributeHoldsIsRefused()
    {
        $elements = new MembersOutsideElement();
        $hex = hash('sha256', 'unseen.example');

        $report = $elements->addItems(self::user(), self::COLLECTION, array(array('type' => 'Value', 'sha256' => $hex)));

        $this->assertSame(array(), $report['added']);
        $this->assertSame(
            array(array('index' => 0, 'key' => 'Value:' . $hex, 'error' => 'Send the value itself: no attribute you can see holds this SHA-256.')),
            $report['refused']
        );
        $this->assertSame(array(), $elements->saved);
    }

    public function testAValueNamedByItsSha256AloneTakesItsTextFromAVisibleAttribute()
    {
        $elements = new MembersOutsideElement();
        $hex = hash('sha256', 'seen.example');
        $this->analystData->visible = array($hex => 9);
        $this->attributes->values->texts = array(9 => 'seen.example');

        $report = $elements->addItems(self::user(), self::COLLECTION, array(array('type' => 'Value', 'sha256' => strtoupper($hex))));

        $this->assertSame(array('Value:' . $hex), $report['added']);
        $this->assertSame('seen.example', $elements->saved[0]['element_value']);
        $this->assertSame($hex, $elements->saved[0]['element_sha256']);
    }

    public function testAnAnswerBecomesARecordAndAMemberUnderItsDerivedUuid()
    {
        $elements = new MembersOutsideElement();
        list($module, $content, $uuid) = self::answered();
        $item = array('type' => 'StandaloneObject', 'module' => $module, 'content' => self::content(), 'origin' => self::origin());

        $report = $elements->addItems(self::user(), self::COLLECTION, array($item));

        $this->assertSame(array('StandaloneObject:' . $uuid), $report['added']);
        $this->assertSame('StandaloneObject', $elements->saved[0]['element_type']);
        $this->assertSame($uuid, $elements->saved[0]['element_uuid']);
        $this->assertSame(json_encode(self::origin()), $elements->saved[0]['origin']);
        $this->assertSame(array($uuid), array_keys($this->standalone->stored));
        $record = $this->standalone->stored[$uuid];
        $this->assertSame($module, $record['module']);
        $this->assertSame('domain-ip', $record['name']);
        $this->assertSame(self::TEMPLATE, $record['template_uuid'], 'its template is looked up by name');
        $this->assertSame(4, $record['template_version']);
        $this->assertSame($content['attributes'], json_decode($record['attributes'], true));
        $this->assertSame(array(), $elements->readableAsked, 'what the request brings is not looked up');
    }

    public function testTheSameAnswerTwiceIsPresent()
    {
        $elements = new MembersOutsideElement();
        list($module, , $uuid) = self::answered();
        $item = array('type' => 'StandaloneObject', 'module' => $module, 'content' => self::content());

        $elements->addItems(self::user(), self::COLLECTION, array($item));
        $report = $elements->addItems(self::user(), self::COLLECTION, array($item));

        $this->assertSame(array(), $report['added']);
        $this->assertSame(array('StandaloneObject:' . $uuid), $report['present']);
        $this->assertCount(1, $elements->saved);
        $this->assertCount(1, $this->standalone->saves);
    }

    public function testAnAnswerThatDoesNotFitIsRefused()
    {
        $elements = new MembersOutsideElement();
        $content = self::content();
        $content['attributes'] = array();

        $report = $elements->addItems(self::user(), self::COLLECTION, array(array('type' => 'StandaloneObject', 'module' => self::MODULE, 'content' => $content)));

        $this->assertSame(array(), $report['added']);
        $this->assertSame('An object needs at least one attribute.', $report['refused'][0]['error']);
        $this->assertSame(array(), $this->standalone->saves);
    }

    public function testAMemberThatCannotBeSavedLeavesNoUnheldRecord()
    {
        $elements = new MembersOutsideElement();
        $elements->failSave = true;
        list($module, , $uuid) = self::answered();

        $report = $elements->addItems(self::user(), self::COLLECTION, array(array('type' => 'StandaloneObject', 'module' => $module, 'content' => self::content())));

        $this->assertSame('Not savable.', $report['refused'][0]['error']);
        $this->assertSame(array($uuid), $this->standalone->unheldAsked);
    }

    public function testAnObjectMadeFromATemplateIsKeyedByTheUuidDrawnForIt()
    {
        $elements = new MembersOutsideElement();

        $report = $elements->addItems(self::user(), self::COLLECTION, array(array(
            'type' => 'StandaloneObject', 'template' => self::TEMPLATE,
            'attributes' => array(array('relation' => 'domain', 'value' => 'a.example')), 'comment' => 'by hand',
        )));

        $this->assertCount(1, $report['added']);
        $uuid = $elements->saved[0]['element_uuid'];
        $this->assertSame('StandaloneObject:' . $uuid, $report['added'][0]);
        $this->assertSame($uuid, $this->standalone->stored[$uuid]['uuid']);
        $this->assertNull($this->standalone->stored[$uuid]['module']);
        $this->assertSame('by hand', $this->standalone->stored[$uuid]['comment']);
    }

    public function testAnOriginIsSavedAsJson()
    {
        $elements = new MembersOutsideElement();

        $elements->addItems(self::user(), self::COLLECTION, array(
            array('type' => 'Value', 'value' => 'evil.example', 'origin' => self::origin(array('ran_at' => '1700000000'))),
        ));

        $this->assertSame('{"module":"circl_passivedns","type":"domain","value":"evil.example","ran_at":1700000000}', $elements->saved[0]['origin']);
    }

    public function testNarrowerValuesAreReported()
    {
        $elements = new MembersOutsideElement();
        $elements->Collection->distribution = 3;
        $narrow = hash('sha256', 'narrow.example');
        $wide = hash('sha256', 'wide.example');
        $unseen = hash('sha256', 'unseen.example');
        $this->analystData->visible = array($narrow => 11, $wide => 12);
        $this->attributes->wide = array(12);

        $report = $elements->addItems(self::user(), self::COLLECTION, array(
            array('type' => 'Value', 'value' => 'narrow.example'),
            array('type' => 'Value', 'value' => 'wide.example'),
            array('type' => 'Value', 'value' => 'unseen.example'),
        ));

        $this->assertSame(array('Value:' . $narrow, 'Value:' . $wide, 'Value:' . $unseen), $report['added']);
        $this->assertSame(array('Value:' . $narrow), $report['narrower']);
        $this->assertSame(array(3), $this->attributes->reachAsked, 'the levels as wide as the collection');
    }

    public function testNothingIsNarrowerInACollectionOnlyYourOrganisationSees()
    {
        $elements = new MembersOutsideElement();
        $this->analystData->visible = array(hash('sha256', 'a.example') => 1);

        $report = $elements->addItems(self::user(), self::COLLECTION, array(array('type' => 'Value', 'value' => 'a.example')));

        $this->assertSame(array(), $report['narrower']);
        $this->assertNull($this->attributes->reachAsked, 'no level is narrower, nothing is asked');
    }

    public function testNarrowerValuesNamesOnlyThoseNoWideAttributeHolds()
    {
        $elements = new MembersOutsideElement();
        $a = hash('sha256', 'a.example');
        $b = hash('sha256', 'b.example');
        $this->analystData->visible = array($a => 1, $b => 2);
        $this->attributes->wide = array(2);

        $this->assertSame(array($a), $elements->narrowerValues(self::user(), 2, array($a, $b)));
        $this->assertSame(array(array(2, 3)), array(array_values($this->attributes->reachAsked)));
        $this->assertSame(array(), $elements->narrowerValues(self::user(), 2, array()));
    }

    // ------------------------------------------------------------ heldItems

    public function testHeldItemsAnswersAValueAndAStandaloneObjectWithoutAReadabilityLookup()
    {
        $elements = new MembersOutsideElement();
        $hex = hash('sha256', 'held.example');
        list($module, , $uuid) = self::answered();
        $elements->stored[1] = array('collection_id' => self::COLLECTION, 'element_type' => 'AttributeValue', 'element_sha256' => $hex);
        $elements->stored[2] = array('collection_id' => self::COLLECTION, 'element_type' => 'StandaloneObject', 'element_uuid' => $uuid);

        $report = $elements->heldItems(self::user(), self::COLLECTION, array(
            array('type' => 'Value', 'value' => 'held.example'),
            array('type' => 'Value', 'value' => 'other.example'),
            array('type' => 'StandaloneObject', 'uuid' => strtoupper($uuid)),
            array('type' => 'StandaloneObject', 'module' => $module, 'content' => self::content()),
            array('type' => 'StandaloneObject', 'uuid' => '9b000000-0000-4000-8000-0000000000f9'),
        ));

        $this->assertSame(array('Value:' . $hex, 'StandaloneObject:' . $uuid), $report['present']);
        $this->assertSame(array('Value:' . hash('sha256', 'other.example'), 'StandaloneObject:9b000000-0000-4000-8000-0000000000f9'), $report['absent']);
        $this->assertSame(array(), $elements->readableAsked);
    }

    // ------------------------------------------------------------ captureElements

    private function capture(MembersOutsideCapture $elements, array $incoming, $fromPre30 = false)
    {
        return $elements->captureElements(array('Collection' => array('id' => self::COLLECTION, 'CollectionElement' => $incoming)), $fromPre30);
    }

    private static function valueElement($uuid, $text, $hex = null, array $extra = array())
    {
        return $extra + array(
            'uuid' => $uuid, 'element_type' => 'AttributeValue', 'element_sha256' => $hex ?? hash('sha256', $text), 'element_value' => $text,
        );
    }

    public function testAValuesTextIsKeptOnlyWhenItHashesToItsSha256()
    {
        $elements = new MembersOutsideCapture();

        $this->capture($elements, array(
            self::valueElement('e1', ' good.example ', hash('sha256', 'good.example')),
            self::valueElement('e2', 'forged.example', hash('sha256', 'real.example')),
            self::valueElement('e3', str_repeat('a', AnalystGraphDocumentTool::MAX_ANSWER_STRING_BYTES + 1)),
            array('uuid' => 'e4', 'element_type' => 'AttributeValue', 'element_sha256' => hash('sha256', 'bare.example')),
        ));

        $byUuid = array_column($elements->rows, 'element_value', 'uuid');
        $this->assertSame('good.example', $byUuid['e1']);
        $this->assertNull($byUuid['e2']);
        $this->assertNull($byUuid['e3']);
        $this->assertNull($byUuid['e4']);
    }

    public function testAStoredValueWithoutTextTakesTheTextItsPartnerSends()
    {
        $elements = new MembersOutsideCapture();
        $hex = hash('sha256', 'good.example');
        $elements->rows[1] = array('id' => 1, 'uuid' => 'e1', 'collection_id' => self::COLLECTION, 'element_type' => 'AttributeValue', 'element_sha256' => $hex, 'element_uuid' => null, 'element_value' => null);

        $this->capture($elements, array(self::valueElement('e1', 'good.example')));

        $this->assertSame('good.example', $elements->rows[1]['element_value']);
    }

    public function testAnOriginIsNormalisedOrDropped()
    {
        $elements = new MembersOutsideCapture();

        $this->capture($elements, array(
            self::valueElement('e1', 'a.example', null, array('origin' => self::origin(array('ran_at' => '1700000000', 'node' => 'x')))),
            self::valueElement('e2', 'b.example', null, array('origin' => array('module' => 'a b'))),
            self::valueElement('e3', 'c.example', null, array('origin' => 'nonsense')),
            self::valueElement('e4', 'd.example'),
        ));

        $byUuid = array_column($elements->rows, 'origin', 'uuid');
        $this->assertSame('{"module":"circl_passivedns","type":"domain","value":"evil.example","ran_at":1700000000}', $byUuid['e1']);
        $this->assertNull($byUuid['e2']);
        $this->assertNull($byUuid['e3']);
        $this->assertNull($byUuid['e4']);
    }

    public function testAStandaloneObjectElementWithItsRecordIsCaptured()
    {
        $elements = new MembersOutsideCapture();
        $record = self::remoteRecord();

        $this->capture($elements, array(array(
            'uuid' => 'e1', 'element_type' => 'StandaloneObject', 'element_uuid' => strtoupper($record['uuid']), 'StandaloneObject' => $record,
        )));

        $this->assertCount(1, $elements->rows);
        $this->assertSame('StandaloneObject', $elements->rows[1]['element_type']);
        $this->assertSame(array(), $elements->logged);
        $this->assertSame(array($record['uuid']), array_keys($this->standalone->stored));
        $this->assertSame('domain-ip', $this->standalone->stored[$record['uuid']]['name']);
    }

    public function testAStandaloneObjectElementWithAForgedUuidIsSkippedAndLogged()
    {
        $elements = new MembersOutsideCapture();
        $forged = '9b000000-0000-4000-8000-0000000000ff';
        $record = self::remoteRecord(self::MODULE, array('uuid' => $forged));

        $this->capture($elements, array(array(
            'uuid' => 'e1', 'element_type' => 'StandaloneObject', 'element_uuid' => $forged, 'StandaloneObject' => $record,
        )));

        $this->assertSame(array(), $elements->rows);
        $this->assertSame(array(), $this->standalone->stored);
        $this->assertCount(1, $elements->logged);
        $this->assertStringContainsString('Could not capture standalone object ' . $forged, $elements->logged[0]);
        $this->assertStringContainsString('derived from its content', $elements->logged[0]);
    }

    public function testAStandaloneObjectElementNamingAnotherRecordIsSkippedAndLogged()
    {
        $elements = new MembersOutsideCapture();
        $record = self::remoteRecord();
        $other = '9b000000-0000-4000-8000-0000000000fe';

        $this->capture($elements, array(
            array('uuid' => 'e1', 'element_type' => 'StandaloneObject', 'element_uuid' => $other, 'StandaloneObject' => $record),
            array('uuid' => 'e2', 'element_type' => 'StandaloneObject', 'element_uuid' => $record['uuid']),
        ));

        $this->assertSame(array(), $elements->rows);
        $this->assertCount(2, $elements->logged);
        $this->assertStringContainsString('The element names another record.', $elements->logged[0]);
        $this->assertStringContainsString('needs a uuid', $elements->logged[1], 'an element without its record has nothing to store');
    }

    public function testAMispOlderThan30NeitherSendsNorLosesStandaloneObjectsAndValues()
    {
        $elements = new MembersOutsideCapture();
        $record = self::remoteRecord();
        $hex = hash('sha256', 'held.example');
        $event = array('collection_id' => self::COLLECTION, 'element_uuid' => self::EVENT, 'element_sha256' => null, 'element_value' => null);
        $elements->rows[1] = array('id' => 1, 'uuid' => 's1', 'element_type' => 'StandaloneObject') + array('element_uuid' => $record['uuid'], 'element_sha256' => null, 'element_value' => null, 'collection_id' => self::COLLECTION);
        $elements->rows[2] = array('id' => 2, 'uuid' => 'v1', 'element_type' => 'AttributeValue', 'element_sha256' => $hex, 'element_uuid' => null, 'element_value' => 'held.example', 'collection_id' => self::COLLECTION);
        $elements->rows[3] = array('id' => 3, 'uuid' => 'ev1', 'element_type' => 'Event') + $event;
        $elements->nextIdFrom(10);

        $this->capture($elements, array(
            array('uuid' => 'n1', 'element_type' => 'StandaloneObject', 'element_uuid' => '9b000000-0000-4000-8000-0000000000fd', 'StandaloneObject' => self::remoteRecord('another_module')),
            self::valueElement('n2', 'new.example'),
        ), true);

        $this->assertSame(array(3), $elements->deleted, 'only what a 2.x MISP can hold is culled');
        $this->assertSame(array(1, 2), array_keys($elements->rows));
        $this->assertSame(array(), $this->standalone->saves, 'no record was taken');
    }

    // ------------------------------------------------------------ StandaloneObject

    public function testAnAnswerBecomesARecordNamedByItsContentWithItsTemplateLookedUpByName()
    {
        list($module, $content, $uuid) = self::answered();
        $errors = array();

        $record = $this->standalone->fromAnswer($module, self::content(), $errors);

        $this->assertSame(array(), $errors);
        $this->assertSame($uuid, $record['uuid']);
        $this->assertSame($module, $record['module']);
        $this->assertSame('domain-ip', $record['name']);
        $this->assertSame('network', $record['meta_category']);
        $this->assertSame(self::TEMPLATE, $record['template_uuid']);
        $this->assertSame(4, $record['template_version']);
        $this->assertSame($content['attributes'], $record['attributes']);
    }

    public function testTheSameAnswerIsOneRecordWhateverTheOrderOfItsAttributes()
    {
        $errors = array();
        $content = self::content();
        $content['attributes'][] = array('relation' => 'ip', 'type' => 'ip-dst', 'value' => '203.0.113.7');
        $reversed = $content;
        $reversed['attributes'] = array_reverse($content['attributes']);

        $a = $this->standalone->fromAnswer(self::MODULE, $content, $errors);
        $b = $this->standalone->fromAnswer(self::MODULE, $reversed, $errors);
        $c = $this->standalone->fromAnswer('another_module', $content, $errors);

        $this->assertSame($a['uuid'], $b['uuid']);
        $this->assertNotSame($a['uuid'], $c['uuid']);
    }

    public function testAnAnswerNamingNoTemplateHasNone()
    {
        $errors = array();

        $record = $this->standalone->fromAnswer(self::MODULE, self::content('no-such-template'), $errors);

        $this->assertNull($record['template_uuid']);
        $this->assertNull($record['template_version']);
    }

    public function testAnAnswerThatIsNotAnObjectWithAModuleIsRefused()
    {
        $errors = array();
        $this->assertNull($this->standalone->fromAnswer('bad module', self::content(), $errors));
        $this->assertSame(array('an object from a module names the module.'), $errors);

        $errors = array();
        $this->assertNull($this->standalone->fromAnswer(self::MODULE, array('kind' => 'element', 'types' => array('x'), 'value' => 'y'), $errors));
        $this->assertStringContainsString('content is an object', $errors[0]);

        $errors = array();
        $this->assertNull($this->standalone->fromAnswer(self::MODULE, self::content(str_repeat('n', 256)), $errors));
        $this->assertSame(array('An object name and meta-category hold at most 255 characters.'), $errors);
    }

    public function testATemplateMakesAnObjectWhoseRelationsGiveItsTypes()
    {
        $errors = array();

        $record = $this->standalone->fromTemplate(self::TEMPLATE, array(
            array('relation' => 'domain', 'value' => ' a.example ', 'comment' => 'c', 'category' => 'External analysis'),
            array('object_relation' => 'ip', 'value' => '203.0.113.7', 'to_ids' => false),
            array('relation' => 'domain', 'value' => 'b.example', 'category' => 'Not a category of it'),
        ), 'by hand', $errors);

        $this->assertSame(array(), $errors);
        $this->assertSame(array('domain', 'ip-dst', 'domain'), array_column($record['attributes'], 'type'));
        $this->assertSame(array('domain', 'ip', 'domain'), array_column($record['attributes'], 'relation'));
        $this->assertSame('a.example', $record['attributes'][0]['value']);
        $this->assertSame(array('External analysis', 'Network activity', 'External analysis'), array_column($record['attributes'], 'category'));
        $this->assertSame(array(true, false, true), array_column($record['attributes'], 'to_ids'));
        $this->assertSame('by hand', $record['comment']);
        $this->assertSame('network', $record['meta_category']);
        $this->assertSame(self::TEMPLATE, $record['template_uuid']);
        $this->assertSame(4, $record['template_version']);
        $this->assertNull($record['module']);
        $this->assertTrue(Validation::uuid($record['uuid']));
    }

    public function testATemplateIsFoundByItsIdToo()
    {
        $errors = array();

        $record = $this->standalone->fromTemplate('5', array(array('relation' => 'domain', 'value' => 'a.example')), '', $errors);

        $this->assertSame('domain-ip', $record['name']);
        $second = $this->standalone->fromTemplate('5', array(array('relation' => 'domain', 'value' => 'a.example')), '', $errors);
        $this->assertNotSame($record['uuid'], $second['uuid'], 'made by hand, so each is its own');
    }

    public function badTemplateInputs()
    {
        return array(
            'unknown template' => array('9b000000-0000-4000-8000-0000000000ee', array(array('relation' => 'domain', 'value' => 'a')), 'No such object template.'),
            'not a reference' => array('nope', array(array('relation' => 'domain', 'value' => 'a')), 'No such object template.'),
            'no attributes' => array(self::TEMPLATE, array(), 'An object needs a list of attributes.'),
            'not a list' => array(self::TEMPLATE, array('domain' => 'a'), 'An object needs a list of attributes.'),
            'unknown relation' => array(self::TEMPLATE, array(array('relation' => 'domain', 'value' => 'a'), array('relation' => 'nope', 'value' => 'b')), 'attributes[1]: not a relation of the template “domain-ip”.'),
            'no relation' => array(self::TEMPLATE, array(array('value' => 'a')), 'attributes[0]: not a relation of the template “domain-ip”.'),
            'empty value' => array(self::TEMPLATE, array(array('relation' => 'domain', 'value' => '  ')), 'attributes[0]: domain needs a value.'),
            'missing required relation' => array(self::TEMPLATE, array(array('relation' => 'ip', 'value' => '203.0.113.7')), 'Could not save the object as a required attribute is not set (domain)'),
        );
    }

    /**
     * @dataProvider badTemplateInputs
     */
    public function testATemplateObjectThatDoesNotFitItsTemplateIsRefused($template, $attributes, $reason)
    {
        $errors = array();

        $this->assertNull($this->standalone->fromTemplate($template, $attributes, '', $errors));
        $this->assertSame(array($reason), $errors);
    }

    public function testARemoteRecordFromAModuleKeepsItsDerivedUuid()
    {
        $errors = array();
        $sent = self::remoteRecord(self::MODULE, array('template_uuid' => strtoupper(self::TEMPLATE), 'template_version' => '4'));
        $sent['uuid'] = strtoupper($sent['uuid']);

        $record = $this->standalone->fromRemote($sent, $errors);

        $this->assertSame(array(), $errors);
        $this->assertSame(strtolower($sent['uuid']), $record['uuid']);
        $this->assertSame(self::MODULE, $record['module']);
        $this->assertSame(self::TEMPLATE, $record['template_uuid']);
        $this->assertSame(4, $record['template_version']);
    }

    public function testARemoteRecordFromAModuleWithAnotherUuidIsRefused()
    {
        $errors = array();

        $record = $this->standalone->fromRemote(self::remoteRecord(self::MODULE, array('uuid' => '9b000000-0000-4000-8000-0000000000ff')), $errors);

        $this->assertNull($record);
        $this->assertSame(array('The uuid of an object from a module is derived from its content.'), $errors);
    }

    public function testARemoteRecordMadeByHandMayHaveAnyUuid()
    {
        $errors = array();
        $sent = self::remoteRecord(self::MODULE, array('uuid' => '9b000000-0000-4000-8000-0000000000aa', 'module' => null));

        $record = $this->standalone->fromRemote($sent, $errors);

        $this->assertSame('9b000000-0000-4000-8000-0000000000aa', $record['uuid']);
        $this->assertNull($record['module']);
    }

    public function badRemoteRecords()
    {
        $good = self::remoteRecord();
        return array(
            'not an array' => array('x', 'A standalone object needs a uuid.'),
            'no uuid' => array(array('uuid' => null) + $good, 'A standalone object needs a uuid.'),
            'bad uuid' => array(array('uuid' => 'nope') + $good, 'A standalone object needs a uuid.'),
            'bad module' => array(array('module' => 'a b') + $good, 'an object from a module names the module.'),
            'no attributes' => array(array('attributes' => array()) + $good, 'An object needs at least one attribute.'),
        );
    }

    /**
     * @dataProvider badRemoteRecords
     */
    public function testARemoteRecordThatDoesNotFitIsRefused($sent, $reason)
    {
        $errors = array();

        $this->assertNull($this->standalone->fromRemote($sent, $errors));
        $this->assertSame(array($reason), $errors);
    }

    public function testEnsureKeepsAStoredRecordAndStoresANewOne()
    {
        $errors = array();
        $record = $this->standalone->fromAnswer(self::MODULE, self::content(), $errors);

        $this->assertTrue($this->standalone->ensure($record));
        $this->assertCount(1, $this->standalone->saves);
        $saved = $this->standalone->saves[0];
        $this->assertSame($record['attributes'], json_decode($saved['attributes'], true));
        $this->assertRegExp('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $saved['created']);

        $changed = array('name' => 'renamed') + $record;
        $this->assertTrue($this->standalone->ensure($changed));
        $this->assertCount(1, $this->standalone->saves, 'a stored record is kept as it is');
        $this->assertSame('domain-ip', $this->standalone->stored[$record['uuid']]['name']);
    }

    public function testEnsureSaysWhenARecordCannotBeStored()
    {
        $errors = array();
        $record = $this->standalone->fromAnswer(self::MODULE, self::content(), $errors);
        $this->standalone->failSave = true;

        $this->assertFalse($this->standalone->ensure($record));
    }

    public function testRecordsComeBackAsTheApiShowsThemByLowercaseUuid()
    {
        $errors = array();
        $record = $this->standalone->fromAnswer(self::MODULE, self::content(), $errors);
        $this->standalone->ensure($record);

        $found = $this->standalone->records(array(strtoupper($record['uuid']), 5, '9b000000-0000-4000-8000-0000000000ee'));

        $this->assertSame(array($record['uuid']), array_keys($found));
        $this->assertSame($record['attributes'], $found[$record['uuid']]['attributes']);
        $this->assertSame(self::MODULE, $found[$record['uuid']]['module']);
        $this->assertSame(array(), $this->standalone->records(array()));
    }

    public function testShapeFillsWhatAStoredRowLeavesOut()
    {
        $shape = StandaloneObject::shape(array('uuid' => 'ABC', 'name' => 'n', 'template_version' => '2', 'attributes' => 'not decoded'));

        $this->assertSame(array(
            'uuid' => 'abc', 'module' => null, 'name' => 'n', 'template_uuid' => null, 'template_version' => 2, 'meta_category' => '',
            'description' => '', 'comment' => '', 'attributes' => array(), 'created' => null,
        ), $shape);
    }

    public function testContentIsWhatAnAnswerOfKindObjectHolds()
    {
        $errors = array();
        $record = $this->standalone->fromAnswer(self::MODULE, self::content(), $errors);

        $this->assertSame(self::content(), StandaloneObject::content($record));
    }

    public function testARecordIsDeletedOnlyOnceNoCollectionHoldsIt()
    {
        $this->standalone->spyUnheld = false;
        $held = $this->register('CollectionElement', new MembersOutsideHeld());
        $held->held = true;

        $this->standalone->deleteIfUnheld('9B000000-0000-4000-8000-0000000000AA');
        $this->assertSame(array(), $this->standalone->deleteAlls);

        $held->held = false;
        $this->standalone->deleteIfUnheld('9B000000-0000-4000-8000-0000000000AA');
        $this->assertSame(array(array('StandaloneObject.uuid' => '9b000000-0000-4000-8000-0000000000aa')), $this->standalone->deleteAlls);
    }
}
