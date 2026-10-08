<?php
/**
 * Attribute finds and the restSearch filter builders match the value columns
 * on the dictionary ids: conditions in a find (callbacks on or 'before'),
 * the attribute-scope and event-scope value filters (a short eventid list
 * bounding the latter), the event-scope wildcard, and the finds that named
 * the value field in their conditions.
 * The tests hide the value virtual field and the text columns from every
 * attribute model and point the stored text away from the dictionary, so a
 * condition left on either finds nothing or fails.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueFilterDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueFilterDbTest extends TestCase
{
    const OBJECT_ID = 2147483000;

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var Event */
    private $event;

    /** @var DboSource */
    private $db;

    /** @var string */
    private $token;

    /** @var array */
    private $user;

    /** @var int[] */
    private $events;

    /** @var array name => attribute id */
    private $ids = [];

    /** @var bool */
    private $cachedMethods;

    /** @var bool */
    private $fullDebug;

    /** @var mixed */
    private $currentUserId;

    /** @var array spl_object_id => the virtual fields it had */
    private $virtualFields = [];

    protected function setUp(): void
    {
        if (!getenv('ATTRIBUTE_VALUE_DB_TESTS')) {
            $this->markTestSkipped('Needs the database, see the file header.');
        }
        if (!self::$booted) {
            if (class_exists('App', false)) {
                $this->markTestSkipped('Needs its own process: run this file alone.');
            }
            require_once __DIR__ . '/OracleBootstrap.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('AttributeValue', 'Model');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->event = $this->attribute->Event;
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        $this->db->begin();
        $this->token = 'avflt' . bin2hex(random_bytes(4));
        $this->user = ClassRegistry::init('User')->getAuthUser(1);
        // The analyst data behaviour reads the request's user from here
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', $this->user['id']);
        $this->events = array_map('intval', $this->event->find('column', [
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id'],
            'limit' => 2,
        ]));
        $this->createFixture();
        $this->hideTextColumnsAndValueField();
        $this->db->fullDebug = true;
    }

    protected function tearDown(): void
    {
        if (!$this->db) {
            return;
        }
        AttributeValue::$strictConditions = true;
        Configure::write('CurrentUserId', $this->currentUserId);
        $this->db->cacheMethods = $this->cachedMethods;
        $this->db->fullDebug = $this->fullDebug;
        foreach ($this->attributeModels() as $key => $model) {
            $model->schema(true);
            if (isset($this->virtualFields[$key])) {
                $model->virtualFields = $this->virtualFields[$key];
            }
        }
        $this->db->rollback();
    }

    private function exec($sql)
    {
        $statement = $this->db->rawQuery($sql);
        if (!($statement instanceof PDOStatement)) {
            return [];
        }
        $rows = $statement->columnCount() > 0 ? $statement->fetchAll(PDO::FETCH_ASSOC) : [];
        $statement->closeCursor();
        return $rows;
    }

    private function createFixture()
    {
        $t = $this->token;
        list($first, $second) = $this->events;
        $this->ids['domain'] = $this->create($first, 'domain', "$t.example.org");
        $this->ids['composite'] = $this->create($first, 'domain|ip', "{$t}a.example|192.0.2.7");
        $this->ids['tick'] = $this->create($first, 'text', "{$t}`tick");
        $this->ids['object'] = $this->create($first, 'domain', "{$t}obj.example.org");
        $this->ids['other'] = $this->create($second, 'domain', "$t-two.example.org");
        $this->ids['regkey'] = $this->create($second, 'regkey|value', "HKLM\\Software\\$t|{$t}rv-data");

        $this->exec(sprintf(
            "UPDATE attributes SET object_id = %d, object_relation = 'domain' WHERE id = %d",
            self::OBJECT_ID,
            $this->ids['object']
        ));
        $this->exec(sprintf(
            "UPDATE attributes SET value1 = 'column-%1\$s', value2 = IF(value2 = '', '', 'column-%1\$s') WHERE id IN (%2\$s)",
            $t,
            implode(', ', $this->ids)
        ));
    }

    private function create($eventId, $type, $value)
    {
        $this->attribute->create();
        $saved = $this->attribute->save(['Attribute' => [
            'event_id' => $eventId,
            'category' => $type === 'regkey|value' ? 'Persistence mechanism' : ($type === 'text' ? 'Other' : 'Network activity'),
            'type' => $type,
            'value' => $value,
            'distribution' => 5,
            'to_ids' => 0,
            'disable_correlation' => 1,
        ]]);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        return (int)$this->attribute->id;
    }

    private function attributeModels()
    {
        // A later test can leave the registry holding another instance
        $models = [spl_object_id($this->attribute) => $this->attribute];
        foreach (ClassRegistry::keys() as $key) {
            $object = ClassRegistry::getObject($key);
            if ($object instanceof MispAttribute) {
                $models[spl_object_id($object)] = $object;
            }
        }
        return $models;
    }

    private function hideTextColumnsAndValueField()
    {
        $this->attribute->Event->Object->Attribute;
        $property = new ReflectionProperty('Model', '_schema');
        foreach ($this->attributeModels() as $key => $model) {
            $schema = $model->schema();
            unset($schema['value1'], $schema['value2']);
            $property->setValue($model, $schema);
            $this->virtualFields[$key] = $model->virtualFields;
            unset($model->virtualFields['value']);
        }
        $this->db->cacheMethods = false;
    }

    private function ids(...$names)
    {
        $ids = [];
        foreach ($names as $name) {
            $ids[] = $this->ids[$name];
        }
        sort($ids);
        return $ids;
    }

    private function select(array $conditions, $callbacks = true)
    {
        $ids = array_map('intval', $this->attribute->find('column', [
            'conditions' => ['AND' => [['Attribute.id' => array_values($this->ids)], $conditions]],
            'fields' => ['Attribute.id'],
            'callbacks' => $callbacks,
        ]));
        sort($ids);
        return $ids;
    }

    private function eventIds(array $params)
    {
        $ids = array_map('intval', $this->event->filterEventIds($this->user, $params));
        sort($ids);
        return $ids;
    }

    private function statements($pattern)
    {
        $out = [];
        foreach ($this->db->getLog(false, false)['log'] as $entry) {
            if (preg_match($pattern, $entry['query'])) {
                $out[] = $entry['query'];
            }
        }
        return $out;
    }

    private function clearLog()
    {
        $this->db->getLog(false, true);
    }

    public function testAFindMatchesTheValueColumnsOnTheIds()
    {
        $t = $this->token;

        $this->assertSame($this->ids('domain'), $this->select(['Attribute.value1' => strtoupper("$t.example.org")]));
        $this->assertSame($this->ids('composite'), $this->select(['Attribute.value' => "{$t}a.example|192.0.2.7"]));
        $this->assertSame($this->ids('regkey'), $this->select(['Attribute.value2 LIKE' => "{$t}rv%"]));
        $this->assertSame(
            $this->ids('composite', 'tick', 'object', 'other', 'regkey'),
            $this->select(['Attribute.value1 !=' => "$t.example.org"])
        );
        $this->assertSame($this->ids('domain'), $this->select(['Attribute.value1' => "$t.example.org"], 'before'));
        // Without callbacks there is no beforeFind, and the stored text no longer matches
        $this->assertSame([], $this->select(['Attribute.value1' => "$t.example.org"], false));
    }

    public function testTheAttributeScopeValueFilterMatchesOnTheIds()
    {
        $t = $this->token;
        $cases = [
            [strtoupper("$t.example.org"), ['domain']],
            [["$t.example.org", "$t-two.example.org"], ['domain', 'other']],
            ["%{$t}rv%", ['regkey']],
            ["!$t.example.org", ['composite', 'tick', 'object', 'other', 'regkey']],
            [['OR' => ["%$t%"], 'NOT' => ["%.example.org"]], ['composite', 'tick', 'regkey']],
            ["192.0.2.7", ['composite']],
        ];
        foreach ($cases as $case) {
            list($value, $expected) = $case;
            $params = ['value' => $value];
            $conditions = $this->event->set_filter_value($params, [], ['filter' => 'value', 'context' => 'Attribute']);
            $this->assertSame($this->ids(...$expected), $this->select($conditions), json_encode($value));
        }
    }

    public function testTheEventScopeValueFilterMatchesOnTheIds()
    {
        $t = $this->token;
        list($first, $second) = $this->events;
        $cases = [
            [strtoupper("$t.example.org"), [$first]],
            [["$t.example.org", "$t-two.example.org"], [$first, $second]],
            ["!$t.example.org", [$second]],
            ["{$t}`tick", [$first]],
            ["%{$t}rv%", [$second]],
            [['AND' => ["$t.example.org", "{$t}`tick"]], [$first]],
            [['AND' => ["$t.example.org", "$t-two.example.org"]], []],
        ];
        foreach ($cases as $case) {
            list($value, $expected) = $case;
            $this->clearLog();
            $this->assertSame($expected, $this->eventIds(['eventid' => $this->events, 'value' => $value]), json_encode($value));
            $events = $this->statements('/`events` AS `Event`/');
            $this->assertNotEmpty($events);
            foreach ($events as $sql) {
                $this->assertStringContainsString('value1_id', $sql);
                $this->assertNotRegExp('/value[12](?!_id)|USE INDEX/', $sql);
            }
        }
    }

    public function testAShortEventidListBoundsTheValueSubquery()
    {
        $t = $this->token;
        list($first, $second) = $this->events;
        $uuid = $this->event->find('first', [
            'recursive' => -1,
            'conditions' => ['Event.id' => $first],
            'fields' => ['Event.uuid'],
        ])['Event']['uuid'];
        $cases = [
            [['eventid' => $this->events], false],
            [[], true],
            [['eventid' => [$first, $second, $uuid]], true],
        ];
        foreach ($cases as $case) {
            list($params, $resolved) = $case;
            $this->clearLog();
            $this->assertSame([$second], $this->eventIds($params + ['value' => "%{$t}rv%"]), json_encode($params));
            $this->assertCount($resolved ? 1 : 0, $this->statements('/`attribute_values` WHERE `value` LIKE .* LIMIT \d+$/'), json_encode($params));
            $this->assertCount($resolved ? 0 : 1, $this->statements('/`events` AS `Event`.*attribute_values/s'), json_encode($params));
        }
    }

    public function testTheEventScopeWildcardResolvesThePatternOnce()
    {
        $t = $this->token;
        list($first, $second) = $this->events;

        $this->assertSame([$second], $this->eventIds(['wildcard' => "%{$t}rv%"]));

        $this->clearLog();
        $this->assertSame([$first, $second], $this->eventIds(['wildcard' => "%$t%"]));
        $this->assertCount(1, $this->statements('/FROM `attribute_values` WHERE `value` LIKE/'));
    }

    public function testTheValueFieldConditionsMatchOnTheIds()
    {
        $t = $this->token;
        list($first) = $this->events;

        $result = $this->event->applyModuleTagChanges($this->user, $first, 'domain', strtoupper("$t.example.org"), []);
        $this->assertTrue($result['matched']);

        $method = new ReflectionMethod('Event', '__findCurrentObjectId');
        $method->setAccessible(true);
        $this->assertEquals(self::OBJECT_ID, $method->invoke($this->event, $first, [
            ['object_relation' => 'domain', 'value' => "{$t}OBJ.example.org", 'type' => 'domain'],
        ]));

        $method = new ReflectionMethod('Event', '__findOriginalUUID');
        $method->setAccessible(true);
        $found = $method->invoke($this->event, 'domain|ip', "{$t}a.example|192.0.2.7", $first);
        $this->assertSame((string)$this->ids['composite'], $found['id']);

        $page = $this->event->fetchPaginatedAttributes($this->user, $first, ['searchFor' => "{$t}a.example|192"]);
        $this->assertSame([(string)$this->ids['composite']], array_column($page['Attribute'], 'id'));
        $this->assertSame("{$t}a.example|192.0.2.7", $page['Attribute'][0]['value']);

        // The command line attribute list, outside any event
        $attributes = $this->attribute->fetchAttributes($this->user, [
            'conditions' => ['Attribute.value LIKE' => "%{$t}_tick"],
            'flatten' => 1,
        ]);
        $this->assertSame([(string)$this->ids['tick']], array_column(array_column($attributes, 'Attribute'), 'id'));
    }

    public function testStrictConditionsDecideAFormThatCannotBeMoved()
    {
        $condition = ['LOWER(Attribute.value1) LIKE' => "column-{$this->token}"];

        AttributeValue::$strictConditions = false;
        // Left on the text columns, which still hold the diverged text
        $this->assertSame($this->ids(...array_keys($this->ids)), $this->select($condition));

        AttributeValue::$strictConditions = true;
        $this->expectException('ValueConditionException');
        $this->select($condition);
    }
}
