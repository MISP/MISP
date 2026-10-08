<?php
/**
 * Attribute finds and the restSearch filter builders match the value columns
 * on the dictionary ids: conditions in a find (callbacks on or 'before'),
 * the attribute-, event- and object-scope value filters (a short eventid list
 * bounding them), the event- and object-scope wildcards, the finds that named
 * the value field in their conditions or wrapped a value column in a
 * function, a proposal search checking its pattern per row, and the attribute
 * fetch, which resolves its conditions once and reads the values of its
 * correlations at once.
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
            App::uses('CakeText', 'Utility');
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
            'category' => $this->attribute->typeDefinitions[$type]['default_category'],
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

    /**
     * Attributes for one test only, with their stored text diverged too.
     *
     * @param array $specs name => [event id, type, value]
     * @return void
     */
    private function addFixtures(array $specs)
    {
        foreach ($this->attributeModels() as $model) {
            $model->schema(true);
        }
        $added = [];
        foreach ($specs as $name => $spec) {
            $added[] = $this->ids[$name] = $this->create(...$spec);
        }
        $this->exec(sprintf(
            "UPDATE attributes SET value1 = 'column-%1\$s', value2 = IF(value2 = '', '', 'column-%1\$s') WHERE id IN (%2\$s)",
            $this->token,
            implode(', ', $added)
        ));
        $this->hideTextColumnsAndValueField();
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

    /**
     * @return int Patterns resolved ahead: dictionary scans of their own,
     *   not a dictionary subquery inside the find.
     */
    private function resolvedPatterns()
    {
        return count($this->statements('/^(?:\/\*.*?\*\/ )?SELECT `id` FROM `attribute_values` WHERE `value` LIKE/'));
    }

    /**
     * Objects 0 and 2 in the first event, 1 in the second; object 2 has no
     * attributes.
     * @return int[]
     */
    private function createObjects()
    {
        list($first, $second) = $this->events;
        $objects = [self::OBJECT_ID => $first, self::OBJECT_ID + 1 => $second, self::OBJECT_ID + 2 => $first];
        foreach ($objects as $id => $eventId) {
            $this->exec(sprintf(
                "INSERT INTO objects (id, name, `meta-category`, template_uuid, template_version, event_id, uuid, timestamp, distribution, comment, deleted) VALUES (%d, 'domain-ip', 'network', '%s', 1, %d, '%s', %d, 5, '', 0)",
                $id,
                CakeText::uuid(),
                $eventId,
                CakeText::uuid(),
                time()
            ));
        }
        $this->exec(sprintf('UPDATE attributes SET object_id = %d WHERE id = %d', self::OBJECT_ID + 1, $this->ids['regkey']));
        return array_keys($objects);
    }

    private function objectIds(array $params, array $objects)
    {
        $object = $this->attribute->Event->Object;
        $conditions = $object->buildFilterConditions($params);
        $found = $object->fetchObjects($this->user, [
            'conditions' => ['AND' => [['Object.id' => $objects], $conditions]],
            'metadata' => 1,
        ]);
        $ids = array_map('intval', array_column(array_column($found, 'Object'), 'id'));
        sort($ids);
        return $ids;
    }

    private function fetchedIds(array $params)
    {
        // No id list here, it would bound the find by itself
        $conditions = $this->attribute->buildFilterConditions($this->user, $params, true);
        $found = $this->attribute->fetchAttributes($this->user, [
            'conditions' => $conditions,
            'flatten' => 1,
        ]);
        $ids = array_map('intval', array_column(array_column($found, 'Attribute'), 'id'));
        sort($ids);
        return $ids;
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

    public function testTheObjectScopeValueFilterMatchesOnTheIds()
    {
        $t = $this->token;
        list($first, $second) = $this->events;
        $objects = $this->createObjects();
        list($a, $b, $empty) = $objects;
        $cases = [
            [['value' => "{$t}OBJ.example.org"], [$a]],
            [['value' => "%{$t}rv%"], [$b]],
            [['value' => ["{$t}obj.example.org", "{$t}rv-data"]], [$a, $b]],
            [['value' => ['AND' => ["{$t}obj.example.org", "{$t}rv-data"]]], []],
            // An object without attributes matches no value, also a negated one
            [['value' => "!{$t}obj.example.org", 'eventid' => $this->events], [$b]],
            [['value' => "%{$t}%", 'type' => 'regkey|value'], [$b]],
            [['type' => 'domain', 'value' => "%{$t}%", 'eventid' => [$first]], [$a]],
        ];
        foreach ($cases as $case) {
            list($params, $expected) = $case;
            $this->clearLog();
            $this->assertSame($expected, $this->objectIds($params, $objects), json_encode($params));
            $statements = $this->statements('/`objects`(?: AS)? `Object`/');
            $this->assertCount(1, $statements);
            $this->assertNotRegExp('/value[12](?!_id)/', $statements[0]);
            // Not repeated inside the subquery of another attribute filter
            $this->assertNotRegExp('/SELECT `Attribute`.`object_id` FROM(?:(?!GROUP BY).)*value1_id/s', $statements[0]);
        }
    }

    public function testAShortEventidListBoundsTheObjectValueSubquery()
    {
        $t = $this->token;
        list($first, $second) = $this->events;
        $objects = $this->createObjects();
        $uuid = $this->event->field('uuid', ['Event.id' => $first]);
        $cases = [
            [['eventid' => $this->events], false],
            [[], true],
            [['eventid' => [$first, $second, $uuid]], true],
        ];
        foreach ($cases as $case) {
            list($params, $resolved) = $case;
            $this->clearLog();
            $this->assertSame([$objects[1]], $this->objectIds($params + ['value' => "%{$t}rv%"], $objects), json_encode($params));
            $this->assertSame($resolved ? 1 : 0, $this->resolvedPatterns(), json_encode($params));
            $this->assertCount($resolved ? 0 : 1, $this->statements('/`objects`(?: AS)? `Object`.*attribute_values/s'), json_encode($params));
        }
    }

    public function testTheObjectScopeWildcardMatchesThroughTheAttributes()
    {
        $t = $this->token;
        $objects = $this->createObjects();
        list($a, $b) = $objects;

        $this->assertSame([$b], $this->objectIds(['wildcard' => "%{$t}rv%"], $objects));
        $this->clearLog();
        $this->assertSame([$a, $b], $this->objectIds(['wildcard' => "%$t%"], $objects));
        $this->assertSame(1, $this->resolvedPatterns());

        // The event info matches objects without attributes too
        $this->exec(sprintf("UPDATE events SET info = '%s-info' WHERE id = %d", $t, $this->events[0]));
        $this->assertSame([$a, $objects[2]], $this->objectIds(['wildcard' => "$t-info"], $objects));
    }

    public function testAShortEventidListBoundsTheAttributeScopeValuePattern()
    {
        $t = $this->token;
        list($first, $second) = $this->events;
        $uuid = $this->event->field('uuid', ['Event.id' => $first]);
        $cases = [
            [['eventid' => $this->events, 'value' => "%{$t}rv%"], ['regkey'], false],
            [['eventid' => [$first], 'value1' => "%{$t}%"], ['domain', 'composite', 'tick', 'object'], false],
            [['eventid' => [$first, $uuid], 'value' => "%{$t}rv%"], [], true],
            [['value' => "%{$t}rv%"], ['regkey'], true],
        ];
        foreach ($cases as $case) {
            list($params, $expected, $resolved) = $case;
            $this->clearLog();
            $this->assertSame($this->ids(...$expected), $this->fetchedIds($params), json_encode($params));
            $this->assertSame($resolved ? 1 : 0, $this->resolvedPatterns(), json_encode($params));
        }
    }

    public function testAFetchResolvesItsValueConditionsOnce()
    {
        $t = $this->token;
        $count = 0;
        $this->clearLog();
        $found = $this->attribute->fetchAttributes($this->user, [
            'conditions' => ['Attribute.value LIKE' => "%$t%"],
            'flatten' => 1,
        ], $count, true);
        $this->assertSame(count($this->ids), $count);
        $this->assertCount(count($this->ids), $found);
        $this->assertSame(1, $this->resolvedPatterns());

        // restSearch, in pages of two
        $memoryLimit = ini_get('memory_limit');
        $coefficient = Configure::read('MISP.default_attribute_memory_coefficient');
        try {
            ini_set('memory_limit', '1024M');
            Configure::write('MISP.default_attribute_memory_coefficient', 2 / 1024);
            $this->clearLog();
            $tmp = $this->attribute->restSearch($this->user, 'json', [
                'value' => "%$t%",
                'to_ids' => [0, 1],
                'published' => [0, 1],
                'limit' => 100,
            ]);
            $response = json_decode($tmp->intoString(), true)['response']['Attribute'];
        } finally {
            ini_set('memory_limit', $memoryLimit);
            Configure::write('MISP.default_attribute_memory_coefficient', $coefficient);
        }
        $ids = array_map('intval', array_column($response, 'id'));
        sort($ids);
        $this->assertSame($this->ids(...array_keys($this->ids)), $ids);
        $this->assertGreaterThanOrEqual(3, count($this->statements('/`attributes` AS `Attribute`.* LIMIT 2$/s')));
        $this->assertSame(1, $this->resolvedPatterns());
    }

    public function testAFetchReadsTheValuesOfItsCorrelationsAtOnce()
    {
        $sides = [$this->ids['domain'], $this->ids['other'], $this->ids['composite']];
        $rows = $this->exec(sprintf(
            'SELECT a.id, a.event_id, a.object_id, a.distribution, e.org_id, e.distribution AS event_distribution FROM attributes a JOIN events e ON e.id = a.event_id WHERE a.id IN (%s)',
            implode(', ', $sides)
        ));
        $rows = array_column($rows, null, 'id');
        $correlate = function ($a, $b) use ($rows) {
            $columns = [];
            $values = [];
            foreach (['' => $rows[$a], '1_' => $rows[$b]] as $prefix => $row) {
                foreach (['attribute_id' => 'id', 'object_id' => 'object_id', 'event_id' => 'event_id', 'org_id' => 'org_id', 'distribution' => 'distribution', 'object_distribution' => 'distribution', 'event_distribution' => 'event_distribution'] as $column => $source) {
                    $columns[] = '`' . $prefix . $column . '`';
                    $values[] = (int)$row[$source];
                }
            }
            $this->exec(sprintf(
                'INSERT INTO default_correlations (%s, value_id) VALUES (%s, 1)',
                implode(', ', $columns),
                implode(', ', $values)
            ));
        };
        $correlate($sides[0], $sides[1]);
        $correlate($sides[2], $sides[1]);

        $this->clearLog();
        $found = $this->attribute->fetchAttributes($this->user, [
            'conditions' => ['Attribute.id' => $sides],
            'includeCorrelations' => true,
            'flatten' => 1,
        ]);
        $this->assertCount(2, $this->statements('/FROM `attribute_values` WHERE `id` IN/'));

        $fields = ['id','event_id','object_id','object_relation','category','type','value','uuid','timestamp','distribution','sharing_group_id','to_ids','comment'];
        $sgids = $this->attribute->SharingGroup->authorizedIds($this->user);
        $related = [];
        foreach ($found as $row) {
            $related[$row['Attribute']['id']] = $row['Attribute']['RelatedAttribute'];
            // As getRelatedAttributes() gives them with the values filled in per find
            $this->assertSame(
                $this->attribute->Correlation->getRelatedAttributes($this->user, $sgids, $row['Attribute'], $fields, true),
                $row['Attribute']['RelatedAttribute']
            );
        }
        $this->assertSame(["$this->token-two.example.org"], array_column($related[$this->ids['domain']], 'value'));
        $this->assertSame(["$this->token.example.org", "{$this->token}a.example|192.0.2.7"], array_column($related[$this->ids['other']], 'value'));
        $this->assertArrayNotHasKey('value1_id', $related[$this->ids['other']][0]);
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

    public function testTheOriginalUuidOfAnObjectAttributeIsFoundOnTheIds()
    {
        $this->createObjects();
        $uuid = $this->exec(sprintf('SELECT uuid FROM objects WHERE id = %d', self::OBJECT_ID))[0]['uuid'];
        list($first) = $this->events;

        $method = new ReflectionMethod('Event', '__findOriginalUUID');
        $method->setAccessible(true);
        $found = $method->invoke($this->event, 'domain', strtoupper("{$this->token}obj.example.org"), $first);
        $this->assertSame(['uuid' => $uuid], $found);
    }

    public function testTheHashAndUrlSearchesMatchOnTheIds()
    {
        $t = $this->token;
        $md5 = md5($t);
        list($first) = $this->events;
        $this->addFixtures([
            'md5' => [$first, 'md5', $md5],
            'file' => [$first, 'filename|md5', "$t.exe|$md5"],
            'hxxp' => [$first, 'url', "http://$t.example/a"],
            'dot' => [$first, 'url', "http://$t.example.org/"],
        ]);
        // A save refangs both, so these are rows stored before it did
        $fanged = ['hxxp' => "hxxp://$t.example/a", 'dot' => "http://$t.example[.]org/"];
        $ids = $this->attribute->loadAttributeValue()->internMany(array_values($fanged));
        foreach ($fanged as $name => $value) {
            $this->exec(sprintf('UPDATE attributes SET value1_id = %d WHERE id = %d', $ids[$value], $this->ids[$name]));
        }

        // downloadSample: every sample of a hash, then the samples alone
        $this->assertSame($this->ids('md5', 'file'), $this->select(['OR' => [
            'AND' => ['Attribute.value1 LIKE' => $md5, 'Attribute.value2' => ''],
            'Attribute.value2 LIKE' => $md5,
        ]]));
        $this->assertSame($this->ids('file'), $this->select(['AND' => ['Attribute.value2 LIKE' => $md5]]));
        // updateAttributeValues: url sanitisation
        $this->assertSame($this->ids('hxxp'), $this->select(['Attribute.value1 LIKE' => 'HXXP%']));
        $this->assertSame($this->ids('dot'), $this->select(['Attribute.value1 LIKE' => '%[.]%']));
    }

    public function testAProposalSearchDeclaredBoundedChecksItsPatternPerRow()
    {
        $t = $this->token;
        list($first) = $this->events;
        $event = $this->event->find('first', [
            'recursive' => -1,
            'conditions' => ['Event.id' => $first],
            'fields' => ['Event.uuid', 'Event.orgc_id'],
        ])['Event'];
        $proposal = ClassRegistry::init('ShadowAttribute');
        $ids = [];
        foreach (['text' => "{$t}prop text", 'regkey|value' => "HKLM\\Software\\x|{$t}prop-data", 'comment' => "{$t}other"] as $type => $value) {
            $proposal->create();
            $saved = $proposal->save(['ShadowAttribute' => [
                'event_id' => $first,
                'event_uuid' => $event['uuid'],
                'event_org_id' => $event['orgc_id'],
                'org_id' => $event['orgc_id'],
                'old_id' => 0,
                'type' => $type,
                'category' => $type === 'regkey|value' ? 'Persistence mechanism' : 'Other',
                'value' => $value,
                'comment' => $t,
            ]]);
            $this->assertNotFalse($saved, json_encode($proposal->validationErrors));
            $ids[] = (int)$proposal->id;
        }
        $this->exec(sprintf(
            "UPDATE shadow_attributes SET value1 = 'column', value2 = IF(value2 = '', '', 'column') WHERE id IN (%s)",
            implode(', ', $ids)
        ));
        $search = function ($bounded) use ($proposal, $t) {
            $conditions = $this->attribute->loadAttributeValue()->rewriteConditions(['OR' => [
                'ShadowAttribute.value1 LIKE' => "%{$t}PROP%",
                'ShadowAttribute.value2 LIKE' => "%{$t}PROP%",
                'LOWER(ShadowAttribute.comment) LIKE' => '%nothing%',
            ]], 'ShadowAttribute', $bounded);
            $found = array_map('intval', $proposal->find('column', [
                'conditions' => ['AND' => [$conditions, ['ShadowAttribute.comment' => $t]]],
                'fields' => ['ShadowAttribute.id'],
            ]));
            sort($found);
            return $found;
        };

        $this->clearLog();
        $this->assertSame([$ids[0], $ids[1]], $search(true));
        $this->assertSame(0, $this->resolvedPatterns());
        $this->assertCount(1, $this->statements('/`shadow_attributes` AS `ShadowAttribute`.*IN \(SELECT `id` FROM `attribute_values` WHERE `value` LIKE/s'));

        $this->clearLog();
        $this->assertSame([$ids[0], $ids[1]], $search(false));
        $this->assertSame(1, $this->resolvedPatterns());
    }
}
