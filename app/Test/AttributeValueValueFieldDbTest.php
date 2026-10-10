<?php
/**
 * Field lists and orders that name the value field read the dictionary, with
 * the keys and the key order of 2.x, where the value was a virtual field over
 * value1 and value2. The tests hide that virtual field and the text columns
 * from every attribute and proposal model, and point the stored text away
 * from the dictionary, so a read or a sort that still needs either shows it.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueValueFieldDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueValueFieldDbTest extends TestCase
{
    // fetchEvent's attribute and proposal columns, in the order 2.x returned them
    const EVENT_ATTRIBUTE_KEYS = [
        'id', 'type', 'category', 'to_ids', 'uuid', 'event_id', 'distribution', 'timestamp', 'comment',
        'sharing_group_id', 'deleted', 'disable_correlation', 'object_id', 'object_relation', 'first_seen',
        'last_seen', 'value',
    ];

    const EVENT_PROPOSAL_KEYS = [
        'id', 'type', 'category', 'to_ids', 'uuid', 'event_uuid', 'event_id', 'old_id', 'comment', 'org_id',
        'proposal_to_delete', 'timestamp', 'first_seen', 'last_seen', 'value',
    ];

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var string */
    private $token;

    /** @var array */
    private $event;

    /** @var array name => id */
    private $ids = [];

    /** @var array attribute id => the value 2.x returned */
    private $values = [];

    /** @var bool */
    private $cachedMethods;

    /** @var bool */
    private $fullDebug;

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
            require_once __DIR__ . '/AttributeValueTextSupport.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('AppModel', 'Model');
            App::uses('AttributeValue', 'Model');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        $this->db->begin();
        $this->token = 'avvf' . bin2hex(random_bytes(4));
        $this->event = $this->attribute->Event->find('first', [
            'recursive' => -1,
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id', 'Event.uuid', 'Event.orgc_id'],
        ])['Event'];
        $this->createFixture();
        $this->hideTextColumnsAndValueField();
        $this->db->fullDebug = true;
        $this->dictionaryReads();
    }

    protected function tearDown(): void
    {
        if (!$this->db) {
            return;
        }
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
        $ip = '192.0.2.' . random_int(1, 254);
        $md5 = md5($t);
        // Created out of value order, so that an id order is never the value order
        $this->ids['b'] = $this->create('text', "{$t}b");
        $this->ids['composite'] = $this->create('filename|md5', "{$t}a|$md5", 'Payload delivery');
        $this->ids['bang'] = $this->create('text', "{$t}a!");
        $this->ids['upper'] = $this->create('text', "{$t}A");
        $this->ids['spaces'] = $this->create('text', "{$t}a, then spaces");
        $this->ids['a'] = $this->create('text', "{$t}a");
        $this->ids['pipe'] = $this->create('text', "{$t}a|zz");
        $this->ids['accent'] = $this->create('text', "{$t}é");
        $this->ids['port'] = $this->create('ip-dst|port', "$ip|8080", 'Network activity');

        // A legacy value2 of spaces: 2.x tested value2 = '', which PAD SPACE holds
        $dictionary = $this->attribute->loadAttributeValue();
        $this->exec(sprintf(
            'UPDATE attributes SET value1_id = %d, value2_id = %d WHERE id = %d',
            $dictionary->intern("{$t}a"),
            $dictionary->intern('   '),
            $this->ids['spaces']
        ));
        AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf("UPDATE attributes SET value2 = '   ' WHERE id = %d", $this->ids['spaces']));
        $this->values[$this->ids['spaces']] = "{$t}a";

        $proposal = ClassRegistry::init('ShadowAttribute');
        $proposal->create();
        $saved = $proposal->save(['ShadowAttribute' => [
            'event_id' => $this->event['id'],
            'event_uuid' => $this->event['uuid'],
            'event_org_id' => $this->event['orgc_id'],
            'org_id' => $this->event['orgc_id'],
            'old_id' => $this->ids['b'],
            'type' => 'text',
            'category' => 'Other',
            'value' => "{$t}proposed",
            'comment' => $t,
        ]]);
        $this->assertNotFalse($saved, json_encode($proposal->validationErrors));
        $this->ids['proposal'] = (int)$proposal->id;

        AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf(
            "UPDATE attributes SET value1 = '%1\$s', value2 = IF(value2 = '', '', '%1\$s') WHERE id IN (%2\$s)",
            $this->columnText(),
            implode(', ', $this->attributeIds())
        ));
        AttributeValueTextSupport::diverge($this->db, 'shadow_attributes', sprintf("UPDATE shadow_attributes SET value1 = '%s' WHERE id = %d", $this->columnText(), $this->ids['proposal']));
    }

    private function create($type, $value, $category = 'Other')
    {
        $this->attribute->create();
        $saved = $this->attribute->save(['Attribute' => [
            'event_id' => $this->event['id'],
            'category' => $category,
            'type' => $type,
            'value' => $value,
            'distribution' => 5,
            'to_ids' => 0,
            'disable_correlation' => 1,
        ]]);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $id = (int)$this->attribute->id;
        $this->values[$id] = $value;
        return $id;
    }

    private function attributeIds()
    {
        return array_keys($this->values);
    }

    private function columnText()
    {
        return "column-{$this->token}";
    }

    private function attributeModels()
    {
        // A later test can leave the registry holding another instance
        $models = [spl_object_id($this->attribute) => $this->attribute];
        foreach (ClassRegistry::keys() as $key) {
            $object = ClassRegistry::getObject($key);
            if ($object instanceof MispAttribute || $object instanceof ShadowAttribute) {
                $models[spl_object_id($object)] = $object;
            }
        }
        return $models;
    }

    private function hideTextColumnsAndValueField()
    {
        // Instantiate the lazily loaded associations, so that all are hidden
        $this->attribute->Event->ShadowAttribute;
        $this->attribute->Event->Object->Attribute;
        ClassRegistry::init('ShadowAttribute')->Attribute;
        ClassRegistry::init('Sighting')->Attribute;
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

    private function dictionaryReads()
    {
        $count = 0;
        foreach ($this->db->getLog(false, true)['log'] as $entry) {
            if (preg_match('/FROM `attribute_values` WHERE `id` IN/', $entry['query'])) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * The fixture ids in value order, sorted by the database in the
     * dictionary's collation over the values 2.x returned.
     */
    private function referenceOrder($direction)
    {
        $collation = $this->exec(
            "SELECT COLLATION_NAME AS c FROM information_schema.COLUMNS"
            . " WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'attribute_values' AND COLUMN_NAME = 'value'"
        )[0]['c'];
        $rows = [];
        foreach ($this->values as $id => $value) {
            $rows[] = sprintf("SELECT %d AS id, _utf8mb4 X'%s' AS v", $id, bin2hex($value));
        }
        return array_map('intval', array_column($this->exec(sprintf(
            'SELECT id FROM (%s) r ORDER BY v COLLATE %s %s, id ASC',
            implode(' UNION ALL ', $rows),
            $collation,
            $direction
        )), 'id'));
    }

    private function ids(array $results, $alias = 'Attribute')
    {
        return array_map('intval', array_column(array_column($results, $alias), 'id'));
    }

    private function assertNoIdsOrColumnText($results)
    {
        $encoded = json_encode($results);
        $this->assertStringNotContainsString('value1_id', $encoded);
        $this->assertStringNotContainsString('value2_id', $encoded);
        $this->assertStringNotContainsString($this->columnText(), $encoded);
    }

    public function testAFieldListNamingTheValueReadsOnlyTheValue()
    {
        $results = $this->attribute->find('all', [
            'recursive' => -1,
            'conditions' => ['Attribute.id' => $this->attributeIds()],
            'fields' => ['Attribute.id', 'Attribute.type', 'Attribute.value', 'Attribute.to_ids'],
        ]);

        $this->assertCount(count($this->values), $results);
        foreach ($results as $result) {
            $this->assertSame(['id', 'type', 'to_ids', 'value'], array_keys($result['Attribute']));
            $this->assertSame($this->values[$result['Attribute']['id']], $result['Attribute']['value']);
        }
        $this->assertNoIdsOrColumnText($results);
        $this->assertSame(1, $this->dictionaryReads());
    }

    public function testTheValueColumnsNamedAlongsideComeFromTheDictionaryToo()
    {
        $result = $this->attribute->find('first', [
            'recursive' => -1,
            'conditions' => ['Attribute.id' => $this->ids['port']],
            'fields' => ['Attribute.id', 'Attribute.value1', 'value'],
        ]);

        $value = $this->values[$this->ids['port']];
        $this->assertSame(
            ['id' => (string)$this->ids['port'], 'value1' => explode('|', $value)[0], 'value' => $value],
            $result['Attribute']
        );
    }

    public function testFindListAndFieldReadTheDictionary()
    {
        $list = $this->attribute->find('list', ['conditions' => ['Attribute.id' => $this->attributeIds()]]);
        ksort($list);
        $expected = $this->values;
        ksort($expected);
        $this->assertSame($expected, $list);

        $this->attribute->id = $this->ids['composite'];
        $this->assertSame($this->values[$this->ids['composite']], $this->attribute->field('value'));
        $this->assertSame($this->values[$this->ids['composite']], $this->attribute->field('Attribute.value'));
        $this->assertSame($this->values[$this->ids['composite']], $this->attribute->field($this->attribute->displayField));
    }

    public function testAnOrderOnTheValueSortsByTheDictionaryText()
    {
        $orders = [
            'ASC' => ['Attribute.value asc', 'Attribute.id asc'],
            'DESC' => ['Attribute.value' => 'desc', 'Attribute.id' => 'asc'],
        ];
        foreach ($orders as $direction => $order) {
            $results = $this->attribute->find('all', [
                'recursive' => -1,
                'conditions' => ['Attribute.id' => $this->attributeIds()],
                'fields' => ['Attribute.id'],
                'order' => $order,
            ]);
            $this->assertSame($this->referenceOrder($direction), $this->ids($results), $direction);
        }

        $page = $this->attribute->find('all', [
            'recursive' => -1,
            'conditions' => ['Attribute.id' => $this->attributeIds()],
            'order' => ['Attribute.value asc', 'Attribute.id asc'],
            'limit' => 3,
            'page' => 2,
        ]);
        $this->assertSame(array_slice($this->referenceOrder('ASC'), 3, 3), $this->ids($page));
        $this->assertNoIdsOrColumnText($page);
    }

    public function testFetchAttributesSortsAndReadsTheDictionary()
    {
        $user = ClassRegistry::init('User')->getAuthUser(1);

        $results = $this->attribute->fetchAttributes($user, [
            'conditions' => ['Attribute.id' => $this->attributeIds()],
            'order' => 'Attribute.value asc,Attribute.id asc',
            'includeProposals' => true,
        ]);

        $this->assertSame($this->referenceOrder('ASC'), $this->ids($results));
        foreach ($results as $result) {
            $this->assertSame($this->values[$result['Attribute']['id']], $result['Attribute']['value']);
        }
        $proposals = array_merge(...array_column($results, 'ShadowAttribute'));
        $this->assertCount(1, $proposals);
        $this->assertSame("{$this->token}proposed", $proposals[0]['value']);
        $this->assertSame("{$this->token}proposed", $proposals[0]['value1']);
        $this->assertNoIdsOrColumnText($results);
    }

    public function testAProposalFieldListAndOrder()
    {
        $results = ClassRegistry::init('ShadowAttribute')->find('all', [
            'recursive' => -1,
            'conditions' => ['ShadowAttribute.id' => $this->ids['proposal']],
            'fields' => ['ShadowAttribute.id', 'ShadowAttribute.value'],
            'order' => ['ShadowAttribute.value' => 'asc'],
        ]);

        $this->assertSame(
            [['ShadowAttribute' => ['id' => (string)$this->ids['proposal'], 'value' => "{$this->token}proposed"]]],
            $results
        );
    }

    /**
     * @param Model $model
     * @param array $named The request's named parameters.
     * @param array $scope
     * @return array
     */
    private function paginate(Model $model, array $named, array $scope)
    {
        App::uses('Controller', 'Controller');
        App::uses('ComponentCollection', 'Controller');
        App::uses('PaginatorComponent', 'Controller/Component');
        $request = new CakeRequest(null, false);
        $request->params['named'] = $named;
        $collection = new ComponentCollection();
        $collection->setController(new Controller($request, new CakeResponse()));
        $paginator = new PaginatorComponent($collection, ['limit' => 50, 'recursive' => -1]);
        return $paginator->paginate($model, $scope);
    }

    public function testThePaginatorSortsByTheValue()
    {
        $proposal = ClassRegistry::init('ShadowAttribute');
        // Only the paginator's check of the virtual fields counts the value as a field
        $this->assertFalse($this->attribute->hasField('value'));
        $this->assertTrue($this->attribute->hasField('value', true));
        $this->assertTrue($this->attribute->hasField('Attribute.value', true));
        $this->assertFalse($this->attribute->hasField('ShadowAttribute.value', true));
        $this->assertTrue($proposal->hasField('ShadowAttribute.value', true));
        $this->assertSame('value', $proposal->hasField(['value', 'id'], true));

        // Values equal in the collation (A and a) may come either way round
        $folded = function (array $ids) {
            return array_map(function ($id) {
                return mb_strtolower($this->values[$id]);
            }, $ids);
        };
        foreach (['Attribute.value' => 'asc', 'value' => 'desc'] as $sort => $direction) {
            $results = $this->paginate(
                $this->attribute,
                ['sort' => $sort, 'direction' => $direction],
                ['Attribute.id' => $this->attributeIds()]
            );
            $this->assertSame(
                $folded($this->referenceOrder(strtoupper($direction))),
                $folded($this->ids($results)),
                $sort
            );
            $this->assertNoIdsOrColumnText($results);
        }

        $t = $this->token;
        $ids = [$this->ids['proposal']];
        foreach (["{$t}m", "{$t}c"] as $value) {
            $proposal->create();
            $this->assertNotFalse($proposal->save(['ShadowAttribute' => [
                'event_id' => $this->event['id'],
                'event_uuid' => $this->event['uuid'],
                'event_org_id' => $this->event['orgc_id'],
                'org_id' => $this->event['orgc_id'],
                'old_id' => 0,
                'type' => 'text',
                'category' => 'Other',
                'value' => $value,
                'comment' => $t,
            ]]), json_encode($proposal->validationErrors));
            $ids[] = (int)$proposal->id;
        }
        $results = $this->paginate(
            $proposal,
            ['sort' => 'ShadowAttribute.value', 'direction' => 'desc'],
            ['ShadowAttribute.id' => $ids]
        );
        $this->assertSame(
            ["{$t}proposed", "{$t}m", "{$t}c"],
            array_column(array_column($results, 'ShadowAttribute'), 'value')
        );
    }

    public function testTheProposalIndexSortsByTheValueAndNotItsColumns()
    {
        App::uses('ShadowAttributesController', 'Controller');
        $controller = new ShadowAttributesController(new CakeRequest(null, false), new CakeResponse());
        $controller->ShadowAttribute = ClassRegistry::init('ShadowAttribute');
        // The columns as the table has them in dual mode
        $controller->ShadowAttribute->schema(true);
        $method = new ReflectionMethod($controller, '__indexOrder');
        $method->setAccessible(true);
        $order = function (array $named) use ($method, $controller) {
            return $method->invoke($controller, $named);
        };

        $this->assertSame(['ShadowAttribute.value' => 'DESC'], $order(['sort' => 'value', 'direction' => 'desc']));
        $this->assertSame(['ShadowAttribute.comment' => 'ASC'], $order(['sort' => 'comment']));
        foreach (['value1', 'value2', 'value1_id', 'value2_id', 'ShadowAttribute.value', 'nothing'] as $sort) {
            $this->assertNull($order(['sort' => $sort, 'direction' => 'asc']), $sort);
        }
        $this->assertNull($order([]));
    }

    public function testFetchEventRowsHoldTheKeysOf2x()
    {
        $user = ClassRegistry::init('User')->getAuthUser(1);

        $events = $this->attribute->Event->fetchEvent($user, ['eventid' => $this->event['id']]);

        $attributes = [];
        foreach ($events[0]['Attribute'] as $attribute) {
            if (isset($this->values[$attribute['id']])) {
                $attributes[$attribute['id']] = $attribute;
            }
        }
        $this->assertCount(count($this->values), $attributes);
        foreach ($attributes as $id => $attribute) {
            $this->assertSame(self::EVENT_ATTRIBUTE_KEYS, array_slice(array_keys($attribute), 0, count(self::EVENT_ATTRIBUTE_KEYS)));
            $this->assertSame($this->values[$id], $attribute['value']);
        }
        $proposal = $attributes[$this->ids['b']]['ShadowAttribute'][0];
        $this->assertSame(self::EVENT_PROPOSAL_KEYS, array_slice(array_keys($proposal), 0, count(self::EVENT_PROPOSAL_KEYS)));
        $this->assertSame("{$this->token}proposed", $proposal['value']);
        $this->assertArrayHasKey('Org', $proposal);
        $this->assertNoIdsOrColumnText($events);
        $this->assertStringNotContainsString('"value1"', json_encode($events));
    }

    public function testASightingCarriesTheValueOf2x()
    {
        $this->exec(sprintf(
            "INSERT INTO sightings (attribute_id, event_id, org_id, date_sighting, uuid, source, type)"
            . " VALUES (%d, %d, %d, %d, '%s', '', 0)",
            $this->ids['composite'],
            $this->event['id'],
            $this->event['orgc_id'],
            time(),
            CakeText::uuid()
        ));
        $sightingId = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];

        $sighting = ClassRegistry::init('Sighting')->getSighting($sightingId);

        $this->assertSame(
            ['id', 'uuid', 'type', 'category', 'to_ids', 'value'],
            array_keys($sighting['Sighting']['Attribute'])
        );
        $this->assertSame($this->values[$this->ids['composite']], $sighting['Sighting']['Attribute']['value']);
    }
}
