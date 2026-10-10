<?php
/**
 * Reads of attributes and proposals take their value text from the
 * dictionary, as primary rows and as association rows at any depth, and
 * never return the ids. The tests hide value1 and value2 from every model's
 * schema, the way the column drop will, and point the stored text away from
 * the dictionary, so a read that still uses the columns shows it.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueHydratorDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueHydratorDbTest extends TestCase
{
    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var string Keeps the test values apart from real ones. */
    private $token;

    /** @var array */
    private $event;

    /** @var array name => id */
    private $ids = [];

    /** @var array attribute or proposal id => [value1, value2, value] */
    private $expected = [];

    /** @var bool */
    private $cachedMethods;

    /** @var bool */
    private $fullDebug;

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
            require_once __DIR__ . '/AttributeValueHydratorSupport.php';
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
        $this->token = 'avhyd' . bin2hex(random_bytes(4));
        $this->event = $this->attribute->Event->find('first', [
            'recursive' => -1,
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id', 'Event.uuid', 'Event.orgc_id'],
        ])['Event'];
        $this->createFixture();
        $this->hideTextColumns();
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
        foreach ($this->attributeModels() as $model) {
            $model->schema(true);
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
        $eventId = (int)$this->event['id'];
        $this->exec(sprintf(
            "INSERT INTO objects (name, `meta-category`, description, template_uuid, template_version, event_id,"
            . " uuid, timestamp, distribution, sharing_group_id, comment, deleted)"
            . " VALUES ('ip-port', 'network', '', '%s', 1, %d, '%s', %d, 5, 0, '%s', 0)",
            CakeText::uuid(),
            $eventId,
            CakeText::uuid(),
            time(),
            $this->token
        ));
        $this->ids['object'] = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];

        $domain = "{$this->token}.example.org";
        $ip = '192.0.2.' . random_int(1, 254);
        $this->ids['standalone'] = $this->create('domain', $domain, [$domain, '', $domain]);
        $this->ids['composite'] = $this->create('ip-dst|port', "$ip|8080", [$ip, '8080', "$ip|8080"], 'ip-port');
        $this->ids['domain'] = $this->create('domain', "obj-$domain", ["obj-$domain", '', "obj-$domain"], 'domain');
        $this->ids['text'] = $this->create('text', "text {$this->token}", ["text {$this->token}", '', "text {$this->token}"], 'text');
        $this->ids['proposal'] = $this->createProposal("prop-$domain");

        $this->exec(sprintf(
            'INSERT INTO attribute_tags (attribute_id, event_id, tag_id, local) VALUES (%d, %d, %d, 0)',
            $this->ids['standalone'],
            $eventId,
            (int)$this->exec('SELECT MIN(id) AS id FROM tags')[0]['id']
        ));
        $this->exec(sprintf(
            "INSERT INTO object_references (uuid, timestamp, object_id, event_id, referenced_id, referenced_type,"
            . " relationship_type, comment, deleted) VALUES ('%s', %d, %d, %d, %d, 0, 'related-to', '', 0)",
            CakeText::uuid(),
            time(),
            $this->ids['object'],
            $eventId,
            $this->ids['standalone']
        ));
        $this->ids['reference'] = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];

        foreach (['attributes' => ['standalone', 'composite', 'domain', 'text'], 'shadow_attributes' => ['proposal']] as $table => $names) {
            foreach ($names as $name) {
                AttributeValueTextSupport::diverge($this->db, $table, sprintf(
                    "UPDATE %s SET value1 = '%s', value2 = IF(value2 = '', '', '%s') WHERE id = %d",
                    $table,
                    $this->columnText(),
                    $this->columnText(),
                    $this->ids[$name]
                ));
            }
        }
    }

    private function create($type, $value, array $expected, $relation = null)
    {
        $this->attribute->create();
        $saved = $this->attribute->save(['Attribute' => [
            'event_id' => $this->event['id'],
            'object_id' => $relation === null ? 0 : $this->ids['object'],
            'object_relation' => $relation,
            'category' => $type === 'text' ? 'Other' : 'Network activity',
            'type' => $type,
            'value' => $value,
            'distribution' => 5,
            'to_ids' => 0,
            'disable_correlation' => 1,
        ]]);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $id = (int)$this->attribute->id;
        $this->expected['Attribute'][$id] = $expected;
        return $id;
    }

    private function createProposal($value)
    {
        $proposal = ClassRegistry::init('ShadowAttribute');
        $proposal->create();
        $saved = $proposal->save(['ShadowAttribute' => [
            'event_id' => $this->event['id'],
            'event_uuid' => $this->event['uuid'],
            'event_org_id' => $this->event['orgc_id'],
            'org_id' => $this->event['orgc_id'],
            'old_id' => $this->ids['standalone'],
            'type' => 'domain',
            'category' => 'Network activity',
            'value' => $value,
            'comment' => $this->token,
        ]]);
        $this->assertNotFalse($saved, json_encode($proposal->validationErrors));
        $id = (int)$proposal->id;
        $this->expected['ShadowAttribute'][$id] = [$value, '', $value];
        return $id;
    }

    private function columnText()
    {
        return "column-{$this->token}";
    }

    /**
     * Every attribute and proposal model the reads below use, each alias
     * being an instance of its own.
     *
     * @return Model[]
     */
    private function attributeModels()
    {
        $models = [];
        foreach (ClassRegistry::keys() as $key) {
            $object = ClassRegistry::getObject($key);
            if ($object instanceof MispAttribute || $object instanceof ShadowAttribute) {
                $models[spl_object_id($object)] = $object;
            }
        }
        return $models;
    }

    private function hideTextColumns()
    {
        // Instantiate the lazily loaded associations, so that all are hidden
        ClassRegistry::init('MispObject')->Attribute;
        ClassRegistry::init('AttributeTag')->Attribute;
        ClassRegistry::init('ObjectReference')->ReferencedAttribute;
        ClassRegistry::init('ShadowAttribute')->Attribute;
        $this->attribute->Event->ShadowAttribute;
        ClassRegistry::init(['class' => 'HydratorNestedFindObject', 'alias' => 'NestedObject'])->Attribute;
        $property = new ReflectionProperty('Model', '_schema');
        foreach ($this->attributeModels() as $model) {
            $schema = $model->schema();
            unset($schema['value1'], $schema['value2']);
            $property->setValue($model, $schema);
        }
        // Else a read of every column reuses a field list cached before
        $this->db->cacheMethods = false;
    }

    /**
     * How many dictionary reads ran since the last call.
     */
    private function dictionaryReads()
    {
        $count = 0;
        foreach ($this->db->getLog(false, true)['log'] as $entry) {
            if (strpos($entry['query'], 'FROM `attribute_values`') !== false) {
                $count++;
            }
        }
        return $count;
    }

    private function assertFilled($row, $model = 'Attribute')
    {
        $this->assertIsArray($row);
        $expected = $this->expected[$model][(int)$row['id']];
        $this->assertSame($expected, [$row['value1'], $row['value2'], $row['value']], json_encode($row));
        $this->assertArrayNotHasKey('value1_id', $row);
        $this->assertArrayNotHasKey('value2_id', $row);
    }

    private function assertNoIdsOrColumnText($results)
    {
        $encoded = json_encode($results);
        $this->assertStringNotContainsString('value1_id', $encoded);
        $this->assertStringNotContainsString('value2_id', $encoded);
        $this->assertStringNotContainsString($this->columnText(), $encoded);
    }

    public function testAPrimaryReadTakesItsValuesFromTheDictionary()
    {
        $ids = [$this->ids['standalone'], $this->ids['composite'], $this->ids['text']];

        $results = $this->attribute->find('all', [
            'recursive' => -1,
            'conditions' => ['Attribute.id' => $ids],
            'order' => ['Attribute.id'],
        ]);

        $this->assertCount(3, $results);
        foreach ($results as $result) {
            $this->assertFilled($result['Attribute']);
        }
        $this->assertNoIdsOrColumnText($results);
        $this->assertSame(1, $this->dictionaryReads());

        // The keys come in the order of a read that has the text columns
        $this->attribute->schema(true);
        $visible = $this->attribute->find('first', [
            'recursive' => -1,
            'conditions' => ['Attribute.id' => $ids[1]],
        ]);
        $this->assertSame(array_keys($visible['Attribute']), array_keys($results[1]['Attribute']));
    }

    public function testAnObjectsAttributesAreFilledInOneRead()
    {
        $results = ClassRegistry::init('MispObject')->find('all', [
            'conditions' => ['Object.id' => $this->ids['object']],
            'contain' => ['Attribute'],
        ]);

        $this->assertCount(3, $results[0]['Attribute']);
        foreach ($results[0]['Attribute'] as $attribute) {
            $this->assertFilled($attribute);
        }
        $this->assertNoIdsOrColumnText($results);
        $this->assertSame(1, $this->dictionaryReads());
    }

    public function testAJoinedAttributeIsFilled()
    {
        $result = ClassRegistry::init('AttributeTag')->find('first', [
            'conditions' => ['AttributeTag.attribute_id' => $this->ids['standalone']],
            'contain' => ['Attribute'],
        ]);

        $this->assertFilled($result['Attribute']);
        $this->assertNoIdsOrColumnText($result);
        $this->assertSame(1, $this->dictionaryReads());
    }

    public function testAnAttributeUnderAnotherAliasIsFilled()
    {
        $reference = ClassRegistry::init('ObjectReference');
        $reference->unbindModel(['belongsTo' => ['Object', 'ReferencedObject']]);
        // The model's own conditions compare the id with a string, and the
        // value virtual field names the Attribute alias: neither works here
        $reference->bindModel(['belongsTo' => ['ReferencedAttribute' => [
            'className' => 'MispAttribute',
            'foreignKey' => 'referenced_id',
            'fields' => ['id', 'value1_id', 'value2_id'],
        ]]]);

        $result = $reference->find('first', [
            'conditions' => ['ObjectReference.id' => $this->ids['reference']],
            'recursive' => 0,
        ]);

        $this->assertFilled($result['ReferencedAttribute']);
        $this->assertNoIdsOrColumnText($result);
        $this->assertSame(1, $this->dictionaryReads());
    }

    public function testNestedAssociationsAreFilledInOneRead()
    {
        $result = $this->attribute->Event->find('first', [
            'conditions' => ['Event.id' => $this->event['id']],
            'fields' => ['Event.id'],
            'contain' => [
                'Object' => [
                    'conditions' => ['Object.id' => $this->ids['object']],
                    'Attribute',
                ],
                'ShadowAttribute' => [
                    'conditions' => ['ShadowAttribute.id' => $this->ids['proposal']],
                ],
            ],
        ]);

        $this->assertCount(3, $result['Object'][0]['Attribute']);
        foreach ($result['Object'][0]['Attribute'] as $attribute) {
            $this->assertFilled($attribute);
        }
        $this->assertFilled($result['ShadowAttribute'][0], 'ShadowAttribute');
        $this->assertNoIdsOrColumnText($result);
        $this->assertSame(1, $this->dictionaryReads());
    }

    public function testAProposalAndItsAttributeAreFilled()
    {
        $result = ClassRegistry::init('ShadowAttribute')->find('first', [
            'conditions' => ['ShadowAttribute.id' => $this->ids['proposal']],
            'contain' => ['Attribute'],
        ]);

        $this->assertFilled($result['ShadowAttribute'], 'ShadowAttribute');
        $this->assertFilled($result['Attribute']);
        $this->assertNoIdsOrColumnText($result);

        $alone = ClassRegistry::init('ShadowAttribute')->find('first', [
            'conditions' => ['ShadowAttribute.id' => $this->ids['proposal']],
            'recursive' => -1,
        ]);
        $this->assertFilled($alone['ShadowAttribute'], 'ShadowAttribute');
        $this->assertNoIdsOrColumnText($alone);
    }

    public function testAFindInsideAFindLeavesTheOuterRowsToTheOuterFind()
    {
        $model = ClassRegistry::init(['class' => 'HydratorNestedFindObject', 'alias' => 'NestedObject']);

        $result = $model->find('first', ['conditions' => ['NestedObject.id' => $this->ids['object']]]);

        foreach ([$result, $model->innerResult] as $read) {
            $this->assertCount(3, $read['Attribute']);
            foreach ($read['Attribute'] as $attribute) {
                $this->assertFilled($attribute);
            }
            $this->assertNoIdsOrColumnText($read);
        }
        $this->assertSame(2, $this->dictionaryReads());
    }

    public function testCallbacksOffIsTheWayToReadTheIds()
    {
        $result = $this->attribute->find('first', [
            'recursive' => -1,
            'conditions' => ['Attribute.id' => $this->ids['standalone']],
            'callbacks' => false,
        ]);

        $this->assertGreaterThan(0, (int)$result['Attribute']['value1_id']);
        $this->assertNull($result['Attribute']['value2_id']);
        $this->assertSame(0, $this->dictionaryReads());
    }
}
