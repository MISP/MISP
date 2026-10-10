<?php
/**
 * What MISP publishes for attributes and proposals (pubsub, Kafka, workflow)
 * carries the value text from the dictionary and never the value ids. The
 * tests run the payload oracle's capture over their own attributes and
 * proposal, with value1 and value2 hidden from every attribute and proposal
 * model's schema, the way the column drop will, and the stored text pointed
 * away from the dictionary, so a read of the columns shows.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValuePayloadDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValuePayloadDbTest extends TestCase
{
    const ID_KEYS = ['value1_id', 'value2_id'];

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var ShadowAttribute */
    private $shadow;

    /** @var DboSource */
    private $db;

    /** @var string Keeps the test values apart from real ones. */
    private $token;

    /** @var array name => id */
    private $ids = [];

    /** @var array name => [value1, value2, value] */
    private $expected = [];

    /** @var string[] The attribute columns 2.x published, without the ids */
    private $columns;

    /** @var bool */
    private $cachedMethods;

    /** @var mixed */
    private $currentUserId;

    protected function setUp(): void
    {
        if (!getenv('ATTRIBUTE_VALUE_DB_TESTS')) {
            $this->markTestSkipped('Needs the database, see the file header.');
        }
        if (!self::$booted) {
            if (class_exists('App', false)) {
                $this->markTestSkipped('Needs its own process: run this file alone.');
            }
            require_once __DIR__ . '/AttributePayloadOracleSupport.php';
            require_once __DIR__ . '/AttributeValueTextSupport.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('CakeText', 'Utility');
            App::uses('AttributeValue', 'Model');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        // The capture asks for these aliases; registered first, they are the instances hidden below
        $this->attribute = ClassRegistry::init(['class' => 'PayloadRecordingAttribute', 'alias' => 'Attribute']);
        $this->shadow = ClassRegistry::init(['class' => 'PayloadRecordingShadowAttribute', 'alias' => 'ShadowAttribute']);
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', 1);
        $this->cachedMethods = $this->db->cacheMethods;
        $this->columns = array_values(array_diff(array_keys($this->attribute->schema()), self::ID_KEYS));
        $this->token = 'avpay' . bin2hex(random_bytes(4));
        $this->db->begin();
        $this->createFixture();
        $this->hideTextColumns();
        PayloadRecorder::take();
    }

    protected function tearDown(): void
    {
        if (!$this->db) {
            return;
        }
        Configure::write('CurrentUserId', $this->currentUserId);
        $this->db->cacheMethods = $this->cachedMethods;
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
        $t = $this->token;
        $this->exec(sprintf(
            "INSERT INTO events (org_id, orgc_id, user_id, date, info, uuid, analysis, distribution, sharing_group_id, threat_level_id, disable_correlation)"
            . " VALUES (1, 1, 1, CURDATE(), 'payload %s', '%s', 0, 0, 0, 4, 1)",
            $t,
            CakeText::uuid()
        ));
        $eventId = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
        $ip = '192.0.2.' . random_int(1, 254);
        foreach ([
            'domain' => ['domain', "$t.example.org", ["$t.example.org", '', "$t.example.org"]],
            'composite' => ['ip-dst|port', "$ip|8080", [$ip, '8080', "$ip|8080"]],
            'pipe_in_text' => ['text', "left $t|right", ["left $t|right", '', "left $t|right"]],
        ] as $name => list($type, $value, $expected)) {
            $this->attribute->create();
            $saved = $this->attribute->save(['Attribute' => [
                'event_id' => $eventId,
                'category' => $type === 'text' ? 'Other' : 'Network activity',
                'type' => $type,
                'value' => $value,
                'distribution' => 5,
                'to_ids' => 0,
                'disable_correlation' => 1,
            ]]);
            $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
            $this->ids[$name] = (int)$this->attribute->id;
            $this->expected[$name] = $expected;
        }
        $event = $this->exec("SELECT uuid FROM events WHERE id = $eventId")[0];
        $this->shadow->create();
        $saved = $this->shadow->save(['ShadowAttribute' => [
            'event_id' => $eventId,
            'event_uuid' => $event['uuid'],
            'event_org_id' => 1,
            'org_id' => 1,
            'old_id' => $this->ids['domain'],
            'type' => 'ip-dst|port',
            'category' => 'Network activity',
            'value' => "$ip|443",
            'comment' => $t,
        ]]);
        $this->assertNotFalse($saved, json_encode($this->shadow->validationErrors));
        $this->ids['proposal'] = (int)$this->shadow->id;
        $this->expected['proposal'] = [$ip, '443', "$ip|443"];

        AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf(
            "UPDATE attributes SET value1 = '%s', value2 = IF(value2 = '', '', '%s') WHERE id IN (%d, %d, %d)",
            $this->columnText(),
            $this->columnText(),
            $this->ids['domain'],
            $this->ids['composite'],
            $this->ids['pipe_in_text']
        ));
        AttributeValueTextSupport::diverge($this->db, 'shadow_attributes', sprintf(
            "UPDATE shadow_attributes SET value1 = '%s', value2 = '%s' WHERE id = %d",
            $this->columnText(),
            $this->columnText(),
            $this->ids['proposal']
        ));
    }

    private function columnText()
    {
        return "column-{$this->token}";
    }

    /**
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
        $this->shadow->Attribute;
        $this->attribute->Event->Attribute;
        $this->attribute->Event->ShadowAttribute;
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
     * Every attribute or proposal row in a payload: its values, all of 2.x's
     * columns, no value ids, no column text anywhere.
     */
    private function assertPayload($payload, $alias, $name)
    {
        $encoded = json_encode($payload);
        $this->assertStringNotContainsString($this->columnText(), $encoded);
        foreach (self::ID_KEYS as $key) {
            $this->assertStringNotContainsString($key, $encoded);
        }
        $row = $payload[$alias];
        $this->assertSame($this->expected[$name], [$row['value1'], $row['value2'], $row['value']], $encoded);
        if ($alias === 'Attribute') {
            $this->assertSame([], array_values(array_diff($this->columns, array_keys($row))), 'columns missing');
        }
    }

    /**
     * @return array transport (a workflow by its trigger) => payload, for the
     *  transports that carry an attribute or proposal row
     */
    private function byTransport(array $published)
    {
        $payloads = [];
        foreach ($published as $entry) {
            switch ($entry['transport']) {
                case 'attribute_save':
                    $payloads['pubsub'] = $entry['args'][0];
                    break;
                case 'publishJson':
                    $payloads['kafka'] = $entry['args'][1];
                    break;
                case 'workflow':
                    $payloads['workflow:' . $entry['args'][0]] = $entry['args'][1];
                    break;
            }
        }
        return $payloads;
    }

    public function testFetchAttributeTakesTheValuesFromTheDictionary()
    {
        foreach (['domain', 'composite', 'pipe_in_text'] as $name) {
            $this->assertPayload($this->attribute->fetchAttribute($this->ids[$name]), 'Attribute', $name);
        }
    }

    public function testAnEditAndADeletePublishTheDictionaryValues()
    {
        $names = ['domain', 'composite', 'pipe_in_text'];
        $captured = AttributePayloadOracle::capture(['attributes' => array_intersect_key($this->ids, array_flip($names))]);
        foreach ($names as $name) {
            $entry = $captured['attributes'][$name];
            $this->assertPayload($entry['fetch'], 'Attribute', $name);
            $this->assertTrue($entry['edit']['saved'], json_encode($entry['edit']['errors']));
            $edit = $this->byTransport($entry['edit']['published']);
            $this->assertSame(['pubsub', 'kafka', 'workflow:attribute-after-save'], array_keys($edit));
            foreach ($edit as $payload) {
                $this->assertPayload($payload, 'Attribute', $name);
            }
            $delete = $this->byTransport($entry['delete']);
            $this->assertSame(['pubsub', 'kafka'], array_keys($delete));
            foreach ($delete as $payload) {
                $this->assertPayload($payload, 'Attribute', $name);
            }
        }
    }

    public function testAProposalPublishesItsValues()
    {
        $captured = AttributePayloadOracle::capture(['proposals' => ['proposal' => $this->ids['proposal']]]);
        $entry = $captured['proposals']['proposal']['add'];
        $this->assertTrue($entry['saved'], json_encode($entry['errors']));
        $published = $this->byTransport($entry['published']);
        $this->assertSame(
            ['workflow:shadow-attribute-before-save', 'kafka', 'workflow:shadow-attribute-after-save'],
            array_keys($published)
        );
        foreach ($published as $payload) {
            $this->assertPayload($payload, 'ShadowAttribute', 'proposal');
        }
    }
}
