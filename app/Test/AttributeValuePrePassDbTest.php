<?php
/**
 * The pre-pass before bulk saves, against the configured MySQL/MariaDB
 * database: each site interns the values its saves will write before those
 * saves and before any transaction of its own, one chunk at a time, so the
 * saves themselves send the dictionary nothing.
 *
 * Every test runs in a transaction that is rolled back, which still spends
 * auto-increment ids. Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set, and it
 * boots the real application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValuePrePassDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValuePrePassDbTest extends TestCase
{
    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var PrePassRecordingAttributeValue */
    private $recorder;

    /** @var string */
    private $token;

    /** @var array */
    private $event;

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
            require_once __DIR__ . '/AttributeValuePrePassSupport.php';
            require_once __DIR__ . '/AttributeValueTextSupport.php';
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('Event')->Attribute;
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->db->begin();
        $this->token = 'avprepass' . bin2hex(random_bytes(4));
        $this->event = $this->attribute->Event->find('first', [
            'recursive' => -1,
            'order' => ['Event.id' => 'ASC'],
        ]);
        $this->recorder = new PrePassRecordingAttributeValue();
        $this->useDictionary($this->recorder);
    }

    protected function tearDown(): void
    {
        if ($this->db) {
            $this->db->rollback();
        }
        if ($this->recorder) {
            $this->useDictionary(null);
        }
    }

    private function useDictionary($model)
    {
        ClassRegistry::removeObject('AttributeValue');
        if ($model) {
            ClassRegistry::addObject('AttributeValue', $model);
        }
        foreach (ClassRegistry::keys() as $key) {
            $object = ClassRegistry::getObject($key);
            if ($object instanceof MispAttribute) {
                unset($object->AttributeValue);
            }
        }
    }

    private function user()
    {
        return ClassRegistry::init('User')->getAuthUser(1);
    }

    private function create($type, $value)
    {
        $this->attribute->create();
        $saved = $this->attribute->save(['Attribute' => [
            'event_id' => $this->event['Event']['id'],
            'type' => $type,
            'category' => $this->attribute->typeDefinitions[$type]['default_category'],
            'value' => $value,
            'distribution' => 5,
            'to_ids' => 0,
        ]]);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        return (int)$this->attribute->id;
    }

    /**
     * Rows whose ids are not the dictionary's ids for their text: the stored
     * text while the text columns exist, after that the text their save split
     * off, which the recorder kept.
     */
    private function mismatched($table, $where)
    {
        if (!AttributeValueTextSupport::present($this->db, $table)) {
            return $this->mismatchedOnTheSavedText($table, $where);
        }
        $statement = $this->db->rawQuery(sprintf(
            'SELECT t.id FROM %s t
             LEFT JOIN attribute_values v1 ON v1.id = t.value1_id
             LEFT JOIN attribute_values v2 ON v2.id = t.value2_id
             WHERE %s AND (
                v1.id IS NULL OR CAST(v1.value AS BINARY) <> CAST(t.value1 AS BINARY)
                OR (OCTET_LENGTH(t.value2) > 0 AND (v2.id IS NULL OR CAST(v2.value AS BINARY) <> CAST(t.value2 AS BINARY)))
                OR (COALESCE(OCTET_LENGTH(t.value2), 0) = 0 AND t.value2_id IS NOT NULL)
             )',
            $table,
            $where
        ));
        $ids = $statement->fetchAll(PDO::FETCH_COLUMN);
        $statement->closeCursor();
        return $ids;
    }

    private function mismatchedOnTheSavedText($table, $where)
    {
        $given = ['value1' => [], 'value2' => []];
        foreach ($this->recorder->assigned as list($column, $text, $id)) {
            if ($id === null ? $text === '' : $this->dictionaryText($id) === $text) {
                $given[$column][(string)$id] = true;
            }
        }
        $statement = $this->db->rawQuery("SELECT t.id, t.value1_id, t.value2_id FROM $table t WHERE $where");
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        $statement->closeCursor();
        $ids = [];
        foreach ($rows as $row) {
            if (!isset($given['value1'][(string)$row['value1_id']]) || !isset($given['value2'][(string)$row['value2_id']])) {
                $ids[] = $row['id'];
            }
        }
        return $ids;
    }

    private function dictionaryText($id)
    {
        $statement = $this->db->rawQuery(sprintf('SELECT value FROM attribute_values WHERE id = %d', $id));
        $text = $statement->fetchColumn();
        $statement->closeCursor();
        return $text;
    }

    private function rowCount($table, $where)
    {
        $statement = $this->db->rawQuery("SELECT COUNT(*) FROM $table WHERE $where");
        $count = (int)$statement->fetchColumn();
        $statement->closeCursor();
        return $count;
    }

    private function assertPrimedOutsideTransactions($minimumPrimes)
    {
        $primes = array_filter($this->recorder->callsOf('prime'), function ($call) {
            return $call['statements'] > 0;
        });
        $this->assertGreaterThanOrEqual($minimumPrimes, count($primes), json_encode($this->recorder->calls));
        foreach ($primes as $prime) {
            $this->assertSame(0, $prime['depth'], json_encode($this->recorder->calls));
        }
        $this->assertSame([], $this->recorder->callsOf('save'));
        $this->assertSame(0, $this->recorder->primedCount());
    }

    private function domainIpTemplate()
    {
        return ClassRegistry::init('ObjectTemplate')->find('first', [
            'recursive' => -1,
            'conditions' => ['ObjectTemplate.name' => 'domain-ip'],
            'order' => ['ObjectTemplate.version' => 'DESC'],
        ])['ObjectTemplate'];
    }

    public function testAddPrimesTheValuesItsSavesWrite()
    {
        $template = $this->domainIpTemplate();
        $data = ['Event' => [
            'info' => "pre-pass {$this->token}",
            'date' => date('Y-m-d'),
            'distribution' => 0,
            'threat_level_id' => 4,
            'analysis' => 0,
            'Attribute' => [
                ['type' => 'domain', 'category' => 'Network activity', 'value' => strtoupper("{$this->token}.example.org")],
                ['type' => 'url', 'category' => 'Network activity', 'value' => "hxxp://{$this->token}.example.org/x"],
                ['type' => 'ip-dst|port', 'category' => 'Network activity', 'value' => '2001:0db8:0000:0000:0000:0000:0000:0042|443'],
                ['type' => 'domain', 'category' => 'Network activity', 'value' => "  {$this->token}.example.net  "],
                ['type' => 'text', 'category' => 'Other', 'value' => "{$this->token} text"],
            ],
            'Object' => [],
        ]];
        foreach (['198.51.100.76', '198.51.100.77'] as $i => $ip) {
            $data['Event']['Object'][] = [
                'name' => 'domain-ip',
                'meta-category' => $template['meta-category'],
                'description' => $template['description'],
                'template_uuid' => $template['uuid'],
                'template_version' => $template['version'],
                'distribution' => 5,
                'Attribute' => [
                    ['type' => 'domain', 'object_relation' => 'domain', 'category' => 'Network activity', 'value' => "obj$i-{$this->token}.example.org"],
                    ['type' => 'ip-dst', 'object_relation' => 'ip', 'category' => 'Network activity', 'value' => $ip],
                ],
            ];
        }
        $created = 0;
        $errors = [];

        $result = $this->attribute->Event->_add($data, false, $this->user(), 0, null, false, null, $created, $errors);
        $created = (int)$this->attribute->Event->id;

        $this->assertTrue($result, json_encode($errors));
        $this->assertGreaterThan(0, $created);
        $this->assertSame(9, $this->rowCount('attributes', "event_id = $created"));
        $this->assertSame([], $this->mismatched('attributes', "t.event_id = $created"));
        $this->assertPrimedOutsideTransactions(2);
        // One pre-pass for the attributes, one for every object; captureObject then finds its values primed
        $costly = array_filter($this->recorder->callsOf('prime'), function ($call) {
            return $call['statements'] > 0;
        });
        $this->assertSame([6, 4], array_column(array_values($costly), 'values'));
    }

    public function testTheOriginalFileIsPrimed()
    {
        $directory = sys_get_temp_dir() . '/avprepass-' . $this->token;
        mkdir($directory);
        $previous = Configure::read('MISP.attachments_dir');
        Configure::write('MISP.attachments_dir', $directory);
        try {
            $this->attribute->Event->add_original_file(
                "original {$this->token}",
                "{$this->token}.txt",
                $this->event['Event']['id'],
                "format-{$this->token}"
            );
        } finally {
            Configure::write('MISP.attachments_dir', $previous);
            exec('rm -rf ' . escapeshellarg($directory));
        }

        $where = sprintf(
            "t.event_id = %d AND %s IN ('%s.txt', 'format-%s')",
            $this->event['Event']['id'],
            AttributeValueTextSupport::text('t', 'value1'),
            $this->token,
            $this->token
        );
        $this->assertSame(2, $this->rowCount('attributes t', $where));
        $this->assertSame([], $this->mismatched('attributes', $where));
        $this->assertPrimedOutsideTransactions(1);
    }

    public function testPrimedChunksHoldOneChunkAtATime()
    {
        $rows = [];
        for ($i = 0; $i < 5; $i++) {
            $rows[] = ['type' => 'domain', 'value' => "c$i-{$this->token}.example.org"];
        }

        $held = [];
        foreach ($this->attribute->primedChunks($rows, 2) as $chunk) {
            $held[] = $this->recorder->primedCount();
        }
        $this->assertSame([2, 2, 1], $held);
        $this->assertSame(0, $this->recorder->primedCount());

        foreach ($this->attribute->primedChunks($rows, 2) as $chunk) {
            break;
        }
        $this->assertSame(0, $this->recorder->primedCount());
    }

    public function testEditAttributeBulkPrimesBeforeItsTransaction()
    {
        $hostId = $this->create('hostname|port', "{$this->token}.example.org|8443");
        $domainId = $this->create('domain', "{$this->token}.example.net");
        $this->recorder->calls = [];
        $rows = [];
        foreach ([
            $hostId => ['hostname|port', "edited-{$this->token}.example.org|9443"],
            $domainId => ['domain', strtoupper("edited-{$this->token}.example.net")],
        ] as $id => list($type, $value)) {
            $uuid = $this->attribute->find('first', [
                'recursive' => -1,
                'conditions' => ['Attribute.id' => $id],
                'fields' => ['uuid'],
            ])['Attribute']['uuid'];
            $rows[] = [
                'id' => $id,
                'uuid' => $uuid,
                'event_id' => $this->event['Event']['id'],
                'object_id' => 0,
                'type' => $type,
                'category' => 'Network activity',
                'value' => $value,
                'to_ids' => 0,
                'distribution' => 5,
                'sharing_group_id' => 0,
                'timestamp' => time() + 1,
            ];
        }

        $this->attribute->editAttributeBulk($rows, $this->event, $this->user());

        $this->assertSame([], $this->mismatched('attributes', "t.id IN ($hostId, $domainId)"));
        $this->assertSame(
            "edited-{$this->token}.example.net",
            $this->attribute->find('first', [
                'recursive' => -1,
                'conditions' => ['Attribute.id' => $domainId],
                'fields' => ['value1'],
            ])['Attribute']['value1']
        );
        $this->assertPrimedOutsideTransactions(1);
    }

    public function testCaptureObjectPrimesItsAttributes()
    {
        $template = $this->domainIpTemplate();

        $this->attribute->Event->Object->captureObject([
            'name' => 'domain-ip',
            'meta-category' => $template['meta-category'],
            'description' => $template['description'],
            'template_uuid' => $template['uuid'],
            'template_version' => $template['version'],
            'distribution' => 5,
            'Attribute' => [
                ['type' => 'domain', 'object_relation' => 'domain', 'category' => 'Network activity', 'value' => "obj-{$this->token}.example.org"],
                ['type' => 'ip-dst', 'object_relation' => 'ip', 'category' => 'Network activity', 'value' => '198.51.100.78'],
            ],
        ], $this->event['Event']['id'], $this->user(), false);

        $objectId = (int)$this->attribute->Event->Object->id;
        $this->assertSame(2, $this->rowCount('attributes', "object_id = $objectId"));
        $this->assertSame([], $this->mismatched('attributes', "t.object_id = $objectId"));
        $this->assertPrimedOutsideTransactions(1);
    }

    public function testSaveAttributesPrimesItsRows()
    {
        $objectId = 0;
        $rows = [];
        foreach (['domain' => strtoupper("sa-{$this->token}.example.org"), 'ip-dst' => '198.51.100.82'] as $type => $value) {
            $rows[] = [
                'event_id' => $this->event['Event']['id'],
                'object_id' => $objectId,
                'type' => $type,
                'category' => 'Network activity',
                'value' => $value,
                'to_ids' => 0,
            ];
        }

        $this->assertTrue($this->attribute->saveAttributes($rows, $this->user()));

        $where = sprintf(
            "t.event_id = %d AND %s IN ('sa-%s.example.org', '198.51.100.82')",
            $this->event['Event']['id'],
            AttributeValueTextSupport::text('t', 'value1'),
            $this->token
        );
        $this->assertSame(2, $this->rowCount('attributes t', $where));
        $this->assertSame([], $this->mismatched('attributes', $where));
        $this->assertPrimedOutsideTransactions(1);
    }

    public function testFeedDataIsPrimedPerSavedChunk()
    {
        $user = $this->user();
        $data = [];
        for ($i = 0; $i < 150; $i++) {
            $data[] = ['type' => 'domain', 'category' => 'Network activity', 'value' => "f$i-{$this->token}.example.org", 'to_ids' => 0];
        }
        $feed = ['Feed' => [
            'id' => 0,
            'name' => "feed {$this->token}",
            'fixed_event' => 0,
            'event_id' => 0,
            'orgc_id' => $user['org_id'],
            'distribution' => 0,
            'sharing_group_id' => 0,
            'override_ids' => 0,
            'publish' => 0,
            'tag_id' => 0,
            'tag_collection_id' => 0,
            'delta_merge' => 0,
            'settings' => [],
        ]];

        ClassRegistry::init('Feed')->saveFreetextFeedData($feed, $data, $user);

        $eventId = (int)$this->attribute->Event->field('id', ['Event.info' => "feed {$this->token} feed"]);
        $this->assertSame(150, $this->rowCount('attributes', "event_id = $eventId"));
        $this->assertSame([], $this->mismatched('attributes', "t.event_id = $eventId"));
        $this->assertPrimedOutsideTransactions(2);
    }

    public function testPulledProposalsArePrimedPerPage()
    {
        App::uses('ServerSyncTool', 'Tools');
        $org = $this->attribute->Event->Orgc->find('first', [
            'recursive' => -1,
            'conditions' => ['Orgc.id' => $this->event['Event']['orgc_id']],
        ])['Orgc'];
        $proposals = [];
        foreach (['198.51.100.79|53', '198.51.100.80|53', '198.51.100.81|8080'] as $i => $value) {
            $proposals[] = ['ShadowAttribute' => [
                'event_uuid' => $this->event['Event']['uuid'],
                'uuid' => CakeText::uuid(),
                'type' => 'ip-src|port',
                'category' => 'Network activity',
                'value' => $value,
                'comment' => $this->token,
                'to_ids' => 0,
                'timestamp' => time(),
                'Org' => ['name' => $org['name'], 'uuid' => $org['uuid']],
            ]];
        }
        $sync = new class($proposals) extends ServerSyncTool {
            private $pages;

            public function __construct(array $proposals)
            {
                $this->pages = [$proposals];
            }

            public function isSupported($flag)
            {
                return true;
            }

            public function debug($message)
            {
            }

            public function fetchProposals(array $params = [])
            {
                $page = array_shift($this->pages) ?? [];
                return new class($page) {
                    private $page;

                    public function __construct(array $page)
                    {
                        $this->page = $page;
                    }

                    public function json()
                    {
                        return $this->page;
                    }
                };
            }
        };

        $fetched = ClassRegistry::init('ShadowAttribute')->pullProposals($this->user(), $sync);

        $where = sprintf("comment = '%s'", $this->token);
        $this->assertSame(3, $fetched);
        $this->assertSame(3, $this->rowCount('shadow_attributes', $where));
        $this->assertSame([], $this->mismatched('shadow_attributes', "t.$where"));
        $this->assertPrimedOutsideTransactions(1);
    }

    /**
     * @param bool $dryRun
     * @return array [the results in order, the yielded keys, values primed when each result came]
     */
    private function normalizeIps($dryRun)
    {
        $results = $keys = $held = [];
        foreach ($this->attribute->normalizeIpAddress($dryRun, 2) as $key => $result) {
            $keys[] = $key;
            $results[] = $result;
            $held[$result['id']] = $this->recorder->primedCount();
        }
        return [$results, $keys, $held];
    }

    public function testNormalizeIpAddressPrimesEachChunk()
    {
        $planted = [];
        foreach ([
            ['ip-dst', '', '2001:0DB8:0000:0000:0000:0000:%04X:0001'],
            ['ip-src', '', '2001:0DB8:0000:0000:0000:0000:%04X:0002/128'],
            ['domain|ip', strtoupper("dip-{$this->token}.example.org") . '|', '2001:0DB8:0000:0000:0000:0000:%04X:0003'],
        ] as list($type, $prefix, $format)) {
            $long = $prefix . sprintf($format, random_int(0x1000, 0xffff));
            $normalized = AttributeValidationTool::modifyBeforeValidation($type, $long);
            $id = $this->create($type, $normalized);
            $parts = explode('|', $long);
            $ids = $this->recorder->internMany($parts);
            // A row stored before the normalisation existed
            $this->db->rawQuery(sprintf(
                'UPDATE attributes SET value1_id = %d, value2_id = %s WHERE id = %d',
                $ids[$parts[0]],
                isset($parts[1]) ? $ids[$parts[1]] : 'NULL',
                $id
            ));
            AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf(
                "UPDATE attributes SET value1 = '%s', value2 = '%s' WHERE id = %d",
                $parts[0],
                $parts[1] ?? '',
                $id
            ));
            $planted[$id] = [$long, $normalized];
        }
        $where = 't.id IN (' . implode(', ', array_keys($planted)) . ')';
        $this->recorder->calls = [];

        list($results) = $this->normalizeIps(true);
        $this->assertSame([], $this->recorder->calls);
        foreach ($planted as $id => list($long, $normalized)) {
            $this->assertSame(explode('|', $long)[0], $this->attribute->find('first', [
                'recursive' => -1,
                'conditions' => ['Attribute.id' => $id],
                'fields' => ['value1'],
            ])['Attribute']['value1']);
        }

        list($results, $keys, $held) = $this->normalizeIps(false);
        $this->assertSame(array_keys($results), $keys);
        $ours = [];
        foreach ($results as $result) {
            if (isset($planted[$result['id']])) {
                $ours[$result['id']] = [$result['value'], $result['normalized_value']];
            }
        }
        $this->assertSame($planted, $ours);
        $this->assertSame([], $this->mismatched('attributes', $where));
        foreach ($planted as $id => list($long, $normalized)) {
            $statement = $this->db->rawQuery(sprintf(
                "SELECT CONCAT_WS('|', %s, NULLIF(%s, '')) FROM attributes WHERE id = %d",
                AttributeValueTextSupport::text('attributes', 'value1'),
                AttributeValueTextSupport::text('attributes', 'value2'),
                $id
            ));
            $this->assertSame($normalized, $statement->fetchColumn());
            $statement->closeCursor();
        }
        // Two changed attributes per chunk, each primed before its saves
        $this->assertCount((int)ceil(count($results) / 2), $this->recorder->callsOf('prime'));
        foreach (array_keys($planted) as $id) {
            $this->assertGreaterThan(0, $held[$id]);
        }
        $this->assertPrimedOutsideTransactions(2);
    }

    public function testATemplateIsPrimedBeforeItsTransaction()
    {
        App::uses('EventTemplateInstantiator', 'Tools');
        $definition = [
            'schema_version' => 1,
            'uuid' => CakeText::uuid(),
            'name' => "pre-pass {$this->token}",
            'event_defaults' => ['distribution' => 0],
            'structure' => [[
                'type' => 'attribute_field',
                'id' => 'domains',
                'label' => 'Domains',
                'misp' => ['category' => 'Network activity', 'type' => 'domain'],
            ]],
        ];
        $input = ['domains' => ["t1-{$this->token}.example.org", strtoupper("t2-{$this->token}.example.org")]];

        $result = (new EventTemplateInstantiator())->instantiate($definition, $input, $this->user());

        $eventId = (int)$result['event_id'];
        $this->assertSame(2, $this->rowCount('attributes', "event_id = $eventId"));
        $this->assertSame([], $this->mismatched('attributes', "t.event_id = $eventId"));
        $this->assertPrimedOutsideTransactions(1);
    }
}
