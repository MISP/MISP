<?php
/**
 * The attribute and proposal save paths against the configured MySQL/MariaDB
 * database: value1_id and value2_id come from the values, never from the
 * caller, and stay out of the change logs.
 *
 * Every test runs in a transaction that is rolled back, which still spends
 * auto-increment ids. Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set, and it
 * boots the real application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueWritePathDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueWritePathDbTest extends TestCase
{
    const FORGED = ['value1_id' => 9000000001, 'value2_id' => 9000000002];

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var string Keeps the test values apart from real ones. */
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
            require_once __DIR__ . '/AttributeValueTextSupport.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('AttributeValue', 'Model');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            // Skipped before the fixture exists: nothing for tearDown to clean up
            $this->db = null;
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->db->begin();
        $this->token = 'avwrite' . bin2hex(random_bytes(4));
        $this->event = $this->attribute->Event->find('first', [
            'recursive' => -1,
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id', 'Event.uuid', 'Event.orgc_id'],
        ])['Event'];
    }

    protected function tearDown(): void
    {
        if ($this->db) {
            $this->db->rollback();
        }
    }

    private function create(array $fields)
    {
        $this->attribute->create();
        $saved = $this->attribute->save(['Attribute' => $fields + [
            'event_id' => $this->event['id'],
            'category' => 'Network activity',
            'distribution' => 5,
            'to_ids' => 0,
        ]]);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        return (int)$this->attribute->id;
    }

    private function storedIds($table, $id)
    {
        $statement = $this->db->rawQuery(sprintf(
            'SELECT value1_id, value2_id FROM %s WHERE id = %d',
            $table,
            $id
        ));
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        $statement->closeCursor();
        return [
            $row['value1_id'] === null ? null : (int)$row['value1_id'],
            $row['value2_id'] === null ? null : (int)$row['value2_id'],
        ];
    }

    private function dictionaryIds(array $values)
    {
        $ids = $this->attribute->loadAttributeValue()->internMany($values);
        return array_map(function ($value) use ($ids) {
            return $ids[$value];
        }, $values);
    }

    /**
     * Columns of a stored row; value1 and value2 as the ids give them back.
     */
    private function stored($id, array $columns)
    {
        $select = array_map(function ($column) {
            return in_array($column, ['value1', 'value2'], true)
                ? AttributeValueTextSupport::text('attributes', $column) . ' AS ' . $column
                : $column;
        }, $columns);
        $statement = $this->db->rawQuery(sprintf(
            'SELECT %s FROM attributes WHERE id = %d',
            implode(', ', $select),
            $id
        ));
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        $statement->closeCursor();
        return $row;
    }

    private function user()
    {
        return ClassRegistry::init('User')->getAuthUser(1);
    }

    private function dictionaryHas($value)
    {
        $hash = bin2hex($this->attribute->loadAttributeValue()->hashOf($value));
        $statement = $this->db->rawQuery("SELECT COUNT(*) FROM attribute_values WHERE hash = X'$hash'");
        $count = (int)$statement->fetchColumn();
        $statement->closeCursor();
        return $count > 0;
    }

    private function maxLogId()
    {
        $statement = $this->db->rawQuery('SELECT IFNULL(MAX(id), 0) FROM logs');
        $id = (int)$statement->fetchColumn();
        $statement->closeCursor();
        return $id;
    }

    private function logChanges($after, $model, $id)
    {
        $statement = $this->db->rawQuery(sprintf(
            "SELECT `change` FROM logs WHERE id > %d AND model = '%s' AND model_id = %d ORDER BY id",
            $after,
            $model,
            $id
        ));
        $changes = $statement->fetchAll(PDO::FETCH_COLUMN);
        $statement->closeCursor();
        return $changes;
    }

    public function testASaveIgnoresTheIdsSentIn()
    {
        $host = "{$this->token}.example.org";
        $id = $this->create(['type' => 'hostname|port', 'value' => "$host|8443"] + self::FORGED);

        $this->assertSame($this->dictionaryIds([$host, '8443']), $this->storedIds('attributes', $id));
    }

    public function testANonCompositeHasNoValue2Row()
    {
        $domain = "{$this->token}.example.org";
        $id = $this->create(['type' => 'domain', 'value' => $domain] + self::FORGED);

        $this->assertSame([$this->dictionaryIds([$domain])[0], null], $this->storedIds('attributes', $id));
    }

    public function testAProposalIgnoresTheIdsSentIn()
    {
        $proposal = ClassRegistry::init('ShadowAttribute');
        $logsBefore = $this->maxLogId();
        $ip = '198.51.100.' . random_int(1, 254);
        $port = (string)random_int(1024, 65535);
        $proposal->create();
        $saved = $proposal->save(['ShadowAttribute' => [
            'event_id' => $this->event['id'],
            'event_uuid' => $this->event['uuid'],
            'event_org_id' => $this->event['orgc_id'],
            'org_id' => $this->event['orgc_id'],
            'old_id' => 0,
            'type' => 'ip-src|port',
            'category' => 'Network activity',
            'value' => "$ip|$port",
            'comment' => $this->token,
        ] + self::FORGED]);
        $this->assertNotFalse($saved, json_encode($proposal->validationErrors));

        $this->assertSame(
            $this->dictionaryIds([$ip, $port]),
            $this->storedIds('shadow_attributes', (int)$proposal->id)
        );
        if (!Configure::read('MISP.log_new_audit')) {
            $changes = implode("\n", $this->logChanges($logsBefore, 'ShadowAttribute', (int)$proposal->id));
            $this->assertStringContainsString("=> ($ip)", $changes);
            $this->assertStringNotContainsString('value1_id', $changes);
            $this->assertStringNotContainsString('value2_id', $changes);
        }
    }

    public function testTheProposalWorkflowsAndKafkaNeverSeeTheIds()
    {
        require_once __DIR__ . '/AttributePayloadOracleSupport.php';
        ClassRegistry::removeObject('ShadowAttribute');
        $proposal = ClassRegistry::init([
            'class' => 'PayloadRecordingShadowAttribute', 'alias' => 'ShadowAttribute',
        ]);
        try {
            PayloadRecorder::take();
            $proposal->create();
            $saved = $proposal->save(['ShadowAttribute' => [
                'event_id' => $this->event['id'],
                'event_uuid' => $this->event['uuid'],
                'event_org_id' => $this->event['orgc_id'],
                'org_id' => $this->event['orgc_id'],
                'old_id' => 0,
                'type' => 'domain',
                'category' => 'Network activity',
                'value' => "{$this->token}.example.org",
            ] + self::FORGED]);
            $published = PayloadRecorder::take();
        } finally {
            ClassRegistry::removeObject('ShadowAttribute');
        }

        $this->assertNotFalse($saved, json_encode($proposal->validationErrors));
        $this->assertSame(['workflow', 'publishJson', 'workflow'], array_column($published, 'transport'));
        $json = json_encode($published);
        $this->assertStringContainsString("\"value1\":\"{$this->token}.example.org\"", $json);
        $this->assertStringNotContainsString('value1_id', $json);
        $this->assertStringNotContainsString('value2_id', $json);
        $this->assertNotNull($this->storedIds('shadow_attributes', (int)$proposal->id)[0]);
    }

    public function testAValueChangeMovesTheIds()
    {
        $id = $this->create(['type' => 'domain', 'value' => "{$this->token}.example.org"]);
        $edited = "edited-{$this->token}.example.org";

        $saved = $this->attribute->save(['Attribute' => [
            'id' => $id,
            'event_id' => $this->event['id'],
            'type' => 'domain',
            'category' => 'Network activity',
            'value' => $edited,
        ] + self::FORGED]);

        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $this->assertSame([$this->dictionaryIds([$edited])[0], null], $this->storedIds('attributes', $id));
    }

    public function testAFieldListNamingTheIdsCannotWriteThem()
    {
        $id = $this->create(['type' => 'domain', 'value' => "{$this->token}.example.org"]);
        $before = $this->storedIds('attributes', $id);

        $saved = $this->attribute->save(['Attribute' => [
            'id' => $id,
            'event_id' => $this->event['id'],
            'type' => 'domain',
            'category' => 'Network activity',
            'value' => "{$this->token}.example.org",
            'comment' => $this->token,
        ] + self::FORGED], ['fieldList' => ['comment', 'value1_id', 'value2_id']]);

        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $this->assertSame($before, $this->storedIds('attributes', $id));
    }

    public function testAFieldListWithoutTheValueColumnsInternsNothing()
    {
        $id = $this->create(['type' => 'domain', 'value' => "{$this->token}.example.org"]);
        $before = $this->storedIds('attributes', $id);
        $unwritten = "unwritten-{$this->token}.example.org";

        $saved = $this->attribute->save(['Attribute' => [
            'id' => $id,
            'event_id' => $this->event['id'],
            'type' => 'domain',
            'category' => 'Network activity',
            'value' => $unwritten,
            'timestamp' => time() + 1,
        ] + self::FORGED], ['fieldList' => ['timestamp']]);

        $this->assertNotFalse($saved);
        $this->assertSame($before, $this->storedIds('attributes', $id));
        $this->assertFalse($this->dictionaryHas($unwritten));
    }

    public function testCaptureAttributeKeepsTheIds()
    {
        $host = "{$this->token}.example.org";

        $this->attribute->captureAttribute([
            'type' => 'hostname|port',
            'category' => 'Network activity',
            'value' => "$host|8443",
            'distribution' => 5,
        ] + self::FORGED, $this->event['id'], $this->user());

        $this->assertNotEmpty($this->attribute->id, json_encode($this->attribute->validationErrors));
        $this->assertSame($this->dictionaryIds([$host, '8443']), $this->storedIds('attributes', (int)$this->attribute->id));
    }

    public function testTheEditFieldListKeepsTheIds()
    {
        $id = $this->create(['type' => 'hostname|port', 'value' => "{$this->token}.example.org|8443"]);
        $edited = "edited-{$this->token}.example.org";

        $saved = $this->attribute->save(['Attribute' => [
            'id' => $id,
            'event_id' => $this->event['id'],
            'type' => 'hostname|port',
            'category' => 'Network activity',
            'value' => "$edited|9443",
        ] + self::FORGED], ['fieldList' => MispAttribute::EDITABLE_FIELDS]);

        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $this->assertSame($this->dictionaryIds([$edited, '9443']), $this->storedIds('attributes', $id));
    }

    public function testEditAttributeBulkKeepsTheIdsOfTheRowsItSaves()
    {
        $user = $this->user();
        $event = $this->attribute->Event->find('first', [
            'recursive' => -1,
            'conditions' => ['Event.id' => $this->event['id']],
        ]);
        $hostId = $this->create(['type' => 'hostname|port', 'value' => "{$this->token}.example.org|8443"]);
        $domainId = $this->create(['type' => 'domain', 'value' => "{$this->token}.example.net"]);
        $culledId = $this->create(['type' => 'ip-dst', 'value' => '192.0.2.' . random_int(1, 254)]);
        $culledBefore = $this->storedIds('attributes', $culledId);
        $rows = [];
        foreach ([
            $hostId => ['hostname|port', "edited-{$this->token}.example.org|9443"],
            $domainId => ['domain', "edited-{$this->token}.example.net"],
            $culledId => ['ip-dst', "invalid-{$this->token}"],
        ] as $id => list($type, $value)) {
            $rows[] = [
                'id' => $id,
                'uuid' => $this->stored($id, ['uuid'])['uuid'],
                'event_id' => $this->event['id'],
                'object_id' => 0,
                'type' => $type,
                'category' => 'Network activity',
                'value' => $value,
                'to_ids' => 0,
                'distribution' => 5,
                'sharing_group_id' => 0,
                'timestamp' => time() + 1,
            ] + self::FORGED;
        }

        $this->attribute->editAttributeBulk($rows, $event, $user);

        $this->assertSame(
            $this->dictionaryIds(["edited-{$this->token}.example.org", '9443']),
            $this->storedIds('attributes', $hostId)
        );
        $this->assertSame(
            [$this->dictionaryIds(["edited-{$this->token}.example.net"])[0], null],
            $this->storedIds('attributes', $domainId)
        );
        $this->assertSame($culledBefore, $this->storedIds('attributes', $culledId));
        $this->assertFalse($this->dictionaryHas("invalid-{$this->token}"));
    }

    public function testAPerAliasFieldListKeepsTheIds()
    {
        // The list saveAssociated hands the attributes of an OpenIOC import
        $fieldList = [
            'Event' => ['published', 'timestamp'],
            'Attribute' => [
                'event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid',
                'distribution', 'timestamp', 'comment', 'sharing_group_id',
            ],
        ];
        $host = "{$this->token}.example.org";

        $saved = $this->attribute->saveMany([[
            'event_id' => $this->event['id'],
            'type' => 'hostname|port',
            'category' => 'Network activity',
            'value' => "$host|8443",
            'to_ids' => 0,
            'distribution' => 5,
            'sharing_group_id' => 0,
        ] + self::FORGED], ['atomic' => false, 'validate' => true, 'fieldList' => $fieldList]);

        $this->assertSame([true], $saved, json_encode($this->attribute->validationErrors));
        $this->assertSame($this->dictionaryIds([$host, '8443']), $this->storedIds('attributes', (int)$this->attribute->id));
    }

    public function testAFieldListLastsOneSave()
    {
        $id = $this->create(['type' => 'domain', 'value' => "{$this->token}.example.org"]);
        $row = [
            'id' => $id,
            'event_id' => $this->event['id'],
            'type' => 'domain',
            'category' => 'Network activity',
        ];

        $first = "first-{$this->token}.example.org";
        $saved = $this->attribute->save(['Attribute' => $row + ['value' => $first]], true, ['value1', 'value2']);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $this->assertSame([], $this->attribute->whitelist);
        $this->assertSame([$this->dictionaryIds([$first])[0], null], $this->storedIds('attributes', $id));

        $unwritten = "unwritten-{$this->token}.example.org";
        $saved = $this->attribute->save(
            ['Attribute' => $row + ['value' => $unwritten, 'comment' => $this->token]],
            ['fieldList' => ['comment']]
        );
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $this->assertSame([], $this->attribute->whitelist);
        $this->assertSame([$this->dictionaryIds([$first])[0], null], $this->storedIds('attributes', $id));
        $this->assertSame(['value1' => $first, 'comment' => $this->token], $this->stored($id, ['value1', 'comment']));
        $this->assertFalse($this->dictionaryHas($unwritten));

        $last = "last-{$this->token}.example.org";
        $saved = $this->attribute->save(['Attribute' => $row + ['value' => $last, 'to_ids' => 1]]);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $this->assertSame([$this->dictionaryIds([$last])[0], null], $this->storedIds('attributes', $id));
        $this->assertSame(['value1' => $last, 'to_ids' => '1'], $this->stored($id, ['value1', 'to_ids']));
    }

    public function testAProposalFieldListKeepsTheIds()
    {
        $proposal = ClassRegistry::init('ShadowAttribute');
        $row = [
            'event_id' => $this->event['id'],
            'event_uuid' => $this->event['uuid'],
            'event_org_id' => $this->event['orgc_id'],
            'org_id' => $this->event['orgc_id'],
            'old_id' => 0,
            'type' => 'domain',
            'category' => 'Network activity',
        ];
        $proposal->create();
        $saved = $proposal->save(['ShadowAttribute' => $row + ['value' => "{$this->token}.example.org"]]);
        $this->assertNotFalse($saved, json_encode($proposal->validationErrors));
        $id = (int)$proposal->id;
        $edited = "edited-{$this->token}.example.org";

        $saved = $proposal->save(
            ['ShadowAttribute' => $row + ['id' => $id, 'value' => $edited] + self::FORGED],
            ['fieldList' => ['value1', 'value2']]
        );

        $this->assertNotFalse($saved, json_encode($proposal->validationErrors));
        $this->assertSame([$this->dictionaryIds([$edited])[0], null], $this->storedIds('shadow_attributes', $id));
        $this->assertSame([], $proposal->whitelist);
    }

    public function testTheSyslogChangeLeavesTheIdsOut()
    {
        if (Configure::read('MISP.log_new_audit')) {
            $this->markTestSkipped('SysLogLogable is off while the audit log is on.');
        }
        // The oracle restore keeps the logs table but reuses attribute ids
        $logsBefore = $this->maxLogId();
        $id = $this->create(['type' => 'domain', 'value' => "{$this->token}.example.org"]);
        $this->attribute->save(['Attribute' => [
            'id' => $id,
            'event_id' => $this->event['id'],
            'type' => 'domain',
            'category' => 'Network activity',
            'value' => "edited-{$this->token}.example.org",
        ]]);

        $changes = $this->logChanges($logsBefore, 'Attribute', $id);

        $this->assertCount(2, $changes, json_encode($changes));
        $this->assertStringContainsString("=> ({$this->token}.example.org)", $changes[0]);
        $this->assertStringContainsString("=> (edited-{$this->token}.example.org)", $changes[1]);
        $this->assertStringNotContainsString('value1_id', implode("\n", $changes));
        $this->assertStringNotContainsString('value2_id', implode("\n", $changes));
    }

    public function testTheAuditLogChangeLeavesTheIdsOut()
    {
        $id = $this->create(['type' => 'domain', 'value' => "{$this->token}.example.org"]);
        $audit = ClassRegistry::init('AuditLog');
        $previous = Configure::read('MISP.log_new_audit');
        Configure::write('MISP.log_new_audit', true);
        try {
            $behavior = new AuditLogBehavior();
            $behavior->setup($this->attribute);
            $this->attribute->id = $id;
            $behavior->beforeSave($this->attribute, []);
            $this->attribute->data = ['Attribute' => [
                'id' => $id,
                'event_id' => $this->event['id'],
                'type' => 'domain',
                'category' => 'Network activity',
                'value1' => "edited-{$this->token}.example.org",
                'value2' => '',
                'value1_id' => 7,
                'value2_id' => null,
            ]];
            $behavior->afterSave($this->attribute, false, ['fieldList' => []]);
        } finally {
            Configure::write('MISP.log_new_audit', $previous);
        }

        $entry = $audit->find('first', [
            'conditions' => ['AuditLog.model' => 'Attribute', 'AuditLog.model_id' => $id],
            'order' => ['AuditLog.id' => 'DESC'],
        ]);
        $change = $entry['AuditLog']['change'];
        $this->assertSame(["{$this->token}.example.org", "edited-{$this->token}.example.org"], $change['value1']);
        $this->assertArrayNotHasKey('value1_id', $change);
        $this->assertArrayNotHasKey('value2_id', $change);
    }

    private function createTyped($type, $value)
    {
        return $this->create([
            'type' => $type,
            'category' => $this->attribute->typeDefinitions[$type]['default_category'],
            'value' => $value,
        ]);
    }

    private function proposal(array $fields)
    {
        $proposal = ClassRegistry::init('ShadowAttribute');
        $proposal->create();
        $saved = $proposal->save(['ShadowAttribute' => $fields + [
            'event_id' => $this->event['id'],
            'event_uuid' => $this->event['uuid'],
            'event_org_id' => $this->event['orgc_id'],
            'org_id' => $this->event['orgc_id'],
            'old_id' => 0,
            'category' => 'Network activity',
            'comment' => $this->token,
        ]]);
        $this->assertNotFalse($saved, json_encode($proposal->validationErrors));
        // What ShadowAttributesController::accept hands acceptProposal()
        return $proposal->find('first', [
            'recursive' => -1,
            'conditions' => ['ShadowAttribute.id' => $proposal->id, 'deleted' => 0],
        ]);
    }

    /**
     * @return string[] A documentation IPv6 address written out in full, and compressed
     */
    private function ipv6()
    {
        $long = sprintf('2001:0DB8:0000:0000:0000:0000:%04X:0000', random_int(0x1000, 0xffff));
        return [$long, inet_ntop(inet_pton($long))];
    }

    public function testATypeChangeThroughTheEditFieldListSplitsAgain()
    {
        $md5 = md5($this->token);
        $id = $this->createTyped('text', "{$this->token}.exe|$md5");
        $this->assertSame([$this->dictionaryIds(["{$this->token}.exe|$md5"])[0], null], $this->storedIds('attributes', $id));
        $existing = $this->attribute->find('first', [
            'recursive' => -1,
            'conditions' => ['Attribute.id' => $id],
        ])['Attribute'];

        // attributes/edit with only a new type: the controller recovers the rest from the stored row
        $request = ['type' => 'filename|md5', 'category' => 'Payload delivery'];
        foreach (['id', 'event_id', 'object_id', 'uuid'] as $field) {
            $request[$field] = $existing[$field];
        }
        $request['timestamp'] = time() + 1;
        foreach (['value', 'to_ids', 'distribution', 'comment', 'first_seen', 'last_seen'] as $field) {
            $request[$field] = $existing[$field];
        }
        $saved = $this->attribute->save(['Attribute' => $request], ['fieldList' => MispAttribute::EDITABLE_FIELDS]);

        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $this->assertSame(['value1' => "{$this->token}.exe", 'value2' => $md5], $this->stored($id, ['value1', 'value2']));
        $this->assertSame($this->dictionaryIds(["{$this->token}.exe", $md5]), $this->storedIds('attributes', $id));
    }

    public function testATypeChangeThroughEditFieldDropsTheValue2Id()
    {
        $sha256 = hash('sha256', $this->token);
        $id = $this->createTyped('filename|sha256', "{$this->token}.bin|$sha256");

        // attributes/editField
        $attribute = $this->attribute->fetchAttributeSimple($this->user(), [
            'conditions' => ['Attribute.id' => $id],
        ]);
        $attribute['Attribute']['type'] = 'text';
        $attribute['Attribute']['category'] = 'Other';
        $attribute['Attribute']['timestamp'] = time() + 1;
        $saved = $this->attribute->save($attribute);

        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $this->assertSame(['value1' => "{$this->token}.bin|$sha256", 'value2' => ''], $this->stored($id, ['value1', 'value2']));
        $this->assertSame([$this->dictionaryIds(["{$this->token}.bin|$sha256"])[0], null], $this->storedIds('attributes', $id));
    }

    public function testATypeChangeThroughEditAttributeBulkSplitsAgain()
    {
        $sha256 = hash('sha256', $this->token);
        $md5 = md5($this->token);
        // The same value split anew, and a value the new type also normalises
        $splitId = $this->createTyped('text', "{$this->token}.dll|$sha256");
        $normalisedId = $this->createTyped('text', "{$this->token}.sys|" . strtoupper($md5));
        $event = $this->attribute->Event->find('first', [
            'recursive' => -1,
            'conditions' => ['Event.id' => $this->event['id']],
        ]);
        $rows = [];
        foreach ([
            $splitId => ['filename|sha256', "{$this->token}.dll|$sha256"],
            $normalisedId => ['filename|md5', "{$this->token}.sys|" . strtoupper($md5)],
        ] as $id => list($type, $value)) {
            $rows[] = [
                'id' => $id,
                'uuid' => $this->stored($id, ['uuid'])['uuid'],
                'event_id' => $this->event['id'],
                'object_id' => 0,
                'type' => $type,
                'category' => 'Payload delivery',
                'value' => $value,
                'to_ids' => 0,
                'distribution' => 5,
                'sharing_group_id' => 0,
                'timestamp' => time() + 1,
            ] + self::FORGED;
        }

        $this->attribute->editAttributeBulk($rows, $event, $this->user());

        $this->assertSame(
            ['type' => 'filename|sha256', 'value1' => "{$this->token}.dll", 'value2' => $sha256],
            $this->stored($splitId, ['type', 'value1', 'value2'])
        );
        $this->assertSame($this->dictionaryIds(["{$this->token}.dll", $sha256]), $this->storedIds('attributes', $splitId));
        $this->assertSame(
            ['type' => 'filename|md5', 'value1' => "{$this->token}.sys", 'value2' => $md5],
            $this->stored($normalisedId, ['type', 'value1', 'value2'])
        );
        $this->assertSame($this->dictionaryIds(["{$this->token}.sys", $md5]), $this->storedIds('attributes', $normalisedId));
    }

    public function testAcceptingAnEditProposalWithANewTypeDerivesTheIds()
    {
        list(, $ip) = $this->ipv6();
        $id = $this->createTyped('ip-dst|port', "$ip|443");
        list($long, $proposedIp) = $this->ipv6();
        $proposal = $this->proposal([
            'old_id' => $id,
            'uuid' => $this->stored($id, ['uuid'])['uuid'],
            'type' => 'ip-dst',
            'value' => $long,
        ]);
        $proposal['ShadowAttribute'] += self::FORGED;

        $result = ClassRegistry::init('ShadowAttribute')->acceptProposal($this->user(), $proposal);

        $this->assertTrue($result['success'], json_encode($result));
        $this->assertSame(
            ['type' => 'ip-dst', 'value1' => $proposedIp, 'value2' => ''],
            $this->stored($id, ['type', 'value1', 'value2'])
        );
        $this->assertSame([$this->dictionaryIds([$proposedIp])[0], null], $this->storedIds('attributes', $id));
    }

    public function testAcceptingANewProposalDerivesTheIds()
    {
        $domain = "{$this->token}.example.org";
        list($long, $ip) = $this->ipv6();
        $proposal = $this->proposal([
            'type' => 'domain|ip',
            'value' => strtoupper($domain) . "|$long",
        ]);
        $proposal['ShadowAttribute'] += self::FORGED;

        $result = ClassRegistry::init('ShadowAttribute')->acceptProposal($this->user(), $proposal);

        $this->assertTrue($result['success'], json_encode($result));
        $statement = $this->db->rawQuery(sprintf(
            "SELECT id FROM attributes WHERE uuid = '%s' AND deleted = 0",
            $proposal['ShadowAttribute']['uuid']
        ));
        $id = (int)$statement->fetchColumn();
        $statement->closeCursor();
        $this->assertGreaterThan(0, $id);
        $this->assertSame(['value1' => $domain, 'value2' => $ip], $this->stored($id, ['value1', 'value2']));
        $this->assertSame($this->dictionaryIds([$domain, $ip]), $this->storedIds('attributes', $id));
    }

    public function testTheRegexpCleanRewriteMovesTheIds()
    {
        $id = $this->createTyped('domain', "{$this->token}-old.example.org");
        $regexp = ClassRegistry::init('Regexp');
        $regexp->create();
        $this->assertNotFalse($regexp->save(['Regexp' => [
            'regexp' => "/{$this->token}-old\\./",
            'replacement' => "{$this->token}-new.",
            'type' => 'ALL',
        ]]));
        $cache = new ReflectionProperty(RegexpBehavior::class, '__allRegexp');
        $cache->setAccessible(true);
        $cache->setValue($this->attribute->Behaviors->Regexp, null);
        try {
            // The loop body of RegexpController::admin_clean
            $allRegexp = $regexp->find('all');
            $item = $this->attribute->find('first', [
                'recursive' => -1,
                'conditions' => ['Attribute.id' => $id],
            ]);
            $result = $regexp->replaceSpecific($item['Attribute']['value'], $allRegexp, $item['Attribute']['type']);
            $this->assertSame(1, $result);
            $saved = $this->attribute->save($item);
        } finally {
            $cache->setValue($this->attribute->Behaviors->Regexp, null);
        }

        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        $this->assertSame(['value1' => "{$this->token}-new.example.org"], $this->stored($id, ['value1']));
        $this->assertSame([$this->dictionaryIds(["{$this->token}-new.example.org"])[0], null], $this->storedIds('attributes', $id));
    }
}
