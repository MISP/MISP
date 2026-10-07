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
            App::uses('ClassRegistry', 'Utility');
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
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
}
