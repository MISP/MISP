<?php
/**
 * The audit log and the syslog record value text, never ids, also once the
 * text columns are gone. The tests hide value1 and value2 from the model's
 * schema, the way the column drop will, and point the stored text away from
 * the dictionary, so a logger that still reads the columns shows it.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueLogDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueLogDbTest extends TestCase
{
    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var ShadowAttribute */
    private $proposal;

    /** @var DboSource */
    private $db;

    /** @var string Keeps the test values apart from real ones. */
    private $token;

    /** @var array */
    private $event;

    /** @var AuditLogBehavior */
    private $audit;

    /** @var bool|null */
    private $auditWasEnabled;

    /** @var string|null */
    private $sqlMode;

    /** @var bool */
    private $cachedMethods;

    /** @var bool */
    private $fullDebug;

    /** @var int */
    private $auditBefore;

    /** @var int */
    private $logsBefore;

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
        $this->proposal = ClassRegistry::init('ShadowAttribute');
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            // Skipped before the fixture exists: nothing for tearDown to clean up
            $this->db = null;
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        $this->db->begin();
        $this->token = 'avlog' . bin2hex(random_bytes(4));
        $this->event = $this->attribute->Event->find('first', [
            'recursive' => -1,
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id', 'Event.uuid', 'Event.orgc_id'],
        ])['Event'];

        // The behaviour reads its switch once per process
        $this->audit = $this->attribute->Behaviors->AuditLog;
        $enabled = new ReflectionProperty('AuditLogBehavior', 'enabled');
        $this->auditWasEnabled = $enabled->getValue($this->audit);
        $enabled->setValue($this->audit, true);

        // The logs tables survive restores while attribute ids are reused
        $this->auditBefore = $this->maxId('audit_logs');
        $this->logsBefore = $this->maxId('logs');
    }

    protected function tearDown(): void
    {
        if (!$this->audit) {
            return;
        }
        $this->db->cacheMethods = $this->cachedMethods;
        $this->db->fullDebug = $this->fullDebug;
        $this->attribute->schema(true);
        $this->proposal->schema(true);
        (new ReflectionProperty('AuditLogBehavior', 'enabled'))->setValue($this->audit, $this->auditWasEnabled);
        if ($this->sqlMode !== null) {
            $this->exec(sprintf("SET SESSION sql_mode = '%s'", $this->sqlMode));
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

    private function maxId($table)
    {
        return (int)$this->exec("SELECT IFNULL(MAX(id), 0) AS id FROM $table")[0]['id'];
    }

    private function hideTextColumns(Model $model)
    {
        $schema = $model->schema();
        unset($schema['value1'], $schema['value2']);
        (new ReflectionProperty('Model', '_schema'))->setValue($model, $schema);
        // Else a read of every column reuses a field list cached before
        $this->db->cacheMethods = false;
    }

    /**
     * An insert leaves out the text columns a hidden schema does not list,
     * which strict mode refuses while they still exist.
     */
    private function allowMissingTextColumns()
    {
        $this->sqlMode = $this->exec('SELECT @@SESSION.sql_mode AS mode')[0]['mode'];
        $modes = array_filter(explode(',', $this->sqlMode), function ($mode) {
            return strpos($mode, 'STRICT_') !== 0;
        });
        $this->exec(sprintf("SET SESSION sql_mode = '%s'", implode(',', $modes)));
    }

    /**
     * Points the stored text away from the dictionary, while the text columns
     * exist.
     */
    private function divergeStoredText($table, $id)
    {
        if (empty($this->exec("SHOW COLUMNS FROM $table LIKE 'value1'"))) {
            return;
        }
        $this->exec(sprintf(
            "UPDATE %s SET value1 = '%s', value2 = IF(value2 = '', '', '%s') WHERE id = %d",
            $table,
            $this->columnText(),
            $this->columnText(),
            $id
        ));
    }

    private function columnText()
    {
        return "column-{$this->token}";
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

    private function edit($id, $type, $value, array $options = [], array $fields = [])
    {
        $saved = $this->attribute->save(['Attribute' => $fields + [
            'id' => $id,
            'event_id' => $this->event['id'],
            'type' => $type,
            'category' => 'Network activity',
            'value' => $value,
        ]], $options);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
    }

    private function createProposal($type, $value)
    {
        $this->proposal->create();
        $saved = $this->proposal->save(['ShadowAttribute' => [
            'event_id' => $this->event['id'],
            'event_uuid' => $this->event['uuid'],
            'event_org_id' => $this->event['orgc_id'],
            'org_id' => $this->event['orgc_id'],
            'old_id' => 0,
            'type' => $type,
            'category' => 'Network activity',
            'value' => $value,
            'comment' => $this->token,
        ]]);
        $this->assertNotFalse($saved, json_encode($this->proposal->validationErrors));
        return (int)$this->proposal->id;
    }

    /**
     * The reads since the last call that list a text column as a column of
     * its own, rather than inside an expression.
     */
    private function textColumnReads()
    {
        $reads = [];
        foreach ($this->db->getLog(false, true)['log'] as $entry) {
            if (preg_match('/^(?:\/\*.*?\*\/\s*)?SELECT (.*?) FROM /s', $entry['query'], $match)
                && preg_match('/(?:^|, )`\w+`\.`value[12]`(?:,|$)/', $match[1])
            ) {
                $reads[] = $entry['query'];
            }
        }
        return $reads;
    }

    private function auditEntries($model, $id)
    {
        $entries = ClassRegistry::init('AuditLog')->find('all', [
            'conditions' => [
                'AuditLog.id >' => $this->auditBefore,
                'AuditLog.model' => $model,
                'AuditLog.model_id' => $id,
            ],
            'fields' => ['AuditLog.action', 'AuditLog.model_title', 'AuditLog.change'],
            'order' => ['AuditLog.id' => 'ASC'],
        ]);
        return array_column($entries, 'AuditLog');
    }

    private function syslogEntries($model, $id)
    {
        return $this->exec(sprintf(
            "SELECT action, title, description, `change` FROM logs WHERE id > %d AND model = '%s' AND model_id = %d ORDER BY id",
            $this->logsBefore,
            $model,
            $id
        ));
    }

    private function assertTextNotIds(array $entries)
    {
        $logged = json_encode($entries);
        $this->assertStringNotContainsString('value1_id', $logged);
        $this->assertStringNotContainsString('value2_id', $logged);
        $this->assertStringNotContainsString($this->columnText(), $logged);
    }

    private function requireSyslog()
    {
        if (Configure::read('MISP.log_new_audit')) {
            $this->markTestSkipped('SysLogLogable is off while the audit log is on.');
        }
    }

    public function testAnAddedValueIsAuditedAsText()
    {
        $this->hideTextColumns($this->attribute);
        $this->allowMissingTextColumns();
        $domain = "{$this->token}.example.org";
        $ip = '192.0.2.' . random_int(1, 254);

        $id = $this->create(['type' => 'domain|ip', 'value' => "$domain|$ip"]);

        $entries = $this->auditEntries('Attribute', $id);
        $this->assertCount(1, $entries, json_encode($entries));
        $this->assertSame($domain, $entries[0]['change']['value1']);
        $this->assertSame($ip, $entries[0]['change']['value2']);
        $this->assertSame("Network activity/domain|ip $domain|$ip", $entries[0]['model_title']);
        $this->assertTextNotIds($entries);
    }

    public function testAnEditedValueIsAuditedFromTheDictionary()
    {
        $domain = "{$this->token}.example.org";
        $id = $this->create(['type' => 'domain', 'value' => $domain]);
        $this->divergeStoredText('attributes', $id);
        $this->hideTextColumns($this->attribute);

        $this->edit($id, 'domain', "edited-$domain");

        $entries = $this->auditEntries('Attribute', $id);
        $this->assertCount(2, $entries, json_encode($entries));
        $this->assertSame([$domain, "edited-$domain"], $entries[1]['change']['value1']);
        $this->assertArrayNotHasKey('value2', $entries[1]['change']);
        $this->assertSame("Network activity/domain edited-$domain", $entries[1]['model_title']);
        $this->assertTextNotIds($entries);
    }

    public function testAnEditThroughTheEditFieldListIsAuditedFromTheDictionary()
    {
        $domain = "{$this->token}.example.org";
        $ip = '192.0.2.' . random_int(1, 254);
        // The correlation engine still reads the text columns by name
        $id = $this->create(['type' => 'domain|ip', 'value' => "$domain|$ip", 'disable_correlation' => 1]);
        $this->divergeStoredText('attributes', $id);
        $this->hideTextColumns($this->attribute);
        $this->db->fullDebug = true;
        $this->textColumnReads();

        $this->edit(
            $id,
            'domain|ip',
            "$domain|198.51.100.7",
            ['fieldList' => MispAttribute::EDITABLE_FIELDS],
            ['disable_correlation' => 1]
        );

        $this->assertSame([], $this->textColumnReads());
        $entries = $this->auditEntries('Attribute', $id);
        $this->assertCount(2, $entries, json_encode($entries));
        $this->assertSame([$ip, '198.51.100.7'], $entries[1]['change']['value2']);
        $this->assertArrayNotHasKey('value1', $entries[1]['change']);
        $this->assertTextNotIds($entries);
    }

    public function testAHardDeletedValueIsAuditedFromTheDictionary()
    {
        $domain = "{$this->token}.example.org";
        $ip = '192.0.2.' . random_int(1, 254);
        $id = $this->create(['type' => 'domain|ip', 'value' => "$domain|$ip"]);
        $this->divergeStoredText('attributes', $id);
        $this->hideTextColumns($this->attribute);

        $this->assertTrue($this->attribute->delete($id));

        $entries = $this->auditEntries('Attribute', $id);
        $this->assertCount(2, $entries, json_encode($entries));
        $this->assertSame(AuditLog::ACTION_DELETE, $entries[1]['action']);
        $this->assertSame($domain, $entries[1]['change']['value1']);
        $this->assertSame($ip, $entries[1]['change']['value2']);
        $this->assertSame("Network activity/domain|ip $domain|$ip", $entries[1]['model_title']);
        $this->assertTextNotIds($entries);
    }

    public function testAnEditedProposalIsAuditedFromTheDictionary()
    {
        $domain = "{$this->token}.example.org";
        $id = $this->createProposal('domain', $domain);
        $this->divergeStoredText('shadow_attributes', $id);
        $this->hideTextColumns($this->proposal);

        $saved = $this->proposal->save(['ShadowAttribute' => [
            'id' => $id,
            'event_id' => $this->event['id'],
            'type' => 'domain',
            'category' => 'Network activity',
            'value' => "edited-$domain",
        ]]);
        $this->assertNotFalse($saved, json_encode($this->proposal->validationErrors));

        $entries = $this->auditEntries('ShadowAttribute', $id);
        $this->assertCount(2, $entries, json_encode($entries));
        $this->assertSame([$domain, "edited-$domain"], $entries[1]['change']['value1']);
        $this->assertTextNotIds($entries);
    }

    public function testAnAddedValueReachesTheSyslogAsText()
    {
        $this->requireSyslog();
        $this->hideTextColumns($this->attribute);
        $this->allowMissingTextColumns();
        $domain = "{$this->token}.example.org";
        $ip = '192.0.2.' . random_int(1, 254);

        $id = $this->create(['type' => 'domain|ip', 'value' => "$domain|$ip"]);

        $entries = $this->syslogEntries('Attribute', $id);
        $this->assertCount(1, $entries, json_encode($entries));
        $this->assertStringContainsString("value1 () => ($domain)", $entries[0]['change']);
        $this->assertStringContainsString("value2 () => ($ip)", $entries[0]['change']);
        $this->assertStringEndsWith("Network activity/domain|ip $domain", $entries[0]['title']);
        $this->assertTextNotIds($entries);
    }

    public function testAnEditedValueReachesTheSyslogAsText()
    {
        $this->requireSyslog();
        $domain = "{$this->token}.example.org";
        $id = $this->create(['type' => 'domain', 'value' => $domain]);
        $this->divergeStoredText('attributes', $id);
        $this->hideTextColumns($this->attribute);

        $this->edit($id, 'domain', "edited-$domain");

        $entries = $this->syslogEntries('Attribute', $id);
        $this->assertCount(2, $entries, json_encode($entries));
        $this->assertStringContainsString("value1 ($domain) => (edited-$domain)", $entries[1]['change']);
        $this->assertStringEndsWith("Network activity/domain edited-$domain", $entries[1]['title']);
        $this->assertTextNotIds($entries);
    }

    public function testASyslogEditLeavesAnUnchangedValueOut()
    {
        $this->requireSyslog();
        $domain = "{$this->token}.example.org";
        $ip = '192.0.2.' . random_int(1, 254);
        $id = $this->create(['type' => 'domain|ip', 'value' => "$domain|$ip"]);
        $this->divergeStoredText('attributes', $id);
        $this->hideTextColumns($this->attribute);

        $this->edit($id, 'domain|ip', "$domain|198.51.100.7");

        $entries = $this->syslogEntries('Attribute', $id);
        $this->assertCount(2, $entries, json_encode($entries));
        $this->assertStringContainsString("value2 ($ip) => (198.51.100.7)", $entries[1]['change']);
        $this->assertStringNotContainsString('value1 (', $entries[1]['change']);
        $this->assertTextNotIds($entries);
    }

    public function testAHardDeletedValueReachesTheSyslogAsText()
    {
        $this->requireSyslog();
        // Its afterDelete hands the syslog a row of its own
        (new ReflectionProperty('AuditLogBehavior', 'enabled'))->setValue($this->audit, false);
        $domain = "{$this->token}.example.org";
        $ip = '192.0.2.' . random_int(1, 254);
        $id = $this->create(['type' => 'domain|ip', 'value' => "$domain|$ip"]);
        $this->divergeStoredText('attributes', $id);
        $this->hideTextColumns($this->attribute);

        $this->assertTrue($this->attribute->delete($id));

        $entries = $this->syslogEntries('Attribute', $id);
        $this->assertCount(2, $entries, json_encode($entries));
        $this->assertSame('delete', $entries[1]['action']);
        $this->assertStringEndsWith("Network activity/domain|ip $domain", $entries[1]['title']);
        $this->assertStringStartsWith("Attribute \"$domain|$ip\" ($id) deleted", $entries[1]['description']);
        $this->assertTextNotIds($entries);
    }
}
