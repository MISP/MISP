<?php
/**
 * Over-correlating values and the OnDemand top list are keyed by the
 * dictionary ids: a blocked value covers its case variants, the event view
 * flags every variant, the index shows the value as stored, occurrences count
 * the variants exactly and the top list counts each value once under the
 * lowest of its variants' ids. The tests create their own events, hide the
 * text columns from every attribute model and point the stored text away from
 * the dictionary, so a read left on them counts the wrong rows.
 *
 * Every test runs in a transaction that is rolled back, then deletes the
 * events, attributes, over-correlation and top-list rows and the dictionary
 * values it created by id: the top-list test truncates its table, which
 * commits the transaction. That test aggregates every attribute of the
 * instance (about 30 s here). Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set,
 * and it boots the real application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueOverCorrelationDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueOverCorrelationDbTest extends TestCase
{
    const SETTINGS = [
        'MISP.correlation_engine',
        'MISP.correlation_limit',
    ];

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var string */
    private $token;

    /** @var array name => event id */
    private $events = [];

    /** @var array name => attribute id */
    private $ids = [];

    /** @var string[] dictionary values the test added */
    private $newValues = [];

    /** @var array */
    private $settings = [];

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
            App::uses('CakeText', 'Utility');
            App::uses('AttributeValue', 'Model');
            App::uses('Correlation', 'Model');
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
        foreach (self::SETTINGS as $setting) {
            $this->settings[$setting] = Configure::read($setting);
        }
        Configure::write('MISP.correlation_engine', 'Default');
        Configure::write('MISP.correlation_limit', 20);
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        // Occurrences run a count per blocked value, more than the default log keeps
        $logMax = new ReflectionProperty('DboSource', '_queriesLogMax');
        $logMax->setAccessible(true);
        $logMax->setValue($this->db, 100000);
        $this->token = 'avoc' . bin2hex(random_bytes(4));
        $this->db->begin();
        $this->createFixture();
        $this->db->fullDebug = true;
    }

    protected function tearDown(): void
    {
        if (!$this->db) {
            return;
        }
        foreach ($this->settings as $setting => $value) {
            Configure::write($setting, $value);
        }
        $this->db->cacheMethods = $this->cachedMethods;
        $this->db->fullDebug = $this->fullDebug;
        foreach ($this->attributeModels() as $model) {
            $model->schema(true);
        }
        try {
            // Throws when something committed the transaction
            $this->db->rollback();
        } finally {
            $this->deleteFixture();
            ClassRegistry::init('OverCorrelatingValue')->cleanCache();
        }
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

    private function hashList(array $values)
    {
        $AttributeValue = ClassRegistry::init('AttributeValue');
        $hashes = [];
        foreach ($values as $value) {
            $hashes[] = "X'" . bin2hex($AttributeValue->hashOf((string)$value)) . "'";
        }
        return implode(', ', $hashes);
    }

    private function deleteFixture()
    {
        if (!empty($this->events)) {
            $events = implode(', ', array_map('intval', $this->events));
            $this->exec("DELETE FROM attributes WHERE event_id IN ($events)");
            $this->exec("DELETE FROM events WHERE id IN ($events)");
        }
        if (!empty($this->newValues)) {
            $ids = array_column($this->exec(sprintf(
                'SELECT id FROM attribute_values WHERE hash IN (%s)',
                $this->hashList($this->newValues)
            )), 'id');
            if (!empty($ids)) {
                $ids = implode(', ', array_map('intval', $ids));
                $this->exec("DELETE FROM over_correlating_values WHERE value_id IN ($ids)");
                $this->exec("DELETE FROM attr_value_counts WHERE value_id IN ($ids)");
                $this->exec("DELETE FROM value_ip_ranges WHERE value_id IN ($ids)");
                $this->exec("DELETE FROM attribute_values WHERE id IN ($ids)");
            }
        }
        if ($this->hasTextKey()) {
            $this->exec(sprintf("DELETE FROM over_correlating_values WHERE value LIKE '%s%%'", $this->token));
        }
    }

    /**
     * Whether over_correlating_values still has its 2.x text key, which the
     * text-column drop removes.
     */
    private function hasTextKey()
    {
        return !empty($this->exec("SHOW COLUMNS FROM over_correlating_values LIKE 'value'"));
    }

    /**
     * A random port no attribute holds yet.
     *
     * @return string
     */
    private function freePort()
    {
        $AttributeValue = ClassRegistry::init('AttributeValue');
        do {
            $port = (string)random_int(20000, 65535);
        } while (!empty($AttributeValue->idsOf([$port])) || in_array($port, $this->newValues, true));
        $this->newValues[] = $port;
        return $port;
    }

    private function createFixture()
    {
        $t = $this->token;
        foreach (['source' => 0, 'target' => 0, 'target2' => 0, 'disabled' => 1] as $name => $disabled) {
            $uuid = CakeText::uuid();
            $this->exec(sprintf(
                "INSERT INTO events (org_id, orgc_id, user_id, date, info, uuid, analysis, distribution, sharing_group_id, threat_level_id, disable_correlation) VALUES (1, 1, 1, CURDATE(), 'AV-503 fixture %s %s', '%s', 0, 0, 0, 4, %d)",
                $t,
                $name,
                $uuid,
                $disabled
            ));
            $this->events[$name] = (int)$this->exec("SELECT id FROM events WHERE uuid = '$uuid'")[0]['id'];
        }
        $specs = [
            's_blocked' => ['source', 'text', "$t-Blocked"],
            't_blocked' => ['target', 'text', "$t-blocked"],
            't2_blocked' => ['target2', 'text', strtoupper("$t-blocked")],
            't_accent' => ['target', 'text', "$t-blöcked"],
            't_value2' => ['target', 'regkey|value', "HKLM\\Software\\$t|$t-BLOCKED"],
            't_prefix' => ['target', 'text', "$t-blocked.extra"],
            't2_deleted' => ['target2', 'other', "$t-blocked"],
            't_disabled' => ['target', 'other', "$t-blocked"],
            'd_blocked' => ['disabled', 'text', "$t-blocked"],
            's_two' => ['source', 'text', "$t-two"],
            't_two' => ['target', 'text', "$t-TWO"],
        ];
        foreach ($specs as $name => list($event, $type, $value)) {
            foreach (explode('|', $value) as $part) {
                if (stripos($part, $t) !== false) {
                    $this->newValues[] = $part;
                }
            }
            $this->attribute->create();
            $saved = $this->attribute->save(['Attribute' => [
                'event_id' => $this->events[$event],
                'category' => $this->attribute->typeDefinitions[$type]['default_category'],
                'type' => $type,
                'value' => $value,
                'distribution' => 5,
                'to_ids' => 0,
                'disable_correlation' => 1,
            ]]);
            $this->assertNotFalse($saved, $name . ': ' . json_encode($this->attribute->validationErrors));
            $this->ids[$name] = (int)$this->attribute->id;
        }
        $enabled = $this->ids;
        unset($enabled['t_disabled']);
        $this->exec(sprintf('UPDATE attributes SET disable_correlation = 0 WHERE id IN (%s)', implode(', ', $enabled)));
        $this->exec(sprintf('UPDATE attributes SET deleted = 1 WHERE id = %d', $this->ids['t2_deleted']));
        AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf(
            "UPDATE attributes SET value1 = 'column-%1\$s', value2 = IF(value2 = '', '', 'column-%1\$s') WHERE id IN (%2\$s)",
            $t,
            implode(', ', $this->ids)
        ));
        $this->hideTextColumns();
    }

    private function attributeModels()
    {
        $models = [spl_object_id($this->attribute) => $this->attribute];
        foreach (ClassRegistry::keys() as $key) {
            $object = ClassRegistry::getObject($key);
            if ($object instanceof MispAttribute) {
                $models[spl_object_id($object)] = $object;
            }
        }
        return $models;
    }

    private function hideTextColumns()
    {
        $property = new ReflectionProperty('Model', '_schema');
        foreach ($this->attributeModels() as $model) {
            $schema = $model->schema();
            unset($schema['value1'], $schema['value2']);
            $property->setValue($model, $schema);
        }
        $this->db->cacheMethods = false;
    }

    /**
     * @return OverCorrelatingValue A fresh instance, so nothing is cached
     */
    private function overCorrelating()
    {
        $model = new OverCorrelatingValue();
        return $model;
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

    private function idOf($value)
    {
        return (int)$this->exec(sprintf('SELECT id FROM attribute_values WHERE hash IN (%s)', $this->hashList([$value])))[0]['id'];
    }

    private function rowsOf($value)
    {
        return $this->exec(sprintf(
            "SELECT o.id, o.value_id, o.occurrence FROM over_correlating_values o JOIN attribute_values v ON v.id = o.value_id WHERE v.value = _utf8mb4'%s'",
            $value
        ));
    }

    public function testABlockCoversTheCaseVariants()
    {
        $t = $this->token;
        $model = $this->overCorrelating();
        $this->assertFalse($model->isBlocked("$t-blöcked"));
        $model->block("$t-Blocked");
        $this->assertTrue($model->isBlocked("$t-blöcked"), 'the same instance sees the block');
        $rows = $this->rowsOf("$t-blocked");
        $this->assertCount(1, $rows);
        $this->assertSame($this->idOf("$t-Blocked"), (int)$rows[0]['value_id']);
        if ($this->hasTextKey()) {
            $stored = $this->exec(sprintf('SELECT value FROM over_correlating_values WHERE id = %d', $rows[0]['id']));
            $this->assertNull($stored[0]['value'], 'the text key is no longer written');
        }

        $model = $this->overCorrelating();
        $this->db->getLog(false, true);
        $this->assertTrue($model->isBlocked("$t-blocked"));
        $this->assertTrue($model->isBlocked(strtoupper("$t-blocked")));
        $this->assertTrue($model->isBlocked("$t-BLOCKED"));
        $this->assertTrue($model->isBlocked("$t-blöcked"), 'the collation folds accents too');
        $this->assertFalse($model->isBlocked("$t-blocked.extra"));
        $this->assertFalse($model->isBlocked("$t-two"));
        $this->assertCount(1, $this->statements('/over_correlating_values/'), 'the blocked values load once');

        $model->block("$t-blocked");
        $this->assertCount(1, $this->rowsOf("$t-blocked"), 'a variant of a blocked value adds no row');

        $model->unblock(strtoupper("$t-blocked"));
        $this->assertSame([], $this->rowsOf("$t-blocked"));
        $this->assertFalse($model->isBlocked("$t-Blocked"));
    }

    public function testTheEventViewFlagsEveryVariant()
    {
        $t = $this->token;
        $port = $this->freePort();
        $model = $this->overCorrelating();
        $model->block("$t-Blocked");
        $model->block($port);
        $correlation = new Correlation();
        $correlation->OverCorrelatingValue = $this->overCorrelating();
        $attributes = [
            'variant' => ['type' => 'text', 'value' => strtoupper("$t-blocked")],
            'accent' => ['type' => 'text', 'value' => "$t-blöcked"],
            'prefix' => ['type' => 'text', 'value' => "$t-blocked.extra"],
            'value2' => ['type' => 'regkey|value', 'value' => "HKLM\\x|$t-blocked"],
            'port' => ['type' => 'text', 'value' => $port],
            'primary_only' => ['type' => 'ip-dst|port', 'value' => "192.0.2.7|$port"],
        ];
        foreach ($attributes as &$attribute) {
            $attribute['disable_correlation'] = false;
        }
        unset($attribute);
        $this->db->getLog(false, true);
        $flagged = [];
        foreach ($correlation->attachCorrelationExclusion($attributes) as $name => $attribute) {
            if (!empty($attribute['over_correlation'])) {
                $flagged[] = $name;
            }
        }
        $this->assertSame(['variant', 'accent', 'value2', 'port'], $flagged);
        $this->assertCount(1, $this->statements('/over_correlating_values/'));
    }

    public function testTheIndexShowsTheValueAsStored()
    {
        $t = $this->token;
        $this->overCorrelating()->block("$t-Blocked");
        $data = $this->overCorrelating()->getOverCorrelations([
            'limit' => 50,
            'page' => 1,
            'order' => 'occurrence desc',
            'conditions' => [['BlockedValue.value LIKE' => "%$t%"]],
        ]);
        $this->assertCount(1, $data);
        $this->assertSame(['id', 'value', 'occurrence', 'over_correlation'], array_keys($data[0]['OverCorrelatingValue']));
        $this->assertSame(['OverCorrelatingValue'], array_keys($data[0]));
        $this->assertSame("$t-Blocked", $data[0]['OverCorrelatingValue']['value']);
    }

    public function testAStoredTextKeyIsRemapped()
    {
        $t = $this->token;
        if (!$this->hasTextKey()) {
            $this->assertSame(0, $this->overCorrelating()->remapValueIds(), 'without the text key there is nothing to remap');
            return;
        }
        $this->exec("INSERT INTO over_correlating_values (value, occurrence) VALUES ('$t-blocked', 0), ('$t-unknown', 0)");
        $this->overCorrelating()->remapValueIds();
        $rows = array_column($this->exec("SELECT value, value_id FROM over_correlating_values WHERE value LIKE '$t%'"), 'value_id', 'value');
        $variants = array_map('intval', array_column($this->exec(
            "SELECT id FROM attribute_values WHERE value = _utf8mb4'$t-blocked'"
        ), 'id'));
        $this->assertGreaterThan(1, count($variants));
        $this->assertSame(min($variants), (int)$rows["$t-blocked"]);
        $this->assertNull($rows["$t-unknown"], 'a value the dictionary does not hold keeps no id');
    }

    public function testOccurrencesCountTheVariantsExactly()
    {
        $t = $this->token;
        $this->overCorrelating()->block("$t-Blocked");
        $this->db->getLog(false, true);
        $this->overCorrelating()->generateOccurrences();
        // s_blocked, t_blocked, t2_blocked, t_accent and t_value2; not the
        // prefix, the deleted, the disabled one or the one in a disabled event
        $this->assertSame('5', (string)$this->rowsOf("$t-blocked")[0]['occurrence']);
        $this->assertCount(1, $this->statements('/SELECT \d+ AS `term`, `id` FROM `attribute_values`/'), 'one resolve for every row');
        $this->assertSame([], $this->statements('/`attributes`.*`value[12]`/'));
    }

    public function testTheTopListCountsEachValueOnce()
    {
        $t = $this->token;
        $correlation = new Correlation();
        $correlation->generateTopOnDemand();
        $this->assertSame('0', (string)$this->exec('SELECT @@in_transaction AS t')[0]['t'], 'TRUNCATE commits');
        try {
            $this->db->rollback();
        } catch (PDOException $e) {
            // Nothing left to roll back: the datasource has let go of it
        }
        $variants = array_map('intval', array_column($this->exec(
            "SELECT id FROM attribute_values WHERE value = _utf8mb4'$t-blocked'"
        ), 'id'));
        $rows = $this->exec(sprintf(
            'SELECT value_id, cnt_v1, cnt_v2 FROM attr_value_counts WHERE value_id IN (%s)',
            implode(', ', $variants)
        ));
        // Every type counts, and the event in which correlation is disabled
        $this->assertSame([[
            'value_id' => (string)min($variants),
            'cnt_v1' => '5',
            'cnt_v2' => '1',
        ]], $rows);
        $this->assertSame(['cnt_v1' => '2', 'cnt_v2' => '0'], $this->exec(sprintf(
            'SELECT cnt_v1, cnt_v2 FROM attr_value_counts WHERE value_id = %d',
            $this->idOf("$t-two")
        ))[0]);
        $this->assertSame(['cnt_v1' => '1', 'cnt_v2' => '0'], $this->exec(sprintf(
            'SELECT cnt_v1, cnt_v2 FROM attr_value_counts WHERE value_id = %d',
            $this->idOf("$t-blocked.extra")
        ))[0]);

        $method = new ReflectionMethod($correlation, 'findTopOnDemand');
        $method->setAccessible(true);
        $found = $method->invoke($correlation, ['limit' => 1, 'page' => 1]);
        $this->assertCount(1, $found);
        $max = (int)$this->exec('SELECT MAX(cnt_v1 + cnt_v2) AS cnt FROM attr_value_counts')[0]['cnt'];
        $this->assertSame($max, $found[0]['Correlation']['count']);
        $this->assertSame((string)$max, (string)$this->exec(sprintf(
            'SELECT cnt_v1 + cnt_v2 AS cnt FROM attr_value_counts WHERE value_id = %d',
            $this->idOf($found[0]['Correlation']['value'])
        ))[0]['cnt'], 'the value shown is the one counted');
    }
}
