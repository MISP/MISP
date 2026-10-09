<?php
/**
 * The OnDemand correlation engine matches an event's values on the dictionary
 * ids: one self-join per pair of value columns, through the dictionary for the
 * case variants, with no temporary table and the text from the dictionary.
 * The tests create their own events, hide the text columns from every
 * attribute model and point the stored text away from the dictionary, so a
 * read left on them finds the wrong rows.
 *
 * Every test runs in a transaction that is rolled back, then deletes the
 * events, attributes, exclusions and dictionary values it created by id, in
 * case something committed the transaction. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueOnDemandDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueOnDemandDbTest extends TestCase
{
    const SETTINGS = [
        'MISP.correlation_engine',
        'MISP.correlation_limit',
        'MISP.max_correlations_per_event',
    ];

    const ADMIN = ['id' => 1, 'Role' => ['perm_site_admin' => 1]];

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
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        foreach (self::SETTINGS as $setting) {
            $this->settings[$setting] = Configure::read($setting);
        }
        Configure::write('MISP.correlation_limit', 20);
        Configure::write('MISP.max_correlations_per_event', 5000);
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        $this->token = 'avod' . bin2hex(random_bytes(4));
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

    private function deleteFixture()
    {
        if (!empty($this->events)) {
            $events = implode(', ', array_map('intval', $this->events));
            $this->exec("DELETE FROM attributes WHERE event_id IN ($events)");
            $this->exec("DELETE FROM events WHERE id IN ($events)");
        }
        $this->exec(sprintf("DELETE FROM correlation_exclusions WHERE comment = '%s'", $this->token));
        if (!empty($this->newValues)) {
            $AttributeValue = ClassRegistry::init('AttributeValue');
            $hashes = [];
            foreach ($this->newValues as $value) {
                $hashes[] = "X'" . bin2hex($AttributeValue->hashOf($value)) . "'";
            }
            $this->exec(sprintf('DELETE FROM attribute_values WHERE hash IN (%s)', implode(', ', $hashes)));
        }
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
        return $port;
    }

    private function createFixture()
    {
        $t = $this->token;
        foreach (['source' => 0, 'target' => 0, 'target2' => 0, 'disabled' => 1] as $name => $disabled) {
            $uuid = CakeText::uuid();
            $this->exec(sprintf(
                "INSERT INTO events (org_id, orgc_id, user_id, date, info, uuid, analysis, distribution, sharing_group_id, threat_level_id, disable_correlation) VALUES (1, 1, 1, CURDATE(), 'AV-502 fixture %s %s', '%s', 0, 0, 0, 4, %d)",
                $t,
                $name,
                $uuid,
                $disabled
            ));
            $this->events[$name] = (int)$this->exec("SELECT id FROM events WHERE uuid = '$uuid'")[0]['id'];
        }
        $prefix = vsprintf('2001:db8:%x:%x', [random_int(4096, 65535), random_int(4096, 65535)]);
        $ip = "$prefix::7";
        $portSource = $this->freePort();
        $this->newValues[] = $portSource;
        $portTarget = $this->freePort();
        $this->newValues[] = $portTarget;
        $specs = [
            's_domain' => ['source', 'domain', "$t.example.org"],
            't_domain' => ['target', 'domain', "$t.example.org"],
            'd_domain' => ['disabled', 'domain', "$t.example.org"],
            't2_deleted' => ['target2', 'hostname', "$t.example.org"],
            's_text' => ['source', 'text', "$t-Mixed"],
            't_text' => ['target', 'text', "$t-mixed"],
            't_value2' => ['target', 'regkey|value', "HKLM\\Software\\$t|" . strtoupper("$t-mixed")],
            's_comp1' => ['source', 'domain|ip', "{$t}a.example|$ip"],
            's_comp2' => ['source', 'domain|ip', "{$t}b.example|$ip"],
            't_comp' => ['target', 'domain|ip', "{$t}c.example|$ip"],
            'd_comp' => ['disabled', 'domain|ip', "{$t}d.example|$ip"],
            's_port' => ['source', 'hostname|port', "$t-host.example|$portSource"],
            't_port' => ['target', 'text', $portSource],
            's_port2' => ['source', 'text', $portTarget],
            't_port2' => ['target', 'ip-dst|port', "$prefix::8|$portTarget"],
            's_tail' => ['source', 'text', "q$t-tail"],
            't_tail' => ['target', 'text', "q$t-tail"],
            's_head' => ['source', 'text', "$t-head-q"],
            't_head' => ['target', 'text', "$t-head-q"],
            's_tail_control' => ['source', 'text', "$t-tail-q"],
            't_tail_control' => ['target', 'text', "$t-tail-q"],
            's_many' => ['source', 'text', "$t-many"],
            't_many' => ['target', 'text', "$t-many"],
            't_many_other' => ['target', 'other', "$t-many"],
            't2_many' => ['target2', 'text', "$t-many"],
            's_two' => ['source', 'text', "$t-two"],
            't_two' => ['target', 'text', "$t-two"],
            't2_two' => ['target2', 'text', "$t-two"],
            's_empty' => ['source', 'text', "$t-empty-s"],
            't_empty' => ['target', 'text', "$t-empty-t"],
        ];
        foreach ([$ip, "$prefix::8"] as $value) {
            $this->newValues[] = $value;
        }
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
        $ids = implode(', ', $this->ids);
        $this->exec("UPDATE attributes SET disable_correlation = 0 WHERE id IN ($ids)");
        $this->exec(sprintf('UPDATE attributes SET deleted = 1 WHERE id = %d', $this->ids['t2_deleted']));
        $this->exec(sprintf(
            "UPDATE attributes SET value1 = 'column-%1\$s', value2 = IF(value2 = '', '', 'column-%1\$s') WHERE id IN (%2\$s)",
            $t,
            $ids
        ));
        // Legacy rows can hold an empty value1, which never correlates
        $hash = "X'" . bin2hex(ClassRegistry::init('AttributeValue')->hashOf('')) . "'";
        if (empty($this->exec("SELECT id FROM attribute_values WHERE hash = $hash"))) {
            $this->newValues[] = '';
            $this->exec("INSERT INTO attribute_values (value, hash) VALUES ('', $hash)");
        }
        $this->exec(sprintf(
            'UPDATE attributes SET value1_id = (SELECT id FROM attribute_values WHERE hash = %s) WHERE id IN (%d, %d)',
            $hash,
            $this->ids['s_empty'],
            $this->ids['t_empty']
        ));
        foreach (["%$t-tail", "$t-head%"] as $exclusion) {
            $this->exec(sprintf(
                "INSERT INTO correlation_exclusions (value, comment) VALUES ('%s', '%s')",
                $exclusion,
                $t
            ));
        }
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
     * The source event's correlations as a site admin, from a fresh engine
     * (it reads the exclusions when it is set up).
     *
     * @return array "source -> target: value", for the fixture's targets
     */
    private function collect()
    {
        Configure::write('MISP.correlation_engine', 'OnDemand');
        $correlation = new Correlation();
        $correlation->Attribute;
        $this->hideTextColumns();
        $behavior = $correlation->Behaviors->OnDemandCorrelation;
        $cache = new ReflectionProperty($behavior, 'correlationCache');
        $cache->setAccessible(true);
        $cache->setValue($behavior, []);
        $collect = new ReflectionMethod($behavior, '__collectCorrelations');
        $collect->setAccessible(true);
        $this->db->getLog(false, true);
        $rows = $collect->invoke($behavior, self::ADMIN, $this->events['source']);
        $names = array_flip($this->ids);
        $out = [];
        foreach ($rows as $row) {
            $this->assertSame($this->events['source'], $row['source_event_id']);
            $this->assertSame($names[(int)$row['id']][0], 't', 'a target of the fixture');
            $out[] = sprintf('%s -> %s: %s', $names[(int)$row['source_id']], $names[(int)$row['id']], $row['value']);
        }
        sort($out);
        return $out;
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

    /**
     * @param int $limit The per-value limit: it counts the pairs found before
     *   any filter, so the IP's 4 (two sources, a target in the disabled
     *   event) go at 3 and below, the 3 of "many" at 2.
     * @return string[]
     */
    private function expected($limit = 20)
    {
        $t = $this->token;
        $expected = [
            "s_domain -> t_domain: $t.example.org",
            // The target's own spelling
            "s_text -> t_text: $t-mixed",
            's_text -> t_value2: ' . strtoupper("$t-mixed"),
            "s_tail_control -> t_tail_control: $t-tail-q",
            "s_two -> t2_two: $t-two",
            "s_two -> t_two: $t-two",
        ];
        if ($limit >= 3) {
            $expected[] = "s_many -> t2_many: $t-many";
            $expected[] = "s_many -> t_many: $t-many";
            $expected[] = "s_many -> t_many_other: $t-many";
        }
        if ($limit >= 4) {
            $expected[] = "s_comp1 -> t_comp: {$this->value('t_comp', 1)}";
            $expected[] = "s_comp2 -> t_comp: {$this->value('t_comp', 1)}";
        }
        sort($expected);
        return $expected;
    }

    private function value($name, $part)
    {
        $row = $this->exec(sprintf(
            'SELECT v.value FROM attributes a JOIN attribute_values v ON v.id = a.value%d_id WHERE a.id = %d',
            $part + 1,
            $this->ids[$name]
        ));
        return $row[0]['value'];
    }

    public function testTheEventCorrelatesOnTheIds()
    {
        $this->assertSame($this->expected(), $this->collect());
        $passes = $this->statements('/FROM attributes AS source/');
        $this->assertCount(4, $passes);
        foreach ($passes as $pass) {
            $this->assertRegExp('/JOIN attribute_values AS target_value ON target_value\.value = source_value\.value/', $pass);
            $this->assertNotRegExp('/\bvalue[12]\b|FORCE INDEX/', $pass);
        }
        $this->assertSame([], $this->statements('/TEMPORARY|DROP TABLE|tmp_source_values/'));
        $this->assertSame([], $this->statements('/`attributes`.*`value[12]`/'));
        // The source event's check and one for all the target events
        $this->assertCount(2, $this->statements('/(?=.*`events`)(?=.*`disable_correlation`)/s'));
        $this->assertSame('1', (string)$this->exec('SELECT @@in_transaction AS t')[0]['t'], 'the transaction is still open');
    }

    public function testTheValueLimitIsTheSetting()
    {
        foreach ([2, 3] as $limit) {
            Configure::write('MISP.correlation_limit', $limit);
            $this->assertSame($this->expected($limit), $this->collect(), "limit $limit");
        }
    }

    public function testTheEventLimitIsTheSetting()
    {
        Configure::write('MISP.max_correlations_per_event', 3);
        $this->assertLessThanOrEqual(3, count($this->collect()));
        $this->assertCount(1, $this->statements('/FROM attributes AS source/'), 'the first pass uses the budget up');
    }
}
