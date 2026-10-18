<?php
/**
 * The Default and NoAcl correlation engines match on the dictionary ids: a
 * saved attribute resolves its values in one statement and looks them up by
 * id, a recorrelation resolves each chunk once, a correlation is keyed by its
 * value's group (the lowest id of its case variants), and the rows the engines
 * read get their value text from the dictionary (the matching attributes,
 * ssdeep). The tests hide the text columns from every
 * attribute model and point the stored text away from the dictionary, so a
 * read left on them records the wrong value or finds nothing.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueCorrelationDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueCorrelationDbTest extends TestCase
{
    const SETTINGS = [
        'MISP.correlation_engine',
        'MISP.enable_advanced_correlations',
        'MISP.completely_disable_correlation',
        'MISP.correlation_chunk_size',
    ];

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var string */
    private $token;

    /** @var string */
    private $ip;

    /** @var int[] source event, target event */
    private $events;

    /** @var array name => attribute id */
    private $ids = [];

    /** @var array name => [type, value1, value2] */
    private $values = [];

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
        Configure::write('MISP.enable_advanced_correlations', false);
        Configure::write('MISP.completely_disable_correlation', false);
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        $this->db->begin();
        $this->token = 'avcor' . bin2hex(random_bytes(4));
        $this->ip = vsprintf('2001:db8:%x:%x::7', [random_int(4096, 65535), random_int(4096, 65535)]);
        $this->events = array_map('intval', $this->attribute->Event->find('column', [
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id'],
            'limit' => 2,
        ]));
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
        list($source, $target) = $this->events;
        $specs = [
            't_domain' => [$target, 'domain', "$t.example.org"],
            't_text' => [$target, 'text', "$t-mixed"],
            't_quirk' => [$target, 'regkey|value', "HKLM\\Software\\$t|" . strtoupper($t) . '-MIXED'],
            't_value2' => [$target, 'domain|ip', "{$t}d.example|{$this->ip}"],
            't_disabled' => [$target, 'hostname', "$t.example.org"],
            's_domain' => [$source, 'domain', "$t.example.org"],
            's_text' => [$source, 'text', "$t-Mixed"],
            's_composite' => [$source, 'domain|ip', "{$t}s.example|{$this->ip}"],
        ];
        $this->add($specs, ['t_disabled']);
    }

    /**
     * Attributes saved without correlating, then switched on (all but
     * $disabled), their stored text diverged and the text columns hidden.
     *
     * @param array $specs name => [event id, type, value]
     * @param string[] $disabled
     * @return void
     */
    private function add(array $specs, array $disabled = [])
    {
        foreach ($this->attributeModels() as $model) {
            $model->schema(true);
        }
        $added = [];
        $enabled = [];
        foreach ($specs as $name => list($eventId, $type, $value)) {
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
            $added[] = $this->ids[$name] = (int)$this->attribute->id;
            $parts = explode('|', $value, 2);
            $this->values[$name] = [$type, $parts[0], isset($parts[1]) ? $parts[1] : ''];
            if (!in_array($name, $disabled, true)) {
                $enabled[] = $this->ids[$name];
            }
        }
        $this->exec(sprintf(
            'UPDATE attributes SET disable_correlation = 0 WHERE id IN (%s)',
            implode(', ', $enabled)
        ));
        AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf(
            "UPDATE attributes SET value1 = 'column-%1\$s', value2 = IF(value2 = '', '', 'column-%1\$s') WHERE id IN (%2\$s)",
            $this->token,
            implode(', ', $added)
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
     * A correlation model on the given engine, its attribute model's text
     * columns hidden too.
     *
     * @param string $engine
     * @return Correlation
     */
    private function engine($engine)
    {
        Configure::write('MISP.correlation_engine', $engine);
        $correlation = new Correlation();
        $correlation->Attribute;
        $this->hideTextColumns();
        // The exclusions load once per process, outside the per-call counts
        $correlation->isExcludedValue('');
        return $correlation;
    }

    /**
     * The attribute as a save hands it to the engine: its own text.
     *
     * @param string $name
     * @return array
     */
    private function saved($name)
    {
        $row = $this->exec(sprintf(
            'SELECT id, event_id, object_id, type, distribution, sharing_group_id, disable_correlation FROM attributes WHERE id = %d',
            $this->ids[$name]
        ))[0];
        list(, $value1, $value2) = $this->values[$name];
        return $row + ['value1' => $value1, 'value2' => $value2];
    }

    /**
     * @param string $table
     * @param string $name
     * @return array the other attribute's name => the text of the correlation's value group
     */
    private function correlationsOf($table, $name)
    {
        $id = $this->ids[$name];
        $names = array_flip($this->ids);
        $out = [];
        $rows = $this->exec(sprintf(
            'SELECT c.attribute_id, c.1_attribute_id, v.value FROM %s c JOIN attribute_values v ON v.id = c.value_id WHERE c.attribute_id = %2$d OR c.1_attribute_id = %2$d',
            $table,
            $id
        ));
        foreach ($rows as $row) {
            $other = (int)$row['attribute_id'] === $id ? (int)$row['1_attribute_id'] : (int)$row['attribute_id'];
            if (isset($names[$other])) {
                $out[$names[$other]] = $row['value'];
            }
        }
        ksort($out);
        return $out;
    }

    private function expected()
    {
        $t = $this->token;
        return [
            's_domain' => ['t_domain' => "$t.example.org"],
            // The group's lowest id is the first spelling saved; a value2 match
            // in another case is keyed by the value's group too
            's_text' => ['t_quirk' => "$t-mixed", 't_text' => "$t-mixed"],
            's_composite' => ['t_value2' => $this->ip],
        ];
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

    private function resolves()
    {
        return count($this->statements('/SELECT \d+ AS `term`, `id` FROM `attribute_values`/'));
    }

    private function assertNoTextColumnRead()
    {
        $reads = [];
        foreach ($this->statements('/`attributes`/') as $statement) {
            if (preg_match('/`value[12]`/', $statement)) {
                $reads[] = $statement;
            }
        }
        $this->assertSame([], $reads);
    }

    private function call($object, $method, ...$args)
    {
        $reflection = new ReflectionMethod($object, $method);
        $reflection->setAccessible(true);
        return $reflection->invokeArgs($object, $args);
    }

    private function correlateSaved($engine, $table)
    {
        $correlation = $this->engine($engine);
        foreach ($this->expected() as $source => $expected) {
            $this->clearLog();
            $this->assertNotFalse($correlation->afterSaveCorrelation($this->saved($source)));
            $this->assertSame(1, $this->resolves(), "$source resolves its values once");
            $this->assertNotEmpty($this->statements('/`Attribute`\.`value[12]_id` IN \(/'));
            $this->assertNoTextColumnRead();
            $this->assertSame($expected, $this->correlationsOf($table, $source), $source);
        }
    }

    public function testASavedAttributeCorrelatesOnTheIds()
    {
        $this->correlateSaved('Default', 'default_correlations');
    }

    public function testTheNoAclEngineCorrelatesOnTheIds()
    {
        $this->correlateSaved('NoAcl', 'no_acl_correlations');
    }

    public function testARecorrelationResolvesEachChunkOnce()
    {
        Configure::write('MISP.correlation_chunk_size', 2);
        $correlation = $this->engine('Default');
        $sourceEvent = $this->events[0];
        $count = (int)$this->exec(sprintf(
            "SELECT COUNT(*) AS n FROM attributes WHERE event_id = %d AND deleted = 0 AND disable_correlation = 0 AND type NOT IN ('%s')",
            $sourceEvent,
            implode("', '", MispAttribute::NON_CORRELATING_TYPES)
        ))[0]['n'];
        $this->assertGreaterThan(2, $count);
        $this->clearLog();
        $this->assertSame($count, $correlation->generateCorrelation(false, $sourceEvent));
        $this->assertSame((int)ceil($count / 2), $this->resolves());
        $this->assertNoTextColumnRead();
        foreach ($this->expected() as $source => $expected) {
            $this->assertSame($expected, $this->correlationsOf('default_correlations', $source), $source);
        }
    }

    public function testTheMatchingAttributesReadTheDictionaryText()
    {
        $correlation = $this->engine('Default');
        $this->clearLog();
        $rows = $this->call($correlation, '__getMatchingAttributes', "{$this->token}-MIXED");
        $this->assertNoTextColumnRead();
        $found = [];
        foreach ($rows as $row) {
            $this->assertArrayNotHasKey('value1_id', $row['Attribute']);
            $found[(int)$row['Attribute']['id']] = [$row['Attribute']['value1'], $row['Attribute']['value2']];
        }
        ksort($found);
        $expected = [];
        foreach (['t_text', 't_quirk', 's_text'] as $name) {
            $expected[$this->ids[$name]] = array_slice($this->values[$name], 1);
        }
        ksort($expected);
        $this->assertSame($expected, $found);
    }

    public function testSsdeepComparesTheDictionaryText()
    {
        if (!function_exists('ssdeep_fuzzy_compare')) {
            // The first block decides, enough to tell the dictionary text from the diverged one
            eval('function ssdeep_fuzzy_compare($a, $b) { return (explode(":", $a)[1] ?? null) === (explode(":", $b)[1] ?? "") ? 60 : 0; }');
        }
        $t = $this->token;
        // No character in common with the others, so the real extension scores it 0 too
        $far = strtr(strtoupper($t), '0123456789', 'GHIJKLMNOP');
        list($source, $target) = $this->events;
        $this->add([
            'ss_source' => [$source, 'ssdeep', "24:{$t}abc:{$t}def"],
            'ss_near' => [$target, 'ssdeep', "24:{$t}abc:{$t}xyz"],
            'ss_far' => [$target, 'ssdeep', "24:{$far}ZZZ:{$far}DEF"],
        ]);
        $correlation = $this->engine('Default');
        $correlation->FuzzyCorrelateSsdeep = new class([$this->ids['ss_near'], $this->ids['ss_far']]) {
            private $ids;

            public function __construct(array $ids)
            {
                $this->ids = $ids;
            }

            public function query_ssdeep_chunks($value, $id)
            {
                return $this->ids;
            }
        };
        $this->clearLog();
        $source = $this->saved('ss_source');
        $conditions = $this->call($correlation, 'ssdeepCorrelation', ['Attribute' => $source]);
        $this->assertSame(['Attribute.id' => [$this->ids['ss_near']]], $conditions);

        $enabled = new ReflectionProperty($correlation, 'advancedCorrelationEnabled');
        $enabled->setAccessible(true);
        $enabled->setValue($correlation, true);
        $rows = $this->call($correlation, '__addAdvancedCorrelations', ['Attribute' => $source]);
        $this->assertSame([$this->ids['ss_near']], array_map('intval', array_column(array_column($rows, 'Attribute'), 'id')));
        $this->assertSame("24:{$t}abc:{$t}xyz", $rows[0]['Attribute']['value1']);
        $this->assertNoTextColumnRead();
    }

    public function testAnSsdeepMatchOnSaveKeepsTheExactFilters()
    {
        if (!function_exists('ssdeep_fuzzy_compare')) {
            eval('function ssdeep_fuzzy_compare($a, $b) { return (explode(":", $a)[1] ?? null) === (explode(":", $b)[1] ?? "") ? 60 : 0; }');
        }
        Configure::write('MISP.enable_advanced_correlations', true);
        $t = $this->token;
        list($source, $target) = $this->events;
        $this->add([
            'ss_source' => [$source, 'ssdeep', "24:{$t}abc:{$t}def"],
            'ss_near' => [$target, 'ssdeep', "24:{$t}abc:{$t}xyz"],
            'ss_deleted' => [$target, 'ssdeep', "24:{$t}abc:{$t}uvw"],
            'ss_same_event' => [$source, 'ssdeep', "24:{$t}abc:{$t}rst"],
        ]);
        $this->exec(sprintf('UPDATE attributes SET deleted = 1 WHERE id = %d', $this->ids['ss_deleted']));
        $correlation = $this->engine('Default');
        $correlation->FuzzyCorrelateSsdeep = new class([$this->ids['ss_near'], $this->ids['ss_deleted'], $this->ids['ss_same_event']]) {
            private $ids;

            public function __construct(array $ids)
            {
                $this->ids = $ids;
            }

            public function query_ssdeep_chunks($value, $id)
            {
                return $this->ids;
            }
        };

        $this->assertNotFalse($correlation->afterSaveCorrelation($this->saved('ss_source')));

        $this->assertSame(['ss_near' => "24:{$t}abc:{$t}xyz"], $this->correlationsOf('default_correlations', 'ss_source'));
    }

    public function testAFullRecorrelationKeepsTheSsdeepMatches()
    {
        if (!function_exists('ssdeep_fuzzy_compare')) {
            eval('function ssdeep_fuzzy_compare($a, $b) { return (explode(":", $a)[1] ?? null) === (explode(":", $b)[1] ?? "") ? 60 : 0; }');
        }
        Configure::write('MISP.enable_advanced_correlations', true);
        $t = $this->token;
        list($source, $target) = $this->events;
        $this->add([
            'ss_first' => [$source, 'ssdeep', "24:{$t}abc:{$t}def"],
            'ss_second' => [$target, 'ssdeep', "24:{$t}abc:{$t}xyz"],
            'ss_third' => [$source, 'ssdeep', "24:{$t}abc:{$t}uvw"],
        ]);
        $correlation = $this->engine('Default');
        // In id order, as a full run meets them, against the real chunk table
        foreach (['ss_first', 'ss_second', 'ss_third'] as $name) {
            $this->assertNotFalse($correlation->afterSaveCorrelation($this->saved($name), true));
        }

        $this->assertSame(['ss_first', 'ss_third'], array_keys($this->correlationsOf('default_correlations', 'ss_second')));
    }
}
