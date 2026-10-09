<?php
/**
 * The Default and NoAcl correlation tables key a correlation by its value's
 * group in the dictionary (the lowest id of its case variants). A related
 * attribute shows the value as that attribute holds it, in full; exact
 * exclusions and over-correlating values hide their whole group; purging an
 * exclusion removes what the exclusion matches; the remap moves 2.x rows from
 * correlation_values to their groups. The tests create their own events, hide
 * the text columns from every attribute model and point the stored text away
 * from the dictionary.
 *
 * Every test runs in a transaction that is rolled back, then deletes what it
 * created by id: the remap creates its map table, which commits the
 * transaction. Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set, and it boots
 * the real application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueCorrelationGroupDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueCorrelationGroupDbTest extends TestCase
{
    const SETTINGS = [
        'MISP.correlation_engine',
        'MISP.enable_advanced_correlations',
        'MISP.completely_disable_correlation',
        'MISP.correlation_limit',
    ];

    const ENGINES = ['Default' => 'default_correlations', 'NoAcl' => 'no_acl_correlations'];

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

    /** @var array name => [type, value1, value2] */
    private $values = [];

    /** @var string[] dictionary values the test added */
    private $newValues = [];

    /** @var int[] correlation_values rows the test added */
    private $correlationValues = [];

    /** @var array|null the remap state to put back, by setting */
    private $remapState = null;

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
            App::uses('CorrelationRemapTool', 'Tools');
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
        Configure::write('MISP.enable_advanced_correlations', false);
        Configure::write('MISP.completely_disable_correlation', false);
        Configure::write('MISP.correlation_limit', 20);
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        $this->token = 'avcg' . bin2hex(random_bytes(4));
        $this->db->begin();
        $this->createFixture();
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

    private function deleteFixture()
    {
        if (!empty($this->ids)) {
            $ids = implode(', ', $this->ids);
            foreach (self::ENGINES as $table) {
                $this->exec("DELETE FROM $table WHERE attribute_id IN ($ids) OR 1_attribute_id IN ($ids)");
            }
        }
        if (!empty($this->events)) {
            $events = implode(', ', array_map('intval', $this->events));
            $this->exec("DELETE FROM attributes WHERE event_id IN ($events)");
            $this->exec("DELETE FROM events WHERE id IN ($events)");
        }
        if (!empty($this->correlationValues)) {
            $this->exec(sprintf('DELETE FROM correlation_values WHERE id IN (%s)', implode(', ', $this->correlationValues)));
        }
        // Rows the 2.x write path would add
        $this->exec(sprintf("DELETE FROM correlation_values WHERE value LIKE '%%%s%%'", $this->token));
        if ($this->remapState !== null) {
            $AdminSetting = ClassRegistry::init('AdminSetting');
            foreach ($this->remapState as $setting => $value) {
                $AdminSetting->changeSetting($setting, $value);
            }
            $this->exec('DROP TABLE IF EXISTS ' . CorrelationRemapTool::MAP);
        }
        $this->exec(sprintf("DELETE FROM correlation_exclusions WHERE comment = '%s'", $this->token));
        if (!empty($this->newValues)) {
            $AttributeValue = ClassRegistry::init('AttributeValue');
            $hashes = [];
            foreach (array_unique($this->newValues) as $value) {
                $hashes[] = "X'" . bin2hex($AttributeValue->hashOf((string)$value)) . "'";
            }
            $ids = array_column($this->exec(sprintf('SELECT id FROM attribute_values WHERE hash IN (%s)', implode(', ', $hashes))), 'id');
            if (!empty($ids)) {
                $ids = implode(', ', array_map('intval', $ids));
                $this->exec("DELETE FROM over_correlating_values WHERE value_id IN ($ids)");
                $this->exec("DELETE FROM value_ip_ranges WHERE value_id IN ($ids)");
                $this->exec("DELETE FROM attribute_values WHERE id IN ($ids)");
            }
        }
    }

    private function createFixture()
    {
        $t = $this->token;
        foreach (['source', 'target', 'target2'] as $name) {
            $uuid = CakeText::uuid();
            $this->exec(sprintf(
                "INSERT INTO events (org_id, orgc_id, user_id, date, info, uuid, analysis, distribution, sharing_group_id, threat_level_id, disable_correlation) VALUES (1, 1, 1, CURDATE(), 'AV-504 fixture %s %s', '%s', 0, 0, 0, 4, 0)",
                $t,
                $name,
                $uuid
            ));
            $this->events[$name] = (int)$this->exec("SELECT id FROM events WHERE uuid = '$uuid'")[0]['id'];
        }
        $long = "$t-" . str_repeat('L', 200);
        // Targets first: the first spelling saved holds a group's lowest id
        $specs = [
            't_mixed' => ['target', 'text', "$t-mixed"],
            't2_upper' => ['target2', 'text', strtoupper("$t-mixed")],
            't_value2' => ['target', 'regkey|value', "HKLM\\Software\\$t|$t-MIXED"],
            't_long' => ['target', 'text', "$long-a"],
            't2_twin' => ['target2', 'text', "$long-b"],
            't_excluded' => ['target', 'text', "$t-excluded"],
            't_wild' => ['target', 'text', "$t-wild-x"],
            't_blocked' => ['target', 'text', "$t-blocked"],
            't_p' => ['target', 'text', "$t-p"],
            't_pq' => ['target', 'text', "$t-pq"],
            't_qp' => ['target', 'text', "q$t-p"],
            't_qpq' => ['target', 'text', "q$t-pq"],
            't_remap' => ['target', 'text', "$t-remap"],
            't2_remap' => ['target2', 'text', strtoupper("$t-remap")],
            's_mixed' => ['source', 'text', "$t-Mixed"],
            's_long' => ['source', 'text', "$long-a"],
            's_twin' => ['source', 'other', "$long-b"],
            's_excluded' => ['source', 'text', "$t-excluded"],
            's_wild' => ['source', 'text', "$t-wild-x"],
            's_blocked' => ['source', 'text', "$t-BLOCKED"],
            's_p' => ['source', 'text', "$t-P"],
            's_pq' => ['source', 'text', "$t-pq"],
            's_qp' => ['source', 'text', "q$t-p"],
            's_qpq' => ['source', 'text', "q$t-pq"],
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
            $parts = explode('|', $value, 2);
            $this->values[$name] = [$type, $parts[0], isset($parts[1]) ? $parts[1] : ''];
        }
        $ids = implode(', ', $this->ids);
        $this->exec("UPDATE attributes SET disable_correlation = 0 WHERE id IN ($ids)");
        $this->exec("UPDATE attributes SET value1 = 'column-$t', value2 = IF(value2 = '', '', 'column-$t') WHERE id IN ($ids)");
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
     * A correlation model on the engine. Cake sets a behaviour up with the
     * model registered under the alias, so it is pointed at this one.
     *
     * @param string $engine
     * @return Correlation
     */
    private function engine($engine)
    {
        Configure::write('MISP.correlation_engine', $engine);
        $correlation = new Correlation();
        $correlation->Behaviors->{$engine . 'Correlation'}->setup($correlation, ['deadlockAvoidance' => false]);
        $correlation->Attribute;
        $this->hideTextColumns();
        return $correlation;
    }

    /**
     * Saves the correlations of every source attribute, as a save would.
     *
     * @param Correlation $correlation
     * @return void
     */
    private function correlate(Correlation $correlation)
    {
        foreach ($this->ids as $name => $id) {
            if ($name[0] !== 's') {
                continue;
            }
            $row = $this->exec(sprintf(
                'SELECT id, event_id, object_id, type, distribution, sharing_group_id, disable_correlation FROM attributes WHERE id = %d',
                $id
            ))[0];
            list(, $value1, $value2) = $this->values[$name];
            $this->assertNotFalse($correlation->afterSaveCorrelation($row + ['value1' => $value1, 'value2' => $value2]));
        }
    }

    /**
     * @param Correlation $correlation
     * @param string $event
     * @return string[] "attribute -> related attribute: value", for the fixture
     */
    private function related(Correlation $correlation, $event)
    {
        $names = array_flip($this->ids);
        $out = [];
        foreach ($correlation->getAttributesRelatedToEvent(self::ADMIN, $this->events[$event], []) as $parent => $list) {
            foreach ($list as $item) {
                if (isset($names[$parent], $names[$item['attribute_id']])) {
                    $out[] = sprintf('%s -> %s: %s', $names[$parent], $names[$item['attribute_id']], $item['value']);
                }
            }
        }
        sort($out);
        return $out;
    }

    /**
     * @param string $value
     * @return int The lowest id of the value's case variants.
     */
    private function groupOf($value)
    {
        return (int)$this->exec(sprintf(
            "SELECT MIN(id) AS id FROM attribute_values WHERE value = _utf8mb4 X'%s'",
            bin2hex($value)
        ))[0]['id'];
    }

    /**
     * @param string $table
     * @param string $a
     * @param string $b
     * @return int[] the value ids of the correlations between two fixture attributes
     */
    private function valueIds($table, $a, $b)
    {
        return array_map('intval', array_column($this->exec(sprintf(
            'SELECT value_id FROM %s WHERE (attribute_id = %2$d AND 1_attribute_id = %3$d) OR (attribute_id = %3$d AND 1_attribute_id = %2$d) ORDER BY value_id',
            $table,
            $this->ids[$a],
            $this->ids[$b]
        )), 'value_id'));
    }

    public function testACorrelationIsKeyedByItsValueGroup()
    {
        $t = $this->token;
        foreach (self::ENGINES as $engine => $table) {
            $this->correlate($this->engine($engine));
            $group = $this->groupOf("$t-mixed");
            $this->assertSame($this->ids['t_mixed'], (int)$this->exec("SELECT id FROM attributes WHERE value1_id = $group")[0]['id'], 'the first spelling saved');
            foreach (['t_mixed', 't2_upper', 't_value2'] as $target) {
                $this->assertSame([$group], $this->valueIds($table, 's_mixed', $target), "$engine $target");
            }
            $this->assertSame([$this->groupOf("$t-" . str_repeat('L', 200) . '-a')], $this->valueIds($table, 's_long', 't_long'));
            $this->assertSame([$this->groupOf("$t-" . str_repeat('L', 200) . '-b')], $this->valueIds($table, 's_twin', 't2_twin'));
        }
    }

    public function testEachSideShowsTheOtherSidesSpelling()
    {
        $t = $this->token;
        $long = "$t-" . str_repeat('L', 200);
        $fromSource = [
            "s_long -> t_long: $long-a",
            "s_mixed -> t2_upper: " . strtoupper("$t-mixed"),
            "s_mixed -> t_mixed: $t-mixed",
            // The value2 that matched, in another case
            "s_mixed -> t_value2: $t-MIXED",
        ];
        $fromTarget = [
            "t_long -> s_long: $long-a",
            "t_mixed -> s_mixed: $t-Mixed",
            "t_value2 -> s_mixed: $t-Mixed",
        ];
        foreach (array_keys(self::ENGINES) as $engine) {
            $correlation = $this->engine($engine);
            $this->correlate($correlation);
            $related = $this->related($correlation, 'source');
            foreach ($fromSource as $line) {
                $this->assertContains($line, $related, $engine);
            }
            $related = $this->related($correlation, 'target');
            foreach ($fromTarget as $line) {
                $this->assertContains($line, $related, $engine);
            }
            $scoped = $correlation->getAttributeCorrelations(self::ADMIN, $this->events['source'], [], [$this->ids['s_mixed'], $this->ids['s_long']]);
            $values = [];
            foreach ($scoped as $parent => $list) {
                foreach ($list as $item) {
                    $values[] = $item['value'];
                }
            }
            sort($values);
            $expected = [strtoupper("$t-mixed"), "$long-a", "$t-MIXED", "$t-mixed"];
            sort($expected);
            $this->assertSame($expected, $values, "$engine scoped");
            $this->assertGreaterThan(191, mb_strlen("$long-a"));
        }
    }

    public function testExactExclusionsAndBlockedValuesHideTheirGroup()
    {
        $t = $this->token;
        foreach (['"' . strtoupper("$t-excluded") . '"', "\"$t-wild%\""] as $exclusion) {
            $this->exec(sprintf("INSERT INTO correlation_exclusions (value, comment) VALUES (%s, '%s')", str_replace('"', "'", $exclusion), $t));
        }
        foreach (array_keys(self::ENGINES) as $engine) {
            $correlation = $this->engine($engine);
            $this->correlate($correlation);
            ClassRegistry::init('OverCorrelatingValue')->block(strtoupper("$t-blocked"));
            $related = $this->related($this->engine($engine), 'source');
            $this->assertContains("s_mixed -> t_mixed: $t-mixed", $related);
            $this->assertNotContains("s_excluded -> t_excluded: $t-excluded", $related, "$engine: an exact exclusion in another case");
            $this->assertContains("s_wild -> t_wild: $t-wild-x", $related, "$engine: a wildcard exclusion is left to the save-time check and the purge");
            $this->assertNotContains("s_blocked -> t_blocked: $t-blocked", $related, "$engine: blocked under another spelling");
        }
    }

    public function testAPurgeRemovesWhatTheExclusionMatches()
    {
        $t = $this->token;
        $steps = [
            strtoupper("$t-p") => ['t_p'],
            "$t-p%" => ['t_p', 't_pq'],
            "%$t-p" => ['t_p', 't_pq', 't_qp'],
            "%$t-p%" => ['t_p', 't_pq', 't_qp', 't_qpq'],
        ];
        foreach (self::ENGINES as $engine => $table) {
            $correlation = $this->engine($engine);
            $this->correlate($correlation);
            foreach ($steps as $exclusion => $gone) {
                $correlation->purgeByValue($exclusion);
                foreach (['t_p' => 's_p', 't_pq' => 's_pq', 't_qp' => 's_qp', 't_qpq' => 's_qpq'] as $target => $source) {
                    $this->assertCount(in_array($target, $gone, true) ? 0 : 1, $this->valueIds($table, $source, $target), "$engine after $exclusion: $target");
                }
                $this->assertCount(1, $this->valueIds($table, 's_mixed', 't_mixed'), 'an unrelated value stays');
            }
        }
    }

    public function testTheRemapMovesOldRowsToTheirGroups()
    {
        $t = $this->token;
        $table = 'default_correlations';
        $setting = CorrelationRemapTool::settingName($table);
        $AdminSetting = ClassRegistry::init('AdminSetting');
        $this->remapState = [$setting => $AdminSetting->getSetting($setting)];
        $long = "$t-" . str_repeat('L', 200);
        $cut = mb_substr("$long-a", 0, 191);
        $this->assertSame($cut, mb_substr("$long-b", 0, 191), 'the two long values share their first 191 characters');
        $cv = [];
        foreach (['remap' => "$t-Remap", 'cut' => $cut, 'mixed' => "$t-MIXED"] as $key => $text) {
            $this->exec(sprintf("INSERT INTO correlation_values (value) VALUES (_utf8mb4 X'%s')", bin2hex($text)));
            $this->correlationValues[] = $cv[$key] = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
        }
        $insert = function ($a, $b, $valueId) use ($table) {
            $this->exec(sprintf(
                'INSERT INTO %s (attribute_id, object_id, event_id, org_id, distribution, object_distribution, event_distribution, 1_attribute_id, 1_object_id, 1_event_id, 1_org_id, 1_distribution, 1_object_distribution, 1_event_distribution, value_id) VALUES (%d, 0, 0, 1, 5, 0, 0, %d, 0, 0, 1, 5, 0, 0, %d)',
                $table,
                $this->ids[$a],
                $this->ids[$b],
                $valueId
            ));
            return (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
        };
        $last = (int)$this->exec("SELECT MAX(id) AS id FROM $table")[0]['id'];
        $rows = [
            'remap' => $insert('t_remap', 't2_remap', $cv['remap']),
            'long' => $insert('t_long', 's_long', $cv['cut']),
            'twin' => $insert('t2_twin', 's_twin', $cv['cut']),
            'repeat' => $insert('t_mixed', 's_mixed', $cv['mixed']),
        ];
        $AdminSetting->changeSetting($setting, json_encode(['bound' => max($rows), 'last' => $last]));
        // Written after the migration, already keyed by the group
        $kept = $insert('t_mixed', 's_mixed', $this->groupOf("$t-mixed"));

        $totals = (new CorrelationRemapTool(ClassRegistry::init('AttributeValue')))->remap($table, 2);
        try {
            $this->db->rollback();
        } catch (PDOException $e) {
            // Creating the map committed the transaction: the datasource has let go of it
        }
        $this->assertSame(2, $totals['by_row']);
        $this->assertSame(1, $totals['dropped']);
        $this->assertSame(['bound' => max($rows), 'last' => max($rows)], json_decode($AdminSetting->getSetting($setting), true));
        $valueOf = function ($id) use ($table) {
            $row = $this->exec("SELECT value_id FROM $table WHERE id = $id");
            return empty($row) ? null : (int)$row[0]['value_id'];
        };
        $this->assertSame($this->groupOf("$t-remap"), $valueOf($rows['remap']));
        $this->assertSame($this->groupOf("$long-a"), $valueOf($rows['long']));
        $this->assertSame($this->groupOf("$long-b"), $valueOf($rows['twin']), 'a cut value resolved through its own attribute');
        $this->assertNull($valueOf($rows['repeat']), 'the pair is held under the group already');
        $this->assertSame($this->groupOf("$t-mixed"), $valueOf($kept));
        $this->newValues[] = $cut;
        $this->assertSame([], $this->exec(sprintf(
            "SELECT id FROM attribute_values WHERE hash = X'%s'",
            bin2hex(ClassRegistry::init('AttributeValue')->hashOf($cut))
        )), 'a cut value is never added to the dictionary');
    }

    public function testTheTopListReadsTheDictionary()
    {
        $correlation = $this->engine('Default');
        $this->correlate($correlation);
        $this->assertTrue($correlation->generateTopCorrelations());
        $top = $correlation->findTop(['limit' => 5, 'page' => 1]);
        $ids = RedisTool::init()->zRevRange(Correlation::CACHE_NAME, 0, 4);
        $this->assertCount(count($ids), $top);
        $texts = ClassRegistry::init('AttributeValue')->fetchValues($ids);
        foreach ($ids as $i => $id) {
            $this->assertSame($texts[(int)$id], $top[$i]['Correlation']['value']);
        }
    }
}
