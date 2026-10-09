<?php
/**
 * The dashboard widgets that read attribute values (TrendingAttributes, the
 * vulnerability dimension of Trending, AttributeGeoMap) take them from the
 * dictionary and name no value text column in SQL. TrendingAttributes counts
 * each exact value (owner, 2026-10-09: 2.x counted case variants together);
 * the vulnerability dimension still does. The tests hide value1 and value2 from every attribute
 * model's schema, the way the column drop will, point the stored text away
 * from the dictionary, so a read of the columns shows, and check the
 * statements the widgets sent.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueWidgetDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueWidgetDbTest extends TestCase
{
    const TEXT_COLUMN = '/`Attribute`\.`value[12]`/';

    /** Generous enough to return every value in the window, the fixtures among them */
    const EVERYTHING = 100000;

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var array */
    private $admin;

    /** @var array */
    private $lesser;

    /** @var string Keeps the test values apart from real ones. */
    private $token;

    /** @var string */
    private $ip;

    /** @var string A vulnerability id of its own, stored in two spellings */
    private $cve;

    /** @var bool */
    private $cachedMethods;

    /** @var bool */
    private $fullDebug;

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
            require_once __DIR__ . '/OracleBootstrap.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('CakeText', 'Utility');
            App::uses('AttributeValue', 'Model');
            foreach (['TrendingAttributesWidget', 'TrendingWidget', 'AttributeGeoMapWidget'] as $widget) {
                require_once APP . "Lib/Dashboard/$widget.php";
            }
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $User = ClassRegistry::init('User');
        $this->admin = $User->getAuthUser(1);
        $lesser = $User->find('first', [
            'recursive' => -1,
            'fields' => ['User.id'],
            'joins' => [['table' => 'roles', 'alias' => 'Role', 'conditions' => ['Role.id = User.role_id', 'Role.perm_site_admin' => 0]]],
            'conditions' => ['User.disabled' => 0],
            'order' => ['User.id' => 'ASC'],
        ]);
        if (empty($lesser)) {
            $this->markTestSkipped('Needs a user who is not a site admin.');
        }
        $this->lesser = $User->getAuthUser($lesser['User']['id']);
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', $this->admin['id']);
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        $logMax = new ReflectionProperty('DboSource', '_queriesLogMax');
        $logMax->setAccessible(true);
        $logMax->setValue($this->db, 100000);
        $this->token = 'avwid' . bin2hex(random_bytes(4));
        $this->db->begin();
        $this->createFixture();
        $this->hideTextColumns();
        $this->db->fullDebug = true;
    }

    protected function tearDown(): void
    {
        if (!$this->db) {
            return;
        }
        Configure::write('CurrentUserId', $this->currentUserId);
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

    private function createEvent($orgId)
    {
        $this->exec(sprintf(
            "INSERT INTO events (org_id, orgc_id, user_id, date, info, uuid, analysis, distribution, sharing_group_id, threat_level_id, disable_correlation)"
            . " VALUES (%d, %d, 1, CURDATE(), 'widgets %s', '%s', 0, 0, 0, 4, 1)",
            $orgId,
            $orgId,
            $this->token,
            CakeText::uuid()
        ));
        return (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
    }

    private function create($eventId, $type, $value, $objectId = 0, $relation = null)
    {
        $this->attribute->create();
        $saved = $this->attribute->save(['Attribute' => [
            'event_id' => $eventId,
            'object_id' => $objectId,
            'object_relation' => $relation,
            'category' => in_array($type, ['vulnerability'], true) ? 'External analysis' : ($type === 'text' ? 'Other' : 'Network activity'),
            'type' => $type,
            'value' => $value,
            'distribution' => 5,
            'to_ids' => 0,
            'disable_correlation' => 1,
        ]]);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        return (int)$this->attribute->id;
    }

    private function createFixture()
    {
        $t = $this->token;
        $orgId = (int)$this->lesser['org_id'];
        $first = $this->createEvent($orgId);
        $second = $this->createEvent($orgId);
        $this->ip = '198.51.100.' . random_int(1, 254);
        $this->cve = 'CVE-2099-' . random_int(1000000, 9999999);
        $ids = [];
        $ids[] = $this->create($first, 'text', "$t-trend");
        $ids[] = $this->create($second, 'text', "$t-trend");
        $ids[] = $this->create($first, 'text', strtoupper("$t-trend"));
        $ids[] = $this->create($first, 'vulnerability', $this->cve);
        $ids[] = $cveVariant = $this->create($second, 'vulnerability', $this->cve);
        // A save uppercases a CVE id: the lower case spelling exists only in rows stored before
        $this->exec(sprintf(
            'UPDATE attributes SET value1_id = %d WHERE id = %d',
            ClassRegistry::init('AttributeValue')->intern(strtolower($this->cve)),
            $cveVariant
        ));
        $ids[] = $this->create($first, 'domain|ip', "geo.$t.example|{$this->ip}");
        $this->exec(sprintf(
            "INSERT INTO objects (name, `meta-category`, description, template_uuid, template_version, event_id, uuid, timestamp, distribution, sharing_group_id, comment, deleted)"
            . " VALUES ('geolocation', 'misc', '', '%s', 1, %d, '%s', %d, 5, 0, '%s', 0)",
            CakeText::uuid(),
            $first,
            CakeText::uuid(),
            time(),
            $t
        ));
        $objectId = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
        $ids[] = $this->create($first, 'text', 'LU', $objectId, 'countrycode');
        $this->exec(sprintf(
            "UPDATE attributes SET value1 = '%s', value2 = IF(value2 = '', '', '%s') WHERE id IN (%s)",
            $this->columnText(),
            $this->columnText(),
            implode(', ', $ids)
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
        ClassRegistry::init('ShadowAttribute')->Attribute;
        $this->attribute->Event->Attribute;
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
     * The statements sent since the last call that name a text column.
     *
     * @return string[]
     */
    private function textColumnStatements()
    {
        $found = [];
        foreach ($this->db->getLog(false, true)['log'] as $entry) {
            if (preg_match(self::TEXT_COLUMN, $entry['query'])) {
                $found[] = $entry['query'];
            }
        }
        return $found;
    }

    private function call($object, $method, array $args)
    {
        $reflection = new ReflectionMethod($object, $method);
        $reflection->setAccessible(true);
        return $reflection->invokeArgs($object, $args);
    }

    /**
     * The entries of a widget's value => count map that belong to the fixture,
     * by lower case value when $fold (a group shows any of its spellings).
     */
    private function own(array $counts, $fold = true)
    {
        $own = [];
        foreach ($counts as $value => $count) {
            if (stripos((string)$value, $this->token) !== false || stripos((string)$value, $this->cve) !== false) {
                $own[$fold ? strtolower((string)$value) : (string)$value] = (int)$count;
            }
        }
        ksort($own);
        return $own;
    }

    private function sorted(array $expected)
    {
        ksort($expected);
        return $expected;
    }

    public function testTrendingAttributesCountsEachSpelling()
    {
        $t = $this->token;
        $options = ['time_window' => '1d', 'threshold' => self::EVERYTHING];
        foreach (['admin' => $this->admin, 'lesser' => $this->lesser] as $who => $user) {
            $this->textColumnStatements();
            $data = (new TrendingAttributesWidget())->handler($user, $options)['data'];
            $this->assertSame([], $this->textColumnStatements(), $who);
            $this->assertSame($this->sorted([
                "$t-trend" => 2,
                strtoupper("$t-trend") => 1,
                $this->cve => 1,
                strtolower($this->cve) => 1,
                "geo.$t.example" => 1,
            ]), $this->own($data, false), $who);
            $this->assertStringNotContainsString($this->columnText(), json_encode($data), $who);
        }
    }

    public function testTrendingAttributesExcludesEveryCaseVariant()
    {
        $t = $this->token;
        $data = (new TrendingAttributesWidget())->handler($this->admin, [
            'time_window' => '1d',
            'threshold' => self::EVERYTHING,
            'exclude' => [strtoupper("$t-trend")],
        ])['data'];
        $this->assertSame($this->sorted([
            $this->cve => 1,
            strtolower($this->cve) => 1,
            "geo.$t.example" => 1,
        ]), $this->own($data, false));
    }

    public function testVulnerabilityCountsDistinctEventsOverCaseVariants()
    {
        $this->textColumnStatements();
        $counts = $this->call(new TrendingWidget(), 'countVulnerability', [$this->admin, time() - 86400, time() + 86400]);
        $this->assertSame([], $this->textColumnStatements());
        $this->assertSame([strtolower($this->cve) => 2], $this->own($counts));
    }

    public function testTheGeoMapListsReadTheDictionary()
    {
        $geo = new AttributeGeoMapWidget();
        $since = time() - 86400;
        $this->textColumnStatements();
        $ips = $this->call($geo, 'fetchAttributeValues', [$this->attribute, ['domain|ip'], 'value2_id', $since, self::EVERYTHING]);
        $domains = $this->call($geo, 'fetchAttributeValues', [$this->attribute, ['domain', 'domain|ip'], 'value1_id', $since, self::EVERYTHING]);
        $codes = $this->call($geo, 'fetchObjectRelationValues', [$this->attribute, 'countrycode', 'geolocation', $since, self::EVERYTHING]);
        $this->assertSame([], $this->textColumnStatements());
        $this->assertContains($this->ip, $ips);
        $this->assertContains("geo.{$this->token}.example", $domains);
        $this->assertContains('LU', $codes);
        $this->assertStringNotContainsString($this->columnText(), json_encode([$ips, $domains, $codes]));
    }
}
