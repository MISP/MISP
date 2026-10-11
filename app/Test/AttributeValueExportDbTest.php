<?php
/**
 * The Bro and RPZ exports take their values from the dictionary and name no
 * value text column in SQL. The tests hide value1 and value2 from every
 * attribute and proposal model's schema, the way the column drop will, point
 * the stored text away from the dictionary, so a read of the columns shows in
 * the output, and check the statements the export sent.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueExportDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueExportDbTest extends TestCase
{
    const TEXT_COLUMN = '/`(Attribute|ShadowAttribute)`\.`value[12]`/';

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var array */
    private $user;

    /** @var string Keeps the test values apart from real ones. */
    private $token;

    /** @var int */
    private $eventId;

    /** @var array name => value */
    private $values = [];

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
            require_once __DIR__ . '/AttributeValueTextSupport.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('CakeText', 'Utility');
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
        $this->user = ClassRegistry::init('User')->getAuthUser(1);
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', $this->user['id']);
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        // One find per Bro type, more statements than the default log keeps
        $logMax = new ReflectionProperty('DboSource', '_queriesLogMax');
        $logMax->setAccessible(true);
        $logMax->setValue($this->db, 100000);
        $this->token = 'avexp' . bin2hex(random_bytes(4));
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

    private function createFixture()
    {
        $t = $this->token;
        $this->exec(sprintf(
            "INSERT INTO events (org_id, orgc_id, user_id, date, info, uuid, analysis, distribution, sharing_group_id, threat_level_id, published, disable_correlation)"
            . " VALUES (1, 1, 1, CURDATE(), 'export %s', '%s', 0, 0, 0, 4, 1, 1)",
            $t,
            CakeText::uuid()
        ));
        $this->eventId = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
        $md5 = md5($t);
        $this->values = [
            'domain' => "$t.example.org",
            'hostname' => "host.$t.example.net",
            'ip' => '198.51.100.' . random_int(1, 254),
            'dip_domain' => "dip.$t.example.com",
            'dip_ip' => '203.0.113.' . random_int(1, 254),
            'filename' => "$t.exe",
            'md5' => $md5,
            'url' => "$t.example.org/gate.php",
        ];
        $v = $this->values;
        $ids = [];
        foreach ([
            ['domain', $v['domain']],
            ['hostname', $v['hostname']],
            ['ip-dst', $v['ip']],
            ['domain|ip', "{$v['dip_domain']}|{$v['dip_ip']}"],
            ['filename|md5', "{$v['filename']}|$md5"],
            ['url', "https://{$v['url']}"],
        ] as list($type, $value)) {
            $this->attribute->create();
            $saved = $this->attribute->save(['Attribute' => [
                'event_id' => $this->eventId,
                'category' => in_array($type, ['filename|md5'], true) ? 'Payload delivery' : 'Network activity',
                'type' => $type,
                'value' => $value,
                'distribution' => 5,
                'to_ids' => 1,
                'disable_correlation' => 1,
            ]]);
            $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
            $ids[] = (int)$this->attribute->id;
        }
        AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf(
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

    private function assertNoColumnText($output)
    {
        $this->assertStringNotContainsString($this->columnText(), $output);
    }

    public function testBroTakesBothPartsFromTheDictionary()
    {
        $this->textColumnStatements();
        $lines = $this->attribute->bro($this->user, 'all', false, (string)$this->eventId, false, false, false, false, true);
        $this->assertSame([], $this->textColumnStatements());
        $v = $this->values;
        $expected = [
            [$v['domain'], 'DOMAIN'],
            [$v['hostname'], 'DOMAIN'],
            [$v['ip'], 'ADDR'],
            [$v['dip_domain'], 'DOMAIN'],
            [$v['dip_ip'], 'ADDR'],
            [$v['filename'], 'FILE_NAME'],
            [$v['md5'], 'FILE_HASH'],
            [$v['url'], 'URL'],
        ];
        $found = [];
        foreach ($lines as $line) {
            $fields = explode("\t", $line);
            $found[] = [$fields[0], substr($fields[1], strlen('Intel::'))];
        }
        sort($expected);
        sort($found);
        $this->assertSame($expected, $found);
        $this->assertNoColumnText(implode("\n", $lines));
    }

    public function testBroByTypeTakesTheCompositePartItExports()
    {
        $this->textColumnStatements();
        $names = $this->attribute->bro($this->user, 'filename', false, (string)$this->eventId, false, false, false, false, true);
        $hashes = $this->attribute->bro($this->user, 'filehash', false, (string)$this->eventId, false, false, false, false, true);
        $this->assertSame([], $this->textColumnStatements());
        $this->assertCount(1, $names);
        $this->assertStringStartsWith($this->values['filename'] . "\tIntel::FILE_NAME\t", reset($names));
        $this->assertCount(1, $hashes);
        $this->assertStringStartsWith($this->values['md5'] . "\tIntel::FILE_HASH\t", reset($hashes));
    }

    /**
     * @return string[] The lines RPZ writes for the fixture, before the action.
     */
    private function rpzLines()
    {
        $v = $this->values;
        $reverse = function ($ip) {
            return '32.' . implode('.', array_reverse(explode('.', $ip))) . '.rpz-ip';
        };
        return [
            $reverse($v['ip']),
            $reverse($v['dip_ip']),
            $v['domain'],
            '*.' . $v['domain'],
            $v['dip_domain'],
            '*.' . $v['dip_domain'],
            $v['hostname'],
        ];
    }

    private function assertRpz($output)
    {
        $named = [];
        foreach (explode("\n", $output) as $line) {
            if (strpos($line, ' CNAME ') !== false) {
                $named[] = substr($line, 0, strpos($line, ' CNAME '));
            }
        }
        $expected = $this->rpzLines();
        sort($expected);
        sort($named);
        $this->assertSame($expected, $named, $output);
        $this->assertNoColumnText($output);
    }

    public function testRpzAttributeScopeTakesBothPartsFromTheDictionary()
    {
        $this->textColumnStatements();
        $tmp = $this->attribute->restSearch($this->user, 'rpz', ['eventid' => $this->eventId]);
        $this->assertSame([], $this->textColumnStatements());
        $this->assertRpz($tmp->intoString());
    }

    public function testRpzEventScopeSplitsTheValue()
    {
        $this->textColumnStatements();
        $tmp = $this->attribute->Event->restSearch($this->user, 'rpz', ['eventid' => $this->eventId]);
        $this->assertSame([], $this->textColumnStatements());
        $this->assertRpz($tmp->intoString());
    }
}
