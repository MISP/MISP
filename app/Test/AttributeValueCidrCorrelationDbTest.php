<?php
/**
 * CIDR correlation on the IP facet. An address correlates with the CIDRs
 * holding it and with its other spellings (/32, v4-mapped, uncompressed
 * IPv6), a CIDR with the single addresses it holds, both under the filters of
 * the exact matches. Two CIDRs never correlate, a CIDR of a |port type holds
 * nothing, and IPv4 sits in no IPv6 range wider than the v4-mapped block. A
 * save probes the facet once per address, a recorrelation once per chunk.
 *
 * The fixtures sit in a /24 and a /64 that no stored value overlaps. A save
 * stores /32 as the address, compresses IPv6 and refuses a CIDR on a |port
 * type, so what only legacy rows hold is made by pointing an attribute at an
 * interned value.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueCidrCorrelationDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueCidrCorrelationDbTest extends TestCase
{
    const SETTINGS = [
        'MISP.correlation_engine',
        'MISP.enable_advanced_correlations',
        'MISP.completely_disable_correlation',
        'MISP.correlation_chunk_size',
    ];

    const PROBE = '/FROM `value_ip_ranges` WHERE `ip_start` IN \(/';

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var string the first three octets of the IPv4 block */
    private $b;

    /** @var string the first four groups of the IPv6 block */
    private $p;

    /** @var int[] source, target, an event with correlation disabled */
    private $events;

    /** @var array name => attribute id */
    private $ids = [];

    /** @var array name => [type, value1, value2] as the engine is handed them */
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
            App::uses('ValueFacetTool', 'Tools');
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
        Configure::write('MISP.enable_advanced_correlations', true);
        Configure::write('MISP.completely_disable_correlation', false);
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        $this->db->begin();
        $this->b = substr($this->freeBlock(function () {
            return sprintf('%d.%d.%d.0/24', random_int(1, 223), random_int(0, 255), random_int(0, 255));
        }), 0, -5);
        $this->p = substr($this->freeBlock(function () {
            return vsprintf('2001:db8:%x:%x::/64', [random_int(4096, 65535), random_int(4096, 65535)]);
        }), 0, -5);
        $this->events = array_map('intval', $this->attribute->Event->find('column', [
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id'],
            'limit' => 3,
        ]));
        $this->exec(sprintf('UPDATE events SET disable_correlation = 0 WHERE id IN (%d, %d)', $this->events[0], $this->events[1]));
        $this->exec(sprintf('UPDATE events SET disable_correlation = 1 WHERE id = %d', $this->events[2]));
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

    /**
     * A block no facet row overlaps or holds.
     *
     * @param callable $candidate
     * @return string
     */
    private function freeBlock(callable $candidate)
    {
        for ($try = 0; $try < 20; $try++) {
            $cidr = $candidate();
            $range = ValueFacetTool::ipRange($cidr);
            $taken = $this->exec(sprintf(
                "SELECT 1 FROM value_ip_ranges WHERE ip_start <= X'%s' AND ip_end >= X'%s' LIMIT 1",
                bin2hex($range[1]),
                bin2hex($range[0])
            ));
            if (empty($taken)) {
                return $cidr;
            }
        }
        $this->fail('No free address block found.');
    }

    private function createFixture()
    {
        $b = $this->b;
        $p = $this->p;
        list($source, $target, $off) = $this->events;
        $this->add([
            's_ip' => [$source, 'ip-dst', "$b.10"],
            's_ip_port' => [$source, 'ip-src|port', "$b.10|8080"],
            's_mapped' => [$source, 'ip-dst', "::ffff:$b.40"],
            's_slash32' => [$source, 'ip-src', "$b.50"],
            's_deleted' => [$source, 'ip-dst', "$b.20", 'deleted'],
            's_disabled' => [$source, 'ip-dst', "$b.21", 'disabled'],
            's_text' => [$source, 'text', "$b.30"],
            's_nested' => [$source, 'ip-dst', "$b.0/28"],
            's_cidr' => [$source, 'ip-dst', "$b.0/24"],
            's_ip6' => [$source, 'ip-dst', "$p::7"],
            's_ip6_long' => [$source, 'ip-dst', "$p::8"],
            's_compat' => [$source, 'ip-dst', vsprintf('::%x:%x:%x', [random_int(4096, 65534), random_int(4096, 65535), random_int(4096, 65535)])],
            't_cidr' => [$target, 'ip-dst', "$b.0/24"],
            't_cidr_hostbits' => [$target, 'ip-src', "$b.99/24"],
            't_cidr_port' => [$target, 'ip-dst|port', "$b.0|80"],
            't_slash32' => [$target, 'ip-src', "$b.10"],
            't_mapped' => [$target, 'ip-dst|port', "::ffff:$b.10|443"],
            't_exact' => [$target, 'ip-dst', "$b.10"],
            't_deleted' => [$target, 'ip-dst', "$b.0/25", 'deleted'],
            't_disabled' => [$target, 'ip-dst', "$b.0/26", 'disabled'],
            't_text' => [$target, 'text', "$b.0/24"],
            't_other' => [$target, 'ip-dst', "$b.128/25"],
            't_v4all' => [$target, 'ip-dst', '::ffff:0:0/96'],
            't_wide6' => [$target, 'ip-dst', '::/0'],
            't_v6low' => [$target, 'ip-dst', '::/80'],
            't_cidr6' => [$target, 'ip-dst', "$p::/64"],
            't_member6' => [$target, 'ip-dst', "$p::7"],
            'o_cidr' => [$off, 'ip-dst', "$b.0/24"],
            'o_ip' => [$off, 'ip-dst', "$b.60"],
        ]);
        $long = function ($group) use ($p) {
            $groups = array_map(function ($g) {
                return sprintf('%04x', hexdec($g));
            }, explode(':', $p));
            return implode(':', $groups) . ":0000:0000:0000:$group";
        };
        $this->legacy('s_slash32', "$b.50/32");
        $this->legacy('t_slash32', "$b.10/32");
        $this->legacy('t_cidr_port', "$b.0/24");
        $this->legacy('s_ip6_long', $long('0008'));
        $this->legacy('t_member6', $long('0007'));
    }

    /**
     * Attributes saved without correlating, then switched on unless flagged
     * disabled, flagged ones soft-deleted, the text columns diverged and
     * hidden.
     *
     * @param array $specs name => [event id, type, value, flag]
     * @return void
     */
    private function add(array $specs)
    {
        $added = [];
        $enabled = [];
        $deleted = [];
        foreach ($specs as $name => $spec) {
            list($eventId, $type, $value) = $spec;
            $flag = isset($spec[3]) ? $spec[3] : null;
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
            $this->assertNotFalse($saved, $name . json_encode($this->attribute->validationErrors));
            $added[] = $this->ids[$name] = (int)$this->attribute->id;
            $row = $this->exec(sprintf(
                'SELECT v1.value AS value1, v2.value AS value2 FROM attributes a JOIN attribute_values v1 ON v1.id = a.value1_id LEFT JOIN attribute_values v2 ON v2.id = a.value2_id WHERE a.id = %d',
                $this->ids[$name]
            ))[0];
            $this->values[$name] = [$type, $row['value1'], (string)$row['value2']];
            if ($flag !== 'disabled') {
                $enabled[] = $this->ids[$name];
            }
            if ($flag === 'deleted') {
                $deleted[] = $this->ids[$name];
            }
        }
        $this->exec(sprintf('UPDATE attributes SET disable_correlation = 0 WHERE id IN (%s)', implode(', ', $enabled)));
        $this->exec(sprintf('UPDATE attributes SET deleted = 1 WHERE id IN (%s)', implode(', ', $deleted)));
        AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf(
            "UPDATE attributes SET value1 = 'column-x', value2 = IF(value2 = '', '', 'column-x') WHERE id IN (%s)",
            implode(', ', $added)
        ));
        $this->hideTextColumns();
    }

    /**
     * Point an attribute at a spelling a save would have normalised away.
     *
     * @param string $name
     * @param string $value1
     * @return void
     */
    private function legacy($name, $value1)
    {
        $id = ClassRegistry::init('AttributeValue')->intern($value1);
        $this->exec(sprintf('UPDATE attributes SET value1_id = %d WHERE id = %d', $id, $this->ids[$name]));
        $this->values[$name][1] = $value1;
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
     * @param string $engine
     * @return Correlation
     */
    private function engine($engine)
    {
        Configure::write('MISP.correlation_engine', $engine);
        $correlation = new Correlation();
        // Behaviours are set up with the first model registered (G71)
        $correlation->Behaviors->{$engine . 'Correlation'}->setup($correlation, ['deadlockAvoidance' => false]);
        $correlation->Attribute;
        $this->hideTextColumns();
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
     * @return array the other fixture's name => the texts of its correlations' value groups
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
            $this->assertArrayHasKey($other, $names, 'Only fixtures can match: the blocks are free');
            $out[$names[$other]][] = $row['value'];
        }
        ksort($out);
        return $out;
    }

    /**
     * @param string ...$names
     * @return array name => [the text of its value1]
     */
    private function byValue1(...$names)
    {
        $out = [];
        foreach ($names as $name) {
            $out[$name] = [$this->values[$name][1]];
        }
        ksort($out);
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

    private function clearLog()
    {
        $this->db->getLog(false, true);
    }

    private function assertNo2xCidrRead()
    {
        $this->assertSame([], $this->statements("/INET_ATON|IS_IPV6|LIKE '%\\/%'/"));
        foreach ($this->statements('/`attributes`/') as $statement) {
            $this->assertNotRegExp('/`value[12]`/', $statement);
        }
    }

    /**
     * As an edit saves it: the attribute's rows purged, then correlated.
     */
    private function correlate(Correlation $correlation, $name)
    {
        $correlation->beforeSaveCorrelation($this->saved($name));
        $this->clearLog();
        $this->assertNotFalse($correlation->afterSaveCorrelation($this->saved($name)));
        $this->assertNo2xCidrRead();
    }

    private function expectedForTheAddress()
    {
        // The exact match once, keyed by the address; the others by their own value
        return $this->byValue1('t_cidr', 't_cidr_hostbits', 't_exact', 't_mapped', 't_slash32', 't_v4all');
    }

    public function testAnAddressCorrelatesWithTheCidrsHoldingItAndItsOtherSpellings()
    {
        foreach (['Default' => 'default_correlations', 'NoAcl' => 'no_acl_correlations'] as $engine => $table) {
            $correlation = $this->engine($engine);
            $this->correlate($correlation, 's_ip');
            $this->assertCount(1, $this->statements(self::PROBE), 'one probe for the address');
            $this->assertSame($this->expectedForTheAddress(), $this->correlationsOf($table, 's_ip'), $engine);
        }
    }

    public function testACidrCorrelatesWithTheSingleAddressesItHolds()
    {
        $correlation = $this->engine('Default');
        $this->correlate($correlation, 't_cidr');
        $this->assertSame([], $this->statements(self::PROBE));
        // s_cidr is the exact match
        $this->assertSame(
            $this->byValue1('s_cidr', 's_ip', 's_ip_port', 's_mapped', 's_slash32'),
            $this->correlationsOf('default_correlations', 't_cidr')
        );
    }

    public function testACidrOfAPortTypeOnlyCorrelatesExactly()
    {
        $correlation = $this->engine('Default');
        $this->correlate($correlation, 't_cidr_port');
        $this->assertSame($this->byValue1('s_cidr'), $this->correlationsOf('default_correlations', 't_cidr_port'));
    }

    public function testIpv6MatchesAnySpellingAndIpv4StaysOutOfWideIpv6Ranges()
    {
        $correlation = $this->engine('Default');
        $this->correlate($correlation, 's_ip6');
        $this->assertSame($this->byValue1('t_cidr6', 't_member6', 't_wide6'), $this->correlationsOf('default_correlations', 's_ip6'));

        $this->correlate($correlation, 't_cidr6');
        $this->assertSame($this->byValue1('s_ip6', 's_ip6_long'), $this->correlationsOf('default_correlations', 't_cidr6'));

        // ::/80 ends with the v4-mapped block: it holds its other addresses, no IPv4
        $this->correlate($correlation, 't_v6low');
        $this->assertSame($this->byValue1('s_compat'), $this->correlationsOf('default_correlations', 't_v6low'));
    }

    public function testWithoutAdvancedCorrelationsOnlyTheExactMatchRemains()
    {
        Configure::write('MISP.enable_advanced_correlations', false);
        $correlation = $this->engine('Default');
        $this->correlate($correlation, 's_ip');
        $this->assertSame([], $this->statements(self::PROBE));
        $this->assertSame($this->byValue1('t_exact'), $this->correlationsOf('default_correlations', 's_ip'));
    }

    public function testARecorrelationProbesOncePerChunk()
    {
        Configure::write('MISP.correlation_chunk_size', 5000);
        $correlation = $this->engine('Default');
        $this->clearLog();
        $correlation->generateCorrelation(false, $this->events[0]);
        $this->assertNo2xCidrRead();
        $this->assertCount(1, $this->statements(self::PROBE));
        $this->assertSame($this->expectedForTheAddress(), $this->correlationsOf('default_correlations', 's_ip'));
        $this->assertSame($this->byValue1('t_cidr6', 't_member6', 't_wide6'), $this->correlationsOf('default_correlations', 's_ip6'));

        // The chunk's lookups are gone with it
        $this->correlate($correlation, 's_ip');
        $this->assertCount(1, $this->statements(self::PROBE));

        Configure::write('MISP.correlation_chunk_size', 3);
        $correlation = $this->engine('Default');
        $rows = $this->exec(sprintf(
            "SELECT a.type, v.value FROM attributes a JOIN attribute_values v ON v.id = a.value1_id WHERE a.event_id = %d AND a.deleted = 0 AND a.disable_correlation = 0 AND a.type NOT IN ('%s') ORDER BY a.id",
            $this->events[0],
            implode("', '", MispAttribute::NON_CORRELATING_TYPES)
        ));
        $chunks = 0;
        foreach (array_chunk($rows, 3) as $chunk) {
            foreach ($chunk as $row) {
                $range = ValueFacetTool::ipRange($row['value']);
                if (in_array($row['type'], Correlation::IP_TYPES, true) && $range !== null && $range[2] === 128) {
                    $chunks++;
                    break;
                }
            }
        }
        $this->clearLog();
        $correlation->generateCorrelation(false, $this->events[0]);
        $this->assertGreaterThan(1, $chunks);
        $this->assertCount($chunks, $this->statements(self::PROBE));
        $this->assertSame($this->expectedForTheAddress(), $this->correlationsOf('default_correlations', 's_ip'));
    }

    public function testCorrelatingAValueAddsItsCidrMatchesUnderTheSameFilters()
    {
        $correlation = $this->engine('Default');
        $this->clearLog();
        $this->assertTrue($correlation->correlateValue($this->values['s_ip'][1]));
        $this->assertNo2xCidrRead();
        $this->assertSame(
            ['t_cidr', 't_cidr_hostbits', 't_exact', 't_mapped', 't_slash32', 't_v4all'],
            array_keys($this->correlationsOf('default_correlations', 's_ip'))
        );
    }
}
