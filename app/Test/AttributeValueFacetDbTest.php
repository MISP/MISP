<?php
/**
 * The IP facet against the configured MySQL/MariaDB database: rows written
 * when values are interned, the byte order the range lookups rely on, and a
 * rebuild over the test's own ids.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueFacetDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueFacetDbTest extends TestCase
{
    private static $booted = false;

    /** @var AttributeValue */
    private $model;

    /** @var DboSource */
    private $db;

    /** @var string */
    private $token;

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
        $this->model = ClassRegistry::init('AttributeValue');
        $this->db = $this->model->getDataSource();
        if (!($this->db instanceof Mysql)) {
            // Skipped before the fixture exists: nothing for tearDown to clean up
            $this->db = null;
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->db->begin();
        $this->token = 'avfacet' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        if ($this->db) {
            $this->db->rollback();
        }
    }

    /**
     * Addresses the dictionary does not hold yet: IPv4 from the shared
     * 100.64.0.0/10 range, IPv6 from the documentation prefix.
     *
     * @return array name => value
     */
    private function fixtures()
    {
        for ($attempt = 0; $attempt < 10; $attempt++) {
            $a = random_int(64, 127);
            $b = random_int(0, 255);
            $x = random_int(1, 0xffff);
            $y = random_int(1, 0xfffe);
            $six = sprintf('2001:db8:%x:%x', $x, $y);
            $values = [
                'cidr4' => "100.$a.$b.77/24",
                'inside4' => "100.$a.$b.5",
                'edge4' => "100.$a.$b.255",
                'outside4' => sprintf('100.%d.%d.5', $a, ($b + 1) % 256),
                'cidr6' => "$six::/64",
                'inside6' => "$six::1",
                'outside6' => sprintf('2001:db8:%x:%x::1', $x, $y + 1),
                'text' => "{$this->token} not an address",
            ];
            if (empty($this->model->idsOf(array_values($values)))) {
                return $values;
            }
        }
        $this->fail('No unused addresses found.');
    }

    private function facetRows(array $ids)
    {
        $rows = [];
        $statement = $this->db->rawQuery(sprintf(
            'SELECT value_id, HEX(ip_start) AS s, HEX(ip_end) AS e, prefix FROM value_ip_ranges WHERE value_id IN (%s)',
            implode(', ', array_map('intval', $ids))
        ));
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $rows[(int)$row['value_id']] = [strtolower($row['s']), strtolower($row['e']), (int)$row['prefix']];
        }
        $statement->closeCursor();
        ksort($rows);
        return $rows;
    }

    private function column($sql)
    {
        $statement = $this->db->rawQuery($sql);
        $values = array_map('intval', $statement->fetchAll(PDO::FETCH_COLUMN));
        $statement->closeCursor();
        sort($values);
        return $values;
    }

    private function expected(array $values, array $ids)
    {
        $rows = [];
        foreach ($values as $value) {
            $range = ValueFacetTool::ipRange($value);
            if ($range !== null) {
                $rows[$ids[$value]] = [bin2hex($range[0]), bin2hex($range[1]), $range[2]];
            }
        }
        ksort($rows);
        return $rows;
    }

    public function testNewAddressesGetTheirRowsWhenInterned()
    {
        $values = $this->fixtures();
        $ids = $this->model->internMany(array_values($values));

        $rows = $this->facetRows($ids);
        $this->assertCount(7, $rows);
        $this->assertSame($this->expected($values, $ids), $rows);
        $this->assertArrayNotHasKey($ids[$values['text']], $rows);
        $v4 = '00000000000000000000ffff';
        $this->assertSame(substr($rows[$ids[$values['cidr4']]][0], 0, 30) . '00', $rows[$ids[$values['cidr4']]][0]);
        $this->assertSame(substr($rows[$ids[$values['cidr4']]][0], 0, 30) . 'ff', $rows[$ids[$values['cidr4']]][1]);
        $this->assertSame(120, $rows[$ids[$values['cidr4']]][2]);
        $this->assertStringStartsWith($v4, $rows[$ids[$values['inside4']]][0]);

        $this->db->fullDebug = true;
        $this->db->getLog(false, true);
        $again = $this->model->internMany(array_values($values));
        $log = $this->db->getLog(false, true)['log'];
        $this->db->fullDebug = false;
        $this->assertSame($ids, $again);
        $this->assertSame([], preg_grep('/value_ip_ranges/', array_column($log, 'query')));
        $this->assertSame($rows, $this->facetRows($ids));
    }

    public function testTheRowsGoWithTheValuesWhenTheTransactionRollsBack()
    {
        $values = $this->fixtures();
        $ids = $this->model->internMany(array_values($values));
        $this->assertCount(7, $this->facetRows($ids));

        $this->db->rollback();
        $this->db->begin();
        $this->assertSame([], $this->facetRows($ids));
        $this->assertSame([], $this->model->idsOf(array_values($values)));
    }

    public function testRangeLookupsFindTheMembersInTheByteOrder()
    {
        $values = $this->fixtures();
        $ids = $this->model->internMany(array_values($values));
        $own = implode(', ', array_map('intval', $ids));
        $cidrs = [$ids[$values['cidr4']], $ids[$values['cidr6']]];

        foreach (['cidr4' => ['inside4', 'edge4'], 'cidr6' => ['inside6']] as $cidr => $members) {
            $range = ValueFacetTool::ipRange($values[$cidr]);
            $found = $this->column(sprintf(
                "SELECT value_id FROM value_ip_ranges WHERE ip_start BETWEEN X'%s' AND X'%s' AND ip_start = ip_end AND value_id IN (%s)",
                bin2hex($range[0]),
                bin2hex($range[1]),
                $own
            ));
            $expected = array_map(function ($name) use ($ids, $values) {
                return $ids[$values[$name]];
            }, $members);
            sort($expected);
            $this->assertSame($expected, $found, $cidr);
        }

        foreach (['inside4' => $ids[$values['cidr4']], 'inside6' => $ids[$values['cidr6']]] as $name => $cidrId) {
            $ip = ValueFacetTool::ipRange($values[$name])[0];
            $this->assertSame([$cidrId], $this->column(sprintf(
                "SELECT value_id FROM value_ip_ranges WHERE ip_start <= X'%1\$s' AND ip_end >= X'%1\$s' AND ip_start < ip_end AND value_id IN (%2\$s)",
                bin2hex($ip),
                $own
            )), $name);
        }
        foreach (['outside4', 'outside6'] as $name) {
            $ip = ValueFacetTool::ipRange($values[$name])[0];
            $this->assertSame([], array_intersect($cidrs, $this->column(sprintf(
                "SELECT value_id FROM value_ip_ranges WHERE ip_start <= X'%1\$s' AND ip_end >= X'%1\$s' AND ip_start < ip_end AND value_id IN (%2\$s)",
                bin2hex($ip),
                $own
            ))), $name);
        }
    }

    public function testARebuildPutsTheTestIdsRight()
    {
        $values = $this->fixtures();
        $ids = $this->model->internMany(array_values($values));
        $expected = $this->expected($values, $ids);
        $text = $ids[$values['text']];
        $this->db->rawQuery(sprintf('DELETE FROM value_ip_ranges WHERE value_id = %d', $ids[$values['inside4']]));
        $this->db->rawQuery(sprintf('UPDATE value_ip_ranges SET prefix = 1 WHERE value_id = %d', $ids[$values['cidr6']]));
        $this->db->rawQuery(sprintf(
            "INSERT INTO value_ip_ranges (value_id, ip_start, ip_end, prefix) VALUES (%d, X'%s', X'%s', 128)",
            $text,
            str_repeat('00', 16),
            str_repeat('00', 16)
        ));

        $from = min($ids) - 1;
        $to = max($ids);
        $totals = $this->model->facets()->rebuild(3, null, $from, $to);

        $this->assertSame(count($ids), $totals['values']);
        $this->assertSame(7, $totals['facets']);
        $this->assertSame(2, $totals['added']);
        $this->assertSame(2, $totals['removed']);
        $this->assertSame($to, $totals['last_id']);
        $this->assertSame($expected, $this->facetRows($ids));

        $again = $this->model->facets()->rebuild(3, null, $from, $to);
        $this->assertSame([0, 0], [$again['added'], $again['removed']]);
    }

    public function testARebuildRemovesTheRowOfAValueThatIsGone()
    {
        $values = $this->fixtures();
        $ids = $this->model->internMany(array_values($values));
        $gone = $ids[$values['inside6']];
        $this->db->rawQuery(sprintf('DELETE FROM attribute_values WHERE id = %d', $gone));

        $totals = $this->model->facets()->rebuild(ValueFacetTool::CHUNK, null, min($ids) - 1, max($ids));

        $this->assertSame(1, $totals['removed']);
        $this->assertSame([], $this->facetRows([$gone]));
        $this->assertCount(6, $this->facetRows($ids));
    }
}
