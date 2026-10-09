<?php
/**
 * ValueFacetTool without a database: what parses as an address or CIDR and
 * the range it covers, and the statements a rebuild sends for each window.
 *
 * AttributeValueFacetDbTest runs the tool against the real database.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';

use PHPUnit\Framework\TestCase;

class ValueFacetFakeStatement
{
    private $rows;

    private $count;

    public function __construct(array $rows, $count)
    {
        $this->rows = $rows;
        $this->count = $count;
    }

    public function fetchAll($mode = null)
    {
        return $this->rows;
    }

    public function rowCount()
    {
        return $this->count;
    }

    public function closeCursor()
    {
        return true;
    }
}

trait ValueFacetFakeDb
{
    /** @var string[] */
    public $statements = [];

    /** @var array id => value, the dictionary */
    public $values = [];

    /** @var array value id => [start, end, prefix], the facet */
    public $facets = [];

    public function rawQuery($sql, $params = array())
    {
        $this->statements[] = $sql;
        if (preg_match('/^SELECT MAX/', $sql)) {
            return new ValueFacetFakeStatement([['id' => empty($this->values) ? null : (string)max(array_keys($this->values))]], 0);
        }
        if (preg_match('/^SELECT .*CASE WHEN .* WHERE \W?id\W? > (\d+) AND \W?id\W? <= (\d+)$/', $sql, $m)) {
            $out = [];
            foreach ($this->values as $id => $value) {
                if ($id > (int)$m[1] && $id <= (int)$m[2]) {
                    $candidate = strlen($value) <= ValueFacetTool::MAX_TEXT && strpbrk($value, '.:') !== false;
                    $out[] = ['id' => (string)$id, 'value' => $candidate ? $value : null];
                }
            }
            return new ValueFacetFakeStatement($out, 0);
        }
        if (preg_match('/^SELECT .* FROM \W?value_ip_ranges\W? WHERE \W?value_id\W? > (\d+) AND \W?value_id\W? <= (\d+)$/', $sql, $m)) {
            $out = [];
            foreach ($this->facets as $id => $facet) {
                if ($id > (int)$m[1] && $id <= (int)$m[2]) {
                    $out[] = ['value_id' => (string)$id, 'ip_start' => $facet[0], 'ip_end' => $facet[1], 'prefix' => (string)$facet[2]];
                }
            }
            return new ValueFacetFakeStatement($out, 0);
        }
        if (preg_match('/^SELECT .* FROM \W?value_ip_ranges\W? WHERE \W?ip_start\W? IN \((.*)\)$/', $sql, $m)) {
            preg_match_all("/(?:X'|decode\(')([0-9a-f]+)'/", $m[1], $literals);
            $starts = array_map('hex2bin', $literals[1]);
            $out = [];
            foreach ($this->facets as $id => $facet) {
                if (in_array($facet[0], $starts, true)) {
                    $out[] = ['value_id' => (string)$id, 'ip_start' => $facet[0], 'ip_end' => $facet[1]];
                }
            }
            return new ValueFacetFakeStatement($out, 0);
        }
        if (preg_match('/^DELETE .* NOT IN/', $sql)) {
            preg_match('/\W?value_id\W? > (\d+)(?: AND \W?value_id\W? <= (\d+))?/', $sql, $m);
            $removed = 0;
            foreach (array_keys($this->facets) as $id) {
                if ($id > (int)$m[1] && (!isset($m[2]) || $id <= (int)$m[2]) && !isset($this->values[$id])) {
                    unset($this->facets[$id]);
                    $removed++;
                }
            }
            return new ValueFacetFakeStatement([], $removed);
        }
        if (preg_match('/^DELETE .* IN \(([\d, ]+)\)$/', $sql, $m)) {
            foreach (explode(', ', $m[1]) as $id) {
                unset($this->facets[(int)$id]);
            }
            return new ValueFacetFakeStatement([], 0);
        }
        if (strpos($sql, 'INSERT INTO') === 0) {
            preg_match_all("/\((\d+), (?:X'|decode\(')([0-9a-f]+)'(?:, 'hex'\))?, (?:X'|decode\(')([0-9a-f]+)'(?:, 'hex'\))?, (\d+)\)/", $sql, $rows, PREG_SET_ORDER);
            foreach ($rows as $row) {
                if (!isset($this->facets[(int)$row[1]])) {
                    $this->facets[(int)$row[1]] = [hex2bin($row[2]), hex2bin($row[3]), (int)$row[4]];
                }
            }
            return true;
        }
        throw new RuntimeException('Unexpected statement: ' . $sql);
    }

    public function begin()
    {
        $this->statements[] = 'BEGIN';
        return true;
    }

    public function commit()
    {
        $this->statements[] = 'COMMIT';
        return true;
    }

    public function rollback()
    {
        $this->statements[] = 'ROLLBACK';
        return true;
    }

    public function writes()
    {
        return array_values(preg_grep('/^(INSERT|DELETE|BEGIN|COMMIT|ROLLBACK)/', $this->statements));
    }
}

class ValueFacetFakeMysql extends MigrationTestMysqlExtended
{
    use ValueFacetFakeDb;
}

class ValueFacetFakePostgres extends MigrationTestPostgres
{
    use ValueFacetFakeDb;
}

class ValueFacetToolTest extends TestCase
{
    protected function setUp(): void
    {
        require_once __DIR__ . '/AttributeValueTestSupport.php';
        require_once __DIR__ . '/../Lib/Tools/ValueFacetTool.php';
    }

    private function tool($db)
    {
        return new ValueFacetTool(new TestAttributeValue($db));
    }

    private static function range($start, $end, $prefix)
    {
        return [hex2bin($start), hex2bin($end), $prefix];
    }

    public function addresses()
    {
        $v4 = '00000000000000000000ffff';
        return [
            'IPv4' => ['192.0.2.1', $v4 . 'c0000201', $v4 . 'c0000201', 128],
            'IPv4 CIDR' => ['10.0.0.0/8', $v4 . '0a000000', $v4 . '0affffff', 104],
            'IPv4 CIDR with host bits' => ['10.1.2.3/8', $v4 . '0a000000', $v4 . '0affffff', 104],
            'IPv4 mask off a byte boundary' => ['172.20.5.4/12', $v4 . 'ac100000', $v4 . 'ac1fffff', 108],
            'IPv4 /32' => ['10.0.0.1/32', $v4 . '0a000001', $v4 . '0a000001', 128],
            'IPv4 /0' => ['0.0.0.0/0', $v4 . '00000000', $v4 . 'ffffffff', 96],
            'mask with a leading zero' => ['10.0.0.0/08', $v4 . '0a000000', $v4 . '0affffff', 104],
            'IPv6' => ['2001:db8::1', '20010db8000000000000000000000001', '20010db8000000000000000000000001', 128],
            'IPv6 CIDR' => ['2001:db8::/32', '20010db8000000000000000000000000', '20010db8ffffffffffffffffffffffff', 32],
            'IPv6 mask off a byte boundary' => ['2001:db8:abcd::/35', '20010db8a00000000000000000000000', '20010db8bfffffffffffffffffffffff', 35],
            'IPv6 /0' => ['::/0', '00000000000000000000000000000000', 'ffffffffffffffffffffffffffffffff', 0],
            'v4-mapped IPv6 shares the IPv4 range' => ['::ffff:192.0.2.1', $v4 . 'c0000201', $v4 . 'c0000201', 128],
            'uppercase IPv6' => ['2001:DB8::1', '20010db8000000000000000000000001', '20010db8000000000000000000000001', 128],
        ];
    }

    /**
     * @dataProvider addresses
     */
    public function testWhatAnAddressOrCidrCovers($value, $start, $end, $prefix)
    {
        $this->assertSame(self::range($start, $end, $prefix), ValueFacetTool::ipRange($value));
    }

    public function notAddresses()
    {
        return [
            [''], ['example.org'], ['1.2.3'], ['01.2.3.4'], ['256.1.1.1'], ['1.2.3.4/33'], ['::1/129'],
            ['1.2.3.4/'], ['1.2.3.4/a'], ['1.2.3.4/-1'], ['1.2.3.4/ 8'], [' 1.2.3.4'], ['1.2.3.4 '],
            ['fe80::1%eth0'], ['1.2.3.4/32/1'], ['1.2.3.4|80'], ['80'], ['16909060'],
            ['1111:2222:3333:4444:5555:6666:777.888.999.000'], [str_repeat('1', 50)],
        ];
    }

    /**
     * @dataProvider notAddresses
     */
    public function testAnythingElseHasNoRange($value)
    {
        $this->assertNull(ValueFacetTool::ipRange($value));
    }

    public function testAddWritesOneRowPerParsingValueInIdOrder()
    {
        $db = new ValueFacetFakeMysql();
        $this->assertSame(2, $this->tool($db)->add(['10.0.0.1' => 9, 'example.org' => 4, '10.0.0.0/8' => 7]));
        $this->assertSame([7, 9], array_keys($db->facets));
        $this->assertCount(1, $db->statements);
        $this->assertStringStartsWith('INSERT INTO `value_ip_ranges` (`value_id`, `ip_start`, `ip_end`, `prefix`) VALUES (7, ', $db->statements[0]);

        $db = new ValueFacetFakeMysql();
        $this->assertSame(0, $this->tool($db)->add(['example.org' => 4]));
        $this->assertSame([], $db->statements);
    }

    public function testAddChunksTheInsert()
    {
        $db = new ValueFacetFakePostgres();
        $ids = [];
        for ($i = 1; $i <= ValueFacetTool::INSERT_ROWS + 1; $i++) {
            $ids['10.0.' . intdiv($i, 256) . '.' . ($i % 256)] = $i;
        }
        $this->tool($db)->add($ids);
        $this->assertCount(2, $db->statements);
        $this->assertStringEndsWith('ON CONFLICT ("value_id") DO NOTHING;', $db->statements[0]);
        $this->assertCount(ValueFacetTool::INSERT_ROWS + 1, $db->facets);
    }

    public function testRebuildAddsWhatIsMissingAndLeavesWhatIsRight()
    {
        foreach ([new ValueFacetFakeMysql(), new ValueFacetFakePostgres()] as $db) {
            $db->values = [1 => '10.0.0.1', 2 => 'example.org', 3 => '2001:db8::/32', 4 => str_repeat('a', 60), 5 => '192.0.2.0/24'];
            $db->facets = [1 => ValueFacetTool::ipRange('10.0.0.1')];

            $totals = $this->tool($db)->rebuild(2);

            $this->assertSame(['values' => 5, 'facets' => 3, 'added' => 2, 'removed' => 0, 'last_id' => 5], $totals);
            $this->assertSame([1, 3, 5], array_keys($db->facets));
            $this->assertSame(ValueFacetTool::ipRange('192.0.2.0/24'), $db->facets[5]);
            // Window 1-2 is right already: read only
            $this->assertSame(['BEGIN', 'INSERT', 'COMMIT', 'BEGIN', 'INSERT', 'COMMIT', 'DELETE'], array_map(function ($s) {
                return strtok($s, ' ');
            }, $db->writes()));
        }
    }

    public function testRebuildReplacesWrongRowsAndRemovesRowsWithoutAnAddress()
    {
        $db = new ValueFacetFakeMysql();
        $db->values = [1 => '10.0.0.0/8', 2 => 'example.org', 3 => '10.0.0.3'];
        $db->facets = [
            1 => ValueFacetTool::ipRange('10.0.0.1'),
            2 => ValueFacetTool::ipRange('10.0.0.2'),
            3 => ValueFacetTool::ipRange('10.0.0.3'),
        ];

        $totals = $this->tool($db)->rebuild();

        $this->assertSame(['values' => 3, 'facets' => 2, 'added' => 1, 'removed' => 2, 'last_id' => 3], $totals);
        ksort($db->facets);
        $this->assertSame([1 => ValueFacetTool::ipRange('10.0.0.0/8'), 3 => ValueFacetTool::ipRange('10.0.0.3')], $db->facets);
        $this->assertContains('DELETE FROM `value_ip_ranges` WHERE `value_id` IN (1, 2)', $db->statements);
    }

    public function testRebuildRemovesRowsWhoseValueIsGone()
    {
        $db = new ValueFacetFakeMysql();
        $db->values = [1 => '10.0.0.1', 3 => '10.0.0.3'];
        $db->facets = [
            1 => ValueFacetTool::ipRange('10.0.0.1'),
            2 => ValueFacetTool::ipRange('10.0.0.2'),
            3 => ValueFacetTool::ipRange('10.0.0.3'),
            9 => ValueFacetTool::ipRange('10.0.0.9'),
        ];

        $totals = $this->tool($db)->rebuild();

        $this->assertSame(2, $totals['removed']);
        $this->assertSame([1, 3], array_keys($db->facets));
        $this->assertCount(2, preg_grep('/NOT IN/', $db->statements));
    }

    public function testRebuildWithinBoundsTouchesOnlyThem()
    {
        $db = new ValueFacetFakeMysql();
        $db->values = [1 => '10.0.0.1', 2 => '10.0.0.2', 3 => '10.0.0.3', 4 => '10.0.0.4'];
        $db->facets = [9 => ValueFacetTool::ipRange('10.0.0.9')];

        $totals = $this->tool($db)->rebuild(10, null, 1, 3);

        $this->assertSame(['values' => 2, 'facets' => 2, 'added' => 2, 'removed' => 0, 'last_id' => 3], $totals);
        ksort($db->facets);
        $this->assertSame([2, 3, 9], array_keys($db->facets));
        $this->assertSame([], preg_grep('/^SELECT MAX/', $db->statements));
    }

    public function testRebuildReportsProgressPerWindowAndRefusesAnEmptyChunk()
    {
        $db = new ValueFacetFakeMysql();
        $db->values = [1 => '10.0.0.1', 2 => '10.0.0.2', 3 => '10.0.0.3'];
        $seen = [];
        $this->tool($db)->rebuild(2, function (array $totals) use (&$seen) {
            $seen[] = $totals['last_id'];
        });
        $this->assertSame([2, 3], $seen);

        $this->expectException(InvalidArgumentException::class);
        $this->tool($db)->rebuild(0);
    }

    public function testARebuildWindowThatFailsIsRolledBack()
    {
        $db = new class extends ValueFacetFakeMysql {
            public function rawQuery($sql, $params = array())
            {
                if (strpos($sql, 'INSERT INTO') === 0) {
                    $this->statements[] = $sql;
                    throw new PDOException('lost connection');
                }
                return parent::rawQuery($sql, $params);
            }
        };
        $db->values = [1 => '10.0.0.1'];
        try {
            $this->tool($db)->rebuild();
            $this->fail('The insert error should reach the caller.');
        } catch (PDOException $e) {
            $this->assertSame('ROLLBACK', end($db->statements));
        }
    }

    private static function address($text)
    {
        return ValueFacetTool::ipRange($text)[0];
    }

    public function testTheStartsOfTheRangesThatCanHoldAnAddress()
    {
        foreach (['192.0.2.1' => 32, '255.255.255.255' => 32, '2001:db8::1' => 128, '::' => 128] as $text => $bits) {
            $expected = [];
            for ($mask = 0; $mask <= $bits; $mask++) {
                $expected[] = ValueFacetTool::ipRange("$text/$mask")[0];
            }
            $this->assertSame(array_values(array_unique($expected)), ValueFacetTool::containingStarts(self::address($text)), $text);
        }
        // A new start at each set bit: 192.0.2.1 has four
        $starts = ValueFacetTool::containingStarts(self::address('192.0.2.1'));
        $this->assertCount(5, $starts);
        // IPv4 is held by IPv4 ranges only, however it is spelled
        $this->assertSame(hex2bin('00000000000000000000ffff00000000'), $starts[0]);
        $this->assertSame($starts, ValueFacetTool::containingStarts(self::address('::ffff:192.0.2.1')));
        $this->assertCount(129, ValueFacetTool::containingStarts(str_repeat("\xff", 16)));
    }

    public function testAnIpv6RangeWiderThanTheV4MappedBlockLeavesItOut()
    {
        foreach (['192.0.2.0/24', '0.0.0.0/0', '::ffff:0:0/96', '2001:db8::/32', '::/96', '::1:0:0:0/80'] as $cidr) {
            $range = ValueFacetTool::ipRange($cidr);
            $this->assertSame([[$range[0], $range[1]]], ValueFacetTool::memberRanges($range), $cidr);
        }
        $this->assertSame([
            [str_repeat("\0", 16), hex2bin('00000000000000000000fffeffffffff')],
            [hex2bin('00000000000000000001000000000000'), str_repeat("\xff", 16)],
        ], ValueFacetTool::memberRanges(ValueFacetTool::ipRange('::/0')));
        // A range ending with the block keeps what comes before it
        $this->assertSame(
            [[str_repeat("\0", 16), hex2bin('00000000000000000000fffeffffffff')]],
            ValueFacetTool::memberRanges(ValueFacetTool::ipRange('::/80'))
        );
    }

    public function testTheRangesHoldingEachAddressAreReadInOneStatement()
    {
        foreach ([new ValueFacetFakeMysql(), new ValueFacetFakePostgres()] as $db) {
            $values = [
                1 => '192.0.2.0/24', 2 => '192.0.2.1', 3 => '::ffff:192.0.2.1', 4 => '192.0.2.1/32',
                5 => '::/0', 6 => '::ffff:0:0/96', 7 => '192.0.2.0', 8 => '2001:db8::/32',
                9 => '192.0.2.128/25', 10 => '192.0.0.0/16', 11 => '2001:db8::5', 12 => '198.51.100.0/24',
            ];
            foreach ($values as $id => $value) {
                $db->facets[$id] = ValueFacetTool::ipRange($value);
            }

            $found = $this->tool($db)->containing([
                'a' => self::address('192.0.2.1'),
                'b' => self::address('2001:db8::5'),
                'c' => self::address('203.0.113.9'),
            ]);

            $this->assertCount(1, $db->statements);
            foreach ($found as &$ids) {
                ksort($ids);
            }
            // The address in every spelling, its CIDRs, never ::/0 for IPv4
            $this->assertSame([
                'a' => [1 => true, 2 => false, 3 => false, 4 => false, 6 => true, 10 => true],
                'b' => [5 => true, 8 => true, 11 => false],
                'c' => [6 => true],
            ], $found);
        }
    }

    public function testTheProbeIsChunked()
    {
        $db = new ValueFacetFakeMysql();
        $db->facets = [1 => ValueFacetTool::ipRange('10.0.0.0/8')];
        $addresses = [];
        for ($i = 0; $i <= ValueFacetTool::PROBE_ADDRESSES; $i++) {
            $addresses["a$i"] = self::address('10.0.' . intdiv($i, 256) . '.' . ($i % 256));
        }

        $found = $this->tool($db)->containing($addresses);

        $this->assertCount(2, $db->statements);
        $this->assertSame(array_fill_keys(array_keys($addresses), [1 => true]), $found);
        $this->assertSame([], $this->tool($db)->containing([]));
        $this->assertCount(2, $db->statements);
    }

    public function testTheMembersOfARangeAreItsSingleAddresses()
    {
        $this->assertSame(
            "SELECT `value_id` FROM `value_ip_ranges` WHERE (`ip_start` BETWEEN X'00000000000000000000ffffc0000200' AND X'00000000000000000000ffffc00002ff') AND `ip_start` = `ip_end`",
            $this->tool(new ValueFacetFakeMysql())->membersQuery(ValueFacetTool::ipRange('192.0.2.7/24'))
        );
        $this->assertSame(
            'SELECT "value_id" FROM "value_ip_ranges" WHERE ("ip_start" BETWEEN decode(\'00000000000000000000000000000000\', \'hex\') AND decode(\'00000000000000000000fffeffffffff\', \'hex\') OR "ip_start" BETWEEN decode(\'00000000000000000001000000000000\', \'hex\') AND decode(\'ffffffffffffffffffffffffffffffff\', \'hex\')) AND "ip_start" = "ip_end"',
            $this->tool(new ValueFacetFakePostgres())->membersQuery(ValueFacetTool::ipRange('::/0'))
        );
    }
}
