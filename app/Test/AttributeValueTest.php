<?php
/**
 * AttributeValue against an in-memory dictionary behind the connectionless
 * MySQL and PostgreSQL drivers: the SQL each engine is sent, the chunking,
 * and the checks that run before and after it.
 *
 * AttributeValueDbTest runs the same model against the real database.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';

use PHPUnit\Framework\TestCase;

class AttributeValueTest extends TestCase
{
    /** @var AttributeValueFakeMysql */
    private $mysql;

    /** @var AttributeValueFakePostgres */
    private $pgsql;

    protected function setUp(): void
    {
        require_once __DIR__ . '/AttributeValueTestSupport.php';
        $this->mysql = new AttributeValueFakeMysql();
        $this->pgsql = new AttributeValueFakePostgres();
    }

    private function model($db)
    {
        return new TestAttributeValue($db);
    }

    private static function hex($value)
    {
        return bin2hex(substr(hash('sha256', $value, true), 0, 16));
    }

    public function testHashOfIsTheFirstSixteenBytesOfSha256()
    {
        $hash = $this->model($this->mysql)->hashOf('a');
        $this->assertSame(16, strlen($hash));
        $this->assertSame('ca978112ca1bbdcafac231b39a23dc4d', bin2hex($hash));
    }

    public function testInternManyInsertsOnlyWhatIsMissingOnMysql()
    {
        $existing = $this->mysql->store('a');
        $this->mysql->allow(['b', 'c']);

        $ids = $this->model($this->mysql)->internMany(['a', 'b', 'b', 'c', 'a']);

        ksort($ids);
        $this->assertSame(['a', 'b', 'c'], array_keys($ids));
        $this->assertSame($existing, $ids['a']);
        $this->assertCount(3, array_unique($ids));
        $this->assertCount(3, $this->mysql->statements);

        list($select, $insert, $reselect) = $this->mysql->statements;
        $this->assertStringStartsWith('SELECT `id`, `value`, `hash` FROM `attribute_values` WHERE `hash` IN (', $select);
        $this->assertStringNotContainsString('LOCK IN SHARE MODE', $select);

        $this->assertStringStartsWith('INSERT INTO `attribute_values` (`value`, `hash`) VALUES ', $insert);
        $this->assertStringEndsWith(' ON DUPLICATE KEY UPDATE `hash` = `hash`;', $insert);
        $this->assertStringNotContainsString(self::hex('a'), $insert);
        $this->assertStringContainsString(sprintf("('b', X'%s')", self::hex('b')), $insert);
        $this->assertStringContainsString(sprintf("('c', X'%s')", self::hex('c')), $insert);

        $this->assertStringStartsWith('SELECT `id`, `value`, `hash` FROM `attribute_values` WHERE `hash` IN (', $reselect);
        $this->assertStringNotContainsString('LOCK IN SHARE MODE', $reselect);
        $this->assertStringNotContainsString(self::hex('a'), $reselect);
    }

    /**
     * Inside a REPEATABLE READ transaction a plain read finds the
     * transaction's own rows, but not one another session committed after
     * the snapshot.
     */
    public function testInsideATransactionALateValueGetsALockingReadOfItsOwn()
    {
        $late = $this->mysql->store('late');
        $this->mysql->hidden[self::hex('late')] = true;
        $this->mysql->allow(['late', 'own']);
        $model = $this->model($this->mysql);
        $model->transaction = true;

        $ids = $model->internMany(['own', 'late']);

        $this->assertSame($late, $ids['late']);
        $this->assertCount(4, $this->mysql->statements);
        $this->assertStringNotContainsString('LOCK IN SHARE MODE', $this->mysql->statements[2]);
        $this->assertSame(
            sprintf("SELECT `id`, `value`, `hash` FROM `attribute_values` WHERE `hash` = X'%s' LOCK IN SHARE MODE", self::hex('late')),
            $this->mysql->statements[3]
        );
    }

    public function testOutsideATransactionNoReadLocks()
    {
        $this->mysql->store('late');
        $this->mysql->hidden[self::hex('late')] = true;
        $this->mysql->allow(['late']);

        try {
            $this->model($this->mysql)->internMany(['late']);
            $this->fail('A plain read outside a transaction sees every committed row.');
        } catch (RuntimeException $e) {
            $this->assertSame('1 attribute values were neither found nor inserted.', $e->getMessage());
        }
        $this->assertSame([], $this->mysql->statementsLike('/LOCK IN SHARE MODE/'));
    }

    private static function deadlock($sqlstate = '40001', $code = 1213)
    {
        $e = new PDOException("SQLSTATE[$sqlstate]: deadlock");
        $e->errorInfo = [$sqlstate, $code, 'deadlock'];
        return $e;
    }

    public function testADeadlockOutsideATransactionIsRetried()
    {
        foreach ([$this->mysql, $this->pgsql] as $db) {
            $db->allow(['a']);
            $db->insertErrors = [$db === $this->mysql ? self::deadlock() : self::deadlock('40P01', 7)];

            $ids = $this->model($db)->internMany(['a']);

            $this->assertSame(['a'], array_keys($ids));
            $this->assertCount(2, $db->statementsLike('/^INSERT/'));
        }
    }

    public function testADeadlockInsideATransactionReachesTheCaller()
    {
        $this->mysql->allow(['a']);
        $this->mysql->insertErrors = [self::deadlock()];
        $model = $this->model($this->mysql);
        $model->transaction = true;

        try {
            $model->internMany(['a']);
            $this->fail('The rolled-back transaction cannot be retried from here.');
        } catch (PDOException $e) {
            $this->assertSame('40001', $e->errorInfo[0]);
        }
        $this->assertCount(1, $this->mysql->statementsLike('/^INSERT/'));
    }

    public function testOnlyDeadlocksAreRetriedAndOnlyFiveTimes()
    {
        $this->mysql->allow(['a']);
        $this->mysql->insertErrors = [self::deadlock('HY000', 1205)];
        try {
            $this->model($this->mysql)->internMany(['a']);
            $this->fail('A lock wait timeout is not a deadlock.');
        } catch (PDOException $e) {
            $this->assertSame(1205, $e->errorInfo[1]);
        }
        $this->assertCount(1, $this->mysql->statementsLike('/^INSERT/'));

        $this->mysql->insertErrors = array_fill(0, AttributeValue::DEADLOCK_ATTEMPTS, self::deadlock());
        try {
            $this->model($this->mysql)->internMany(['a']);
            $this->fail('The last deadlock should reach the caller.');
        } catch (PDOException $e) {
            $this->assertSame(1213, $e->errorInfo[1]);
        }
        $this->assertCount(1 + AttributeValue::DEADLOCK_ATTEMPTS, $this->mysql->statementsLike('/^INSERT/'));
    }

    public function testInternManyOnPostgres()
    {
        $this->pgsql->store('a');
        $this->pgsql->allow(['b']);

        $ids = $this->model($this->pgsql)->internMany(['a', 'b']);

        ksort($ids);
        $this->assertSame(['a', 'b'], array_keys($ids));
        list($select, $insert, $reselect) = $this->pgsql->statements;
        $this->assertStringStartsWith('SELECT "id", "value", "hash" FROM "attribute_values" WHERE "hash" IN (', $select);
        $this->assertStringContainsString(sprintf("decode('%s', 'hex')", self::hex('a')), $select);
        $this->assertSame(
            sprintf(
                "INSERT INTO \"attribute_values\" (\"value\", \"hash\") VALUES ('b', decode('%s', 'hex')) ON CONFLICT (\"hash\") DO NOTHING;",
                self::hex('b')
            ),
            $insert
        );
        $this->assertStringNotContainsString('SHARE', $reselect);
    }

    public function testNothingIsInsertedWhenEveryValueExists()
    {
        $this->mysql->store('a');
        $this->mysql->store('b');

        $this->model($this->mysql)->internMany(['b', 'a']);

        $this->assertCount(1, $this->mysql->statements);
    }

    public function testRowsAreInsertedInHashOrder()
    {
        $values = ['x1', 'x2', 'x3', 'x4', 'x5', 'x6'];
        $this->mysql->allow($values);

        $this->model($this->mysql)->internMany($values);

        $insert = $this->mysql->statementsLike('/^INSERT/')[0];
        preg_match_all("/X'([0-9a-f]{32})'/", $insert, $matches);
        $sorted = $matches[1];
        sort($sorted, SORT_STRING);
        $this->assertSame($sorted, $matches[1]);
        $this->assertNotSame(array_map([self::class, 'hex'], $values), $matches[1]);
    }

    public function testSelectsAndInsertsAreChunkedByAThousand()
    {
        $values = [];
        for ($i = 0; $i < 2500; $i++) {
            $values[] = 'v' . $i;
        }
        $this->mysql->allow($values);

        $ids = $this->model($this->mysql)->internMany($values);

        $this->assertCount(2500, $ids);
        $this->assertCount(9, $this->mysql->statements);
        foreach ($this->mysql->statements as $sql) {
            $this->assertLessThanOrEqual(1000, preg_match_all("/X'/", $sql));
        }
        $this->assertCount(3, $this->mysql->statementsLike('/^INSERT/'));
        $this->assertCount(6, $this->mysql->statementsLike('/^SELECT/'));
    }

    public function testInsertsAreSplitToStayUnderTheStatementBudget()
    {
        $values = [];
        for ($i = 0; $i < 40; $i++) {
            $values[] = str_pad((string)$i, 60000, 'x');
        }
        $this->mysql->allow($values);

        $this->model($this->mysql)->internMany($values);

        $inserts = $this->mysql->statementsLike('/^INSERT/');
        $this->assertCount(2, $inserts);
        foreach ($inserts as $insert) {
            $this->assertLessThan(AttributeValue::STATEMENT_BYTES + 100000, strlen($insert));
        }
    }

    public function testAValueThatCollidesWithAStoredOneIsRefused()
    {
        $this->mysql->store('a');
        $model = $this->model($this->mysql);
        $model->collisions = ['b' => 'a'];

        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('collides with an input value');
        $model->internMany(['b']);
    }

    public function testTheCollisionIsCaughtOnTheReselectToo()
    {
        $model = $this->model($this->mysql);
        $model->collisions = ['b' => 'a'];
        $this->mysql->known[self::hex('a')] = 'a';

        try {
            $model->internMany(['b']);
            $this->fail('A collision on the re-select should have been refused.');
        } catch (RuntimeException $e) {
            $this->assertStringContainsString('collides with an input value', $e->getMessage());
        }
        $this->assertCount(2, $this->mysql->statementsLike('/^SELECT/'));
    }

    public function testTwoInputValuesSharingAHashAreRefusedBeforeAnySql()
    {
        $model = $this->model($this->pgsql);
        $model->collisions = ['b' => 'a'];

        try {
            $model->internMany(['a', 'b']);
            $this->fail('Two values sharing a hash should have been refused.');
        } catch (RuntimeException $e) {
            $this->assertStringContainsString('share a hash', $e->getMessage());
        }
        $this->assertSame([], $this->pgsql->statements);
    }

    /**
     * A row stored truncated, under the hash of the full value.
     */
    public function testARowThatDoesNotMatchItsHashIsRefused()
    {
        foreach ([$this->mysql, $this->pgsql] as $db) {
            $db->store('abc', 7, 'abcdef');
            try {
                $this->model($db)->internMany(['abcdef']);
                $this->fail('A corrupt row should have been refused.');
            } catch (RuntimeException $e) {
                $this->assertSame('Attribute value 7 does not match its stored hash.', $e->getMessage());
            }
        }
    }

    public function testAValueLostByTheInsertIsReported()
    {
        $this->mysql->allow(['a']);
        $this->mysql->dropInserts = true;

        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('1 attribute values were neither found nor inserted.');
        $this->model($this->mysql)->internMany(['a']);
    }

    public function testAnOverlongValueIsRefusedBeforeAnySql()
    {
        $model = $this->model($this->mysql);
        $longest = str_repeat('y', AttributeValue::MAX_BYTES);
        $this->mysql->allow([$longest]);
        $this->assertSame(1, $model->intern($longest));

        $this->mysql->statements = [];
        try {
            $model->internMany(['ok', $longest . 'y']);
            $this->fail('A value over the limit should have been refused.');
        } catch (InvalidArgumentException $e) {
            $this->assertSame('A value of 65536 bytes exceeds the 65535-byte limit.', $e->getMessage());
        }
        $this->assertSame([], $this->mysql->statements);
    }

    public function testNonScalarValuesAreRefused()
    {
        foreach ([null, ['a']] as $value) {
            try {
                $this->model($this->mysql)->internMany([$value]);
                $this->fail('A non-scalar value should have been refused.');
            } catch (InvalidArgumentException $e) {
                $this->assertSame('Attribute values must be scalars.', $e->getMessage());
            }
        }
    }

    /**
     * MysqlExtended::value() leaves ints unquoted, and PHP turns numeric-string
     * array keys into ints.
     */
    public function testNumbersAreInternedAsStrings()
    {
        $this->mysql->allow(['80', '']);
        $model = $this->model($this->mysql);

        $id = $model->intern(80);

        $this->assertSame($id, $model->intern('80'));
        $this->assertStringContainsString("('80', X'", $this->mysql->statementsLike('/^INSERT/')[0]);
        $this->assertSame([80 => $id], $model->internMany(['80']));
        $this->assertIsInt($model->intern(''));
    }

    public function testInternManyOfNothingSendsNothing()
    {
        $this->assertSame([], $this->model($this->mysql)->internMany([]));
        $this->assertSame([], $this->mysql->statements);
    }

    public function testResolveCiMapsEveryTermToItsVariantsOnMysql()
    {
        $this->mysql->responder = function ($sql) {
            return [['term' => '0', 'id' => '4'], ['term' => '0', 'id' => '9'], ['term' => '2', 'id' => '5']];
        };

        $result = $this->model($this->mysql)->resolveCi(['United States', 'nothing', 'x', 'nothing']);

        $this->assertSame(['United States' => [4, 9], 'nothing' => [], 'x' => [5]], $result);
        $this->assertSame(
            ["SELECT 0 AS `term`, `id` FROM `attribute_values` WHERE `value` = 'United States'"
                . " UNION ALL SELECT 1 AS `term`, `id` FROM `attribute_values` WHERE `value` = 'nothing'"
                . " UNION ALL SELECT 2 AS `term`, `id` FROM `attribute_values` WHERE `value` = 'x'"],
            $this->mysql->statements
        );
    }

    public function testResolveCiUsesTheExpressionIndexOnPostgres()
    {
        $this->model($this->pgsql)->resolveCi(["it's"]);

        $this->assertSame(
            ['SELECT 0 AS "term", "id" FROM "attribute_values" WHERE'
                . " lower(left(\"value\", 128)) = lower(left('it''s', 128)) AND lower(\"value\") = lower('it''s')"],
            $this->pgsql->statements
        );
    }

    public function testResolveCiChunksAndSkipsTermsNoValueCanEqual()
    {
        $terms = [str_repeat('z', AttributeValue::MAX_BYTES + 1)];
        for ($i = 0; $i < 1500; $i++) {
            $terms[] = 't' . $i;
        }

        $result = $this->model($this->mysql)->resolveCi($terms);

        $this->assertCount(1501, $result);
        $this->assertCount(2, $this->mysql->statements);
        $this->assertStringNotContainsString('zzz', implode('', $this->mysql->statements));
        $this->assertStringStartsWith('SELECT 1000 AS `term`', $this->mysql->statements[1]);
    }

    public function testResolveLike()
    {
        $this->mysql->responder = function ($sql) {
            return [['id' => '8'], ['id' => '3']];
        };
        $model = $this->model($this->mysql);

        $this->assertSame(['ids' => [3, 8], 'overflow' => false], $model->resolveLike('evil%', 2));
        $this->assertSame(
            "SELECT `id` FROM `attribute_values` WHERE `value` LIKE 'evil%' LIMIT 3",
            $this->mysql->statements[0]
        );
        $this->assertSame(['ids' => [], 'overflow' => true], $model->resolveLike('evil%', 1));

        $this->model($this->pgsql)->resolveLike('%evil%', 50000);
        $this->assertSame(
            "SELECT \"id\" FROM \"attribute_values\" WHERE \"value\" ILIKE '%evil%' LIMIT 50001",
            $this->pgsql->statements[0]
        );
    }

    public function testResolveLikeRefusesAZeroLimit()
    {
        $this->expectException('InvalidArgumentException');
        $this->model($this->mysql)->resolveLike('a%', 0);
    }

    public function testFetchValuesIsChunkedAndDeduplicated()
    {
        $this->mysql->responder = function ($sql) {
            preg_match('/IN \(([0-9, ]+)\)/', $sql, $m);
            $rows = [];
            foreach (explode(', ', $m[1]) as $id) {
                $rows[] = ['id' => $id, 'value' => 'v' . $id];
            }
            return $rows;
        };
        $ids = range(1, 1200);
        $ids[] = '5';
        $ids[] = 0;
        $ids[] = null;

        $values = $this->model($this->mysql)->fetchValues($ids);

        $this->assertCount(1200, $values);
        $this->assertSame('v5', $values[5]);
        $this->assertCount(2, $this->mysql->statements);
        $this->assertStringStartsWith(
            'SELECT `id`, `value` FROM `attribute_values` WHERE `id` IN (1, 2, 3,',
            $this->mysql->statements[0]
        );
        $this->assertSame([], $this->model($this->pgsql)->fetchValues([0, null]));
        $this->assertSame([], $this->pgsql->statements);
    }

    public function testAttachValuesHydratesAndDropsTheIds()
    {
        $this->mysql->responder = function ($sql) {
            return [
                ['id' => '1', 'value' => 'evil.com'],
                ['id' => '2', 'value' => 'file.exe'],
                ['id' => '3', 'value' => 'd41d8cd98f00b204e9800998ecf8427e'],
                ['id' => '4', 'value' => '  '],
            ];
        };
        $rows = [
            ['Attribute' => ['id' => 10, 'value1_id' => '1', 'value2_id' => null]],
            ['Attribute' => ['id' => 11, 'value1_id' => 2, 'value2_id' => 3], 'Event' => ['id' => 1]],
            ['Attribute' => ['id' => 12, 'value1_id' => null, 'value2_id' => null, 'value1' => 'old', 'value2' => '']],
            ['Attribute' => ['id' => 13, 'value1_id' => 2, 'value2_id' => 4]],
            ['Event' => ['id' => 2]],
        ];

        $this->model($this->mysql)->attachValues($rows, 'Attribute');

        $this->assertSame(
            ['id' => 10, 'value1' => 'evil.com', 'value2' => '', 'value' => 'evil.com'],
            $rows[0]['Attribute']
        );
        $this->assertSame(
            'file.exe|d41d8cd98f00b204e9800998ecf8427e',
            $rows[1]['Attribute']['value']
        );
        $this->assertSame(['id' => 1], $rows[1]['Event']);
        $this->assertSame(['id' => 12, 'value1' => 'old', 'value2' => ''], $rows[2]['Attribute']);
        $this->assertSame(['id' => 13, 'value1' => 'file.exe', 'value2' => '  ', 'value' => 'file.exe'], $rows[3]['Attribute']);
        $this->assertSame(['Event' => ['id' => 2]], $rows[4]);
        $this->assertCount(1, $this->mysql->statements);
        $this->assertStringEndsWith('IN (1, 2, 3, 4)', $this->mysql->statements[0]);
    }

    public function testAttachValuesRefusesADanglingId()
    {
        $rows = [['Attribute' => ['value1_id' => 99, 'value2_id' => null]]];

        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('Attribute value 99 is missing from the dictionary.');
        $this->model($this->pgsql)->attachValues($rows, 'Attribute');
    }

    public function testAttachValuesWithoutIdsSendsNothing()
    {
        $rows = [['Attribute' => ['id' => 1, 'value1' => 'a', 'value2' => '']]];

        $this->model($this->mysql)->attachValues($rows, 'Attribute');

        $this->assertSame([['Attribute' => ['id' => 1, 'value1' => 'a', 'value2' => '']]], $rows);
        $this->assertSame([], $this->mysql->statements);
    }

    public function testAssignIdsIgnoresTheIdsSentIn()
    {
        $stored = $this->mysql->store('evil.com');
        $this->mysql->allow(['8443']);
        $row = [
            'value1' => 'evil.com',
            'value2' => '8443',
            'value1_id' => 9000000001,
            'value2_id' => '9000000002',
        ];

        $this->model($this->mysql)->assignIds($row);

        $this->assertSame($stored, $row['value1_id']);
        $this->assertSame($this->mysql->rows[self::hex('8443')]['id'], $row['value2_id']);
        $this->assertNotSame($stored, $row['value2_id']);
    }

    public function testAssignIdsDropsTheIdsSentInWhenNoValueIsWritten()
    {
        $row = ['id' => 5, 'comment' => 'x', 'value1_id' => 1, 'value2_id' => 2];

        $this->model($this->mysql)->assignIds($row);

        $this->assertSame(['id' => 5, 'comment' => 'x'], $row);
        $this->assertSame([], $this->mysql->statements);
    }

    public function testAssignIdsGivesAnEmptyValue2NoRowButSpacesOne()
    {
        $this->pgsql->allow(['a.exe', '  ']);
        $empty = ['value1' => 'a.exe', 'value2' => ''];
        $spaces = ['value1' => 'a.exe', 'value2' => '  '];

        $this->model($this->pgsql)->assignIds($empty);
        $this->model($this->pgsql)->assignIds($spaces);

        $this->assertNull($empty['value2_id']);
        $this->assertSame($empty['value1_id'], $spaces['value1_id']);
        $this->assertSame($this->pgsql->rows[self::hex('  ')]['id'], $spaces['value2_id']);
        $this->assertArrayNotHasKey(self::hex(''), $this->pgsql->rows);
    }

    public function testAssignIdsGivesAnEmptyValue1ItsRow()
    {
        $this->mysql->allow(['']);
        $row = ['value1' => null, 'value2' => ''];

        $this->model($this->mysql)->assignIds($row);

        $this->assertSame($this->mysql->rows[self::hex('')]['id'], $row['value1_id']);
        $this->assertNull($row['value2_id']);
    }

    public function testAssignIdsInternsEqualPartsOnce()
    {
        $this->mysql->allow(['53']);
        $row = ['value1' => '53', 'value2' => 53];

        $this->model($this->mysql)->assignIds($row);

        $this->assertSame($row['value1_id'], $row['value2_id']);
        $this->assertCount(1, $this->mysql->statementsLike('/^INSERT/'));
    }

    public function testAssignIdsOnlyCoversTheColumnsTheFieldListWrites()
    {
        $this->mysql->allow(['evil.com']);
        $touch = ['value1' => 'evil.com', 'value2' => '', 'value1_id' => 1, 'value2_id' => 2];
        $first = ['value1' => 'evil.com', 'value2' => 'x', 'value2_id' => 2];

        $this->model($this->mysql)->assignIds($touch, ['timestamp']);
        $this->assertSame(['value1' => 'evil.com', 'value2' => ''], $touch);
        $this->assertSame([], $this->mysql->statements);

        $this->model($this->mysql)->assignIds($first, ['value1', 'comment']);
        $this->assertSame(['value1', 'value2', 'value1_id'], array_keys($first));
        $this->assertSame($this->mysql->rows[self::hex('evil.com')]['id'], $first['value1_id']);
    }

    public function testAssignIdsRefusesAValueTheDictionaryCannotHold()
    {
        $row = ['value1' => str_repeat('A', AttributeValue::MAX_BYTES + 1), 'value2' => ''];

        $this->expectException('InvalidArgumentException');
        $this->model($this->mysql)->assignIds($row);
    }
}
