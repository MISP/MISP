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

    public function testValuesFoundMissingGetTheirIpFacetRows()
    {
        foreach ([$this->mysql, $this->pgsql] as $db) {
            $db->store('192.0.2.1');
            $db->allow(['2001:db8::/32', 'example.org', '10.1.2.3']);

            $ids = $this->model($db)->internMany(['10.1.2.3', 'example.org', '192.0.2.1', '2001:db8::/32']);

            $facets = $db->statementsLike('/value_ip_ranges/');
            $this->assertCount(1, $facets);
            $literal = $db === $this->mysql ? "X'%s'" : "decode('%s', 'hex')";
            $rows = [
                $ids['10.1.2.3'] => ['00000000000000000000ffff0a010203', '00000000000000000000ffff0a010203', 128],
                $ids['2001:db8::/32'] => ['20010db8000000000000000000000000', '20010db8ffffffffffffffffffffffff', 32],
            ];
            ksort($rows);
            $expected = [];
            foreach ($rows as $id => $row) {
                $expected[] = sprintf("(%d, $literal, $literal, %d)", $id, $row[0], $row[1], $row[2]);
            }
            $this->assertStringContainsString('VALUES ' . implode(', ', $expected) . ' ON', $facets[0]);
            $this->assertStringEndsWith(
                $db === $this->mysql ? 'ON DUPLICATE KEY UPDATE `value_id` = `value_id`;' : 'ON CONFLICT ("value_id") DO NOTHING;',
                $facets[0]
            );
        }
    }

    public function testValuesAlreadyStoredGetNoFacetStatement()
    {
        $this->mysql->store('10.0.0.1');
        $this->model($this->mysql)->internMany(['10.0.0.1']);
        $this->assertSame([], $this->mysql->statementsLike('/value_ip_ranges/'));

        $this->mysql->allow(['example.org']);
        $this->model($this->mysql)->internMany(['example.org']);
        $this->assertSame([], $this->mysql->statementsLike('/value_ip_ranges/'));
    }

    public function testAFacetDeadlockIsRetriedAfterTheValueWasCommitted()
    {
        $this->mysql->allow(['10.0.0.1']);
        $this->mysql->insertErrors = [null, self::deadlock()];

        $ids = $this->model($this->mysql)->internMany(['10.0.0.1']);

        $this->assertSame(['10.0.0.1'], array_keys($ids));
        $this->assertCount(1, $this->mysql->statementsLike('/^INSERT INTO `attribute_values`/'));
        $this->assertCount(2, $this->mysql->statementsLike('/^INSERT INTO `value_ip_ranges`/'));
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

    public function testLikeConditionReadsTheDictionaryInsideTheStatement()
    {
        $in = $this->model($this->mysql)->likeCondition('Attribute.value1_id', "%it's%");
        $notIn = $this->model($this->pgsql)->likeCondition('ShadowAttribute.value2_id', '%x%', true);

        $this->assertSame('expression', $in->type);
        $this->assertSame(
            "`Attribute`.`value1_id` IN (SELECT `id` FROM `attribute_values` WHERE `value` LIKE '%it''s%')",
            $in->value
        );
        $this->assertSame(
            "\"ShadowAttribute\".\"value2_id\" NOT IN (SELECT \"id\" FROM \"attribute_values\" WHERE \"value\" ILIKE '%x%')",
            $notIn->value
        );
        $this->assertSame([], $this->mysql->statements);
    }

    public function testResolveSearchNarrowsByWordsAndChecksTheWordStartOnMysql()
    {
        $this->mysql->responder = function ($sql) {
            return [['id' => '8'], ['id' => '3']];
        };
        $model = $this->model($this->mysql);

        $this->assertSame(['ids' => [3, 8], 'overflow' => false], $model->resolveSearch('google.com', 2));
        $this->assertSame(
            "SELECT `id` FROM `attribute_values` WHERE MATCH(`value`) AGAINST('+google +com*' IN BOOLEAN MODE)" .
            " AND `value` LIKE '%google.com%' AND `value` REGEXP '(^|[^\p{L}\p{N}_])google\.com' LIMIT 3",
            $this->mysql->statements[0]
        );
        $this->assertSame(['ids' => [], 'overflow' => true], $model->resolveSearch('google.com', 1));
    }

    public function testATextStartingWithPunctuationNeedsNoWordBoundaryBeforeIt()
    {
        $this->model($this->mysql)->resolveSearch('.com/', 50000);

        $this->assertSame(
            "SELECT `id` FROM `attribute_values` WHERE MATCH(`value`) AGAINST('+com' IN BOOLEAN MODE)" .
            " AND `value` LIKE '%.com/%' AND `value` REGEXP '\.com/' LIMIT 50001",
            $this->mysql->statements[0]
        );
    }

    public function testOnlyTheLongestWordsTheIndexHoldsAreSearched()
    {
        $model = $this->model($this->mysql);
        $hash = str_repeat('ab', 64);

        $model->resolveSearch('http://www.ab.example-site.com/wp/x_y.php?q=1', 10);
        $model->resolveSearch($hash . ' evil', 10);
        $model->resolveSearch('évil', 10);
        $model->ftTokenSizes = [1, 84];
        $model->resolveSearch('1.2.3.4', 10);

        $this->assertStringContainsString("AGAINST('+example +http +site +www' IN BOOLEAN MODE)", $this->mysql->statements[0]);
        $this->assertStringContainsString("AGAINST('+evil*' IN BOOLEAN MODE)", $this->mysql->statements[1]);
        $this->assertStringContainsString("AGAINST('+évil*' IN BOOLEAN MODE)", $this->mysql->statements[2]);
        $this->assertStringContainsString("AGAINST('+1 +2 +3 +4*' IN BOOLEAN MODE)", $this->mysql->statements[3]);
        // Only the URL holds stopwords (www, com)
        $this->assertSame(1, $model->stopwordChecks);
    }

    public function testWithoutAnIndexableWordTheDictionaryIsScanned()
    {
        $this->model($this->mysql)->resolveSearch('.ru', 10);

        $this->assertSame(
            "SELECT `id` FROM `attribute_values` WHERE `value` LIKE '%.ru%' AND `value` REGEXP '\.ru' LIMIT 11",
            $this->mysql->statements[0]
        );
    }

    public function testAStopwordTheIndexMayLackIsLeftToTheCheck()
    {
        $model = $this->model($this->mysql);
        $model->indexHoldsStopwords = false;

        $model->resolveSearch('google.com', 10);
        $model->resolveSearch('.com', 10);

        $this->assertStringContainsString("AGAINST('+google' IN BOOLEAN MODE) AND `value` LIKE '%google.com%'", $this->mysql->statements[0]);
        $this->assertStringStartsWith("SELECT `id` FROM `attribute_values` WHERE `value` LIKE '%.com%'", $this->mysql->statements[1]);
        $this->assertSame(2, $model->stopwordChecks);

        $model->indexHoldsStopwords = true;
        $model->resolveSearch('.com', 10);
        $this->assertStringContainsString("AGAINST('+com*' IN BOOLEAN MODE)", $this->mysql->statements[2]);
    }

    public function testTheSearchTextIsLiteral()
    {
        $this->model($this->mysql)->resolveSearch("50%_off\\x's", 10);
        $this->model($this->pgsql)->resolveSearch("50%_off\\x's", 10);

        $this->assertSame(
            "SELECT `id` FROM `attribute_values` WHERE MATCH(`value`) AGAINST('+_off' IN BOOLEAN MODE)" .
            " AND `value` LIKE '%50\%\_off\\\\x''s%' AND `value` REGEXP '(^|[^\p{L}\p{N}_])50%_off\\\\x''s' LIMIT 11",
            $this->mysql->statements[0]
        );
        $this->assertSame(
            "SELECT \"id\" FROM \"attribute_values\" WHERE \"value\" ILIKE '%50\%\_off\\\\x''s%' LIMIT 11",
            $this->pgsql->statements[0]
        );
    }

    public function testSearchConditionReadsAheadOrInsideTheStatement()
    {
        $this->mysql->responder = function ($sql) {
            if (strpos($sql, 'evil') !== false) {
                return [['id' => '9'], ['id' => '4']];
            }
            return array_fill(0, 3, ['id' => '1']);
        };
        $model = $this->model($this->mysql);

        $condition = $model->searchCondition(['evil', 'broad'], 'Attribute', false, false, 2);

        $this->assertCount(2, $this->mysql->statements);
        $this->assertSame(['Attribute.value1_id IN' => [4, 9]], $condition['OR'][0]);
        // Inside the statement without the index, as a bounded find
        $this->assertSame(
            "`Attribute`.`value1_id` IN (SELECT `id` FROM `attribute_values` WHERE `value` LIKE '%broad%'" .
            " AND `value` REGEXP '(^|[^\p{L}\p{N}_])broad')",
            $condition['OR'][1]->value
        );
        $this->assertSame(['Attribute.value2_id IN' => [4, 9]], $condition['OR'][2]);
        $this->assertStringStartsWith('`Attribute`.`value2_id` IN (SELECT', $condition['OR'][3]->value);

        $not = $model->searchCondition(['evil'], 'ShadowAttribute', true, false, 2);
        $this->assertSame(['AND' => [
            ['ShadowAttribute.value1_id NOT IN' => [4, 9]],
            ['OR' => [['ShadowAttribute.value2_id' => null], ['AND' => [['ShadowAttribute.value2_id NOT IN' => [4, 9]]]]]],
        ]], $not);
    }

    public function testABoundedSearchChecksEachRowWithoutTheIndex()
    {
        $condition = $this->model($this->mysql)->searchCondition(['google.com'], 'Attribute', false, true);
        $pgsql = $this->model($this->pgsql)->searchCondition(['google.com'], 'Attribute', true, true);

        $this->assertSame([], $this->mysql->statements);
        $this->assertSame(
            "`Attribute`.`value1_id` IN (SELECT `id` FROM `attribute_values` WHERE `value` LIKE '%google.com%'" .
            " AND `value` REGEXP '(^|[^\p{L}\p{N}_])google\.com')",
            $condition['OR'][0]->value
        );
        $this->assertSame(
            "\"Attribute\".\"value1_id\" NOT IN (SELECT \"id\" FROM \"attribute_values\" WHERE \"value\" ILIKE '%google.com%')",
            $pgsql['AND'][0]->value
        );
    }

    public function testASearchNothingMatchesIsFalseAndItsNegationTrue()
    {
        $model = $this->model($this->mysql);

        $this->assertSame([ValueConditionRewriter::SQL_FALSE], $model->searchCondition(['absent'], 'Attribute'));
        $this->assertSame([ValueConditionRewriter::SQL_TRUE], $model->searchCondition(['absent'], 'Attribute', true));
        $this->assertCount(2, $this->mysql->statements);

        $this->assertSame(
            [ValueConditionRewriter::SQL_FALSE],
            $model->searchCondition([str_repeat('a', AttributeValue::MAX_BYTES + 1)], 'Attribute')
        );
        $this->assertCount(2, $this->mysql->statements);
    }

    public function testMatchesEmptyDecidesLettersDigitsAndWildcardsWithoutTheDatabase()
    {
        foreach ([$this->mysql, $this->pgsql] as $db) {
            $model = $this->model($db);
            $this->assertSame(['' => true, 'a ' => false, '0' => false], $model->matchesEmpty(['', 'a ', '0']));
            $this->assertSame(
                ['' => true, '%%' => true, 'a%' => false, '_' => false, '%\\_' => false],
                $model->matchesEmpty(['', '%%', 'a%', '_', '%\\_'], true)
            );
            $this->assertSame([], $db->statements);
        }
    }

    public function testMatchesEmptyAsksTheMysqlCollationForTheRest()
    {
        $this->mysql->responder = function ($sql) {
            return [['term' => '0']];
        };
        $model = $this->model($this->mysql);

        $this->assertSame(['  ' => true, 'x' => false, '-' => false], $model->matchesEmpty(['  ', 'x', '-']));
        $this->assertSame(
            ["SELECT 0 AS `term` FROM DUAL WHERE _utf8mb4'' COLLATE utf8mb4_uca1400_ai_ci = '  '"
                . " UNION ALL SELECT 1 AS `term` FROM DUAL WHERE _utf8mb4'' COLLATE utf8mb4_uca1400_ai_ci = '-'"],
            $this->mysql->statements
        );

        $this->mysql->statements = [];
        $model->matchesEmpty(['\\%'], true);
        $this->assertSame(
            ["SELECT 0 AS `term` FROM DUAL WHERE _utf8mb4'' COLLATE utf8mb4_uca1400_ai_ci LIKE '\\%'"],
            $this->mysql->statements
        );
    }

    public function testMatchesEmptyOnPostgresComparesLowerCaseSoOnlyTheEmptyTermMatches()
    {
        $this->assertSame(['  ' => false, '-' => false], $this->model($this->pgsql)->matchesEmpty(['  ', '-']));
        $this->assertSame(['\\%' => false], $this->model($this->pgsql)->matchesEmpty(['\\%'], true));
        $this->assertSame([], $this->pgsql->statements);
    }

    public function testMatchesEmptyRefusesAnUnexpectedCollationName()
    {
        $model = $this->model($this->mysql);
        $model->collation = 'x; DROP TABLE y';

        $this->expectException('RuntimeException');
        $model->matchesEmpty([' ']);
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

    private function answerIds(array $values)
    {
        return function ($sql) use ($values) {
            preg_match('/IN \(([0-9, ]+)\)/', $sql, $m);
            $rows = [];
            foreach (explode(', ', $m[1]) as $id) {
                if (isset($values[$id])) {
                    $rows[] = ['id' => $id, 'value' => $values[$id]];
                }
            }
            return $rows;
        };
    }

    public function testAttachFoundHydratesPrimaryRowsInOneStatement()
    {
        $this->mysql->responder = $this->answerIds([1 => 'evil.com', 2 => '8080']);
        $model = $this->model($this->mysql);
        $model->findInProgress = true;
        $results = [
            ['Proposal' => ['id' => 1, 'value1_id' => 1, 'value2_id' => null]],
            ['Proposal' => ['id' => 2, 'value1_id' => 1, 'value2_id' => 2], 'Attribute' => ['value1_id' => 1]],
        ];

        $model->attachFound($results, 'Proposal', true);

        $this->assertSame(['id' => 1, 'value1' => 'evil.com', 'value2' => '', 'value' => 'evil.com'], $results[0]['Proposal']);
        $this->assertSame('evil.com|8080', $results[1]['Proposal']['value']);
        // Another model's rows are its own afterFind's
        $this->assertSame(['value1_id' => 1], $results[1]['Attribute']);
        $this->assertCount(1, $this->mysql->statements);
        $this->assertSame(0, $model->deferredCalls);
    }

    public function testAttachFoundLeavesAssociationRowsToTheFindInProgress()
    {
        $model = $this->model($this->mysql);
        $model->findInProgress = true;
        $results = [['Attribute' => ['id' => 1, 'value1_id' => 1, 'value2_id' => null]]];

        $model->attachFound($results, 'Attribute', false);

        $this->assertSame([['Attribute' => ['id' => 1, 'value1_id' => 1, 'value2_id' => null]]], $results);
        $this->assertSame([], $this->mysql->statements);
        $this->assertSame(1, $model->deferredCalls);
    }

    public function testAttachFoundHydratesAnAssociationRowWhenNoFindIsInProgress()
    {
        $this->mysql->responder = $this->answerIds([3 => 'a.example']);
        $model = $this->model($this->mysql);
        $results = [['ReferencedAttribute' => ['id' => 1, 'value1_id' => 3, 'value2_id' => null]]];

        $model->attachFound($results, 'ReferencedAttribute', false);

        $this->assertSame('a.example', $results[0]['ReferencedAttribute']['value']);
        $this->assertArrayNotHasKey('value1_id', $results[0]['ReferencedAttribute']);
        $this->assertCount(1, $this->mysql->statements);
    }

    public function testAttachFoundDefersNothingForRowsWithoutIds()
    {
        $model = $this->model($this->mysql);
        $model->findInProgress = true;
        $results = [['Attribute' => ['id' => 1, 'value' => 'a']]];

        $model->attachFound($results, 'Attribute', false);

        $this->assertSame([['Attribute' => ['id' => 1, 'value' => 'a']]], $results);
        $this->assertSame(0, $model->deferredCalls);
    }

    public function testAttachFoundLeavesTheIdsToAFindThatWantsNoText()
    {
        $model = $this->model($this->mysql);
        $model->findInProgress = true;
        $model->textWanted = false;
        $rows = [['Attribute' => ['id' => 1, 'value1_id' => 1, 'value2_id' => 2]]];

        $results = $rows;
        $model->attachFound($results, 'Attribute', true);
        $this->assertSame($rows, $results);
        $model->attachFound($results, 'Attribute', false);
        $this->assertSame($rows, $results);

        $this->assertSame([], $this->mysql->statements);
        $this->assertSame(0, $model->deferredCalls);
    }

    public function testAttachNestedHydratesEveryShapeInOneStatement()
    {
        $this->mysql->responder = $this->answerIds([
            1 => 'evil.com', 2 => 'file.exe', 3 => 'd41d8cd98f00b204e9800998ecf8427e', 4 => '10.0.0.1',
        ]);
        $data = [
            'Event' => ['id' => 7, 'info' => 'value1_id'],
            'Attribute' => [
                ['id' => 1, 'value1_id' => 1, 'value2_id' => null, 'ShadowAttribute' => [
                    ['id' => 9, 'value1_id' => 4, 'value2_id' => null],
                ]],
                ['id' => 2, 'value1_id' => null, 'value2_id' => null, 'value1' => 'old', 'value2' => ''],
            ],
            'Object' => [
                ['id' => 3, 'Attribute' => [['id' => 4, 'value1_id' => 2, 'value2_id' => 3]]],
            ],
            'ReferencedAttribute' => ['id' => 5, 'value1_id' => 1, 'value2_id' => null],
        ];

        $this->model($this->mysql)->attachNested($data);

        $this->assertSame('evil.com', $data['Attribute'][0]['value']);
        $this->assertSame('10.0.0.1', $data['Attribute'][0]['ShadowAttribute'][0]['value1']);
        $this->assertSame(['id' => 2, 'value1' => 'old', 'value2' => ''], $data['Attribute'][1]);
        $this->assertSame(
            ['id' => 4, 'value1' => 'file.exe', 'value2' => 'd41d8cd98f00b204e9800998ecf8427e',
                'value' => 'file.exe|d41d8cd98f00b204e9800998ecf8427e'],
            $data['Object'][0]['Attribute'][0]
        );
        $this->assertSame('evil.com', $data['ReferencedAttribute']['value']);
        $this->assertSame(['id' => 7, 'info' => 'value1_id'], $data['Event']);
        $this->assertStringNotContainsString('_id":', json_encode($data));
        $this->assertCount(1, $this->mysql->statements);
        $this->assertStringEndsWith('IN (1, 4, 2, 3)', $this->mysql->statements[0]);
    }

    public function testWithoutTheTextColumnsTheTextTakesThePlaceOfTheIds()
    {
        $this->mysql->responder = $this->answerIds([1 => 'evil.com', 2 => '8080']);
        $rows = [['Attribute' => [
            'id' => 1, 'type' => 'domain|port', 'value1_id' => 1, 'value2_id' => 2, 'to_ids' => 0, 'value' => 'old',
        ]]];

        $this->model($this->mysql)->attachValues($rows, 'Attribute');

        $this->assertSame(
            ['id' => 1, 'type' => 'domain|port', 'value1' => 'evil.com', 'value2' => '8080', 'to_ids' => 0,
                'value' => 'evil.com|8080'],
            $rows[0]['Attribute']
        );
    }

    public function testOnlyTheValueKeysAskedForAreAdded()
    {
        $this->mysql->responder = $this->answerIds([1 => 'evil.com', 2 => '8080']);
        $rows = [
            ['Attribute' => ['id' => 1, 'type' => 'domain|port', 'value1_id' => 1, 'value2_id' => 2, 'to_ids' => 0]],
            ['Attribute' => ['id' => 2, 'value1_id' => 1, 'value2_id' => null]],
        ];

        $this->model($this->mysql)->attachValues($rows, 'Attribute', ['value']);

        $this->assertSame(['id' => 1, 'type' => 'domain|port', 'to_ids' => 0, 'value' => 'evil.com|8080'], $rows[0]['Attribute']);
        $this->assertSame(['id' => 2, 'value' => 'evil.com'], $rows[1]['Attribute']);

        $rows = [['Attribute' => ['value1_id' => 1, 'id' => 1, 'value2_id' => 2]]];
        $this->model($this->mysql)->attachValues($rows, 'Attribute', ['value2', 'value']);
        $this->assertSame(['id' => 1, 'value2' => '8080', 'value' => 'evil.com|8080'], $rows[0]['Attribute']);
    }

    public function testAValueKeyTheRowHoldsIsFilledEvenIfNotAskedFor()
    {
        $this->mysql->responder = $this->answerIds([1 => 'evil.com', 2 => '8080']);
        $rows = [['Attribute' => [
            'id' => 1, 'value1' => 'stale', 'value2' => 'stale', 'value1_id' => 1, 'value2_id' => 2, 'value' => 'stale',
        ]]];

        $this->model($this->mysql)->attachValues($rows, 'Attribute', ['value']);

        $this->assertSame(
            ['id' => 1, 'value1' => 'evil.com', 'value2' => '8080', 'value' => 'evil.com|8080'],
            $rows[0]['Attribute']
        );
    }

    public function testAnAddedKeyGoesBeforeTheAssociationsTheRowHolds()
    {
        $this->mysql->responder = $this->answerIds([1 => 'evil.com']);
        $data = ['ShadowAttribute' => [
            ['id' => 2, 'value1_id' => 1, 'value2_id' => null, 'last_seen' => null, 'Org' => ['id' => 1], 'Tag' => []],
        ]];

        $this->model($this->mysql)->attachNested($data, ['value']);

        $this->assertSame(
            ['id', 'last_seen', 'value', 'Org', 'Tag'],
            array_keys($data['ShadowAttribute'][0])
        );
    }

    public function testPrimaryRowsGetTheKeysOfTheFindInProgress()
    {
        $this->mysql->responder = $this->answerIds([1 => 'evil.com']);
        $model = $this->model($this->mysql);
        $model->valueKeys = ['value'];
        $results = [['Attribute' => ['id' => 1, 'value1_id' => 1, 'value2_id' => null]]];

        $model->attachFound($results, 'Attribute', true);

        $this->assertSame([['Attribute' => ['id' => 1, 'value' => 'evil.com']]], $results);
    }

    public function testAttachNestedAddsOnlyTheKeysAskedFor()
    {
        $this->mysql->responder = $this->answerIds([1 => 'evil.com', 2 => 'a.example']);
        $data = [
            'Attribute' => [['id' => 1, 'value1_id' => 1, 'value2_id' => null]],
            'ShadowAttribute' => [['id' => 2, 'value1_id' => 2, 'value2_id' => null, 'old_id' => 1]],
        ];

        $this->model($this->mysql)->attachNested($data, ['value']);

        $this->assertSame(
            ['Attribute' => [['id' => 1, 'value' => 'evil.com']], 'ShadowAttribute' => [['id' => 2, 'old_id' => 1, 'value' => 'a.example']]],
            $data
        );
        $this->assertCount(1, $this->mysql->statements);
    }

    public function testPrepareFindTranslatesFindsWhoseAfterFindRuns()
    {
        $model = $this->model($this->mysql);

        $query = $model->prepareFind(['fields' => ['Attribute.value'], 'order' => ['Attribute.id'], 'callbacks' => true], 'Attribute');

        $this->assertSame(['Attribute.value1_id', 'Attribute.value2_id'], $query['fields']);
        $this->assertSame([['value']], $model->askedKeys);

        $model->prepareFind(['fields' => ['Attribute.id'], 'order' => ['Attribute.value'], 'joins' => [], 'callbacks' => true], 'Attribute');
        $this->assertSame([['value']], $model->askedKeys);

        foreach (['before', false] as $callbacks) {
            $query = ['fields' => ['Attribute.value'], 'order' => ['Attribute.value'], 'callbacks' => $callbacks];
            $this->assertSame($query, $model->prepareFind($query, 'Attribute'));
        }
        $this->assertSame([['value']], $model->askedKeys);
    }

    public function testRewriteConditionsMovesTheValueColumnsToTheIds()
    {
        $this->mysql->responder = function ($sql) {
            return [['term' => '0', 'id' => '7'], ['term' => '0', 'id' => '3']];
        };

        $conditions = $this->model($this->mysql)->rewriteConditions(
            ['Attribute.event_id' => 5, 'OR' => ['Attribute.value1' => 'Evil.com', 'Attribute.comment' => 'x']],
            'Attribute'
        );

        $this->assertSame(
            ['Attribute.event_id' => 5, 'OR' => [['Attribute.value1_id IN' => [3, 7]], 'Attribute.comment' => 'x']],
            $conditions
        );
        $this->assertSame(["SELECT 0 AS `term`, `id` FROM `attribute_values` WHERE `value` = 'Evil.com'"], $this->mysql->statements);
    }

    public function testRewriteConditionsDeclaredBoundedReadsAnUnanchoredPatternInTheStatement()
    {
        $conditions = $this->model($this->mysql)->rewriteConditions(
            ['ShadowAttribute.value1 LIKE' => '%evil%'],
            'ShadowAttribute',
            true
        );

        $this->assertSame('expression', $conditions[0][0]->type);
        $this->assertSame(
            "`ShadowAttribute`.`value1_id` IN (SELECT `id` FROM `attribute_values` WHERE `value` LIKE '%evil%')",
            $conditions[0][0]->value
        );
        $this->assertSame([], $this->mysql->statements);
    }

    public function testRewriteConditionsThrowsWithStrictConditions()
    {
        AttributeValue::$strictConditions = true;
        try {
            $this->model($this->mysql)->rewriteConditions(['LOWER(Attribute.value1) LIKE' => 'x'], 'Attribute');
            $this->fail('A function-wrapped value column was passed through.');
        } catch (ValueConditionException $e) {
            $this->assertStringContainsString('LOWER(Attribute.value1) LIKE', $e->getMessage());
        } finally {
            AttributeValue::$strictConditions = null;
        }
        $this->assertSame([], $this->mysql->statements);
    }

    public function testStrictConditionsFollowTheDebugLevelUnlessSet()
    {
        $this->assertNull((new ReflectionClass('AttributeValue'))->getDefaultProperties()['strictConditions']);
        $strict = new ReflectionProperty('ValueConditionRewriter', 'strict');
        $strict->setAccessible(true);
        $debug = Configure::read('debug');
        try {
            foreach ([[null, 0, false], [null, 1, true], [null, 2, true], [true, 0, true], [false, 1, false]] as list($setting, $level, $expected)) {
                AttributeValue::$strictConditions = $setting;
                Configure::write('debug', $level);
                $rewriter = $this->model($this->mysql)->batchRewriter('Attribute', []);
                $this->assertSame($expected, $strict->getValue($rewriter), json_encode([$setting, $level]));
            }
            AttributeValue::$strictConditions = null;
            Configure::write('debug', 1);
            $this->expectException('ValueConditionException');
            $this->model($this->mysql)->rewriteConditions(['IS_IPV6(value1)'], 'Attribute');
        } finally {
            AttributeValue::$strictConditions = null;
            Configure::write('debug', $debug);
        }
    }

    public function testABatchRewriterResolvesItsTermsInOneStatement()
    {
        $this->mysql->responder = function ($sql) {
            return [['term' => '0', 'id' => '7'], ['term' => '0', 'id' => '3'], ['term' => '1', 'id' => '5']];
        };

        $rewriter = $this->model($this->mysql)->batchRewriter('Attribute', ['Evil.com', 'b.example', 'Evil.com']);

        $this->assertSame(
            ["SELECT 0 AS `term`, `id` FROM `attribute_values` WHERE `value` = 'Evil.com'"
                . " UNION ALL SELECT 1 AS `term`, `id` FROM `attribute_values` WHERE `value` = 'b.example'"],
            $this->mysql->statements
        );
        $this->assertSame([['Attribute.value1_id IN' => [3, 7]]], $rewriter->rewrite(['Attribute.value1' => 'Evil.com']));
        $this->assertSame(
            ['OR' => [['Attribute.value1_id IN' => [3, 5, 7]], ['Attribute.value2_id IN' => [3, 5, 7]]]],
            $rewriter->rewrite(['OR' => ['Attribute.value1' => ['b.example', 'Evil.com'], 'Attribute.value2' => ['b.example', 'Evil.com']]])
        );
        $this->assertCount(1, $this->mysql->statements);
    }

    public function testAttachNestedRefusesADanglingId()
    {
        $data = [['Object' => ['Attribute' => [['value1_id' => 99, 'value2_id' => null]]]]];

        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('Attribute value 99 is missing from the dictionary.');
        $this->model($this->pgsql)->attachNested($data);
    }

    public function testAttachNestedOfAnythingElseSendsNothing()
    {
        $count = 3;
        $model = $this->model($this->mysql);

        $model->attachNested($count);
        $rows = [['Attribute' => ['id' => 1, 'value1_id' => null]]];
        $model->attachNested($rows);

        $this->assertSame(3, $count);
        $this->assertSame([['Attribute' => ['id' => 1]]], $rows);
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

    public function testPrimedValuesCostTheirSavesNoQuery()
    {
        $this->mysql->allow(['evil.com', '8443']);
        $model = $this->model($this->mysql);

        $previous = $model->prime(['evil.com', '8443', 'evil.com']);
        $primed = count($this->mysql->statements);
        $row = ['value1' => 'evil.com', 'value2' => '8443'];
        $model->assignIds($row);

        $this->assertSame([], $previous);
        $this->assertCount(1, $this->mysql->statementsLike('/^INSERT/'));
        $this->assertCount($primed, $this->mysql->statements);
        $this->assertSame($this->mysql->rows[self::hex('evil.com')]['id'], $row['value1_id']);
        $this->assertSame($this->mysql->rows[self::hex('8443')]['id'], $row['value2_id']);
    }

    public function testPrimingAgainQueriesOnlyTheNewValues()
    {
        $this->mysql->allow(['a', 'b']);
        $model = $this->model($this->mysql);
        $model->prime(['a']);
        $before = count($this->mysql->statements);

        $model->prime(['a']);
        $this->assertCount($before, $this->mysql->statements);

        $model->prime(['a', 'b']);
        $sent = implode("\n", array_slice($this->mysql->statements, $before));
        $this->assertStringNotContainsString(self::hex('a'), $sent);
        $this->assertStringContainsString(self::hex('b'), $sent);
    }

    public function testReleaseRestoresTheEnclosingMap()
    {
        $this->mysql->allow(['outer', 'inner']);
        $model = $this->model($this->mysql);
        $outer = $model->prime(['outer']);
        $inner = $model->prime(['inner']);
        $model->release($inner);
        $before = count($this->mysql->statements);

        $kept = ['value1' => 'outer'];
        $model->assignIds($kept);
        $this->assertCount($before, $this->mysql->statements);

        $released = ['value1' => 'inner'];
        $model->assignIds($released);
        $this->assertCount($before + 1, $this->mysql->statements);

        $model->release($outer);
        $again = ['value1' => 'outer'];
        $model->assignIds($again);
        $this->assertCount($before + 2, $this->mysql->statements);
    }

    public function testPrimingInsideATransactionOnlyLooksUp()
    {
        $stored = $this->mysql->store('known.example');
        $this->mysql->allow(['new.example']);
        $model = $this->model($this->mysql);
        $model->transaction = true;

        $model->prime(['known.example', 'new.example']);
        $this->assertSame([], $this->mysql->statementsLike('/^INSERT/'));

        $before = count($this->mysql->statements);
        $row = ['value1' => 'known.example', 'value2' => 'new.example'];
        $model->assignIds($row);
        $this->assertSame($stored, $row['value1_id']);
        $this->assertSame($this->mysql->rows[self::hex('new.example')]['id'], $row['value2_id']);
        $sent = implode("\n", array_slice($this->mysql->statements, $before));
        $this->assertStringNotContainsString(self::hex('known.example'), $sent);
        $this->assertCount(1, $this->mysql->statementsLike('/^INSERT/'));
    }

    public function testPrimeLeavesAValueTheDictionaryCannotHoldToTheSave()
    {
        $long = str_repeat('A', AttributeValue::MAX_BYTES + 1);
        $model = $this->model($this->mysql);

        $model->prime([$long]);
        $this->assertSame([], $this->mysql->statements);

        $row = ['value1' => $long, 'value2' => ''];
        $this->expectException('InvalidArgumentException');
        $model->assignIds($row);
    }

    public function testIdsOfLooksUpWithoutInserting()
    {
        $stored = $this->mysql->store('known.example');
        $model = $this->model($this->mysql);

        $ids = $model->idsOf(['known.example', 'unknown.example', 'known.example']);

        $this->assertSame(['known.example' => $stored], $ids);
        $this->assertCount(1, $this->mysql->statements);
        $this->assertSame([], $this->mysql->statementsLike('/^INSERT/'));
    }

    public function testIdsOfReadsThePrimedMapAndSkipsValuesTooLongToStore()
    {
        $this->mysql->allow(['primed.example']);
        $model = $this->model($this->mysql);
        $model->prime(['primed.example']);
        $before = count($this->mysql->statements);

        $ids = $model->idsOf(['primed.example', str_repeat('A', AttributeValue::MAX_BYTES + 1)]);

        $this->assertSame(['primed.example' => $this->mysql->rows[self::hex('primed.example')]['id']], $ids);
        $this->assertCount($before, $this->mysql->statements);
    }

    public function testWithIdFieldsAddsTheIdOfEachValueColumnOnTheList()
    {
        $model = $this->model($this->mysql);

        $this->assertSame([], $model->withIdFields([]));
        $this->assertSame(['timestamp'], $model->withIdFields(['timestamp']));
        $this->assertSame(['comment', 'value1_id'], $model->withIdFields(['comment', 'value1_id']));
        $this->assertSame(
            ['value', 'value1', 'value2', 'value1_id', 'value2_id'],
            $model->withIdFields(['value', 'value1', 'value2'])
        );
        $this->assertSame(['value2', 'value2_id'], $model->withIdFields(['value2', 'value2_id']));
        $this->assertSame([], $this->mysql->statements);
    }

    public function testWithValueColumnsNamesTheTextOfEachIdTheSchemaHolds()
    {
        $text = ['type' => 'text', 'null' => false];
        $id = ['type' => 'biginteger', 'null' => true];
        $stored = ['type' => 'text', 'null' => false, 'collate' => 'utf8mb3_unicode_ci'];

        $this->assertSame(
            ['value1_id' => $id, 'value2_id' => $id, 'value1' => $text, 'value2' => $text],
            AttributeValue::withValueColumns(['value1_id' => $id, 'value2_id' => $id])
        );
        $this->assertSame(
            ['value1' => $stored, 'value2' => $stored, 'value1_id' => $id, 'value2_id' => $id],
            AttributeValue::withValueColumns(['value1' => $stored, 'value2' => $stored, 'value1_id' => $id, 'value2_id' => $id])
        );
        $this->assertSame(
            ['value1_id' => $id, 'value1' => $text],
            AttributeValue::withValueColumns(['value1_id' => $id])
        );
        $this->assertSame(['name' => $text], AttributeValue::withValueColumns(['name' => $text]));
    }

    public function testAssignIdsRefusesAValueTheDictionaryCannotHold()
    {
        $row = ['value1' => str_repeat('A', AttributeValue::MAX_BYTES + 1), 'value2' => ''];

        $this->expectException('InvalidArgumentException');
        $this->model($this->mysql)->assignIds($row);
    }

    public function testFindAddressedReadsAPositiveIdOnly()
    {
        $this->mysql->responder = $this->answerIds([5 => 'evil.com']);
        $model = $this->model($this->mysql);

        $this->assertSame(['id' => 5, 'value' => 'evil.com'], $model->findAddressed(['id' => 5]));
        $this->assertSame(['id' => 5, 'value' => 'evil.com'], $model->findAddressed(['id' => '5']));
        $this->assertNull($model->findAddressed(['id' => 6]));
        $this->assertCount(3, $this->mysql->statements);
        foreach (['abc', '0', '-5', '5 OR 1=1', '5.0', ['5']] as $id) {
            $this->assertNull($model->findAddressed(['id' => $id]), var_export($id, true));
        }
        $this->assertCount(3, $this->mysql->statements);
    }

    public function testFindAddressedBySha256ChecksTheWholeHash()
    {
        $this->mysql->store('evil.com', 9);
        // Stored under the hash prefix of another text
        $this->mysql->store('other', 10, 'collide.example');
        $model = $this->model($this->mysql);

        $sha256 = hash('sha256', 'evil.com');
        $this->assertSame(['id' => 9, 'value' => 'evil.com'], $model->findAddressed(['sha256' => $sha256]));
        $this->assertSame(['id' => 9, 'value' => 'evil.com'], $model->findAddressed(['sha256' => strtoupper($sha256)]));
        $this->assertNull($model->findAddressed(['sha256' => hash('sha256', 'collide.example')]));
        $this->assertNull($model->findAddressed(['sha256' => hash('sha256', 'absent.example')]));
        $this->assertCount(4, $this->mysql->statements);
        foreach ([substr($sha256, 0, 32), $sha256 . '0', 'g' . substr($sha256, 1), [$sha256]] as $bad) {
            $this->assertNull($model->findAddressed(['sha256' => $bad]), var_export($bad, true));
        }
        $this->assertCount(4, $this->mysql->statements);
    }

    public function testFindAddressedByTextMatchesTheExactBytes()
    {
        $this->mysql->store('evil.com', 9);
        $this->mysql->store('8080', 11);
        $model = $this->model($this->mysql);

        $this->assertSame(['id' => 9, 'value' => 'evil.com'], $model->findAddressed(['value' => 'evil.com']));
        $this->assertSame(['id' => 11, 'value' => '8080'], $model->findAddressed(['value' => 8080]));
        $this->assertNull($model->findAddressed(['value' => 'EVIL.com']));
        $this->assertNull($model->findAddressed(['value' => ['evil.com']]));
        $this->assertNull($model->findAddressed([]));
    }
}
