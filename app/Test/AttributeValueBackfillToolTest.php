<?php
/**
 * AttributeValueBackfillTool against the connectionless MySQL and PostgreSQL
 * drivers: the statements each engine is sent, the walk over the table, and
 * what happens when a chunk cannot be committed.
 *
 * AttributeValueBackfillDbTest runs the tool against the real database.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';

use PHPUnit\Framework\TestCase;

class AttributeValueBackfillFakeStatement
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

trait AttributeValueBackfillFakeDb
{
    /** @var string[] */
    public $statements = [];

    /** @var callable Answers a statement with rows, or with a row count for a write. */
    public $responder;

    public function rawQuery($sql, $params = array())
    {
        $this->statements[] = $sql;
        $responder = $this->responder;
        $answer = $responder($sql);
        return is_int($answer)
            ? new AttributeValueBackfillFakeStatement([], $answer)
            : new AttributeValueBackfillFakeStatement($answer, 0);
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
}

class AttributeValueBackfillFakeMysql extends MigrationTestMysqlExtended
{
    use AttributeValueBackfillFakeDb;
}

class AttributeValueBackfillFakePostgres extends MigrationTestPostgres
{
    use AttributeValueBackfillFakeDb;
}

class AttributeValueBackfillToolTest extends TestCase
{
    /** @var AttributeValueBackfillFakeMysql */
    private $mysql;

    /** @var AttributeValueBackfillFakePostgres */
    private $pgsql;

    protected function setUp(): void
    {
        require_once __DIR__ . '/AttributeValueTestSupport.php';
        require_once __DIR__ . '/../Lib/Tools/AttributeValueBackfillTool.php';
        $this->mysql = new AttributeValueBackfillFakeMysql();
        $this->pgsql = new AttributeValueBackfillFakePostgres();
    }

    private function tool($db)
    {
        return new AttributeValueBackfillTool(new TestAttributeValue($db));
    }

    /**
     * A table of rows [id => [value1_id, refused]]. Checks pass and inserts
     * add two values unless told otherwise.
     */
    private function table(array $rows, array $check = ['bad' => '0', 'first_bad' => null])
    {
        return function ($sql) use ($rows, $check) {
            if (preg_match('/^SELECT id, value1_id, .* WHERE id > (\d+) ORDER BY id LIMIT (\d+)$/', $sql, $m)) {
                $out = [];
                foreach ($rows as $id => $row) {
                    if ($id > (int)$m[1] && count($out) < (int)$m[2]) {
                        $out[] = ['id' => (string)$id, 'value1_id' => $row[0], 'refused' => (string)$row[1]];
                    }
                }
                return $out;
            }
            if (strpos($sql, 'SELECT COUNT(*) AS bad') === 0) {
                return [$check];
            }
            if (strpos($sql, 'INSERT INTO') === 0) {
                return 2;
            }
            return 0;
        };
    }

    private function writes($db)
    {
        return array_values(array_filter($db->statements, function ($sql) {
            return strpos($sql, 'SELECT id, value1_id,') !== 0;
        }));
    }

    public function testBackfillSendsTheseStatementsToMysql()
    {
        $this->mysql->responder = $this->table([1 => [null, 0], 2 => ['7', 0], 3 => [null, 0]]);

        $totals = $this->tool($this->mysql)->backfill('attributes', 10);

        $this->assertSame(['rows' => 2, 'values' => 2, 'last_id' => 3], $totals);
        $hash1 = 'UNHEX(LEFT(SHA2(a.value1, 256), 32))';
        $hash2 = 'UNHEX(LEFT(SHA2(a.value2, 256), 32))';
        $this->assertSame([
            'SELECT id, value1_id, CASE WHEN value1 IS NULL OR OCTET_LENGTH(value1) > 65535'
            . ' OR OCTET_LENGTH(value2) > 65535 THEN 1 ELSE 0 END AS refused'
            . ' FROM `attributes` WHERE id > 0 ORDER BY id LIMIT 10',
            'INSERT INTO `attribute_values` (value, hash) SELECT MIN(s.v), s.h FROM ('
            . "SELECT a.value1 AS v, $hash1 AS h FROM `attributes` a WHERE a.id IN (1, 3)"
            . " UNION ALL SELECT a.value2, $hash2 FROM `attributes` a WHERE a.id IN (1, 3) AND OCTET_LENGTH(a.value2) > 0"
            . ') s WHERE NOT EXISTS (SELECT 1 FROM `attribute_values` x WHERE x.hash = s.h) GROUP BY s.h ORDER BY s.h'
            . ' ON DUPLICATE KEY UPDATE `hash` = `hash`;',
            'BEGIN',
            "UPDATE `attributes` AS a SET value1_id = (SELECT v.id FROM `attribute_values` v WHERE v.hash = $hash1),"
            . ' value2_id = CASE WHEN COALESCE(OCTET_LENGTH(a.value2), 0) = 0 THEN NULL'
            . " ELSE (SELECT v.id FROM `attribute_values` v WHERE v.hash = $hash2) END"
            . ' WHERE a.id IN (1, 3)',
            'SELECT COUNT(*) AS bad, MIN(a.id) AS first_bad FROM `attributes` a'
            . ' LEFT JOIN `attribute_values` v1 ON v1.id = a.value1_id'
            . ' LEFT JOIN `attribute_values` v2 ON v2.id = a.value2_id'
            . ' WHERE a.id IN (1, 3) AND (a.value1 IS NULL OR v1.id IS NULL'
            . ' OR CAST(v1.value AS BINARY) <> CAST(a.value1 AS BINARY)'
            . ' OR (a.value2_id IS NULL AND COALESCE(OCTET_LENGTH(a.value2), 0) > 0)'
            . ' OR (a.value2_id IS NOT NULL AND (v2.id IS NULL OR COALESCE(OCTET_LENGTH(a.value2), 0) = 0'
            . ' OR CAST(v2.value AS BINARY) <> CAST(a.value2 AS BINARY))))',
            'COMMIT',
            'SELECT id, value1_id, CASE WHEN value1 IS NULL OR OCTET_LENGTH(value1) > 65535'
            . ' OR OCTET_LENGTH(value2) > 65535 THEN 1 ELSE 0 END AS refused'
            . ' FROM `attributes` WHERE id > 3 ORDER BY id LIMIT 10',
        ], $this->mysql->statements);
    }

    public function testBackfillSendsTheseStatementsToPostgres()
    {
        $this->pgsql->responder = $this->table([1 => [null, 0]]);

        $this->tool($this->pgsql)->backfill('shadow_attributes', 10);

        $hash1 = "substring(sha256(convert_to(a.value1, 'UTF8')) from 1 for 16)";
        $hash2 = "substring(sha256(convert_to(a.value2, 'UTF8')) from 1 for 16)";
        $this->assertSame([
            'INSERT INTO "attribute_values" (value, hash) SELECT MIN(s.v), s.h FROM ('
            . "SELECT a.value1 AS v, $hash1 AS h FROM \"shadow_attributes\" a WHERE a.id IN (1)"
            . " UNION ALL SELECT a.value2, $hash2 FROM \"shadow_attributes\" a WHERE a.id IN (1) AND OCTET_LENGTH(a.value2) > 0"
            . ') s WHERE NOT EXISTS (SELECT 1 FROM "attribute_values" x WHERE x.hash = s.h) GROUP BY s.h ORDER BY s.h'
            . ' ON CONFLICT ("hash") DO NOTHING;',
            'BEGIN',
            "UPDATE \"shadow_attributes\" AS a SET value1_id = (SELECT v.id FROM \"attribute_values\" v WHERE v.hash = $hash1),"
            . ' value2_id = CASE WHEN COALESCE(OCTET_LENGTH(a.value2), 0) = 0 THEN NULL'
            . " ELSE (SELECT v.id FROM \"attribute_values\" v WHERE v.hash = $hash2) END"
            . ' WHERE a.id IN (1)',
            'SELECT COUNT(*) AS bad, MIN(a.id) AS first_bad FROM "shadow_attributes" a'
            . ' LEFT JOIN "attribute_values" v1 ON v1.id = a.value1_id'
            . ' LEFT JOIN "attribute_values" v2 ON v2.id = a.value2_id'
            . ' WHERE a.id IN (1) AND (a.value1 IS NULL OR v1.id IS NULL'
            . " OR convert_to(v1.value, 'UTF8') <> convert_to(a.value1, 'UTF8')"
            . ' OR (a.value2_id IS NULL AND COALESCE(OCTET_LENGTH(a.value2), 0) > 0)'
            . ' OR (a.value2_id IS NOT NULL AND (v2.id IS NULL OR COALESCE(OCTET_LENGTH(a.value2), 0) = 0'
            . " OR convert_to(v2.value, 'UTF8') <> convert_to(a.value2, 'UTF8'))))",
            'COMMIT',
        ], $this->writes($this->pgsql));
    }

    public function testOnlyRowsWithoutIdsAreTouchedChunkByChunk()
    {
        $this->mysql->responder = $this->table([
            1 => ['11', 0], 2 => ['12', 0], 3 => ['13', 0],
            4 => [null, 0], 5 => ['15', 1], 6 => [null, 0],
            7 => [null, 0],
        ]);
        $seen = [];

        $totals = $this->tool($this->mysql)->backfill('attributes', 3, function (array $totals) use (&$seen) {
            $seen[] = $totals;
        });

        $this->assertSame(['rows' => 3, 'values' => 4, 'last_id' => 7], $totals);
        $this->assertSame([3, 6, 7], array_column($seen, 'last_id'));
        $this->assertSame([0, 2, 3], array_column($seen, 'rows'));
        preg_match_all('/WHERE id > (\d+) ORDER BY id LIMIT 3/', implode("\n", $this->mysql->statements), $m);
        $this->assertSame(['0', '3', '6', '7'], $m[1]);
        $updates = preg_grep('/^UPDATE/', $this->mysql->statements);
        $this->assertCount(2, $updates);
        $this->assertStringEndsWith('WHERE a.id IN (4, 6)', array_shift($updates));
        $this->assertStringEndsWith('WHERE a.id IN (7)', array_shift($updates));
        $this->assertSame(2, count(preg_grep('/^COMMIT$/', $this->mysql->statements)));
    }

    /**
     * Earlier chunks stay committed, so the run resumes from there once the
     * row is fixed. Rows that already have ids are not judged.
     */
    public function testARefusedRowStopsTheRunBeforeItsChunkIsWritten()
    {
        $this->mysql->responder = $this->table([1 => [null, 0], 2 => [null, 1]]);

        try {
            $this->tool($this->mysql)->backfill('shadow_attributes', 1);
            $this->fail('The refused row was accepted.');
        } catch (RuntimeException $e) {
            $this->assertSame(
                'Row 2 of shadow_attributes has a NULL value1 or a value over 65535 bytes, which the dictionary refuses.',
                $e->getMessage()
            );
        }
        $writes = $this->writes($this->mysql);
        $this->assertCount(5, $writes);
        $this->assertSame('COMMIT', end($writes));
        $this->assertStringContainsString('WHERE id > 1 ORDER BY id', end($this->mysql->statements));
    }

    public function testAChunkThatFailsItsCheckIsRolledBack()
    {
        $this->mysql->responder = $this->table([4 => [null, 0], 5 => [null, 0]], ['bad' => '2', 'first_bad' => '5']);

        try {
            $this->tool($this->mysql)->backfill('attributes', 10);
            $this->fail('A chunk that failed its check was committed.');
        } catch (RuntimeException $e) {
            $this->assertSame(
                '2 rows of attributes do not match their dictionary values, the first is 5. Their ids were rolled back.',
                $e->getMessage()
            );
        }
        $this->assertSame('ROLLBACK', end($this->mysql->statements));
        $this->assertNotContains('COMMIT', $this->mysql->statements);
    }

    public function testAFailedUpdateIsRolledBackAndRethrown()
    {
        $table = $this->table([1 => [null, 0]]);
        $error = new PDOException('Deadlock found when trying to get lock');
        $this->mysql->responder = function ($sql) use ($table, $error) {
            if (strpos($sql, 'UPDATE') === 0) {
                throw $error;
            }
            return $table($sql);
        };

        try {
            $this->tool($this->mysql)->backfill('attributes', 10);
            $this->fail('The error was swallowed.');
        } catch (PDOException $e) {
            $this->assertSame($error, $e);
        }
        $this->assertSame('ROLLBACK', end($this->mysql->statements));
        $this->assertNotContains('COMMIT', $this->mysql->statements);
    }

    public function testVerifyAddsUpTheChunks()
    {
        $chunks = [
            0 => ['id' => '10', 'counts' => ['total' => '10', 'pending' => '1', 'mismatched' => '0', 'first_mismatch' => null]],
            10 => ['id' => '25', 'counts' => ['total' => '5', 'pending' => '0', 'mismatched' => '2', 'first_mismatch' => '17']],
            25 => ['id' => '30', 'counts' => ['total' => '3', 'pending' => '0', 'mismatched' => '1', 'first_mismatch' => '26']],
        ];
        $this->mysql->responder = function ($sql) use ($chunks) {
            if (preg_match('/^SELECT MAX\(w\.id\) AS id FROM \(SELECT id FROM `attributes` WHERE id > (\d+) ORDER BY id LIMIT 10\) w$/', $sql, $m)) {
                return [['id' => isset($chunks[$m[1]]) ? $chunks[$m[1]]['id'] : null]];
            }
            preg_match('/WHERE a\.id > (\d+) AND a\.id <= \d+$/', $sql, $m);
            return [$chunks[$m[1]]['counts']];
        };
        $progress = 0;

        $counts = $this->tool($this->mysql)->verify('attributes', 10, function () use (&$progress) {
            $progress++;
        });

        $this->assertSame(['total' => 18, 'pending' => 1, 'mismatched' => 3, 'first_mismatch' => 17], $counts);
        $this->assertSame(3, $progress);
        $aggregates = array_values(preg_grep('/^SELECT COUNT/', $this->mysql->statements));
        $this->assertStringStartsWith(
            'SELECT COUNT(*) AS total, SUM(CASE WHEN a.value1_id IS NULL THEN 1 ELSE 0 END) AS pending,'
            . ' SUM(CASE WHEN a.value1_id IS NOT NULL AND (a.value1 IS NULL OR v1.id IS NULL',
            $aggregates[0]
        );
        $this->assertStringEndsWith(' WHERE a.id > 0 AND a.id <= 10', $aggregates[0]);
        $this->assertStringEndsWith(' WHERE a.id > 10 AND a.id <= 25', $aggregates[1]);
        $this->assertStringEndsWith(' WHERE a.id > 25 AND a.id <= 30', $aggregates[2]);
        $this->assertNotContains('BEGIN', $this->mysql->statements);
    }

    public function testVerifyDictionaryComparesEachHashWithItsValue()
    {
        foreach ([[$this->mysql, 'UNHEX(LEFT(SHA2(v.value, 256), 32))', '`attribute_values`'],
            [$this->pgsql, "substring(sha256(convert_to(v.value, 'UTF8')) from 1 for 16)", '"attribute_values"']] as list($db, $hash, $table)) {
            $db->responder = function ($sql) {
                if (strpos($sql, 'SELECT MAX') === 0) {
                    return [['id' => strpos($sql, 'id > 0 ') ? '4' : null]];
                }
                return [['total' => '4', 'mismatched' => '1', 'first_mismatch' => '3']];
            };

            $counts = $this->tool($db)->verifyDictionary(100);

            $this->assertSame(['total' => 4, 'mismatched' => 1, 'first_mismatch' => 3], $counts);
            $this->assertSame(
                "SELECT COUNT(*) AS total, SUM(CASE WHEN v.hash <> $hash THEN 1 ELSE 0 END) AS mismatched,"
                . " MIN(CASE WHEN v.hash <> $hash THEN v.id END) AS first_mismatch"
                . " FROM $table v WHERE v.id > 0 AND v.id <= 4",
                $db->statements[1]
            );
        }
    }

    public function testAnEmptyTableNeedsNothing()
    {
        $this->mysql->responder = function ($sql) {
            return strpos($sql, 'SELECT MAX') === 0 ? [['id' => null]] : [];
        };
        $tool = $this->tool($this->mysql);

        $this->assertSame(['rows' => 0, 'values' => 0, 'last_id' => 0], $tool->backfill('attributes'));
        $this->assertSame(['total' => 0, 'pending' => 0, 'mismatched' => 0, 'first_mismatch' => null], $tool->verify('attributes'));
        $this->assertSame(['total' => 0, 'mismatched' => 0, 'first_mismatch' => null], $tool->verifyDictionary());
        $this->assertCount(3, $this->mysql->statements);
    }

    public function testTheChunkSizeMustBePositive()
    {
        $this->mysql->responder = function () {
            return [];
        };
        $tool = $this->tool($this->mysql);
        foreach (['backfill', 'verify'] as $method) {
            try {
                $tool->$method('attributes', 0);
                $this->fail("$method accepted a chunk size of 0.");
            } catch (InvalidArgumentException $e) {
                $this->assertSame('The chunk size must be at least 1.', $e->getMessage());
            }
        }
        $this->assertSame([], $this->mysql->statements);
    }
}
