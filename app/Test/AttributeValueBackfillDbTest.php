<?php
/**
 * AttributeValueBackfillTool against the configured MySQL/MariaDB database.
 *
 * The tool commits per chunk, so it runs on scratch tables created and
 * dropped around each test: a copy of attribute_values, and two tables whose
 * value columns match those of attributes (utf8mb3_unicode_ci, NOT NULL) and
 * shadow_attributes (utf8mb3_bin, nullable). Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueBackfillDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueBackfillDbTest extends TestCase
{
    const VALUES = 'avbf_values';
    const ATTRIBUTES = 'avbf_attributes';
    const SHADOW = 'avbf_shadow';

    private static $booted = false;

    /** @var AttributeValue */
    private $model;

    /** @var DboSource */
    private $db;

    /** @var AttributeValueBackfillTool */
    private $tool;

    /** @var array id => [value1, value2] */
    private $attributes = [];

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
            App::uses('ConnectionManager', 'Model');
            App::uses('AttributeValueBackfillTool', 'Tools');
            self::$booted = true;
        }
        $this->db = ConnectionManager::getDataSource('default');
        if (!($this->db instanceof Mysql)) {
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->db->cacheSources = false;
        $this->dropTables();
        $this->db->rawQuery(sprintf('CREATE TABLE %s LIKE attribute_values', self::VALUES));
        $this->db->rawQuery(sprintf(
            'CREATE TABLE %s (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,'
            . ' value1 TEXT CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,'
            . ' value2 TEXT CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,'
            . ' value1_id BIGINT UNSIGNED NULL, value2_id BIGINT UNSIGNED NULL)',
            self::ATTRIBUTES
        ));
        $this->db->rawQuery(sprintf(
            'CREATE TABLE %s (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,'
            . ' value1 TEXT CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NULL,'
            . ' value2 TEXT CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NULL,'
            . ' value1_id BIGINT UNSIGNED NULL, value2_id BIGINT UNSIGNED NULL)',
            self::SHADOW
        ));
        $this->model = ClassRegistry::init(['class' => 'AttributeValue', 'table' => self::VALUES]);
        $this->tool = new AttributeValueBackfillTool($this->model);
        $this->attributes = $this->seed(self::ATTRIBUTES, [
            ['Foo', ''],
            ['foo', ''],
            ['café', ''],
            ['cafe', ''],
            ["United\u{00A0}States", ''],
            ['United States', ''],
            ['a', ''],
            ['a ', ''],
            ['a', ' '],
            ['a', 'b'],
            ['b', 'a'],
            ['', ''],
            ['x', 'X'],
            [str_repeat('€', 20000), ''],
            ["it's \\ a %_ 中文", 'Foo'],
            ['Foo', ''],
            ['pre', ''],
        ]);
    }

    protected function tearDown(): void
    {
        if ($this->model) {
            $this->dropTables();
        }
    }

    private function dropTables()
    {
        foreach ([self::VALUES, self::ATTRIBUTES, self::SHADOW] as $table) {
            $this->db->rawQuery('DROP TABLE IF EXISTS ' . $table);
        }
    }

    /**
     * @return array id => [value1, value2]
     */
    private function seed($table, array $rows)
    {
        $seeded = [];
        foreach ($rows as $row) {
            $this->db->rawQuery(sprintf(
                'INSERT INTO %s (value1, value2) VALUES (%s, %s)',
                $table,
                $row[0] === null ? 'NULL' : $this->db->value($row[0], 'string'),
                $row[1] === null ? 'NULL' : $this->db->value($row[1], 'string')
            ));
            $seeded[(int)$this->db->lastInsertId()] = $row;
        }
        return $seeded;
    }

    private function rows($sql)
    {
        $statement = $this->db->rawQuery($sql);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        $statement->closeCursor();
        return $rows;
    }

    /**
     * @return array id => [value1_id, value2_id]
     */
    private function ids($table)
    {
        $ids = [];
        foreach ($this->rows("SELECT id, value1_id, value2_id FROM $table ORDER BY id") as $row) {
            $ids[(int)$row['id']] = [
                $row['value1_id'] === null ? null : (int)$row['value1_id'],
                $row['value2_id'] === null ? null : (int)$row['value2_id'],
            ];
        }
        return $ids;
    }

    /**
     * @return array id => value
     */
    private function dictionary()
    {
        $values = [];
        foreach ($this->rows('SELECT id, value, hash FROM ' . self::VALUES) as $row) {
            $this->assertSame(bin2hex($this->model->hashOf($row['value'])), bin2hex($row['hash']), 'stored hash of ' . $row['id']);
            $values[(int)$row['id']] = $row['value'];
        }
        return $values;
    }

    private function idOf($value)
    {
        $rows = $this->rows(sprintf(
            "SELECT id FROM %s WHERE hash = X'%s'",
            self::VALUES,
            bin2hex($this->model->hashOf($value))
        ));
        return (int)$rows[0]['id'];
    }

    private function assertReconstructs($table, array $seeded)
    {
        $dictionary = $this->dictionary();
        foreach ($this->ids($table) as $id => list($value1Id, $value2Id)) {
            list($value1, $value2) = $seeded[$id];
            $this->assertNotNull($value1Id, "value1_id of $id");
            $this->assertSame(bin2hex($value1), bin2hex($dictionary[$value1Id]), "value1 of $id");
            if ((string)$value2 === '') {
                $this->assertNull($value2Id, "value2_id of $id");
            } else {
                $this->assertNotNull($value2Id, "value2_id of $id");
                $this->assertSame(bin2hex($value2), bin2hex($dictionary[$value2Id]), "value2 of $id");
            }
        }
    }

    public function testEveryRowGetsTheIdsOfItsExactValues()
    {
        $pre = $this->model->intern('pre');
        $shadow = $this->seed(self::SHADOW, [['Foo', ''], ['foo', null], ['shadow only', 'x']]);

        $attributes = $this->tool->backfill(self::ATTRIBUTES, 4);
        $proposals = $this->tool->backfill(self::SHADOW, 2);

        $this->assertSame(['rows' => 17, 'values' => 15, 'last_id' => max(array_keys($this->attributes))], $attributes);
        $this->assertSame(['rows' => 3, 'values' => 1, 'last_id' => max(array_keys($shadow))], $proposals);
        $this->assertReconstructs(self::ATTRIBUTES, $this->attributes);
        $this->assertReconstructs(self::SHADOW, $shadow);

        $distinct = [];
        foreach (array_merge(array_values($this->attributes), array_values($shadow)) as list($value1, $value2)) {
            $distinct[$value1] = true;
            if ((string)$value2 !== '') {
                $distinct[$value2] = true;
            }
        }
        $dictionary = $this->dictionary();
        $this->assertCount(count($distinct), $dictionary);
        $this->assertSame($pre, $this->idOf('pre'));
        foreach ([['Foo', 'foo'], ['café', 'cafe'], ["United\u{00A0}States", 'United States'], ['a', 'a '], ['x', 'X']] as list($one, $other)) {
            $this->assertNotSame($this->idOf($one), $this->idOf($other), "$one / $other");
        }

        // The model finds every row the backfill wrote, and adds none
        $ids = $this->model->internMany(array_keys($distinct));
        foreach ($ids as $value => $id) {
            $this->assertSame($this->idOf((string)$value), $id);
        }
        $this->assertCount(count($distinct), $this->dictionary());
    }

    public function testVerifyCountsMissingAndWrongIdsByteForByte()
    {
        $total = count($this->attributes);
        $this->assertSame(
            ['total' => $total, 'pending' => $total, 'mismatched' => 0, 'first_mismatch' => null],
            $this->tool->verify(self::ATTRIBUTES, 5)
        );

        $this->tool->backfill(self::ATTRIBUTES, 5);

        $this->assertSame(
            ['total' => $total, 'pending' => 0, 'mismatched' => 0, 'first_mismatch' => null],
            $this->tool->verify(self::ATTRIBUTES, 5)
        );
        $this->assertSame(['total' => $total - 1, 'mismatched' => 0, 'first_mismatch' => null], $this->tool->verifyDictionary(5));

        $ids = array_keys($this->attributes);
        // A case variant, which a collation-aware comparison would let through
        $this->db->rawQuery(sprintf('UPDATE %s SET value1_id = %d WHERE id = %d', self::ATTRIBUTES, $this->idOf('foo'), $ids[0]));
        // An empty value2 with the id of the empty string, and a value2 without an id
        $this->db->rawQuery(sprintf('UPDATE %s SET value2_id = %d WHERE id = %d', self::ATTRIBUTES, $this->idOf(''), $ids[6]));
        $this->db->rawQuery(sprintf('UPDATE %s SET value2_id = NULL WHERE id = %d', self::ATTRIBUTES, $ids[9]));
        // A dangling id
        $this->db->rawQuery(sprintf('UPDATE %s SET value1_id = 999999999 WHERE id = %d', self::ATTRIBUTES, $ids[10]));
        // A space-only value2 pointing at the empty string
        $this->db->rawQuery(sprintf('UPDATE %s SET value2_id = %d WHERE id = %d', self::ATTRIBUTES, $this->idOf(''), $ids[8]));

        $this->assertSame(
            ['total' => $total, 'pending' => 0, 'mismatched' => 5, 'first_mismatch' => $ids[0]],
            $this->tool->verify(self::ATTRIBUTES, 5)
        );

        $this->db->rawQuery(sprintf("UPDATE %s SET value = 'CAFE' WHERE id = %d", self::VALUES, $this->idOf('cafe')));

        $this->assertSame(
            ['total' => $total - 1, 'mismatched' => 1, 'first_mismatch' => $this->idOf('cafe')],
            $this->tool->verifyDictionary(5)
        );
        $this->assertSame(6, $this->tool->verify(self::ATTRIBUTES, 5)['mismatched']);
    }

    public function testAStoppedRunResumesWithTheRowsItHadNotReached()
    {
        $chunks = 0;
        try {
            $this->tool->backfill(self::ATTRIBUTES, 3, function () use (&$chunks) {
                if (++$chunks === 2) {
                    throw new RuntimeException('stopped');
                }
            });
            $this->fail('The run was not stopped.');
        } catch (RuntimeException $e) {
            $this->assertSame('stopped', $e->getMessage());
        }
        $before = $this->ids(self::ATTRIBUTES);
        $done = array_filter($before, function ($ids) {
            return $ids[0] !== null;
        });
        $this->assertCount(6, $done);
        $dictionary = count($this->dictionary());

        $totals = $this->tool->backfill(self::ATTRIBUTES, 3);

        $this->assertSame(count($this->attributes) - 6, $totals['rows']);
        $this->assertCount($dictionary + $totals['values'], $this->dictionary());
        $after = $this->ids(self::ATTRIBUTES);
        foreach ($done as $id => $ids) {
            $this->assertSame($ids, $after[$id]);
        }
        $this->assertReconstructs(self::ATTRIBUTES, $this->attributes);
    }

    /**
     * A dictionary row that does not hold the value its hash belongs to, as a
     * truncated insert would leave behind.
     */
    public function testAChunkThatDoesNotReconstructIsRolledBack()
    {
        $this->db->rawQuery(sprintf(
            "INSERT INTO %s (value, hash) VALUES ('CAFE', X'%s')",
            self::VALUES,
            bin2hex($this->model->hashOf('cafe'))
        ));
        $ids = array_keys($this->attributes);

        try {
            $this->tool->backfill(self::ATTRIBUTES, 2);
            $this->fail('The chunk was committed.');
        } catch (RuntimeException $e) {
            $this->assertSame(sprintf(
                '1 rows of %s do not match their dictionary values, the first is %d. Their ids were rolled back.',
                self::ATTRIBUTES,
                $ids[3]
            ), $e->getMessage());
        }
        $after = $this->ids(self::ATTRIBUTES);
        $this->assertNotNull($after[$ids[1]][0]);
        $this->assertSame([null, null], $after[$ids[2]]);
        $this->assertSame([null, null], $after[$ids[3]]);
    }

    public function testARowWithoutValue1IsRefusedBeforeAnythingIsWritten()
    {
        $shadow = $this->seed(self::SHADOW, [[null, 'x']]);

        try {
            $this->tool->backfill(self::SHADOW);
            $this->fail('A NULL value1 was accepted.');
        } catch (RuntimeException $e) {
            $this->assertStringStartsWith(sprintf('Row %d of %s has a NULL value1', key($shadow), self::SHADOW), $e->getMessage());
        }
        $this->assertSame([], $this->dictionary());
    }
}
