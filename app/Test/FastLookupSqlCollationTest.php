<?php

/**
 * Requires the disposable integration database socket; ordinary unit runs skip.
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class FastLookupSqlCollationTest extends PHPUnit\Framework\TestCase
{
    private $server;
    private $pdo;
    private $database;

    protected function setUp(): void
    {
        $socket = getenv('MISP_FASTLOOKUP_LIFECYCLE_SOCKET');
        if (!$socket || !extension_loaded('pdo_mysql') || !file_exists($socket)) {
            $this->markTestSkipped('Requires a disposable MariaDB socket in MISP_FASTLOOKUP_LIFECYCLE_SOCKET.');
        }
        require_once __DIR__ . '/fixtures/FastLookupConfigurationStub.php';
        require_once __DIR__ . '/../Lib/Tools/FastLookupConfig.php';
        require_once __DIR__ . '/../Lib/Tools/FastLookupValueTool.php';
        $this->server = new PDO('mysql:unix_socket=' . $socket . ';charset=utf8mb4', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        // The disposable socket has no application database; use a scratch one,
        // uniquely named per run so concurrent worktrees never collide.
        $this->database = 'fastlookup_collation_' . bin2hex(random_bytes(8));
        $this->server->exec('CREATE DATABASE ' . $this->database);
        $this->pdo = new PDO('mysql:unix_socket=' . $socket . ';dbname=' . $this->database . ';charset=utf8mb4',
            'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        Configure::clear();
    }

    protected function tearDown(): void
    {
        if ($this->pdo instanceof PDO && $this->database) {
            $this->server->exec('DROP DATABASE ' . $this->database);
        }
        // Isolated failures serialize the test case; PDO cannot be serialized.
        $this->pdo = $this->server = null;
    }

    /** @dataProvider collations */
    public function testExactTokensNeverLoseDatabaseEqualValues($collation): void
    {
        $attribute = new FastLookupTestAttribute();
        $attribute->db = new class($this->pdo) extends FastLookupTestDatasource {
            private $pdo;
            public function __construct($pdo) { $this->pdo = $pdo; $this->config['datasource'] = 'Database/Mysql'; }
            public function rawQuery($sql) { $this->queries[] = $sql; return $this->pdo->query($sql); }
            public function value($value, $type = null) { return $this->pdo->quote($value); }
            public function getConnection() { return $this->pdo; }
        };
        $charset = explode('_', $collation, 2)[0];
        $attribute->columns = array_fill_keys(['value1', 'value2'], ['charset' => $charset, 'collate' => $collation]);
        $tool = new FastLookupValueTool($attribute);
        $pairs = [
            ['CAFÉ ', 'cafe'], ["cafe\u{00a0}", 'cafe'], ["a\u{200b}", 'a'],
            ["a\u{0301}", 'a'], ['Straße', 'strasse'], ['Æ', 'ae'], ['x ', 'x'],
            ["\u{200b}", "\u{200b}"], ["\u{0301}", "\u{0301}"], ['Case', 'case'],
            ['α', 'Α'], ['large' . str_repeat(' ', 300), 'large'],
        ];
        // Values are round-tripped through a real MySQL table with the collation
        // under test, so the weights scanColumns()/prepareScannedAttributes()
        // consume are the database's own, not a value computed in PHP.
        $table = 'fastlookup_collation_probe';
        $this->pdo->exec('DROP TABLE IF EXISTS ' . $table);
        $this->pdo->exec(
            'CREATE TABLE ' . $table . ' ('
            . 'id INT PRIMARY KEY, type VARCHAR(64), '
            . 'value1 VARCHAR(500) CHARACTER SET ' . $charset . ' COLLATE ' . $collation . ', '
            . 'value2 VARCHAR(500) CHARACTER SET ' . $charset . ' COLLATE ' . $collation . ')'
        );
        try {
            foreach ($pairs as list($stored, $query)) {
                $left = 'CONVERT(' . $this->pdo->quote($stored) . ' USING ' . $charset . ') COLLATE ' . $collation;
                $right = 'CONVERT(' . $this->pdo->quote($query) . ' USING ' . $charset . ') COLLATE ' . $collation;
                $equal = (bool)$this->pdo->query('SELECT ' . $left . ' = ' . $right)->fetchColumn();

                $this->pdo->exec('TRUNCATE TABLE ' . $table);
                $insert = $this->pdo->prepare('INSERT INTO ' . $table . " (id, type, value1, value2) VALUES (1, 'domain', ?, '')");
                $insert->execute([$stored]);
                $row = $this->pdo->query('SELECT ' . $tool->scanColumns('t') . ' FROM ' . $table . ' t WHERE t.id = 1')
                    ->fetch(PDO::FETCH_ASSOC);
                $prepared = $tool->prepareScannedAttributes([$row]);

                $queries = $tool->queryTokens([$query], ['domain'], $fallback, $weights);
                $candidate = !empty($fallback[0]['value1']) || (bool)array_intersect($prepared[0]['tokens'], array_column($queries[0], 'token'));
                if ($weights[0]['value1'] === '') {
                    // An ignorable-only value never matches, by design.
                    $this->assertFalse($candidate);
                } elseif ($equal) {
                    $this->assertTrue($candidate, $collation . ' lost a SQL-equal pair: ' . json_encode([$stored, $query]));
                } else {
                    // False positives are allowed; final SQL equality revalidates.
                    $this->assertIsBool($candidate);
                }
            }
        } finally {
            $this->pdo->exec('DROP TABLE IF EXISTS ' . $table);
        }
    }

    /** @dataProvider collations */
    public function testAsciiWeightsEqualDatabaseWeightsWithoutQueries($collation): void
    {
        $attribute = new FastLookupTestAttribute();
        $attribute->db = new class($this->pdo) extends FastLookupTestDatasource {
            private $pdo;
            public function __construct($pdo) { $this->pdo = $pdo; $this->config['datasource'] = 'Database/Mysql'; }
            public function rawQuery($sql) { $this->queries[] = $sql; return $this->pdo->query($sql); }
            public function value($value, $type = null) { return $this->pdo->quote($value); }
            public function getConnection() { return $this->pdo; }
        };
        $charset = explode('_', $collation, 2)[0];
        $attribute->columns = array_fill_keys(['value1', 'value2'], ['charset' => $charset, 'collate' => $collation]);
        $tool = new FastLookupValueTool($attribute);
        $tool->queryTokens(['warm-up'], ['md5']);
        $queries = count($attribute->db->queries);

        $inputs = ['', ' ', '   ', "\t", " \t ", "a \x00", "\x00 ", ' a', "a\x7f ", str_repeat(' ', 300)];
        for ($n = 0; $n < 128; ++$n) {
            $inputs[] = chr($n);
            $inputs[] = 'x' . chr($n) . ' ';
        }
        mt_srand(20260929 + crc32($collation));
        $controls = array_merge(array_map('chr', range(0, 31)), ["\x7f"]);
        for ($i = 0; $i < 2000; ++$i) {
            $value = '';
            for ($length = mt_rand(0, 300), $j = 0; $j < $length; ++$j) {
                $roll = mt_rand(0, 9);
                $value .= $roll < 2 ? $controls[mt_rand(0, count($controls) - 1)] : ($roll < 4 ? ' ' : chr(mt_rand(0x21, 0x7e)));
            }
            $inputs[] = $value . str_repeat(' ', mt_rand(0, 3));
        }

        $mismatches = [];
        foreach (array_chunk($inputs, 500) as $chunk) {
            $tool->queryTokens($chunk, ['md5'], $fallback, $weights);
            $this->assertSame($queries, count($attribute->db->queries), $collation . ' issued a weights query for ASCII values.');
            $this->assertSame([], $fallback);
            $columns = [];
            foreach ($chunk as $value) {
                $columns[] = 'WEIGHT_STRING(RTRIM(CONVERT(' . $this->pdo->quote($value) . ' USING ' . $charset . ') COLLATE ' . $collation . '))';
            }
            $row = $this->pdo->query('SELECT ' . implode(', ', $columns))->fetch(PDO::FETCH_NUM);
            foreach ($chunk as $i => $value) {
                $expected = $tool->stripColumnPadding('value1', $row[$i]);
                if ($weights[$i]['value1'] !== $expected || $weights[$i]['value2'] !== $expected) {
                    $mismatches[] = bin2hex($value);
                }
            }
        }
        $this->assertSame([], array_slice($mismatches, 0, 5), $collation . ': ' . count($mismatches) . ' of ' . count($inputs) . ' ASCII weights differ from SQL.');
        $this->assertSame($queries, count($attribute->db->queries));
    }

    public static function collations(): array
    {
        return [['utf8mb3_unicode_ci'], ['utf8mb4_unicode_ci'], ['utf8mb3_general_ci'],
            ['utf8mb4_general_ci'], ['utf8mb3_bin'], ['utf8mb4_bin']];
    }
}
