<?php

/**
 * Requires the disposable integration database socket; ordinary unit runs skip.
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class FastLookupSqlCollationTest extends PHPUnit\Framework\TestCase
{
    private $pdo;

    protected function setUp(): void
    {
        $socket = getenv('MISP_FASTLOOKUP_LIFECYCLE_SOCKET');
        if (!$socket || !extension_loaded('pdo_mysql') || !file_exists($socket)) {
            $this->markTestSkipped('Requires a disposable MariaDB socket in MISP_FASTLOOKUP_LIFECYCLE_SOCKET.');
        }
        require_once __DIR__ . '/fixtures/FastLookupConfigurationStub.php';
        require_once __DIR__ . '/../Lib/Tools/FastLookupConfig.php';
        require_once __DIR__ . '/../Lib/Tools/FastLookupValueTool.php';
        $this->pdo = new PDO('mysql:unix_socket=' . $socket . ';charset=utf8mb4', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        // The disposable socket has no application database; use a scratch one for the probe table.
        $this->pdo->exec('CREATE DATABASE IF NOT EXISTS fastlookup_collation_test');
        $this->pdo->exec('USE fastlookup_collation_test');
        Configure::clear();
    }

    protected function tearDown(): void
    {
        if ($this->pdo instanceof PDO) {
            $this->pdo->exec('DROP DATABASE IF EXISTS fastlookup_collation_test');
        }
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

                $queries = $tool->queryTokens([$query], ['domain'], $fallback);
                $candidate = !empty($fallback[0]['value1']) || (bool)array_intersect($prepared[0]['tokens'], array_column($queries[0], 'token'));
                if ($equal) {
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

    public static function collations(): array
    {
        return [['utf8mb3_unicode_ci'], ['utf8mb4_unicode_ci'], ['utf8mb3_general_ci'],
            ['utf8mb4_general_ci'], ['utf8mb3_bin'], ['utf8mb4_bin']];
    }
}
