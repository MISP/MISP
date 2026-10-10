<?php
/**
 * AttributeValue against the configured MySQL/MariaDB database: the collation
 * behaviour and byte-exact round trips that AttributeValueTest cannot fake.
 *
 * Every test runs in a transaction that is rolled back, which still spends
 * auto-increment ids on attribute_values. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueDbTest extends TestCase
{
    private static $booted = false;

    /** @var AttributeValue */
    private $model;

    /** @var DboSource */
    private $db;

    /** @var string Keeps the test rows apart from real values. */
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
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->db->begin();
        $this->token = 'avtest' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        if ($this->db) {
            $this->db->rollback();
        }
    }

    private function unitedStates()
    {
        $t = $this->token;
        return [
            "$t United States",
            "$t united states",
            "$t United\u{00A0}States",
            "$t United States ",
            "$t Ünited States",
        ];
    }

    private function scalar($sql)
    {
        $statement = $this->db->rawQuery($sql);
        $value = $statement->fetchColumn();
        $statement->closeCursor();
        return $value;
    }

    public function testInternIsByteExactAndIdempotent()
    {
        $values = $this->unitedStates();

        $ids = $this->model->internMany($values);

        $this->assertCount(5, array_unique($ids));
        $again = $this->model->internMany(array_reverse($values));
        ksort($ids);
        ksort($again);
        $this->assertSame($ids, $again);
        $this->assertSame($ids[$values[2]], $this->model->intern($values[2]));
        $hashes = [];
        foreach ($values as $value) {
            $hashes[] = "X'" . bin2hex($this->model->hashOf($value)) . "'";
        }
        $this->assertSame('5', (string)$this->scalar(
            'SELECT COUNT(*) FROM attribute_values WHERE hash IN (' . implode(', ', $hashes) . ')'
        ));
    }

    public function testResolveCiReturnsEveryCollationVariant()
    {
        $ids = array_values($this->model->internMany($this->unitedStates()));
        sort($ids);
        $term = strtoupper($this->token) . ' UNITED STATES';

        $result = $this->model->resolveCi([$term, $this->token . ' nowhere']);

        sort($result[$term]);
        $this->assertSame($ids, $result[$term]);
        $this->assertSame([], $result[$this->token . ' nowhere']);
    }

    public function testFourByteCharactersStayDistinct()
    {
        $grin = $this->model->intern($this->token . "\u{1F600}");
        $imp = $this->model->intern($this->token . "\u{1F608}");

        $this->assertNotSame($grin, $imp);
        $this->assertSame([$grin], $this->model->resolveCi([$this->token . "\u{1F600}"])[$this->token . "\u{1F600}"]);
    }

    public function testTheCiLookupComparesBeyondTheIndexedPrefix()
    {
        $prefix = $this->token . str_repeat('p', 200);
        $a = $this->model->intern($prefix . 'a');
        $this->model->intern($prefix . 'b');
        $term = strtoupper($prefix) . 'A';

        $this->assertSame([$a], $this->model->resolveCi([$term])[$term]);
    }

    public function testResolveLike()
    {
        $ids = array_values($this->model->internMany($this->unitedStates()));
        sort($ids);

        $this->assertSame(['ids' => $ids, 'overflow' => false], $this->model->resolveLike($this->token . ' united%', 5));
        $this->assertSame(['ids' => [], 'overflow' => true], $this->model->resolveLike($this->token . ' united%', 4));
    }

    public function testFetchValuesIsByteIdentical()
    {
        $t = $this->token;
        $values = [
            "$t \u{1F600} four bytes",
            "$t it's a \\ backslash",
            "$t trailing  ",
            "$t\u{00A0}nbsp",
            $t . str_repeat('L', AttributeValue::MAX_BYTES - strlen($t)),
        ];

        $ids = $this->model->internMany($values);
        $fetched = $this->model->fetchValues(array_values($ids));

        foreach ($values as $value) {
            $this->assertSame(bin2hex($value), bin2hex($fetched[$ids[$value]]));
        }
    }

    public function testAttachValuesGivesBackTheText()
    {
        $Attribute = ClassRegistry::init(['class' => 'MispAttribute', 'alias' => 'Attribute']);
        foreach (['value2_id IS NOT NULL', 'value2_id IS NULL'] as $where) {
            $id = (int)$this->scalar("SELECT id FROM attributes WHERE $where AND deleted = 0 ORDER BY id LIMIT 1");
            $rows = $Attribute->find('all', [
                'conditions' => ['Attribute.id' => $id],
                'fields' => ['Attribute.id', 'Attribute.value1_id', 'Attribute.value2_id'],
                'recursive' => -1,
                'callbacks' => false,
            ]);
            $value1 = $this->scalar(sprintf('SELECT value FROM attribute_values WHERE id = %d', $rows[0]['Attribute']['value1_id']));
            $value2 = $rows[0]['Attribute']['value2_id'] === null
                ? ''
                : $this->scalar(sprintf('SELECT value FROM attribute_values WHERE id = %d', $rows[0]['Attribute']['value2_id']));

            $this->model->attachValues($rows, 'Attribute');

            $this->assertSame([
                'id' => (string)$id,
                'value1' => $value1,
                'value2' => $value2,
                'value' => $value2 === '' ? $value1 : "$value1|$value2",
            ], $rows[0]['Attribute']);
        }
    }
}
