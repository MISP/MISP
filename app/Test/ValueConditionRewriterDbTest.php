<?php
/**
 * Rewritten conditions select the same attributes on the value ids as the
 * originals select on the text, read back from the ids in the collation of
 * the 2.x text columns, through Cake against the real database: generic_add_filter's forms, the value field, the empty value2,
 * negation, overflow and bounded finds, and a fixed sample of real values.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/ValueConditionRewriterDbTest.php
 */

use PHPUnit\Framework\TestCase;

class ValueConditionRewriterDbTest extends TestCase
{
    // A 2.x text column, which the reference reads need, as a virtual field
    const TEXT_2X = "COALESCE((SELECT v.value FROM attribute_values v WHERE v.id = Attribute.%s_id), '') COLLATE utf8mb4_unicode_ci";

    // The 2.x value field over those
    const VALUE_2X = "CASE WHEN %2\$s = '' THEN %1\$s ELSE CONCAT(%1\$s, '|', %2\$s) END";

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var string */
    private $token;

    /** @var array */
    private $event;

    /** @var array name => attribute id */
    private $ids = [];

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
            App::uses('ValueConditionRewriter', 'Tools');
            App::uses('AttributeValue', 'Model');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->db->begin();
        $this->token = 'avcond' . bin2hex(random_bytes(4));
        $this->event = $this->attribute->Event->find('first', [
            'recursive' => -1,
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id'],
        ])['Event'];
        $this->createFixture();
        $text = [];
        foreach (['value1', 'value2'] as $column) {
            $text[$column] = $this->attribute->virtualFields[$column] = sprintf(self::TEXT_2X, $column);
        }
        $this->attribute->virtualFields['value'] = sprintf(self::VALUE_2X, $text['value1'], $text['value2']);
    }

    protected function tearDown(): void
    {
        if ($this->db) {
            $this->db->rollback();
        }
        if ($this->attribute) {
            unset($this->attribute->virtualFields['value1'], $this->attribute->virtualFields['value2'], $this->attribute->virtualFields['value']);
        }
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

    private function createFixture()
    {
        $t = $this->token;
        $this->ids['domain'] = $this->create('domain', "$t.example.org");
        $this->ids['upper'] = $this->create('text', strtoupper($t) . '.EXAMPLE.ORG');
        $this->ids['accent'] = $this->create('text', "café $t");
        $this->ids['plain'] = $this->create('text', "cafe $t");
        $this->ids['piped'] = $this->create('text', "{$t}a.example|192.0.2.7");
        $this->ids['composite'] = $this->create('domain|ip', "{$t}a.example|192.0.2.7");
        $this->ids['underscore'] = $this->create('text', "{$t}_under_score");
        $this->ids['spaced'] = $this->create('domain|ip', "{$t}sp.example|192.0.2.8");
        $this->ids['legacy'] = $this->create('domain|ip', "{$t}lg.example|192.0.2.9");

        $values = $this->attribute->loadAttributeValue()->internMany([' ', "{$t}x|y"]);
        $this->exec(sprintf('UPDATE attributes SET value2_id = %d WHERE id = %d', $values[' '], $this->ids['spaced']));
        $this->exec(sprintf('UPDATE attributes SET value1_id = %d WHERE id = %d', $values["{$t}x|y"], $this->ids['legacy']));
    }

    private function create($type, $value)
    {
        $this->attribute->create();
        $saved = $this->attribute->save(['Attribute' => [
            'event_id' => $this->event['id'],
            'category' => $type === 'text' ? 'Other' : 'Network activity',
            'type' => $type,
            'value' => $value,
            'distribution' => 5,
            'to_ids' => 0,
            'disable_correlation' => 1,
        ]]);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        return (int)$this->attribute->id;
    }

    /**
     * @param array $conditions
     * @return int[]
     */
    private function select(array $conditions)
    {
        $ids = $this->attribute->find('column', [
            'conditions' => $conditions,
            'fields' => ['Attribute.id'],
            'callbacks' => false,
        ]);
        $ids = array_map('intval', $ids);
        sort($ids);
        return $ids;
    }

    /**
     * @param array $scope
     * @param array $conditions
     * @param array $options
     * @return void
     */
    private function assertSameRows(array $scope, array $conditions, array $options = [])
    {
        $original = ['AND' => [$scope, $conditions]];
        $rewriter = new ValueConditionRewriter($this->attribute->loadAttributeValue(), 'Attribute', $options + ['strict' => true]);
        $rewritten = $rewriter->rewrite($original);

        $this->assertNotRegExp('/"Attribute\\.value[12]?[" ]/', json_encode($rewritten));
        $this->assertSame($this->select($original), $this->select($rewritten), json_encode($conditions) . ' ' . json_encode($options));
    }

    private function cases()
    {
        $t = $this->token;
        $cases = [];
        $filters = [
            ['OR' => ["$t.example.org"]],
            ['OR' => [strtoupper($t) . '.example.org']],
            ['OR' => ["cafe $t"]],
            ['OR' => ["%$t%"]],
            ['OR' => ["{$t}a.example|192.0.2.7", '192.0.2.8']],
            ['NOT' => ["$t.example.org"]],
            ['NOT' => ["%{$t}a%"]],
            ['OR' => ["%$t%"], 'NOT' => ['%example%']],
            ['AND' => ["%$t%", "{$t}_under_score"]],
        ];
        foreach ($filters as $filter) {
            $cases[] = $this->attribute->generic_add_filter([], $filter, ['Attribute.value1', 'Attribute.value2']);
        }
        foreach ([['OR' => ['192.0.2.7']], ['NOT' => ['192.0.2.7']], ['OR' => ['%2.0.2%']], ['NOT' => ['%2.0.2.8%']]] as $filter) {
            $cases[] = $this->attribute->generic_add_filter([], $filter, 'Attribute.value2');
        }
        $cases[] = ['Attribute.value' => "{$t}a.example|192.0.2.7"];
        $cases[] = ['Attribute.value' => ["{$t}x|y|192.0.2.9", "{$t}sp.example"]];
        $cases[] = ['Attribute.value LIKE' => "%{$t}a.example|192%"];
        $cases[] = ['Attribute.value LIKE' => "%{$t}%"];
        $cases[] = ['Attribute.value LIKE' => "%{$t}_under%"];
        $cases[] = ['Attribute.value LIKE' => "%.example_192.0.2._"];
        $cases[] = ['Attribute.value NOT LIKE' => '%|%'];
        $cases[] = ['Attribute.value !=' => "$t.example.org"];
        $cases[] = ['Attribute.value NOT IN' => ["{$t}a.example|192.0.2.7", "cafe $t"]];
        $cases[] = ['Attribute.value2' => ''];
        $cases[] = ['Attribute.value2 !=' => ''];
        $cases[] = ['NOT' => ['Attribute.value' => "$t.example.org"]];
        $cases[] = ['Attribute.value1 NOT LIKE' => '%example%'];
        $cases[] = ['XOR' => [['Attribute.value2' => ''], ['Attribute.value1 LIKE' => "$t%"]]];
        return $cases;
    }

    public function testTheFixtureRowsAreSelectedAsOnTheTextColumns()
    {
        $scopes = [
            'unbounded' => [$this->scopeByUuid(), []],
            'overflow' => [$this->scopeByUuid(), ['overflow' => 1]],
            'bounded' => [['Attribute.id' => array_values($this->ids)], []],
        ];
        foreach ($scopes as list($scope, $options)) {
            foreach ($this->cases() as $conditions) {
                $this->assertSameRows($scope, $conditions, $options);
            }
        }
    }

    public function testTheCasesSelectWhatTheyShould()
    {
        $scope = ['Attribute.id' => array_values($this->ids)];
        $t = $this->token;
        $this->assertSame(
            $this->sorted(['domain', 'upper']),
            $this->select(['AND' => [$scope, ['Attribute.value' => "$t.example.org"]]])
        );
        $this->assertSame(
            $this->sorted(['piped', 'composite']),
            $this->select(['AND' => [$scope, ['Attribute.value' => "{$t}a.example|192.0.2.7"]]])
        );
        $this->assertSame(
            $this->sorted(['domain', 'upper', 'accent', 'plain', 'piped', 'underscore', 'spaced']),
            $this->select(['AND' => [$scope, ['Attribute.value2' => '']]])
        );
        $this->assertSame(
            $this->sorted(['accent', 'plain']),
            $this->select(['AND' => [$scope, ['Attribute.value1' => "cafe $t"]]])
        );
    }

    public function testASampleOfRealValuesSelectsTheSameAttributes()
    {
        $columns = sprintf(
            'id, event_id, %s AS value1, %s AS value2',
            AttributeValueTextSupport::text('attributes', 'value1'),
            AttributeValueTextSupport::text('attributes', 'value2')
        );
        $sample = $this->exec(
            "(SELECT $columns FROM attributes WHERE deleted = 0 AND id % 50021 = 7 ORDER BY id LIMIT 40)"
            . " UNION ALL (SELECT $columns FROM attributes WHERE deleted = 0 AND value2_id IS NOT NULL"
            . ' AND id % 5003 = 11 ORDER BY id LIMIT 20)'
        );
        $this->assertNotEmpty($sample);
        $candidates = $this->candidates(array_column($sample, 'value1'));
        $this->assertGreaterThanOrEqual(count(array_unique(array_column($sample, 'value1'))), count($candidates));
        foreach ($sample as $row) {
            $value = $row['value2'] === '' ? $row['value1'] : $row['value1'] . '|' . $row['value2'];
            $this->assertSameRows(
                ['Attribute.event_id' => (int)$row['event_id']],
                ['Attribute.value' => $value]
            );
            $filter = ['OR' => [$row['value1']]];
            $this->assertSameRows(
                ['Attribute.deleted' => 0, 'OR' => ['Attribute.value1_id' => $candidates, 'Attribute.value2_id' => $candidates]],
                $this->attribute->generic_add_filter([], $filter, ['Attribute.value1', 'Attribute.value2'])
            );
        }
    }

    public function testTheEmptyStringIsComparedInTheDictionaryCollation()
    {
        $dictionary = $this->attribute->loadAttributeValue();
        $this->assertStringStartsWith('utf8mb4_', $dictionary->getDataSource()->describe($dictionary)['value']['collate']);

        $terms = ['  ', '-', "\u{00a0}", "\u{200b}", 'x'];
        $expected = [];
        foreach ($terms as $term) {
            $row = $this->exec(sprintf(
                "SELECT COUNT(*) AS n FROM attribute_values WHERE id = (SELECT MIN(id) FROM attribute_values) AND SUBSTRING(value, 1, 0) = %s",
                $this->db->value($term, 'string')
            ));
            $expected[$term] = (int)$row[0]['n'] === 1;
        }
        $this->assertSame($expected, $dictionary->matchesEmpty($terms));
        $this->assertTrue($expected['  ']);
        $this->assertFalse($expected['x']);
    }

    /**
     * The dictionary ids that equal a term, or match it where it is a
     * pattern, in the dictionary collation or the 2.x one. Both sides of an
     * instance-wide search can only find attributes holding one of them, so
     * scoping both to these keeps what they find and spares a table scan per
     * term.
     *
     * @param string[] $terms
     * @return int[]
     */
    private function candidates(array $terms)
    {
        $exact = [];
        $ids = [];
        foreach (array_unique($terms) as $term) {
            $quoted = $this->db->value($term, 'string');
            if (str_starts_with($term, '%') || str_ends_with($term, '%')) {
                $ids = array_merge($ids, array_column($this->exec(
                    "SELECT id FROM attribute_values WHERE value LIKE $quoted OR value COLLATE utf8mb4_unicode_ci LIKE $quoted"
                ), 'id'));
            } else {
                $exact[] = $quoted;
            }
        }
        if (!empty($exact)) {
            $list = implode(', ', $exact);
            $ids = array_merge($ids, array_column($this->exec(
                "SELECT id FROM attribute_values WHERE value IN ($list) OR value COLLATE utf8mb4_unicode_ci IN ($list)"
            ), 'id'));
        }
        return array_values(array_unique(array_map('intval', $ids)));
    }

    private function scopeByUuid()
    {
        return ['Attribute.uuid' => $this->attribute->find('column', [
            'conditions' => ['Attribute.id' => array_values($this->ids)],
            'fields' => ['Attribute.uuid'],
            'callbacks' => false,
        ])];
    }

    private function sorted(array $names)
    {
        $ids = [];
        foreach ($names as $name) {
            $ids[] = $this->ids[$name];
        }
        sort($ids);
        return $ids;
    }
}
