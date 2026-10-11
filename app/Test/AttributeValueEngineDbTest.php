<?php
/**
 * The attribute value dictionary on whichever engine the application is
 * configured for, MySQL/MariaDB or PostgreSQL: the statements that differ
 * between the two, run for real. Interning and exact lookups, the
 * case-insensitive lookup (PostgreSQL folds case only), LIKE and
 * value_search, the empty-value rule, the IP facet on binary columns,
 * deleting an unheld value, and a find through the condition rewriter.
 *
 * InnoDB's FULLTEXT index only sees committed rows, so values are interned
 * outside any transaction and deleted by id in tearDown; the find test saves
 * its attribute inside a transaction that is rolled back. Every value holds
 * a random token no stored value holds.
 *
 * Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real
 * application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueEngineDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueEngineDbTest extends TestCase
{
    const LIMIT = 1000;

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var AttributeValue */
    private $values;

    /** @var DboSource */
    private $db;

    /** @var bool */
    private $mysql;

    /** @var string */
    private $t;

    /** @var int[] dictionary ids interned for the test */
    private $interned = [];

    /** @var mixed */
    private $currentUserId;

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
            App::uses('ValueFacetTool', 'Tools');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->values = $this->attribute->loadAttributeValue();
        $this->db = $this->attribute->getDataSource();
        $this->mysql = $this->db instanceof Mysql;
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', 1);
        $this->t = 've' . bin2hex(random_bytes(5));
    }

    protected function tearDown(): void
    {
        if (!$this->db) {
            return;
        }
        Configure::write('CurrentUserId', $this->currentUserId);
        if (!empty($this->interned)) {
            $ids = implode(', ', array_map('intval', $this->interned));
            $this->exec("DELETE FROM value_ip_ranges WHERE value_id IN ($ids)");
            $this->exec("DELETE FROM attribute_values WHERE id IN ($ids)");
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

    /**
     * @param string[] $values
     * @return array [value => id]
     */
    private function intern(array $values)
    {
        $ids = $this->values->internMany($values);
        foreach ($ids as $id) {
            $this->interned[] = (int)$id;
        }
        return $ids;
    }

    private function sorted(array $ids)
    {
        $ids = array_map('intval', $ids);
        sort($ids);
        return $ids;
    }

    public function testInterningIsExactAndRepeatable()
    {
        $value = "$this->t-Value";
        $id = $this->intern([$value])[$value];
        $this->assertSame($id, $this->values->intern($value), 'a repeat finds the row');
        $lower = strtolower($value);
        $this->assertNotSame($id, $this->intern([$lower])[$lower], 'a case variant is its own value');
        $this->assertSame([$value => $id], $this->values->idsOf([$value, "$this->t-missing"]));
        $this->assertSame([$id => $value], $this->values->fetchValues([$id]));
    }

    public function testTheCaseInsensitiveLookupFollowsTheEngine()
    {
        $base = "$this->t-Mise à jour";
        $spellings = [
            'base' => $base,
            'upper' => mb_strtoupper($base),
            'accent' => "$this->t-Mise a jour",
            'nbsp' => "$this->t-Mise\u{00A0}à jour",
            'trailing' => "$base ",
        ];
        $ids = $this->intern(array_values($spellings));
        $folded = $this->mysql ? array_keys($spellings) : ['base', 'upper'];
        $expected = [];
        foreach ($folded as $name) {
            $expected[] = $ids[$spellings[$name]];
        }
        $this->assertSame($this->sorted($expected), $this->sorted($this->values->resolveCi([$base])[$base]));
    }

    public function testLikeIgnoresCaseAndOnlyMysqlAccents()
    {
        $value = "$this->t-Mise à jour requise";
        $id = $this->intern([$value])[$value];
        $found = $this->values->resolveLike('%' . strtoupper($this->t) . '-MISE À%', self::LIMIT);
        $this->assertSame([$id], $this->sorted($found['ids']));
        $this->assertFalse($found['overflow']);
        $accent = $this->values->resolveLike("%$this->t-mise a jour%", self::LIMIT);
        $this->assertSame($this->mysql ? [$id] : [], $this->sorted($accent['ids']));
    }

    public function testValueSearchStartsAtAWordOnMysqlAndAnywhereOnPostgres()
    {
        $word = "{$this->t}needle";
        $start = "path/$word.example";
        $inside = "zz$word.example";
        $ids = $this->intern([$start, $inside]);
        $found = $this->values->resolveSearch(strtoupper($word), self::LIMIT);
        $expected = $this->mysql ? [$ids[$start]] : [$ids[$start], $ids[$inside]];
        $this->assertSame($this->sorted($expected), $this->sorted($found['ids']));
    }

    public function testTheEmptyValueRule()
    {
        $this->assertSame(
            ['' => true, ' ' => $this->mysql, 'x' => false],
            $this->values->matchesEmpty(['', ' ', 'x'])
        );
        $this->assertSame(['%' => true, '_' => false], $this->values->matchesEmpty(['%', '_'], true));
    }

    public function testTheIpFacetFindsRangesAndMembersOnBinaryColumns()
    {
        $net = sprintf('100.%d.%d', random_int(64, 127), random_int(0, 255));
        $cidr = "$net.0/24";
        $address = "$net.7";
        $outside = sprintf('100.%d.%d.7', random_int(64, 127), random_int(0, 255));
        $ids = $this->intern([$cidr, $address]);
        $facets = $this->values->facets();
        $probe = ValueFacetTool::ipRange($address)[0];
        $found = $facets->containing(['a' => $probe, 'b' => ValueFacetTool::ipRange($outside)[0]]);
        $this->assertTrue($found['a'][$ids[$cidr]], 'the range holding the address');
        $this->assertFalse($found['a'][$ids[$address]], 'the address itself');
        $this->assertArrayNotHasKey($ids[$cidr], $found['b']);
        $members = array_column($this->exec($facets->membersQuery(ValueFacetTool::ipRange($cidr))), 'value_id');
        $this->assertContains($ids[$address], array_map('intval', $members));
        $this->assertNotContains($ids[$cidr], array_map('intval', $members));
    }

    public function testAnUnheldValueIsDeletedWithItsFacetRow()
    {
        $net = sprintf('100.%d.%d.9', random_int(64, 127), random_int(0, 255));
        $ids = $this->intern([$net, "$this->t-orphan"]);
        foreach ($ids as $value => $id) {
            $this->assertSame([], $this->values->holders($id));
            $this->assertTrue($this->values->deleteUnheld($id), (string)$value);
            $this->assertSame([], $this->values->fetchValues([$id]));
        }
        $left = $this->exec(sprintf('SELECT COUNT(*) AS n FROM value_ip_ranges WHERE value_id = %d', $ids[$net]));
        $this->assertSame(0, (int)$left[0]['n']);
    }

    public function testAFindMatchesThroughTheRewriter()
    {
        $event = (int)$this->exec('SELECT MIN(id) AS id FROM events')[0]['id'];
        $this->assertGreaterThan(0, $event);
        $value = "$this->t-Rewritten.example";
        $this->db->begin();
        try {
            $this->attribute->create();
            $this->assertNotFalse($this->attribute->save(['Attribute' => [
                'event_id' => $event,
                'category' => 'Network activity',
                'type' => 'domain',
                'value' => $value,
                'distribution' => 5,
                'to_ids' => 0,
            ]]), json_encode($this->attribute->validationErrors));
            $id = (int)$this->attribute->id;
            $find = function ($conditions) use ($event) {
                return array_map('intval', $this->attribute->find('column', [
                    'fields' => ['Attribute.id'],
                    'conditions' => ['Attribute.event_id' => $event] + $conditions,
                ]));
            };
            $stored = strtolower($value);
            $this->assertSame([$id], $find(['Attribute.value' => strtoupper($value)]), 'the save keeps a domain lower case; the find folds case');
            $this->assertSame([$id], $find(['Attribute.value LIKE' => strtoupper($this->t) . '-REWRITTEN%']));
            $this->assertSame([], $find(['Attribute.value !=' => $stored, 'Attribute.id' => $id]));
            $row = $this->attribute->find('first', ['recursive' => -1, 'conditions' => ['Attribute.id' => $id], 'fields' => ['Attribute.value']]);
            $this->assertSame($stored, $row['Attribute']['value']);
            // A raw statement: its row nests differently on the two drivers
            $valueId = $this->values->idsOf([$stored])[$stored];
            $admin = ClassRegistry::init('User')->getAuthUser(1);
            $this->assertSame([$valueId], $this->attribute->visibleValueIds($admin, [$valueId], 10));
        } finally {
            $this->db->rollback();
        }
    }
}
