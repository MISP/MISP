<?php
/**
 * The value texts the collection members migration gives back to the
 * members it finds. The schema changes need a database; the backfill runs
 * here over fakes.
 */

require_once __DIR__ . '/MigrationLedgerStubs.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261118_080050_collection_members_outside_misp.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                throw new RuntimeException("No fake registered for $name.");
            }
            return self::$instances[$name];
        }
    }
}

/** collection_elements: the rows the backfill reads and the saves it makes. */
class MembersMigrationElements
{
    public $rows = array();
    public $saves = array();
    public $schemaReloads = 0;
    public $finds = 0;
    public $failOn = null;

    public function schema($reload = false)
    {
        $this->schemaReloads += $reload ? 1 : 0;
    }

    public function find($type, $query)
    {
        $this->finds++;
        $after = $query['conditions']['CollectionElement.id >'];
        $out = array();
        ksort($this->rows);
        foreach ($this->rows as $id => $row) {
            if ($id > $after && $row['element_sha256'] !== null && $row['element_value'] === null) {
                $out[$id] = $row['element_sha256'];
            }
        }
        return array_slice($out, 0, $query['limit'], true);
    }

    public function create()
    {
    }

    public function save($data, $options)
    {
        $this->saves[] = array($data, $options);
        if ($this->failOn === $data['CollectionElement']['id']) {
            return false;
        }
        $this->rows[$data['CollectionElement']['id']]['element_value'] = $data['CollectionElement']['element_value'];
        return $data;
    }
}

class MembersMigrationValues
{
    public $ids = array();
    public $texts = array();
    public $asked = array();

    public function findBySha256(array $hexes)
    {
        $this->asked[] = $hexes;
        return array_intersect_key($this->ids, array_flip($hexes));
    }

    public function fetchValues(array $ids)
    {
        return array_intersect_key($this->texts, array_flip($ids));
    }
}

class MembersMigrationAttribute
{
    public $values;

    public function loadAttributeValue()
    {
        return $this->values;
    }
}

class CollectionMembersOutsideMispMigrationTest extends TestCase
{
    const MIGRATION = 'Migration_20261118_080050_collection_members_outside_misp';

    /** @var MembersMigrationElements */
    private $elements;
    /** @var MembersMigrationValues */
    private $values;

    protected function setUp(): void
    {
        $this->elements = new MembersMigrationElements();
        $this->values = new MembersMigrationValues();
        $attribute = new MembersMigrationAttribute();
        $attribute->values = $this->values;
        ClassRegistry::$instances['CollectionElement'] = $this->elements;
        ClassRegistry::$instances['MispAttribute'] = $attribute;
    }

    protected function tearDown(): void
    {
        unset(ClassRegistry::$instances['CollectionElement'], ClassRegistry::$instances['MispAttribute']);
    }

    private static function row($hex, $text = null)
    {
        return array('element_sha256' => $hex, 'element_value' => $text);
    }

    private function backfill()
    {
        $class = self::MIGRATION;
        return (new $class())->afterUp();
    }

    public function testAMemberTakesItsTextFromTheValueTable()
    {
        $hex = hash('sha256', 'evil.example');
        $this->elements->rows = array(4 => self::row(strtoupper($hex)));
        $this->values->ids = array($hex => 90);
        $this->values->texts = array(90 => 'evil.example');

        $this->assertTrue($this->backfill());

        $this->assertSame('evil.example', $this->elements->rows[4]['element_value']);
        $this->assertSame(array(array('CollectionElement' => array('id' => 4, 'element_value' => 'evil.example')), array('validate' => false, 'callbacks' => false, 'fieldList' => array('element_value'))), $this->elements->saves[0]);
        $this->assertSame(1, $this->elements->schemaReloads, 'the new column is known before it is written');
        $this->assertSame(array(array($hex)), $this->values->asked, 'looked up in lower case');
    }

    public function testAMemberWhoseValueIsGoneStaysEmpty()
    {
        $kept = hash('sha256', 'kept.example');
        $gone = hash('sha256', 'gone.example');
        $this->elements->rows = array(1 => self::row($gone), 2 => self::row($kept));
        $this->values->ids = array($kept => 91, $gone => 92);
        $this->values->texts = array(91 => 'kept.example');

        $this->assertTrue($this->backfill());

        $this->assertNull($this->elements->rows[1]['element_value']);
        $this->assertSame('kept.example', $this->elements->rows[2]['element_value']);
        $this->assertCount(1, $this->elements->saves);
    }

    public function testNothingIsReadOrWrittenForMembersThatAreNotValues()
    {
        $this->elements->rows = array(1 => self::row(null), 2 => self::row(hash('sha256', 'a'), 'already.kept'));

        $this->assertTrue($this->backfill());

        $this->assertSame(array(), $this->elements->saves);
        $this->assertSame(array(), $this->values->asked);
        $this->assertSame('already.kept', $this->elements->rows[2]['element_value']);
    }

    public function testEveryMemberIsReachedPastTheBatchSize()
    {
        for ($i = 1; $i <= 1203; $i++) {
            $hex = hash('sha256', 'v' . $i);
            $this->elements->rows[$i] = self::row($hex);
            $this->values->ids[$hex] = $i;
            $this->values->texts[$i] = 'v' . $i;
        }

        $this->assertTrue($this->backfill());

        $this->assertCount(1203, $this->elements->saves);
        $this->assertSame('v1203', $this->elements->rows[1203]['element_value']);
        $this->assertSame(3, $this->elements->finds, 'in batches of 500');
    }

    public function testASaveThatFailsFailsTheMigration()
    {
        $hex = hash('sha256', 'evil.example');
        $this->elements->rows = array(4 => self::row($hex));
        $this->values->ids = array($hex => 90);
        $this->values->texts = array(90 => 'evil.example');
        $this->elements->failOn = 4;

        $this->assertFalse($this->backfill());
    }
}
