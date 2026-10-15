<?php
/**
 * CollectionElement::captureElements(): a collection received over REST or
 * sync is authoritative for its elements. An element resent without its own
 * uuid, or under a uuid this instance does not know, must keep the stored
 * row for the same target instead of colliding with it and culling it.
 *
 * Pure PHPUnit: the probe keeps the table in memory and enforces its unique
 * keys, so a duplicate insert fails as it would on MySQL.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $id = false;
        public $data = array();
        public $validationErrors = array();

        public function create($data = array())
        {
            $this->id = false;
        }

        public function save($data = null, $validate = true, $fieldList = array())
        {
            return true;
        }

        public function find($type, $options = array())
        {
            return array();
        }
    }
}
if (!class_exists('CakeText', false)) {
    class CakeText
    {
        private static $counter = 0;

        public static function uuid()
        {
            self::$counter++;
            return sprintf('00000000-0000-4000-8000-%012d', self::$counter);
        }
    }
}

require_once __DIR__ . '/../Model/CollectionElement.php';

use PHPUnit\Framework\TestCase;

class CollectionElementCaptureProbe extends CollectionElement
{
    /** @var array id => row */
    public $rows = [];

    /** @var string[] */
    public $logged = [];

    public $deleted = [];

    private $nextId = 1;

    public function find($type = 'first', $options = array())
    {
        $collectionId = $options['conditions']['CollectionElement.collection_id'];
        $out = [];
        foreach ($this->rows as $row) {
            if ($row['collection_id'] == $collectionId) {
                $out[] = ['CollectionElement' => $row];
            }
        }
        return $out;
    }

    public function create($data = array(), $filterKey = false)
    {
        $this->id = false;
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $row = $data['CollectionElement'] ?? $data;
        $id = $row['id'] ?? null;
        $stored = $id ? $this->rows[$id] : [];
        $row = array_merge($stored, $row);
        foreach ($this->rows as $otherId => $other) {
            if ($otherId == $id) {
                continue;
            }
            $sameTarget = false;
            foreach (['element_uuid', 'element_sha256'] as $column) {
                $sameTarget = $sameTarget || (!empty($row[$column]) && $other['collection_id'] == $row['collection_id']
                    && strtolower($other[$column] ?? '') === strtolower($row[$column]));
            }
            if ($other['uuid'] === $row['uuid'] || $sameTarget) {
                $e = new PDOException('SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry');
                $e->errorInfo = ['23000', 1062, 'Duplicate entry'];
                throw $e;
            }
        }
        if (!$id) {
            $row['id'] = $id = $this->nextId++;
        }
        $this->rows[$id] = $row;
        return ['CollectionElement' => $row];
    }

    public function delete($id = null, $cascade = true)
    {
        $this->deleted[] = $id;
        unset($this->rows[$id]);
        return true;
    }

    public function log($message, $type = LOG_ERR, $scope = null)
    {
        $this->logged[] = $message;
        return true;
    }
}

class CollectionElementCaptureTest extends TestCase
{
    const COLLECTION = 7;

    const EVENT = '5f0c1b3e-9a52-4c1e-8d43-0a8f1e2b7c11';

    const CLUSTER = '0b7a2c9d-3e4f-4a51-9b6c-7d8e9f0a1b22';

    const OTHER_EVENT = 'c3d4e5f6-0718-4293-a4b5-c6d7e8f90a33';

    const VALUE = '3cbad7bc936718f07fa8665bc64ce46986142bea60f86fd0c05cd2a4a8ea2bc4';

    /** @var CollectionElementCaptureProbe */
    private $elements;

    protected function setUp(): void
    {
        // The model constructor needs CakePHP; captureElements() needs none of it
        $this->elements = (new ReflectionClass('CollectionElementCaptureProbe'))->newInstanceWithoutConstructor();
        foreach ([['stored-event', 'Event', self::EVENT], ['stored-cluster', 'GalaxyCluster', self::CLUSTER]] as $i => $row) {
            $this->elements->rows[$i + 100] = [
                'id' => $i + 100,
                'uuid' => $row[0],
                'element_type' => $row[1],
                'element_uuid' => $row[2],
                'element_sha256' => null,
                'collection_id' => self::COLLECTION,
                'description' => 'stored',
            ];
        }
        $this->elements->rows[102] = [
            'id' => 102,
            'uuid' => 'stored-value',
            'element_type' => 'AttributeValue',
            'element_uuid' => null,
            'element_sha256' => self::VALUE,
            'collection_id' => self::COLLECTION,
            'description' => 'stored',
        ];
    }

    private function capture(array $elements)
    {
        $this->elements->captureElements(['Collection' => ['id' => self::COLLECTION, 'CollectionElement' => $elements]]);
        $byUuid = [];
        foreach ($this->elements->rows as $row) {
            $byUuid[$row['uuid']] = [$row['id'], $row['element_uuid'] ?? $row['element_sha256'], $row['description']];
        }
        ksort($byUuid);
        return $byUuid;
    }

    public function testElementsResentWithoutTheirUuidsAreKept()
    {
        $rows = $this->capture([
            ['element_type' => 'Event', 'element_uuid' => strtoupper(self::EVENT), 'description' => 'edited'],
            ['element_type' => 'GalaxyCluster', 'element_uuid' => self::CLUSTER],
            ['element_type' => 'AttributeValue', 'element_sha256' => strtoupper(self::VALUE)],
        ]);
        $this->assertSame([
            'stored-cluster' => [101, self::CLUSTER, 'stored'],
            'stored-event' => [100, self::EVENT, 'edited'],
            'stored-value' => [102, self::VALUE, 'stored'],
        ], $rows);
        $this->assertSame([], $this->elements->deleted);
        $this->assertSame([], $this->elements->logged);
    }

    public function testAnUnknownUuidOnAStoredTargetKeepsTheStoredRow()
    {
        $rows = $this->capture([
            ['uuid' => 'remote-event', 'element_type' => 'Event', 'element_uuid' => self::EVENT],
            ['uuid' => 'stored-cluster', 'element_type' => 'GalaxyCluster', 'element_uuid' => self::CLUSTER],
            ['uuid' => 'remote-value', 'element_type' => 'AttributeValue', 'element_sha256' => self::VALUE],
        ]);
        $this->assertSame(['stored-cluster', 'stored-event', 'stored-value'], array_keys($rows));
        $this->assertSame([], $this->elements->logged);
    }

    public function testAbsentElementsAreCulledAndNewOnesAdded()
    {
        $rows = $this->capture([
            ['element_type' => 'Event', 'element_uuid' => self::EVENT],
            ['element_type' => 'Event', 'element_uuid' => self::OTHER_EVENT, 'description' => 'new'],
        ]);
        $this->assertSame([100, self::EVENT, 'stored'], $rows['stored-event']);
        $this->assertArrayNotHasKey('stored-cluster', $rows);
        $this->assertArrayNotHasKey('stored-value', $rows);
        $this->assertSame([101, 102], $this->elements->deleted);
        $added = array_values(array_diff_key($rows, ['stored-event' => true]));
        $this->assertCount(1, $added);
        $this->assertSame([self::OTHER_EVENT, 'new'], array_slice($added[0], 1));
    }

    public function testOneStoredRowServesOneResentElement()
    {
        $this->capture([
            ['element_type' => 'Event', 'element_uuid' => self::EVENT],
            ['element_type' => 'Event', 'element_uuid' => self::EVENT],
            ['element_type' => 'GalaxyCluster', 'element_uuid' => self::CLUSTER],
            ['element_type' => 'AttributeValue', 'element_sha256' => self::VALUE],
        ]);
        $this->assertCount(3, $this->elements->rows);
        $this->assertSame([], $this->elements->logged, 'The second copy is dropped before it can collide.');
    }

    public function testRowUuidsCompareAsTheColumnDoes()
    {
        $rows = $this->capture([
            ['uuid' => 'STORED-EVENT', 'element_type' => 'Event', 'element_uuid' => self::EVENT],
        ]);
        $this->assertSame([100, self::EVENT, 'stored'], $rows['stored-event']);
        $this->assertSame([], $this->elements->logged);
    }

    public function testCapturedCorpusIsReturned()
    {
        $data = $this->elements->captureElements(['Collection' => ['id' => self::COLLECTION, 'CollectionElement' => [
            ['element_type' => 'GalaxyCluster', 'element_uuid' => self::CLUSTER],
        ]]]);
        $this->assertSame(['stored-cluster'], array_column($data['Collection']['CollectionElement'], 'uuid'));
    }
}
