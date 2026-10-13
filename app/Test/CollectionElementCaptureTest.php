<?php
/**
 * CollectionElement::captureElements() against an in-memory table.
 *
 * Pure PHPUnit, no CakePHP bootstrap and no database, as the other tests
 * under app/Test/. The table enforces collection_elements' two unique keys,
 * `uuid` and (`element_uuid`, `collection_id`), comparing case-insensitively
 * as their ascii_general_ci columns do, and throws the PDOException MySQL
 * would on a duplicate.
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

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $alias = 'Collection';
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

require_once __DIR__ . '/../Model/CollectionElement.php';

use PHPUnit\Framework\TestCase;

class CaptureTestCollectionElement extends CollectionElement
{
    /** @var array<int, array> rows by id */
    public $rows = array();
    public $logged = array();
    private $nextId = 1;

    public function seed(array $row)
    {
        $row['id'] = $this->nextId++;
        $this->rows[$row['id']] = $row + array('description' => null);
        return $row['id'];
    }

    public function find($type, $options = array())
    {
        $collectionId = $options['conditions']['CollectionElement.collection_id'];
        $out = array();
        foreach ($this->rows as $row) {
            if ($row['collection_id'] == $collectionId) {
                $out[] = array('CollectionElement' => $row);
            }
        }
        return $out;
    }

    public function create($data = array())
    {
        $this->id = false;
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $row = isset($data['CollectionElement']) ? $data['CollectionElement'] : $data;
        $id = isset($row['id']) ? $row['id'] : null;
        foreach ($this->rows as $other) {
            if ($other['id'] === $id) {
                continue;
            }
            if (strcasecmp($other['uuid'], $row['uuid']) === 0
                || (strcasecmp($other['element_uuid'], (string)$row['element_uuid']) === 0
                    && $other['collection_id'] == $row['collection_id'])
            ) {
                throw new PDOException('SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry');
            }
        }
        if ($id === null) {
            $id = $this->nextId++;
            $row['id'] = $id;
        }
        $this->rows[$id] = $row + array('description' => null);
        $this->id = $id;
        return true;
    }

    public function delete($id = null, $cascade = true)
    {
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
    const COLLECTION = 5;
    const EVENT_A = '4f74bdee-3c2e-4211-b400-b6dcd6ef1400';
    const EVENT_B = '9c2ec5f6-afa1-4753-891b-d130b4539648';
    const CLUSTER = '1c4e5d32-1fe9-4116-9d9d-59e3925bd6a2';
    const ROW_A = '280f9534-6006-48ca-b172-7f8361cdc76d';
    const ROW_B = '2bec48f9-bcac-42f0-b9b5-a9adc2259267';

    /** @var CaptureTestCollectionElement */
    private $model;
    private $idA;
    private $idB;

    protected function setUp(): void
    {
        $this->model = new CaptureTestCollectionElement();
        $this->idA = $this->model->seed(array(
            'uuid' => self::ROW_A, 'element_uuid' => self::EVENT_A,
            'element_type' => 'Event', 'collection_id' => self::COLLECTION,
            'description' => 'first',
        ));
        $this->idB = $this->model->seed(array(
            'uuid' => self::ROW_B, 'element_uuid' => self::EVENT_B,
            'element_type' => 'Event', 'collection_id' => self::COLLECTION,
        ));
    }

    private function capture(array $elements)
    {
        return $this->model->captureElements(array('Collection' => array(
            'id' => self::COLLECTION, 'CollectionElement' => $elements,
        )));
    }

    private function rowsByElement()
    {
        $out = array();
        foreach ($this->model->rows as $row) {
            $out[$row['element_uuid']] = $row;
        }
        ksort($out);
        return $out;
    }

    public function testElementsResentWithoutRowUuidsAreKept()
    {
        $this->capture(array(
            array('element_uuid' => self::EVENT_A, 'element_type' => 'Event', 'description' => 'edited'),
            array('element_uuid' => self::EVENT_B, 'element_type' => 'Event'),
        ));
        $rows = $this->rowsByElement();
        $this->assertSame(array(self::EVENT_A, self::EVENT_B), array_keys($rows));
        $this->assertSame($this->idA, $rows[self::EVENT_A]['id']);
        $this->assertSame(self::ROW_A, $rows[self::EVENT_A]['uuid']);
        $this->assertSame('edited', $rows[self::EVENT_A]['description']);
        $this->assertSame($this->idB, $rows[self::EVENT_B]['id']);
        $this->assertSame(array(), $this->model->logged);
    }

    public function testAnElementUnderAnotherRowUuidIsTheRowAlreadyHeld()
    {
        $this->capture(array(
            array('uuid' => '6d1f3c2e-8a4b-4c7d-9e0f-1a2b3c4d5e6f', 'element_uuid' => self::EVENT_A,
                'element_type' => 'Event', 'description' => 're-added'),
            array('uuid' => self::ROW_B, 'element_uuid' => self::EVENT_B, 'element_type' => 'Event'),
        ));
        $rows = $this->rowsByElement();
        $this->assertCount(2, $rows);
        $this->assertSame(self::ROW_A, $rows[self::EVENT_A]['uuid']);
        $this->assertSame('re-added', $rows[self::EVENT_A]['description']);
        $this->assertSame(array(), $this->model->logged);
    }

    public function testElementUuidsCompareAsTheColumnDoes()
    {
        $this->capture(array(
            array('element_uuid' => strtoupper(self::EVENT_A), 'element_type' => 'Event'),
            array('uuid' => strtoupper(self::ROW_B), 'element_uuid' => self::EVENT_B, 'element_type' => 'Event'),
        ));
        $rows = $this->rowsByElement();
        $this->assertSame(array($this->idA, $this->idB), array($rows[self::EVENT_A]['id'], $rows[self::EVENT_B]['id']));
        $this->assertSame(array(), $this->model->logged);
    }

    public function testElementsNoLongerSentAreRemovedAndNewOnesAdded()
    {
        $this->capture(array(
            array('element_uuid' => self::EVENT_A, 'element_type' => 'Event'),
            array('element_uuid' => self::CLUSTER, 'element_type' => 'GalaxyCluster'),
        ));
        $rows = $this->rowsByElement();
        $this->assertSame(array(self::CLUSTER, self::EVENT_A), array_keys($rows));
        $this->assertSame($this->idA, $rows[self::EVENT_A]['id']);
        $this->assertSame(self::COLLECTION, $rows[self::CLUSTER]['collection_id']);
    }

    public function testTheSameElementTwiceKeepsOneRow()
    {
        $this->capture(array(
            array('uuid' => self::ROW_A, 'element_uuid' => self::EVENT_A, 'element_type' => 'Event'),
            array('element_uuid' => self::EVENT_A, 'element_type' => 'Event'),
        ));
        $rows = $this->rowsByElement();
        $this->assertSame(array(self::EVENT_A), array_keys($rows));
        $this->assertSame($this->idA, $rows[self::EVENT_A]['id']);
        $this->assertSame(array(), $this->model->logged);
    }

    public function testCapturedCorpusIsReturned()
    {
        $data = $this->capture(array(
            array('element_uuid' => self::EVENT_B, 'element_type' => 'Event'),
        ));
        $this->assertSame(array(self::ROW_B), array_column($data['Collection']['CollectionElement'], 'uuid'));
    }
}
