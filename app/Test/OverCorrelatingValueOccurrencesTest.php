<?php
/**
 * OverCorrelatingValue::generateOccurrences() unit test.
 *
 * generateOccurrences() used to run one COUNT query per over correlating value, it now sums one
 * match expression per value over a single pass, a chunk of values at a time. What is pinned down
 * here is that a) the number of attribute queries follows the number of chunks and not the number
 * of values, b) every value still receives the count of its own match expression and c) that match
 * expression is the condition the per value count queries were built from.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB - the convention used by every other test under
 * app/Test/ (see CollectionPullTest / PewPewMapWidgetTest). The framework classes the model
 * touches are stubbed first (guarded with class_exists so a full suite run shares whichever file
 * loaded them first), then the real model is loaded.
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

if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new OverCorrelatingValueFakeAttribute();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $id = false;
        public $data = array();

        public function create($data = array())
        {
            $this->id = false;
        }

        public function find($type = 'first', $query = array())
        {
            return array();
        }

        public function save($data = null, $validate = true, $fieldList = array())
        {
            return true;
        }

        public function saveMany($data = null, $options = array())
        {
            return true;
        }
    }
}

if (!class_exists('MispAttribute', false)) {
    /** Only the two type lists the counting conditions are built from. */
    class MispAttribute
    {
        const NON_CORRELATING_TYPES = array('comment', 'port');

        const PRIMARY_ONLY_CORRELATING_TYPES = array('ip-src|port', 'hostname|port');
    }
}

if (!class_exists('OverCorrelatingValueFakeDataSource', false)) {
    /** Quotes and names like the MySQL datasource does, without a connection. */
    class OverCorrelatingValueFakeDataSource
    {
        public function value($data, $column = null)
        {
            return "'" . str_replace(array('\\', "'"), array('\\\\', "\\'"), $data) . "'";
        }

        public function fullTableName($model)
        {
            return '`' . $model->table . '`';
        }
    }
}

if (!class_exists('OverCorrelatingValueFakeAttribute', false)) {
    /** MispAttribute stand-in: records what it is asked and replays canned rows. */
    class OverCorrelatingValueFakeAttribute
    {
        public $table = 'attributes';
        public $Event;
        public $responses = array();
        public $queries = array();
        public $rows = array();
        public $findCalls = 0;

        public function __construct()
        {
            $this->Event = new OverCorrelatingValueFakeEvent();
        }

        public function find($type = 'first', $query = array())
        {
            $this->findCalls++;
            return empty($this->responses) ? array() : array_shift($this->responses);
        }

        public function getDataSource()
        {
            return new OverCorrelatingValueFakeDataSource();
        }

        public function query($sql, $cache = true)
        {
            $this->queries[] = $sql;
            return empty($this->rows) ? array() : array_shift($this->rows);
        }
    }
}

if (!class_exists('OverCorrelatingValueFakeEvent', false)) {
    class OverCorrelatingValueFakeEvent
    {
        public $table = 'events';
    }
}

require_once __DIR__ . '/../Model/OverCorrelatingValue.php';

use PHPUnit\Framework\TestCase;

/** The model with its own storage replaced: canned rows in, saved rows recorded. */
class OverCorrelatingValueOccurrencesTestable extends OverCorrelatingValue
{
    public $rows = array();
    public $saved = null;
    public $saveCalls = 0;

    public function find($type = 'first', $query = array())
    {
        return $this->rows;
    }

    public function saveMany($data = null, $options = array())
    {
        $this->saveCalls++;
        $this->saved = $data;
        return true;
    }
}

class OverCorrelatingValueOccurrencesTest extends TestCase
{
    /** @var OverCorrelatingValueOccurrencesTestable */
    private $overCorrelatingValue;

    /** @var OverCorrelatingValueFakeAttribute */
    private $attribute;

    protected function setUp(): void
    {
        ClassRegistry::reset();
        $this->attribute = new OverCorrelatingValueFakeAttribute();
        ClassRegistry::$instances['MispAttribute'] = $this->attribute;
        $this->overCorrelatingValue = new OverCorrelatingValueOccurrencesTestable();
    }

    /** @return array over correlating values, shaped like find('all') returns them */
    private function overCorrelations($count)
    {
        $overCorrelations = array();
        for ($i = 0; $i < $count; $i++) {
            $overCorrelations[] = array('OverCorrelatingValue' => array(
                'id' => $i + 1,
                'value' => 'value' . $i,
                'occurrence' => 0,
            ));
        }
        return $overCorrelations;
    }

    /** @return array a query result holding the sum of every value of one chunk */
    private function counts($from, $to)
    {
        $row = array();
        for ($i = $from; $i < $to; $i++) {
            $row['occurrence_' . $i] = (string)($i + 1);
        }
        return array(array($row));
    }

    public function testCountsAChunkOfValuesPerQuery()
    {
        $this->overCorrelatingValue->rows = $this->overCorrelations(150);
        $this->attribute->rows = array($this->counts(0, 100), $this->counts(100, 150));

        $this->overCorrelatingValue->generateOccurrences();

        $this->assertCount(2, $this->attribute->queries);
        $this->assertSame(0, $this->attribute->findCalls);
        $this->assertSame(1, $this->overCorrelatingValue->saveCalls);
    }

    public function testEveryValueKeepsItsOwnCount()
    {
        $this->overCorrelatingValue->rows = $this->overCorrelations(150);
        $this->attribute->rows = array($this->counts(0, 100), $this->counts(100, 150));

        $this->overCorrelatingValue->generateOccurrences();

        $saved = $this->overCorrelatingValue->saved;
        $this->assertCount(150, $saved);
        $this->assertSame(1, $saved[0]['OverCorrelatingValue']['occurrence']);
        $this->assertSame(100, $saved[99]['OverCorrelatingValue']['occurrence']);
        $this->assertSame(101, $saved[100]['OverCorrelatingValue']['occurrence']);
        $this->assertSame(150, $saved[149]['OverCorrelatingValue']['occurrence']);
        $this->assertSame(150, $saved[149]['OverCorrelatingValue']['id']);
    }

    public function testValueWithoutAMatchIsCountedAsZero()
    {
        $this->overCorrelatingValue->rows = $this->overCorrelations(1);
        $this->attribute->rows = array(array(array(array('occurrence_0' => null))));

        $this->overCorrelatingValue->generateOccurrences();

        $saved = $this->overCorrelatingValue->saved;
        $this->assertSame(0, $saved[0]['OverCorrelatingValue']['occurrence']);
    }

    public function testMatchesWhatTheCountQueriesMatched()
    {
        $overCorrelations = $this->overCorrelations(1);
        $overCorrelations[0]['OverCorrelatingValue']['value'] = "o'brien";
        $this->overCorrelatingValue->rows = $overCorrelations;
        $this->attribute->rows = array($this->counts(0, 1));

        $this->overCorrelatingValue->generateOccurrences();

        $primaryOnly = "'" . implode("', '", MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES) . "'";
        $match = "Attribute.value1 LIKE 'o\\'brien%'"
            . " OR (Attribute.value2 LIKE 'o\\'brien%'"
            . " AND Attribute.type NOT IN ($primaryOnly))";
        $query = $this->attribute->queries[0];
        $this->assertStringContainsString("SUM($match) AS occurrence_0", $query);
        $this->assertStringContainsString("WHERE (($match))", $query);
        $this->assertStringContainsString(
            'FROM `attributes` AS Attribute INNER JOIN `events` AS Event ON Event.id = Attribute.event_id',
            $query
        );
        $this->assertStringContainsString(
            "AND Attribute.type NOT IN ('" . implode("', '", MispAttribute::NON_CORRELATING_TYPES) . "')",
            $query
        );
        $this->assertStringContainsString('AND Attribute.disable_correlation = 0', $query);
        $this->assertStringContainsString('AND Event.disable_correlation = 0', $query);
        $this->assertStringContainsString('AND Attribute.deleted = 0', $query);
    }
}
