<?php
/**
 * MispAttribute::fetchRelated() unit tests.
 *
 * fetchRelated() used to run one ACL scoped fetchAttributes() call per candidate,
 * so resolving a freetext import of N values cost N queries. It now fetches the
 * related attributes for a chunk of candidates with a single query and
 * distributes the rows, falling back to the query per candidate whenever the
 * batch cannot be distributed faithfully - the row cap was reached, or the
 * database matched a row that cannot be attributed back to a candidate.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB - the convention used by every other
 * test under app/Test/ (see UserCanSeeEmailsTest). The framework classes are
 * stubbed with class_exists() guards, so in a full suite run whichever file
 * loads them first wins for everyone.
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
        public $useTable = null;

        public function __construct($id = false, $table = null, $ds = null)
        {
        }
    }
}

if (!function_exists('__')) {
    function __($string)
    {
        $args = func_get_args();
        $format = array_shift($args);
        return empty($args) ? $format : vsprintf($format, $args);
    }
}

require_once __DIR__ . '/../Model/MispAttribute.php';

use PHPUnit\Framework\TestCase;

/**
 * MispAttribute double. fetchAttributes() is replaced by a recorder that matches
 * the injected rows case insensitively, the way the utf8mb3_unicode_ci
 * value1/value2 columns do, and honours the limit it is given.
 * getCompositeTypes() is fixed, as the real one walks the type definitions, and
 * the constructor is skipped, as the AppModel stub that wins in a full suite run
 * may not have one.
 */
class FetchRelatedTestableAttribute extends MispAttribute
{
    /** @var array Options of every fetchAttributes() call, in order. */
    public $fetchAttributesCalls = array();

    /** @var array Rows the fake query can match. */
    public $injectedRows = array();

    /** @var array Rows the fake query always returns, whatever the conditions. */
    public $unattributableRows = array();

    public function __construct($id = false, $table = null, $ds = null)
    {
    }

    public function getCompositeTypes()
    {
        return array('filename|md5', 'ip-src|port');
    }

    public function fetchAttributes(array $user, array $options = [], &$result_count = false, $real_count = false, &$skipped_item_count = false)
    {
        $this->fetchAttributesCalls[] = $options;
        $wanted = array();
        foreach ($options['conditions']['OR'] as $values) {
            foreach ((array)$values as $value) {
                $wanted[mb_strtolower($value)] = true;
            }
        }
        $matched = array();
        foreach (array_merge($this->injectedRows, $this->unattributableRows) as $row) {
            $isUnattributable = in_array($row, $this->unattributableRows, true);
            $value1 = mb_strtolower($row['Attribute']['value1']);
            $value2 = mb_strtolower($row['Attribute']['value2']);
            if ($isUnattributable || isset($wanted[$value1]) || isset($wanted[$value2])) {
                $matched[] = $row;
                if (count($matched) >= $options['limit']) {
                    break;
                }
            }
        }
        return $matched;
    }
}

class MispAttributeFetchRelatedTest extends TestCase
{
    private $attribute;

    protected function setUp(): void
    {
        $this->attribute = new FetchRelatedTestableAttribute();
    }

    public function testBatchesEveryCandidateIntoOneQuery()
    {
        $resultArray = array();
        for ($i = 0; $i < 50; $i++) {
            $resultArray[] = array('default_type' => 'ip-src', 'value' => '10.0.0.' . $i);
            $this->attribute->injectedRows[] = $this->row($i, '10.0.0.' . $i);
        }
        $this->attribute->fetchRelated($this->user(), $resultArray);

        $this->assertCount(1, $this->attribute->fetchAttributesCalls);
        foreach ($resultArray as $i => $result) {
            $this->assertCount(1, $result['related']);
            $this->assertSame('10.0.0.' . $i, $result['related'][0]['Attribute']['value1']);
        }
    }

    public function testKeepsTheCorrelationConditions()
    {
        $resultArray = array(array('default_type' => 'ip-src', 'value' => '1.2.3.4'));
        $this->attribute->fetchRelated($this->user(), $resultArray);

        $options = $this->attribute->fetchAttributesCalls[0];
        $this->assertSame(array('1.2.3.4'), $options['conditions']['OR']['Attribute.value1']);
        $this->assertSame(array('1.2.3.4'), $options['conditions']['OR']['Attribute.value2']);
        $this->assertSame(MispAttribute::NON_CORRELATING_TYPES, $options['conditions']['NOT']['Attribute.type']);
        $this->assertSame(0, $options['conditions']['Attribute.disable_correlation']);
        $this->assertSame(1, $options['flatten']);
        $this->assertSame(array('AttributeTag' => false), $options['contain']);
        $this->assertFalse($options['order']);
    }

    public function testAppliesThePerCandidateLimit()
    {
        for ($i = 0; $i < 15; $i++) {
            $this->attribute->injectedRows[] = $this->row($i, 'hot.example.com');
        }
        $this->attribute->injectedRows[] = $this->row(99, 'cold.example.com');
        $resultArray = array(
            array('default_type' => 'hostname', 'value' => 'hot.example.com'),
            array('default_type' => 'hostname', 'value' => 'cold.example.com'),
        );
        $this->attribute->fetchRelated($this->user(), $resultArray);

        $this->assertCount(1, $this->attribute->fetchAttributesCalls);
        $this->assertCount(11, $resultArray[0]['related']);
        $this->assertCount(1, $resultArray[1]['related']);
    }

    public function testRowMatchingBothValuesOfACompositeIsReturnedOnce()
    {
        $this->attribute->injectedRows[] = $this->row(1, 'evil.exe', 'd41d8cd98f00b204e9800998ecf8427e');
        $resultArray = array(
            array('default_type' => 'filename|md5', 'value' => 'evil.exe|d41d8cd98f00b204e9800998ecf8427e'),
        );
        $this->attribute->fetchRelated($this->user(), $resultArray);

        $this->assertCount(1, $resultArray[0]['related']);
        $this->assertSame(1, $resultArray[0]['related'][0]['Attribute']['id']);
    }

    public function testPrimaryOnlyCompositeIgnoresTheSecondValue()
    {
        $this->attribute->injectedRows[] = $this->row(1, '1.2.3.4');
        $this->attribute->injectedRows[] = $this->row(2, '80');
        $resultArray = array(array('default_type' => 'ip-src|port', 'value' => '1.2.3.4|80'));
        $this->attribute->fetchRelated($this->user(), $resultArray);

        $this->assertCount(1, $resultArray[0]['related']);
        $this->assertSame(1, $resultArray[0]['related'][0]['Attribute']['id']);
    }

    public function testDistributesCaseInsensitively()
    {
        $this->attribute->injectedRows[] = $this->row(1, 'D41D8CD98F00B204E9800998ECF8427E');
        $resultArray = array(
            array('default_type' => 'md5', 'value' => 'd41d8cd98f00b204e9800998ecf8427e'),
        );
        $this->attribute->fetchRelated($this->user(), $resultArray);

        $this->assertCount(1, $this->attribute->fetchAttributesCalls);
        $this->assertCount(1, $resultArray[0]['related']);
    }

    public function testFallsBackWhenTheBatchHitsTheRowLimit()
    {
        for ($i = 0; $i < 30; $i++) {
            $this->attribute->injectedRows[] = $this->row($i, 'hot.example.com');
        }
        $resultArray = array(
            array('default_type' => 'hostname', 'value' => 'hot.example.com'),
            array('default_type' => 'hostname', 'value' => 'hot.example.com'),
        );
        $this->attribute->fetchRelated($this->user(), $resultArray);

        $this->assertCount(3, $this->attribute->fetchAttributesCalls);
        $this->assertCount(11, $resultArray[0]['related']);
        $this->assertCount(11, $resultArray[1]['related']);
    }

    public function testFallsBackWhenARowCannotBeAttributed()
    {
        $this->attribute->injectedRows[] = $this->row(1, 'aaa.example.com');
        $this->attribute->unattributableRows[] = $this->row(2, 'accent-folded-by-the-database');
        $resultArray = array(
            array('default_type' => 'hostname', 'value' => 'aaa.example.com'),
            array('default_type' => 'hostname', 'value' => 'bbb.example.com'),
        );
        $this->attribute->fetchRelated($this->user(), $resultArray);

        $this->assertCount(3, $this->attribute->fetchAttributesCalls);
        $this->assertSame(11, $this->attribute->fetchAttributesCalls[1]['limit']);
    }

    public function testEmptyResultArrayIsNotQueried()
    {
        $resultArray = array();
        $this->attribute->fetchRelated($this->user(), $resultArray);

        $this->assertSame(array(), $this->attribute->fetchAttributesCalls);
    }

    private function user()
    {
        return array('id' => 1, 'org_id' => 1, 'Role' => array('perm_site_admin' => 0));
    }

    private function row($id, $value1, $value2 = '')
    {
        return array(
            'Attribute' => array(
                'id' => $id,
                'uuid' => sprintf('00000000-0000-4000-8000-%012d', $id),
                'type' => 'hostname',
                'category' => 'Network activity',
                'value1' => $value1,
                'value2' => $value2,
                'value' => $value2 === '' ? $value1 : $value1 . '|' . $value2,
                'comment' => '',
            ),
            'Event' => array('id' => 1, 'info' => 'test'),
        );
    }
}
