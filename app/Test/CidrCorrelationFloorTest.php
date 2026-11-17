<?php
/**
 * CIDR correlation floor: Correlation::cidrCorrelation() collects nothing for
 * a CIDR broader than IPv4 /8 or IPv6 /16, and asks the facet for an address's
 * CIDRs with the floor applied. The facet is replaced by a test double.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

class CidrCorrelationFloorModelStub
{
}

class CidrCorrelationFloorDb
{
    public function name($name)
    {
        return '`' . str_replace('.', '`.`', $name) . '`';
    }
}

class CidrCorrelationFloorFacets
{
    public $hits = [];

    public $floorRequested = [];

    public function membersQuery(array $range)
    {
        return 'SELECT 1';
    }

    public function containing(array $addresses, $correlating = false)
    {
        $this->floorRequested[] = $correlating;
        return array_map(function () {
            return $this->hits;
        }, $addresses);
    }
}

class CidrCorrelationFloorTest extends TestCase
{
    private $registry = false;

    protected function setUp(): void
    {
        // Declared here and not at load: the other test files' stubs must win
        if (!class_exists('ClassRegistry', false)) {
            eval('class ClassRegistry { public static $instances = []; public static function init($name) { return self::$instances[$name]; } public static function reset() { self::$instances = []; } }');
        }
        if (!class_exists('AppModel', false)) {
            class_alias('CidrCorrelationFloorModelStub', 'AppModel');
        }
        require_once __DIR__ . '/../Lib/Tools/ValueFacetTool.php';
        require_once __DIR__ . '/../Model/Correlation.php';
        $this->registry = ClassRegistry::$instances['AttributeValue'] ?? false;
    }

    protected function tearDown(): void
    {
        if ($this->registry === false) {
            unset(ClassRegistry::$instances['AttributeValue']);
        } else {
            ClassRegistry::$instances['AttributeValue'] = $this->registry;
        }
    }

    private function cidr($type, $value, array $hits = [], &$facets = null)
    {
        $facets = new CidrCorrelationFloorFacets();
        $facets->hits = $hits;
        $attributeValue = new class($facets) {
            private $facets;

            public function __construct($facets)
            {
                $this->facets = $facets;
            }

            public function facets()
            {
                return $this->facets;
            }
        };
        ClassRegistry::$instances['AttributeValue'] = $attributeValue;
        $model = new class extends Correlation {
            public function __construct()
            {
            }

            public function getDataSource($id = null)
            {
                return new CidrCorrelationFloorDb();
            }
        };
        $method = new ReflectionMethod(Correlation::class, 'cidrCorrelation');
        $method->setAccessible(true);
        return $method->invoke($model, ['Attribute' => ['type' => $type, 'value1' => $value]], []);
    }

    public function testBroadCidrAttributesCollectNothing()
    {
        foreach (['10.0.0.0/7', '0.0.0.0/0', '2000::/15', '::/0'] as $value) {
            $this->assertNull($this->cidr('ip-src', $value), $value);
        }
    }

    public function testCidrAttributesAtTheFloorStillCorrelate()
    {
        foreach (['10.0.0.0/8', '10.0.0.0/24', '2000::/16', '2000::/64'] as $value) {
            $conditions = $this->cidr('ip-dst', $value);
            $this->assertSame(Correlation::IP_TYPES, $conditions['Attribute.type'], $value);
        }
    }

    public function testAnAddressIsMatchedByTheCidrsTheFloorLetsThrough()
    {
        foreach (['10.1.2.3', '2000::1'] as $value) {
            $conditions = $this->cidr('ip-src', $value, [5 => true, 6 => false], $facets);
            $this->assertSame([true], $facets->floorRequested, $value);
            $this->assertSame([
                ['Attribute.value1_id' => [5], 'Attribute.type' => Correlation::CIDR_TYPES],
                ['Attribute.value1_id' => [6], 'Attribute.type' => Correlation::IP_TYPES],
            ], $conditions['OR'], $value);
        }
    }
}
