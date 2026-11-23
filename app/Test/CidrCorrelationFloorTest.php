<?php
/**
 * CIDR correlation floor tests: very broad prefixes are not correlated.
 *
 * The attribute lookup and the CIDR list are replaced by test doubles.
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

class CidrCorrelationFloorAttributeStub
{
    public $queries = 0;
    public $ips = [];

    public function find($type, $options = [])
    {
        $this->queries++;
        return $this->ips;
    }
}

class CidrCorrelationFloorTest extends TestCase
{
    private static function correlation(array $cidrList, array $ips)
    {
        // Loaded at run time: an AppModel stub declared while the suite loads
        // its files would shadow the fuller ones other test files need.
        if (!class_exists('AppModel', false)) {
            class_alias('CidrCorrelationFloorModelStub', 'AppModel');
        }
        require_once __DIR__ . '/../Model/Correlation.php';
        $attributes = new CidrCorrelationFloorAttributeStub();
        $attributes->ips = $ips;
        $model = new class extends Correlation {
            public $cidrs = [];

            public function __construct()
            {
            }

            protected function isMysql()
            {
                return false;
            }

            public function getCidrList()
            {
                return $this->cidrs;
            }
        };
        $model->cidrs = $cidrList;
        $model->Attribute = $attributes;
        return [$model, $attributes];
    }

    private static function cidr($model, $value)
    {
        $method = new ReflectionMethod(Correlation::class, 'cidrCorrelation');
        $method->setAccessible(true);
        return $method->invoke($model, ['Attribute' => ['value1' => $value]]);
    }

    public function broadCidrProvider()
    {
        return [
            'ipv4 /7' => ['10.0.0.0/7', '10.1.2.3'],
            'ipv4 /1' => ['0.0.0.0/1', '10.1.2.3'],
            'ipv6 /15' => ['2000::/15', '2000::1'],
        ];
    }

    public function floorCidrProvider()
    {
        return [
            'ipv4 /8' => ['10.0.0.0/8', '10.1.2.3'],
            'ipv6 /16' => ['2001::/16', '2001::1'],
        ];
    }

    /**
     * @dataProvider broadCidrProvider
     */
    public function testBroadCidrAttributeCollectsNothing($cidr, $ip)
    {
        list($model, $attributes) = self::correlation([], [$ip]);
        $this->assertSame([], self::cidr($model, $cidr));
        $this->assertSame(0, $attributes->queries);
    }

    /**
     * @dataProvider floorCidrProvider
     */
    public function testFloorCidrAttributeStillCollectsIps($cidr, $ip)
    {
        list($model, $attributes) = self::correlation([], [$ip]);
        $result = self::cidr($model, $cidr);
        $this->assertSame(1, $attributes->queries);
        $this->assertSame([$ip], $result['OR']['Attribute.value1']);
    }

    /**
     * @dataProvider broadCidrProvider
     */
    public function testIpIsNotMatchedByBroadCidr($cidr, $ip)
    {
        list($model) = self::correlation([$cidr], []);
        $this->assertSame([], self::cidr($model, $ip));
    }

    /**
     * @dataProvider floorCidrProvider
     */
    public function testIpIsStillMatchedByFloorCidr($cidr, $ip)
    {
        list($model) = self::correlation([$cidr], []);
        $result = self::cidr($model, $ip);
        $this->assertSame([$cidr], $result['OR']['Attribute.value1']);
    }

    public function testBroadCidrIsSkippedAmongOthers()
    {
        list($model) = self::correlation(['10.0.0.0/7', '10.0.0.0/8'], []);
        $result = self::cidr($model, '10.1.2.3');
        $this->assertSame(['10.0.0.0/8'], $result['OR']['Attribute.value1']);
    }
}
