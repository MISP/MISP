<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        $args = func_get_args();
        array_shift($args);
        return $args ? vsprintf($singular, $args) : $singular;
    }
}
if (!class_exists('MispAttribute')) {
    class MispAttribute
    {
        const NON_CORRELATING_TYPES = ['comment', 'text'];
    }
}
require_once __DIR__ . '/../Model/ValueRenderers/ValueRendererBase.php';
foreach (glob(__DIR__ . '/../Model/ValueRenderers/*Renderer.php') as $rendererFile) {
    require_once $rendererFile;
}
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueRendererTool.php';

use PHPUnit\Framework\TestCase;

class ValueRendererEventUseTest extends TestCase
{
    private function object($name, array $relations, $module = 'o1', $ranAt = 1)
    {
        $attributes = [];
        foreach ($relations as $relation => $values) {
            foreach ((array)$values as $value) {
                $attributes[] = ['relation' => $relation, 'value' => $value];
            }
        }
        return ['name' => $name, 'attributes' => $attributes, 'module' => $module, 'ran_at' => $ranAt];
    }

    private function subjects(array $groups)
    {
        return array_map(function ($group) {
            return [$group['subject'], count($group['objects'])];
        }, $groups);
    }

    public function testEveryShippedRendererDeclaresHowTheEventPageMayUseIt(): void
    {
        $each = [];
        foreach (glob(__DIR__ . '/../Model/ValueRenderers/*Renderer.php') as $file) {
            $class = basename($file, '.php');
            $renderer = new $class();
            $this->assertContains($renderer->eventUse, [ValueRendererBase::EVENT_SET, ValueRendererBase::EVENT_EACH], $class);
            if ($renderer->eventUse === ValueRendererBase::EVENT_EACH) {
                $each[] = $renderer->id;
            }
        }
        sort($each);
        $this->assertSame(['crypto-flow', 'file-verdict', 'known-good', 'port-service-set', 'reputation'], $each);
    }

    public function testObjectsWithoutASubjectAreEachTheirOwnGroup(): void
    {
        $renderer = new ReputationRenderer();
        $groups = $renderer->groupsOf([
            $this->object('greynoise-ip', ['ip-src' => '1.2.3.4', 'classification' => 'malicious'], 'a'),
            $this->object('abuseipdb', ['abuse-confidence-score' => '90'], 'b'),
            $this->object('crowdsec-ip-context', ['ip' => '1.2.3.4'], 'c'),
            $this->object('abuseipdb', ['abuse-confidence-score' => '10'], 'd'),
        ]);
        $this->assertSame([['1.2.3.4', 2], [null, 1], [null, 1]], $this->subjects($groups));
        $this->assertSame(
            [ValueRendererBase::SUBJECT_NAMED, ValueRendererBase::SUBJECT_OWN, ValueRendererBase::SUBJECT_OWN],
            array_column($groups, 'kind')
        );
    }

    public function testEveryEachRendererNamesItsOwnSubjects(): void
    {
        foreach (glob(__DIR__ . '/../Model/ValueRenderers/*Renderer.php') as $file) {
            $class = basename($file, '.php');
            $renderer = new $class();
            if ($renderer->eventUse !== ValueRendererBase::EVENT_EACH) {
                continue;
            }
            $words = $renderer->subjectWords();
            $this->assertSame(['one', 'many', 'none', 'none_title', 'none_group'], array_keys($words), $class);
            $this->assertNotSame('subject', $words['one'], $class);
        }
    }

    public function testCryptoTransactionsJoinTheWalletsTheyName(): void
    {
        $renderer = new CryptoFlowRenderer();
        $groups = $renderer->groupsOf([
            $this->object('coin-address', ['address' => 'A', 'current-balance' => '1'], 'w1'),
            $this->object('btc-wallet', ['wallet-address' => 'B', 'balance_BTC' => '2'], 'w2'),
            $this->object('btc-transaction', ['btc-address' => ['A', 'B'], 'transaction-number' => 't1'], 't1'),
            $this->object('btc-transaction', ['btc-address' => ['C', 'D'], 'transaction-number' => 't2'], 't2'),
        ]);
        $this->assertSame([['A', 2], ['B', 2], [null, 1]], $this->subjects($groups));
        $this->assertSame('t2', $groups[2]['objects'][0]['module']);
        $this->assertSame(
            [ValueRendererBase::SUBJECT_NAMED, ValueRendererBase::SUBJECT_NAMED, ValueRendererBase::SUBJECT_NONE],
            array_column($groups, 'kind')
        );
    }

    public function testPortServiceHostReadsTheDestinationAddress(): void
    {
        $renderer = new PortServiceSetRenderer();
        $object = $this->object('ip-port', ['ip-dst' => '10.0.0.1', 'dst-port' => '22']);
        $this->assertSame(['10.0.0.1'], $renderer->subjectsOf($object));
        $this->assertSame('10.0.0.1', $renderer->prepare([$object], [])['services'][0]['host']);
    }

    public function testKnownGoodSubjectIsTheStrongestHash(): void
    {
        $renderer = new KnownGoodRenderer();
        $object = $this->object('hashlookup', ['MD5' => 'md5', 'SHA-256' => 'sha256', 'SHA-1' => 'sha1']);
        $this->assertSame(['sha256'], $renderer->subjectsOf($object));
    }

    public function testGeolocationDrawsGpxAndGeojsonByTheirBoundingBox(): void
    {
        $renderer = new GeolocationRenderer();
        $gpx = $this->object('gpx', ['name' => 'Route', 'start-time' => '2026-10-03T07:02:00Z'], 'g', 9);
        $area = $this->object('geojson', [
            'filename' => 'area.geojson',
            'min-latitude' => '49.6', 'min-longitude' => '6.1', 'max-latitude' => '49.7', 'max-longitude' => '6.2',
        ], 'j', 8);
        $this->assertTrue($renderer->matches([$gpx], []));

        $place = $this->object('geolocation', [
            'city' => 'Luxembourg', 'country' => 'LU', 'latitude' => '49.61', 'longitude' => '6.13',
        ], 'p', 1);
        $data = $renderer->prepare([$gpx, $area, $place], []);
        $this->assertCount(1, $data['points']);
        $this->assertSame('Luxembourg', $data['place']['city']);
        $this->assertSame(['Route', 'area.geojson'], array_column($data['extents'], 'name'));
        $this->assertNull($data['extents'][0]['box']);
        $this->assertSame([49.6, 6.1, 49.7, 6.2], $data['extents'][1]['box']);
        $this->assertNotNull($data['extents'][0]['start']);
    }

    public function testAUavIsAnExtentNamedAndTimedByItsOwnRelations(): void
    {
        $renderer = new GeolocationRenderer();
        $uav = $this->object('uav', [
            'craftname' => 'Courier drone',
            'first-seen' => '2026-10-03T07:00:00Z',
            'last-seen' => '2026-10-03T07:40:00Z',
        ], 'u');
        $this->assertTrue($renderer->matches([$uav], []));
        $data = $renderer->prepare([$uav], []);
        $this->assertSame([], $data['points']);
        $this->assertSame('uav', $data['extents'][0]['template']);
        $this->assertSame('Courier drone', $data['extents'][0]['name']);
        $this->assertNull($data['extents'][0]['box']);
        $this->assertSame(2400, $data['extents'][0]['end'] - $data['extents'][0]['start']);
    }

    public function testAPointCarriesItsAccuracyRadius(): void
    {
        $renderer = new GeolocationRenderer();
        $data = $renderer->prepare([
            $this->object('geolocation', [
                'country' => 'US', 'latitude' => '37.751', 'longitude' => '-97.822', 'accuracy-radius' => '1000',
            ], 'a'),
            $this->object('geolocation', [
                'city' => 'Luxembourg', 'latitude' => '49.61', 'longitude' => '6.13', 'accuracy-radius' => '0',
            ], 'b'),
            $this->object('geolocation', ['city' => 'Paris', 'latitude' => '48.85', 'longitude' => '2.35'], 'c'),
        ], []);
        $this->assertSame([1000.0, null, null], array_column($data['points'], 'radius'));
    }

    public function testAnInvertedOrOutOfRangeBoxIsNotDrawn(): void
    {
        $renderer = new GeolocationRenderer();
        $data = $renderer->prepare([
            $this->object('geojson', [
                'min-latitude' => '50', 'min-longitude' => '6', 'max-latitude' => '49', 'max-longitude' => '7',
            ]),
            $this->object('gpx', [
                'min-latitude' => '10', 'min-longitude' => '170', 'max-latitude' => '11', 'max-longitude' => '190',
            ]),
        ], []);
        $this->assertSame([null, null], array_column($data['extents'], 'box'));
    }

    public function testAStoredObjectIsShapedTheWayAModuleAnswerIs(): void
    {
        $shaped = ValueRendererTool::shapeObject([
            'name' => 'domain-ip',
            'meta-category' => 'network',
            'comment' => 'seen',
            'Attribute' => [
                ['object_relation' => 'domain', 'type' => 'domain', 'value' => 'example.com', 'to_ids' => true],
                ['object_relation' => 'ip', 'type' => 'ip-dst', 'value' => '1.2.3.4', 'disable_correlation' => true],
                ['object_relation' => 'text', 'type' => 'text', 'value' => 'note'],
            ],
        ]);
        $this->assertSame('domain-ip', $shaped['name']);
        $this->assertSame('network', $shaped['meta_category']);
        $this->assertNull($shaped['description']);
        $this->assertSame(['domain', 'ip', 'text'], array_column($shaped['attributes'], 'relation'));
        $this->assertSame([true, false, false], array_column($shaped['attributes'], 'correlates'));
        $this->assertSame([true, false, false], array_column($shaped['attributes'], 'to_ids'));
    }
}
