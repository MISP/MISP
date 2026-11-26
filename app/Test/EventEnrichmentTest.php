<?php
/** Bulk enrichment response handling, without CakePHP, DB or network. */
require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class EventEnrichmentTest extends TestCase
{
    protected function setUp(): void
    {
        // Keep the framework stubs out of the process that discovers every test file.
        require_once __DIR__ . '/EventEnrichmentStubs.php';
    }

    /** @dataProvider responseSequences */
    public function testBatchContinuesAndPreservesTheCount(
        $format, array $responses, $expectedCount, $moduleCount
    ) {
        $modules = $this->modules($format, $moduleCount);
        $module = $this->moduleService($modules, $responses);
        $attributes = [];
        for ($i = 0; $i < count($responses) / $moduleCount; ++$i) {
            $attributes[] = [
                'id' => $i + 1, 'uuid' => 'attribute-' . $i,
                'object_id' => '0', 'type' => 'ip-dst',
                'value' => '192.0.2.' . ($i + 1),
                'distribution' => 0, 'sharing_group_id' => 0,
            ];
        }
        $event = $this->getMockBuilder(EnrichmentTestEvent::class)
            ->disableOriginalConstructor()
            ->setMethods([
                'fetchEvent', 'processModuleResultsData', 'handleModuleResult',
            ])->getMock();
        $event->method('fetchEvent')->willReturn([
            ['Event' => ['id' => 42], 'Attribute' => $attributes],
        ]);
        $event->method('processModuleResultsData')->willReturnCallback(
            function ($user, $results) { return count($results); }
        );
        $event->method('handleModuleResult')->willReturnCallback(
            function ($response) { return $response['results']; }
        );
        $event->Attribute = new class {
            public $saved = [];

            public function create() {}

            public function save($attribute)
            {
                $this->saved[] = $attribute;
                return true;
            }
        };

        ClassRegistry::$instances['Module'] = $module;
        $count = $event->enrichment([
            'user' => ['id' => 1], 'event_id' => 42,
            'modules' => array_column($modules, 'name'),
        ]);
        $this->assertSame($expectedCount, $count);
        $this->assertCount(count($responses), $module->requests);
        $this->assertSame([], $module->responses);
        if ($format !== 'misp_standard') {
            $this->assertCount($expectedCount, $event->Attribute->saved);
        }
    }

    /** @dataProvider formats */
    public function testSingleAttributeEnrichmentSkipsModuleErrors($format)
    {
        $modules = $this->modules($format, 2);
        $module = $this->moduleService($modules, [['error' => 'NXDOMAIN'], self::success()]);
        $attribute = new EnrichmentTestAttribute();
        $attribute->attribute = [
            'id' => 1, 'uuid' => 'attribute-0', 'event_id' => 42,
            'object_id' => '0', 'type' => 'ip-dst', 'value' => '192.0.2.1',
            'distribution' => 0, 'sharing_group_id' => 0,
        ];
        $attribute->Event = new class {
            public function find($type, $options = [])
            {
                return ['Event' => ['id' => 42]];
            }

            public function processModuleResultsData($user, $results)
            {
                return count($results);
            }

            public function handleModuleResult($response)
            {
                return $response['results'] ?? [];
            }
        };

        ClassRegistry::$instances['Module'] = $module;
        $count = $attribute->enrichment([
            'user' => ['id' => 1], 'id' => 1,
            'modules' => array_column($modules, 'name'),
        ]);
        $this->assertSame(1, $count);
        $this->assertCount(2, $module->requests);
        if ($format !== 'misp_standard') {
            $this->assertCount(1, $attribute->saved);
        }
    }

    public function responseSequences()
    {
        $success = self::success();
        $error = ['error' => 'NXDOMAIN'];
        $sequences = [
            'error between successes' => [[$success, $error, $success], 2, 1],
            'error first' => [[$error, $success], 1, 1],
            'error last preserves count' => [[$success, $error], 1, 1],
            'all errors' => [[$error, $error], 0, 1],
            'missing results' => [[[], $success], 1, 1],
            'empty results' => [[['results' => []], $success], 1, 1],
            'next module and attribute' => [
                [$error, $success, $success, $success], 3, 2,
            ],
            'malformed response, next module' => [['not json', $success], 1, 2],
            'malformed response, next attribute' => [
                [$success, 'not json', $success, $success], 3, 2,
            ],
        ];
        foreach ($this->formats() as [$format]) {
            foreach ($sequences as $name => $sequence) {
                yield "$format: $name" => array_merge([$format], $sequence);
            }
        }
    }

    public function formats()
    {
        return ['misp_standard' => ['misp_standard'], 'simple' => ['simple']];
    }

    private static function success()
    {
        return ['results' => [
            ['default_type' => 'hostname', 'value' => 'host.example'],
        ]];
    }

    private function modules($format, $moduleCount)
    {
        $modules = [];
        foreach (array_slice(['reversedns', 'dns'], 0, $moduleCount) as $name) {
            $modules[] = [
                'name' => $name,
                'mispattributes' => ['input' => ['ip-dst'], 'format' => $format],
            ];
        }
        return $modules;
    }

    private function moduleService(array $modules, array $responses)
    {
        return new class($modules, $responses) {
            public $modules;
            public $responses;
            public $requests = [];

            public function __construct($modules, $responses)
            {
                $this->modules = $modules;
                $this->responses = $responses;
            }

            public function getEnabledModules($user)
            {
                return ['modules' => $this->modules];
            }

            public function getModuleConfig(array $module, $moduleFamily, array $user)
            {
                return [];
            }

            public function queryModuleServer(...$args)
            {
                $this->requests[] = $args[0];
                return array_shift($this->responses);
            }
        };
    }
}
