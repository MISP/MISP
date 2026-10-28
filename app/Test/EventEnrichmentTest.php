<?php
/** Bulk enrichment response handling, without CakePHP, DB or network. */
require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package) {}
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel {}
}
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = [];

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new class {
                    public $responses = [];

                    public function find($type, $options = [])
                    {
                        return array_shift($this->responses) ?: [];
                    }
                };
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = [];
        }
    }
}
require_once __DIR__ . '/../Model/Event.php';

class EnrichmentTestEvent extends Event
{
    public $Attribute;
    public $Module;
}

class EventEnrichmentTest extends TestCase
{
    /** @dataProvider responseSequences */
    public function testBatchContinuesAndPreservesTheCount(
        $format, array $responses, $expectedCount, $moduleCount
    ) {
        $modules = [];
        foreach (array_slice(['reversedns', 'dns'], 0, $moduleCount) as $name) {
            $modules[] = [
                'name' => $name,
                'mispattributes' => ['input' => ['ip-dst'], 'format' => $format],
            ];
        }
        $module = new class($modules, $responses) {
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

            public function queryModuleServer(...$args)
            {
                $this->requests[] = $args[0];
                return array_shift($this->responses);
            }
        };
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

        $previousInstances = ClassRegistry::$instances;
        ClassRegistry::$instances['Module'] = $module;
        try {
            $count = $event->enrichment([
                'user' => ['id' => 1], 'event_id' => 42,
                'modules' => array_column($modules, 'name'),
            ]);
        } finally {
            ClassRegistry::$instances = $previousInstances;
        }
        $this->assertSame($expectedCount, $count);
        $this->assertCount(count($responses), $module->requests);
        $this->assertSame([], $module->responses);
        if ($format !== 'misp_standard') {
            $this->assertCount($expectedCount, $event->Attribute->saved);
        }
    }

    public function responseSequences()
    {
        $success = ['results' => [
            ['default_type' => 'hostname', 'value' => 'host.example'],
        ]];
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
        ];
        foreach (['misp_standard', 'simple'] as $format) {
            foreach ($sequences as $name => $sequence) {
                yield "$format: $name" => array_merge([$format], $sequence);
            }
        }
    }
}
