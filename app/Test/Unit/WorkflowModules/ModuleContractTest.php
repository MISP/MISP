<?php

use MispTest\Support\FakeModel;
use PHPUnit\Framework\TestCase;

require_once APP . 'Test/Support/FakeModel.php';

/**
 * The contract every workflow module must satisfy.
 *
 * Workflows are user-authored automation: a module with a duplicate id or a
 * missing description is a silent misconfiguration that mis-routes real
 * intelligence. The uniqueness check in particular is an assertion about the
 * registry as a whole, which no single-module test can make.
 *
 * Properties are read through reflection defaults so no constructor runs -
 * several modules call ClassRegistry::init() in their constructor, which
 * would need a database.
 */
class ModuleContractTest extends TestCase
{
    /** @var string */
    private static $moduleDir;

    public static function setUpBeforeClass(): void
    {
        self::$moduleDir = APP . 'Model/WorkflowModules/';
        require_once self::$moduleDir . 'WorkflowBaseModule.php';

        // Module_splunk_hec_export extends Module_webhook, so load it first.
        require_once self::$moduleDir . 'action/Module_webhook.php';

        foreach (self::moduleFiles() as $file) {
            require_once $file;
        }
    }

    private static function moduleFiles(): array
    {
        $files = [];
        foreach (['action', 'logic', 'trigger'] as $kind) {
            foreach (glob(self::$moduleDir . $kind . '/Module_*.php') as $file) {
                $files[] = $file;
            }
        }
        sort($files);
        return $files;
    }

    public function moduleProvider(): array
    {
        $dir = APP . 'Model/WorkflowModules/';
        $cases = [];
        foreach (['action', 'logic', 'trigger'] as $kind) {
            foreach (glob($dir . $kind . '/Module_*.php') as $file) {
                $class = basename($file, '.php');
                $cases[$kind . '/' . $class] = [$class, $kind];
            }
        }
        ksort($cases);
        return $cases;
    }

    private function defaults(string $class): array
    {
        $this->assertTrue(class_exists($class, false), "$class was not declared by its file");
        return (new ReflectionClass($class))->getDefaultProperties();
    }

    /** @dataProvider moduleProvider */
    public function testOverridesTheBasePlaceholders(string $class, string $kind): void
    {
        $d = $this->defaults($class);
        $this->assertNotSame(
            'to-override', $d['id'] ?? null,
            "$class must set its own \$id; it still carries the WorkflowBaseModule placeholder"
        );
        $this->assertNotSame(
            'to-override', $d['description'] ?? null,
            "$class must set its own \$description; it still carries the base placeholder"
        );
        $this->assertIsString($d['id'] ?? null, "$class::\$id must be a string");
        $this->assertNotSame('', trim((string)($d['id'] ?? '')), "$class::\$id must not be empty");
    }

    /** @dataProvider moduleProvider */
    public function testDeclaresNameAndDescription(string $class, string $kind): void
    {
        $d = $this->defaults($class);
        foreach (['name', 'description'] as $prop) {
            $this->assertIsString($d[$prop] ?? null, "$class::\$$prop must be a string");
            $this->assertNotSame('', trim((string)($d[$prop] ?? '')), "$class::\$$prop must not be empty");
        }
    }

    /** @dataProvider moduleProvider */
    public function testInputsAndOutputsAreSaneForItsKind(string $class, string $kind): void
    {
        $d = $this->defaults($class);
        foreach (['inputs', 'outputs'] as $prop) {
            $this->assertIsInt($d[$prop] ?? null, "$class::\$$prop must be an int");
            $this->assertGreaterThanOrEqual(0, $d[$prop], "$class::\$$prop must not be negative");
        }
        if ($kind === 'trigger') {
            $this->assertSame(0, $d['inputs'], "trigger $class must have 0 inputs - it starts a workflow");
            $this->assertGreaterThan(0, $d['outputs'], "trigger $class must have an output to feed the workflow");
        } else {
            // Outputs may legitimately be 0: terminal modules such as
            // Module_stop_execution and Module_splunk_hec_export end a branch.
            $this->assertGreaterThan(0, $d['inputs'], "$kind module $class must consume at least one input");
        }
    }

    /** @dataProvider moduleProvider */
    public function testParamsAreWellFormed(string $class, string $kind): void
    {
        $d = $this->defaults($class);
        $this->assertIsArray($d['params'] ?? null, "$class::\$params must be an array");
    }

    /** @dataProvider moduleProvider */
    public function testActionAndLogicModulesExposeExec(string $class, string $kind): void
    {
        if ($kind === 'trigger') {
            $this->assertTrue(true, 'triggers do not execute');
            return;
        }
        $r = new ReflectionClass($class);
        $this->assertTrue(
            $r->hasMethod('exec'),
            "$kind module $class must expose exec() - the workflow engine calls it"
        );
        $this->assertTrue($r->getMethod('exec')->isPublic(), "$class::exec() must be public");
    }

    protected function setUp(): void
    {
        ClassRegistry::reset();
        ClassRegistry::$factory = static function ($name) { return new FakeModel(); };
    }

    /**
     * Constructing every module executes its constructor, which is where most
     * modules build their $params definitions.
     *
     * @dataProvider moduleProvider
     */
    public function testConstructsAndBuildsWellFormedParams(string $class, string $kind): void
    {
        $module = new $class();
        $this->assertInstanceOf($class, $module);
        $this->assertIsArray($module->params, "$class::\$params must be an array after construction");

        foreach ($module->params as $index => $param) {
            $this->assertIsArray($param, "$class::\$params[$index] must be an array");
            $this->assertArrayHasKey('id', $param, "$class::\$params[$index] must declare an id");
            $this->assertArrayHasKey('type', $param, "$class param '{$param['id']}' must declare a type");
            $this->assertNotSame('', trim((string)$param['id']), "$class::\$params[$index] id must not be empty");
        }
    }

    /**
     * Param ids must be unique within a module, or the later one silently
     * shadows the earlier when the workflow engine reads its configuration.
     *
     * @dataProvider moduleProvider
     */
    public function testParamIdsAreUniqueWithinAModule(string $class, string $kind): void
    {
        $module = new $class();
        $ids = [];
        foreach ($module->params as $param) {
            $id = $param['id'] ?? null;
            if ($id === null) {
                continue;
            }
            $this->assertNotContains($id, $ids, "$class declares param id '$id' more than once");
            $ids[] = $id;
        }
        $this->assertTrue(true);
    }

    /**
     * The assertion that only a family test can make: two modules sharing an
     * id silently shadow each other in the registry.
     */
    public function testModuleIdsAreUniqueAcrossTheRegistry(): void
    {
        $seen = [];
        foreach ($this->moduleProvider() as [$class, $kind]) {
            $id = (new ReflectionClass($class))->getDefaultProperties()['id'] ?? null;
            if ($id === null || $id === 'to-override') {
                continue;
            }
            $this->assertArrayNotHasKey(
                $id,
                $seen,
                sprintf('module id "%s" is claimed by both %s and %s', $id, $seen[$id] ?? '?', $class)
            );
            $seen[$id] = $class;
        }
        $this->assertGreaterThan(50, count($seen), 'expected the registry to hold most of the 67 modules');
    }
}
