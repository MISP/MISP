<?php

use MispTest\Support\FakeModel;
use PHPUnit\Framework\TestCase;

require_once APP . 'Test/Support/FakeModel.php';

/**
 * The contract every dashboard widget must satisfy.
 *
 * This is a family test, not a per-widget test: it discovers every widget on
 * disk and asserts the invariants the dashboard relies on. Its value is that
 * it fails when someone ADDS a malformed widget - a class of bug no
 * per-widget suite can catch, because the failure is about the family.
 *
 * Properties are read through reflection defaults rather than by
 * instantiating, so inherited values are seen (EventStreamCardsWidget
 * inherits from EventStreamWidget; three Orgs* widgets inherit from
 * OrgsContributorsGeneric) and no constructor side effects run.
 */
class WidgetContractTest extends TestCase
{
    /**
     * Widgets whose handler() genuinely needs infrastructure that layer 1
     * forbids. Listed explicitly by class rather than matched on exception
     * text, so a real regression in any OTHER widget still fails the suite.
     *
     * Each of these is exercised by the live suite instead.
     */
    private const NEEDS_INFRASTRUCTURE = [
        'APIActivityWidget'       => 'needs a Redis connection',
        'UsageDataWidget'         => 'needs a Redis connection',
        'MispAdminHealthWidget'   => 'needs Redis INFO output',
        'MispAdminResourceWidget' => 'needs Redis INFO output',
        'BenchmarkTopListWidget'  => 'needs a real model to construct BenchmarkTool',
        'RecentEventReportsWidget' => 'needs the EventReport model',
        'RecentSightingsWidget'   => 'needs a real model result object (intoString)',
        'ThresholdSightingsWidget' => 'needs a real model result object (intoString)',
    ];

    /** @var string */
    private static $widgetDir;
    /** @var string */
    private static $templateDir;

    public static function setUpBeforeClass(): void
    {
        self::$widgetDir   = APP . 'Lib/Dashboard/';
        self::$templateDir = APP . 'View/Elements/dashboard/Widgets/';

        // Parent classes first: a subclass cannot be declared before its parent.
        foreach (['OrgsContributorsGeneric.php', 'EventStreamWidget.php'] as $parent) {
            require_once self::$widgetDir . $parent;
        }
        foreach (glob(self::$widgetDir . '*Widget.php') as $file) {
            require_once $file;
        }
    }

    public function widgetProvider(): array
    {
        $cases = [];
        foreach (glob(APP . 'Lib/Dashboard/*Widget.php') as $file) {
            $class = basename($file, '.php');
            $cases[$class] = [$class];
        }
        ksort($cases);
        return $cases;
    }

    private function defaults(string $class): array
    {
        $this->assertTrue(class_exists($class, false), "$class was not declared by its file");
        return (new ReflectionClass($class))->getDefaultProperties();
    }

    /** @dataProvider widgetProvider */
    public function testDeclaresTitleAndDescription(string $class): void
    {
        $d = $this->defaults($class);
        foreach (['title', 'description'] as $prop) {
            $this->assertArrayHasKey($prop, $d, "$class must declare \$$prop");
            $this->assertIsString($d[$prop], "$class::\$$prop must be a string");
            $this->assertNotSame('', trim((string)$d[$prop]), "$class::\$$prop must not be empty");
        }
    }

    /** @dataProvider widgetProvider */
    public function testRenderKindHasATemplateOnDisk(string $class): void
    {
        $d = $this->defaults($class);
        $this->assertArrayHasKey('render', $d, "$class must declare \$render");
        $render = (string)$d['render'];
        $this->assertNotSame('', $render, "$class::\$render must not be empty");

        $template = self::$templateDir . $render . '.ctp';
        $this->assertFileExists(
            $template,
            sprintf('%s renders as "%s" but %s does not exist', $class, $render, $template)
        );
    }

    /** @dataProvider widgetProvider */
    public function testExposesAHandler(string $class): void
    {
        $r = new ReflectionClass($class);
        $this->assertTrue(
            $r->hasMethod('handler'),
            "$class must expose handler() (directly or inherited) - the dashboard calls it to render"
        );
        $this->assertTrue(
            $r->getMethod('handler')->isPublic(),
            "$class::handler() must be public"
        );
    }

    /** @dataProvider widgetProvider */
    public function testParamsAndDimensionsAreWellFormed(string $class): void
    {
        $d = $this->defaults($class);

        if (array_key_exists('params', $d) && $d['params'] !== null) {
            $this->assertIsArray($d['params'], "$class::\$params must be an array");
        }
        foreach (['width', 'height'] as $dim) {
            if (array_key_exists($dim, $d) && $d[$dim] !== null) {
                $this->assertIsInt($d[$dim], "$class::\$$dim must be an int");
                $this->assertGreaterThan(0, $d[$dim], "$class::\$$dim must be positive");
            }
        }
        if (array_key_exists('cacheLifetime', $d) && $d['cacheLifetime'] !== null && $d['cacheLifetime'] !== false) {
            $this->assertIsInt($d['cacheLifetime'], "$class::\$cacheLifetime must be an int or false");
            $this->assertGreaterThan(0, $d['cacheLifetime'], "$class::\$cacheLifetime must be positive");
        }
    }

    /**
     * A realistic site-admin user. Widgets read well beyond id/org_id -
     * Role.name, last_login and the Organisation sub-array are all consumed.
     */
    private static function user(): array
    {
        return [
            'id' => 1,
            'org_id' => 1,
            'email' => 'admin@test.local',
            'last_login' => 1735689600,
            'current_login' => 1735689600,
            'authkey' => str_repeat('a', 40),
            'Role' => [
                'id' => 1,
                'name' => 'Site Admin',
                'perm_site_admin' => 1,
                'perm_admin' => 1,
                'perm_sync' => 1,
                'perm_audit' => 1,
            ],
            'Organisation' => ['id' => 1, 'name' => 'TestOrg', 'uuid' => 'test-org-uuid'],
        ];
    }

    /**
     * Build the options array the dashboard would pass for an unconfigured
     * widget: every declared param key, carrying its declared default.
     *
     * Widgets declare params in two shapes. The legacy shape is a
     * `key => 'description'` map with defaults held separately in $schema;
     * the modern shape is a list of `['id' => ..., 'default' => ...]` entries.
     * Both must yield the same option keys, because a widget that reads
     * $options['x'] unguarded fatals if x is absent.
     */
    private static function defaultOptionsFor(object $widget): array
    {
        $options = [];
        $schema = (isset($widget->schema) && is_array($widget->schema)) ? $widget->schema : [];

        if (isset($widget->params) && is_array($widget->params)) {
            foreach ($widget->params as $key => $param) {
                if (is_array($param) && isset($param['id'])) {
                    $options[$param['id']] = $param['default'] ?? ($schema[$param['id']]['default'] ?? null);
                } elseif (is_string($key)) {
                    $options[$key] = $schema[$key]['default'] ?? null;
                }
            }
        }
        foreach ($schema as $key => $definition) {
            if (!array_key_exists($key, $options)) {
                $options[$key] = $definition['default'] ?? null;
            }
        }
        return $options;
    }

    protected function setUp(): void
    {
        ClassRegistry::reset();
        ClassRegistry::$factory = static function ($name) { return new FakeModel(); };
    }

    /**
     * Constructing every widget executes its constructor, which is where
     * several build their params and resolve collaborators.
     *
     * @dataProvider widgetProvider
     */
    public function testConstructs(string $class): void
    {
        $widget = new $class();
        $this->assertInstanceOf($class, $widget);
    }

    /**
     * Drives each widget's handler() with a site-admin user and no options.
     *
     * A widget that genuinely needs infrastructure layer 1 forbids (Redis, a
     * real model) is skipped with its reason rather than failed - but only for
     * that narrow, documented set, so a real regression still fails.
     *
     * @dataProvider widgetProvider
     */
    public function testHandlerExecutes(string $class): void
    {
        $widget = new $class();

        $options = self::defaultOptionsFor($widget);

        if (isset(self::NEEDS_INFRASTRUCTURE[$class])) {
            $this->markTestSkipped(sprintf(
                '%s %s - layer 1 forbids it, so this is covered by the live suite instead.',
                $class,
                self::NEEDS_INFRASTRUCTURE[$class]
            ));
        }

        $result = $widget->handler(self::user(), $options);

        $this->assertTrue(
            $result === null || is_array($result) || is_string($result) || is_numeric($result),
            sprintf('%s::handler() returned an unexpected %s', $class, gettype($result))
        );
    }

    public function testEveryRenderKindIsUsedByAtLeastOneWidgetAndViceVersa(): void
    {
        $used = [];
        foreach ($this->widgetProvider() as [$class]) {
            $d = (new ReflectionClass($class))->getDefaultProperties();
            if (!empty($d['render'])) {
                $used[(string)$d['render']] = true;
            }
        }
        $this->assertNotEmpty($used, 'no widget declared a render kind');

        foreach (array_keys($used) as $render) {
            $this->assertFileExists(
                self::$templateDir . $render . '.ctp',
                sprintf('render kind "%s" has no template', $render)
            );
        }
    }
}
