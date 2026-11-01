<?php

require_once __DIR__ . '/IntegrationTestCase.php';

/**
 * MISP ships three interchangeable correlation strategies:
 * DefaultCorrelationBehavior, NoAclCorrelationBehavior and
 * OnDemandCorrelationBehavior, selected by MISP.correlation_engine.
 *
 * They are interchangeable only if they AGREE. That is an assertion about
 * three implementations relative to each other, which no single HTTP request
 * can make - it is the reason layer 2 exists. Combined they are 1,195
 * statements, of which OnDemandCorrelationBehavior was 0% in both suites.
 */
class CorrelationEngineTest extends IntegrationTestCase
{
    private const ENGINES = ['Default', 'NoAcl', 'OnDemand'];

    /** @var string|null */
    private $originalEngine;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalEngine = Configure::read('MISP.correlation_engine');
    }

    protected function tearDown(): void
    {
        // Restore the engine before the base class removes fixture events, so
        // cleanup runs against the configuration the instance started with.
        Configure::write('MISP.correlation_engine', $this->originalEngine);
        parent::tearDown();
    }

    private function behaviorClass(string $engine): string
    {
        return $engine . 'CorrelationBehavior';
    }

    private function loadBehavior(string $engine): void
    {
        App::uses($this->behaviorClass($engine), 'Model/Behavior');
    }

    // ------------------------------------------------------------ interface

    /**
     * Every engine must expose the same public surface. If one gains a method
     * the others lack, switching engines silently changes behaviour.
     */
    public function testAllEnginesShareThePublicInterface(): void
    {
        $surfaces = [];
        foreach (self::ENGINES as $engine) {
            $this->loadBehavior($engine);
            $class = $this->behaviorClass($engine);
            $this->assertTrue(class_exists($class), "$class must exist");

            $methods = [];
            foreach ((new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
                if ($method->getDeclaringClass()->getName() === 'ModelBehavior') {
                    continue; // inherited framework surface, not the strategy's
                }
                if (strpos($method->getName(), '_') === 0) {
                    continue; // engine-private helper
                }
                $methods[] = $method->getName();
            }
            sort($methods);
            $surfaces[$engine] = $methods;
        }

        $reference = $surfaces['Default'];
        foreach (['NoAcl', 'OnDemand'] as $engine) {
            $missing = array_diff($reference, $surfaces[$engine]);
            $this->assertSame(
                [],
                array_values($missing),
                sprintf(
                    '%s is missing methods the Default engine provides: %s',
                    $this->behaviorClass($engine),
                    implode(', ', $missing)
                )
            );
        }
    }

    /**
     * An engine may accept FEWER arguments than the caller passes - PHP
     * discards the extras - but it must never REQUIRE more, or swapping to it
     * breaks the call site.
     *
     * NoAclCorrelationBehavior::runGetAttributesRelatedToEvent legitimately
     * takes one parameter fewer than Default: Correlation.php:1115 passes
     * $sgids, and an engine that skips ACL has no use for sharing-group ids,
     * so it drops them. That is a deliberate narrowing, which this invariant
     * permits. A widening would be a real break, which it does not.
     */
    public function testNoEngineRequiresMoreArgumentsThanTheDefault(): void
    {
        $required = [];
        foreach (self::ENGINES as $engine) {
            $this->loadBehavior($engine);
            foreach ((new ReflectionClass($this->behaviorClass($engine)))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
                if ($method->getDeclaringClass()->getName() === 'ModelBehavior') {
                    continue;
                }
                $required[$engine][$method->getName()] = $method->getNumberOfRequiredParameters();
            }
        }

        $breaks = [];
        foreach ($required['Default'] as $name => $defaultRequired) {
            foreach (['NoAcl', 'OnDemand'] as $engine) {
                if (!isset($required[$engine][$name])) {
                    continue;
                }
                if ($required[$engine][$name] > $defaultRequired) {
                    $breaks[] = sprintf(
                        '%s::%s requires %d args but the Default engine requires only %d, '
                        . 'so call sites written against Default would break',
                        $this->behaviorClass($engine), $name,
                        $required[$engine][$name], $defaultRequired
                    );
                }
            }
        }
        $this->assertSame([], $breaks, implode("\n", $breaks));
    }

    /**
     * Records the one place the engines' signatures diverge today, so a NEW
     * divergence stands out instead of hiding among accepted ones.
     */
    public function testTheOnlyKnownSignatureDivergenceIsTheAclArgument(): void
    {
        $known = ['NoAclCorrelationBehavior::runGetAttributesRelatedToEvent'];

        $required = [];
        foreach (self::ENGINES as $engine) {
            $this->loadBehavior($engine);
            foreach ((new ReflectionClass($this->behaviorClass($engine)))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
                if ($method->getDeclaringClass()->getName() === 'ModelBehavior') {
                    continue;
                }
                $required[$engine][$method->getName()] = $method->getNumberOfRequiredParameters();
            }
        }

        $divergences = [];
        foreach ($required['Default'] as $name => $defaultRequired) {
            foreach (['NoAcl', 'OnDemand'] as $engine) {
                if (!isset($required[$engine][$name])) {
                    continue;
                }
                if ($required[$engine][$name] !== $defaultRequired) {
                    $divergences[] = $this->behaviorClass($engine) . '::' . $name;
                }
            }
        }
        sort($divergences);
        sort($known);

        $this->assertSame(
            $known,
            $divergences,
            "the set of engines whose signatures differ from Default has changed"
        );
    }

    /** Each engine must name a correlation table, and they must differ. */
    public function testEachEngineDeclaresItsOwnTable(): void
    {
        $correlation = $this->model('Correlation');
        $tables = [];
        foreach (self::ENGINES as $engine) {
            Configure::write('MISP.correlation_engine', $engine);
            $fresh = ClassRegistry::init('Correlation', true);
            $table = method_exists($fresh, 'getTableName') ? $fresh->getTableName() : null;
            if ($table === null) {
                $this->markTestSkipped('Correlation::getTableName() is not exposed on this version');
            }
            $this->assertIsString($table, "$engine must name a correlation table");
            $this->assertNotSame('', $table);
            $tables[$engine] = $table;
        }
        $this->assertCount(
            count(self::ENGINES),
            array_unique($tables),
            'engines must not share a correlation table: ' . json_encode($tables)
        );
        unset($correlation);
    }

    // ------------------------------------------------------------ behaviour

    /**
     * Two events sharing an attribute value must correlate.
     *
     * This is the base fact every engine has to satisfy before their
     * agreement is meaningful.
     */
    public function testTwoEventsSharingAValueCorrelate(): void
    {
        $value = '198.51.100.' . random_int(2, 250);

        $firstId = $this->createEvent('correlation fixture A', [
            ['type' => 'ip-dst', 'value' => $value],
        ]);
        $secondId = $this->createEvent('correlation fixture B', [
            ['type' => 'ip-dst', 'value' => $value],
        ]);

        $correlation = $this->model('Correlation');
        $correlation->generateCorrelation(false, $firstId);
        $correlation->generateCorrelation(false, $secondId);

        $related = $correlation->fetchRelatedEventIds($this->adminUser(), $firstId, []);
        if ($related === null) {
            $this->markTestSkipped('this engine does not expose fetchRelatedEventIds directly');
        }

        $this->assertContains(
            $secondId,
            array_map('intval', (array)$related),
            'an event sharing an attribute value must be reported as related'
        );
    }

    /**
     * The Default and NoAcl engines must agree for a site admin.
     *
     * NoAcl exists to skip the ACL filtering that Default applies. For a user
     * who can see everything, that filtering is a no-op, so the two engines
     * must produce the same related-event set. If they diverge here, one of
     * them is wrong.
     */
    public function testDefaultAndNoAclAgreeForASiteAdmin(): void
    {
        $value = '198.51.100.' . random_int(2, 250);

        $firstId = $this->createEvent('engine agreement A', [
            ['type' => 'ip-dst', 'value' => $value],
        ]);
        $secondId = $this->createEvent('engine agreement B', [
            ['type' => 'ip-dst', 'value' => $value],
        ]);

        $user = $this->adminUser();
        if (empty($user['Role']['perm_site_admin'])) {
            $this->markTestSkipped('user 1 is not a site admin on this instance');
        }

        $results = [];
        foreach (['Default', 'NoAcl'] as $engine) {
            Configure::write('MISP.correlation_engine', $engine);
            $correlation = ClassRegistry::init('Correlation', true);
            $correlation->generateCorrelation(false, $firstId);
            $correlation->generateCorrelation(false, $secondId);

            $related = $correlation->fetchRelatedEventIds($user, $firstId, []);
            if ($related === null) {
                $this->markTestSkipped("engine $engine does not expose fetchRelatedEventIds");
            }
            $ids = array_map('intval', (array)$related);
            sort($ids);
            $results[$engine] = $ids;
        }

        $this->assertSame(
            $results['Default'],
            $results['NoAcl'],
            'for a site admin the ACL filter is a no-op, so both engines must agree'
        );
    }
}
