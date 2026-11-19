<?php

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
    }
}

require_once __DIR__ . '/../Model/Galaxy.php';

class GalaxyMitreAttackLookupTest extends \PHPUnit\Framework\TestCase
{
    public function testDefaultLookupPrefersTheBundledNamespace()
    {
        $galaxy = $this->galaxyWithNamespaces([
            'mitre-attack' => 17,
            'mitre' => 42,
        ]);

        $this->assertSame(42, $galaxy->getMitreAttackGalaxyId());
    }

    public function testDefaultLookupFallsBackToTheLegacyNamespace()
    {
        $galaxy = $this->galaxyWithNamespaces(['mitre-attack' => 17]);

        $this->assertSame(17, $galaxy->getMitreAttackGalaxyId());
    }

    public function testExplicitNamespaceRestrictsLookup()
    {
        $galaxy = $this->galaxyWithNamespaces(['mitre' => 42]);

        $this->assertSame(42, $galaxy->getMitreAttackGalaxyId());
        $this->assertSame(0, $galaxy->getMitreAttackGalaxyId(
            'mitre-attack-pattern',
            'mitre-attack'
        ));
    }

    private function galaxyWithNamespaces(array $ids)
    {
        return new class ($ids) extends Galaxy {
            private $ids;

            public function __construct(array $ids)
            {
                $this->ids = $ids;
            }

            public function find($type = 'first', $query = array())
            {
                $namespace = $query['conditions']['Galaxy.namespace'];
                return isset($this->ids[$namespace])
                    ? ['Galaxy' => ['id' => $this->ids[$namespace]]]
                    : [];
            }
        };
    }
}
