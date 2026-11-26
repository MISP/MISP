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
    public function testFindsTheBundledGalaxyUnderTheCurrentNamespace()
    {
        $galaxy = $this->galaxyWithRows([
            $this->row(42, 'mitre', true, 20),
        ]);

        $this->assertSame(42, $galaxy->getMitreAttackGalaxyId());
    }

    public function testFindsTheBundledGalaxyUnderTheLegacyNamespace()
    {
        $galaxy = $this->galaxyWithRows([
            $this->row(17, 'mitre-attack', true, 19),
        ]);

        $this->assertSame(17, $galaxy->getMitreAttackGalaxyId());
    }

    public function testIgnoresACustomGalaxyOfTheSameType()
    {
        $galaxy = $this->galaxyWithRows([
            $this->row(42, 'mitre', true, 20),
            $this->row(99, 'mitre', false, 1790000000),
        ]);

        $this->assertSame(42, $galaxy->getMitreAttackGalaxyId());
    }

    public function testReturnsZeroWithoutABundledGalaxy()
    {
        $galaxy = $this->galaxyWithRows([
            $this->row(99, 'mitre', false, 1790000000),
        ]);

        $this->assertSame(0, $galaxy->getMitreAttackGalaxyId());
    }

    public function testExplicitNamespaceRestrictsLookup()
    {
        $galaxy = $this->galaxyWithRows([
            $this->row(42, 'mitre', true, 20),
        ]);

        $this->assertSame(42, $galaxy->getMitreAttackGalaxyId(
            'mitre-attack-pattern',
            'mitre'
        ));
        $this->assertSame(0, $galaxy->getMitreAttackGalaxyId(
            'mitre-attack-pattern',
            'mitre-attack'
        ));
    }

    private function row($id, $namespace, $default, $version)
    {
        return [
            'id' => $id,
            'type' => 'mitre-attack-pattern',
            'namespace' => $namespace,
            'default' => $default,
            'version' => $version,
        ];
    }

    private function galaxyWithRows(array $rows)
    {
        return new class ($rows) extends Galaxy {
            private $rows;

            public function __construct(array $rows)
            {
                $this->rows = $rows;
            }

            public function find($type = 'first', $query = array())
            {
                $rows = array_filter(
                    $this->rows,
                    function ($row) use ($query) {
                        foreach ($query['conditions'] as $field => $value) {
                            $column = substr($field, strlen('Galaxy.'));
                            if ($row[$column] != $value) {
                                return false;
                            }
                        }
                        return true;
                    }
                );
                usort($rows, function ($a, $b) {
                    return [$b['version'], $a['id']]
                        <=> [$a['version'], $b['id']];
                });
                return empty($rows) ? [] : ['Galaxy' => reset($rows)];
            }
        };
    }
}
