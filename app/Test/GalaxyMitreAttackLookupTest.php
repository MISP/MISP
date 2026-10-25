<?php
/**
 * Connectionless tests for resolving the default MITRE ATT&CK galaxy.
 */

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

class GalaxyMitreAttackLookupModel extends Galaxy
{
    public $lastQuery;

    private $findResult;

    public function __construct($findResult)
    {
        $this->findResult = $findResult;
    }

    public function find($type = 'first', $query = array())
    {
        $this->lastQuery = $query;
        return $this->findResult;
    }
}

class GalaxyMitreAttackLookupTest extends \PHPUnit\Framework\TestCase
{
    public function testDefaultLookupUsesTheStableGalaxyType()
    {
        $model = new GalaxyMitreAttackLookupModel(array(
            'Galaxy' => array('id' => 47),
        ));

        $this->assertSame(47, $model->getMitreAttackGalaxyId());
        $conditions = $model->lastQuery['conditions'];
        $this->assertSame(
            'mitre-attack-pattern',
            $conditions['Galaxy.type']
        );
        $this->assertArrayNotHasKey('Galaxy.namespace', $conditions);
    }

    public function testExplicitNamespaceStillFiltersTheLookup()
    {
        $model = new GalaxyMitreAttackLookupModel(array(
            'Galaxy' => array('id' => 12),
        ));

        $this->assertSame(
            12,
            $model->getMitreAttackGalaxyId(
                'mitre-attack-pattern',
                'mitre-attack'
            )
        );
        $conditions = $model->lastQuery['conditions'];
        $this->assertSame('mitre-attack', $conditions['Galaxy.namespace']);
    }

    public function testMissingGalaxyReturnsZero()
    {
        $model = new GalaxyMitreAttackLookupModel(array());

        $this->assertSame(0, $model->getMitreAttackGalaxyId());
    }
}
