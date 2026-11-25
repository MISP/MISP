<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

/**
 * AppController::_orgcNamePullRuleConditions() unit tests.
 *
 * The helper is the single implementation of the orgc_name OR/NOT pull-rule
 * parsing that AnalystDataController::indexMinimal and
 * CollectionsController::indexMinimal run a sync peer's filters through, so the
 * cases below pin both column shapes it is called with: orgc_uuid / uuid
 * (analyst data) and Collection.orgc_id / id (collections).
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB - the convention used by every
 * other test under app/Test/ (see DashboardCsvExportTest, which drives a
 * controller method through reflection the same way).
 *
 * Load-order contract - a full-suite run includes every test file before the
 * first test runs, in sorted filename order:
 *   - this file must sort AFTER BetterSecurityComponentTest, whose Controller
 *     stub carries the members that test needs, so that stub wins the guard
 *     below;
 *   - it must sort BEFORE DashboardCsvExportTest, which declares an empty
 *     AppController stub - once that stub exists the real AppController can no
 *     longer be loaded and these tests skip themselves rather than fatal.
 * Renaming this file can silently break either end.
 */

if (!function_exists('__')) {
    // Fake translation function
    function __($singular, $args = null)
    {
        $arguments = func_get_args();
        return vsprintf($singular, array_slice($arguments, 1));
    }
}

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

if (!class_exists('Controller', false)) {
    class Controller
    {
    }
}

if (!class_exists('AppController', false)) {
    require_once __DIR__ . '/../Controller/AppController.php';
}

if (!class_exists('StubOrgcResolver', false)) {
    /**
     * Stands in for the Organisation model: the helper only ever calls
     * fetchOrg(), which hands back the org row or false for an unknown name.
     */
    class StubOrgcResolver
    {
        private $orgs;

        public function __construct(array $orgs)
        {
            $this->orgs = $orgs;
        }

        public function fetchOrg($name)
        {
            return isset($this->orgs[$name]) ? $this->orgs[$name] : false;
        }
    }
}

class ControllerOrgcPullRuleTest extends TestCase
{
    /** @var StubOrgcResolver */
    private $orgs;

    protected function setUp(): void
    {
        $realAppController = realpath(__DIR__ . '/../Controller/AppController.php');
        $loadedFrom = (new ReflectionClass('AppController'))->getFileName();
        if ($loadedFrom === false || realpath($loadedFrom) !== $realAppController) {
            $this->markTestSkipped('AppController was declared as a stub by another test file in this run.');
        }
        $this->orgs = new StubOrgcResolver(array(
            'OrgA' => array('id' => 3, 'uuid' => 'uuid-a'),
            'OrgB' => array('id' => 7, 'uuid' => 'uuid-b'),
        ));
    }

    /**
     * @param array|string $orgcNames
     * @param string $filterName
     * @param string $orgField
     * @return array|false
     */
    private function conditions($orgcNames, $filterName = 'orgc_uuid', $orgField = 'uuid')
    {
        $controller = (new ReflectionClass('AppController'))->newInstanceWithoutConstructor();
        $method = new ReflectionMethod('AppController', '_orgcNamePullRuleConditions');
        $method->setAccessible(true);
        return $method->invoke($controller, $orgcNames, $this->orgs, $filterName, $orgField);
    }

    public function testNoNamesYieldNoConditions()
    {
        $this->assertSame(array(), $this->conditions(array()));
    }

    public function testOrRuleBuildsAnOrCondition()
    {
        $this->assertSame(
            array('OR' => array(array('orgc_uuid' => 'uuid-a'), array('orgc_uuid' => 'uuid-b'))),
            $this->conditions(array('OrgA', 'OrgB'))
        );
    }

    public function testNotRuleBuildsAnAndCondition()
    {
        $this->assertSame(
            array(array('AND' => array(array('orgc_uuid !=' => 'uuid-a')))),
            $this->conditions(array('!OrgA'))
        );
    }

    public function testOrAndNotRulesCombine()
    {
        $this->assertSame(
            array(
                'OR' => array(array('orgc_uuid' => 'uuid-a')),
                0 => array('AND' => array(array('orgc_uuid !=' => 'uuid-b'))),
            ),
            $this->conditions(array('OrgA', '!OrgB'))
        );
    }

    public function testUnresolvedNotRuleImposesNoRestriction()
    {
        $this->assertSame(array(), $this->conditions(array('!Ghost')));
    }

    public function testUnresolvedOrRuleSignalsNoMatch()
    {
        $this->assertFalse($this->conditions(array('Ghost')));
        $this->assertFalse($this->conditions(array('Ghost', '!OrgA')));
    }

    public function testOrRuleSurvivesAnUnresolvedSibling()
    {
        $this->assertSame(
            array('OR' => array(array('orgc_uuid' => 'uuid-a'))),
            $this->conditions(array('OrgA', 'Ghost'))
        );
    }

    public function testSingleStringIsAccepted()
    {
        $this->assertSame(
            array('OR' => array(array('orgc_uuid' => 'uuid-a'))),
            $this->conditions('OrgA')
        );
    }

    public function testNonStringAndEmptyEntriesAreSkipped()
    {
        $this->assertSame(
            array('OR' => array(array('orgc_uuid' => 'uuid-a'))),
            $this->conditions(array('', null, 42, 'OrgA'))
        );
        // Nothing usable was supplied, so no allow-list was ever asserted.
        $this->assertSame(array(), $this->conditions(array('', null)));
    }

    public function testCollectionColumnAndFieldArePluggedThrough()
    {
        $this->assertSame(
            array('OR' => array(array('Collection.orgc_id' => 3))),
            $this->conditions(array('OrgA'), 'Collection.orgc_id', 'id')
        );
        $this->assertSame(
            array(array('AND' => array(array('Collection.orgc_id !=' => 3)))),
            $this->conditions(array('!OrgA'), 'Collection.orgc_id', 'id')
        );
    }
}
