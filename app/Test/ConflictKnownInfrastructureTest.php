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
        $arguments = array_slice(func_get_args(), 1);
        return empty($arguments) ? $singular : vsprintf($singular, $arguments);
    }
}
require_once __DIR__ . '/../Lib/Tools/WarninglistCategory.php';
require_once __DIR__ . '/../Model/ValueEscalations/ValueEscalationBase.php';
require_once __DIR__ . '/../Model/ValueEscalations/'
    . 'ConflictKnownInfrastructure.php';

use PHPUnit\Framework\TestCase;

class ConflictKnownInfrastructureTest extends TestCase
{
    private function context($threat, $benign)
    {
        return array(
            'warninglist' => array('hits' => array(
                array('name' => 'CDN ranges', 'category' => 'known'),
            )),
            'stances' => array(
                'threat_orgs' => $threat,
                'benign_orgs' => $benign,
                'orgs' => $threat + $benign,
            ),
        );
    }

    public function testOrganisationsCallingItHarmlessDoNotFireIt()
    {
        $rule = new ConflictKnownInfrastructure();
        $this->assertNull($rule->fires($this->context(0, 3), array()));
        $this->assertNull($rule->fires($this->context(2, 4), array()));
    }

    public function testEnoughOrganisationsFlaggingItFireIt()
    {
        $rule = new ConflictKnownInfrastructure();
        $fired = $rule->fires($this->context(3, 5), array());
        $this->assertNotNull($fired);
        $this->assertStringContainsString('3 organisations report it',
            $fired['prose']);
        $this->assertStringContainsString('3 organisations flag it',
            $fired['evidence']);
    }

    public function testWithoutStancesItCountsTheOrganisationsFlaggingIt()
    {
        $rule = new ConflictKnownInfrastructure();
        $context = $this->context(0, 0);
        unset($context['stances']);
        $context['orgs'] = array(
            array('id' => 1, 'to_ids_yes' => 1),
            array('id' => 2, 'to_ids_yes' => 0, 'to_ids_no' => 1),
            array('id' => 3, 'to_ids_yes' => 2),
        );
        $entry = array('when' => array('min_independent_reports' => 2));
        $this->assertNotNull($rule->fires($context, $entry));
        $entry['when']['min_independent_reports'] = 3;
        $this->assertNull($rule->fires($context, $entry));
    }

    public function testOnlyTheConfiguredCategoryMatches()
    {
        $rule = new ConflictKnownInfrastructure();
        $entry = array('when' => array(
            'warninglist_category' => 'false_positive',
        ));
        $this->assertNull($rule->fires($this->context(5, 0), $entry));
    }
}
