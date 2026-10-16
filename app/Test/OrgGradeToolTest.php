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
        $arguments = func_get_args();
        return vsprintf($singular, array_slice($arguments, 1));
    }
}
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueTrustTool.php';
require_once __DIR__ . '/../Lib/Tools/AnalystProfile/OrgGradeTool.php';

use PHPUnit\Framework\TestCase;

class OrgGradeToolTest extends TestCase
{
    const UUID = '5a7c4b7e-1b2c-4d3e-8f90-0123456789ab';

    private function resolution($via, array $parameters = [], array $extra = [])
    {
        return [
            'profile' => $extra + [
                'id' => 7,
                'name' => 'SOC Triage',
                'parameters' => $parameters,
            ],
            'via' => $via,
        ];
    }

    public function testOwnProfileIsWrittenInPlace()
    {
        $target = OrgGradeTool::target($this->resolution('user'));
        $this->assertSame('own', $target['mode']);
        $this->assertSame(['id' => 7, 'name' => 'SOC Triage', 'via' => 'user'], $target['profile']);
    }

    public function testEveryOtherScopeForks()
    {
        foreach (['user_selection', 'org', 'org_selection', 'instance'] as $via) {
            $target = OrgGradeTool::target($this->resolution($via));
            $this->assertSame('fork', $target['mode'], $via);
            $this->assertSame($via, $target['profile']['via']);
        }
    }

    public function testNothingToGradeWithoutAProfileInForce()
    {
        $this->assertSame('none', OrgGradeTool::target(['profile' => null, 'via' => null])['mode']);
        $broken = $this->resolution('user', [], ['parameters_unparseable' => true]);
        $this->assertSame('none', OrgGradeTool::target($broken)['mode']);
    }

    public function testReadingCarriesTheGradesInForceAndTheirWords()
    {
        $reading = OrgGradeTool::reading($this->resolution('org', [
            'reference' => ['org_trust' => [strtoupper(self::UUID) => 'b', 'other' => 'Z']],
        ]));
        $this->assertSame([self::UUID => 'B'], $reading['grades']);
        $this->assertSame('Usually reliable', $reading['labels']['B']);
        $this->assertSame('No opinion recorded', $reading['labels']['unrated']);
        $this->assertSame(1.25, $reading['scale']['A']);
        $this->assertSame(0.0, $reading['scale']['G']);
        $this->assertSame('B', OrgGradeTool::gradeOf($reading['grades'], strtoupper(self::UUID)));
        $this->assertNull(OrgGradeTool::gradeOf($reading['grades'], ''));
    }

    public function testParseAcceptsGradesAndUnrated()
    {
        $this->assertSame(['ok' => true, 'grade' => 'C'], OrgGradeTool::parse('c'));
        $this->assertSame(['ok' => true, 'grade' => null], OrgGradeTool::parse('unrated'));
        $this->assertFalse(OrgGradeTool::parse('H')['ok']);
        $this->assertFalse(OrgGradeTool::parse('')['ok']);
        $this->assertFalse(OrgGradeTool::parse(['A'])['ok']);
    }

    public function testApplyAddsToAnEmptyDocument()
    {
        $applied = OrgGradeTool::apply([], self::UUID, 'A');
        $this->assertSame([self::UUID => 'A'], $applied['parameters']['reference']['org_trust']);
        $this->assertNull($applied['previous']);
        $this->assertTrue($applied['changed']);
    }

    public function testApplyReplacesAnEntryWhateverItsCase()
    {
        $parameters = [
            'signals' => ['x' => 1],
            'reference' => [
                'org_trust' => [strtoupper(self::UUID) => 'd', 'f00' => 'B'],
                'org_trust_scale' => ['A' => 2],
            ],
        ];
        $applied = OrgGradeTool::apply($parameters, self::UUID, 'G');
        $this->assertSame(['f00' => 'B', self::UUID => 'G'], $applied['parameters']['reference']['org_trust']);
        $this->assertSame(['A' => 2], $applied['parameters']['reference']['org_trust_scale']);
        $this->assertSame(['x' => 1], $applied['parameters']['signals']);
        $this->assertSame('D', $applied['previous']);
        $this->assertTrue($applied['changed']);
    }

    public function testNoOpinionRemovesTheEntry()
    {
        $parameters = ['reference' => ['org_trust' => [self::UUID => 'B']]];
        $applied = OrgGradeTool::apply($parameters, self::UUID, null);
        $this->assertSame([], $applied['parameters']['reference']['org_trust']);
        $this->assertSame('B', $applied['previous']);
        $this->assertTrue($applied['changed']);
    }

    public function testTheSameGradeIsNotAChange()
    {
        $parameters = ['reference' => ['org_trust' => [self::UUID => 'b']]];
        $this->assertFalse(OrgGradeTool::apply($parameters, self::UUID, 'B')['changed']);
        $this->assertFalse(OrgGradeTool::apply([], self::UUID, null)['changed']);
    }
}
