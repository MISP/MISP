<?php
/**
 * enrichment.registration_age: one row from the newest graded registration
 * answer, read at the value's first report.
 */
if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
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
        $args = func_get_args();
        array_shift($args);
        return $args ? vsprintf($singular, $args) : $singular;
    }
}
if (!class_exists('MispAttribute')) {
    class MispAttribute
    {
        const NON_CORRELATING_TYPES = ['comment', 'text'];
    }
}
require_once __DIR__ . '/../Model/ValueSignals/ValueSignalBase.php';
require_once __DIR__ . '/../Model/ValueSignals/EnrichmentRegistrationAge.php';
require_once __DIR__ . '/../Model/ValueRenderers/ValueRendererBase.php';
require_once __DIR__ . '/../Model/ValueRenderers/RegistrationRenderer.php';
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueSignalLoader.php';
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueRendererTool.php';

use PHPUnit\Framework\TestCase;

class EnrichmentRegistrationAgeTest extends TestCase
{
    const REPORT = 1767225600; // 2026-01-01 00:00:00 UTC

    const NOW = 1768435200; // 2026-01-15

    const DAY = 86400;

    private $signal;

    protected function setUp(): void
    {
        $this->signal = new EnrichmentRegistrationAge();
    }

    /** A stored run holding one `whois` object, as `rdap` returns it. */
    private function answer($module, $createdDaysBeforeReport,
        $domain = 'evil.com', $ranAt = null
    ) {
        $created = self::REPORT
            - (int)round($createdDaysBeforeReport * self::DAY);
        return array(
            'state' => 'ok',
            'module' => $module,
            'ran_at' => $ranAt === null ? self::NOW - self::DAY : $ranAt,
            'objects' => array(array(
                'name' => 'whois',
                'attributes' => array(
                    array('relation' => 'domain', 'value' => $domain),
                    array(
                        'relation' => 'creation-date',
                        'value' => gmdate('Y-m-d\TH:i:s+00:00', $created),
                    ),
                    array('relation' => 'registrar', 'value' => 'R'),
                ),
            )),
        );
    }

    private function context(array $runs, array $grades,
        $value = 'evil.com', $firstReport = self::REPORT
    ) {
        $scale = array('A' => 1.25, 'B' => 1.1, 'C' => 1.0, 'G' => 0.0);
        $factors = array();
        foreach ($runs as $run) {
            $module = $run['module'];
            $factors[$module] = isset($grades[$module])
                ? $scale[$grades[$module]]
                : 0.0;
        }
        return array(
            'value' => $value,
            'now' => self::NOW,
            'as_of' => '2026-01-15',
            'occurrences' => array('oldest' => $firstReport),
            'enrichment' => array(
                'runs' => $runs,
                'trust' => array(
                    'grades' => $grades,
                    'factors' => $factors,
                    'in_force' => true,
                ),
            ),
        );
    }

    private function evaluate(array $context, array $config = array())
    {
        return $this->signal->evaluate($context, $config + array(
            'points' => array('fresh' => 12, 'young' => 4),
            'config' => array('fresh_days' => 30, 'young_days' => 180),
        ));
    }

    public function testAFreshDomainDrawsTheFreshPoints()
    {
        $row = $this->evaluate($this->context(
            array($this->answer('rdap', 6)),
            array('rdap' => 'C')
        ));
        $this->assertSame(12, $row['contribution']);
        $this->assertSame(
            'Registered 6 days before it was first reported',
            $row['signal']
        );
        $this->assertStringContainsString('rdap · created 2025-12-26',
            $row['evidence']);
        $this->assertStringContainsString('graded C', $row['evidence']);
        $this->assertSame('lean', $row['axis']);
        $this->assertArrayNotHasKey('voice', $row);
    }

    public function testAYoungDomainSupportsButNeverContests()
    {
        $row = $this->evaluate($this->context(
            array($this->answer('rdap', 100)),
            array('rdap' => 'C')
        ));
        $this->assertSame(4, $row['contribution']);
        $this->assertTrue($row['voice']);
        $this->assertSame(
            'Registered 3 months before it was first reported',
            $row['signal']
        );
    }

    public function testAnOlderDomainIsSilent()
    {
        $this->assertNull($this->evaluate($this->context(
            array($this->answer('rdap', 900)),
            array('rdap' => 'C')
        )));
    }

    public function testASubdomainNamesTheDomainItSitsUnder()
    {
        $row = $this->evaluate($this->context(
            array($this->answer('rdap', 6)),
            array('rdap' => 'C'),
            'login.evil.com'
        ));
        $this->assertSame(
            'evil.com was registered 6 days before this was first'
                . ' reported',
            $row['signal']
        );
    }

    public function testTheModulesGradeScalesThePoints()
    {
        $row = $this->evaluate($this->context(
            array($this->answer('rdap', 6)),
            array('rdap' => 'B')
        ));
        $this->assertSame(13, $row['contribution']);
    }

    public function testAnUngradedAnswerThatWouldScoreIsSetAside()
    {
        $out = $this->evaluate($this->context(
            array($this->answer('rdap', 6)),
            array()
        ));
        $this->assertSame(array(), $out['rows']);
        $this->assertSame('ungraded', $out['not_counted'][0]['kind']);
        $this->assertSame('policy', $out['not_counted'][0]['reason']);
    }

    public function testAnUngradedOldAnswerSaysNothing()
    {
        $this->assertNull($this->evaluate($this->context(
            array($this->answer('rdap', 900)),
            array()
        )));
    }

    public function testALaterRegistrationIsSetAside()
    {
        $out = $this->evaluate($this->context(
            array($this->answer('rdap', -40)),
            array('rdap' => 'C')
        ));
        $this->assertSame(array(), $out['rows']);
        $this->assertSame('reregistered', $out['not_counted'][0]['kind']);
        $this->assertStringContainsString('2026-02-10',
            $out['not_counted'][0]['note']);
        $this->assertStringContainsString('2026-01-01',
            $out['not_counted'][0]['note']);
    }

    public function testTheNewestGradedAnswerWinsAndTheOthersAreNamed()
    {
        $row = $this->evaluate($this->context(
            array(
                $this->answer('securitytrails', 400, 'evil.com',
                    self::NOW - 30 * self::DAY),
                $this->answer('virustotal', 6, 'evil.com',
                    self::NOW - 10 * self::DAY),
                $this->answer('rdap', 6, 'evil.com', self::NOW - self::DAY),
                $this->answer('validin', 3, 'evil.com', self::NOW),
            ),
            array('rdap' => 'C', 'virustotal' => 'C',
                'securitytrails' => 'C')
        ));
        $this->assertStringStartsWith('rdap ·', $row['evidence']);
        $this->assertStringEndsWith(
            '; rdap, virustotal agree; securitytrails says 2024-11-27',
            $row['evidence']
        );
        $this->assertStringNotContainsString('validin', $row['evidence']);
    }

    public function testTheProfilesThresholdsApply()
    {
        $row = $this->evaluate(
            $this->context(array($this->answer('rdap', 20)),
                array('rdap' => 'C')),
            array('config' => array('fresh_days' => 7, 'young_days' => 90))
        );
        $this->assertSame(4, $row['contribution']);
    }

    public function testNothingToSayWithoutAnAnswerOrAFirstReport()
    {
        $this->assertNull($this->evaluate(
            $this->context(array(), array('rdap' => 'C'))
        ));
        $this->assertNull($this->evaluate($this->context(
            array($this->answer('rdap', 6)),
            array('rdap' => 'C'),
            'evil.com',
            null
        )));
        $this->assertNull($this->evaluate($this->context(
            array($this->answer('rdap', 6, 'other.org')),
            array('rdap' => 'C')
        )));
    }

    public function testTheDefaultsAreTheRenderers()
    {
        $config = $this->signal->getConfig();
        $this->assertSame(
            RegistrationRenderer::THRESHOLDS,
            array(
                'fresh_days' => $config['config_schema']['fresh_days']
                    ['default'],
                'young_days' => $config['config_schema']['young_days']
                    ['default'],
            )
        );
    }
}
