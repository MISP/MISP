<?php
/**
 * RegistrationRenderer::readingOf()/matchOf(): how old a domain was at its
 * first report, what that age reads as, and which records are about the
 * value at all.
 */
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
require_once __DIR__ . '/../Model/ValueRenderers/ValueRendererBase.php';
require_once __DIR__ . '/../Model/ValueRenderers/RegistrationRenderer.php';

use PHPUnit\Framework\TestCase;

class RegistrationReadingTest extends TestCase
{
    const REPORT = 1767225600; // 2026-01-01 00:00:00 UTC

    const DAY = 86400;

    private function read($ageDays, $value = 'evil.com',
        $domain = 'evil.com', array $thresholds = array()
    ) {
        return RegistrationRenderer::readingOf(
            array(
                'domain' => $domain,
                'created' => self::REPORT - (int)round($ageDays * self::DAY),
            ),
            $value,
            self::REPORT,
            $thresholds
        );
    }

    public function testADomainRegisteredDaysBeforeItsFirstReportIsFresh()
    {
        $reading = $this->read(6);
        $this->assertSame('exact', $reading['match']);
        $this->assertSame(6, $reading['age_days']);
        $this->assertSame(RegistrationRenderer::FRESH, $reading['tier']);
        $this->assertFalse($reading['reregistered']);
        $this->assertSame(self::REPORT, $reading['first_report']);
    }

    public function tierBoundaries()
    {
        return array(
            'same day' => array(0, RegistrationRenderer::FRESH),
            'last fresh day' => array(30, RegistrationRenderer::FRESH),
            'first young day' => array(31, RegistrationRenderer::YOUNG),
            'last young day' => array(180, RegistrationRenderer::YOUNG),
            'older' => array(181, null),
            'years older' => array(4000, null),
        );
    }

    /**
     * @dataProvider tierBoundaries
     */
    public function testTheShippedThresholdsDecideTheTier($days, $tier)
    {
        $reading = $this->read($days);
        $this->assertSame($days, $reading['age_days']);
        $this->assertSame($tier, $reading['tier']);
    }

    public function testTheProfilesThresholdsReplaceTheDefaults()
    {
        $thresholds = array('fresh_days' => 7, 'young_days' => 90);
        $this->assertSame(
            RegistrationRenderer::YOUNG,
            $this->read(20, 'evil.com', 'evil.com', $thresholds)['tier']
        );
        $this->assertNull(
            $this->read(100, 'evil.com', 'evil.com', $thresholds)['tier']
        );
    }

    public function testARegistrationWithinTheToleranceAfterTheReportIsAgeZero()
    {
        foreach (array(-0.5, -1, -2) as $days) {
            $reading = $this->read($days);
            $this->assertFalse($reading['reregistered'], (string)$days);
            $this->assertSame(0, $reading['age_days'], (string)$days);
            $this->assertSame(
                RegistrationRenderer::FRESH,
                $reading['tier'],
                (string)$days
            );
        }
    }

    public function testALaterRegistrationHasNoAgeAndNoTier()
    {
        $reading = $this->read(-3);
        $this->assertTrue($reading['reregistered']);
        $this->assertNull($reading['age_days']);
        $this->assertNull($reading['tier']);
        $this->assertSame(self::REPORT + 3 * self::DAY, $reading['created']);
    }

    public function testASubdomainIsReadAgainstItsParentsRecord()
    {
        $reading = $this->read(6, 'login.mail.evil.com');
        $this->assertSame('parent', $reading['match']);
        $this->assertSame('evil.com', $reading['domain']);
        $this->assertSame(RegistrationRenderer::FRESH, $reading['tier']);
    }

    public function names()
    {
        return array(
            'exact' => array('evil.com', 'evil.com', 'exact'),
            'parent' => array('evil.com', 'a.evil.com', 'parent'),
            'case and trailing dot' => array(
                'EVIL.COM.', 'Login.Evil.Com.', 'parent',
            ),
            'a look-alike is not a child' => array(
                'evil.com', 'notevil.com', null,
            ),
            'a longer name is not a parent' => array(
                'evil.com', 'evil.com.attacker.net', null,
            ),
            'a record for a child does not answer its parent' => array(
                'a.evil.com', 'evil.com', null,
            ),
            'a bare label never matches' => array('com', 'evil.com', null),
            'a url is not a domain' => array(
                'evil.com', 'https://evil.com/login', null,
            ),
            'an email address is not a domain' => array(
                'evil.com', 'payroll@evil.com', null,
            ),
            'an ip record has no domain' => array(null, '1.2.3.4', null),
            'an empty value' => array('evil.com', '', null),
        );
    }

    /**
     * @dataProvider names
     */
    public function testWhichRecordsAreAboutTheValue($domain, $value, $match)
    {
        $this->assertSame(
            $match,
            RegistrationRenderer::matchOf($domain, $value)
        );
    }

    public function testAnInternationalisedValueMatchesItsAsciiRecord()
    {
        if (!function_exists('idn_to_ascii')) {
            $this->markTestSkipped('No intl extension.');
        }
        $this->assertSame(
            'parent',
            RegistrationRenderer::matchOf(
                'xn--mnchen-3ya.de',
                'login.münchen.de'
            )
        );
    }

    public function testNothingToReadWithoutADateOrAFirstReport()
    {
        $this->assertNull(RegistrationRenderer::readingOf(
            array('domain' => 'evil.com', 'created' => null),
            'evil.com',
            self::REPORT,
            array()
        ));
        $this->assertNull(RegistrationRenderer::readingOf(
            array('domain' => 'evil.com', 'created' => self::REPORT),
            'evil.com',
            null,
            array()
        ));
        $this->assertNull($this->read(6, 'other.org'));
    }

    private function whois($domain, $created)
    {
        return array(
            'name' => 'whois',
            'module' => 'rdap',
            'ran_at' => self::REPORT,
            'attributes' => array(
                array('relation' => 'domain', 'value' => $domain),
                array(
                    'relation' => 'creation-date',
                    'value' => gmdate('Y-m-d\\TH:i:s+00:00', $created),
                ),
            ),
        );
    }

    public function testPrepareReadsEachRecordAgainstTheFirstReport()
    {
        $renderer = new RegistrationRenderer();
        $data = $renderer->prepare(
            array($this->whois('evil.com', self::REPORT - 6 * self::DAY)),
            array(),
            array(
                'value' => 'login.evil.com',
                'first_report' => self::REPORT,
                'now' => self::REPORT + 100 * self::DAY,
                'thresholds' => array('registration' => array(
                    'fresh_days' => 30, 'young_days' => 180,
                )),
            )
        );
        $record = $data['headline'];
        $this->assertSame(106, $record['age_days']);
        $this->assertSame(6, $record['reading']['age_days']);
        $this->assertSame('parent', $record['reading']['match']);
        $this->assertSame(RegistrationRenderer::FRESH,
            $record['reading']['tier']);
        $this->assertSame(array('fresh_days' => 30, 'young_days' => 180),
            $data['thresholds']);
    }

    public function testWithoutFactsPrepareDrawsAsBefore()
    {
        $renderer = new RegistrationRenderer();
        $data = $renderer->prepare(
            array($this->whois('evil.com', self::REPORT)),
            array()
        );
        $this->assertNull($data['headline']['reading']);
        $this->assertNull($data['thresholds']);
        $this->assertIsInt($data['headline']['age_days']);
    }

    public function testThresholdsComeFromTheProfilesEntry()
    {
        $entry = array(
            'id' => 'enrichment.registration_age',
            'enabled' => true,
            'config' => array('fresh_days' => 7),
        );
        $this->assertSame(
            array('fresh_days' => 7, 'young_days' => 180),
            RegistrationRenderer::thresholdsFrom(
                array('parameters' => array('signals' => array($entry)))
            )
        );
        $this->assertSame(
            array('fresh_days' => 7, 'young_days' => 180),
            RegistrationRenderer::thresholdsFrom(
                array('signals' => array($entry))
            )
        );
        $entry['enabled'] = false;
        $this->assertNull(RegistrationRenderer::thresholdsFrom(
            array('parameters' => array('signals' => array($entry)))
        ));
        $this->assertNull(RegistrationRenderer::thresholdsFrom(
            array('parameters' => array('signals' => array()))
        ));
        $this->assertNull(RegistrationRenderer::thresholdsFrom(null));
    }
}
