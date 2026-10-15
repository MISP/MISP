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
        if (count($arguments) === 1) {
            return $singular;
        }
        return vsprintf($singular, array_slice($arguments, 1));
    }
}
require_once __DIR__ . '/../Lib/Tools/ComplexTypeTool.php';
require_once __DIR__ . '/../Lib/Tools/AttributeValidationTool.php';
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueTypeGuessTool.php';

use PHPUnit\Framework\TestCase;

class ValueTypeGuessToolTest extends TestCase
{
    const KNOWN = array(
        'ip-src', 'ip-dst', 'domain', 'hostname', 'url', 'link', 'filename',
        'md5', 'imphash', 'x509-fingerprint-md5', 'ja3-fingerprint-md5',
        'vulnerability', 'AS', 'email', 'email-src', 'email-dst',
        'target-email', 'whois-registrant-email', 'regkey', 'user-agent',
        'mutex', 'text', 'comment', 'phone-number', 'port',
    );

    public function testReadsCleanIndicators(): void
    {
        $this->assertSame(
            array('ip-dst', 'ip-src'),
            ValueTypeGuessTool::read('8.8.8.8', self::KNOWN)
        );
        $this->assertSame(
            array('domain', 'filename'),
            ValueTypeGuessTool::read(
                'evil-domain.com',
                self::KNOWN,
                array('com')
            )
        );
        $this->assertSame(
            array(
                'md5', 'imphash', 'x509-fingerprint-md5',
                'ja3-fingerprint-md5',
            ),
            ValueTypeGuessTool::read(
                'f1d3ff8443297732862df21dc4e57262',
                self::KNOWN
            )
        );
        $this->assertSame(
            array('vulnerability'),
            ValueTypeGuessTool::read('CVE-2024-3400', self::KNOWN)
        );
        $this->assertSame(
            array('AS'),
            ValueTypeGuessTool::read('AS13335', self::KNOWN)
        );
    }

    public function testDefaultTypeComesFirst(): void
    {
        $types = ValueTypeGuessTool::read('john@example.org', self::KNOWN);
        $this->assertSame('email-src', $types[0]);
        $this->assertContains('whois-registrant-email', $types);
    }

    public function testPseudoAndUnknownTypesAreDropped(): void
    {
        $types = ValueTypeGuessTool::read('8.8.8.8', self::KNOWN);
        $this->assertNotContains('ip-src/ip-dst', $types);
        $this->assertSame(
            array('ip-dst'),
            ValueTypeGuessTool::read('8.8.8.8', array('ip-dst'))
        );
    }

    public function testRewrittenValueReadsAsNothing(): void
    {
        $this->assertSame(
            array(),
            ValueTypeGuessTool::read('1.2.3.4:443', self::KNOWN)
        );
        $this->assertSame(
            array(),
            ValueTypeGuessTool::read(
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                self::KNOWN
            )
        );
    }

    public function testUnreadableValueReadsAsNothing(): void
    {
        $this->assertSame(
            array(),
            ValueTypeGuessTool::read('13335', self::KNOWN)
        );
        $this->assertSame(array(), ValueTypeGuessTool::read('', self::KNOWN));
    }

    public function testRankSplitsFitsAnyTextAndFails(): void
    {
        $ranked = ValueTypeGuessTool::rank(
            'evil-domain.com',
            array('ip-dst', 'domain', 'text', 'hostname', 'md5', 'comment')
        );
        $this->assertSame(array('domain', 'hostname'), $ranked['fits']);
        $this->assertSame(array('text', 'comment'), $ranked['any_text']);
        $this->assertSame(array('ip-dst', 'md5'), $ranked['fails']);
    }

    public function testRankPutsAsFirstForBareNumber(): void
    {
        $ranked = ValueTypeGuessTool::rank(
            '13335',
            array('ip-dst', 'AS', 'text')
        );
        $this->assertSame(array('AS'), $ranked['fits']);
        $this->assertSame(array('ip-dst'), $ranked['fails']);
    }

    public function testUnknownTypeIsRefused(): void
    {
        $this->assertFalse(ValueTypeGuessTool::accepts('ip', '8.8.8.8'));
        $ranked = ValueTypeGuessTool::rank('8.8.8.8', array('ip'));
        $this->assertSame(array('ip'), $ranked['fails']);
    }
}
