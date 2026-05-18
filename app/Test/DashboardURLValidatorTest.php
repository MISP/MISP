<?php
/**
 * DashboardURLValidator unit tests (DD-03 contract).
 *
 * Pure PHPUnit — follows the convention used by every other test
 * under app/Test/: no CakePHP bootstrap, no DB. The validator's
 * only framework dependency is Configure::read('MISP.baseurl'),
 * which we stub at the top of this file (mirroring how
 * EventTemplateValidatorTest stubs App).
 */

require_once __DIR__ . '/../Vendor/autoload.php';
require_once __DIR__ . '/../Lib/Dashboard/Tools/DashboardURLValidator.php';

if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function reset()
        {
            self::$values = array();
        }
    }
}

use PHPUnit\Framework\TestCase;

class DashboardURLValidatorTest extends TestCase
{
    protected function setUp(): void
    {
        Configure::reset();
        Configure::write('MISP.baseurl', 'https://misp.example.com');
    }

    // -------- relative URLs --------

    public function testRelativePathAllowed(): void
    {
        $this->assertSame(
            '/events/index/tag:tlp:red',
            DashboardURLValidator::validate('/events/index/tag:tlp:red')
        );
    }

    public function testRelativeWithoutLeadingSlashAllowed(): void
    {
        $this->assertSame(
            'events/index',
            DashboardURLValidator::validate('events/index')
        );
    }

    public function testQueryOnlyAllowed(): void
    {
        $this->assertSame(
            '?filter=foo',
            DashboardURLValidator::validate('?filter=foo')
        );
    }

    public function testFragmentOnlyAllowed(): void
    {
        $this->assertSame('#section', DashboardURLValidator::validate('#section'));
    }

    public function testMispFilterSyntaxAllowed(): void
    {
        // `tag:tlp:red` looks like a custom-scheme URL to parse_url
        // but is a valid MISP filter path. The validator must not
        // treat it as absolute.
        $this->assertSame(
            'tag:tlp:red',
            DashboardURLValidator::validate('tag:tlp:red')
        );
        $this->assertSame(
            'events/index/tag:tlp:red',
            DashboardURLValidator::validate('events/index/tag:tlp:red')
        );
    }

    // -------- absolute URLs (same host) --------

    public function testAbsoluteSameHostAllowed(): void
    {
        $this->assertSame(
            'https://misp.example.com/events/index',
            DashboardURLValidator::validate('https://misp.example.com/events/index')
        );
    }

    public function testAbsoluteSameHostMixedCaseAllowed(): void
    {
        $this->assertSame(
            'https://MISP.example.com/events/index',
            DashboardURLValidator::validate('https://MISP.example.com/events/index')
        );
    }

    public function testProtocolRelativeSameHostAllowed(): void
    {
        $this->assertSame(
            '//misp.example.com/events/index',
            DashboardURLValidator::validate('//misp.example.com/events/index')
        );
    }

    // -------- absolute URLs (off-host / scheme / port) --------

    public function testAbsoluteOffHostRejected(): void
    {
        $this->assertNull(
            DashboardURLValidator::validate('https://evil.example.com/events/index')
        );
    }

    public function testProtocolRelativeOffHostRejected(): void
    {
        $this->assertNull(
            DashboardURLValidator::validate('//evil.example.com/events/index')
        );
    }

    public function testSchemeMismatchRejected(): void
    {
        // baseurl is https://; http:// to the same host is a
        // mixed-content surface that MISP shouldn't help create.
        $this->assertNull(
            DashboardURLValidator::validate('http://misp.example.com/events/index')
        );
    }

    public function testPortMismatchRejected(): void
    {
        $this->assertNull(
            DashboardURLValidator::validate('https://misp.example.com:8443/events/index')
        );
    }

    public function testExplicitPortMatchAllowed(): void
    {
        Configure::write('MISP.baseurl', 'https://misp.example.com:8443');
        $this->assertSame(
            'https://misp.example.com:8443/events/index',
            DashboardURLValidator::validate('https://misp.example.com:8443/events/index')
        );
    }

    // -------- dangerous schemes --------

    public function testJavascriptSchemeRejected(): void
    {
        $this->assertNull(DashboardURLValidator::validate('javascript:alert(1)'));
        $this->assertNull(DashboardURLValidator::validate('JAVASCRIPT:alert(1)'));
        // leading whitespace must not bypass
        $this->assertNull(DashboardURLValidator::validate("  javascript:alert(1)"));
        $this->assertNull(DashboardURLValidator::validate("\tjavascript:alert(1)"));
    }

    public function testDataSchemeRejected(): void
    {
        $this->assertNull(
            DashboardURLValidator::validate('data:text/html,<script>alert(1)</script>')
        );
    }

    public function testVbscriptSchemeRejected(): void
    {
        $this->assertNull(DashboardURLValidator::validate('vbscript:msgbox(1)'));
    }

    public function testFileSchemeRejected(): void
    {
        $this->assertNull(DashboardURLValidator::validate('file:///etc/passwd'));
    }

    // -------- malformed / hostile inputs --------

    public function testEmptyStringRejected(): void
    {
        $this->assertNull(DashboardURLValidator::validate(''));
    }

    public function testNullRejected(): void
    {
        $this->assertNull(DashboardURLValidator::validate(null));
    }

    public function testNonStringRejected(): void
    {
        $this->assertNull(DashboardURLValidator::validate(42));
        $this->assertNull(DashboardURLValidator::validate(array('href' => '/foo')));
        $this->assertNull(DashboardURLValidator::validate(false));
    }

    public function testControlCharsRejected(): void
    {
        // NUL anywhere kills it.
        $this->assertNull(DashboardURLValidator::validate("/events/index\x00"));
        $this->assertNull(DashboardURLValidator::validate("\x00/events/index"));
        // Line feed / carriage return — header-injection risk.
        $this->assertNull(DashboardURLValidator::validate("/events/index\n"));
        $this->assertNull(DashboardURLValidator::validate("/events/index\r"));
        // Tab.
        $this->assertNull(DashboardURLValidator::validate("/events/index\t"));
        // DEL.
        $this->assertNull(DashboardURLValidator::validate("/events/index\x7f"));
    }

    // -------- no baseurl configured --------

    public function testNoBaseurlConfiguredAllowsRelativeRejectsAbsolute(): void
    {
        Configure::reset();
        $this->assertSame(
            '/events/index',
            DashboardURLValidator::validate('/events/index')
        );
        $this->assertNull(
            DashboardURLValidator::validate('https://misp.example.com/events/index')
        );
    }
}
