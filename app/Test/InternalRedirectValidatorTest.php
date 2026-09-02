<?php
/**
 * InternalRedirectValidator unit tests (V20 contract).
 *
 * Pure PHPUnit - follows the convention used by every other test under
 * app/Test/: no CakePHP bootstrap, no DB. The validator has no framework
 * dependency at all, so nothing needs stubbing.
 */

require_once __DIR__ . '/../Vendor/autoload.php';
require_once __DIR__ . '/../Lib/Tools/InternalRedirectValidator.php';

use PHPUnit\Framework\TestCase;

class InternalRedirectValidatorTest extends TestCase
{
    // -------- ordinary MISP paths survive unchanged --------

    public function testPlainPathAllowed(): void
    {
        $this->assertSame('/events/index', InternalRedirectValidator::sanitize('/events/index'));
    }

    public function testRootAllowed(): void
    {
        $this->assertSame('/', InternalRedirectValidator::sanitize('/'));
    }

    /**
     * MISP's named-parameter filter syntax puts colons all over the path.
     * parse_url does not mistake them for a scheme once the string starts
     * with '/', but pin it - the whole feature would break otherwise.
     */
    public function testFilterSyntaxPathAllowed(): void
    {
        $this->assertSame(
            '/events/index/searchtag:tlp:red/searchall:value',
            InternalRedirectValidator::sanitize('/events/index/searchtag:tlp:red/searchall:value')
        );
    }

    public function testQueryAndFragmentPreserved(): void
    {
        $this->assertSame(
            '/events/index?page=2#top',
            InternalRedirectValidator::sanitize('/events/index?page=2#top')
        );
    }

    public function testInternalDoubleSlashLaterInPathAllowed(): void
    {
        // Only a leading '//' makes a URL protocol-relative.
        $this->assertSame('/events//index', InternalRedirectValidator::sanitize('/events//index'));
    }

    // -------- the V20 payloads --------

    public function testProtocolRelativeRejected(): void
    {
        $this->assertSame('', InternalRedirectValidator::sanitize('//attacker.example'));
        $this->assertSame('', InternalRedirectValidator::sanitize('//attacker.example/fake-login'));
    }

    /**
     * Browsers read a backslash as a slash in and around the authority, so
     * '//\host' and '/\host' both resolve off-site.
     */
    public function testBackslashAuthorityRejected(): void
    {
        $this->assertSame('', InternalRedirectValidator::sanitize('//\\attacker.example'));
        $this->assertSame('', InternalRedirectValidator::sanitize('/\\attacker.example'));
    }

    public function testTripleSlashRejected(): void
    {
        // parse_url() cannot parse this one at all - it must not fall through.
        $this->assertSame('', InternalRedirectValidator::sanitize('///attacker.example'));
    }

    public function testAbsoluteUrlRejected(): void
    {
        $this->assertSame('', InternalRedirectValidator::sanitize('http://attacker.example/'));
        $this->assertSame('', InternalRedirectValidator::sanitize('https://attacker.example/'));
        $this->assertSame('', InternalRedirectValidator::sanitize('javascript:alert(1)'));
    }

    public function testUserinfoRejected(): void
    {
        $this->assertSame('', InternalRedirectValidator::sanitize('//misp.example.com@attacker.example/'));
    }

    public function testRelativePathWithoutLeadingSlashRejected(): void
    {
        $this->assertSame('', InternalRedirectValidator::sanitize('events/index'));
        $this->assertSame('', InternalRedirectValidator::sanitize('attacker.example'));
    }

    // -------- the "do not decode" decision, pinned --------

    /**
     * A percent-encoded slash is NOT decoded by the browser before it
     * resolves a Location header, so '/%2f%2fevil' is an ordinary
     * same-origin path and is allowed through verbatim. Decoding inside
     * sanitize() while the caller redirects the raw string would validate
     * one value and emit another - the bug this contract exists to prevent.
     */
    public function testPercentEncodedSlashesStaySameOriginAndAreAllowed(): void
    {
        $this->assertSame(
            '/%2f%2fattacker.example',
            InternalRedirectValidator::sanitize('/%2f%2fattacker.example')
        );
        $this->assertSame(
            '/%5c%5cattacker.example',
            InternalRedirectValidator::sanitize('/%5c%5cattacker.example')
        );
    }

    /**
     * The caller decoding first is the other half of the same contract:
     * UsersController::routeafterlogin() hands in rawurldecode($sessionUrl)
     * and redirects what comes back, so the decoded form is what is checked.
     */
    public function testCallerDecodedProtocolRelativeIsRejected(): void
    {
        $this->assertSame('', InternalRedirectValidator::sanitize(rawurldecode('/%2f%2fattacker.example')));
    }

    // -------- hardening beyond the inherited check --------

    public function testControlCharactersRejected(): void
    {
        $this->assertSame('', InternalRedirectValidator::sanitize("/events/index\r\nSet-Cookie: a=b"));
        $this->assertSame('', InternalRedirectValidator::sanitize("/events/index\n"));
        $this->assertSame('', InternalRedirectValidator::sanitize("/events/\x00index"));
    }

    public function testNonStringAndEmptyRejected(): void
    {
        $this->assertSame('', InternalRedirectValidator::sanitize(''));
        $this->assertSame('', InternalRedirectValidator::sanitize(null));
        $this->assertSame('', InternalRedirectValidator::sanitize(array('path' => '/events/index')));
        $this->assertSame('', InternalRedirectValidator::sanitize(42));
        $this->assertSame('', InternalRedirectValidator::sanitize(false));
    }
}
