<?php

use PHPUnit\Framework\TestCase;

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

if (!class_exists('ForbiddenException', false)) {
    class ForbiddenException extends RuntimeException
    {
    }
}

require_once __DIR__ . '/../Lib/Tools/CidrTool.php';
require_once __DIR__ . '/../Lib/Tools/UrlEgressValidator.php';

class UrlEgressValidatorTest extends TestCase
{
    /**
     * Literal addresses, so no name resolution is involved and the test does
     * not depend on the network.
     */
    public function testStrictPolicyRefusesInternalLiterals(): void
    {
        $refused = [
            'http://127.0.0.1/' => 'loopback',
            'http://127.1.2.3/' => 'loopback, not just .0.1',
            'http://169.254.169.254/latest/meta-data/' => 'cloud metadata',
            'http://10.0.0.5/' => 'RFC1918 10/8',
            'http://172.16.0.5/' => 'RFC1918 172.16/12',
            'http://172.31.255.254/' => 'RFC1918 upper edge of 172.16/12',
            'http://192.168.1.1/' => 'RFC1918 192.168/16',
            'http://169.254.1.1/' => 'link-local generally',
            'http://100.64.0.1/' => 'CGNAT',
            'http://0.0.0.0/' => 'unspecified',
            'https://[::1]/' => 'IPv6 loopback',
            'http://[fd00::1]/' => 'IPv6 unique local',
            'http://[fe80::1]/' => 'IPv6 link local',
            'http://[::ffff:127.0.0.1]/' => 'IPv4-mapped loopback',
            'http://[::ffff:10.0.0.1]/' => 'IPv4-mapped RFC1918',
        ];
        foreach ($refused as $url => $why) {
            $this->assertRefused($url, UrlEgressValidator::POLICY_DENY_INTERNAL, $why);
        }
    }

    public function testStrictPolicyAllowsPublicLiterals(): void
    {
        foreach (['http://8.8.8.8/', 'https://1.1.1.1/x', 'http://172.32.0.1/', 'https://[2001:4860:4860::8888]/'] as $url) {
            $result = UrlEgressValidator::validate($url, UrlEgressValidator::POLICY_DENY_INTERNAL);
            $this->assertFalse($result['pin'], "$url is a literal, so there is nothing to pin");
        }
    }

    /**
     * 172.32.0.1 sits just outside 172.16/12 and is a genuine public address.
     * A naive "starts with 172." check would wrongly refuse it.
     */
    public function testAdjacentPublicRangeIsNotCaughtByPrivateRange(): void
    {
        $result = UrlEgressValidator::validate('http://172.32.0.1/', UrlEgressValidator::POLICY_DENY_INTERNAL);
        $this->assertSame('172.32.0.1', $result['ip']);
    }

    /**
     * These are the encodings that defeat a resolve-and-compare check:
     * gethostbyname leaves them alone, but curl and PHP's stream wrapper
     * both connect to 127.0.0.1.
     */
    public function testNumericHostEncodingsAreRefused(): void
    {
        foreach (['http://0x7f000001/', 'http://2130706433/', 'http://127.1/', 'http://0177.0.0.1/'] as $url) {
            try {
                UrlEgressValidator::validate($url, UrlEgressValidator::POLICY_DENY_INTERNAL);
                $this->fail("$url should have been refused");
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('not an IP address or a valid hostname', $e->getMessage());
            } catch (ForbiddenException $e) {
                // Also acceptable: refused as a resolved internal address.
                $this->assertTrue(true);
            }
        }
    }

    public function testNonHttpSchemesAreRefused(): void
    {
        foreach (['file:///etc/passwd', 'gopher://x/', 'ftp://x/', 'javascript:alert(1)', ''] as $url) {
            $this->expectExceptionCatch($url);
        }
    }

    /**
     * The loopback policy is what a site admin's targets get: internal
     * ranges stay reachable because internal sync and internal feeds are
     * supported deployments, but loopback and metadata do not.
     */
    public function testLoopbackPolicyLeavesPrivateRangesReachable(): void
    {
        foreach (['http://10.0.0.5/', 'http://192.168.1.1/', 'http://172.16.0.5/'] as $url) {
            $result = UrlEgressValidator::validate($url, UrlEgressValidator::POLICY_DENY_LOOPBACK);
            $this->assertNotEmpty($result['ip'], "$url must stay reachable for site-admin targets");
        }
    }

    public function testLoopbackPolicyStillRefusesLoopbackAndMetadata(): void
    {
        foreach (['http://127.0.0.1/', 'http://169.254.169.254/', 'https://[::1]/', 'http://0.0.0.0/'] as $url) {
            $this->assertRefused($url, UrlEgressValidator::POLICY_DENY_LOOPBACK, 'loopback policy');
        }
    }

    /**
     * The bug in the check this replaces: it only ever tested IPv4 and only
     * three exact values, so [::1] walked straight through.
     */
    public function testLoopbackPolicyCoversIpv6LoopbackUnlikeThePreviousCheck(): void
    {
        $this->assertRefused('http://[::1]:8080/x', UrlEgressValidator::POLICY_DENY_LOOPBACK, 'IPv6 loopback');
    }

    /**
     * Exercises the resolution path rather than a literal, without needing a
     * network: `localhost` comes from /etc/hosts, which is exactly the lookup
     * a DNS-only resolver misses.
     */
    public function testNamedLoopbackIsResolvedAndRefused(): void
    {
        foreach ([UrlEgressValidator::POLICY_DENY_INTERNAL, UrlEgressValidator::POLICY_DENY_LOOPBACK] as $policy) {
            try {
                UrlEgressValidator::validate('http://localhost/x', $policy);
                $this->fail('localhost should have been refused under ' . $policy);
            } catch (ForbiddenException $e) {
                $this->assertStringContainsString('127.0.0.1', $e->getMessage(), 'the message should name the address it resolved to');
            }
        }
    }

    public function testRedirectMustStayOnTheSameHost(): void
    {
        $from = 'http://feed.example.com/list.json';
        $this->assertTrue(UrlEgressValidator::isRedirectAllowed($from, 'http://feed.example.com/other.json'));
        $this->assertTrue(UrlEgressValidator::isRedirectAllowed($from, 'http://FEED.example.com/x'), 'host compare is case-insensitive');
        $this->assertTrue(UrlEgressValidator::isRedirectAllowed($from, 'http://feed.example.com./x'), 'trailing dot is the same host');
        $this->assertTrue(UrlEgressValidator::isRedirectAllowed($from, 'https://feed.example.com/x'), 'upgrade to https is fine');

        $this->assertFalse(UrlEgressValidator::isRedirectAllowed($from, 'http://169.254.169.254/latest/meta-data/'));
        $this->assertFalse(UrlEgressValidator::isRedirectAllowed($from, 'http://127.0.0.1/'));
        $this->assertFalse(UrlEgressValidator::isRedirectAllowed($from, 'http://evil.example.net/'));
        $this->assertFalse(UrlEgressValidator::isRedirectAllowed($from, 'http://feed.example.com.evil.net/'), 'suffix must not be treated as the same host');
        $this->assertFalse(UrlEgressValidator::isRedirectAllowed($from, 'file:///etc/passwd'));
    }

    public function testRedirectMayNotDowngradeHttps(): void
    {
        $this->assertFalse(
            UrlEgressValidator::isRedirectAllowed('https://feed.example.com/x', 'http://feed.example.com/x'),
            'a fetch that started protected must not be redirected onto plaintext'
        );
    }

    /**
     * An internal feed must keep working - it is the ordinary deployment,
     * not an attack.
     */
    public function testRedirectAnchorDoesNotPenaliseInternalFeeds(): void
    {
        $this->assertTrue(UrlEgressValidator::isRedirectAllowed('http://10.0.0.5/feed.json', 'http://10.0.0.5/feed/v2.json'));
    }

    public function testRefusedRangesGrowUnderTheStrictPolicy(): void
    {
        $loopback = UrlEgressValidator::refusedRanges(UrlEgressValidator::POLICY_DENY_LOOPBACK);
        $internal = UrlEgressValidator::refusedRanges(UrlEgressValidator::POLICY_DENY_INTERNAL);
        $this->assertGreaterThan(count($loopback), count($internal));
        foreach ($loopback as $range) {
            $this->assertContains($range, $internal, 'the strict policy must be a superset');
        }
    }

    private function assertRefused($url, $policy, $why): void
    {
        try {
            UrlEgressValidator::validate($url, $policy);
            $this->fail("$url should have been refused ($why)");
        } catch (ForbiddenException $e) {
            $this->assertStringContainsString('restricted range', $e->getMessage());
        }
    }

    private function expectExceptionCatch($url): void
    {
        try {
            UrlEgressValidator::validate($url, UrlEgressValidator::POLICY_DENY_INTERNAL);
            $this->fail("$url should have been refused");
        } catch (InvalidArgumentException $e) {
            $this->assertTrue(true);
        }
    }
}
