<?php
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/CidrTool.php';
require_once __DIR__ . '/../Lib/Tools/ClientIpTool.php';

use PHPUnit\Framework\TestCase;

class ClientIpToolTest extends TestCase
{
    private const PROXY = '192.0.2.10';

    private function server(string $header, ?string $value, string $remote = self::PROXY): array
    {
        $server = ['REMOTE_ADDR' => $remote];
        if ($value !== null) {
            $server[$header] = $value;
        }
        return $server;
    }

    public function testNoHeaderConfigured(): void
    {
        $server = $this->server('HTTP_X_FORWARDED_FOR', '203.0.113.5');
        $this->assertSame(self::PROXY, ClientIpTool::resolve($server, null));
        $this->assertSame(self::PROXY, ClientIpTool::resolve($server, ''));
        $this->assertSame(self::PROXY, ClientIpTool::resolve($server, 'REMOTE_ADDR'));
    }

    public function testHeaderAbsent(): void
    {
        $server = $this->server('HTTP_X_FORWARDED_FOR', null);
        $this->assertSame(self::PROXY, ClientIpTool::resolve($server, 'HTTP_X_FORWARDED_FOR'));
    }

    public function testNoRemoteAddr(): void
    {
        $this->assertNull(ClientIpTool::resolve([], 'HTTP_X_FORWARDED_FOR'));
    }

    public function testClientChosenEntryIsIgnored(): void
    {
        $server = $this->server('HTTP_X_FORWARDED_FOR', '198.51.100.99, 203.0.113.5');
        $this->assertSame('203.0.113.5', ClientIpTool::resolve($server, 'HTTP_X_FORWARDED_FOR'));
    }

    public function testTrustedProxyChain(): void
    {
        $server = $this->server('HTTP_X_FORWARDED_FOR', '198.51.100.99, 203.0.113.5, 192.0.2.20');
        $trusted = '192.0.2.0/24';
        $this->assertSame('203.0.113.5', ClientIpTool::resolve($server, 'HTTP_X_FORWARDED_FOR', $trusted));
        $this->assertSame('203.0.113.5', ClientIpTool::resolve($server, 'HTTP_X_FORWARDED_FOR', [$trusted]));
    }

    public function testAllEntriesTrustedUsesLeftMost(): void
    {
        $server = $this->server('HTTP_X_FORWARDED_FOR', '192.0.2.30, 192.0.2.20');
        $this->assertSame('192.0.2.30', ClientIpTool::resolve($server, 'HTTP_X_FORWARDED_FOR', '192.0.2.0/24'));
    }

    public function testRequestNotFromTrustedProxy(): void
    {
        $server = $this->server('HTTP_X_FORWARDED_FOR', '203.0.113.5', '198.51.100.7');
        $this->assertSame('198.51.100.7', ClientIpTool::resolve($server, 'HTTP_X_FORWARDED_FOR', '192.0.2.0/24'));
    }

    public function testNonIpValue(): void
    {
        $server = $this->server('HTTP_X_FORWARDED_FOR', '203.0.113.5, not-an-ip');
        $this->assertSame(self::PROXY, ClientIpTool::resolve($server, 'HTTP_X_FORWARDED_FOR'));
        $server = $this->server('HTTP_X_FORWARDED_FOR', 'unknown');
        $this->assertSame(self::PROXY, ClientIpTool::resolve($server, 'HTTP_X_FORWARDED_FOR', '192.0.2.0/24'));
    }

    public function testSingleValueHeader(): void
    {
        $server = $this->server('HTTP_X_REAL_IP', '203.0.113.5');
        $this->assertSame('203.0.113.5', ClientIpTool::resolve($server, 'HTTP_X_REAL_IP'));
        $this->assertSame('203.0.113.5', ClientIpTool::resolve($server, 'HTTP_X_REAL_IP', self::PROXY));
    }

    public function testIpv6(): void
    {
        $server = $this->server('HTTP_X_FORWARDED_FOR', '2001:db8::bad, 2001:db8:1::5, 2001:db8:ffff::1', '2001:db8:ffff::2');
        $this->assertSame('2001:db8:ffff::1', ClientIpTool::resolve($server, 'HTTP_X_FORWARDED_FOR'));
        $this->assertSame('2001:db8:1::5', ClientIpTool::resolve($server, 'HTTP_X_FORWARDED_FOR', '2001:db8:ffff::/48'));
    }
}
