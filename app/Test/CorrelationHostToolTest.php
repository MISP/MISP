<?php
require_once __DIR__ . '/../Lib/Tools/CorrelationHostTool.php';

use PHPUnit\Framework\TestCase;

class CorrelationHostToolTest extends TestCase
{
    public function testDomainCorrelatesWithSubdomain(): void
    {
        $domain = $this->makeAttribute('domain', 'example.com');
        $hostname = $this->makeAttribute('hostname', 'c2.example.com');

        $this->assertSame(
            'example.com',
            CorrelationHostTool::correlationValue($domain, $hostname)
        );
        $this->assertSame(
            'example.com',
            CorrelationHostTool::correlationValue($hostname, $domain)
        );
    }

    public function testExactDomainMatchIsLeftToNormalCorrelation(): void
    {
        $domain = $this->makeAttribute('domain', 'example.com');
        $hostname = $this->makeAttribute('hostname', 'example.com');

        $this->assertNull(
            CorrelationHostTool::correlationValue($domain, $hostname)
        );
    }

    public function testDomainMatchRequiresDnsLabelBoundary(): void
    {
        $domain = $this->makeAttribute('domain', 'example.com');
        $lookalike = $this->makeAttribute('hostname', 'notexample.com');

        $this->assertNull(
            CorrelationHostTool::correlationValue($domain, $lookalike)
        );
    }

    public function testDomainCorrelatesWithUrlHost(): void
    {
        $domain = $this->makeAttribute('domain', 'example.com');
        $url = $this->makeAttribute(
            'url',
            'https://User:Pass@C2.Example.COM.:8443/download'
        );

        $this->assertSame(
            'example.com',
            CorrelationHostTool::correlationValue($domain, $url)
        );
        $this->assertSame(
            'example.com',
            CorrelationHostTool::correlationValue($url, $domain)
        );
    }

    public function testSchemeLessUrlHostCorrelates(): void
    {
        $hostname = $this->makeAttribute('hostname', 'c2.example.com');
        $url = $this->makeAttribute('url', 'c2.example.com/download');

        $this->assertSame(
            'c2.example.com',
            CorrelationHostTool::correlationValue($url, $hostname)
        );
    }

    public function testDomainInUrlPathDoesNotCorrelate(): void
    {
        $domain = $this->makeAttribute('domain', 'example.com');
        $url = $this->makeAttribute(
            'url',
            'https://unrelated.test/path/example.com'
        );

        $this->assertNull(
            CorrelationHostTool::correlationValue($domain, $url)
        );
    }

    public function testDomainInUrlQueryDoesNotCorrelate(): void
    {
        $domain = $this->makeAttribute('domain', 'example.com');
        $url = $this->makeAttribute(
            'url',
            'https://unrelated.test/?redirect=https://example.com/'
        );

        $this->assertNull(
            CorrelationHostTool::correlationValue($domain, $url)
        );
    }

    public function testDomainInUrlUserInfoDoesNotCorrelate(): void
    {
        $domain = $this->makeAttribute('domain', 'example.com');
        $url = $this->makeAttribute(
            'url',
            'https://example.com@unrelated.test/download'
        );

        $this->assertNull(
            CorrelationHostTool::correlationValue($domain, $url)
        );
    }

    public function testIpv4CorrelatesWithUrlHost(): void
    {
        $ip = $this->makeAttribute('ip-dst', '192.0.2.42');
        $url = $this->makeAttribute('url', 'https://192.0.2.42:8443/a');

        $this->assertSame(
            '192.0.2.42',
            CorrelationHostTool::correlationValue($ip, $url)
        );
        $this->assertSame(
            '192.0.2.42',
            CorrelationHostTool::correlationValue($url, $ip)
        );
    }

    public function testPortCompositesCorrelateByHostOnly(): void
    {
        $hostname = $this->makeAttribute(
            'hostname|port',
            'c2.example.com',
            '443'
        );
        $ip = $this->makeAttribute('ip-dst|port', '192.0.2.42', '443');
        $hostnameUrl = $this->makeAttribute(
            'url',
            'https://c2.example.com:8443/a'
        );
        $ipUrl = $this->makeAttribute('url', 'https://192.0.2.42:8443/a');

        $this->assertSame(
            'c2.example.com',
            CorrelationHostTool::correlationValue($hostname, $hostnameUrl)
        );
        $this->assertSame(
            '192.0.2.42',
            CorrelationHostTool::correlationValue($ip, $ipUrl)
        );
    }

    public function testIpInUrlPathDoesNotCorrelate(): void
    {
        $ip = $this->makeAttribute('ip-src', '192.0.2.42');
        $url = $this->makeAttribute(
            'url',
            'https://unrelated.test/192.0.2.42'
        );

        $this->assertNull(
            CorrelationHostTool::correlationValue($ip, $url)
        );
    }

    public function testIpv6FormsAreCanonicalized(): void
    {
        $ip = $this->makeAttribute('ip-src', '2001:0db8:0:0:0:0:0:1');
        $url = $this->makeAttribute('url', 'https://[2001:db8::1]/a');

        $this->assertSame(
            '2001:db8::1',
            CorrelationHostTool::correlationValue($ip, $url)
        );
    }

    public function testDomainIpCanCorrelateByEitherComponent(): void
    {
        $domainIp = $this->makeAttribute(
            'domain|ip',
            'example.com',
            '192.0.2.42'
        );
        $domainUrl = $this->makeAttribute(
            'url',
            'https://c2.example.com/a'
        );
        $ipUrl = $this->makeAttribute('url', 'https://192.0.2.42/a');

        $this->assertSame(
            'example.com',
            CorrelationHostTool::correlationValue($domainIp, $domainUrl)
        );
        $this->assertSame(
            '192.0.2.42',
            CorrelationHostTool::correlationValue($domainIp, $ipUrl)
        );
    }

    public function testUrlsDoNotCorrelateDirectlyByHost(): void
    {
        $first = $this->makeAttribute('url', 'https://example.com/one');
        $second = $this->makeAttribute('url', 'https://example.com/two');

        $this->assertNull(
            CorrelationHostTool::correlationValue($first, $second)
        );
    }

    public function testCandidateValuesContainParentDomains(): void
    {
        $url = $this->makeAttribute('url', 'https://a.b.example.com/path');

        $this->assertSame(
            ['a.b.example.com', 'b.example.com', 'example.com'],
            CorrelationHostTool::candidateSearchValues($url)
        );
    }

    private function makeAttribute($type, $value1, $value2 = '')
    {
        return [
            'type' => $type,
            'value1' => $value1,
            'value2' => $value2,
        ];
    }
}
