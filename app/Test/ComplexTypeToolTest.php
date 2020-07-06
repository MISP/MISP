<?php
require_once __DIR__ . '/../Lib/Tools/ComplexTypeTool.php';

use PHPUnit\Framework\TestCase;

class ComplexTypeToolTest extends TestCase
{
    public function testCheckFreeTextIpv4(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('127.0.0.1');
        $this->assertCount(1, $results);
        $this->assertEquals('127.0.0.1', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/6009
    public function testCheckFreeTextIpv6(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('2a00:1450:4005:80a::2003');
        $this->assertCount(1, $results);
        $this->assertEquals('2a00:1450:4005:80a::2003', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);
    }

    public function testCheckFreeTextIpv6WithPort(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('[1fff:0:a88:85a3::ac1f]:8001');
        $this->assertCount(1, $results);
        $this->assertEquals('1fff:0:a88:85a3::ac1f|8001', $results[0]['value']);
        $this->assertEquals('ip-dst|port', $results[0]['default_type']);
    }

    public function testCheckFreeTextDomain(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('example.com', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    public function testCheckFreeTextDomainWithPort(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('example.com:80');
        $this->assertCount(1, $results);
        $this->assertEquals('example.com', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    public function testCheckFreeTextDomainUppercase(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('EXAMPLE.COM');
        $this->assertCount(1, $results);
        $this->assertEquals('EXAMPLE.COM', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/657
    public function testCheckFreeTextPunycode(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('xn--ghq549cb2anjl2suxo.com');
        $this->assertCount(1, $results);
        $this->assertEquals('xn--ghq549cb2anjl2suxo.com', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/657
    public function testCheckFreeTextPunycodeTld(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $complexTypeTool->setTLDs(['xn--fiqs8s']);
        $results = $complexTypeTool->checkFreeText('xn--lbrs59br5a.xn--fiqs8s');
        $this->assertCount(1, $results);
        $this->assertEquals('xn--lbrs59br5a.xn--fiqs8s', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/3580
    public function testCheckFreeTextDate(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('2018-08-21');
        $this->assertCount(0, $results);
    }

    public function testCheckFreeTextEmail(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('test@example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('test@example.com', $results[0]['value']);
        $this->assertEquals('email-src', $results[0]['default_type']);
    }

    public function testCheckFreeTextEmailBracket(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('test[@]example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('test@example.com', $results[0]['value']);
        $this->assertEquals('email-src', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/4805
    public function testCheckFreeTextEmailBracketAt(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('test[at]example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('test@example.com', $results[0]['value']);
        $this->assertEquals('email-src', $results[0]['default_type']);
    }

    public function testCheckFreeTextUrlHttp(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('http://example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('http://example.com', $results[0]['value']);
        $this->assertEquals('url', $results[0]['default_type']);
    }

    public function testCheckFreeTextUrlHttps(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('https://example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('https://example.com', $results[0]['value']);
        $this->assertEquals('url', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/4908
    public function testCheckFreeTextUrlReplace(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        foreach (['hxxp://example.com', 'hxtp://example.com', 'htxp://example.com'] as $test) {
            $results = $complexTypeTool->checkFreeText($test);
            $this->assertCount(1, $results);
            $this->assertEquals('http://example.com', $results[0]['value']);
            $this->assertEquals('url', $results[0]['default_type']);
        }
    }

    // Issue https://github.com/MISP/MISP/issues/4908
    public function testCheckFreeTextUrlReplaceHttps(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        foreach (['hxxps://example.com', 'hxtps://example.com', 'htxps://example.com'] as $test) {
            $results = $complexTypeTool->checkFreeText($test);
            $this->assertCount(1, $results);
            $this->assertEquals('https://example.com', $results[0]['value']);
            $this->assertEquals('url', $results[0]['default_type']);
        }
    }
}
