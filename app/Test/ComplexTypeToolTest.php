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

    public function testCheckFreeTextPunycode(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('xn--ghq549cb2anjl2suxo.com');
        $this->assertCount(1, $results);
        $this->assertEquals('xn--ghq549cb2anjl2suxo.com', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    public function testCheckFreeTextPunycodeTld(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $complexTypeTool->setTLDs(['xn--fiqs8s']);
        $results = $complexTypeTool->checkFreeText('xn--lbrs59br5a.xn--fiqs8s');
        $this->assertCount(1, $results);
        $this->assertEquals('xn--lbrs59br5a.xn--fiqs8s', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }
}
