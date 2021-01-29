<?php
require_once __DIR__ . '/../Lib/Tools/CidrTool.php';

use PHPUnit\Framework\TestCase;

class CidrToolTest extends TestCase
{
    public function testEmptyList(): void
    {
        $cidrTool = new CidrTool([]);
        $this->assertFalse($cidrTool->contains('1.2.3.4'));
    }

    public function testIpv4Fullmask(): void
    {
        $cidrTool = new CidrTool(['1.2.3.4/32']);
        $this->assertEquals('1.2.3.4/32', $cidrTool->contains('1.2.3.4'));
    }

    public function testIpv4WithoutNetmask(): void
    {
        $cidrTool = new CidrTool(['1.2.3.4']);
        $this->assertEquals('1.2.3.4/32', $cidrTool->contains('1.2.3.4'));
    }

    public function testIpv4(): void
    {
        $cidrTool = new CidrTool(['10.0.0.0/8', '8.0.0.0/8', '9.0.0.0/8']);
        $this->assertEquals('8.0.0.0/8', $cidrTool->contains('8.8.8.8'));
        $this->assertFalse($cidrTool->contains('::1'));
        $this->assertFalse($cidrTool->contains('7.1.2.3'));
    }

    public function testIpv6(): void
    {
        $cidrTool = new CidrTool(['2001:0db8:1234::/48']);
        $this->assertEquals('2001:db8:1234::/48', $cidrTool->contains('2001:0db8:1234:0000:0000:0000:0000:0000'));
        $this->assertEquals('2001:db8:1234::/48', $cidrTool->contains('2001:0db8:1234:ffff:ffff:ffff:ffff:ffff'));
        $this->assertFalse($cidrTool->contains('2002:0db8:1234:ffff:ffff:ffff:ffff:ffff'));
    }
}
