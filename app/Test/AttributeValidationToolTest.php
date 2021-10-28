<?php
require_once __DIR__ . '/../Lib/Tools/AttributeValidationTool.php';

use PHPUnit\Framework\TestCase;

if (!function_exists('__')) {
    // Fake translation function
    function __($singular, $args = null)
    {
        $arguments = func_get_args();
        return sprintf($singular, array_slice($arguments, 1));
    }
}

class AttributeValidationToolTest extends TestCase
{
    public function testValidateIp(): void
    {
        $this->assertTrue(AttributeValidationTool::validate('ip-src', '127.0.0.1'));
        $this->assertTrue(AttributeValidationTool::validate('ip-src', '127.0.0.1'));
        $this->assertTrue(AttributeValidationTool::validate('ip-src', '127.0.0.1/32'));
        $this->assertTrue(AttributeValidationTool::validate('ip-dst', '127.0.0.1/32'));
    }

    public function testValidatePort(): void
    {
        $this->assertTrue(AttributeValidationTool::validate('port', '1'));
        $this->assertTrue(AttributeValidationTool::validate('port', 1));
        $this->assertTrue(AttributeValidationTool::validate('port', 80));
        $this->assertNotTrue(AttributeValidationTool::validate('port', -80));
        $this->assertNotTrue(AttributeValidationTool::validate('port', '-80'));
    }

    public function testValidateSshFingerprint(): void
    {
        $this->assertTrue(AttributeValidationTool::validate('ssh-fingerprint', '7b:e5:6f:a7:f4:f9:81:62:5c:e3:1f:bf:8b:57:6c:5a'));
        $this->assertTrue(AttributeValidationTool::validate('ssh-fingerprint', 'MD5:7b:e5:6f:a7:f4:f9:81:62:5c:e3:1f:bf:8b:57:6c:5a'));
        $this->assertTrue(AttributeValidationTool::validate('ssh-fingerprint', 'SHA256:mVPwvezndPv/ARoIadVY98vAC0g+P/5633yTC4d/wXE'));
    }
}
