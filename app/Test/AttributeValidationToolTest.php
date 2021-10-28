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
        $this->shouldBeValid('ssh-fingerprint', [
            '7b:e5:6f:a7:f4:f9:81:62:5c:e3:1f:bf:8b:57:6c:5a',
            'MD5:7b:e5:6f:a7:f4:f9:81:62:5c:e3:1f:bf:8b:57:6c:5a',
            'SHA256:mVPwvezndPv/ARoIadVY98vAC0g+P/5633yTC4d/wXE',
        ]);
    }

    public function testValidateSsdeep(): void
    {
        $this->shouldBeValid('ssdeep', [
            '96:s4Ud1Lj96tHHlZDrwciQmA+4uy1I0G4HYuL8N3TzS8QsO/wqWXLcMSx:sF1LjEtHHlZDrJzrhuyZvHYm8tKp/RWO',
            '384:EWo4X1WaPW9ZWhWzLo+lWpct/fWbkWsWIwW0/S7dZhgG8:EWo4X1WmW9ZWhWH/WpchfWgWsWTWtf8',
            '6144:3wSQSlrBHFjOvwYAU/Fsgi/2WDg5+YaNk5xcHrYw+Zg+XrZsGEREYRGAFU25ttR/:ctM7E0L4q',
        ]);
        $this->shouldBeValid('filename|ssdeep', [
            'ahoj.txt|96:s4Ud1Lj96tHHlZDrwciQmA+4uy1I0G4HYuL8N3TzS8QsO/wqWXLcMSx:sF1LjEtHHlZDrJzrhuyZvHYm8tKp/RWO',
        ]);
    }

    public function testValidateDomainIp(): void
    {
        $this->shouldBeValid('domain|ip', [
            'example.com|127.0.0.1',
            'example.com|::1',
        ]);
        $this->shouldBeInvalid('domain|ip', [
            'example.com|127',
            'example.com|1',
        ]);
    }

    private function shouldBeValid($type, array $values)
    {
        foreach ($values as $value) {
            $this->assertTrue(AttributeValidationTool::validate($type, $value));
        }
    }

    private function shouldBeInvalid($type, array $values)
    {
        foreach ($values as $value) {
            $this->assertNotTrue(AttributeValidationTool::validate($type, $value));
        }
    }
}
