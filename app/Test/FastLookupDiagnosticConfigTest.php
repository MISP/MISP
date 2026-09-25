<?php
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class FastLookupDiagnosticConfigTest extends TestCase
{
    private $attribute;

    protected function setUp(): void
    {
        require_once __DIR__ . '/fixtures/FastLookupConfigurationStub.php';
        require_once __DIR__ . '/../Lib/Tools/FastLookupConfig.php';
        Configure::clear();
        $this->attribute = new FastLookupTestAttribute();
        $this->assertTrue(method_exists(FastLookupConfig::class, 'diagnosticScope'));
    }

    public function testValidConfigurationRetainsTheNormalScopeShape(): void
    {
        $this->assertSame(FastLookupConfig::scope($this->attribute), FastLookupConfig::diagnosticScope($this->attribute));
    }

    public function testInvalidTypeKeepsItsLiteralNameAndOtherValidSettings(): void
    {
        Configure::write('MISP.fast_lookup_attribute_types', ' unknown-type,domain,domain ');
        Configure::write('MISP.fast_lookup_published_only', false);
        Configure::write('MISP.fast_lookup_max_values', '20000');
        $scope = FastLookupConfig::diagnosticScope($this->attribute);
        $this->assertSame(['domain', 'unknown-type'], $scope['attribute_types']);
        $this->assertFalse($scope['published_only']);
        $this->assertSame(20000, $scope['max_values']);
        $this->assertFalse($scope['configuration_valid']);
    }

    public function testInvalidPolicyAndLimitNeverUseValidDefaults(): void
    {
        Configure::write('MISP.fast_lookup_attribute_types', 'domain');
        Configure::write('MISP.fast_lookup_published_only', 'false');
        Configure::write('MISP.fast_lookup_max_values', 0);
        $scope = FastLookupConfig::diagnosticScope($this->attribute);
        $this->assertSame(['domain'], $scope['attribute_types']);
        $this->assertNull($scope['published_only']);
        $this->assertNull($scope['max_values']);
        $this->assertFalse($scope['configuration_valid']);
    }

    public function testMalformedTypeSettingDoesNotClaimDefaultMembership(): void
    {
        Configure::write('MISP.fast_lookup_attribute_types', ['domain']);
        $scope = FastLookupConfig::diagnosticScope($this->attribute);
        $this->assertNull($scope['attribute_types']);
        $this->assertFalse($scope['configuration_valid']);
    }
}
