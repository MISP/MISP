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

    public function testExcludedTypesAreRealMispTypesAndNeverDefaults(): void
    {
        $types = json_decode(file_get_contents(dirname(__DIR__, 2) . '/describeTypes.json'), true)['result']['types'];
        $this->assertSame([], array_values(array_diff(FastLookupConfig::EXCLUDED_TYPES, $types)));
        $this->assertSame([], array_values(array_intersect(FastLookupConfig::DEFAULT_TYPES, FastLookupConfig::EXCLUDED_TYPES)));
    }

    public function testExcludedTypesAreRejectedEverywhere(): void
    {
        Configure::write('MISP.fast_lookup_attribute_types', 'domain,port');
        try {
            FastLookupConfig::scope($this->attribute);
            $this->fail('An excluded type must invalidate the scope.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('port is never indexed', $e->getMessage());
        }
        $this->assertFalse(FastLookupConfig::diagnosticScope($this->attribute)['configuration_valid']);
    }

    public function testFalsePositiveRateSettingIsDeclared(): void
    {
        $source = file_get_contents(__DIR__ . '/../Model/Server.php');
        $this->assertStringContainsString("'fast_lookup_false_positive_rate' => array(", $source);
        $this->assertStringContainsString('FastLookupConfig::DEFAULT_FALSE_POSITIVE_RATE', $source);
    }
}
