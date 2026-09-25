<?php

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class FastLookupValueToolTest extends PHPUnit\Framework\TestCase
{
    private $attribute;
    private $tool;

    protected function setUp(): void
    {
        require_once __DIR__ . '/fixtures/FastLookupConfigurationStub.php';
        foreach (['FastLookupConfig', 'FastLookupValueTool'] as $class) {
            $path = __DIR__ . '/../Lib/Tools/' . $class . '.php';
            if (is_file($path)) { require_once $path; }
            $this->assertTrue(class_exists($class), $class . ' must implement persistent matching.');
        }
        Configure::clear();
        $this->attribute = new FastLookupTestAttribute();
        $this->tool = new FastLookupValueTool($this->attribute);
    }

    public function testDefaultsAndMembershipFingerprint(): void
    {
        $scope = FastLookupConfig::scope($this->attribute);
        $this->assertTrue($scope['published_only']);
        $this->assertSame(10000, $scope['max_values']);
        $this->assertContains('domain|ip', $scope['attribute_types']);
        $first = FastLookupConfig::fingerprint($this->attribute);
        Configure::write('MISP.fast_lookup_max_values', '20000');
        Configure::write('MISP.fast_lookup_enabled', true);
        $this->assertSame($first, FastLookupConfig::fingerprint($this->attribute));
        Configure::write('MISP.fast_lookup_published_only', false);
        $this->assertNotSame($first, FastLookupConfig::fingerprint($this->attribute));
        $this->assertStringNotContainsString('secret', FastLookupConfig::namespaceFor($this->attribute));
    }

    public function testConfigurationRejectsUnknownTypesAndSortsScope(): void
    {
        Configure::write('MISP.fast_lookup_attribute_types', ' ip-src,domain,ip-src ');
        $this->assertSame(['domain', 'ip-src'], FastLookupConfig::scope($this->attribute)['attribute_types']);
        Configure::write('MISP.fast_lookup_attribute_types', 'domain,not-a-misp-type');
        $this->expectException(InvalidArgumentException::class);
        FastLookupConfig::scope($this->attribute);
    }

    /** @dataProvider invalidLimits */
    public function testConfigurationRejectsInvalidLimits($limit): void
    {
        Configure::write('MISP.fast_lookup_max_values', $limit);
        $this->expectException(InvalidArgumentException::class);
        FastLookupConfig::scope($this->attribute);
    }

    public static function invalidLimits(): array { return [[0], [-1], ['10abc'], ['1.5'], [1.5], [true], ['9999999999999999999999999']]; }

    public function testFingerprintChangesWithDatabaseCollationAndVersion(): void
    {
        $first = FastLookupConfig::fingerprint($this->attribute);
        $this->attribute->columns['value2']['collate'] = 'utf8mb4_bin';
        $second = FastLookupConfig::fingerprint($this->attribute);
        $this->assertNotSame($first, $second);
        $this->attribute->db->version = '11.4.0-MariaDB';
        $this->assertNotSame($second, FastLookupConfig::fingerprint($this->attribute));
    }

    public function testCanonicalNetworkTokensMatchHostBitsAndBothFamilies(): void
    {
        $rows = [
            ['id' => '1', 'type' => 'ip-src', 'value1' => '192.0.2.199/24', 'value2' => ''],
            ['id' => '2', 'type' => 'ip-dst', 'value1' => '2001:db8:abcd::1234/48', 'value2' => ''],
            ['id' => '3', 'type' => 'ip-src', 'value1' => '0.0.0.0/0', 'value2' => ''],
            ['id' => '4', 'type' => 'ip-dst', 'value1' => '::/0', 'value2' => ''],
        ];
        $prepared = $this->tool->prepareAttributes($rows);
        $queries = $this->tool->queryTokens(['192.0.2.3', '2001:db8:abcd::5'], ['ip-src', 'ip-dst']);
        foreach ($prepared as $i => $row) {
            foreach ($row['tokens'] as $token) {
                $this->assertSame(17, strlen($token));
                $this->assertStringNotContainsString($rows[$i]['value1'], $token);
            }
            $network = array_values(array_filter($row['tokens'], function ($token) { return $token[0] === 'I'; }));
            $this->assertCount(1, $network);
            $input = in_array($i, [0, 2], true) ? 0 : 1;
            $this->assertContains($network[0], array_column($queries[$input], 'token'));
        }
    }

    public function testExpandedMatchesReturnOriginalRangesAndExcludeOtherFamilies(): void
    {
        $attribute = ['type' => 'ip-src', 'value1' => '192.0.2.199/24', 'value2' => ''];
        $this->assertSame(['ip_ranges' => ['192.0.2.199/24'], 'domains' => []], $this->tool->expandedMatches('192.0.2.1', $attribute));
        $this->assertSame(['ip_ranges' => [], 'domains' => []], $this->tool->expandedMatches('192.0.3.1', $attribute));
        $this->assertSame(['ip_ranges' => [], 'domains' => []], $this->tool->expandedMatches('::ffff:192.0.2.1', $attribute));
        $attribute['value1'] = '2001:db8::FFFF/128';
        $this->assertSame(['2001:db8::FFFF/128'], $this->tool->expandedMatches('2001:db8::ffff', $attribute)['ip_ranges']);
    }

    public function testDomainParentsRespectLabelsAndAttributeTypes(): void
    {
        $domain = ['type' => 'domain|ip', 'value1' => 'Example.Org', 'value2' => '192.0.2.1'];
        $this->assertSame(['Example.Org'], $this->tool->expandedMatches('a.b.example.org.', $domain)['domains']);
        $this->assertSame([], $this->tool->expandedMatches('badexample.org', $domain)['domains']);
        $domain['type'] = 'hostname';
        $this->assertSame([], $this->tool->expandedMatches('a.example.org', $domain)['domains']);
        $domain['type'] = 'text';
        $this->assertSame([], $this->tool->expandedMatches('a.example.org', $domain)['domains']);
    }

    public function testCompositesIndexBothExactSidesWithoutTreatingPortsAsNetworks(): void
    {
        $rows = [
            ['id' => '1', 'type' => 'domain|ip', 'value1' => 'example.org', 'value2' => '192.0.2.1'],
            ['id' => '2', 'type' => 'ip-src|port', 'value1' => '192.0.2.1', 'value2' => '443'],
            ['id' => '3', 'type' => 'malware-sample', 'value1' => 'file.exe', 'value2' => str_repeat('a', 32)],
        ];
        foreach ($this->tool->prepareAttributes($rows) as $row) {
            $exact = array_filter($row['tokens'], function ($token) { return $token[0] === 'E'; });
            $this->assertCount(2, $exact);
            $this->assertCount(0, array_filter($row['tokens'], function ($token) { return $token[0] === 'I'; }));
        }
    }

    public function testDomainTokensMeetQuerySuffixesButNotSubstrings(): void
    {
        $prepared = $this->tool->prepareAttributes([['id' => '9', 'type' => 'domain', 'value1' => 'example.org', 'value2' => '']]);
        $domain = array_values(array_filter($prepared[0]['tokens'], function ($token) { return $token[0] === 'D'; }))[0];
        $queries = $this->tool->queryTokens(['www.example.org', 'badexample.org'], ['domain']);
        $this->assertContains($domain, array_column($queries[0], 'token'));
        $this->assertNotContains($domain, array_column($queries[1], 'token'));
    }

    public function testSameLiteralAndCollationShareOneDatabaseWeight(): void
    {
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $this->attribute->db->responses = [[
            ['input_index' => 0, 'component' => 'value1', 'weight' => "\x0e\x60", 'pad_weight' => "\x02\x09"],
            ['input_index' => 0, 'component' => 'value2', 'weight' => "\x0e\x60", 'pad_weight' => "\x02\x09"],
        ]];
        $query = $this->tool->queryTokens(['c'], ['domain']);
        $this->assertCount(1, $query[0]);
        $this->assertSame([], $this->tool->exactFallbackComponents());
        $this->assertSame(1, substr_count($this->attribute->db->queries[0], ' AS weight,'), 'Equivalent component collations must not duplicate weight work.');
    }
}
