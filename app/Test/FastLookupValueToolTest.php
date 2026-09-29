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
        $prepared = $this->tool->prepareScannedAttributes($rows);
        $queries = $this->tool->queryTokens(['192.0.2.3', '2001:db8:abcd::5'], ['ip-src', 'ip-dst']);
        foreach ($prepared as $i => $row) {
            foreach ($row['tokens'] as $token) {
                $this->assertSame(1 + FastLookupValueTool::DIGEST_BYTES, strlen($token));
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

    public function testCompositesIndexBothExactSidesExceptPortsAndNeverTreatPortsAsNetworks(): void
    {
        $rows = [
            ['id' => '1', 'type' => 'domain|ip', 'value1' => 'example.org', 'value2' => '192.0.2.1'],
            ['id' => '2', 'type' => 'ip-src|port', 'value1' => '192.0.2.1', 'value2' => '443'],
            ['id' => '3', 'type' => 'malware-sample', 'value1' => 'file.exe', 'value2' => str_repeat('a', 32)],
        ];
        $expected = ['1' => 2, '2' => 1, '3' => 2];
        foreach ($this->tool->prepareScannedAttributes($rows) as $row) {
            $exact = array_filter($row['tokens'], function ($token) { return $token[0] === 'E'; });
            $this->assertCount($expected[$row['id']], $exact);
            $this->assertCount(0, array_filter($row['tokens'], function ($token) { return $token[0] === 'I'; }));
        }
    }

    public function testDomainTokensMeetQuerySuffixesButNotSubstrings(): void
    {
        $prepared = $this->tool->prepareScannedAttributes([['id' => '9', 'type' => 'domain', 'value1' => 'example.org', 'value2' => '']]);
        $domain = array_values(array_filter($prepared[0]['tokens'], function ($token) { return $token[0] === 'D'; }))[0];
        $queries = $this->tool->queryTokens(['www.example.org', 'badexample.org'], ['domain']);
        $this->assertContains($domain, array_column($queries[0], 'token'));
        $this->assertNotContains($domain, array_column($queries[1], 'token'));
    }

    public function testSameLiteralAndCollationShareOneDatabaseWeight(): void
    {
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $this->attribute->db->responses = [[["\x0e\x60", "\x02\x09"]]];
        $query = $this->tool->queryTokens(['é'], ['domain'], $fallback);
        $this->assertCount(1, $query[0]);
        $this->assertSame([], $fallback);
        $this->assertSame(1, substr_count($this->attribute->db->queries[0], 'WEIGHT_STRING(RTRIM('), 'Equivalent component collations must not duplicate weight work.');
    }

    public function testWeightsUseOneWideSelectWithPadColumns(): void
    {
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $this->attribute->db->responses = [[["\x00A\x00 ", "\x00B", "\x00 "]]];
        $this->tool->queryTokens(['Ä', 'ß', 'Ä'], ['domain'], $fallback, $weights);
        $queries = $this->attribute->db->queries;
        $this->assertCount(1, $queries);
        $this->assertStringStartsWith("SELECT WEIGHT_STRING(RTRIM(CONVERT('Ä' USING utf8mb3) COLLATE utf8mb3_unicode_ci)) AS ", $queries[0]);
        $this->assertStringNotContainsString('UNION', $queries[0]);
        $this->assertSame(1, substr_count($queries[0], "WEIGHT_STRING(CONVERT(' ' USING utf8mb3) COLLATE utf8mb3_unicode_ci)"));
        $this->assertSame(1, substr_count($queries[0], "CONVERT('Ä' USING"));
        $this->assertSame([
            0 => ['value1' => "\x00A", 'value2' => "\x00A"],
            1 => ['value1' => "\x00B", 'value2' => "\x00B"],
            2 => ['value1' => "\x00A", 'value2' => "\x00A"],
        ], $weights);
    }

    /** @dataProvider malformedWideRows */
    public function testMalformedWideWeightRowFailsClosed(array $row): void
    {
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $this->attribute->db->responses = [[$row]];
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid IOC collation weight response.');
        $this->tool->queryTokens(['Ä'], ['domain']);
    }

    public static function malformedWideRows(): array
    {
        return [
            'too few columns' => [["\x00A"]],
            'non-string cell' => [[null, "\x00 "]],
            'empty pad' => [["\x00A", '']],
        ];
    }

    public function testEmptyWeightProducesNoTokenAndNoFallback(): void
    {
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $this->attribute->db->responses = [[['', "\x02\x09"]]];
        $query = $this->tool->queryTokens(["\u{200b}"], ['md5'], $fallback, $weights);
        $this->assertSame([], $fallback);
        $this->assertSame('', $weights[0]['value1']);
        $this->assertNotContains('exact', array_column($query[0], 'kind'));
    }

    public function testPrefixLengthsPruneNetworkTokens(): void
    {
        $count = function ($value, $prefixLengths) {
            $queries = $this->tool->queryTokens([$value], ['ip-dst'], $fallback, $weights, $prefixLengths);
            return count(array_filter($queries[0], function ($t) { return $t['kind'] === 'ip_range'; }));
        };
        $this->assertSame(2, $count('10.1.2.3', [4 => [13 => true, 32 => true], 6 => []]));
        $this->assertSame(33, $count('10.1.2.3', null));
        $this->assertSame(1, $count('2001:db8::1', [4 => [], 6 => [128 => true]]));
    }

    public function testScannedRowsReportNetworkLengths(): void
    {
        $rows = [
            ['id' => '1', 'type' => 'ip-dst', 'value1' => '10.0.0.0/13', 'value2' => ''],
            ['id' => '2', 'type' => 'ip-src', 'value1' => '10.1.2.3', 'value2' => ''],
            ['id' => '3', 'type' => 'ip-dst|port', 'value1' => '2001:db8::/32', 'value2' => '80'],
            ['id' => '4', 'type' => 'domain', 'value1' => 'example.org', 'value2' => ''],
        ];
        $prepared = $this->tool->prepareScannedAttributes($rows);
        $this->assertSame([[[4, 13]], [], [[6, 32]], []], array_column($prepared, 'networks'));
    }

    public function testFalsePositiveRateIsInScopeAndFingerprint(): void
    {
        $this->assertSame(0.001, FastLookupConfig::scope($this->attribute)['false_positive_rate']);
        $first = FastLookupConfig::fingerprint($this->attribute);
        Configure::write('MISP.fast_lookup_false_positive_rate', '0.01');
        $this->assertSame(0.01, FastLookupConfig::scope($this->attribute)['false_positive_rate']);
        $this->assertNotSame($first, FastLookupConfig::fingerprint($this->attribute));
        foreach (['0', '0.5', 'abc', '0.00001', -1] as $invalid) {
            $this->assertIsString(FastLookupConfig::validateFalsePositiveRateSetting($invalid));
        }
        $this->assertTrue(FastLookupConfig::validateFalsePositiveRateSetting('0.0001'));
    }

    public function testScanColumnsSelectWeightsOnlyForSupportedCollations(): void
    {
        $this->assertStringNotContainsString('WEIGHT_STRING', $this->tool->scanColumns('a'));
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $tool = new FastLookupValueTool($this->attribute);
        $columns = $tool->scanColumns('a');
        $this->assertStringContainsString('WEIGHT_STRING(RTRIM(`a`.`value1`)) AS `weight1`', $columns);
        $this->assertStringContainsString('WEIGHT_STRING(RTRIM(`a`.`value2`)) AS `weight2`', $columns);
        $this->attribute->columns['value2']['collate'] = 'utf8mb4_0900_ai_ci';
        $tool = new FastLookupValueTool($this->attribute);
        $this->assertStringContainsString('NULL AS `weight2`', $tool->scanColumns('a'));
    }

    public function testScannedWeightsStripPaddingAndMatchQueryTokens(): void
    {
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $tool = new FastLookupValueTool($this->attribute);
        // The pad weight is fetched once per collation and reused by the query-side weights.
        $this->attribute->db->responses = [
            [['pad_weight' => "\x02\x09"]],
            [["\x0e\x60"]],
        ];
        $prepared = $tool->prepareScannedAttributes([
            ['id' => '5', 'type' => 'md5', 'value1' => 'é ', 'value2' => '', 'weight1' => "\x0e\x60\x02\x09", 'weight2' => null],
        ]);
        $query = $tool->queryTokens(['é'], ['md5']);
        $this->assertSame([$query[0][0]['token']], $prepared[0]['tokens']);
        $this->assertSame('exact', $query[0][0]['kind']);
        $this->assertArrayNotHasKey('type', $query[0][0]);
    }

    public function testQueryTokensAreTypeAgnosticAndUnique(): void
    {
        // Two domain-bearing types used to repeat each parent token once per type.
        $queries = $this->tool->queryTokens(['www.example.org'], ['domain', 'domain|ip', 'hostname']);
        $tokens = array_column($queries[0], 'token');
        $this->assertSame($tokens, array_values(array_unique($tokens)));
        $this->assertSame(['domain', 'domain'], array_column($queries[0], 'kind'));
    }

    /** A synthetic per-code-point table: weight "\x00" . byte, so a space weighs like the pad. */
    private static function asciiTable(): array
    {
        $table = [];
        for ($n = 0; $n < 128; ++$n) {
            $table[chr($n)] = "\x00" . chr($n);
        }
        return $table;
    }

    /** Value cells, then the 128 table cells and the probe weight, then the pad cell. */
    private static function wideRow(array $valueCells, ?string $probe = null, array $padCells = ["\x00 "]): array
    {
        $table = self::asciiTable();
        $probe = $probe ?? strtr(rtrim(FastLookupValueTool::ASCII_PROBE, ' '), $table);
        return array_merge($valueCells, array_values($table), [$probe], $padCells);
    }

    public function testAsciiWeightsComeFromVerifiedTableWithoutFurtherQueries(): void
    {
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $this->attribute->db->responses = [[self::wideRow(["\x0e\x60"])]];
        $this->tool->queryTokens(['A b  ', 'é', "\t", ''], ['md5'], $fallback, $weights);
        $queries = $this->attribute->db->queries;
        $this->assertCount(1, $queries);
        $this->assertSame(128, substr_count($queries[0], 'WEIGHT_STRING(CONVERT(CHAR('));
        $this->assertSame(1, substr_count($queries[0], "CONVERT('é' USING"));
        $this->assertStringNotContainsString("'A b  '", $queries[0]);
        $this->assertSame(1, substr_count($queries[0], "WEIGHT_STRING(CONVERT(' ' USING utf8mb3) COLLATE utf8mb3_unicode_ci)"));
        $this->assertSame([], $fallback);
        $this->assertSame([
            0 => ['value1' => "\x00A\x00 \x00b", 'value2' => "\x00A\x00 \x00b"],
            1 => ['value1' => "\x0e\x60", 'value2' => "\x0e\x60"],
            2 => ['value1' => "\x00\t", 'value2' => "\x00\t"],
            3 => ['value1' => '', 'value2' => ''],
        ], $weights);

        // Memoised: an all-ASCII batch issues no query (the stub throws on any).
        $this->tool->queryTokens(['xyz ', ' ', "a\x00 "], ['md5'], $fallback, $weights);
        $this->assertCount(1, $this->attribute->db->queries);
        $this->assertSame("\x00x\x00y\x00z", $weights[0]['value1']);
        $this->assertSame('', $weights[1]['value1']);
        $this->assertSame("\x00a\x00\x00", $weights[2]['value1']);
    }

    public function testNonAsciiValuesStillGetSqlColumnsOnceTableIsMemoised(): void
    {
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $this->attribute->db->responses = [[self::wideRow([])], [["\x0e\x60"]]];
        $this->tool->queryTokens(['a'], ['md5']);
        $this->tool->queryTokens(['é', 'a'], ['md5'], $fallback, $weights);
        $queries = $this->attribute->db->queries;
        $this->assertCount(2, $queries);
        $this->assertSame("SELECT WEIGHT_STRING(RTRIM(CONVERT('é' USING utf8mb3) COLLATE utf8mb3_unicode_ci)) AS `w0`", $queries[1]);
        $this->assertSame([
            0 => ['value1' => "\x0e\x60", 'value2' => "\x0e\x60"],
            1 => ['value1' => "\x00a", 'value2' => "\x00a"],
        ], $weights);
    }

    public function testProbeMismatchFallsBackToSqlForTheToolLifetime(): void
    {
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $this->attribute->db->responses = [[self::wideRow([], "\x00?")], [["\x01A"]], [["\x01B"]]];
        $this->tool->queryTokens(['A '], ['md5'], $fallback, $weights);
        $queries = $this->attribute->db->queries;
        $this->assertCount(2, $queries);
        $this->assertSame("SELECT WEIGHT_STRING(RTRIM(CONVERT('A ' USING utf8mb3) COLLATE utf8mb3_unicode_ci)) AS `w0`", $queries[1]);
        $this->assertSame([0 => ['value1' => "\x01A", 'value2' => "\x01A"]], $weights);
        $this->tool->queryTokens(['B'], ['md5'], $fallback, $weights);
        $this->assertCount(3, $this->attribute->db->queries);
        $this->assertStringNotContainsString('CHAR(', $this->attribute->db->queries[2]);
        $this->assertSame("\x01B", $weights[0]['value1']);
    }

    /** @dataProvider malformedTableRows */
    public function testMalformedTableRowFailsClosed(string $defect): void
    {
        $row = self::wideRow([]);
        if ($defect === 'null table cell') {
            $row[65] = null;
        } elseif ($defect === 'null probe') {
            $row[128] = null;
        } else {
            unset($row[128]);
        }
        $this->attribute->db->config['datasource'] = 'Database/Mysql';
        $this->attribute->db->responses = [[array_values($row)]];
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid IOC collation weight response.');
        $this->tool->queryTokens(['A'], ['md5']);
    }

    public static function malformedTableRows(): array
    {
        return ['null table cell' => ['null table cell'], 'null probe' => ['null probe'], 'missing probe' => ['missing probe']];
    }
}
