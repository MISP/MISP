<?php
/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class AttributeFastLookupTest extends PHPUnit\Framework\TestCase
{
    protected function setUp(): void
    {
        require_once __DIR__ . '/../Lib/Tools/FastLookupFilter.php';
        require_once __DIR__ . '/fixtures/FastLookupConfigurationStub.php';
        foreach (['FastLookupConfig', 'FastLookupValueTool', 'AttributeFastLookupTool'] as $class) {
            $path = __DIR__ . '/../Lib/Tools/' . $class . '.php';
            if (is_file($path)) { require_once $path; }
        }
        Configure::clear();
    }

    private function tool(&$attribute, &$manager)
    {
        $attribute = new FastLookupTestAttribute();
        $manager = new FastLookupTestManager();
        return new AttributeFastLookupTool($attribute, $manager);
    }

    public function testWarmingReturnsScopeAndProgressWithoutQuerying(): void
    {
        $tool = $this->tool($attribute, $manager);
        $manager->snapshot = ['status' => 'warming', 'progress' => ['percent' => 40]];
        $result = $tool->lookup([], ['value' => ['example.org']]);
        $this->assertSame('warming', $result['status']);
        $this->assertSame(10000, $result['scope']['max_values']);
        $this->assertSame(40, $result['progress']['percent']);
        $this->assertArrayNotHasKey('results', $result);
        $this->assertSame([], $attribute->db->queries);
        $this->assertSame([], $manager->index->reads);
    }

    public function testFallbackSqlPreservesCollationScopeAndSortedOriginalKeys(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->responses = [[
            ['input_index' => '0', 'event_id' => '10'], ['input_index' => '0', 'event_id' => '2'],
            ['input_index' => '0', 'event_id' => '10'], ['input_index' => '1', 'event_id' => '1'],
        ], [['input_index' => '0', 'event_id' => '2']]];
        $result = $tool->lookup(['id' => 17], ['value' => ['cafe', '0', 'cafe', 'missing']]);
        $this->assertSame('{"cafe":{"event_ids":["2","10"],"ip_ranges":{},"domains":{}},"0":{"event_ids":["1"],"ip_ranges":{},"domains":{}}}', json_encode($result['results']));
        $this->assertCount(2, $attribute->db->queries);
        $sql = implode("\n", $attribute->db->queries);
        foreach (["`Attribute`.`value1` = 'cafe'", "`Attribute`.`value2` = 'cafe'", 'INNER JOIN `events`', 'LEFT JOIN `objects`',
            '`Attribute`.`deleted` = 0', '`Event`.`published` = 1', '`Attribute`.`type` IN (', '`Event`.`org_id` = 7', '`Object`.`distribution` = 5'] as $part) {
            $this->assertStringContainsString($part, $sql);
        }
        $this->assertStringNotContainsString('BINARY ', $sql);
        $this->assertSame([['id' => 17]], $attribute->users);
    }

    public function testMaybePresentExactTokenUsesLiveEqualityWithoutIdRestriction(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $manager->index->hits = [0 => ['exact' => true, 'ip_range' => [], 'domain' => []]];
        $attribute->db->responses = [
            [FastLookupTestDatasource::weightRow([])],
            [['event_id' => '7', 'weight' => "\x00C\x00A\x00F\x00E\x00 "]],
            [],
        ];
        $result = $tool->lookup([], ['value' => ['cafe']]);
        $this->assertSame(['7'], $result['results']->cafe['event_ids']);
        $this->assertStringContainsString('WEIGHT_STRING', $attribute->db->queries[0]);
        $this->assertStringNotContainsString('`Attribute`.`id` IN (', $attribute->db->queries[1]);
        $this->assertStringContainsString("`Attribute`.`value1` IN ('cafe')", $attribute->db->queries[1]);
        $this->assertStringContainsString('WEIGHT_STRING(RTRIM(`Attribute`.`value1`))', $attribute->db->queries[1]);
        $this->assertNotEmpty($manager->index->reads[0][1][0]);
    }

    public function testPortHalvesOfCompositesNeverMatch(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->responses = [[], []];
        $tool->lookup([], ['value' => ['443']]);
        $this->assertCount(2, $attribute->db->queries);
        $branches = explode(' UNION ', implode(' UNION ', $attribute->db->queries));
        $value1 = array_values(array_filter($branches, function ($sql) { return strpos($sql, "`Attribute`.`value1` = '443'") !== false; }));
        $value2 = array_values(array_filter($branches, function ($sql) { return strpos($sql, "`Attribute`.`value2` = '443'") !== false; }));
        $this->assertCount(1, $value1);
        $this->assertCount(1, $value2);
        $this->assertStringNotContainsString('NOT IN', $value1[0]);
        $this->assertStringContainsString("`Attribute`.`type` NOT IN ('hostname|port','ip-dst|port','ip-src|port')", $value2[0]);
    }

    public function testConfigurablePublicationAndTypeScopeApplyToLiveSql(): void
    {
        Configure::write('MISP.fast_lookup_published_only', false);
        Configure::write('MISP.fast_lookup_attribute_types', 'domain');
        $tool = $this->tool($attribute, $manager);
        $attribute->db->responses = [[], []];
        $result = $tool->lookup([], ['value' => ['example.org']]);
        $this->assertSame(['domain'], $result['scope']['attribute_types']);
        $this->assertStringNotContainsString('`Event`.`published` = 1', $attribute->db->queries[0]);
        $this->assertStringContainsString("`Attribute`.`type` IN ('domain')", $attribute->db->queries[0]);
    }

    public function testExpandedMatchesAreRecheckedAgainstCurrentSqlValues(): void
    {
        $tool = $this->tool($attribute, $manager);
        $manager->index->hits = [
            0 => ['exact' => false, 'ip_range' => ['11', '12', '13'], 'domain' => []],
            1 => ['exact' => false, 'ip_range' => [], 'domain' => ['14', '15']],
        ];
        $attribute->db->responses = [[], [], [
            ['id' => '11', 'event_id' => '10', 'type' => 'ip-src', 'value1' => '192.0.2.199/24', 'value2' => ''],
            ['id' => '12', 'event_id' => '2', 'type' => 'ip-dst', 'value1' => '192.0.2.0/25', 'value2' => ''],
            ['id' => '13', 'event_id' => '3', 'type' => 'ip-src', 'value1' => '192.0.3.0/24', 'value2' => ''],
            ['id' => '14', 'event_id' => '9', 'type' => 'domain', 'value1' => 'example.org', 'value2' => ''],
            ['id' => '15', 'event_id' => '5', 'type' => 'hostname', 'value1' => 'example.org', 'value2' => ''],
        ]];
        $result = $tool->lookup([], ['value' => ['192.0.2.1', 'www.example.org']]);
        $this->assertSame(['2', '10'], $result['results']->{'192.0.2.1'}['event_ids']);
        $this->assertSame(['10'], $result['results']->{'192.0.2.1'}['ip_ranges']->{'192.0.2.199/24'});
        $this->assertSame(['9'], $result['results']->{'www.example.org'}['domains']->{'example.org'});
        $this->assertStringContainsString('`Attribute`.`id` IN (11,12,13,14,15)', $attribute->db->queries[2]);
        $this->assertStringContainsString('`Event`.`org_id` = 7', $attribute->db->queries[2]);
        $this->assertStringNotContainsString("= '192.0.2.1'", $attribute->db->queries[2]);
    }

    public function testGenerationFenceDiscardsAllResults(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->responses = [[['input_index' => 0, 'event_id' => '7']], []];
        $manager->current = false;
        $result = $tool->lookup([], ['value' => ['example.org']]);
        $this->assertNotSame('ready', $result['status']);
        $this->assertArrayNotHasKey('results', $result);
        $this->assertArrayHasKey('scope', $result);
    }

    public function testDefaultAdmitsTenThousandSha512Values(): void
    {
        $tool = $this->tool($attribute, $manager);
        $manager->snapshot = ['status' => 'warming'];
        $values = array_map(function ($i) { return hash('sha512', (string)$i); }, range(1, 10000));
        $this->assertSame('warming', $tool->lookup([], ['value' => $values])['status']);
        $this->expectException(InvalidArgumentException::class);
        $tool->lookup([], ['value' => array_merge($values, ['extra'])]);
    }

    public function testConfiguredMaximumIsValidatedBeforeIndexAccess(): void
    {
        Configure::write('MISP.fast_lookup_max_values', 2);
        $tool = $this->tool($attribute, $manager);
        try {
            $tool->lookup([], ['value' => ['a', 'b', 'c']]);
            $this->fail('Expected request maximum rejection.');
        } catch (InvalidArgumentException $e) {
            $this->assertSame(0, $manager->reads);
        }
    }

    /** @dataProvider invalidRequests */
    public function testMalformedRequestsNeverReadIndexOrSql(array $request): void
    {
        $tool = $this->tool($attribute, $manager);
        try {
            $tool->lookup([], $request);
            $this->fail('Expected InvalidArgumentException.');
        } catch (InvalidArgumentException $e) {
            $this->assertSame([], $attribute->db->queries);
            $this->assertSame(0, $manager->reads);
        }
    }

    public static function invalidRequests(): array
    {
        return [[[]], [['value' => 'x']], [['value' => ['a' => 'x']]], [['value' => [1]]],
            [['value' => ['']]], [['value' => ["\xff"]]], [['value' => ["x\0y"]]],
            [['value' => ['x'], 'maxAge' => 0]], [['value' => ['x'], 'maxAge' => 1]],
            [['value' => ['x'], 'other' => true]], [['value' => [str_repeat('x', 4097)]]],
            [['value' => array_fill(0, 4097, str_repeat('x', 4096))]]];
    }

    public function testEmptyReadyResultsAreAnObject(): void
    {
        $tool = $this->tool($attribute, $manager);
        $result = $tool->lookup([], ['value' => []]);
        $this->assertSame('ready', $result['status']);
        $this->assertSame('{}', json_encode($result['results']));
        $this->assertSame([], $attribute->db->queries);
    }

    public function testLiteralQuotingAndIpv6Normalization(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->responses = [[['input_index' => 1, 'event_id' => '9']], []];
        $result = $tool->lookup([], ['value' => ["!%' OR 1=1 --", '2001:0DB8:0:0::1']]);
        $this->assertSame(['9'], $result['results']->{'2001:0DB8:0:0::1'}['event_ids']);
        $this->assertStringContainsString("= '!%'' OR 1=1 --'", $attribute->db->queries[0]);
        $this->assertStringContainsString("= '2001:db8::1'", $attribute->db->queries[0]);
    }

    public function testFourByteUnicodeSkipsOnlyIncompatibleComponent(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->columns['value2'] = ['charset' => 'utf8mb4', 'collate' => 'utf8mb4_unicode_ci'];
        $attribute->db->responses = [[['input_index' => 0, 'event_id' => '9']]];
        $result = $tool->lookup([], ['value' => ['stored-😀']]);
        $this->assertSame(['9'], $result['results']->{'stored-😀'}['event_ids']);
        $this->assertStringContainsString("`Attribute`.`value2` = 'stored-😀'", $attribute->db->queries[0]);
        $this->assertStringNotContainsString('`Attribute`.`value1`', $attribute->db->queries[0]);
    }

    public function testLaterBatchesKeepTheirInputOrdinals(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->responses = [[], [], [['input_index' => 1000, 'event_id' => '1']], []];
        $values = array_map(function ($i) { return 'ioc-' . $i; }, range(0, 1000));
        $result = $tool->lookup([], ['value' => $values]);
        $this->assertSame(['1'], $result['results']->{'ioc-1000'}['event_ids']);
        $this->assertCount(4, $attribute->db->queries);
        $this->assertStringContainsString("'ioc-1000'", $attribute->db->queries[2]);
        $this->assertStringNotContainsString("'ioc-999'", $attribute->db->queries[2]);
    }

    public function testSqlResourceLimitDoesNotReturnPartialResults(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->responses = [array_map(function ($i) { return ['input_index' => 0, 'event_id' => (string)$i]; }, range(1, 100001))];
        $this->expectException(OverflowException::class);
        $tool->lookup([], ['value' => ['example.org']]);
    }

    public function testExhaustedBudgetStopsBeforeAnotherCandidateBatch(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->responses = [array_map(function ($i) { return ['input_index' => 0, 'event_id' => (string)$i]; }, range(1, 100000)), []];
        $values = array_map(function ($i) { return 'ioc-' . $i; }, range(0, 1000));
        try {
            $tool->lookup([], ['value' => $values]);
            $this->fail('An exhausted row budget must stop the lookup.');
        } catch (OverflowException $e) {
            $this->assertCount(1, $manager->index->reads, 'No second candidate batch was read.');
        }
    }

    public function testMalformedCandidateIdsNeverEnterSql(): void
    {
        $tool = $this->tool($attribute, $manager);
        $manager->index->hits = [0 => ['exact' => false, 'ip_range' => ['1) OR 1=1'], 'domain' => []]];
        try {
            $tool->lookup([], ['value' => ['192.0.2.1']]);
            $this->fail('Invalid candidate IDs must fail closed.');
        } catch (FastLookupIndexUnavailableException $e) {
            $this->assertSame([], $attribute->db->queries);
        }
    }

    /** @dataProvider malformedCandidateReplies */
    public function testMalformedCandidateReplyFailsClosedAsUnavailable(array $hits, array $values): void
    {
        $tool = $this->tool($attribute, $manager);
        $manager->index->hits = $hits;
        try {
            $tool->lookup([], ['value' => $values]);
            $this->fail('A malformed filter reply must never read as "absent".');
        } catch (FastLookupIndexUnavailableException $e) {
            $this->assertSame([], $attribute->db->queries, 'Nothing reached SQL.');
        }
    }

    public function malformedCandidateReplies(): array
    {
        $absent = ['exact' => false, 'ip_range' => [], 'domain' => []];
        return [
            'no exact flag' => [[0 => ['ip_range' => [], 'domain' => []]], ['example.org']],
            'exact flag not boolean' => [[0 => ['exact' => 1, 'ip_range' => [], 'domain' => []]], ['example.org']],
            'empty reply' => [[], ['example.org']],
            'a position missing' => [[0 => $absent], ['example.org', 'example.net']],
            'an extra position' => [[0 => $absent, 1 => $absent], ['example.org']],
            'groups not an array' => [[0 => false], ['example.org']],
            'no range list' => [[0 => ['exact' => false, 'domain' => []]], ['example.org']],
        ];
    }

    public function testIgnorableOnlyInputNeverMatches(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $attribute->db->responses = [
            [['', "\x02\x09"]],
            [],
        ];
        $result = $tool->lookup([], ['value' => ["\u{200b}"]]);
        $this->assertSame('{}', json_encode($result['results']));
        foreach (array_slice($attribute->db->queries, 1) as $query) {
            $this->assertStringNotContainsString("\u{200b}", $query);
        }
    }

    public function testAbsentExactTokenSkipsSqlEquality(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $manager->index->hits = [0 => ['exact' => false, 'ip_range' => [], 'domain' => []]];
        $attribute->db->responses = [
            [FastLookupTestDatasource::weightRow([])],
        ];
        $result = $tool->lookup([], ['value' => ['c']]);
        $this->assertSame('{}', json_encode($result['results']));
        $this->assertCount(1, $attribute->db->queries, 'Only the collation weight query runs for an absent value.');
    }

    /**
     * Tokenizer-level: the tokens prepareScannedAttributes() derives for
     * stored attributes must intersect the queryTokens() a lookup of a child
     * value produces, for an IP range, an ASCII domain, and an IDN domain in
     * both storage directions (MISP stores IDN domains as punycode, per
     * AttributeValidationTool::modifyBeforeValidation('domain', ...), but the
     * tokenizer's own domain() normalization must match either way).
     *
     * The stub datasource never supports collation weights, so queryTokens()
     * routes exact matches to $fallback and emits no 'E' token; the check is
     * therefore only that the token sets intersect.
     */
    public function testTokenizerIntersectsStoredRangeAndDomainTokensWithQueryTokens(): void
    {
        $attribute = new FastLookupTestAttribute();
        require_once __DIR__ . '/../Lib/Tools/FastLookupValueTool.php';
        $tool = new FastLookupValueTool($attribute);
        $rows = [
            ['id' => '11', 'type' => 'ip-src', 'value1' => '10.0.0.5/24', 'value2' => ''],
            ['id' => '12', 'type' => 'domain', 'value1' => 'Evil.COM.', 'value2' => ''],
            // Stored as punycode (how MISP actually persists an IDN domain), queried in Unicode.
            ['id' => '13', 'type' => 'domain', 'value1' => 'xn--bcher-kva.example', 'value2' => ''],
            // Reverse direction: stored in Unicode, queried as a punycode child.
            ['id' => '14', 'type' => 'domain', 'value1' => 'bücher.example', 'value2' => ''],
        ];
        $prepared = $tool->prepareScannedAttributes($rows);
        $queries = $tool->queryTokens(
            ['10.0.0.7', 'www.evil.com', 'www.bücher.example', 'www.xn--bcher-kva.example'],
            ['ip-src', 'domain']
        );
        foreach ($prepared as $i => $row) {
            $storedTokens = $row['tokens'];
            $queryTokens = array_column($queries[$i], 'token');
            $intersection = array_intersect($storedTokens, $queryTokens);
            $this->assertNotEmpty($intersection, "Row $i ({$rows[$i]['value1']}) must share a token with its query.");
        }
        // The punycode-stored and Unicode-stored IDN rows must land on the
        // same domain token: the tokenizer normalizes both to one spelling.
        $domainToken = function ($tokens) { return array_values(array_filter($tokens, function ($t) { return $t[0] === 'D'; })); };
        $this->assertSame($domainToken($prepared[2]['tokens']), $domainToken($prepared[3]['tokens']));
    }

    /**
     * A stale filter entry (the exact token maybe-present and a range
     * candidate ID both point at attributes SQL no longer has) must vanish
     * from the results while the response stays ready.
     */
    public function testStaleFilterEntriesAreDroppedByLiveSqlAndResponseStaysReady(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $manager->index->hits = [0 => ['exact' => true, 'ip_range' => ['11'], 'domain' => []]];
        $attribute->db->responses = [
            [FastLookupTestDatasource::weightRow([])],
            [],
            [],
            [],
        ];
        $result = $tool->lookup([], ['value' => ['c']]);
        $this->assertSame('ready', $result['status']);
        $this->assertSame('{}', json_encode($result['results']));
        $this->assertCount(4, $attribute->db->queries);
        $this->assertStringContainsString('`Attribute`.`id` IN (11)', $attribute->db->queries[3]);
        $this->assertStringContainsString('`Attribute`.`deleted` = 0', $attribute->db->queries[1]);
    }

    /** A MySQL-typed datasource answering every weights query with distinct weights and every other query with no rows. */
    private function weighingTool(&$attribute, &$manager)
    {
        $attribute = new FastLookupTestAttribute();
        $attribute->db = new class extends FastLookupTestDatasource {
            public function rawQuery($sql)
            {
                $this->queries[] = $sql;
                if (strpos($sql, 'SELECT WEIGHT_STRING') !== 0) {
                    return new FastLookupTestStatement([]);
                }
                preg_match_all('/ AS `([wpq]|t\d+_)(\d+)`/', $sql, $columns, PREG_SET_ORDER);
                $table = self::asciiWeightTable();
                $row = [];
                foreach ($columns as $n => [, $kind, $ordinal]) {
                    if ($kind === 'p') {
                        $row[] = "\x00 ";
                    } elseif ($kind === 'q') {
                        $row[] = strtr(rtrim(FastLookupValueTool::ASCII_PROBE, ' '), $table);
                    } elseif ($kind !== 'w') {
                        $row[] = $table[chr((int)$ordinal)];
                    } else {
                        $row[] = 'w' . count($this->queries) . '-' . $n;
                    }
                }
                return new FastLookupTestStatement([$row]);
            }
        };
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $manager = new FastLookupTestManager();
        return new AttributeFastLookupTool($attribute, $manager);
    }

    private function weightQueries($attribute)
    {
        return array_values(array_filter($attribute->db->queries, function ($sql) { return strpos($sql, 'SELECT WEIGHT_STRING') === 0; }));
    }

    public function testEqualWeightsShareOneInEntryAndAllInputsMatch(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $exact = ['exact' => true, 'ip_range' => [], 'domain' => []];
        $manager->index->hits = [0 => $exact, 1 => $exact, 2 => $exact];
        $weight = "\x00C\x00A\x00F\x00E";
        $attribute->db->responses = [
            [FastLookupTestDatasource::weightRow([$weight . "\x00 "])],
            [['event_id' => '7', 'weight' => $weight . "\x00 "]],
            [],
        ];
        $result = $tool->lookup([], ['value' => ['CAFE', 'cafe', "cafe\u{a0}"]]);
        $this->assertCount(3, $attribute->db->queries);
        $sql = $attribute->db->queries[1];
        $this->assertStringContainsString("`Attribute`.`value1` IN ('CAFE')", $sql);
        $this->assertRegExp("/`Attribute`.`value1` IN \('[^']*'\)/", $sql);
        $this->assertStringNotContainsString('UNION', $sql);
        $this->assertStringNotContainsString("= 'cafe'", implode("\n", $attribute->db->queries));
        foreach (['CAFE', 'cafe', "cafe\u{a0}"] as $input) {
            $this->assertSame(['7'], $result['results']->{$input}['event_ids']);
        }
    }

    public function testRowsMapOnlyToInputsWithTheSameWeight(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $exact = ['exact' => true, 'ip_range' => [], 'domain' => []];
        $manager->index->hits = [0 => $exact, 1 => $exact];
        $attribute->db->responses = [
            [FastLookupTestDatasource::weightRow([])],
            [['event_id' => '5', 'weight' => "\x00B\x00 "]],
            [],
        ];
        $result = $tool->lookup([], ['value' => ['a', 'b']]);
        $this->assertStringContainsString("`Attribute`.`value1` IN ('a','b')", $attribute->db->queries[1]);
        $this->assertSame('{"b":{"event_ids":["5"],"ip_ranges":{},"domains":{}}}', json_encode($result['results']));
    }

    public function testDuplicatePairsAcrossComponentsCountOnce(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $manager->index->hits = [0 => ['exact' => true, 'ip_range' => [], 'domain' => []]];
        $rows = array_map(function ($i) { return ['event_id' => (string)$i, 'weight' => "\x00C\x00 "]; }, range(1, 100000));
        $attribute->db->responses = [[FastLookupTestDatasource::weightRow([])], $rows, $rows];
        $result = $tool->lookup([], ['value' => ['c']]);
        $this->assertCount(100000, $result['results']->c['event_ids']);
        $this->assertStringContainsString('`Attribute`.`value2` IN (', $attribute->db->queries[2]);
    }

    public function testLaterEqualityQueriesKeepTheFullRowLimit(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $manager->index->hits = [0 => ['exact' => true, 'ip_range' => [], 'domain' => []]];
        $attribute->db->responses = [
            [FastLookupTestDatasource::weightRow([])],
            [['event_id' => '1', 'weight' => "\x00C"], ['event_id' => '2', 'weight' => "\x00C"]],
            [],
        ];
        $tool->lookup([], ['value' => ['c']]);
        $this->assertStringEndsWith(' LIMIT 100001', $attribute->db->queries[1]);
        $this->assertStringEndsWith(' LIMIT 100001', $attribute->db->queries[2]);
    }

    public function testLaterFallbackQueriesKeepTheFullRowLimit(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->responses = [[['input_index' => 0, 'event_id' => '1'], ['input_index' => 0, 'event_id' => '2']], []];
        $tool->lookup([], ['value' => ['c']]);
        $this->assertStringEndsWith(' LIMIT 100001', $attribute->db->queries[1]);
    }

    public function testOneQueryReturningMoreThanMaxRowsOverflows(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $manager->index->hits = [0 => ['exact' => true, 'ip_range' => [], 'domain' => []]];
        $rows = array_map(function ($i) { return ['event_id' => (string)$i, 'weight' => "\x00C\x00 "]; }, range(1, 100001));
        $attribute->db->responses = [[FastLookupTestDatasource::weightRow([])], $rows, []];
        $this->expectException(OverflowException::class);
        $tool->lookup([], ['value' => ['c']]);
    }

    public function testRowMatchingNoInputWeightFailsClosed(): void
    {
        $tool = $this->tool($attribute, $manager);
        $attribute->db->config['datasource'] = 'Database/Mysql';
        $manager->index->hits = [0 => ['exact' => true, 'ip_range' => [], 'domain' => []]];
        $attribute->db->responses = [[FastLookupTestDatasource::weightRow([])], [['event_id' => '1', 'weight' => "\x00X"]], []];
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid IOC lookup response.');
        $tool->lookup([], ['value' => ['c']]);
    }

    public function testBatchesCloseAtTheByteCap(): void
    {
        $tool = $this->weighingTool($attribute, $manager);
        $values = array_map(function ($i) {
            // Non-ASCII, so every batch carries its values into the weights query.
            return substr("\u{e9}" . sprintf('%04d', $i) . str_repeat("'" . str_repeat('x', 19), 200), 0, 4000);
        }, range(0, 999));
        $this->assertSame(200, substr_count($values[0], "'"));
        $this->assertGreaterThan(4194304, array_sum(array_map(function ($value) use ($attribute) { return strlen($attribute->db->value($value, 'string')); }, $values)));
        $result = $tool->lookup([], ['value' => $values]);
        $this->assertSame('ready', $result['status']);
        $this->assertGreaterThan(1, count($this->weightQueries($attribute)));
        $this->assertGreaterThan(1, count($manager->index->reads));
        foreach ($attribute->db->queries as $sql) {
            $this->assertLessThanOrEqual(8388608, strlen($sql));
        }
    }

    public function testLaterAsciiBatchesIssueNoWeightsQuery(): void
    {
        $tool = $this->weighingTool($attribute, $manager);
        $values = array_map(function ($i) { return 'ioc-' . $i; }, range(0, 2499));
        $result = $tool->lookup([], ['value' => $values]);
        $this->assertSame('ready', $result['status']);
        $this->assertCount(3, $manager->index->reads);
        $this->assertCount(1, $this->weightQueries($attribute));
    }

    public function testThousandValuesUseOneBatch(): void
    {
        $tool = $this->weighingTool($attribute, $manager);
        $values = array_map(function ($i) { return 'ioc-' . $i; }, range(0, 999));
        $manager->index->hits = array_fill(0, 1000, ['exact' => true, 'ip_range' => [], 'domain' => []]);
        $tool->lookup([], ['value' => $values]);
        $this->assertCount(1, $this->weightQueries($attribute));
        $this->assertCount(1, $manager->index->reads);
        $in = array_filter($attribute->db->queries, function ($sql) { return strpos($sql, 'SELECT DISTINCT') === 0; });
        $this->assertCount(2, $in);
    }

    public function testPrefixLengthsAreReadOnceAndPassedToCandidates(): void
    {
        Configure::write('MISP.fast_lookup_attribute_types', 'ip-dst');
        $tool = $this->tool($attribute, $manager);
        $manager->index->prefixes = ['version' => '3', 'lengths' => [4 => [32 => true], 6 => []]];
        $attribute->db->responses = [[], []];
        $tool->lookup([], ['value' => ['10.1.2.3']]);
        $this->assertSame(1, $manager->index->prefixReads);
        $this->assertCount(1, $manager->index->reads);
        $this->assertSame('3', $manager->index->reads[0][3]);
        $ranges = array_filter($manager->index->reads[0][1][0], function ($token) { return $token['kind'] === 'ip_range'; });
        $this->assertCount(1, $ranges);
        $this->assertSame('I', array_values($ranges)[0]['token'][0]);
    }

    private function rangeTokens(array $tokens): array
    {
        $ranges = array_column(array_filter($tokens, function ($token) { return $token['kind'] === 'ip_range'; }), 'token');
        sort($ranges);
        return $ranges;
    }

    public function testPrefixVersionChangeRefreshesOnceThenFails(): void
    {
        Configure::write('MISP.fast_lookup_attribute_types', 'ip-dst');
        $tool = $this->tool($attribute, $manager);
        $stale = ['version' => '3', 'lengths' => [4 => [32 => true], 6 => []]];
        $fresh = ['version' => '4', 'lengths' => [4 => [8 => true, 16 => true], 6 => []]];
        $manager->index->prefixSequence = [$stale, $fresh];
        $manager->index->changes = 1;
        $attribute->db->responses = [[], []];
        $result = $tool->lookup([], ['value' => ['10.1.2.3']]);
        $this->assertSame('ready', $result['status']);
        $this->assertSame(2, $manager->index->prefixReads);
        $this->assertCount(2, $manager->index->reads);
        $this->assertSame('3', $manager->index->reads[0][3]);
        $this->assertSame('4', $manager->index->reads[1][3]);
        $expected = (new FastLookupValueTool($attribute))->queryTokens(['10.1.2.3'], ['ip-dst'], $fallback, $weights, $fresh['lengths']);
        $retried = $this->rangeTokens($manager->index->reads[1][1][0]);
        $this->assertCount(2, $retried);
        $this->assertSame($this->rangeTokens($expected[0]), $retried);
        $this->assertNotSame($this->rangeTokens($manager->index->reads[0][1][0]), $retried);

        $tool = $this->tool($attribute, $manager);
        $manager->index->changes = 2;
        try {
            $tool->lookup([], ['value' => ['10.1.2.3']]);
            $this->fail('A second prefix change must fail the lookup.');
        } catch (FastLookupIndexUnavailableException $e) {
            $this->assertSame(2, $manager->index->prefixReads);
            $this->assertSame([], $attribute->db->queries);
        }
    }

    public function testRequestsWithoutRangeTokensSkipThePrefixVersionCheck(): void
    {
        Configure::write('MISP.fast_lookup_attribute_types', 'sha256');
        $tool = $this->tool($attribute, $manager);
        $manager->index->prefixes = ['version' => '3', 'lengths' => [4 => [32 => true], 6 => []]];
        $manager->index->changes = 5;
        $attribute->db->responses = [[], []];
        $result = $tool->lookup([], ['value' => [hash('sha256', 'x')]]);
        $this->assertSame('ready', $result['status']);
        $this->assertCount(1, $manager->index->reads);
        $this->assertSame([], $this->rangeTokens($manager->index->reads[0][1][0]));
        $this->assertNull($manager->index->reads[0][3]);
        $this->assertSame(1, $manager->index->prefixReads);
    }
}
