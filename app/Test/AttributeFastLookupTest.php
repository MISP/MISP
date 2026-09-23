<?php

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package) {}
    }
}

if (is_file(__DIR__ . '/../Lib/Tools/AttributeFastLookupTool.php')) {
    require_once __DIR__ . '/../Lib/Tools/AttributeFastLookupTool.php';
}

class FastLookupSqlStatement
{
    private $rows;
    private $offset = 0;
    public $closed = false;
    public function __construct(array $rows) { $this->rows = $rows; }
    public function fetch($mode) { return $this->rows[$this->offset++] ?? false; }
    public function closeCursor() { $this->closed = true; }
}

class FastLookupSqlDatasource
{
    public $config = ['host' => 'db', 'database' => 'misp', 'password' => 'secret'];
    public $queries = [];
    public $responses = [];
    public $aclConditions;
    public function name($name) { return '`' . str_replace('.', '`.`', $name) . '`'; }
    public function value($value, $type = null) { return "'" . str_replace("'", "''", $value) . "'"; }
    public function fullTableName($model) { return $this->name($model->useTable); }
    public function conditions($conditions, $quote, $where, $model)
    {
        $this->aclConditions = $conditions;
        return '`Event`.`org_id` = 7 AND (`Attribute`.`object_id` = 0 OR `Object`.`distribution` = 5)';
    }
    public function rawQuery($sql)
    {
        $this->queries[] = $sql;
        if (!$this->responses) {
            throw new RuntimeException('Unexpected SQL query.');
        }
        return new FastLookupSqlStatement(array_shift($this->responses));
    }
}

class FastLookupSqlAttribute
{
    public $useTable = 'attributes';
    public $Event;
    public $Object;
    public $db;
    public $users = [];
    public $columns = [
        'value1' => ['charset' => 'utf8mb3', 'collate' => 'utf8mb3_unicode_ci'],
        'value2' => ['charset' => 'utf8mb3', 'collate' => 'utf8mb3_unicode_ci'],
    ];
    public function __construct()
    {
        $this->db = new FastLookupSqlDatasource();
        $this->Event = (object)['useTable' => 'events'];
        $this->Object = (object)['useTable' => 'objects'];
    }
    public function getDataSource() { return $this->db; }
    public function schema($field) { return $this->columns[$field]; }
    public function buildConditions($user)
    {
        $this->users[] = $user;
        return ['Event.org_id' => 7];
    }
}

class FastLookupRecordingCache
{
    public $hits = [];
    public $reads = [];
    public $writes = [];
    public function getMany(array $values, $maxAge)
    {
        $this->reads[] = [$values, $maxAge];
        return $this->hits;
    }
    public function storeMany(array $values, array $candidates, $queriedAt)
    {
        $this->writes[] = [$values, $candidates, $queriedAt];
    }
}

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class AttributeFastLookupTest extends PHPUnit\Framework\TestCase
{
    protected function setUp(): void
    {
        require_once __DIR__ . '/fixtures/FastLookupConfigurationStub.php';
        require_once __DIR__ . '/../Lib/Tools/FastLookupCache.php';
    }

    private function tool(&$attribute, &$cache)
    {
        $this->assertTrue(class_exists('AttributeFastLookupTool'), 'The lookup module must exist.');
        $attribute = new FastLookupSqlAttribute();
        $cache = new FastLookupRecordingCache();
        return new AttributeFastLookupTool($attribute, $cache);
    }

    public function testCustomConfiguredDurationBecomesTheRequestDefault()
    {
        Configure::write('MISP.fast_lookup_cache_ttl', '21600');
        $tool = $this->tool($attribute, $cache);
        $cache->hits = [0 => []];
        $this->assertSame('{}', json_encode($tool->lookup([], ['value' => ['missing']])));
        $this->assertSame(21600, $cache->reads[0][1]);
        $this->assertSame([], $attribute->db->queries);
    }

    public function testCallerCanUseConfiguredMaximumOrRequestFresherData()
    {
        Configure::write('MISP.fast_lookup_cache_ttl', 120);
        $tool = $this->tool($attribute, $cache);
        $cache->hits = [0 => []];
        $this->assertSame('{}', json_encode($tool->lookup([], ['value' => ['missing'], 'maxAge' => 120])));
        $this->assertSame('{}', json_encode($tool->lookup([], ['value' => ['missing'], 'maxAge' => 30])));
        $this->assertSame([[['missing'], 120], [['missing'], 30]], $cache->reads);
        $this->expectException(InvalidArgumentException::class);
        $tool->lookup([], ['value' => ['missing'], 'maxAge' => 121]);
    }

    /** @dataProvider disabledDurations */
    public function testDisabledOrInvalidConfigurationAlwaysUsesFreshSql($configured)
    {
        Configure::write('MISP.fast_lookup_cache_ttl', $configured);
        $tool = $this->tool($attribute, $cache);
        $attribute->db->responses = [[['input_index' => 0, 'event_id' => '7']]];
        $this->assertSame('{"example.org":["7"]}', json_encode($tool->lookup([], ['value' => ['example.org']])));
        $this->assertSame([], $cache->reads);
        $this->assertSame([], $cache->writes);
        $this->assertCount(1, $attribute->db->queries);
        $this->assertStringContainsString('`Event`.`org_id` = 7', $attribute->db->queries[0]);
        $this->expectException(InvalidArgumentException::class);
        $tool->lookup([], ['value' => ['example.org'], 'maxAge' => 1]);
    }

    public static function disabledDurations()
    {
        return [[0], ['0'], ['invalid'], [-1], [false]];
    }

    public function testFreshLookupPreservesKeysAndAllDistinctSortedEvents()
    {
        $tool = $this->tool($attribute, $cache);
        $attribute->db->responses = [[
            ['input_index' => '0', 'event_id' => '10'],
            ['input_index' => '0', 'event_id' => '2'],
            ['input_index' => '0', 'event_id' => '10'],
            ['input_index' => '1', 'event_id' => '1'],
        ]];
        $result = $tool->lookup(['id' => 17], ['value' => ['ÉXAMPLE', '0', 'ÉXAMPLE', 'missing'], 'maxAge' => 0]);
        $this->assertSame('{"ÉXAMPLE":["2","10"],"0":["1"]}', json_encode($result, JSON_UNESCAPED_UNICODE));
        $this->assertSame([], $cache->reads);
        $this->assertSame([], $cache->writes);
        $this->assertCount(1, $attribute->db->queries);
        $sql = $attribute->db->queries[0];
        $this->assertStringContainsString('INNER JOIN `events`', $sql);
        $this->assertStringContainsString('LEFT JOIN `objects`', $sql);
        $this->assertStringContainsString('`Attribute`.`deleted` = 0', $sql);
        $this->assertStringContainsString('`Event`.`org_id` = 7', $sql);
        $this->assertStringContainsString('`Object`.`distribution` = 5', $sql);
        $this->assertSame([['id' => 17]], $attribute->users);
    }

    public function testLiteralOperatorsAreQuotedAndIpv6NormalizationPreservesOriginalKey()
    {
        $tool = $this->tool($attribute, $cache);
        $attribute->db->responses = [[['input_index' => 1, 'event_id' => '9']]];
        $result = $tool->lookup([], ['value' => ["!%' OR 1=1 --", '2001:0DB8:0:0::1'], 'maxAge' => 0]);
        $this->assertSame('{"2001:0DB8:0:0::1":["9"]}', json_encode($result));
        $sql = $attribute->db->queries[0];
        $this->assertStringContainsString("= '!%'' OR 1=1 --'", $sql);
        $this->assertStringContainsString("= '2001:db8::1'", $sql);
        $this->assertStringNotContainsString(' LIKE ', $sql);
    }

    public function testColdLookupCachesCompleteGlobalCandidatesAfterLiveChecks()
    {
        $tool = $this->tool($attribute, $cache);
        $attribute->db->responses = [
            [['input_index' => 0, 'attribute_id' => '11'], ['input_index' => 0, 'attribute_id' => '12']],
            [['input_index' => 0, 'event_id' => '7']],
        ];
        $started = microtime(true);
        $result = $tool->lookup([], ['value' => ['example.org', 'missing']]);
        $this->assertSame('{"example.org":["7"]}', json_encode($result));
        $this->assertSame([[['example.org', 'missing'], 10800]], $cache->reads);
        $this->assertSame([0 => ['11', '12'], 1 => []], $cache->writes[0][1]);
        $this->assertGreaterThanOrEqual($started, $cache->writes[0][2]);
        $this->assertStringNotContainsString('deleted', $attribute->db->queries[0]);
        $this->assertStringNotContainsString(' JOIN ', $attribute->db->queries[0]);
        $this->assertStringContainsString('`Attribute`.`id` IN (11,12)', $attribute->db->queries[1]);
        $this->assertStringContainsString("`Attribute`.`value1` = 'example.org'", $attribute->db->queries[1]);
        $this->assertStringContainsString("`Attribute`.`value2` = 'example.org'", $attribute->db->queries[1]);
    }

    public function testWarmPositiveAndNegativeHitsOnlyRunLiveChecksWithoutRefreshingCache()
    {
        $tool = $this->tool($attribute, $cache);
        $cache->hits = [0 => ['11', '12'], 1 => []];
        $attribute->db->responses = [[['input_index' => 0, 'event_id' => '8']]];
        $result = $tool->lookup([], ['value' => ['example.org', 'missing'], 'maxAge' => 3]);
        $this->assertSame('{"example.org":["8"]}', json_encode($result));
        $this->assertCount(1, $attribute->db->queries);
        $this->assertSame([], $cache->writes);
        $this->assertSame(3, $cache->reads[0][1]);
    }

    public function testEmptyAndInvisibleResultsAreObjects()
    {
        $tool = $this->tool($attribute, $cache);
        $this->assertSame('{}', json_encode($tool->lookup([], ['value' => []])));
        $this->assertSame([], $attribute->db->queries);
        $cache->hits = [0 => []];
        $this->assertSame('{}', json_encode($tool->lookup([], ['value' => ['0']])));
        $this->assertSame([], $attribute->db->queries);
    }

    /** @dataProvider invalidRequests */
    public function testRejectsMalformedRequestsBeforeSqlOrRedis(array $request)
    {
        $tool = $this->tool($attribute, $cache);
        try {
            $tool->lookup([], $request);
            $this->fail('Expected InvalidArgumentException.');
        } catch (Throwable $e) {
            $this->assertInstanceOf(InvalidArgumentException::class, $e);
            $this->assertSame([], $attribute->db->queries);
            $this->assertSame([], $cache->reads);
        }
    }

    public static function invalidRequests()
    {
        return [
            [[]], [['value' => 'x']], [['value' => ['a' => 'x']]],
            [['value' => [1 => 'x']]], [['value' => [1]]], [['value' => ['']]],
            [['value' => ["\xff"]]], [['value' => ["\0x"]]], [['value' => ["x\0y"]]],
            [['value' => ['x'], 'other' => true]],
            [['value' => ['x'], 'maxAge' => -1]], [['value' => ['x'], 'maxAge' => 10801]],
            [['value' => ['x'], 'maxAge' => '60']], [['value' => ['x'], 'maxAge' => 1.0]],
            [['value' => ['x'], 'maxAge' => null]], [['value' => ['x'], 'maxAge' => true]],
            [['value' => array_fill(0, 1001, 'x')]], [['value' => [str_repeat('x', 4097)]]],
            [['value' => array_fill(0, 257, str_repeat('x', 4096))]],
        ];
    }

    public function testBatchesInputsWithoutDroppingLaterMatches()
    {
        $tool = $this->tool($attribute, $cache);
        $attribute->db->responses = [[], [['input_index' => 100, 'event_id' => '1']]];
        $values = array_map(function ($i) { return 'ioc-' . $i; }, range(0, 100));
        $result = $tool->lookup([], ['value' => $values, 'maxAge' => 0]);
        $this->assertSame('{"ioc-100":["1"]}', json_encode($result));
        $this->assertCount(2, $attribute->db->queries);
    }

    public function testResourceLimitThrowsInsteadOfCachingPartialCandidates()
    {
        $tool = $this->tool($attribute, $cache);
        $attribute->db->responses = [array_fill(0, 100001, ['input_index' => 0, 'attribute_id' => '1'])];
        try {
            $tool->lookup([], ['value' => ['example.org']]);
            $this->fail('Expected OverflowException.');
        } catch (OverflowException $e) {
            $this->assertSame([], $cache->writes);
        }
    }

    public function testMixedCacheHitsDiscoverOnlyMissingInputsAndRetainTheirOrdinals()
    {
        $tool = $this->tool($attribute, $cache);
        $cache->hits = [0 => ['11'], 1 => []];
        $attribute->db->responses = [
            [['input_index' => 2, 'attribute_id' => '21']],
            [['input_index' => 2, 'event_id' => '8']],
        ];
        $result = $tool->lookup([], ['value' => ['old', 'negative', 'new']]);
        $this->assertSame('{"new":["8"]}', json_encode($result));
        $this->assertStringContainsString('SELECT 2 AS `input_index`', $attribute->db->queries[0]);
        $this->assertStringNotContainsString("= 'old'", $attribute->db->queries[0]);
        $this->assertSame([2 => ['21']], $cache->writes[0][1]);
    }

    public function testLiveQueryOverflowDoesNotPublishAnyCandidateEntries()
    {
        $tool = $this->tool($attribute, $cache);
        $attribute->db->responses = [
            [['input_index' => 0, 'attribute_id' => '11']],
            array_fill(0, 100000, ['input_index' => 0, 'event_id' => '1']),
        ];
        try {
            $tool->lookup([], ['value' => ['example.org']]);
            $this->fail('Expected OverflowException.');
        } catch (OverflowException $e) {
            $this->assertSame([], $cache->writes);
        }
    }

    public function testOversizedWarmCandidatesFailBeforeIssuingUnboundedSql()
    {
        $tool = $this->tool($attribute, $cache);
        $cache->hits = [0 => array_fill(0, 100001, '1')];
        try {
            $tool->lookup([], ['value' => ['example.org']]);
            $this->fail('Expected OverflowException.');
        } catch (OverflowException $e) {
            $this->assertSame([], $attribute->db->queries);
            $this->assertSame([], $cache->writes);
        }
    }

    public function testFourByteUtf8HasNoMatchInThreeByteColumnsWithoutSqlErrors()
    {
        $tool = $this->tool($attribute, $cache);
        $attribute->db->responses = [[]];
        $result = $tool->lookup([], ['value' => ['absent-😀'], 'maxAge' => 0]);
        $this->assertSame('{}', json_encode($result));
        $this->assertSame([], $attribute->db->queries);
    }

    public function testFourByteUtf8StillMatchesAComponentThatSupportsIt()
    {
        $tool = $this->tool($attribute, $cache);
        $attribute->columns['value2'] = ['charset' => 'utf8mb4', 'collate' => 'utf8mb4_unicode_ci'];
        $attribute->db->responses = [[['input_index' => 0, 'event_id' => '9']]];
        $result = $tool->lookup([], ['value' => ['stored-😀'], 'maxAge' => 0]);
        $this->assertSame('{"stored-😀":["9"]}', json_encode($result, JSON_UNESCAPED_UNICODE));
        $this->assertStringContainsString("`Attribute`.`value2` = 'stored-😀'", $attribute->db->queries[0]);
        $this->assertStringNotContainsString('`Attribute`.`value1`', $attribute->db->queries[0]);
    }

    public function testLegacyUtf8CollationMetadataAlsoSkipsUnsupportedLiterals()
    {
        $tool = $this->tool($attribute, $cache);
        $attribute->columns = ['value1' => ['collate' => 'utf8_unicode_ci'], 'value2' => ['charset' => 'utf8']];
        $attribute->db->responses = [[]];
        $this->assertSame('{}', json_encode($tool->lookup([], ['value' => ['😀'], 'maxAge' => 0])));
        $this->assertSame([], $attribute->db->queries);
    }
}
