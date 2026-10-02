<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/QueryPlanSummary.php';

class QueryPlanSummaryTest extends TestCase
{
    public function testShapeDropsLiteralsCommentsAndSchema()
    {
        $sql = "/* [User: 1] Events :: view */ SELECT `Attribute`.`id`, "
            . "`Attribute`.`1_attribute_id` FROM `misp`.`attributes` AS "
            . "`Attribute` WHERE `Attribute`.`value1` = 'it\\'s' AND "
            . "`Attribute`.`event_id` = 5386 AND `Attribute`.`id` IN "
            . "(1, 2, 3) AND value2 <> '' LIMIT 60, -1";
        $this->assertSame(
            'SELECT `Attribute`.`id`, `Attribute`.`1_attribute_id` FROM '
            . '`attributes` AS `Attribute` WHERE `Attribute`.`value1` = ? '
            . 'AND `Attribute`.`event_id` = ? AND `Attribute`.`id` IN (?+) '
            . 'AND value2 <> ? LIMIT ?, ?',
            QueryPlanSummary::shape($sql, 'misp')
        );
    }

    public function testShapeKeepsDigitsInsideIdentifiers()
    {
        $this->assertSame(
            'SELECT a.value1, t1.x FROM attributes a WHERE a.id > ?',
            QueryPlanSummary::shape(
                "SELECT a.value1, t1.x FROM attributes a WHERE a.id > 10.5"
            )
        );
    }

    public function testShapeCollapsesListsAndValueRows()
    {
        $this->assertSame(
            'INSERT INTO `default_correlations` (`a`, `b`) VALUES (?+), ...',
            QueryPlanSummary::shape(
                "INSERT INTO `default_correlations` (`a`, `b`) VALUES "
                . "(1, 'x'), (2, 'y'),\n (3, 'z')"
            )
        );
        $this->assertSame(
            'SELECT * FROM attributes WHERE value1 IN (?+)',
            QueryPlanSummary::shape(
                "SELECT * FROM attributes WHERE value1 IN ('a')"
            )
        );
    }

    public function testKindAndExplainVerb()
    {
        $this->assertSame('select', QueryPlanSummary::kind('(SELECT 1)'));
        $this->assertSame(
            'ANALYZE',
            QueryPlanSummary::explainVerb('SELECT a FROM attributes')
        );
        $this->assertSame(
            'EXPLAIN',
            QueryPlanSummary::explainVerb('DELETE FROM attributes')
        );
        $this->assertSame(
            'EXPLAIN',
            QueryPlanSummary::explainVerb(
                'INSERT INTO tmp_source_values SELECT ? FROM attributes'
            )
        );
        $this->assertNull(
            QueryPlanSummary::explainVerb('INSERT INTO attributes VALUES (?+)')
        );
        $this->assertNull(
            QueryPlanSummary::explainVerb('SHOW FULL COLUMNS FROM attributes')
        );
    }

    public function testValueTablesAreMatchedAsWholeNames()
    {
        $this->assertTrue(QueryPlanSummary::touchesValueTables(
            'SELECT * FROM `attributes` AS `Attribute`'
        ));
        $this->assertTrue(QueryPlanSummary::touchesValueTables(
            'SELECT * FROM default_correlations'
        ));
        $this->assertFalse(QueryPlanSummary::touchesValueTables(
            'SELECT * FROM `object_attributes`, events'
        ));
    }

    public function testSummariseIndexMergeUnderFilesort()
    {
        $plan = ['query_block' => ['select_id' => 1, 'r_loops' => 1,
            'nested_loop' => [['read_sorted_file' => ['r_rows' => 5,
                'filesort' => ['sort_key' => 'a.value1', 'r_loops' => 1,
                    'table' => [
                        'table_name' => 'a',
                        'access_type' => 'index_merge',
                        'index_merge' => ['sort_union' => [
                            ['range' => ['key' => 'idx_value1',
                                'used_key_parts' => ['value1']]],
                            ['range' => ['key' => 'idx_value2']],
                        ]],
                        'r_loops' => 1, 'rows' => 44, 'r_rows' => 43,
                        'r_total_time_ms' => 0.2,
                    ]]]]]]];
        $this->assertSame([
            'tables' => [[
                'table' => 'a', 'access' => 'index_merge',
                'merged' => ['value1', 'idx_value2'],
                'loops' => 1, 'examined' => 43,
            ]],
            'filesort' => true,
            'temporary' => false,
        ], QueryPlanSummary::summarise($plan));
        $this->assertSame(
            ['a idx_value1+idx_value2'],
            QueryPlanSummary::indexes($plan)
        );
    }

    public function testSummariseMaterialisedSubquery()
    {
        $plan = ['query_block' => ['nested_loop' => [
            ['table' => ['table_name' => 'e', 'access_type' => 'index',
                'key' => 'idx_e', 'used_key_parts' => ['org_id', 'id'],
                'using_index' => true, 'rows' => 6438]],
            ['table' => ['table_name' => '<subquery2>',
                'access_type' => 'eq_ref', 'key' => 'distinct_key',
                'materialized' => ['unique' => 1, 'query_block' => [
                    'temporary_table' => ['nested_loop' => [['table' => [
                        'table_name' => 'attributes',
                        'access_type' => 'ALL',
                        'r_loops' => 2, 'r_rows' => 1000000.5,
                    ]]]],
                ]]]],
        ]]];
        $summary = QueryPlanSummary::summarise($plan);
        $this->assertSame([
            ['table' => 'e', 'access' => 'index',
                'key_parts' => ['org_id', 'id'], 'covering' => true],
            ['table' => '<subquery2>', 'access' => 'eq_ref',
                'key' => 'distinct_key', 'materialized' => true],
            ['table' => 'attributes', 'access' => 'ALL', 'loops' => 2,
                'examined' => 2000001],
        ], $summary['tables']);
        $this->assertFalse($summary['filesort']);
        $this->assertTrue($summary['temporary']);
        $this->assertSame(
            ['#1 e index ?', '#1 attributes ALL 2000001'],
            QueryPlanSummary::largeReads([$summary])
        );
        $this->assertSame(
            ['e idx_e', '<subquery2> distinct_key', 'attributes'],
            QueryPlanSummary::indexes($plan)
        );
    }

    public function testSummariseKeepsPlanMessages()
    {
        $plan = ['query_block' => ['select_id' => 1, 'table' => [
            'message' => 'Impossible WHERE noticed after reading const tables',
        ]]];
        $this->assertSame([
            'tables' => [],
            'filesort' => false,
            'temporary' => false,
            'notes' => ['Impossible WHERE noticed after reading const tables'],
        ], QueryPlanSummary::summarise($plan));
    }

    public function testLargeReadsCountRowsWhateverTheAccess()
    {
        $statements = [
            ['tables' => [['table' => 'a', 'access' => 'ALL',
                'examined' => 99999]]],
            ['tables' => [['table' => 'b', 'access' => 'ref',
                'examined' => 5000000]]],
            ['explain_error' => 'x'],
            ['tables' => [['table' => '<union1,2>', 'access' => 'ALL']]],
            ['tables' => [['table' => 'c', 'access' => 'ref'],
                ['table' => 'd', 'access' => 'ALL']]],
        ];
        $this->assertSame(
            ['#2 b ref 5000000', '#5 d ALL ?'],
            QueryPlanSummary::largeReads($statements)
        );
    }
}
