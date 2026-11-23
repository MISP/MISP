<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

class TagOnlyFilterFakeModel
{
    public $rows;
    public $queries = [];

    public function __construct(array $rows)
    {
        $this->rows = $rows;
    }

    public function find($type, array $query)
    {
        $this->queries[] = $query;
        return isset($query['limit']) ? array_slice($this->rows, 0, $query['limit']) : $this->rows;
    }

    public function query($sql)
    {
        $this->queries[] = $sql;
        preg_match('/LIMIT (\d+)/', $sql, $limit);
        return [[['c' => (string)min(count($this->rows), (int)$limit[1])]]];
    }
}

/**
 * Runs the real MispAttribute::__tagOnlyCondition() body against fake tag
 * tables honouring the query limit, with a budget of 10 attributes.
 */
class AttributeTagOnlyFilterTest extends TestCase
{
    private static function stubClass()
    {
        $name = 'MispAttributeStubForTagOnlyFilter';
        if (!class_exists($name, false)) {
            $source = file_get_contents(__DIR__ . '/../Model/MispAttribute.php');
            $start = strpos($source, 'private function __tagOnlyCondition(');
            $open = strpos($source, '{', $start);
            $depth = 0;
            for ($i = $open, $n = strlen($source); $i < $n; $i++) {
                if ($source[$i] === '{') {
                    $depth++;
                } elseif ($source[$i] === '}' && --$depth === 0) {
                    break;
                }
            }
            $method = substr($source, $start, $i - $start + 1);
            eval('class ' . $name . ' {
                const TAG_FILTER_ID_LIST_LIMIT = 10;
                public $Event;
                public $AttributeTag;
                public function run(array $tagIds) { return $this->__tagOnlyCondition($tagIds); }
                ' . $method . '
            }');
        }
        return $name;
    }

    /**
     * @param array $events [event id => attribute_count]
     * @param array $attributeIds
     */
    private function condition(array $events, array $attributeIds, array $tagIds = [7])
    {
        $eventRows = [];
        foreach ($events as $row) {
            $eventRows[] = ['EventTag' => ['event_id' => (string)$row[0]], 'Event' => ['attribute_count' => (string)$row[1]]];
        }
        $class = self::stubClass();
        $stub = new $class();
        $stub->Event = new stdClass();
        $stub->Event->EventTag = new TagOnlyFilterFakeModel($eventRows);
        $stub->AttributeTag = new TagOnlyFilterFakeModel(array_map('strval', $attributeIds));
        return [$stub->run($tagIds), $stub];
    }

    private function assertSubqueries($condition, $tagList = '7')
    {
        $this->assertIsString($condition);
        $this->assertStringContainsString("FROM attribute_tags at WHERE at.tag_id IN ({$tagList})", $condition);
        $this->assertStringContainsString("FROM event_tags et WHERE et.tag_id IN ({$tagList})", $condition);
    }

    public function testFewMatchesBecomeExactIdLists()
    {
        list($condition) = $this->condition([[1, 5]], [11, 12]);
        $this->assertSame(['OR' => [['Attribute.id' => [11, 12]], ['Attribute.event_id' => [1]]]], $condition);
    }

    public function testExactlyTheBudgetStillUsesTheCompleteLists()
    {
        list($condition) = $this->condition([[1, 4], [2, 3]], [21, 22, 23]);
        $this->assertSame(['OR' => [['Attribute.id' => [21, 22, 23]], ['Attribute.event_id' => [1, 2]]]], $condition);
    }

    public function testEventsOverTheBudgetKeepTheSubqueries()
    {
        list($condition, $stub) = $this->condition([[1, 6], [2, 5]], [11]);
        $this->assertSubqueries($condition);
        $this->assertSame([], $stub->AttributeTag->queries);
    }

    public function testACutOffEventListAlwaysFallsBack()
    {
        // Eleven empty events: the limit (11) returns them all, each costs 1
        list($condition) = $this->condition(array_map(function ($id) {
            return [$id, 0];
        }, range(1, 11)), []);
        $this->assertSubqueries($condition);
    }

    public function testAttributeTagsOverTheRemainingBudgetKeepTheSubqueries()
    {
        list($condition, $stub) = $this->condition([[1, 7]], [11, 12, 13, 14]);
        $this->assertSubqueries($condition);
        $this->assertCount(1, $stub->AttributeTag->queries, 'the ids are not fetched');
        $this->assertStringContainsString('WHERE tag_id IN (7) LIMIT 4)', $stub->AttributeTag->queries[0]);
    }

    public function testTheFetchedAttributeListIsNeverCut()
    {
        list($condition, $stub) = $this->condition([[1, 2]], range(101, 108));
        $this->assertSame(range(101, 108), $condition['OR'][0]['Attribute.id']);
        $this->assertArrayNotHasKey('limit', $stub->AttributeTag->queries[1]);
    }

    public function testNoTaggedRowsMatchNothing()
    {
        list($condition) = $this->condition([], []);
        $this->assertSame(['Attribute.id' => -1], $condition);
    }

    public function testRepeatedIdsAppearOnce()
    {
        list($condition) = $this->condition([[1, 1], [1, 1], [2, 1]], [11, 11, 12], [7, 8]);
        $this->assertSame(['OR' => [['Attribute.id' => [11, 12]], ['Attribute.event_id' => [1, 2]]]], $condition);
    }

    public function testFallbackCarriesEveryTag()
    {
        list($condition) = $this->condition([[1, 50]], [], [7, 8]);
        $this->assertSubqueries($condition, '7,8');
    }
}
