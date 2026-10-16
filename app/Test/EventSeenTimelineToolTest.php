<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
require_once __DIR__
    . '/../Lib/Tools/ValueIntelligence/ValueIntelligenceBuckets.php';
require_once __DIR__ . '/../Lib/Tools/EventOverview/EventSeenTimelineTool.php';

use PHPUnit\Framework\TestCase;

class EventSeenTimelineToolTest extends TestCase
{
    private static function day($date)
    {
        return intdiv((new DateTimeImmutable($date . ' 00:00:00', new DateTimeZone('UTC')))->getTimestamp(), 86400);
    }

    private static function counts(array $histogram)
    {
        $counts = [];
        foreach ($histogram['bars'] as $bar) {
            $counts[$bar['from']] = $bar['count'];
        }
        return $counts;
    }

    public function testNoDatedRowsHasNoHistogram()
    {
        $this->assertNull(EventSeenTimelineTool::histogram([], [], '2026-10-05'));
    }

    public function testARangeCountsInEveryBucketItSpansAndAPointInOne()
    {
        $starts = [self::day('2024-01-03') => 1, self::day('2024-01-10') => 1];
        $ends = [self::day('2024-01-05') => 1, self::day('2024-01-10') => 1];
        $histogram = EventSeenTimelineTool::histogram($starts, $ends, '2026-10-05');

        $this->assertSame('day', $histogram['unit']);
        $this->assertSame('2024-01-03', $histogram['from']);
        $this->assertSame('2024-01-10', $histogram['to']);
        $this->assertSame([
            '2024-01-03' => 1, '2024-01-04' => 1, '2024-01-05' => 1, '2024-01-06' => 0,
            '2024-01-07' => 0, '2024-01-08' => 0, '2024-01-09' => 0, '2024-01-10' => 1,
        ], self::counts($histogram));
        $this->assertSame(1, $histogram['max']);
        $this->assertSame(0, $histogram['outside']);
    }

    public function testOverlappingRowsAddUpPerBucket()
    {
        $starts = [self::day('2024-01-01') => 2, self::day('2024-01-02') => 1];
        $ends = [self::day('2024-01-03') => 3];
        $histogram = EventSeenTimelineTool::histogram($starts, $ends, '2026-10-05');

        $this->assertSame(['2024-01-01' => 2, '2024-01-02' => 3, '2024-01-03' => 3], self::counts($histogram));
        $this->assertSame(3, $histogram['max']);
    }

    public function testTheUnitWidensWithTheSpan()
    {
        $weekly = EventSeenTimelineTool::histogram(
            [self::day('2024-01-01') => 1],
            [self::day('2024-06-01') => 1],
            '2026-10-05'
        );
        $monthly = EventSeenTimelineTool::histogram(
            [self::day('2020-01-15') => 1],
            [self::day('2024-06-01') => 1],
            '2026-10-05'
        );

        $this->assertSame('week', $weekly['unit']);
        $this->assertSame('month', $monthly['unit']);
        $this->assertSame('2020-01-01', $monthly['bars'][0]['from']);
        $this->assertSame(1, min(array_column($monthly['bars'], 'count')));
    }

    public function testRowsFarInTheFutureAreOutsideTheSpan()
    {
        $future = self::day('2026-10-05') + EventSeenTimelineTool::SPAN_AHEAD_DAYS + 100;
        $histogram = EventSeenTimelineTool::histogram(
            [self::day('2024-01-01') => 1, $future => 2],
            [self::day('2024-01-02') => 1, $future => 2],
            '2026-10-05'
        );

        $this->assertSame(2, $histogram['outside']);
        $this->assertSame(
            gmdate('Y-m-d', (self::day('2026-10-05') + EventSeenTimelineTool::SPAN_AHEAD_DAYS) * 86400),
            $histogram['to']
        );
        $this->assertSame(1, $histogram['bars'][0]['count']);
    }

    public function testRowsBeforeTheWidestSpanAreOutsideIt()
    {
        $histogram = EventSeenTimelineTool::histogram(
            [self::day('1900-01-01') => 1, self::day('2020-01-01') => 1],
            [self::day('1900-01-02') => 1, self::day('2020-02-01') => 1],
            '2026-10-05'
        );

        $this->assertSame(1, $histogram['outside']);
        $this->assertSame(
            substr(gmdate('Y-m-d', (self::day('2020-02-01') - EventSeenTimelineTool::SPAN_MAX_DAYS + 1) * 86400), 0, 7),
            substr($histogram['from'], 0, 7)
        );
        $this->assertSame(0, $histogram['bars'][0]['count']);
    }

    public function testARowStraddlingTheLowerEdgeStillCounts()
    {
        $histogram = EventSeenTimelineTool::histogram(
            [self::day('1900-01-01') => 1],
            [self::day('2020-01-01') => 1],
            '2026-10-05'
        );

        $this->assertSame(0, $histogram['outside']);
        $this->assertSame(1, $histogram['bars'][0]['count']);
    }

    public function testTheWindowDefaultsToTheSpan()
    {
        $histogram = ['from' => '2024-01-01', 'to' => '2024-03-01'];

        $this->assertSame(
            [self::day('2024-01-01'), self::day('2024-03-01')],
            EventSeenTimelineTool::window([], $histogram)
        );
        $this->assertSame(
            [self::day('2024-02-01'), self::day('2024-03-01')],
            EventSeenTimelineTool::window(['from' => '2024-02-01', 'to' => 'nonsense'], $histogram)
        );
        $this->assertSame(
            [self::day('2024-01-05'), self::day('2024-01-09')],
            EventSeenTimelineTool::window(['from' => '2024-01-09', 'to' => '2024-01-05'], $histogram)
        );
        $this->assertNull(EventSeenTimelineTool::window([], null));
    }

    public function testRowsMergeEarliestFirstAndAreCut()
    {
        $merged = EventSeenTimelineTool::mergeRows(
            [['id' => 1, 's' => '300'], ['id' => 2, 's' => '100']],
            [['id' => 9, 's' => '200'], ['id' => 8, 's' => '100']],
            3
        );

        $this->assertSame(
            ['attribute:2', 'object:8', 'object:9'],
            array_map(function ($row) {
                return $row['kind'] . ':' . $row['id'];
            }, $merged)
        );
    }

    public function testAFilterPicksTheKindsItCanMatch()
    {
        $this->assertSame(['attributes' => true, 'objects' => true], EventSeenTimelineTool::wanted([]));
        $this->assertSame(
            ['attributes' => true, 'objects' => false],
            EventSeenTimelineTool::wanted(['types' => ['ip-dst']])
        );
        $this->assertSame(
            ['attributes' => false, 'objects' => true],
            EventSeenTimelineTool::wanted(['objects' => ['file']])
        );
        $this->assertSame(
            ['attributes' => true, 'objects' => true],
            EventSeenTimelineTool::wanted(['types' => ['ip-dst'], 'objects' => ['file']])
        );
        $this->assertSame(
            ['attributes' => false, 'objects' => true],
            EventSeenTimelineTool::wanted(['kind' => 'object'])
        );
    }

    public function testAnEventFilterOnlyNarrowsTheView()
    {
        $this->assertSame([7, 9], EventSeenTimelineTool::filterEvents(['7', '9'], []));
        $this->assertSame([9], EventSeenTimelineTool::filterEvents([7, 9], ['9', '12']));
        $this->assertSame([], EventSeenTimelineTool::filterEvents([7, 9], ['12']));
    }

    public function testLabelsJoinCompositesAndAreCut()
    {
        $this->assertSame('evil.exe|d41d8cd9', EventSeenTimelineTool::label('evil.exe', 'd41d8cd9'));
        $this->assertSame('1.2.3.4', EventSeenTimelineTool::label('1.2.3.4', ''));
        $long = EventSeenTimelineTool::label(str_repeat('é', 300), '');
        $this->assertSame(EventSeenTimelineTool::LABEL_MAX, mb_strlen($long));
        $this->assertSame('…', mb_substr($long, -1));
    }

    public function testTalliesMergeAcrossAnExtensionSet()
    {
        $tally = function ($attributes, $objects, array $types) {
            return [
                'starts' => [100 => $attributes], 'ends' => [101 => $attributes],
                'attributes' => $attributes, 'objects' => $objects, 'undated' => 1,
                'undated_attributes' => 1, 'undated_objects' => 0,
                'facets' => ['types' => $types, 'objects' => [], 'categories' => []],
            ];
        };
        $merged = EventSeenTimelineTool::mergeTallies([
            7 => $tally(2, 1, ['ip-dst' => 2]),
            9 => $tally(3, 0, ['ip-dst' => 1, 'domain' => 2]),
        ]);

        $this->assertSame([100 => 5], $merged['starts']);
        $this->assertSame(5, $merged['attributes']);
        $this->assertSame(2, $merged['undated']);
        $this->assertSame(2, $merged['undated_attributes']);
        $this->assertSame(0, $merged['undated_objects']);
        $this->assertSame(['ip-dst' => 3, 'domain' => 2], $merged['facets']['types']);
        $this->assertSame([7 => 3, 9 => 3], $merged['facets']['events']);
    }

    public function testItemsCarryOwnDatesAndTheirSpan()
    {
        $object = EventSeenTimelineTool::objectItem([
            'id' => '5', 'uuid' => 'u', 'event_id' => '7', 'name' => 'file', 'category' => 'file',
            'ofs' => '2000', 'ols' => null, 's' => '1000', 'e' => '2000', 'dated_children' => '2',
        ]);
        $attribute = EventSeenTimelineTool::attributeItem([
            'id' => '6', 'uuid' => 'v', 'event_id' => '7', 'type' => 'md5', 'category' => 'Payload delivery',
            'to_ids' => '1', 'value1' => 'abc', 'value2' => '', 'first_seen' => null, 'last_seen' => '3000',
            's' => '3000', 'e' => '3000', 'object_relation' => 'md5',
        ]);

        $this->assertSame([2000, null, 1000, 2000, 2], [
            $object['first_seen'], $object['last_seen'], $object['start'], $object['end'],
            $object['children_count'],
        ]);
        $this->assertSame([null, 3000, true, 'md5'], [
            $attribute['first_seen'], $attribute['last_seen'], $attribute['to_ids'], $attribute['relation'],
        ]);
    }

    public function testTheBasisIsSeenUnlessTheTimestampIsAsked()
    {
        $this->assertSame('seen', EventSeenTimelineTool::basis([]));
        $this->assertSame('seen', EventSeenTimelineTool::basis(['basis' => 'created']));
        $this->assertSame('timestamp', EventSeenTimelineTool::basis(['basis' => 'timestamp']));
    }

    public function testTheTimestampBasisPlacesARowAtOneInstant()
    {
        $start = EventSeenTimelineTool::dateSql('timestamp', 'Attribute', 's');
        $this->assertSame($start, EventSeenTimelineTool::dateSql('timestamp', 'Attribute', 'e'));
        $this->assertStringContainsString('NULLIF(Attribute.timestamp, 0)', $start);
        $this->assertSame('Attribute.timestamp > 0', EventSeenTimelineTool::datedSql('timestamp', 'Attribute'));
        $this->assertStringContainsString('first_seen', EventSeenTimelineTool::dateSql('seen', 'Object', 's'));
    }

    public function testItemsCarryTheirTimestampInMicroseconds()
    {
        $attribute = EventSeenTimelineTool::attributeItem([
            'id' => '6', 'uuid' => 'v', 'event_id' => '7', 'type' => 'md5', 'category' => 'Payload delivery',
            'to_ids' => '0', 'value1' => 'abc', 'value2' => '', 'first_seen' => null, 'last_seen' => null,
            'timestamp' => '1700000000', 's' => '1700000000000000', 'e' => '1700000000000000',
        ]);
        $object = EventSeenTimelineTool::objectItem([
            'id' => '5', 'uuid' => 'u', 'event_id' => '7', 'name' => 'file', 'category' => 'file',
            'ofs' => null, 'ols' => null, 'ots' => '0', 's' => null, 'e' => null, 'dated_children' => '0',
        ]);

        $this->assertSame(1700000000000000, $attribute['timestamp']);
        $this->assertNull($object['timestamp']);
    }
}
