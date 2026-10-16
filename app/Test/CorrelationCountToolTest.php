<?php
require_once __DIR__ . '/../Lib/Tools/CorrelationCountTool.php';

use PHPUnit\Framework\TestCase;

class CorrelationCountToolTest extends TestCase
{
    private function row($eventId)
    {
        return ['id' => $eventId, 'attribute_id' => 900, 'value' => 'x'];
    }

    public function testNothingCorrelates(): void
    {
        $counts = CorrelationCountTool::aggregate([], [
            ['id' => 1, 'uuid' => 'a-1', 'object_uuid' => null],
        ]);
        $this->assertSame(0, $counts['total']);
        $this->assertSame([], $counts['attributes']);
        $this->assertSame([], $counts['objects']);
        $this->assertSame([], $counts['events']);
    }

    public function testCountsPerAttributeObjectAndEvent(): void
    {
        $related = [
            1 => [$this->row(7), $this->row(7), $this->row(8)],
            2 => [$this->row(8)],
            3 => [$this->row(9)],
        ];
        $attributes = [
            ['id' => 1, 'uuid' => 'a-1', 'object_uuid' => 'o-1'],
            ['id' => 2, 'uuid' => 'a-2', 'object_uuid' => 'o-1'],
            ['id' => 3, 'uuid' => 'a-3', 'object_uuid' => null],
        ];
        $counts = CorrelationCountTool::aggregate($related, $attributes);

        $this->assertSame(5, $counts['total']);
        $this->assertSame(['a-1' => 3, 'a-2' => 1, 'a-3' => 1], $counts['attributes']);
        $this->assertSame(['o-1' => 4], $counts['objects']);
        $this->assertSame(['7' => 2, '8' => 2, '9' => 1], $counts['events']);
    }

    public function testAttributeTheUserCannotSeeIsNotCounted(): void
    {
        $related = [
            1 => [$this->row(7)],
            2 => [$this->row(7), $this->row(8)],
        ];
        $counts = CorrelationCountTool::aggregate($related, [
            ['id' => 1, 'uuid' => 'a-1', 'object_uuid' => null],
        ]);
        $this->assertSame(1, $counts['total']);
        $this->assertSame(['a-1' => 1], $counts['attributes']);
        $this->assertSame(['7' => 1], $counts['events']);
    }
}
