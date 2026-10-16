<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueDictionaryStatsTool.php';

use PHPUnit\Framework\TestCase;

class ValueDictionaryStatsToolTest extends TestCase
{
    const DAY = 86400;

    // 2026-10-16 12:00 UTC
    const NOW = 1792152000;

    private function read($valuesMax, $attributesMax, $total, $newValues = null, $newAttributes = null)
    {
        return [
            'values_max_id' => $valuesMax,
            'attributes_max_id' => $attributesMax,
            'total' => $total,
            'new_values' => $newValues,
            'new_attributes' => $newAttributes,
        ];
    }

    public function testFirstRunTakesTheFullCountAndHasNoHistory()
    {
        $state = ValueDictionaryStatsTool::rollForward(null, $this->read(400, 900, 250), self::NOW);
        $this->assertSame(250, $state['total']);
        $this->assertSame([], $state['days']);
        $this->assertSame(self::NOW, $state['started_at']);
        $this->assertSame(self::NOW, $state['full_at']);
        $this->assertSame(400, $state['values_max_id']);
        $this->assertSame(900, $state['attributes_max_id']);
    }

    public function testDeltaRunAddsToTheTotalAndTodaysBucket()
    {
        $state = ValueDictionaryStatsTool::rollForward(null, $this->read(400, 900, 250), self::NOW - self::DAY);
        $state = ValueDictionaryStatsTool::rollForward($state, $this->read(430, 1000, null, 20, 70), self::NOW);
        $state = ValueDictionaryStatsTool::rollForward($state, $this->read(440, 1010, null, 5, 10), self::NOW + 60);
        $this->assertSame(275, $state['total']);
        $this->assertSame(['2026-10-16' => ['values' => 25, 'attributes' => 80]], $state['days']);
        $this->assertSame(self::NOW - self::DAY, $state['full_at']);
        $this->assertSame(440, $state['values_max_id']);
    }

    public function testFullRecountReplacesTheTotalButKeepsTheDelta()
    {
        $state = ValueDictionaryStatsTool::rollForward(null, $this->read(400, 900, 250), self::NOW - self::DAY);
        $state = ValueDictionaryStatsTool::rollForward($state, $this->read(430, 1000, 262, 20, 70), self::NOW);
        $this->assertSame(262, $state['total']);
        $this->assertSame(20, $state['days']['2026-10-16']['values']);
        $this->assertSame(self::NOW, $state['full_at']);
    }

    public function testBucketsOlderThanThirtyDaysArePruned()
    {
        $state = ValueDictionaryStatsTool::rollForward(null, $this->read(1, 1, 1), self::NOW - 40 * self::DAY);
        $state['days'] = [
            gmdate('Y-m-d', self::NOW - 30 * self::DAY) => ['values' => 1, 'attributes' => 1],
            gmdate('Y-m-d', self::NOW - 29 * self::DAY) => ['values' => 2, 'attributes' => 2],
        ];
        $state = ValueDictionaryStatsTool::rollForward($state, $this->read(1, 1, null, 0, 0), self::NOW);
        $this->assertSame([gmdate('Y-m-d', self::NOW - 29 * self::DAY)], array_keys($state['days']));
    }

    public function testSummaryWindowsTheLastSevenDaysAndAddsTheLiveTail()
    {
        $state = ValueDictionaryStatsTool::rollForward(null, $this->read(1, 1, 1000), self::NOW - 20 * self::DAY);
        $state['days'] = [
            gmdate('Y-m-d', self::NOW - 7 * self::DAY) => ['values' => 500, 'attributes' => 900],
            gmdate('Y-m-d', self::NOW - 6 * self::DAY) => ['values' => 10, 'attributes' => 30],
            gmdate('Y-m-d', self::NOW) => ['values' => 3, 'attributes' => 4],
        ];
        $summary = ValueDictionaryStatsTool::summarise($state, 7, 11, self::NOW);
        $this->assertSame(1007, $summary['total']);
        $this->assertFalse($summary['total_floor']);
        $this->assertSame(20, $summary['recent']['values']);
        $this->assertSame(45, $summary['recent']['attributes']);
        $this->assertNull($summary['recent']['since']);
        $this->assertCount(30, $summary['series']);
        $last = end($summary['series']);
        $this->assertSame(['day' => '2026-10-16', 'values' => 10], $last);
        $this->assertSame(0, $summary['series'][28]['values']);
    }

    public function testDaysBeforeTheFirstCountAreUnknownNotZero()
    {
        $state = ValueDictionaryStatsTool::rollForward(null, $this->read(1, 1, 50), self::NOW - 2 * self::DAY);
        $summary = ValueDictionaryStatsTool::summarise($state, 0, 0, self::NOW);
        $this->assertSame(self::NOW - 2 * self::DAY, $summary['recent']['since']);
        $this->assertNull($summary['series'][26]['values']);
        $this->assertSame(0, $summary['series'][27]['values']);
    }

    public function testAnOverflowingTailIsCappedAndFlagged()
    {
        $state = ValueDictionaryStatsTool::rollForward(null, $this->read(1, 1, 50), self::NOW - 3 * self::DAY);
        $over = ValueDictionaryStatsTool::LIVE_CAP + 1;
        $summary = ValueDictionaryStatsTool::summarise($state, $over, 3, self::NOW);
        $this->assertTrue($summary['total_floor']);
        $this->assertTrue($summary['recent']['floor']);
        $this->assertSame(50 + ValueDictionaryStatsTool::LIVE_CAP, $summary['total']);

        $summary = ValueDictionaryStatsTool::summarise($state, 3, $over, self::NOW);
        $this->assertFalse($summary['total_floor']);
        $this->assertTrue($summary['recent']['floor']);
    }
}
