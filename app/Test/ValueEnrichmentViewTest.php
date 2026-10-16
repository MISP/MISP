<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueEnrichmentTool.php';

use PHPUnit\Framework\TestCase;

class ValueEnrichmentViewTest extends TestCase
{
    private function answer(array $attributes, array $objects, $total)
    {
        return array(
            'attributes' => $attributes,
            'objects' => $objects,
            'elements' => array(),
            'total' => $total,
            'shown' => 0,
            'capped' => false,
        );
    }

    public function testTheDefaultViewIsTheFirstElementsInKeptOrder(): void
    {
        $view = ValueEnrichmentTool::view(
            $this->answer(range(1, 3), range(10, 19), 40),
            false,
            5
        );
        $this->assertSame(array(1, 2, 3), $view['attributes']);
        $this->assertSame(array(10, 11), $view['objects']);
        $this->assertSame(13, $view['kept']);
        $this->assertSame(5, $view['shown']);
        $this->assertTrue($view['capped']);
    }

    public function testAllShowsEveryKeptElement(): void
    {
        $view = ValueEnrichmentTool::view(
            $this->answer(range(1, 3), range(10, 19), 13),
            true,
            5
        );
        $this->assertCount(10, $view['objects']);
        $this->assertSame(13, $view['shown']);
        $this->assertFalse($view['capped']);
    }

    public function testAllStillSaysWhatWasNotKept(): void
    {
        $view = ValueEnrichmentTool::view(
            $this->answer(array(), range(1, 8), 50),
            true,
            5
        );
        $this->assertSame(8, $view['shown']);
        $this->assertTrue($view['capped']);
    }

    public function testAStoredRunMissingAListReadsAsEmpty(): void
    {
        $view = ValueEnrichmentTool::view(
            array('objects' => range(1, 3), 'total' => 3),
            false,
            200
        );
        $this->assertSame(array(), $view['elements']);
        $this->assertSame(3, $view['kept']);
        $this->assertFalse($view['capped']);
    }

    public function testEveryElementIsCheckedWhileItsValuesFit(): void
    {
        $budget = ValueEnrichmentTool::knownBudget(
            array(array('a', 'b'), array('b', 'c'), array(), array('d')),
            'x',
            10
        );
        $this->assertSame(4, $budget['checked']);
        $this->assertSame(array('a', 'b', 'c', 'd'), $budget['values']);
    }

    public function testCheckingStopsAtTheFirstElementThatWouldOverflow(): void
    {
        $budget = ValueEnrichmentTool::knownBudget(
            array(array('a', 'b'), array('c', 'd', 'e'), array('f')),
            'x',
            4
        );
        $this->assertSame(1, $budget['checked']);
        $this->assertSame(array('a', 'b'), $budget['values']);
    }

    public function testTheSubjectAndRepeatsCostNothing(): void
    {
        $budget = ValueEnrichmentTool::knownBudget(
            array(array('8.8.8.8', 'a'), array('a', '8.8.8.8'), array('b')),
            '8.8.8.8',
            2
        );
        $this->assertSame(3, $budget['checked']);
        $this->assertSame(array('a', 'b'), $budget['values']);
    }

    public function testNumericValuesStayStrings(): void
    {
        $budget = ValueEnrichmentTool::knownBudget(
            array(array('443', '1204')),
            'x',
            10
        );
        $this->assertSame(array('443', '1204'), $budget['values']);
    }
}
