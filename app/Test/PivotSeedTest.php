<?php
require_once __DIR__ . '/../Lib/Tools/PivotExplorer/PivotSeed.php';

use PHPUnit\Framework\TestCase;

class PivotSeedTest extends TestCase
{
    public function testLinksAreDrawnWhateverTheirCost(): void
    {
        $seed = new PivotSeed(3);
        $seed->linkObject(10);
        $seed->linkAttribute(5, 0);
        $seed->addChildCounts([10 => 9]);

        $this->assertSame(11, $seed->linkedCost());
        $this->assertSame(['attributes' => [5], 'objects' => [10]], $seed->elements());
    }

    public function testAnAttributeInAnObjectBringsTheObject(): void
    {
        $seed = new PivotSeed();
        $seed->linkAttribute(7, 42);

        $this->assertSame([], $seed->linkedAttributeIds());
        $this->assertSame([42], $seed->linkedObjectIds());
    }

    public function testHitsLandWhenTheyAllFit(): void
    {
        $seed = new PivotSeed(10);
        $seed->linkObject(1);
        $seed->hit(20, 0);
        $seed->hit(21, 2);
        $seed->addChildCounts([1 => 2, 2 => 3]);

        // 3 linked + 1 free hit + an object of 1 + 3
        $this->assertSame(3, $seed->linkedCost());
        $this->assertSame(5, $seed->hitCost());
        $this->assertTrue($seed->hitsFit());
        $this->assertSame(['attributes' => [20], 'objects' => [1, 2]], $seed->elements());
    }

    public function testHitsLandWholeOrNotAtAll(): void
    {
        $seed = new PivotSeed(4);
        $seed->linkAttribute(1);
        $seed->hit(2);
        $seed->hit(3);
        $seed->hit(4, 9);
        $seed->addChildCounts([9 => 1]);

        $this->assertFalse($seed->hitsFit());
        $this->assertSame(['attributes' => [1], 'objects' => []], $seed->elements());
    }

    public function testAHitOnSomethingAlreadyLinkedCostsNothing(): void
    {
        $seed = new PivotSeed();
        $seed->linkObject(3);
        $seed->linkAttribute(8);
        $seed->hit(30, 3);
        $seed->hit(8);

        $this->assertFalse($seed->hasHits());
        $this->assertSame(0, $seed->hitCost());
    }

    public function testLinkingLaterTakesAnElementOutOfTheHits(): void
    {
        $seed = new PivotSeed();
        $seed->hit(8);
        $seed->hit(30, 3);
        $seed->linkAttribute(8);
        $seed->linkObject(3);

        $this->assertFalse($seed->hasHits());
    }

    public function testOnlyObjectsWithoutACountAreAskedFor(): void
    {
        $seed = new PivotSeed();
        $seed->linkObject(1);
        $seed->hit(5, 2);
        $seed->addChildCounts([1 => 4]);

        $this->assertSame([2], $seed->uncountedObjectIds());
    }

    public function testFarEndsCountOncePerNode(): void
    {
        $seed = new PivotSeed();
        $seed->linkFarEnd('event:abc');
        $seed->linkFarEnd('event:abc');
        $seed->linkFarEnd('GalaxyCluster:def');

        $this->assertSame(2, $seed->linkedCost());
    }

    public function testFeedHitsAreScannedUpToTheLimit(): void
    {
        $this->assertTrue(PivotSeed::scansFeedHits(PivotSeed::FEED_SCAN_LIMIT));
        $this->assertFalse(PivotSeed::scansFeedHits(PivotSeed::FEED_SCAN_LIMIT + 1));
        $this->assertTrue(PivotSeed::scansFeedHits('0'));
    }

    public function testLinksOverTheBudgetDoNotFitBeforeAnyCount(): void
    {
        $seed = new PivotSeed(3);
        foreach ([1, 2, 3, 4] as $objectId) {
            $seed->linkObject($objectId);
        }

        $this->assertFalse($seed->linksFit());
        $this->assertSame([1, 2, 3, 4], $seed->uncountedObjectIds());
    }

    public function testLinksThatFitUntilChildrenAreCounted(): void
    {
        $seed = new PivotSeed(5);
        $seed->linkObject(1);
        $seed->linkObject(2);
        $this->assertTrue($seed->linksFit());

        $seed->addChildCounts([1 => 2, 2 => 2]);
        $this->assertFalse($seed->linksFit());
    }

    public function testTheSummaryNamesTheLeadingTypes(): void
    {
        $seed = new PivotSeed(1);
        $seed->linkObject(1);
        $seed->linkObject(2);
        $seed->linkAttribute(9);
        foreach (['analysed-with', 'analysed-with', 'drops', null, 'drops', 'analysed-with'] as $type) {
            $seed->countReference($type);
        }
        $seed->countRelationship('related-to');
        $seed->countRelationship('uses');

        $summary = $seed->linkedSummary();
        $this->assertSame(2, $summary['objects']);
        $this->assertSame(1, $summary['attributes']);
        $this->assertSame(6, $summary['references']);
        $this->assertSame(2, $summary['relationships']);
        $this->assertSame(3, $summary['nodes']);
        $this->assertSame([['analysed-with', 3], ['drops', 2], ['related-to', 2]], $summary['types']);
    }
}
