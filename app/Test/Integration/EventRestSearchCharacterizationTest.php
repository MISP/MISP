<?php

require_once __DIR__ . '/IntegrationTestCase.php';

/**
 * Characterization of Event::restSearch() and its two helpers,
 * restSearchFilterMassage() and clusterEventIds().
 *
 * The live Python suite (tests/testlive_restsearch_contract.py) already pins
 * 34 snapshots of what restSearch *serialises* over HTTP. Per the capability
 * boundary in ADR 0001 - assert at the highest layer that can assert it, and
 * no higher - this file deliberately does NOT re-record export bytes. It pins
 * only what HTTP cannot observe:
 *
 *   - the by-reference outputs $elementCounter and $renderView,
 *   - which of restSearch's internal branches a given return format selects
 *     (non_restrictive_export, mock_query_only, additional_params),
 *   - the filter rewriting done before any query runs,
 *   - the memory-driven chunking of event ids,
 *   - two defects that a refactor must not silently "fix" into a different
 *     shape without someone noticing (see KNOWN-DEFECT below).
 *
 * These are characterization tests (ADR 0002): they record today's behaviour,
 * not an opinion about whether it is correct.
 */
class EventRestSearchCharacterizationTest extends IntegrationTestCase
{
    /** @var int|null */
    private $eventId;

    protected function setUp(): void
    {
        parent::setUp();
        $this->eventId = $this->createEvent('restSearch characterization', [
            ['type' => 'ip-dst', 'value' => '198.51.100.7'],
            ['type' => 'domain', 'value' => 'restsearch.example'],
        ]);
    }

    private function event()
    {
        return $this->model('Event');
    }

    /** Narrow every search to the fixture event so other data cannot leak in. */
    private function filters(array $extra = []): array
    {
        return array_merge(['eventid' => $this->eventId], $extra);
    }

    private function publishFixture(): void
    {
        $this->event()->save(
            ['Event' => ['id' => $this->eventId, 'published' => 1]],
            ['fieldList' => ['published'], 'callbacks' => false]
        );
    }

    // ---------------------------------------------------------------- format

    public function testUnknownReturnFormatThrows(): void
    {
        $this->expectException(NotFoundException::class);
        $this->event()->restSearch($this->adminUser(), 'not-a-format', $this->filters());
    }

    /**
     * KNOWN-DEFECT: Event::restSearch declares and documents a $paramsOnly
     * parameter but never reads it. GalaxyCluster, MispObject and
     * MispAttribute all honour it and return the massaged filter array; Event
     * runs the full export regardless. No caller passes true today
     * (DecayingModelController uses the Attribute implementation), so this is
     * latent rather than broken - but anyone adding a caller would get an
     * export where they expected parameters.
     */
    public function testParamsOnlyIsIgnoredAndAFullExportRuns(): void
    {
        $result = $this->event()->restSearch($this->adminUser(), 'json', $this->filters(), true);
        $this->assertInstanceOf(
            TmpFileTool::class,
            $result,
            'restSearch ignores $paramsOnly and always exports; if this now returns an ' .
            'array the parameter has been implemented - update the callers and this test'
        );
    }

    // ------------------------------------------------------- by-ref outputs

    public function testElementCounterReportsTheNumberOfMatchedEvents(): void
    {
        $counter = 0;
        $this->event()->restSearch($this->adminUser(), 'json', $this->filters(), false, false, $counter);
        $this->assertSame(1, (int)$counter, 'one event matched, so the element counter must read 1');
    }

    public function testMockQueryOnlyFormatNeverCountsElements(): void
    {
        // OpendataExport sets mock_query_only, which makes restSearch skip
        // filterEventIds() entirely - so the counter cannot move. It then
        // throws out of header() because no 'setup' filter was supplied; that
        // throw is what proves execution reached the export tool with an
        // empty chunk list.
        $counter = 0;
        try {
            $this->event()->restSearch($this->adminUser(), 'opendata', $this->filters(), false, false, $counter);
            $this->fail('opendata without a "setup" filter is expected to throw');
        } catch (Exception $e) {
            $this->assertStringContainsString('setup', $e->getMessage());
        }
        $this->assertSame(0, (int)$counter, 'mock_query_only must skip the event query');
    }

    public function testRenderViewStaysFalseForPlainFormats(): void
    {
        $renderView = false;
        $counter = 0;
        $this->event()->restSearch($this->adminUser(), 'json', $this->filters(), false, false, $counter, $renderView);
        $this->assertFalse($renderView, 'json is not a rendered view');
    }

    public function testRenderViewIsTakenFromTheExportTool(): void
    {
        $renderView = false;
        $counter = 0;
        try {
            $this->event()->restSearch(
                $this->adminUser(), 'context-markdown', $this->filters(), false, false, $counter, $renderView
            );
        } catch (\Throwable $e) {
            // The context exports need galaxy/taxonomy data this instance may
            // not carry. $renderView is assigned before any of that runs, so
            // the assertion below is still meaningful.
        }
        $this->assertSame(
            'context_markdown_view',
            $renderView,
            'restSearch must surface the export tool\'s renderView to its caller'
        );
    }

    // ------------------------------------------- restrictive vs permissive

    public function testNonRestrictiveFormatReturnsAnUnpublishedEvent(): void
    {
        // JsonExport declares non_restrictive_export, so restSearch does not
        // inject published=1 / to_ids=1 defaults.
        $body = $this->event()->restSearch($this->adminUser(), 'json', $this->filters())->intoString();
        $decoded = JsonTool::decode($body);
        $this->assertCount(1, $decoded['response'], 'the unpublished fixture must be returned');
        $this->assertSame(
            (int)$this->eventId,
            (int)$decoded['response'][0]['Event']['id']
        );
    }

    public function testRestrictiveFormatHidesAnUnpublishedEvent(): void
    {
        // TextExport declares no non_restrictive_export, so published=1 is
        // forced on and the unpublished fixture drops out.
        $body = $this->event()->restSearch($this->adminUser(), 'text', $this->filters())->intoString();
        $this->assertStringNotContainsString('198.51.100.7', $body);
    }

    public function testRestrictiveFormatReturnsAPublishedEvent(): void
    {
        $this->publishFixture();
        $body = $this->event()->restSearch($this->adminUser(), 'text', $this->filters())->intoString();
        $this->assertStringContainsString('198.51.100.7', $body);
    }

    public function testCountFormatReturnsTheFooterCounter(): void
    {
        // CountExport's handler returns '' for every element, so nothing is
        // ever written to the body; the whole output is footer()'s integer.
        // additional_params (flatten=1) is merged in by restSearch.
        $body = $this->event()->restSearch($this->adminUser(), 'count', $this->filters())->intoString();
        $this->assertSame('1', trim($body), 'count exports one line per matched event');
    }

    // ------------------------------------------------ restSearchFilterMassage

    private function massage(array $filters, bool $nonRestrictive = true): array
    {
        return $this->event()->restSearchFilterMassage($filters, $nonRestrictive, $this->adminUser());
    }

    public function testIgnoreOpensBothToIdsAndPublished(): void
    {
        $out = $this->massage(['ignore' => 1]);
        $this->assertSame([0, 1], $out['to_ids']);
        $this->assertSame([0, 1], $out['published']);
    }

    public function testQuickFilterBecomesSearchallAndDropsValue(): void
    {
        $out = $this->massage(['quickFilter' => 'needle', 'value' => 'haystack']);
        $this->assertSame('needle', $out['searchall']);
        $this->assertArrayNotHasKey('value', $out, 'quickFilter consumes value');
        $this->assertSame('needle', $out['wildcard'], 'searchall with no value falls back to itself');
    }

    public function testSearchallPrefersAnExplicitValueForTheWildcard(): void
    {
        $out = $this->massage(['searchall' => 'ignored', 'value' => 'preferred']);
        $this->assertSame('preferred', $out['wildcard']);
    }

    public function testSingularTagIsAliasedToTags(): void
    {
        $out = $this->massage(['tag' => 'tlp:white']);
        $this->assertSame('tlp:white', $out['tags']);
    }

    public function testExplicitTagsWinOverSingularTag(): void
    {
        $out = $this->massage(['tag' => 'tlp:white', 'tags' => ['tlp:green']]);
        $this->assertSame(['tlp:green'], $out['tags']);
    }

    public function testWithAttachmentsEnablesIncludeAttachments(): void
    {
        $out = $this->massage(['withAttachments' => 1]);
        $this->assertSame(1, $out['includeAttachments']);
    }

    public function testRestrictiveMassageInjectsDefaultsAndProposalBlocking(): void
    {
        $out = $this->massage([], false);
        $this->assertSame(1, $out['to_ids']);
        $this->assertSame(1, $out['published']);
        $this->assertSame(1, $out['allow_proposal_blocking']);
    }

    public function testRestrictiveMassageLeavesExplicitValuesAlone(): void
    {
        $out = $this->massage(['to_ids' => 0, 'published' => 0], false);
        $this->assertSame(0, $out['to_ids']);
        $this->assertSame(0, $out['published']);
    }

    public function testPermissiveMassageInjectsNoDefaults(): void
    {
        $out = $this->massage([], true);
        $this->assertArrayNotHasKey('to_ids', $out);
        $this->assertArrayNotHasKey('published', $out);
        $this->assertArrayNotHasKey('allow_proposal_blocking', $out);
    }

    // ------------------------------------------------------ clusterEventIds

    /** The memory budget clusterEventIds() computes for a given coefficient. */
    private function chunkLimit(int $coefficient): float
    {
        $model = $this->event();
        $convert = new ReflectionMethod(get_class($model), 'convert_to_memory_limit_to_mb');
        $convert->setAccessible(true);
        $memoryInMb = $convert->invoke($model, ini_get('memory_limit'));
        // The divisor defaults to 3 unless MISP.default_event_memory_multiplier
        // is set - see testMemoryDivisorIsGatedByTheWrongSettingKey().
        return $memoryInMb * ($coefficient / 3);
    }

    /** A stand-in export tool: only memory_scaling_factor is read. */
    private function exportToolWithScalingFactor(?int $factor)
    {
        $tool = new stdClass();
        if ($factor !== null) {
            $tool->memory_scaling_factor = $factor;
        }
        return $tool;
    }

    public function testClusterEventIdsReturnsNothingForNoEvents(): void
    {
        $this->assertSame([], $this->event()->clusterEventIds($this->exportToolWithScalingFactor(1), []));
    }

    public function testClusterEventIdsKeepsSmallEventsInOneChunk(): void
    {
        $limit = $this->chunkLimit(1);
        $this->assertGreaterThan(30, $limit, 'the test needs headroom below the memory limit');
        $ids = [11 => 1, 22 => 1, 33 => 1];
        $chunks = $this->event()->clusterEventIds($this->exportToolWithScalingFactor(1), $ids);
        $this->assertSame([[11, 22, 33]], $chunks);
    }

    public function testClusterEventIdsSplitsOnceTheBudgetIsExceeded(): void
    {
        $limit = (int)$this->chunkLimit(1);
        $ids = [11 => $limit, 22 => $limit, 33 => $limit];
        $chunks = $this->event()->clusterEventIds($this->exportToolWithScalingFactor(1), $ids);
        $this->assertSame([[11], [22], [33]], $chunks, 'each event alone fills the budget');
    }

    public function testClusterEventIdsGivesAnOversizedEventItsOwnChunk(): void
    {
        $limit = (int)$this->chunkLimit(1);
        // The first event alone blows the budget, so it is isolated; the
        // remaining small ones share the next chunk.
        //
        // Note the key gap: the oversized branch writes chunk 0 and then
        // increments $i, and the following overflow increments $i again
        // before writing - so the second chunk lands at key 2 and key 1 never
        // exists. restSearch only ever foreach-es the result, so this is
        // invisible today, but any caller indexing by position would break.
        // Pinned as-is rather than corrected: renumbering is a behaviour
        // change, not a cleanup.
        $ids = [11 => $limit * 10, 22 => 1, 33 => 1];
        $chunks = $this->event()->clusterEventIds($this->exportToolWithScalingFactor(1), $ids);
        $this->assertSame([0 => [11], 2 => [22, 33]], $chunks);
        $this->assertArrayNotHasKey(1, $chunks, 'the chunk list is not densely keyed');
    }

    /**
     * KNOWN-DEFECT: clusterEventIds() checks for MISP.default_event_memory_
     * multiplier but reads MISP.default_event_memory_divisor:
     *
     *   Configure::check('MISP.default_event_memory_multiplier')
     *       ? Configure::read('MISP.default_event_memory_divisor')
     *       : 3
     *
     * So setting the divisor alone does nothing, and setting the multiplier
     * without also setting the divisor makes the read return null and the
     * division below raise DivisionByZeroError. Both settings are undocumented
     * and unset by default, which is why nobody has hit it.
     */
    public function testMemoryDivisorIsGatedByTheWrongSettingKey(): void
    {
        $model = $this->event();
        $tool = $this->exportToolWithScalingFactor(1);

        Configure::write('MISP.default_event_memory_divisor', 1);
        try {
            $chunks = $model->clusterEventIds($tool, [11 => 1]);
            $this->assertSame([[11]], $chunks, 'setting the divisor alone must have no effect');

            Configure::write('MISP.default_event_memory_multiplier', 1);
            Configure::delete('MISP.default_event_memory_divisor');
            $this->expectException(DivisionByZeroError::class);
            $model->clusterEventIds($tool, [11 => 1]);
        } finally {
            Configure::delete('MISP.default_event_memory_divisor');
            Configure::delete('MISP.default_event_memory_multiplier');
        }
    }
}
