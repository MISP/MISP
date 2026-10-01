<?php

require_once __DIR__ . '/IntegrationTestCase.php';
require_once __DIR__ . '/../Support/Snapshot.php';

use MispTest\Support\Snapshot;

/**
 * Characterization of Event::fetchEvent().
 *
 * At 566 statements it is the largest single method in MISP and the hub of
 * event reading - the API, the UI and sync all land here. It is also the main
 * obstacle to splitting Model/Event.php, because nothing pins what it returns.
 *
 * These are CHARACTERIZATION tests (ADR 0002): they record what the code does
 * today without claiming it is correct, so that a refactor which changes the
 * shape of the result fails loudly. They are deliberately not specifications -
 * a behaviour recorded here may well be wrong, and that is fine; what matters
 * is that it does not change by accident.
 */
class EventFetchCharacterizationTest extends IntegrationTestCase
{
    /** @var int|null */
    private $eventId;

    protected function setUp(): void
    {
        parent::setUp();
        $this->eventId = $this->createEvent('fetchEvent characterization', [
            ['type' => 'ip-dst', 'value' => '8.8.8.8'],
            ['type' => 'domain', 'value' => 'example.com'],
            ['type' => 'md5', 'value' => 'd41d8cd98f00b204e9800998ecf8427e',
             'category' => 'Payload delivery'],
        ]);
    }

    private function fetch(array $options): array
    {
        $options['eventid'] = $this->eventId;
        return $this->localise(
            $this->model('Event')->fetchEvent($this->adminUser(), $options)
        );
    }

    /**
     * Drop related events this test did not create.
     *
     * RelatedEvent is the one part of the result that is a property of the
     * DATABASE rather than of fetchEvent(): it lists every other event holding
     * a matching attribute value. A clean CI runner has none, a developer's
     * instance has whatever it happens to hold - including events orphaned by
     * an earlier interrupted run of this very suite. Recording that in a
     * golden file makes the snapshot a fact about the recorder's machine, and
     * the suite then fails on CI for reasons no refactor caused.
     *
     * Filtering to the ids this test created keeps the key, its position and
     * the entry shape under the snapshot while removing the part no test can
     * control. Correlation itself is pinned where it belongs, by
     * CorrelationEngineTest, which builds both sides of the relationship.
     */
    private function localise(array $events): array
    {
        foreach ($events as $index => $event) {
            if (!isset($event['RelatedEvent']) || !is_array($event['RelatedEvent'])) {
                continue;
            }
            $mine = [];
            foreach ($event['RelatedEvent'] as $related) {
                $id = (int)($related['Event']['id'] ?? 0);
                if (in_array($id, $this->createdEventIds, true)) {
                    $mine[] = $related;
                }
            }
            $events[$index]['RelatedEvent'] = $mine;
        }
        return $events;
    }

    private function pin(string $name, array $result): void
    {
        [$ok, $message] = Snapshot::compare($name, $result);
        $this->assertTrue($ok, $message);
    }

    public function testDefaultFetchShape(): void
    {
        $result = $this->fetch([]);
        $this->assertCount(1, $result, 'fetching by eventid must return exactly one event');
        $this->pin('fetchevent_default', $result);
    }

    public function testMetadataOnlyOmitsAttributes(): void
    {
        $result = $this->fetch(['metadata' => 1]);
        $this->assertArrayNotHasKey(
            'Attribute',
            $result[0]['Event'] ?? [],
            'metadata=1 must not hydrate attributes - that is its entire purpose'
        );
        $this->pin('fetchevent_metadata_only', $result);
    }

    /**
     * @dataProvider optionProvider
     */
    public function testOptionCombination(string $name, array $options): void
    {
        $result = $this->fetch($options);
        $this->assertIsArray($result, "fetchEvent must return an array for $name");
        $this->pin('fetchevent_' . $name, $result);
    }

    public function optionProvider(): array
    {
        return [
            'no_correlations'      => ['no_correlations', ['includeEventCorrelations' => false]],
            'exclude_local_tags'   => ['exclude_local_tags', ['excludeLocalTags' => 1]],
            'no_full_clusters'     => ['no_full_clusters', ['fetchFullClusters' => false]],
            'with_analyst_data'    => ['with_analyst_data', ['includeAnalystData' => true]],
            'deleted_included'     => ['deleted_included', ['deleted' => [0, 1]]],
            'flatten'              => ['flatten', ['flatten' => 1]],
            'type_filter'          => ['type_filter', ['type' => 'ip-dst']],
            'category_filter'      => ['category_filter', ['category' => 'Payload delivery']],
            'to_ids_filter'        => ['to_ids_filter', ['to_ids' => 1]],
            'value_filter'         => ['value_filter', ['value' => '8.8.8.8']],
            'enforce_warninglist'  => ['enforce_warninglist', ['enforceWarninglist' => true]],
            'include_tag_counts'   => ['include_tag_counts', ['includeTagCounts' => true]],
            'sgReferenceOnly'      => ['sg_reference_only', ['sgReferenceOnly' => true]],
        ];
    }

    /**
     * A filter that matches nothing must still return a well-formed result
     * rather than a hydrated event with an empty attribute list, or vice
     * versa. This is the branch most likely to be broken silently by a
     * refactor of the condition builder.
     */
    public function testFilterMatchingNothing(): void
    {
        $result = $this->fetch(['value' => 'no-attribute-has-this-value-198.51.100.254']);
        $this->pin('fetchevent_filter_matches_nothing', $result);
    }

    /**
     * KNOWN DEFECT - asserted as the DESIRED behaviour and skipped while it
     * fails, so it starts passing the moment it is fixed (ADR 0002).
     *
     * AnalystDataParentBehavior::attachAnalystData() resolves the acting user
     * from Configure::read('CurrentUserId') (AnalystDataParentBehavior.php:22).
     * An authenticated web request sets that; a console shell, a background
     * worker and a test do not. When it is unset, __currentUser stays null and
     * the behaviour calls SharingGroup::authorizedIds(null, ...), whose
     * signature requires an array - a fatal TypeError.
     *
     * So any code path attaching analyst data outside a web request dies, and
     * the error names SharingGroup rather than the missing configuration.
     */
    public function testAnalystDataWithoutCurrentUserId(): void
    {
        $previous = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', null);
        try {
            $result = $this->fetch(['includeAnalystData' => true]);
            $this->assertIsArray($result);
        } catch (\TypeError $e) {
            $this->markTestSkipped(
                'known defect: attaching analyst data without Configure CurrentUserId set '
                . 'raises a fatal TypeError - ' . $e->getMessage()
            );
        } finally {
            Configure::write('CurrentUserId', $previous);
        }
    }

    public function testUnknownEventIdReturnsEmpty(): void
    {
        $result = $this->model('Event')->fetchEvent($this->adminUser(), ['eventid' => 999999999]);
        $this->assertSame([], $result, 'an unknown event id must yield an empty result, not a fatal');
    }
}
