<?php
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class RestSearchExportPlanTest extends TestCase
{
    private $user = ['org_id' => 1, 'Role' => [
        'perm_sync' => false, 'perm_site_admin' => false,
    ]];

    protected function setUp(): void
    {
        require_once __DIR__ . '/RestSearchExportStubs.php';
    }

    public function testLeanFetchProjectsOnlyConsumedFieldsAndSkipsEnrichment()
    {
        $model = new RestSearchExportAttribute();
        $rows = $model->fetchAttributes($this->user, [
            'limit' => 10, 'flatten' => 1,
            'exportRequirements' => [
                'fields' => ['Attribute.value'],
                'attributeTags' => false, 'organisations' => false,
                'threatLevels' => false,
            ],
        ]);
        $query = $model->queries[0][1];
        $this->assertNotContains('Attribute.*', $query['fields']);
        $this->assertSame([], $query['contain']);
        $this->assertSame(0, $model->tagCalls);
        $this->assertSame([], $model->Event->Org->queries);
        $this->assertSame([], $model->Event->ThreatLevel->queries);
        $this->assertSame('file|abc', $rows[0]['Attribute']['value']);
        $this->assertSame(12, $rows[0]['Attribute']['id']);
    }

    public function testUndeclaredExporterKeepsFullFetchAndEnrichment()
    {
        $model = new RestSearchExportAttribute();
        $rows = $model->fetchAttributes($this->user, ['limit' => 10]);
        $this->assertContains('Attribute.*', $model->queries[0][1]['fields']);
        $this->assertSame(['AttributeTag'], $model->queries[0][1]['contain']);
        $this->assertSame(1, $model->tagCalls);
        $this->assertArrayHasKey('Org', $rows[0]['Event']);
        $this->assertArrayHasKey('ThreatLevel', $rows[0]['Event']);
        $this->assertFalse(property_exists(new JsonExport(), 'fetch_requirements'));
    }

    public function testSimpleExportersHaveOutputParityWithProjectedRows()
    {
        foreach (['TextExport', 'CacheExport', 'HashesExport', 'CountExport'] as $class) {
            $full = new $class();
            $lean = new $class();
            $this->assertTrue(property_exists($lean, 'fetch_requirements'), $class);
            $model = new RestSearchExportAttribute();
            $rows = $model->fetchAttributes($this->user, [
                'limit' => 10, 'exportRequirements' => $lean->fetch_requirements,
            ]);
            $options = ['scope' => 'Attribute', 'filters' => ['includeEventUuid' => 1]];
            $this->assertSame(
                $full->handler($model->rows[0], $options),
                $lean->handler($rows[0], $options), $class
            );
            $this->assertSame($full->footer(), $lean->footer(), $class);
        }
    }
    /** @dataProvider fullRowOptions */
    public function testProcessingDependenciesKeepFullRows($option)
    {
        $model = new RestSearchExportAttribute();
        $model->rows = [];
        Configure::$values['MISP.proposals_block_attributes'] = true;
        ClassRegistry::$models['Warninglist'] = new stdClass();
        ClassRegistry::$models['Sighting'] = new stdClass();
        ClassRegistry::$models['Correlation'] = new stdClass();
        $model->fetchAttributes($this->user, [
            'limit' => 10, $option => 1,
            'exportRequirements' => (new TextExport())->fetch_requirements,
        ]);
        $this->assertContains('Attribute.*', $model->queries[0][1]['fields']);
        Configure::$values = [];
    }

    public function fullRowOptions()
    {
        return array_map(function ($option) { return [$option]; }, [
            'withAttachments', 'includeSightings', 'includeSightingdb',
            'includeCorrelations', 'includeContext', 'includeEventTags',
            'includeWarninglistHits', 'enforceWarninglist', 'includeDecayScore',
            'excludeDecayed', 'decayingModel', 'includeFullModel',
            'includeAttributeUuid', 'includeEventUuid', 'includeGalaxy',
            'includeProposals', 'allow_proposal_blocking',
        ]);
    }

    public function testRestrictiveTextStaysLeanWhenProposalBlockingIsDisabled()
    {
        Configure::$values = [];
        $model = new RestSearchExportAttribute();
        $allowedlist = new Allowedlist();
        $allowedlist->allowedlistedItems = [];
        ClassRegistry::$models['Allowedlist'] = $allowedlist;
        $result = $model->restSearch($this->user, 'text', []);
        $this->assertSame("file|abc\n", (string)$result);
        $this->assertNotContains('Attribute.*', $model->queries[0][1]['fields']);
    }

    public function testProposalBlockingStillRemovesLeanExporterCandidates()
    {
        Configure::$values['MISP.proposals_block_attributes'] = true;
        $model = new RestSearchExportAttribute();
        $model->rows[0]['Attribute']['category'] = 'Payload delivery';
        $model->rows[0]['Attribute']['to_ids'] = 1;
        $model->rows[0]['ShadowAttribute'] = [[
            'value' => 'file|abc', 'type' => 'filename|md5',
            'category' => 'Payload delivery', 'to_ids' => 0,
        ]];
        $skipped = 0;
        $count = 0;
        $rows = $model->fetchAttributes($this->user, [
            'limit' => 10, 'allow_proposal_blocking' => 1,
            'exportRequirements' => (new TextExport())->fetch_requirements,
        ], $count, false, $skipped);
        $this->assertSame([], $rows);
        $this->assertSame(1, $skipped);
        $this->assertSame(['ShadowAttribute'], $model->queries[0][1]['contain']);
        Configure::$values = [];
    }

    public function testDefaultJsonRetainsFullAttributeAndEventResponse()
    {
        Configure::$values = [];
        $allowedlist = new Allowedlist();
        $allowedlist->allowedlistedItems = [];
        ClassRegistry::$models['Allowedlist'] = $allowedlist;
        $model = new RestSearchExportAttribute();
        $result = $model->restSearch($this->user, 'json', []);
        $response = json_decode((string)$result, true);
        $this->assertSame([
            'response' => ['Attribute' => [[
                'id' => 12, 'event_id' => 3, 'type' => 'filename|md5',
                'value' => 'file|abc', 'comment' => 'large comment',
                'Event' => [
                    'id' => 3, 'org_id' => 1, 'orgc_id' => 1,
                    'threat_level_id' => 1, 'uuid' => 'event-uuid',
                    'Org' => ['id' => 1], 'Orgc' => ['id' => 1],
                    'ThreatLevel' => '',
                ],
            ]]],
        ], $response);
    }

}
