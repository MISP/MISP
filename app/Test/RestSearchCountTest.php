<?php
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class RestSearchCountTest extends TestCase
{
    private $user = ['org_id' => 1, 'Role' => [
        'perm_sync' => false, 'perm_site_admin' => false,
    ]];

    protected function setUp(): void
    {
        require_once __DIR__ . '/RestSearchExportStubs.php';
        Configure::$values = [];
        $allowedlist = new Allowedlist();
        $allowedlist->allowedlistedItems = [];
        ClassRegistry::$models['Allowedlist'] = $allowedlist;
    }

    public function testSqlCountUsesTheSameAclFiltersAndJoinsAsFetch()
    {
        $model = new RestSearchExportAttribute();
        $count = 0;
        $result = $model->restSearch($this->user, 'count', [], false, false, $count);
        $this->assertSame('1', (string)$result);
        $this->assertSame(1, $count);
        $this->assertSame('count', $model->queries[0][0]);
        $this->assertCount(1, $model->queries);
        $countQuery = $model->queries[0][1];
        $reference = new RestSearchExportAttribute();
        $params = $reference->restSearch($this->user, 'count', [], true);
        $reference->fetchAttributes($this->user, $params);
        $fetchQuery = $reference->queries[0][1];
        $this->assertSame($fetchQuery['conditions'], $countQuery['conditions']);
        $this->assertSame($fetchQuery['joins'], $countQuery['joins']);
        $this->assertArrayNotHasKey('fields', $countQuery);
        $this->assertSame([], $countQuery['contain']);
        $this->assertSame([], $model->Event->Org->queries);
        $this->assertSame([], $model->Event->ThreatLevel->queries);
    }

    public function testAllowedlistFallsBackAndExcludesMatchingAttributes()
    {
        ClassRegistry::$models['Allowedlist']->allowedlistedItems = ['/file/'];
        $model = new RestSearchExportAttribute();
        $result = $model->restSearch($this->user, 'count', []);
        $this->assertSame('0', (string)$result);
        $this->assertSame('all', $model->queries[0][0]);
    }

    public function testExplicitLimitKeepsHydratedCountSemantics()
    {
        $model = new RestSearchExportAttribute();
        $result = $model->restSearch($this->user, 'count', ['limit' => 10]);
        $this->assertSame('1', (string)$result);
        $this->assertSame('all', $model->queries[0][0]);
    }

    public function testControllerUnboundedDefaultsUseSqlCount()
    {
        // AppController supplies zero for a user with no REST result cap.
        $model = new RestSearchExportAttribute();
        $result = $model->restSearch($this->user, 'count', ['limit' => 0]);
        $this->assertSame('1', (string)$result);
        $this->assertSame('count', $model->queries[0][0]);
        $this->assertArrayNotHasKey('limit', $model->queries[0][1]);
        $this->assertArrayNotHasKey('page', $model->queries[0][1]);
    }

    public function testPageBeyondOneKeepsTheFallback()
    {
        $model = new RestSearchExportAttribute();
        $model->rows = [];
        $model->restSearch($this->user, 'count', ['limit' => 0, 'page' => 2]);
        $this->assertSame('all', $model->queries[0][0]);
    }

    public function testZeroMatchesIsAnUnadornedZero()
    {
        $model = new RestSearchExportAttribute();
        $model->rows = [];
        $count = -1;
        $result = $model->restSearch($this->user, 'count', [], false, false, $count);
        $this->assertSame('0', (string)$result);
        $this->assertSame(0, $count);
        $this->assertSame('count', $model->queries[0][0]);
    }
    /** @dataProvider fallbackOptions */
    public function testComplexOptionsNeverSelectCountOnly($filters)
    {
        Configure::$values['MISP.proposals_block_attributes'] = true;
        ClassRegistry::$models['Warninglist'] = new stdClass();
        ClassRegistry::$models['Sighting'] = new stdClass();
        ClassRegistry::$models['Correlation'] = new stdClass();
        $model = new RestSearchExportAttribute();
        $model->rows = [];
        $result = $model->restSearch($this->user, 'count', $filters);
        $this->assertSame('0', (string)$result);
        $this->assertSame('all', $model->queries[0][0]);
    }

    public function fallbackOptions()
    {
        return array_map(function ($option) { return [[$option => 1]]; }, [
            'enforceWarninglist', 'excludeDecayed', 'includeDecayScore',
            'allow_proposal_blocking', 'includeProposals', 'includeContext',
            'includeSightings', 'includeCorrelations', 'withAttachments',
            'includeEventTags', 'includeWarninglistHits', 'offset',
            'group',
        ]);
    }

    public function testWarninglistStillExcludesCountCandidates()
    {
        ClassRegistry::$models['Warninglist'] = new class {
            public function filterWarninglistAttribute($attribute) {
                return $attribute['value'] !== 'file|abc';
            }
        };
        $model = new RestSearchExportAttribute();
        $result = $model->restSearch($this->user, 'count', ['enforceWarninglist' => 1]);
        $this->assertSame('0', (string)$result);
        $this->assertSame('all', $model->queries[0][0]);
        $this->assertContains('Attribute.*', $model->queries[0][1]['fields']);
    }

}
