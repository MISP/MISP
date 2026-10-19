<?php
/**
 * When the upgrade's closing migration queues the full recorrelation, when it
 * only prints the command, and when there is nothing to do. The reads and the
 * queueing need a database; these drive the decision alone.
 */

require_once __DIR__ . '/MigrationLedgerStubs.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261016_204637_queue_full_recorrelation.php';

use PHPUnit\Framework\TestCase;

class QueueFullRecorrelationMigrationTest extends TestCase
{
    const MIGRATION = 'Migration_20261016_204637_queue_full_recorrelation';

    /** An upgraded instance with background jobs: the case that queues. */
    const UPGRADED = array(
        'disabled' => false,
        'engine' => 'Default',
        'table' => 'default_correlations',
        'correlated' => false,
        'attributes' => true,
        'backgroundJobs' => true,
        'pendingJob' => null,
        'unqueuedJob' => null,
    );

    /**
     * @param array $changes
     * @return array
     */
    private static function decide(array $changes = array())
    {
        $class = self::MIGRATION;
        return $class::decide($changes + self::UPGRADED);
    }

    public function testAnEmptyTableWithAttributesQueuesTheRecorrelation()
    {
        $decision = self::decide();
        $this->assertSame('queue', $decision['action']);
        $this->assertStringContainsString('default_correlations', $decision['line']);
    }

    public function testTheNoAclEngineQueuesForItsOwnTable()
    {
        $decision = self::decide(array('engine' => 'NoAcl', 'table' => 'no_acl_correlations'));
        $this->assertSame('queue', $decision['action']);
        $this->assertStringContainsString('no_acl_correlations', $decision['line']);
    }

    public function testDisabledCorrelationQueuesNothing()
    {
        $decision = self::decide(array('disabled' => true));
        $this->assertSame('none', $decision['action']);
        $this->assertStringContainsString('MISP.completely_disable_correlation', $decision['line']);
    }

    public function testTheOnDemandEngineQueuesNothing()
    {
        $decision = self::decide(array('engine' => 'OnDemand', 'table' => null));
        $this->assertSame('none', $decision['action']);
        $this->assertSame('The OnDemand correlation engine stores no correlations: nothing to recorrelate.', $decision['line']);
    }

    public function testATableThatHoldsCorrelationsIsLeftAlone()
    {
        $decision = self::decide(array('correlated' => true));
        $this->assertSame('none', $decision['action']);
        $this->assertStringContainsString('default_correlations already holds correlations', $decision['line']);
    }

    public function testNoAttributesMeansNothingToRecorrelate()
    {
        foreach (array(true, false) as $backgroundJobs) {
            $decision = self::decide(array('attributes' => false, 'backgroundJobs' => $backgroundJobs));
            $this->assertSame('none', $decision['action']);
            $this->assertSame('No attributes: nothing to recorrelate.', $decision['line']);
        }
    }

    public function testWithoutBackgroundJobsOnlyTheCommandIsPrinted()
    {
        foreach (array(null, 42) as $pendingJob) {
            $decision = self::decide(array('backgroundJobs' => false, 'pendingJob' => $pendingJob));
            $this->assertSame('command', $decision['action']);
            $this->assertStringContainsString('Console/cake Admin jobGenerateCorrelation', $decision['line']);
        }
    }

    public function testARerunWithItsJobStillPendingQueuesNoSecondOne()
    {
        $decision = self::decide(array('pendingJob' => 42));
        $this->assertSame('queued', $decision['action']);
        $this->assertStringContainsString('(job 42)', $decision['line']);
    }

    public function testARowAnInterruptedRunLeftUnqueuedIsQueued()
    {
        $decision = self::decide(array('unqueuedJob' => 42));
        $this->assertSame('queue', $decision['action']);
        $this->assertStringContainsString('left unqueued (job 42)', $decision['line']);
    }

    public function testItRunsAfterEverySchemaV3Migration()
    {
        $last = '';
        foreach (glob(APPLIBS . 'Migration/Migrations/' . AbstractMigration::CLASS_PREFIX . '*_schema_v3_*.php') as $file) {
            $last = max($last, AbstractMigration::idFromClassName(basename($file, '.php')));
        }
        $this->assertNotSame('', $last);
        $this->assertGreaterThan($last, AbstractMigration::idFromClassName(self::MIGRATION));
    }
}
