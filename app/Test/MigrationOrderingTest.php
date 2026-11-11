<?php
/**
 * Order, and the halt.
 *
 * The legacy update loop applied every pending update in sequence and carried
 * on past a failure. Nothing in it knew that update 158 might only make sense
 * against the schema update 157 was supposed to produce, so a failed 157 was
 * followed by a 158 running against the wrong shape - and, because a later
 * success reset the failure counter, the whole thing could finish looking
 * healthy.
 *
 * Migrations halt instead. The first failure ends the run; every successor
 * stays pending and untried, and the next run picks up the failed one first.
 * That is the property this file exists to pin, and the canonical case is the
 * three-step change - add a column, backfill it, drop the old one - where the
 * third step is destructive and the first step failing must not let it near
 * the database.
 *
 * The ordering half is the precondition for all of that: ids are fixed-width
 * timestamps, so sorting them as strings sorts them chronologically, and the
 * order a directory happens to be read in is irrelevant.
 *
 * @see MigrationLedgerStubs.php for the migration classes and the in-memory manager.
 */

require_once __DIR__ . '/MigrationLedgerStubs.php';

use PHPUnit\Framework\TestCase;

class MigrationOrderingTest extends TestCase
{
    /** The three-step change, plus one migration that has nothing to do with it. */
    private static $threeStepFiles = array(
        'Migration_20260101_000000_add_column.php',
        'Migration_20260102_000000_backfill_column.php',
        'Migration_20260103_000000_drop_old_column.php',
        'Migration_20260104_000000_unrelated.php',
    );

    private static $inOrder = array(
        '20260101_000000_add_column',
        '20260102_000000_backfill_column',
        '20260103_000000_drop_old_column',
        '20260104_000000_unrelated',
    );

    // --------------------------------------------------------------- order

    public function testAShuffledDirectoryStillYieldsIdOrder()
    {
        $shuffled = array(
            'Migration_20260103_000000_drop_old_column.php',
            'Migration_20260101_000000_add_column.php',
            'Migration_20260104_000000_unrelated.php',
            'Migration_20260102_000000_backfill_column.php',
        );

        $manager = new TestMigrationManager($shuffled);

        $this->assertSame(self::$inOrder, $manager->ids());
        $this->assertSame(self::$inOrder, array_keys($manager->pending()));
    }

    /**
     * Chronological order is a lexicographic one only because the timestamp is
     * fixed-width. A migration from years earlier has to sort first on the
     * strength of its digits alone.
     */
    public function testOrderIsChronologicalAcrossYears()
    {
        $manager = new TestMigrationManager(array(
            'Migration_20260104_000000_unrelated.php',
            'Migration_20200101_000000_older_than_the_freeze.php',
        ));

        $this->assertSame(
            array('20200101_000000_older_than_the_freeze', '20260104_000000_unrelated'),
            $manager->ids()
        );
    }

    public function testTheRunFollowsIdOrder()
    {
        $manager = new TestMigrationManager(self::$threeStepFiles);
        $manager->applyPending();

        $this->assertSame(self::$inOrder, $manager->executed);
    }

    // ---------------------------------------------------------------- halt

    public function testAFailureLeavesEverySuccessorUntried()
    {
        $manager = new TestMigrationManager(self::$threeStepFiles);
        $manager->failing = array('20260102_000000_backfill_column');

        $results = $manager->applyPending();

        $this->assertSame(
            array('20260101_000000_add_column', '20260102_000000_backfill_column'),
            $manager->executed
        );
        $this->assertSame(
            array('20260101_000000_add_column' => true, '20260102_000000_backfill_column' => false),
            $results
        );
    }

    public function testEverySuccessorStaysPendingAfterAFailure()
    {
        $manager = new TestMigrationManager(self::$threeStepFiles);
        $manager->failing = array('20260102_000000_backfill_column');
        $manager->applyPending();

        $this->assertSame(
            array(
                '20260102_000000_backfill_column',
                '20260103_000000_drop_old_column',
                '20260104_000000_unrelated',
            ),
            array_keys($manager->pending())
        );
    }

    /**
     * The successes before a failure are kept. Halting is not a rollback - it
     * stops the run, it does not undo what already landed.
     */
    public function testWhatSucceededBeforeTheFailureIsRecorded()
    {
        $manager = new TestMigrationManager(self::$threeStepFiles);
        $manager->failing = array('20260102_000000_backfill_column');
        $manager->applyPending();

        $this->assertSame(array('20260101_000000_add_column'), $manager->applied());
        $this->assertSame(array('20260102_000000_backfill_column'), $manager->failed());
    }

    public function testTheNextRunRetriesTheFailedMigrationFirst()
    {
        $manager = new TestMigrationManager(self::$threeStepFiles);
        $manager->failing = array('20260102_000000_backfill_column');
        $manager->applyPending();

        // A second process: same ledger, nothing remembered in memory.
        $manager->forgetDiscovery();
        $manager->executed = array();
        $manager->failing = array();
        $manager->applyPending();

        $this->assertSame(
            array(
                '20260102_000000_backfill_column',
                '20260103_000000_drop_old_column',
                '20260104_000000_unrelated',
            ),
            $manager->executed
        );
        $this->assertSame(array(), $manager->pending());
    }

    /**
     * A success cannot follow a failure inside one run. The legacy loop's
     * resetUpdateFailNumber() on success could therefore erase the evidence of
     * a failure that had happened moments earlier; with the halt in place there
     * is no later success to do the erasing.
     */
    public function testNoSuccessFollowsAFailureWithinOneRun()
    {
        $manager = new TestMigrationManager(self::$threeStepFiles);
        $manager->failing = array('20260101_000000_add_column');

        $results = $manager->applyPending();

        $this->assertSame(array('20260101_000000_add_column' => false), $results);
        $this->assertNotContains(true, $results, 'nothing may succeed after a failure');
        $this->assertSame(array('20260101_000000_add_column'), $manager->executed);
    }

    /**
     * The scenario the halt was written for, end to end.
     *
     * Step one adds the column, step two backfills it, step three drops the
     * column step two read from. Step one fails. Step three must never run -
     * it is the destructive one, and it would be dropping a column nothing has
     * copied out of yet.
     */
    public function testTheDestructiveThirdStepNeverRunsWhenTheFirstStepFails()
    {
        $manager = new TestMigrationManager(self::$threeStepFiles);
        $manager->failing = array('20260101_000000_add_column');

        $manager->applyPending();

        $this->assertNotContains('20260103_000000_drop_old_column', $manager->executed);
        $this->assertNotContains('20260102_000000_backfill_column', $manager->executed);
        $this->assertArrayHasKey('20260103_000000_drop_old_column', $manager->pending());
        $this->assertArrayNotHasKey(
            '20260103_000000_drop_old_column',
            $manager->ledger(),
            'a migration that was never attempted has no ledger row at all'
        );
    }

    public function testAnEmptyPendingSetRunsNothing()
    {
        $manager = new TestMigrationManager(self::$threeStepFiles);
        $manager->applyPending();
        $manager->executed = array();

        $this->assertSame(array(), $manager->applyPending());
        $this->assertSame(array(), $manager->executed);
    }
}
