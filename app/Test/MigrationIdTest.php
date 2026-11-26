<?php
/**
 * A migration's identity comes from its file name, and this pins what that
 * means.
 *
 * The rule is small - the id is the class name without the "Migration_" prefix,
 * and the class name is the file name - but it carries two loads. It is what
 * makes the ledger key stable without anyone declaring it, so a migration
 * cannot end up recorded under a key that disagrees with the file it came from.
 * And its fixed-width timestamp is what makes sorting ids as strings sort them
 * chronologically, which is the whole of pending()'s ordering.
 *
 * So the interesting tests here are the rejections. A file name that does not
 * conform has to throw during discovery rather than be quietly passed over: a
 * skipped migration is a migration that silently never runs, which is precisely
 * the failure the ledger exists to remove.
 *
 * @see MigrationLedgerStubs.php for the migration classes and the in-memory manager.
 */

require_once __DIR__ . '/MigrationLedgerStubs.php';

use PHPUnit\Framework\TestCase;

class MigrationIdTest extends TestCase
{
    // ------------------------------------------------------------ derivation

    public function testTheIdIsTheClassNameWithoutThePrefix()
    {
        $this->assertSame(
            '20260101_000000_add_column',
            AbstractMigration::idFromClassName('Migration_20260101_000000_add_column')
        );
    }

    public function testAMigrationKnowsItsOwnId()
    {
        $migration = new Migration_20260101_000000_add_column();
        $this->assertSame('20260101_000000_add_column', $migration->id());
    }

    public function testTheClassNameIsRecoverableFromTheId()
    {
        $id = '20260101_000000_add_column';
        $this->assertSame(
            'Migration_' . $id,
            AbstractMigration::classNameFromId($id)
        );
        $this->assertSame(
            $id,
            AbstractMigration::idFromClassName(AbstractMigration::classNameFromId($id))
        );
    }

    // ------------------------------------------------------------- rejection

    public function testAClassWithoutThePrefixIsRejected()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('must be named Migration_');
        AbstractMigration::idFromClassName('NotAMigration_20260105_000000_wrong_prefix');
    }

    /**
     * @dataProvider malformedIds
     */
    public function testAMalformedIdIsRejected($id, $why)
    {
        $this->assertFalse(AbstractMigration::isMigrationId($id), $why);

        $this->expectException('InvalidArgumentException');
        AbstractMigration::idFromClassName('Migration_' . $id);
    }

    public function malformedIds()
    {
        return array(
            array('add_column', 'no timestamp at all'),
            array('2026_01_01_add_column', 'the date is not fixed-width'),
            array('20260101_add_column', 'no time part'),
            array('20260101_000000', 'no slug'),
            array('20260101_000000_add column', 'a space is not a slug character'),
            array('20260101_000000_add-column', 'a dash is not a slug character'),
            array('202601011_000000_x', 'nine digits of date'),
            array('20261301_000000_x', 'month 13'),
            array('20260132_000000_x', 'day 32'),
            array('20260229_000000_x', '2026 is not a leap year'),
            array('20260101_240000_x', 'hour 24'),
            array('20260101_006000_x', 'minute 60'),
            array('20260101_000060_x', 'second 60'),
        );
    }

    public function testARealLeapDayIsAccepted()
    {
        $this->assertTrue(AbstractMigration::isMigrationId('20240229_120000_leap_day'));
    }

    /**
     * The disjointness runUpdates() relies on when it unions the legacy update
     * map with the pending migrations: a legacy command is an integer or a
     * '2.4.x' string, and neither can ever look like a migration id.
     */
    public function testALegacyUpdateCommandIsNotAMigrationId()
    {
        foreach (array(1, 159, '159', '2.4.20', '2.4.146', 'adminTable', 'addSightings') as $command) {
            $this->assertFalse(
                AbstractMigration::isMigrationId($command),
                var_export($command, true) . ' must not be mistaken for a migration id'
            );
        }
    }

    // ------------------------------------------------------------- discovery

    public function testDiscoveryRejectsAMalformedFileNameRatherThanSkippingIt()
    {
        $manager = new TestMigrationManager(array(
            'Migration_20260101_000000_add_column.php',
            'Migration_whenever_i_get_round_to_it.php',
            'Migration_20260104_000000_unrelated.php',
        ));

        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('whenever_i_get_round_to_it');
        $manager->migrations();
    }

    public function testDiscoveryRejectsAFileWhoseClassIsMissing()
    {
        $manager = new TestMigrationManager(array(
            'Migration_20261231_235959_never_written.php',
        ));

        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('does not declare a class');
        $manager->migrations();
    }

    public function testDiscoveryRejectsAClassThatIsNotAMigration()
    {
        $manager = new TestMigrationManager(array(
            'Migration_20260106_000000_not_a_subclass.php',
        ));

        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('does not extend AbstractMigration');
        $manager->migrations();
    }

    public function testAWellFormedDirectoryIsDiscoveredWhole()
    {
        $manager = new TestMigrationManager(array(
            'Migration_20260101_000000_add_column.php',
            'Migration_20260104_000000_unrelated.php',
        ));

        $this->assertSame(
            array('20260101_000000_add_column', '20260104_000000_unrelated'),
            $manager->ids()
        );
    }

    public function testAskingForAnUnknownIdNamesTheFileItWasLookingFor()
    {
        $manager = new TestMigrationManager(array());

        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('Migration_20260101_000000_add_column.php');
        $manager->migration('20260101_000000_add_column');
    }
}
