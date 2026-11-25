<?php
/**
 * What the migration that stores collection members under their lowercase
 * uuid decides per row. The reads and the writes need a database; these
 * drive the decisions alone.
 */

require_once __DIR__ . '/MigrationLedgerStubs.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261125_121841_lowercase_collection_element_uuids.php';

use PHPUnit\Framework\TestCase;

class LowercaseCollectionElementUuidsMigrationTest extends TestCase
{
    const MIGRATION = 'Migration_20261125_121841_lowercase_collection_element_uuids';

    const U1 = '5c1f0e2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f';

    const U2 = '6d2a1f3e-4c5b-4d6e-9f70-8b9cad0e1f30';

    /**
     * @param array $rows
     * @param array $held
     * @return array
     */
    private static function plan(array $rows, array $held = array())
    {
        $class = self::MIGRATION;
        return $class::plan($rows, $held);
    }

    /**
     * @param int $id
     * @param int $collection
     * @param string $uuid
     * @return array
     */
    private static function row($id, $collection, $uuid)
    {
        return array('id' => $id, 'collection_id' => $collection, 'element_uuid' => $uuid);
    }

    public function testAnUppercaseMemberIsLowercased()
    {
        $this->assertSame(
            array(4 => self::U1),
            self::plan(array(self::row(4, 7, strtoupper(self::U1))))
        );
    }

    public function testAMixedCaseMemberIsLowercased()
    {
        $mixed = '5C1F0e2d-3b4a-4c5d-8e6f-7A8B9C0D1E2F';
        $this->assertSame(array(4 => self::U1), self::plan(array(self::row(4, 7, $mixed))));
    }

    public function testAMemberWhoseCollectionHoldsTheLowercaseSpellingGoes()
    {
        $this->assertSame(
            array(4 => 'drop'),
            self::plan(array(self::row(4, 7, strtoupper(self::U1))), array('7:' . self::U1 => true))
        );
    }

    public function testTheSameUuidInAnotherCollectionDoesNotMakeItADuplicate()
    {
        $this->assertSame(
            array(4 => self::U1),
            self::plan(array(self::row(4, 7, strtoupper(self::U1))), array('8:' . self::U1 => true))
        );
    }

    public function testOfTwoSpellingsInOneCollectionTheFirstIsKept()
    {
        $this->assertSame(
            array(4 => self::U1, 9 => 'drop'),
            self::plan(array(
                self::row(4, 7, strtoupper(self::U1)),
                self::row(9, 7, '5C1F0E2D-3b4a-4c5d-8e6f-7a8b9c0d1e2f'),
            ))
        );
    }

    public function testTwoCollectionsEachKeepTheirMember()
    {
        $this->assertSame(
            array(4 => self::U1, 9 => self::U1),
            self::plan(array(
                self::row(4, 7, strtoupper(self::U1)),
                self::row(9, 8, strtoupper(self::U1)),
            ))
        );
    }

    public function testLowercaseMembersAreLeftAlone()
    {
        $this->assertSame(
            array(5 => self::U2),
            self::plan(array(
                self::row(4, 7, self::U1),
                self::row(5, 7, strtoupper(self::U2)),
            ), array('7:' . self::U1 => true))
        );
    }

    public function testItIsDataOnly()
    {
        $class = self::MIGRATION;
        $migration = new $class();
        $this->assertFalse($migration->requiresLogout);
        $this->assertSame('20261125_121841_lowercase_collection_element_uuids', $migration->id());
    }
}
