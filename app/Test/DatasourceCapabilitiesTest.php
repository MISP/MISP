<?php
/**
 * The $supports vocabulary the datasources declare, and the one property of it
 * that is easy to break by accident.
 *
 * AppModel::checkDbSupport() reads $supports off the datasource, so a
 * capability is only real on the driver that declares it. MysqlObserverExtended
 * is the datasource database.default.php actually ships, and it used to restate
 * the whole array rather than inherit it - which meant a capability added to
 * MysqlExtended silently did not reach the driver every instance runs. The copy
 * is gone; this is what stops it coming back.
 *
 * @see MigrationSchemaStubs.php for how the real Cake drivers are loaded without a connection.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';
require_once __DIR__ . '/../Model/Datasource/Database/MysqlObserverExtended.php';

use PHPUnit\Framework\TestCase;

class DatasourceCapabilitiesTest extends TestCase
{
    /**
     * The capabilities MISP's own code asks about. Index hints and the join
     * controls are the driver's extended query rendering; the temporary MEMORY
     * table and the fulltext index are engine constructs PostgreSQL has no
     * equivalent for.
     */
    public function testMysqlExtendedDeclaresTheWholeVocabulary()
    {
        $db = new MigrationTestMysqlExtended();
        $this->assertSame(
            array(
                'indexHints',
                'ignoreIndexHints',
                'reverseJoin',
                'straightJoin',
                'insertMulti',
                'temporaryMemoryTable',
                'fulltextIndex',
            ),
            array_keys($db->supports)
        );
        foreach ($db->supports as $capability => $supported) {
            $this->assertTrue($supported, $capability . ' is declared but not enabled');
        }
    }

    /**
     * The one that matters: the shipped default has to answer the same as its
     * parent, without restating it.
     */
    public function testTheShippedDatasourceInheritsThemRatherThanRestatingThem()
    {
        $parent = new ReflectionClass('MysqlExtended');
        $shipped = new ReflectionClass('MysqlObserverExtended');

        $this->assertSame(
            $parent->getDefaultProperties()['supports'],
            $shipped->getDefaultProperties()['supports']
        );
        $this->assertSame(
            'MysqlExtended',
            $shipped->getProperty('supports')->getDeclaringClass()->getName(),
            'MysqlObserverExtended must inherit $supports, not declare its own copy'
        );
    }

    /**
     * upsert is deliberately absent. It looks like it belongs in this list and
     * does not: PostgreSQL has ON CONFLICT, so a probe reading false there
     * would push a caller into a slower read-then-write with a race in it.
     * Upserts go through SqlDialect::upsert(), which renders both engines.
     */
    public function testUpsertIsNotACapabilityProbe()
    {
        $db = new MigrationTestMysqlExtended();
        $this->assertArrayNotHasKey('upsert', $db->supports);
        $this->assertTrue(method_exists('SqlDialect', 'upsert'));
    }

    /**
     * Cake's unmodified Mysql is the baseline, and declaring nothing is the
     * whole of what that means: a call site asks rather than branching, and a
     * legacy instance still pointed at Database/Mysql gets correct results
     * with whatever plan the server picks for itself.
     */
    public function testTheBaselineDriverDeclaresNothing()
    {
        $this->assertFalse(isset((new MigrationTestMysql())->supports));
    }
}
