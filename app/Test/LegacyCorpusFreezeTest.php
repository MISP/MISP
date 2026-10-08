<?php
/**
 * The legacy update corpus is frozen, and this is what holds it that way.
 *
 * `DB_CHANGES` is an archive: every number in it has already run on instances in
 * the wild, and an instance decides what to apply from it by comparing against a
 * single high-water mark. Add a case above the freeze and it is applied by the
 * instances below that number and silently skipped by every instance already
 * past it - which is the exact bug the migration ledger was built to remove,
 * reappearing in the code that removed it. New schema changes belong in
 * app/Lib/Migration/Migrations/.
 *
 * `AppModel::findUpgrades()` raises on this at runtime too. The check is here as
 * well because the runtime one only fires on an instance that runs an update,
 * where this fires in CI on the commit that introduces the mistake.
 *
 * Read from the source rather than from the loaded class on purpose: AppModel
 * needs the full CakePHP bootstrap, which no test under app/Test/ has, and
 * several test files declare their own stub AppModel. The rule being asserted is
 * a rule about what the file may contain, so reading the file is the honest way
 * to ask.
 */

require_once __DIR__ . '/MigrationLedgerStubs.php';

use PHPUnit\Framework\TestCase;

class LegacyCorpusFreezeTest extends TestCase
{
    /** @var string */
    private static $source;

    public static function setUpBeforeClass(): void
    {
        self::$source = file_get_contents(__DIR__ . '/../Model/AppModel.php');
    }

    public function testTheFreezeIsDeclared()
    {
        $this->assertSame(159, $this->freeze());
    }

    public function testTheCorpusDoesNotReachPastTheFreeze()
    {
        $keys = $this->dbChangeKeys();

        $this->assertNotEmpty($keys);
        $this->assertLessThanOrEqual(
            $this->freeze(),
            max($keys),
            'DB_CHANGES is frozen. A new schema change is a migration class under app/Lib/Migration/Migrations/, not another case here.'
        );
    }

    public function testFindUpgradesStillEnforcesTheFreezeAtRuntime()
    {
        $this->assertStringContainsString(
            'assertLegacyCorpusFrozen()',
            self::$source,
            'the runtime guard has gone missing from AppModel'
        );
    }

    /**
     * The property §6.7's single loop rests on: findUpgrades() unions the legacy
     * map with the pending migrations, and the union is only safe because no
     * legacy key can ever look like a migration id.
     */
    public function testNoLegacyKeyCanBeMistakenForAMigrationId()
    {
        foreach ($this->dbChangeKeys() as $key) {
            $this->assertFalse(
                AbstractMigration::isMigrationId((string)$key),
                'the legacy key ' . $key . ' collides with the migration id space'
            );
        }
        foreach ($this->oldDbChangeKeys() as $key) {
            $this->assertFalse(
                AbstractMigration::isMigrationId($key),
                'the legacy key ' . $key . ' collides with the migration id space'
            );
        }
    }

    // ----------------------------------------------------------------- guts

    private function freeze()
    {
        $this->assertSame(
            1,
            preg_match('/const DB_CHANGES_FREEZE = (\d+);/', self::$source, $match),
            'AppModel no longer declares DB_CHANGES_FREEZE'
        );
        return (int)$match[1];
    }

    /**
     * @return array The integer keys of DB_CHANGES.
     */
    private function dbChangeKeys()
    {
        $this->assertSame(
            1,
            preg_match('/const DB_CHANGES = array\((.*?)\n\s*\);/s', self::$source, $match),
            'AppModel no longer declares DB_CHANGES'
        );
        preg_match_all('/(\d+)\s*=>/', $match[1], $keys);
        return array_map('intval', $keys[1]);
    }

    /**
     * @return array The '2.4.x' keys OLD_DB_CHANGES expands into.
     */
    private function oldDbChangeKeys()
    {
        $this->assertSame(
            1,
            preg_match('/const OLD_DB_CHANGES = array\((.*?)\n\s*\);/s', self::$source, $match),
            'AppModel no longer declares OLD_DB_CHANGES'
        );
        preg_match_all('/(\d+)\s*=>/', $match[1], $keys);
        $expanded = array();
        foreach ($keys[1] as $hotfix) {
            $expanded[] = '2.4.' . $hotfix;
        }
        return $expanded;
    }
}
