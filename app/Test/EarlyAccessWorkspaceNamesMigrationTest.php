<?php
/**
 * When the migration that carries v3 Early Access's analyst graph names over
 * to workspaces has anything to do. The counts and the writes need a
 * database; these drive the decision alone.
 */

require_once __DIR__ . '/MigrationLedgerStubs.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261022_123413_early_access_workspace_names.php';

use PHPUnit\Framework\TestCase;

class EarlyAccessWorkspaceNamesMigrationTest extends TestCase
{
    const MIGRATION = 'Migration_20261022_123413_early_access_workspace_names';

    /** What a fresh install, or one upgraded from 2.5, holds. */
    const NOTHING = array(
        'Note.object_type' => 0,
        'Opinion.object_type' => 0,
        'Relationship.object_type' => 0,
        'Relationship.related_object_type' => 0,
    );

    /**
     * @param array $targets
     * @param int $settings
     * @return array
     */
    private static function decide(array $targets = array(), $settings = 0)
    {
        $class = self::MIGRATION;
        return $class::decide(array('targets' => $targets + self::NOTHING, 'settings' => $settings));
    }

    public function testAnInstanceThatNeverRanEarlyAccessIsLeftAlone()
    {
        $decision = self::decide();
        $this->assertSame('none', $decision['action']);
        $this->assertStringContainsString('did not run v3 Early Access', $decision['line']);
    }

    public function testAnalystDataOnAnAnalystGraphIsRenamed()
    {
        $decision = self::decide(array('Note.object_type' => 2, 'Relationship.related_object_type' => 1));
        $this->assertSame('rename', $decision['action']);
        $this->assertSame('From v3 Early Access: 3 analyst data reference(s) to an analyst graph now name a Workspace.', $decision['line']);
    }

    public function testAnActiveAnalystGraphAloneIsEnough()
    {
        $decision = self::decide(array(), 2);
        $this->assertSame('rename', $decision['action']);
        $this->assertSame('From v3 Early Access: 2 active analyst graph setting(s) move to the active workspace.', $decision['line']);
    }

    public function testBothAreSaid()
    {
        $decision = self::decide(array('Opinion.object_type' => 1), 1);
        $this->assertSame('From v3 Early Access: 1 analyst data reference(s) to an analyst graph now name a Workspace; 1 active analyst graph setting(s) move to the active workspace.', $decision['line']);
    }

    public function testEveryColumnNamingATargetTypeIsCovered()
    {
        $class = self::MIGRATION;
        $covered = array();
        foreach ($class::TARGETS as $target) {
            $covered[] = $target[0] . '.' . $target[1];
        }
        $this->assertSame(array_keys(self::NOTHING), $covered);
    }
}
