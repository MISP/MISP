<?php
/**
 * When the migration that points analyst data at saved graphs again has
 * anything to do. The counts and the writes need a database; these drive the
 * decision alone.
 */

require_once __DIR__ . '/MigrationLedgerStubs.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261028_083019_analyst_graph_names_back.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261022_123413_early_access_workspace_names.php';

use PHPUnit\Framework\TestCase;

class AnalystGraphNamesBackMigrationTest extends TestCase
{
    const MIGRATION = 'Migration_20261028_083019_analyst_graph_names_back';

    const EARLY_ACCESS = 'Migration_20261022_123413_early_access_workspace_names';

    /** What a fresh install, or one upgraded from 2.5, holds. */
    const NOTHING = array(
        'Note.object_type' => 0,
        'Opinion.object_type' => 0,
        'Relationship.object_type' => 0,
        'Relationship.related_object_type' => 0,
    );

    /**
     * @param array $targets
     * @return array
     */
    private static function decide(array $targets = array())
    {
        $class = self::MIGRATION;
        return $class::decide($targets + self::NOTHING);
    }

    public function testAnInstanceWithoutWorkspaceReferencesIsLeftAlone()
    {
        $decision = self::decide();
        $this->assertSame('none', $decision['action']);
        $this->assertStringContainsString('nothing to rename', $decision['line']);
    }

    public function testReferencesToAWorkspaceAreRenamed()
    {
        $decision = self::decide(array('Note.object_type' => 2, 'Relationship.related_object_type' => 1));
        $this->assertSame('rename', $decision['action']);
        $this->assertSame('3 analyst data reference(s) to a workspace now name a saved graph (Graph) again.', $decision['line']);
    }

    public function testItUndoesWhatTheEarlyAccessMigrationWrote()
    {
        $back = self::MIGRATION;
        $earlyAccess = self::EARLY_ACCESS;
        $this->assertSame($earlyAccess::NEW_TYPE, $back::OLD_TYPE);
        $this->assertSame($earlyAccess::OLD_TYPE, $back::NEW_TYPE);
        $this->assertSame($earlyAccess::TARGETS, $back::TARGETS);
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

    public function testTheNewTypeIsTheSavedGraphModel()
    {
        $class = self::MIGRATION;
        $this->assertSame('Graph', $class::NEW_TYPE);
        $this->assertStringContainsString("public \$current_type = '" . $class::NEW_TYPE . "';", file_get_contents(__DIR__ . '/../Model/Graph.php'));
    }
}
