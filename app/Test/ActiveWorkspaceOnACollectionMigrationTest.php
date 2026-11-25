<?php
/**
 * What the migration that turns an Early Access active workspace, a graph,
 * into the collection that graph is drawn on decides and writes per row. The
 * reads and the writes need a database; these drive the decisions alone.
 */

require_once __DIR__ . '/MigrationLedgerStubs.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261120_081016_active_workspace_on_a_collection.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261022_123413_early_access_workspace_names.php';
require_once __DIR__ . '/../Lib/Tools/ActiveWorkspaceTool.php';

use PHPUnit\Framework\TestCase;

class ActiveWorkspaceOnACollectionMigrationTest extends TestCase
{
    const MIGRATION = 'Migration_20261120_081016_active_workspace_on_a_collection';

    const EARLY_ACCESS = 'Migration_20261022_123413_early_access_workspace_names';

    const G1 = '8a1d6c3e-4b2f-4c7a-9e10-2f3b4c5d6e7f';

    const C1 = '0b9e8d7c-6a5f-4e3d-8c2b-1a0f9e8d7c6b';

    /**
     * @param mixed $stored
     * @return string|false|null
     */
    private static function named($stored)
    {
        $class = self::MIGRATION;
        return $class::named($stored);
    }

    /**
     * @param array|null $graph
     * @param array|null $found
     * @return array|null
     */
    private static function converted($graph, $found = null)
    {
        $class = self::MIGRATION;
        return $class::converted($graph, $found);
    }

    /**
     * @param string $type
     * @return array
     */
    private static function graphOn($type)
    {
        return array('uuid' => self::G1, 'object_type' => $type, 'object_uuid' => self::C1);
    }

    public function testAnInstanceWithoutEarlyAccessRowsIsLeftAlone()
    {
        $class = self::MIGRATION;
        $decision = $class::decide(0);
        $this->assertSame('none', $decision['action']);
        $this->assertSame('No active workspace still names a graph: there is nothing to convert.', $decision['line']);
    }

    public function testRowsStillNamingAGraphAreConverted()
    {
        $class = self::MIGRATION;
        $decision = $class::decide(3);
        $this->assertSame('convert', $decision['action']);
        $this->assertStringStartsWith('From v3 Early Access: 3 active workspace setting(s) still name a graph.', $decision['line']);
    }

    public function earlyAccessShapes()
    {
        return array(
            'as stored' => array('{"workspace_uuid":"' . self::G1 . '"}', self::G1),
            'spelled in capitals' => array('{"workspace_uuid":"' . strtoupper(self::G1) . '"}', self::G1),
            'already decoded' => array(array('workspace_uuid' => self::G1), self::G1),
            'naming nothing' => array('{"workspace_uuid":null}', null),
            'not a uuid' => array('{"workspace_uuid":"zz"}', null),
            'not a string' => array('{"workspace_uuid":5}', null),
        );
    }

    /**
     * @dataProvider earlyAccessShapes
     */
    public function testTheEarlyAccessShapeIsRecognised($stored, $expected)
    {
        $this->assertSame($expected, self::named($stored));
    }

    public function otherValues()
    {
        return array(
            'a workspace' => array('{"collection_uuid":"' . self::C1 . '","graph_uuid":"' . self::G1 . '"}'),
            'a workspace without a graph' => array('{"collection_uuid":"' . self::C1 . '","graph_uuid":null}'),
            'cleared' => array('{"collection_uuid":null,"graph_uuid":null}'),
            'the placeholder' => array('[]'),
            'both keys' => array('{"workspace_uuid":"' . self::G1 . '","collection_uuid":"' . self::C1 . '"}'),
            'not JSON' => array('workspace_uuid'),
            'a string' => array('"' . self::G1 . '"'),
        );
    }

    /**
     * @dataProvider otherValues
     */
    public function testAnyOtherValueIsLeftAlone($stored)
    {
        $this->assertFalse(self::named($stored));
    }

    public function testAGraphOnACollectionTheUserMayEditStaysTheirLayout()
    {
        $found = array(array('uuid' => self::C1), array('uuid' => self::G1), null);
        $this->assertSame(
            array('collection_uuid' => self::C1, 'graph_uuid' => self::G1),
            self::converted(self::graphOn('Collection'), $found)
        );
    }

    public function testAnotherOrganisationsGraphLeavesTheCollectionWithoutOne()
    {
        $found = array(array('uuid' => self::C1), null, 'graph');
        $this->assertSame(
            array('collection_uuid' => self::C1, 'graph_uuid' => null),
            self::converted(self::graphOn('Collection'), $found)
        );
    }

    public function refusedCollections()
    {
        return array(
            'gone or not visible' => array(array(null, null, 'collection')),
            'not editable' => array(array(array('uuid' => self::C1), null, 'edit')),
        );
    }

    /**
     * @dataProvider refusedCollections
     */
    public function testACollectionTheUserMayNotEditEndsIt($found)
    {
        $this->assertNull(self::converted(self::graphOn('Collection'), $found));
    }

    public function otherTargets()
    {
        return array(
            'an event' => array('Event'),
            'a cluster' => array('GalaxyCluster'),
        );
    }

    /**
     * @dataProvider otherTargets
     */
    public function testAGraphOnAnotherRecordEndsIt($type)
    {
        $this->assertNull(self::converted(self::graphOn($type)));
    }

    public function testAGraphThatIsGoneEndsIt()
    {
        $this->assertNull(self::converted(null));
    }

    public function testItReadsWhatTheEarlyAccessMigrationWrote()
    {
        $class = self::MIGRATION;
        $earlyAccess = self::EARLY_ACCESS;
        $this->assertSame($earlyAccess::NEW_SETTING, $class::SETTING);
        $this->assertStringContainsString(
            "array('" . $class::OLD_KEY . "' => \$uuid)",
            file_get_contents(APPLIBS . 'Migration/Migrations/' . $earlyAccess . '.php')
        );
    }

    public function testItWritesTheSettingTheWorkspaceIsReadFrom()
    {
        $class = self::MIGRATION;
        $this->assertSame(ActiveWorkspaceTool::SETTING, $class::SETTING);
    }
}
