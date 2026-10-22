<?php
/**
 * A MISP older than 3.0 that reads from this instance gets no analyst data
 * addressed by a value's SHA-256: SyncTool::valueTargetsWithheld() and the
 * AnalystData::beforeFind condition built on it.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }

        public static function import($type = null, $name = null, $parent = true)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}
if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }

        public static function reset()
        {
            self::$values = array();
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/SyncTool.php';
require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Model/Relationship.php';
require_once __DIR__ . '/../Model/Workspace.php';

class SyncWithheldNoteProbe extends AnalystData
{
    public $alias = 'Note';

    public function __construct()
    {
    }
}

class SyncWithheldRelationshipProbe extends Relationship
{
    public $alias = 'Relationship';

    public function __construct()
    {
    }
}

class SyncWithheldGraphProbe extends Workspace
{
    public $alias = 'Workspace';

    public function __construct()
    {
    }
}

class SyncAnalystDataWithheldTest extends TestCase
{
    const EVENT = 'b2c3d4e5-f607-4182-93a4-b5c6d7e8f922';

    protected function tearDown(): void
    {
        Configure::write('CurrentRequesterMispVersion', null);
    }

    private function requester($version)
    {
        Configure::write('CurrentRequesterMispVersion', $version);
    }

    public function testOnlyAMispOlderThan30IsWithheldFrom()
    {
        foreach (['2.4.155' => true, '2.5.50' => true, '3.0.0' => false, '3.1.0' => false] as $version => $withheld) {
            $this->requester($version);
            $this->assertSame($withheld, SyncTool::valueTargetsWithheld(), $version);
        }
        $this->requester(null);
        $this->assertFalse(SyncTool::valueTargetsWithheld(), 'an API client or the CLI');
    }

    public function testQueriesUnchangedForMisp30AndApiClients()
    {
        $query = ['conditions' => ['Note.object_uuid' => [self::EVENT]], 'recursive' => -1];
        foreach (['3.0.0', null] as $version) {
            $this->requester($version);
            $this->assertSame($query, (new SyncWithheldNoteProbe())->beforeFind($query));
            $this->assertSame($query, (new SyncWithheldRelationshipProbe())->beforeFind($query));
        }
    }

    public function testValueRowsLeftOutForAMispOlderThan30()
    {
        $this->requester('2.5.50');
        $note = (new SyncWithheldNoteProbe())->beforeFind([
            'conditions' => ['Note.object_uuid' => [self::EVENT]],
            'recursive' => -1,
        ]);
        $this->assertSame([
            'conditions' => ['Note.object_sha256' => null, ['Note.object_uuid' => [self::EVENT]]],
            'recursive' => -1,
        ], $note);

        $relationship = (new SyncWithheldRelationshipProbe())->beforeFind([]);
        $this->assertSame(['conditions' => [
            'Relationship.object_sha256' => null,
            'Relationship.related_object_sha256' => null,
        ]], $relationship);

        $stringConditions = (new SyncWithheldNoteProbe())->beforeFind(['conditions' => 'Note.id > 5']);
        $this->assertSame(['Note.object_sha256' => null, 'Note.id > 5'], $stringConditions['conditions']);
    }

    public function testGraphQueriesUnchangedForAMispOlderThan30()
    {
        $this->requester('2.5.50');
        $query = ['conditions' => ['Workspace.object_uuid' => [self::EVENT]], 'recursive' => -1];
        $this->assertSame($query, (new SyncWithheldGraphProbe())->beforeFind($query));
    }
}
