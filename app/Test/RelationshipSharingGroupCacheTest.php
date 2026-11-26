<?php
/**
 * The sharing groups that decide which analyst data a user may read are
 * cached per user: one AnalystDataBehavior instance and one Relationship
 * model serve every user of a process.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention). Named
 * to load after DatasourceCapabilitiesTest, whose Model stub then wins.
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
if (!class_exists('Model', false)) {
    class Model
    {
    }
}
if (!class_exists('ModelBehavior', false)) {
    class ModelBehavior
    {
    }
}

require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Model/Relationship.php';
require_once __DIR__ . '/../Model/Behavior/AnalystDataBehavior.php';

class SharingGroupCacheTestSharingGroups
{
    /** @var int[] the user ids asked about */
    public $asked = [];

    public function authorizedIds(array $user, $useCache = true)
    {
        $this->asked[] = $user['id'];
        return [$user['id'] * 10];
    }
}

class SharingGroupCacheTestModel extends Model
{
    public $current_type;

    public $SharingGroup;
}

class SharingGroupCacheTestRelationship extends Relationship
{
    public $data = [];

    /** @var AnalystDataBehavior */
    public $behavior;

    /** @var SharingGroupCacheTestModel */
    public $asModel;

    /** @var array what find() answers */
    public $found = [];

    /** @var array the conditions of each find() */
    public $queries = [];

    /** @var int[] the user each related element was resolved for */
    public $resolvedFor = [];

    public function analystDataConditions($user)
    {
        return $this->behavior->analystDataConditions($this->asModel, $user);
    }

    public function find($type = 'first', $query = [])
    {
        $this->queries[] = $query['conditions'];
        return $this->found;
    }

    public function getRelatedElement(array $user, $type, $uuid): array
    {
        $this->resolvedFor[] = $user['id'];
        return [];
    }
}

class RelationshipSharingGroupCacheTest extends TestCase
{
    /** @var SharingGroupCacheTestSharingGroups */
    private $sharingGroups;

    /** @var AnalystDataBehavior */
    private $behavior;

    protected function setUp(): void
    {
        $this->sharingGroups = new SharingGroupCacheTestSharingGroups();
        $this->behavior = new AnalystDataBehavior();
    }

    private function model($type)
    {
        $model = (new ReflectionClass('SharingGroupCacheTestModel'))->newInstanceWithoutConstructor();
        $model->current_type = $type;
        $model->SharingGroup = $this->sharingGroups;
        return $model;
    }

    private static function user($id, $siteAdmin = false)
    {
        return [
            'id' => $id,
            'Role' => ['perm_site_admin' => $siteAdmin],
            'Organisation' => ['uuid' => "org-$id"],
        ];
    }

    public function testEachUserGetsTheirOwnSharingGroups()
    {
        $notes = $this->model('Note');
        $opinions = $this->model('Opinion');

        $first = $this->behavior->analystDataConditions($notes, self::user(1));
        $second = $this->behavior->analystDataConditions($opinions, self::user(2));
        $again = $this->behavior->analystDataConditions($notes, self::user(1));

        $this->assertSame([10], $first['OR']['AND']['Note.sharing_group_id IN']);
        $this->assertSame('org-1', $first['OR']['Note.org_uuid']);
        $this->assertSame([20], $second['OR']['AND']['Opinion.sharing_group_id IN']);
        $this->assertSame('org-2', $second['OR']['Opinion.orgc_uuid']);
        $this->assertSame($first, $again);
        $this->assertSame([1, 2], $this->sharingGroups->asked);
    }

    public function testASiteAdminReadsAllAnalystData()
    {
        $this->assertSame([], $this->behavior->analystDataConditions($this->model('Note'), self::user(3, true)));
        $this->assertSame([], $this->sharingGroups->asked);
    }

    public function testInboundRelationshipsAreFilteredAndResolvedForTheUserAsked()
    {
        $relationship = (new ReflectionClass('SharingGroupCacheTestRelationship'))->newInstanceWithoutConstructor();
        $relationship->behavior = $this->behavior;
        $relationship->asModel = $this->model('Relationship');
        $relationship->found = [['Relationship' => [
            'object_type' => 'Event',
            'object_uuid' => '28635464-d6d0-499a-8467-47a06c447d63',
        ]]];

        $relationship->getInboundRelationships(self::user(1), 'Attribute', 'bdfc376c-be54-44be-bc54-53cb08832a65');
        $relationship->getInboundRelationships(self::user(2), 'Attribute', 'bdfc376c-be54-44be-bc54-53cb08832a65');

        $this->assertSame([10], $relationship->queries[0]['AND'][0]['OR']['AND']['Relationship.sharing_group_id IN']);
        $this->assertSame([20], $relationship->queries[1]['AND'][0]['OR']['AND']['Relationship.sharing_group_id IN']);
        $this->assertSame([1, 2], $relationship->resolvedFor);
    }
}
