<?php
/**
 * Who may change a sharing group's membership: a sync user's exemption from
 * the extend flag covers groups received through sync, not locally created
 * ones.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }

        public static function import(...$args)
        {
        }
    }
}
if (!class_exists('Model', false)) {
    class Model
    {
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel extends Model
    {
    }
}
if (!class_exists('Validation', false)) {
    class Validation
    {
        public static function uuid($value)
        {
            return preg_match('/^[0-9a-f-]{36}$/i', (string)$value);
        }
    }
}

require_once __DIR__ . '/../Model/SharingGroup.php';

class SharingGroupExtendSyncTestMembers
{
    /** @var array<int, int> org_id => extend */
    public $orgs = [];

    public $allOrgs = false;

    public function checkIfAuthorised($id, $orgId = null)
    {
        return $orgId === null ? $this->allOrgs : isset($this->orgs[$orgId]);
    }

    public function hasAny($conditions)
    {
        $orgId = $conditions['org_id'];
        return isset($this->orgs[$orgId])
            && $this->orgs[$orgId] == $conditions['extend'];
    }
}

class SharingGroupExtendSyncTestModel extends SharingGroup
{
    /** @var array|null the sharing groups row */
    public $row;

    public function __construct()
    {
        $this->SharingGroupOrg = new SharingGroupExtendSyncTestMembers();
        $this->SharingGroupServer = new SharingGroupExtendSyncTestMembers();
    }

    public function find($type = 'first', $query = [])
    {
        $byUuid = isset($query['conditions']['SharingGroup.uuid']);
        if (empty($this->row) || $byUuid) {
            return [];
        }
        return ['SharingGroup' => $this->row];
    }

    public function exists($id = null)
    {
        return !empty($this->row);
    }
}

class SharingGroupExtendSyncTest extends TestCase
{
    const OWNER_ORG = 1;
    const MEMBER_ORG = 2;
    const LOCAL = 1;
    const SYNCED = 0;

    private function group($local, $memberExtend)
    {
        $sg = new SharingGroupExtendSyncTestModel();
        $sg->row = [
            'id' => 5,
            'org_id' => self::OWNER_ORG,
            'local' => $local,
        ];
        $sg->SharingGroupOrg->orgs = [self::OWNER_ORG => 1];
        if ($memberExtend !== null) {
            $sg->SharingGroupOrg->orgs[self::MEMBER_ORG] = $memberExtend;
        }
        return $sg;
    }

    private function mayExtend($sg, $sync = true, $sharingGroup = true)
    {
        $user = [
            'id' => 10,
            'org_id' => self::MEMBER_ORG,
            'Role' => [
                'perm_site_admin' => 0,
                'perm_sync' => $sync ? 1 : 0,
                'perm_sharing_group' => $sharingGroup ? 1 : 0,
            ],
        ];
        return $sg->checkIfAuthorisedExtend($user, 5);
    }

    public function testSyncMemberCannotExtendLocalGroup()
    {
        $this->assertFalse($this->mayExtend($this->group(self::LOCAL, 0)));
    }

    public function testSyncMemberMayExtendSyncedGroup()
    {
        $this->assertTrue($this->mayExtend($this->group(self::SYNCED, 0)));
    }

    public function testSyncUserOutsideSyncedGroupCannotExtend()
    {
        $this->assertFalse($this->mayExtend($this->group(self::SYNCED, null)));
    }

    public function testSyncUserCannotExtendLocalGroupOpenToAllLocalOrgs()
    {
        $sg = $this->group(self::LOCAL, null);
        $sg->SharingGroupServer->allOrgs = true;
        $this->assertFalse($this->mayExtend($sg));
    }

    public function testExtendFlagStillGrantsSyncUserOnLocalGroup()
    {
        $this->assertTrue($this->mayExtend($this->group(self::LOCAL, 1)));
    }

    public function testNonSyncMemberNeedsExtend()
    {
        $plainMember = $this->group(self::SYNCED, 0);
        $extender = $this->group(self::SYNCED, 1);
        $this->assertFalse($this->mayExtend($plainMember, false));
        $this->assertTrue($this->mayExtend($extender, false));
    }

    public function testOwnerOrgMayExtendLocalGroup()
    {
        $sg = $this->group(self::LOCAL, null);
        $sg->row['org_id'] = self::MEMBER_ORG;
        $this->assertTrue($this->mayExtend($sg));
    }

    public function testMissingGroupIsRefused()
    {
        $sg = $this->group(self::SYNCED, 0);
        $sg->row = null;
        $this->assertFalse($this->mayExtend($sg));
    }

    public function testNoSharingGroupPermissionIsRefused()
    {
        $sg = $this->group(self::SYNCED, 1);
        $this->assertFalse($this->mayExtend($sg, true, false));
    }
}
