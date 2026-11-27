<?php
/**
 * A sharing group created through the API is local, like one created through
 * the form: sync may not rewrite it. Capturing an existing group leaves its
 * local flag alone.
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

class SharingGroupCaptureLocalTestMembers
{
    public function checkIfAuthorised($id, $orgId = null)
    {
        return false;
    }
}

class SharingGroupCaptureLocalTestModel extends SharingGroup
{
    public $alias = 'SharingGroup';

    /** @var array|null the stored sharing_groups row */
    public $existing;

    /** @var array[] every row passed to save() */
    public $saved = [];

    public function __construct()
    {
        $this->SharingGroupOrg = new SharingGroupCaptureLocalTestMembers();
        $this->SharingGroupServer = new SharingGroupCaptureLocalTestMembers();
    }

    public function find($type = 'first', $query = [])
    {
        if (empty($this->existing)) {
            return [];
        }
        return [
            'SharingGroup' => $this->existing,
            'SharingGroupOrg' => [],
            'SharingGroupServer' => [],
        ];
    }

    public function exists($id = null)
    {
        return !empty($this->existing);
    }

    public function create($data = [], $filterKey = false)
    {
    }

    public function save($data = null, $validate = true, $fieldList = [])
    {
        $this->saved[] = $data;
        $this->id = 7;
        return true;
    }
}

class SharingGroupCaptureLocalTest extends TestCase
{
    const UUID = '5d2a4e9c-1b3f-4c6d-8e7f-90a1b2c3d4e5';

    private function admin()
    {
        return [
            'id' => 3,
            'org_id' => 1,
            'Organisation' => [
                'uuid' => '0b9e7f2a-6c1d-4e3b-a5f4-7d8c9e0a1b2c',
                'name' => 'Host org',
            ],
            'Role' => [
                'perm_site_admin' => 1,
                'perm_sync' => 1,
                'perm_sharing_group' => 1,
            ],
        ];
    }

    private function payload()
    {
        return ['uuid' => self::UUID, 'name' => 'Created over the API'];
    }

    public function testNewGroupFromTheApiIsLocal()
    {
        $sg = new SharingGroupCaptureLocalTestModel();
        $id = $sg->captureSG($this->payload(), $this->admin(), false, true);
        $this->assertSame(7, $id);
        $this->assertSame(1, $sg->saved[0]['local']);
        $this->assertSame(0, $sg->saved[0]['sync_user_id']);
    }

    public function testNewGroupFromCaptureIsNotLocal()
    {
        $sg = new SharingGroupCaptureLocalTestModel();
        $id = $sg->captureSG($this->payload(), $this->admin());
        $this->assertSame(7, $id);
        $this->assertSame(0, $sg->saved[0]['local']);
        $this->assertSame(3, $sg->saved[0]['sync_user_id']);
    }

    public function testExistingGroupKeepsItsLocalFlag()
    {
        $sg = new SharingGroupCaptureLocalTestModel();
        $sg->existing = [
            'id' => 7,
            'uuid' => self::UUID,
            'org_id' => 1,
            'local' => 0,
            'modified' => '2020-01-01 00:00:00',
        ];
        $sg->captureSG($this->payload(), $this->admin(), false, true);
        $this->assertNotEmpty($sg->saved);
        foreach ($sg->saved as $row) {
            $this->assertSame(0, $row['local']);
        }
    }
}
