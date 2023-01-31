<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class RolesFixture extends TestFixture
{
    public $connection = 'test';

    public const ROLE_ADMIN_ID = 1;
    public const ROLE_SYNC_ID = 2;
    public const ROLE_ORG_ADMIN_ID = 3;
    public const ROLE_REGULAR_USER_ID = 4;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::ROLE_ADMIN_ID,
                'uuid' => $faker->uuid(),
                'name' => 'admin',
                'is_default' => false,
                'perm_admin' => true,
                'perm_sync' => false,
                'perm_org_admin' => false
            ],
            [
                'id' => self::ROLE_SYNC_ID,
                'uuid' => $faker->uuid(),
                'name' => 'sync',
                'is_default' => false,
                'perm_admin' => false,
                'perm_sync' => true,
                'perm_org_admin' => false
            ],
            [
                'id' => self::ROLE_ORG_ADMIN_ID,
                'uuid' => $faker->uuid(),
                'name' => 'org_admin',
                'is_default' => false,
                'perm_admin' => false,
                'perm_sync' => false,
                'perm_org_admin' => true
            ],
            [
                'id' => self::ROLE_REGULAR_USER_ID,
                'uuid' => $faker->uuid(),
                'name' => 'user',
                'is_default' => true,
                'perm_admin' => false,
                'perm_sync' => false,
                'perm_org_admin' => false
            ]
        ];
        parent::init();
    }
}
