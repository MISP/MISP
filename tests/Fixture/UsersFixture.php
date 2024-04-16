<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Authentication\PasswordHasher\DefaultPasswordHasher;
use Cake\TestSuite\Fixture\TestFixture;

class UsersFixture extends TestFixture
{
    public $connection = 'test';

    // Admin user
    public const USER_ADMIN_ID = 1000;
    public const USER_ADMIN_EMAIL = 'admin@test.test';
    public const USER_ADMIN_PASSWORD = 'AdminPassword';

    // Sync user
    public const USER_SYNC_ID = 2000;
    public const USER_SYNC_EMAIL = 'sync@test.test';
    public const USER_SYNC_PASSWORD = 'SyncPassword';

    // Org Admin user
    public const USER_ORG_ADMIN_ID = 3000;
    public const USER_ORG_ADMIN_EMAIL = 'org_admin@test.test';
    public const USER_ORG_ADMIN_PASSWORD = 'OrgAdminPassword';

    // Regular User user
    public const USER_REGULAR_USER_ID = 4000;
    public const USER_REGULAR_USER_EMAIL = 'user@test.test';
    public const USER_REGULAR_USER_PASSWORD = 'UserPassword';

    public function init(): void
    {
        $hasher = new DefaultPasswordHasher();
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::USER_ADMIN_ID,
                'uuid' => $faker->uuid(),
                'email' => self::USER_ADMIN_EMAIL,
                'password' => $hasher->hash(self::USER_ADMIN_PASSWORD),
                'role_id' => RolesFixture::ROLE_ADMIN_ID,
                'disabled' => 0,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'date_created' => $faker->dateTime()->getTimestamp(),
                'date_modified' => $faker->dateTime()->getTimestamp(),
            ],
            [
                'id' => self::USER_SYNC_ID,
                'uuid' => $faker->uuid(),
                'email' => self::USER_SYNC_EMAIL,
                'password' => $hasher->hash(self::USER_SYNC_PASSWORD),
                'role_id' => RolesFixture::ROLE_SYNC_ID,
                'disabled' => 0,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'date_created' => $faker->dateTime()->getTimestamp(),
                'date_modified' => $faker->dateTime()->getTimestamp(),
            ],
            [
                'id' => self::USER_ORG_ADMIN_ID,
                'uuid' => $faker->uuid(),
                'email' => self::USER_ORG_ADMIN_EMAIL,
                'password' => $hasher->hash(self::USER_ORG_ADMIN_PASSWORD),
                'role_id' => RolesFixture::ROLE_ORG_ADMIN_ID,
                'disabled' => 0,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'date_created' => $faker->dateTime()->getTimestamp(),
                'date_modified' => $faker->dateTime()->getTimestamp(),
            ],
            [
                'id' => self::USER_REGULAR_USER_ID,
                'uuid' => $faker->uuid(),
                'email' => self::USER_REGULAR_USER_EMAIL,
                'password' => $hasher->hash(self::USER_REGULAR_USER_PASSWORD),
                'role_id' => RolesFixture::ROLE_REGULAR_USER_ID,
                'disabled' => 0,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'date_created' => $faker->dateTime()->getTimestamp(),
                'date_modified' => $faker->dateTime()->getTimestamp(),
            ],
        ];
        parent::init();
    }
}
