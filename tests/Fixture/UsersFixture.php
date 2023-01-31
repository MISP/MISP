<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;
use Authentication\PasswordHasher\DefaultPasswordHasher;

class UsersFixture extends TestFixture
{
    public $connection = 'test';

    // Admin user
    public const USER_ADMIN_ID = 1;
    public const USER_ADMIN_USERNAME = 'admin';
    public const USER_ADMIN_PASSWORD = 'AdminPassword';

    // Sync user
    public const USER_SYNC_ID = 2;
    public const USER_SYNC_USERNAME = 'sync';
    public const USER_SYNC_PASSWORD = 'SyncPassword';

    // Org Admin user
    public const USER_ORG_ADMIN_ID = 3;
    public const USER_ORG_ADMIN_USERNAME = 'org_admin';
    public const USER_ORG_ADMIN_PASSWORD = 'OrgAdminPassword';

    // Regular User user
    public const USER_REGULAR_USER_ID = 4;
    public const USER_REGULAR_USER_USERNAME = 'user';
    public const USER_REGULAR_USER_PASSWORD = 'UserPassword';


    public function init(): void
    {
        $hasher = new DefaultPasswordHasher();
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::USER_ADMIN_ID,
                'uuid' => $faker->uuid(),
                'username' => self::USER_ADMIN_USERNAME,
                'password' => $hasher->hash(self::USER_ADMIN_PASSWORD),
                'role_id' => RolesFixture::ROLE_ADMIN_ID,
                'individual_id' => IndividualsFixture::INDIVIDUAL_ADMIN_ID,
                'disabled' => 0,
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::USER_SYNC_ID,
                'uuid' => $faker->uuid(),
                'username' => self::USER_SYNC_USERNAME,
                'password' => $hasher->hash(self::USER_SYNC_PASSWORD),
                'role_id' => RolesFixture::ROLE_SYNC_ID,
                'individual_id' => IndividualsFixture::INDIVIDUAL_SYNC_ID,
                'disabled' => 0,
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::USER_ORG_ADMIN_ID,
                'uuid' => $faker->uuid(),
                'username' => self::USER_ORG_ADMIN_USERNAME,
                'password' => $hasher->hash(self::USER_ORG_ADMIN_PASSWORD),
                'role_id' => RolesFixture::ROLE_ORG_ADMIN_ID,
                'individual_id' => IndividualsFixture::INDIVIDUAL_ORG_ADMIN_ID,
                'disabled' => 0,
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::USER_REGULAR_USER_ID,
                'uuid' => $faker->uuid(),
                'username' => self::USER_REGULAR_USER_USERNAME,
                'password' => $hasher->hash(self::USER_REGULAR_USER_PASSWORD),
                'role_id' => RolesFixture::ROLE_REGULAR_USER_ID,
                'individual_id' => IndividualsFixture::INDIVIDUAL_REGULAR_USER_ID,
                'disabled' => 0,
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ]
        ];
        parent::init();
    }
}
