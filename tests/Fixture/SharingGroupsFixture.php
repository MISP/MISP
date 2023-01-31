<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class SharingGroupsFixture extends TestFixture
{
    public $connection = 'test';

    public const SHARING_GROUP_A_ID = 1;
    public const SHARING_GROUP_B_ID = 2;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::SHARING_GROUP_A_ID,
                'uuid' => $faker->uuid(),
                'name' => 'Sharing Group A',
                'releasability' => 'Sharing Group A releasability',
                'description' => 'Sharing Group A description',
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'active' => true,
                'local' => true,
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::SHARING_GROUP_B_ID,
                'uuid' => $faker->uuid(),
                'name' => 'Sharing Group B',
                'releasability' => 'Sharing Group B releasability',
                'description' => 'Sharing Group B description',
                'organisation_id' => OrganisationsFixture::ORGANISATION_B_ID,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'active' => true,
                'local' => true,
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
        ];
        parent::init();
    }
}
