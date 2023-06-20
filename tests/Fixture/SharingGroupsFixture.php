<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class SharingGroupsFixture extends TestFixture
{
    public $connection = 'test';

    public const SHARING_GROUP_A_ID = 1000;
    public const SHARING_GROUP_A_UUID = '6e4706da-a808-4db6-8f0b-3ec7d53f48c7';

    public const SHARING_GROUP_B_ID = 2000;
    public const SHARING_GROUP_B_UUID = '9cb340c1-aebe-4d57-a9ac-915632e3eadf';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::SHARING_GROUP_A_ID,
                'uuid' => self::SHARING_GROUP_A_UUID,
                'name' => 'Sharing Group A',
                'description' => 'Sharing Group A',
                'releasability' => 'UNCLASSIFIED',
                'organisation_uuid' => OrganisationsFixture::ORGANISATION_A_UUID,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'active' => true,
                'local' => true,
                'roaming' => false,
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::SHARING_GROUP_B_ID,
                'uuid' => self::SHARING_GROUP_B_UUID,
                'name' => 'Sharing Group B',
                'description' => 'Sharing Group B',
                'releasability' => 'UNCLASSIFIED',
                'organisation_uuid' => OrganisationsFixture::ORGANISATION_B_UUID,
                'org_id' => OrganisationsFixture::ORGANISATION_B_ID,
                'active' => true,
                'local' => true,
                'roaming' => false,
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ]
        ];
        parent::init();
    }
}
