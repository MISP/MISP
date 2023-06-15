<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class SharingGroupOrgsFixture extends TestFixture
{
    public $connection = 'test';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_A_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'extend' => false,
            ],
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_A_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_B_ID,
                'extend' => false,
            ],
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_B_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'extend' => false,
            ],
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_B_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_B_ID,
                'extend' => false,
            ],
        ];
        parent::init();
    }
}
