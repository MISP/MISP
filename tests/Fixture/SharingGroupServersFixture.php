<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class SharingGroupServersFixture extends TestFixture
{
    public $connection = 'test';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_A_ID,
                'server_id' => ServersFixture::SERVER_A_ID,
                'all_orgs' => false,
            ],
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_A_ID,
                'server_id' => ServersFixture::SERVER_C_ID,
                'all_orgs' => false,
            ]
        ];
        parent::init();
    }
}
