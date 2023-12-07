<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class AccessLogsFixture extends TestFixture
{
    public $connection = 'test';

    public const ACCESS_LOG_1_ID = 1000;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::ACCESS_LOG_1_ID,
                'created' => $faker->dateTime()->getTimestamp(),
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'request_method' => 0,
                'controller' => 'UsersController',
                'action' => 'index',
                'url' => 'http://localhost',
                'request' => null,
                'response_code' => 200,
                'memory_usage' => 0,
                'duration' => 1,
                'query_count' => 0,
                'query_log' => null,
            ]
        ];
        parent::init();
    }
}
