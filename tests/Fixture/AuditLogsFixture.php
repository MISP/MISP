<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class AuditLogsFixture extends TestFixture
{
    public $connection = 'test';

    public const AUDIT_LOG_1_ID = 1000;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::AUDIT_LOG_1_ID,
                'created' => $faker->dateTime()->getTimestamp(),
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'authkey_id' => AuthKeysFixture::ADMIN_API_ID,
                'ip' => null,
                'request_type' => 0,
                'request_id' => '',
                'request_action' => 'login',
                'model' => 'Users',
                'model_id' => UsersFixture::USER_ADMIN_ID,
                'model_title' => '',
                'event_id' => null,
                'changed' => json_encode([])
            ]
        ];
        parent::init();
    }
}
