<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class InboxFixture extends TestFixture
{
    public $connection = 'test';
    public $table = 'inbox';

    public const INBOX_USER_REGISTRATION_ID = 1;
    public const INBOX_INCOMING_CONNECTION_REQUEST_ID = 2;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::INBOX_USER_REGISTRATION_ID,
                'uuid' => $faker->uuid(),
                'scope' => 'User',
                'action' => 'Registration',
                'title' => 'User account creation requested for foo@bar.com',
                'origin' => '::1',
                'comment' => null,
                'description' => 'Handle user account for this cerebrate instance',
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'data' => [
                    'email' => 'foo@bar.com',
                    'password' => '$2y$10$dr5C0MWgBx1723yyws0HPudTqHz4k8wJ1PQ1ApVkNuH64LuZAr\/ve',
                ],
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::INBOX_INCOMING_CONNECTION_REQUEST_ID,
                'uuid' => $faker->uuid(),
                'scope' => 'LocalTool',
                'action' => 'IncomingConnectionRequest',
                'title' => 'Request for MISP Inter-connection',
                'origin' => 'http://127.0.0.1',
                'comment' => null,
                'description' => 'Handle Phase I of inter-connection when another cerebrate instance performs the request.',
                'user_id' => UsersFixture::USER_ORG_ADMIN_ID,
                'data' => [
                    'connectorName' => 'MispConnector',
                    'cerebrateURL' => 'http://127.0.0.1',
                    'local_tool_id' => 1,
                    'remote_tool_id' => 1,
                ],
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
        ];
        parent::init();
    }
}
