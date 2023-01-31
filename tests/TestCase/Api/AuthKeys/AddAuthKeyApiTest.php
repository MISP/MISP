<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\AuthKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Helper\ApiTestTrait;

class AddAuthKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/authKeys/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testAddAdminAuthKey(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid;

        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'authkey' => $faker->sha1,
                'expiration' => 0,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'comment' => $faker->text
            ]
        );

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"uuid": "%s"', $uuid));
        $this->assertDbRecordExists('AuthKeys', ['uuid' => $uuid]);
    }

    public function testAddAdminAuthKeyNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid;


        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'authkey' => $faker->sha1,
                'expiration' => 0,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'comment' => $faker->text
            ]
        );

        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists('AuthKeys', ['uuid' => $uuid]);
    }
}
