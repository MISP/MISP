<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Users;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Fixture\RolesFixture;
use App\Test\Helper\ApiTestTrait;

class EditUserApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/users/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys'
    ];


    public function testEditUser(): void
    {
        $this->markTestSkipped("This is not implemented yet.");
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, UsersFixture::USER_REGULAR_USER_ID);
        $this->put(
            $url,
            [
                'id' => UsersFixture::USER_REGULAR_USER_ID,
                'role_id' => UsersFixture::ROLE_ORG_ADMIN_ID,
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('Users', [
            'id' => UsersFixture::USER_REGULAR_USER_ID,
            'role_id' => UsersFixture::ROLE_ORG_ADMIN_ID
        ]);
    }

    public function testEditRoleNotAllowedAsRegularUser(): void
    {
        $this->markTestSkipped("This is not implemented yet.");
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $this->put(
            self::ENDPOINT,
            [
                'role_id' => UsersFixture::ROLE_ADMIN_ID,
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('Users', [
            'id' => UsersFixture::USER_REGULAR_USER_ID,
            'role_id' => UsersFixture::ROLE_ADMIN_ID
        ]);
    }
}
